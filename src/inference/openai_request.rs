//! Closed OpenAI endpoint matching and bounded JSON request collection.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, Method, Response, StatusCode};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use std::error::Error;

/// Fixed upper bound for a native OpenAI request body.
pub(crate) const OPENAI_REQUEST_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// Fixed upper bound for an external OpenAI model alias.
const OPENAI_MODEL_ALIAS_LIMIT: usize = 255;

/// A supported OpenAI-compatible request shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenAiRequestProfile {
    /// List the models visible to the caller.
    Models,
    /// Create a chat completion.
    ChatCompletions,
    /// Create a legacy text completion.
    Completions,
    /// Create embeddings.
    Embeddings,
}

impl OpenAiRequestProfile {
    /// Match only the method and exact path combinations owned by the native
    /// OpenAI data plane. Query parameters do not affect the path match.
    pub(crate) fn match_request(method: &Method, path: &str) -> Option<Self> {
        match (method, path) {
            (&Method::GET, "/v1/models") => Some(Self::Models),
            (&Method::POST, "/v1/chat/completions") => Some(Self::ChatCompletions),
            (&Method::POST, "/v1/completions") => Some(Self::Completions),
            (&Method::POST, "/v1/embeddings") => Some(Self::Embeddings),
            _ => None,
        }
    }

    /// Whether this profile requires a bounded JSON request body.
    pub(crate) const fn requires_json_body(self) -> bool {
        !matches!(self, Self::Models)
    }
}

/// A stable OpenAI-compatible request rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenAiRequestError {
    /// The request does not declare an `application/json` media type.
    UnsupportedMediaType,
    /// The declared or observed request body exceeds the fixed limit.
    BodyTooLarge,
    /// The request body could not be read from the downstream connection.
    BodyReadFailed,
    /// The request body is not syntactically valid JSON.
    InvalidJson,
    /// The JSON request body is not an object.
    InvalidBodyShape,
    /// The JSON request object does not contain a model.
    MissingModel,
    /// The model is not a bounded, non-empty string.
    InvalidModel,
}

impl OpenAiRequestError {
    /// HTTP status associated with this stable rejection.
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyReadFailed
            | Self::InvalidJson
            | Self::InvalidBodyShape
            | Self::MissingModel
            | Self::InvalidModel => StatusCode::BAD_REQUEST,
        }
    }

    fn body(self) -> &'static [u8] {
        match self {
            Self::UnsupportedMediaType => br#"{"error":{"message":"Content-Type must be application/json.","type":"invalid_request_error","param":null,"code":"unsupported_media_type"}}"#,
            Self::BodyTooLarge => br#"{"error":{"message":"Request body exceeds the 8 MiB limit.","type":"invalid_request_error","param":null,"code":"request_too_large"}}"#,
            Self::BodyReadFailed => br#"{"error":{"message":"Request body could not be read.","type":"invalid_request_error","param":null,"code":"invalid_request_body"}}"#,
            Self::InvalidJson => br#"{"error":{"message":"Request body must contain valid JSON.","type":"invalid_request_error","param":null,"code":"invalid_json"}}"#,
            Self::InvalidBodyShape => br#"{"error":{"message":"Request body must be a JSON object.","type":"invalid_request_error","param":null,"code":"invalid_request_body"}}"#,
            Self::MissingModel => br#"{"error":{"message":"Required field 'model' is missing.","type":"invalid_request_error","param":"model","code":"missing_model"}}"#,
            Self::InvalidModel => br#"{"error":{"message":"Field 'model' must be a non-empty string of at most 255 bytes.","type":"invalid_request_error","param":"model","code":"invalid_model"}}"#,
        }
    }

    /// Convert the rejection into an HTTP response without including parser
    /// details or request content.
    pub(crate) fn into_response(self) -> Response<Bytes> {
        let mut response = Response::new(Bytes::from_static(self.body()));
        *response.status_mut() = self.status();
        response.headers_mut().insert(
            CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        response
    }
}

/// One validated OpenAI JSON request.
///
/// The parsed document remains available at the inference-dispatch boundary so
/// later authorization and model-routing stages do not need to parse it again.
#[derive(Debug, PartialEq)]
pub(crate) struct OpenAiJsonRequest {
    body: Bytes,
    document: serde_json::Map<String, serde_json::Value>,
}

impl OpenAiJsonRequest {
    /// Validated external model alias selected by the client.
    pub(crate) fn model_alias(&self) -> &str {
        self.document
            .get("model")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    }

    /// Recover the original validated request bytes unchanged.
    pub(crate) fn into_body(self) -> Bytes {
        self.body
    }
}

/// Collect and validate one OpenAI JSON request body under the fixed limit.
///
/// The raw bytes and parsed object are retained together. The ordinary proxy
/// can therefore forward exactly what the client sent, while a later native
/// dispatch stage can consume the already parsed model alias and document.
pub(crate) async fn collect_json_body<B>(
    headers: &HeaderMap,
    body: B,
) -> Result<OpenAiJsonRequest, OpenAiRequestError>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    if !has_json_content_type(headers) {
        return Err(OpenAiRequestError::UnsupportedMediaType);
    }

    if declared_body_is_too_large(headers) {
        return Err(OpenAiRequestError::BodyTooLarge);
    }

    let body = Limited::new(body, OPENAI_REQUEST_BODY_LIMIT)
        .collect()
        .await
        .map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                OpenAiRequestError::BodyTooLarge
            } else {
                OpenAiRequestError::BodyReadFailed
            }
        })?
        .to_bytes();

    let document = match serde_json::from_slice::<serde_json::Value>(&body)
        .map_err(|_| OpenAiRequestError::InvalidJson)?
    {
        serde_json::Value::Object(document) => document,
        _ => return Err(OpenAiRequestError::InvalidBodyShape),
    };
    let model = document
        .get("model")
        .ok_or(OpenAiRequestError::MissingModel)?
        .as_str()
        .ok_or(OpenAiRequestError::InvalidModel)?;
    if !valid_model_alias(model) {
        return Err(OpenAiRequestError::InvalidModel);
    }

    Ok(OpenAiJsonRequest { body, document })
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn declared_body_is_too_large(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|length| length > OPENAI_REQUEST_BODY_LIMIT as u64)
}

pub(crate) fn valid_model_alias(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= OPENAI_MODEL_ALIAS_LIMIT
        && model.trim() == model
        && !model.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    fn json_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers
    }

    #[test]
    fn matches_only_the_closed_endpoint_and_method_set() {
        let supported = [
            (Method::GET, "/v1/models", OpenAiRequestProfile::Models),
            (
                Method::POST,
                "/v1/chat/completions",
                OpenAiRequestProfile::ChatCompletions,
            ),
            (
                Method::POST,
                "/v1/completions",
                OpenAiRequestProfile::Completions,
            ),
            (
                Method::POST,
                "/v1/embeddings",
                OpenAiRequestProfile::Embeddings,
            ),
        ];

        for (method, path, expected) in supported {
            assert_eq!(
                OpenAiRequestProfile::match_request(&method, path),
                Some(expected)
            );
        }

        for (method, path) in [
            (Method::POST, "/v1/models"),
            (Method::GET, "/v1/chat/completions"),
            (Method::POST, "/v1/chat/completions/"),
            (Method::POST, "/prefix/v1/chat/completions"),
            (Method::POST, "/v1/responses"),
        ] {
            assert_eq!(OpenAiRequestProfile::match_request(&method, path), None);
        }
    }

    #[test]
    fn only_post_profiles_require_json_bodies() {
        assert!(!OpenAiRequestProfile::Models.requires_json_body());
        assert!(OpenAiRequestProfile::ChatCompletions.requires_json_body());
        assert!(OpenAiRequestProfile::Completions.requires_json_body());
        assert!(OpenAiRequestProfile::Embeddings.requires_json_body());
    }

    #[tokio::test]
    async fn accepts_json_media_type_parameters_and_preserves_bytes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            "Application/JSON; charset=utf-8".parse().unwrap(),
        );
        let request = Bytes::from_static(br#"{ "model": "local" }"#);

        let collected = collect_json_body(&headers, Full::new(request.clone()))
            .await
            .unwrap();

        assert_eq!(collected.model_alias(), "local");
        assert_eq!(collected.into_body(), request);
    }

    #[tokio::test]
    async fn rejects_missing_or_non_json_content_type() {
        let body = || Full::new(Bytes::from_static(br#"{"model":"local"}"#));

        assert_eq!(
            collect_json_body(&HeaderMap::new(), body()).await,
            Err(OpenAiRequestError::UnsupportedMediaType)
        );

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/problem+json".parse().unwrap());
        assert_eq!(
            collect_json_body(&headers, body()).await,
            Err(OpenAiRequestError::UnsupportedMediaType)
        );
    }

    #[tokio::test]
    async fn enforces_the_observed_body_limit() {
        let headers = json_headers();
        let at_limit = Bytes::from(vec![b' '; OPENAI_REQUEST_BODY_LIMIT]);
        assert_eq!(
            collect_json_body(&headers, Full::new(at_limit)).await,
            Err(OpenAiRequestError::InvalidJson)
        );

        let over_limit = Bytes::from(vec![b' '; OPENAI_REQUEST_BODY_LIMIT + 1]);
        assert_eq!(
            collect_json_body(&headers, Full::new(over_limit)).await,
            Err(OpenAiRequestError::BodyTooLarge)
        );
    }

    #[tokio::test]
    async fn rejects_an_oversized_declared_length_before_reading() {
        let mut headers = json_headers();
        headers.insert(
            CONTENT_LENGTH,
            (OPENAI_REQUEST_BODY_LIMIT + 1).to_string().parse().unwrap(),
        );

        assert_eq!(
            collect_json_body(&headers, Full::new(Bytes::new())).await,
            Err(OpenAiRequestError::BodyTooLarge)
        );
    }

    #[tokio::test]
    async fn rejects_invalid_json_without_echoing_parser_details() {
        let error = collect_json_body(
            &json_headers(),
            Full::new(Bytes::from_static(br#"{"model":"local""#)),
        )
        .await
        .unwrap_err();
        let response = error.into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        assert_eq!(
            response.body().as_ref(),
            br#"{"error":{"message":"Request body must contain valid JSON.","type":"invalid_request_error","param":null,"code":"invalid_json"}}"#
        );
    }

    #[tokio::test]
    async fn requires_a_json_object_with_a_bounded_model_alias() {
        let cases = [
            (br#"[]"#.as_slice(), OpenAiRequestError::InvalidBodyShape),
            (br#"{}"#.as_slice(), OpenAiRequestError::MissingModel),
            (
                br#"{"model":42}"#.as_slice(),
                OpenAiRequestError::InvalidModel,
            ),
            (
                br#"{"model":""}"#.as_slice(),
                OpenAiRequestError::InvalidModel,
            ),
            (
                br#"{"model":" leading-space"}"#.as_slice(),
                OpenAiRequestError::InvalidModel,
            ),
            (
                br#"{"model":"control\u0000character"}"#.as_slice(),
                OpenAiRequestError::InvalidModel,
            ),
        ];

        for (body, expected) in cases {
            assert_eq!(
                collect_json_body(&json_headers(), Full::new(Bytes::copy_from_slice(body)))
                    .await
                    .unwrap_err(),
                expected
            );
        }

        let at_limit = "x".repeat(OPENAI_MODEL_ALIAS_LIMIT);
        let body = Bytes::from(format!(r#"{{"model":"{at_limit}"}}"#));
        let request = collect_json_body(&json_headers(), Full::new(body))
            .await
            .unwrap();
        assert_eq!(request.model_alias(), at_limit);

        let over_limit = "x".repeat(OPENAI_MODEL_ALIAS_LIMIT + 1);
        let body = Bytes::from(format!(r#"{{"model":"{over_limit}"}}"#));
        assert_eq!(
            collect_json_body(&json_headers(), Full::new(body))
                .await
                .unwrap_err(),
            OpenAiRequestError::InvalidModel
        );

        let multi_byte_over_limit = "é".repeat(OPENAI_MODEL_ALIAS_LIMIT / 2 + 1);
        assert!(multi_byte_over_limit.len() > OPENAI_MODEL_ALIAS_LIMIT);
        let body = Bytes::from(format!(r#"{{"model":"{multi_byte_over_limit}"}}"#));
        assert_eq!(
            collect_json_body(&json_headers(), Full::new(body))
                .await
                .unwrap_err(),
            OpenAiRequestError::InvalidModel
        );
    }

    #[test]
    fn stable_error_contract_maps_each_failure() {
        let cases = [
            (
                OpenAiRequestError::UnsupportedMediaType,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                None,
            ),
            (
                OpenAiRequestError::BodyTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
                None,
            ),
            (
                OpenAiRequestError::BodyReadFailed,
                StatusCode::BAD_REQUEST,
                "invalid_request_body",
                None,
            ),
            (
                OpenAiRequestError::InvalidJson,
                StatusCode::BAD_REQUEST,
                "invalid_json",
                None,
            ),
            (
                OpenAiRequestError::InvalidBodyShape,
                StatusCode::BAD_REQUEST,
                "invalid_request_body",
                None,
            ),
            (
                OpenAiRequestError::MissingModel,
                StatusCode::BAD_REQUEST,
                "missing_model",
                Some("model"),
            ),
            (
                OpenAiRequestError::InvalidModel,
                StatusCode::BAD_REQUEST,
                "invalid_model",
                Some("model"),
            ),
        ];

        for (error, status, code, param) in cases {
            let response = error.into_response();
            let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(body["error"]["type"], "invalid_request_error");
            assert_eq!(body["error"]["code"], code);
            assert_eq!(
                body["error"]["param"],
                param.map_or(serde_json::Value::Null, serde_json::Value::from)
            );
        }
    }
}
