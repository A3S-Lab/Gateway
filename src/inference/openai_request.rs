//! Closed OpenAI endpoint matching and bounded JSON request collection.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, Method, Response, StatusCode};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use std::error::Error;

/// Fixed upper bound for a native OpenAI request body.
pub(crate) const OPENAI_REQUEST_BODY_LIMIT: usize = 8 * 1024 * 1024;

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
}

impl OpenAiRequestError {
    /// HTTP status associated with this stable rejection.
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyReadFailed | Self::InvalidJson => StatusCode::BAD_REQUEST,
        }
    }

    fn body(self) -> &'static [u8] {
        match self {
            Self::UnsupportedMediaType => br#"{"error":{"message":"Content-Type must be application/json.","type":"invalid_request_error","param":null,"code":"unsupported_media_type"}}"#,
            Self::BodyTooLarge => br#"{"error":{"message":"Request body exceeds the 8 MiB limit.","type":"invalid_request_error","param":null,"code":"request_too_large"}}"#,
            Self::BodyReadFailed => br#"{"error":{"message":"Request body could not be read.","type":"invalid_request_error","param":null,"code":"invalid_request_body"}}"#,
            Self::InvalidJson => br#"{"error":{"message":"Request body must contain valid JSON.","type":"invalid_request_error","param":null,"code":"invalid_json"}}"#,
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

/// Collect and validate one OpenAI JSON request body under the fixed limit.
///
/// The raw bytes are returned unchanged so the ordinary proxy can forward
/// exactly what the client sent. JSON is parsed once here for validation.
pub(crate) async fn collect_json_body<B>(
    headers: &HeaderMap,
    body: B,
) -> Result<Bytes, OpenAiRequestError>
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

    serde_json::from_slice::<serde_json::Value>(&body)
        .map_err(|_| OpenAiRequestError::InvalidJson)?;

    Ok(body)
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

        assert_eq!(collected, request);
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

    #[test]
    fn stable_error_contract_maps_each_failure() {
        let cases = [
            (
                OpenAiRequestError::UnsupportedMediaType,
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
            ),
            (
                OpenAiRequestError::BodyTooLarge,
                StatusCode::PAYLOAD_TOO_LARGE,
                "request_too_large",
            ),
            (
                OpenAiRequestError::BodyReadFailed,
                StatusCode::BAD_REQUEST,
                "invalid_request_body",
            ),
            (
                OpenAiRequestError::InvalidJson,
                StatusCode::BAD_REQUEST,
                "invalid_json",
            ),
        ];

        for (error, status, code) in cases {
            let response = error.into_response();
            let body: serde_json::Value = serde_json::from_slice(response.body()).unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(body["error"]["type"], "invalid_request_error");
            assert_eq!(body["error"]["param"], serde_json::Value::Null);
            assert_eq!(body["error"]["code"], code);
        }
    }
}
