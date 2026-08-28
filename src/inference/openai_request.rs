//! Closed OpenAI endpoint matching and bounded JSON request collection.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, Method, Response, StatusCode};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;

/// Fixed upper bound for a native OpenAI request body.
pub(crate) const OPENAI_REQUEST_BODY_LIMIT: usize = 8 * 1024 * 1024;

/// Fixed upper bound for an external OpenAI model alias.
const OPENAI_MODEL_ALIAS_LIMIT: usize = 255;
const PROMPT_CACHE_KEY_LIMIT: usize = 256;

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

    /// Whether this endpoint can request an SSE response through its JSON
    /// `stream` field.
    pub(crate) const fn supports_streaming(self) -> bool {
        matches!(self, Self::ChatCompletions | Self::Completions)
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
    /// The optional prompt-cache affinity key is not a bounded identifier.
    InvalidPromptCacheKey,
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
            | Self::InvalidModel
            | Self::InvalidPromptCacheKey => StatusCode::BAD_REQUEST,
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
            Self::InvalidPromptCacheKey => br#"{"error":{"message":"Field 'prompt_cache_key' must be a non-empty string of at most 256 bytes without surrounding whitespace or control characters.","type":"invalid_request_error","param":"prompt_cache_key","code":"invalid_prompt_cache_key"}}"#,
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
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct OpenAiJsonRequest {
    body: Bytes,
    document: serde_json::Map<String, serde_json::Value>,
}

/// A validated OpenAI request that will be forwarded without managed model
/// rewriting. Only the fields needed by the proxy boundary are retained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OpenAiProxyRequest {
    body: Bytes,
}

impl OpenAiProxyRequest {
    /// Recover the original validated request bytes unchanged.
    pub(crate) fn into_body(self) -> Bytes {
        self.body
    }
}

impl OpenAiJsonRequest {
    /// Validated external model alias selected by the client.
    pub(crate) fn model_alias(&self) -> &str {
        self.document
            .get("model")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
    }

    /// Whether the validated request explicitly selects OpenAI SSE streaming.
    pub(crate) fn stream_requested(&self) -> bool {
        self.document
            .get("stream")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }

    /// Recover the original validated request bytes unchanged.
    pub(crate) fn into_body(self) -> Bytes {
        self.body
    }

    /// Derive the only cache identifier allowed to cross the managed boundary.
    /// The client value is never returned or retained outside this request.
    pub(crate) fn scoped_prompt_cache_key(
        &self,
        credential_id: uuid::Uuid,
        model_id: uuid::Uuid,
        endpoint: crate::config::InferenceEndpoint,
    ) -> Option<String> {
        let caller_key = self
            .document
            .get("prompt_cache_key")
            .and_then(serde_json::Value::as_str)?;
        let mut digest = Sha256::new();
        hash_part(&mut digest, b"a3s.gateway.prompt-cache-key.v1");
        hash_part(&mut digest, credential_id.as_bytes());
        hash_part(&mut digest, model_id.as_bytes());
        hash_part(&mut digest, endpoint.as_str().as_bytes());
        hash_part(&mut digest, caller_key.as_bytes());
        Some(format!("a3s-gw-pcache-v1:{:x}", digest.finalize()))
    }

    /// Build a replayable managed dispatch body for one upstream target.
    pub(crate) fn routed_body(
        &self,
        upstream_model: &str,
        scoped_prompt_cache_key: Option<&str>,
    ) -> Result<Bytes, serde_json::Error> {
        let mut document = self.document.clone();
        document.insert(
            "model".to_string(),
            serde_json::Value::String(upstream_model.to_string()),
        );
        if document.contains_key("prompt_cache_key") {
            match scoped_prompt_cache_key {
                Some(key) => {
                    document.insert(
                        "prompt_cache_key".to_string(),
                        serde_json::Value::String(key.to_string()),
                    );
                }
                None => {
                    document.remove("prompt_cache_key");
                }
            }
        }
        serde_json::to_vec(&document).map(Bytes::from)
    }
}

fn hash_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

/// Build a deterministic OpenAI-compatible model list from granted aliases.
pub(crate) fn models_response(models: &[String]) -> Result<Response<Bytes>, serde_json::Error> {
    let data = models
        .iter()
        .map(|model| {
            serde_json::json!({
                "id": model,
                "object": "model",
                "created": 0,
                "owned_by": "a3s"
            })
        })
        .collect::<Vec<_>>();
    let body = serde_json::to_vec(&serde_json::json!({
        "object": "list",
        "data": data
    }))?;
    let mut response = Response::new(Bytes::from(body));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Ok(response)
}

#[derive(Debug, Clone, Copy)]
enum ProxyJsonField {
    Model,
    Other,
}

struct ProxyJsonFieldVisitor;

impl Visitor<'_> for ProxyJsonFieldVisitor {
    type Value = ProxyJsonField;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenAI request field")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(match value {
            "model" => ProxyJsonField::Model,
            _ => ProxyJsonField::Other,
        })
    }

    fn visit_borrowed_str<E>(self, value: &'_ str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }
}

impl<'de> Deserialize<'de> for ProxyJsonField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_identifier(ProxyJsonFieldVisitor)
    }
}

#[derive(Default)]
struct ProxyJsonMetadata {
    model: Option<serde_json::Value>,
}

struct ProxyJsonMetadataVisitor;

impl<'de> Visitor<'de> for ProxyJsonMetadataVisitor {
    type Value = ProxyJsonMetadata;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an OpenAI JSON request object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut metadata = ProxyJsonMetadata::default();
        while let Some(field) = map.next_key::<ProxyJsonField>()? {
            match field {
                ProxyJsonField::Model => metadata.model = Some(map.next_value()?),
                ProxyJsonField::Other => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(metadata)
    }
}

impl<'de> Deserialize<'de> for ProxyJsonMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ProxyJsonMetadataVisitor)
    }
}

/// Collect and validate an OpenAI JSON request that does not require managed
/// model rewriting. Unknown fields are syntactically validated and discarded
/// instead of being allocated into a complete JSON document.
pub(crate) async fn collect_proxy_json_body<B>(
    headers: &HeaderMap,
    body: B,
) -> Result<OpenAiProxyRequest, OpenAiRequestError>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let body = collect_bounded_json_body(headers, body).await?;
    if body
        .iter()
        .find(|byte| !byte.is_ascii_whitespace())
        .is_none_or(|byte| *byte != b'{')
    {
        serde_json::from_slice::<IgnoredAny>(&body).map_err(|_| OpenAiRequestError::InvalidJson)?;
        return Err(OpenAiRequestError::InvalidBodyShape);
    }
    let metadata = serde_json::from_slice::<ProxyJsonMetadata>(&body)
        .map_err(|_| OpenAiRequestError::InvalidJson)?;
    let model = metadata
        .model
        .as_ref()
        .ok_or(OpenAiRequestError::MissingModel)?
        .as_str()
        .ok_or(OpenAiRequestError::InvalidModel)?;
    if !valid_model_alias(model) {
        return Err(OpenAiRequestError::InvalidModel);
    }
    Ok(OpenAiProxyRequest { body })
}

fn validate_prompt_cache_key(value: Option<&serde_json::Value>) -> Result<(), OpenAiRequestError> {
    let Some(value) = value else {
        return Ok(());
    };
    let Some(key) = value.as_str() else {
        return Err(OpenAiRequestError::InvalidPromptCacheKey);
    };
    if key.is_empty()
        || key.len() > PROMPT_CACHE_KEY_LIMIT
        || key.trim() != key
        || key.chars().any(char::is_control)
    {
        return Err(OpenAiRequestError::InvalidPromptCacheKey);
    }
    Ok(())
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
    let body = collect_bounded_json_body(headers, body).await?;

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
    validate_prompt_cache_key(document.get("prompt_cache_key"))?;

    Ok(OpenAiJsonRequest { body, document })
}

async fn collect_bounded_json_body<B>(
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

    Limited::new(body, OPENAI_REQUEST_BODY_LIMIT)
        .collect()
        .await
        .map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                OpenAiRequestError::BodyTooLarge
            } else {
                OpenAiRequestError::BodyReadFailed
            }
        })
        .map(|collected| collected.to_bytes())
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

    #[test]
    fn only_completion_profiles_support_json_selected_streaming() {
        assert!(!OpenAiRequestProfile::Models.supports_streaming());
        assert!(OpenAiRequestProfile::ChatCompletions.supports_streaming());
        assert!(OpenAiRequestProfile::Completions.supports_streaming());
        assert!(!OpenAiRequestProfile::Embeddings.supports_streaming());
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
    async fn recognizes_only_a_boolean_true_stream_field() {
        for (body, expected) in [
            (br#"{"model":"local","stream":true}"#.as_slice(), true),
            (br#"{"model":"local","stream":false}"#.as_slice(), false),
            (br#"{"model":"local","stream":"true"}"#.as_slice(), false),
            (br#"{"model":"local"}"#.as_slice(), false),
        ] {
            let request =
                collect_json_body(&json_headers(), Full::new(Bytes::copy_from_slice(body)))
                    .await
                    .unwrap();
            assert_eq!(request.stream_requested(), expected);
        }
    }

    #[tokio::test]
    async fn proxy_validation_discards_unknown_fields_and_preserves_bytes() {
        let request = Bytes::from_static(
            br#"{"model":"local","messages":[{"role":"user","content":"hello"}],"metadata":{"tenant":"acme"},"stream":true}"#,
        );

        let collected = collect_proxy_json_body(&json_headers(), Full::new(request.clone()))
            .await
            .unwrap();

        assert_eq!(collected.into_body(), request);
    }

    #[tokio::test]
    async fn proxy_validation_keeps_last_duplicate_field_semantics() {
        let collected = collect_proxy_json_body(
            &json_headers(),
            Full::new(Bytes::from_static(
                br#"{"model":42,"model":"local","stream":true}"#,
            )),
        )
        .await
        .unwrap();

        assert_eq!(
            collected.into_body(),
            br#"{"model":42,"model":"local","stream":true}"#.as_slice()
        );
    }

    #[tokio::test]
    async fn proxy_validation_enforces_model_alias_bounds_without_rewriting() {
        let at_limit = "x".repeat(OPENAI_MODEL_ALIAS_LIMIT);
        let body = Bytes::from(format!(r#"{{"model":"{at_limit}","messages":[]}}"#));
        let collected = collect_proxy_json_body(&json_headers(), Full::new(body.clone()))
            .await
            .unwrap();
        assert_eq!(collected.into_body(), body);

        let over_limit = "x".repeat(OPENAI_MODEL_ALIAS_LIMIT + 1);
        for body in [
            Bytes::from_static(br#"{"model":""}"#),
            Bytes::from_static(br#"{"model":" leading-space"}"#),
            Bytes::from_static(br#"{"model":"control\u0000character"}"#),
            Bytes::from(format!(r#"{{"model":"{over_limit}"}}"#)),
        ] {
            assert_eq!(
                collect_proxy_json_body(&json_headers(), Full::new(body))
                    .await
                    .unwrap_err(),
                OpenAiRequestError::InvalidModel
            );
        }
    }

    #[tokio::test]
    async fn proxy_validation_preserves_shape_and_syntax_errors() {
        for (body, expected) in [
            (br#"[]"#.as_slice(), OpenAiRequestError::InvalidBodyShape),
            (
                br#"{"model":"local""#.as_slice(),
                OpenAiRequestError::InvalidJson,
            ),
            (br#"{}"#.as_slice(), OpenAiRequestError::MissingModel),
            (
                br#"{"model":42}"#.as_slice(),
                OpenAiRequestError::InvalidModel,
            ),
        ] {
            let error =
                collect_proxy_json_body(&json_headers(), Full::new(Bytes::copy_from_slice(body)))
                    .await
                    .unwrap_err();
            assert_eq!(error, expected);
        }
    }

    #[tokio::test]
    async fn rewrites_only_the_model_for_managed_dispatch() {
        let request = collect_json_body(
            &json_headers(),
            Full::new(Bytes::from_static(
                br#"{ "model": "external", "messages": [{"role":"user","content":"hello"}] }"#,
            )),
        )
        .await
        .unwrap();

        let routed = request.routed_body("internal/model-v2", None).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&routed).unwrap();
        assert_eq!(document["model"], "internal/model-v2");
        assert_eq!(document["messages"][0]["content"], "hello");
    }

    #[tokio::test]
    async fn managed_dispatch_collapses_duplicate_model_fields() {
        let request = collect_json_body(
            &json_headers(),
            Full::new(Bytes::from_static(
                br#"{"model":"hidden","model":"external","messages":[]}"#,
            )),
        )
        .await
        .unwrap();

        let routed = request.routed_body("external", None).unwrap();
        let routed = String::from_utf8(routed.to_vec()).unwrap();
        assert_eq!(routed.matches("\"model\"").count(), 1);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&routed).unwrap()["model"],
            "external"
        );
    }

    #[tokio::test]
    async fn managed_dispatch_scopes_prompt_cache_affinity_without_forwarding_the_raw_key() {
        let request = collect_json_body(
            &json_headers(),
            Full::new(Bytes::from_static(
                br#"{"model":"external","prompt_cache_key":"private-session","messages":[]}"#,
            )),
        )
        .await
        .unwrap();
        let credential_id = uuid::Uuid::from_u128(1);
        let model_id = uuid::Uuid::from_u128(2);
        let scoped = request
            .scoped_prompt_cache_key(
                credential_id,
                model_id,
                crate::config::InferenceEndpoint::ChatCompletions,
            )
            .unwrap();
        assert_eq!(
            Some(scoped.clone()),
            request.scoped_prompt_cache_key(
                credential_id,
                model_id,
                crate::config::InferenceEndpoint::ChatCompletions,
            )
        );
        assert_ne!(
            Some(scoped.clone()),
            request.scoped_prompt_cache_key(
                uuid::Uuid::from_u128(3),
                model_id,
                crate::config::InferenceEndpoint::ChatCompletions,
            )
        );
        assert!(scoped.starts_with("a3s-gw-pcache-v1:"));
        assert!(!scoped.contains("private-session"));

        let routed = request.routed_body("internal", Some(&scoped)).unwrap();
        let document: serde_json::Value = serde_json::from_slice(&routed).unwrap();
        assert_eq!(document["prompt_cache_key"], scoped);
        assert!(!String::from_utf8(routed.to_vec())
            .unwrap()
            .contains("private-session"));
    }

    #[tokio::test]
    async fn rejects_ambiguous_or_unbounded_prompt_cache_keys() {
        let over_limit = "x".repeat(PROMPT_CACHE_KEY_LIMIT + 1);
        let bodies = [
            Bytes::from_static(br#"{"model":"external","prompt_cache_key":42}"#),
            Bytes::from_static(br#"{"model":"external","prompt_cache_key":""}"#),
            Bytes::from_static(br#"{"model":"external","prompt_cache_key":" leading"}"#),
            Bytes::from_static(br#"{"model":"external","prompt_cache_key":"line\nbreak"}"#),
            Bytes::from(format!(
                r#"{{"model":"external","prompt_cache_key":"{over_limit}"}}"#
            )),
        ];
        for body in bodies {
            assert_eq!(
                collect_json_body(&json_headers(), Full::new(body))
                    .await
                    .unwrap_err(),
                OpenAiRequestError::InvalidPromptCacheKey
            );
        }
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
            (
                OpenAiRequestError::InvalidPromptCacheKey,
                StatusCode::BAD_REQUEST,
                "invalid_prompt_cache_key",
                Some("prompt_cache_key"),
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
