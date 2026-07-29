//! Bounded modern MCP JSON-RPC and mirrored-header validation.

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::Bytes;
use http::header::{ACCEPT, ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Response, StatusCode, Uri};
use http_body_util::{BodyExt, LengthLimitError, Limited};
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::error::Error;
use std::fmt;

const PROTOCOL_VERSION_HEADER: HeaderName = HeaderName::from_static("mcp-protocol-version");
const METHOD_HEADER: HeaderName = HeaderName::from_static("mcp-method");
const NAME_HEADER: HeaderName = HeaderName::from_static("mcp-name");
const PROTOCOL_VERSION_META: &str = "io.modelcontextprotocol/protocolVersion";
const CLIENT_INFO_META: &str = "io.modelcontextprotocol/clientInfo";
const CLIENT_CAPABILITIES_META: &str = "io.modelcontextprotocol/clientCapabilities";
const BASE64_PREFIX: &str = "=?base64?";
const BASE64_SUFFIX: &str = "?=";
const MAX_PROTOCOL_VERSION_BYTES: usize = 64;
const MAX_METHOD_BYTES: usize = 255;
const MAX_CLIENT_IMPLEMENTATION_FIELD_BYTES: usize = 255;
const MAX_REQUEST_ID_BYTES: usize = 1_024;

/// Stable categories for request validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpRequestErrorKind {
    MethodNotAllowed,
    UnsupportedMediaType,
    NotAcceptable,
    HeadersTooLarge,
    BodyTooLarge,
    BodyReadFailed,
    InvalidJson,
    InvalidRequest,
    HeaderMismatch,
    UnsupportedProtocolVersion,
}

/// A bounded request failure that never retains request payloads or credentials.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct McpRequestError {
    kind: McpRequestErrorKind,
    request_id: Option<McpRequestId>,
    requested_protocol_version: Option<String>,
}

impl fmt::Debug for McpRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpRequestError")
            .field("kind", &self.kind)
            .field("has_request_id", &self.request_id.is_some())
            .field(
                "has_requested_protocol_version",
                &self.requested_protocol_version.is_some(),
            )
            .finish()
    }
}

impl McpRequestError {
    fn new(kind: McpRequestErrorKind) -> Self {
        Self {
            kind,
            request_id: None,
            requested_protocol_version: None,
        }
    }

    fn for_request(kind: McpRequestErrorKind, request_id: Option<McpRequestId>) -> Self {
        Self {
            kind,
            request_id,
            requested_protocol_version: None,
        }
    }

    fn unsupported(request_id: Option<McpRequestId>, requested_protocol_version: String) -> Self {
        Self {
            kind: McpRequestErrorKind::UnsupportedProtocolVersion,
            request_id,
            requested_protocol_version: Some(requested_protocol_version),
        }
    }

    #[cfg(test)]
    pub(crate) const fn kind(&self) -> McpRequestErrorKind {
        self.kind
    }

    pub(crate) const fn status(&self) -> StatusCode {
        match self.kind {
            McpRequestErrorKind::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            McpRequestErrorKind::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            McpRequestErrorKind::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            McpRequestErrorKind::HeadersTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            McpRequestErrorKind::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            McpRequestErrorKind::BodyReadFailed
            | McpRequestErrorKind::InvalidJson
            | McpRequestErrorKind::InvalidRequest
            | McpRequestErrorKind::HeaderMismatch
            | McpRequestErrorKind::UnsupportedProtocolVersion => StatusCode::BAD_REQUEST,
        }
    }

    fn json_rpc_code(&self) -> i64 {
        match self.kind {
            McpRequestErrorKind::InvalidJson | McpRequestErrorKind::BodyReadFailed => -32_700,
            McpRequestErrorKind::HeaderMismatch => -32_020,
            McpRequestErrorKind::UnsupportedProtocolVersion => -32_022,
            McpRequestErrorKind::MethodNotAllowed
            | McpRequestErrorKind::UnsupportedMediaType
            | McpRequestErrorKind::NotAcceptable
            | McpRequestErrorKind::HeadersTooLarge
            | McpRequestErrorKind::BodyTooLarge
            | McpRequestErrorKind::InvalidRequest => -32_600,
        }
    }

    fn message(&self) -> &'static str {
        match self.kind {
            McpRequestErrorKind::MethodNotAllowed => {
                "The MCP endpoint accepts only HTTP POST requests."
            }
            McpRequestErrorKind::UnsupportedMediaType => "Content-Type must be application/json.",
            McpRequestErrorKind::NotAcceptable => {
                "Accept must include application/json and text/event-stream."
            }
            McpRequestErrorKind::HeadersTooLarge => "Request headers exceed the configured limit.",
            McpRequestErrorKind::BodyTooLarge => "Request body exceeds the configured limit.",
            McpRequestErrorKind::BodyReadFailed => "Request body could not be read.",
            McpRequestErrorKind::InvalidJson => "Parse error: Invalid JSON.",
            McpRequestErrorKind::InvalidRequest => "Invalid JSON-RPC request.",
            McpRequestErrorKind::HeaderMismatch => {
                "MCP request metadata headers do not match the JSON-RPC body."
            }
            McpRequestErrorKind::UnsupportedProtocolVersion => "Unsupported protocol version.",
        }
    }

    /// Build a stable, payload-free modern JSON-RPC error response.
    pub(crate) fn into_response(self, supported_versions: &[String]) -> Response<Bytes> {
        let status = self.status();
        let mut error = serde_json::json!({
            "code": self.json_rpc_code(),
            "message": self.message(),
        });
        if self.kind == McpRequestErrorKind::UnsupportedProtocolVersion {
            error["data"] = serde_json::json!({
                "supported": supported_versions,
                "requested": self.requested_protocol_version,
            });
        }
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": self.request_id.map(McpRequestId::into_value).unwrap_or(Value::Null),
            "error": error,
        }))
        .unwrap_or_else(|_| {
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"Internal error."}}"#
                .to_vec()
        });
        let mut response = Response::new(Bytes::from(body));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self.kind == McpRequestErrorKind::MethodNotAllowed {
            response
                .headers_mut()
                .insert(ALLOW, HeaderValue::from_static("POST"));
        }
        response
    }
}

/// Header-only validation result. It is safe to construct before local
/// authentication because none of its values are trusted for authorization.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct McpRequestHead {
    protocol_version: String,
    method: String,
    name: Option<String>,
}

impl fmt::Debug for McpRequestHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpRequestHead")
            .field("protocol_version", &self.protocol_version)
            .field("method", &self.method)
            .field("has_name", &self.name.is_some())
            .finish()
    }
}

/// One validated JSON-RPC request or notification.
///
/// Original bytes are retained for exactly-once upstream dispatch. Debug output
/// deliberately omits the body, request ID, name, and client metadata.
#[derive(Clone, PartialEq)]
pub(crate) struct McpJsonRequest {
    body: Bytes,
    request_id: Option<McpRequestId>,
    method: String,
    name: Option<String>,
    protocol_version: String,
}

impl fmt::Debug for McpJsonRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpJsonRequest")
            .field("body_bytes", &self.body.len())
            .field("is_notification", &self.request_id.is_none())
            .field("method", &self.method)
            .field("has_name", &self.name.is_some())
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

impl McpJsonRequest {
    pub(crate) fn method(&self) -> &str {
        &self.method
    }

    pub(crate) fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    pub(crate) const fn is_notification(&self) -> bool {
        self.request_id.is_none()
    }

    pub(crate) fn request_id_value(&self) -> Option<Value> {
        self.request_id
            .as_ref()
            .map(|request_id| request_id.0.clone())
    }

    pub(crate) fn into_body(self) -> Bytes {
        self.body
    }
}

/// Validate bounded HTTP metadata without reading the request body.
///
/// The caller can authenticate after this function and before body collection.
/// Mirrored values remain untrusted until `collect_mcp_json_request` compares
/// them with the parsed body.
pub(crate) fn validate_mcp_request_head(
    http_method: &Method,
    uri: &Uri,
    expected_path: &str,
    headers: &HeaderMap,
    max_header_bytes: u64,
    max_request_bytes: u64,
) -> Result<McpRequestHead, McpRequestError> {
    if http_method != Method::POST {
        return Err(McpRequestError::new(McpRequestErrorKind::MethodNotAllowed));
    }
    if uri.path() != expected_path || uri.query().is_some() {
        return Err(McpRequestError::new(McpRequestErrorKind::InvalidRequest));
    }
    if header_bytes(headers) > max_header_bytes {
        return Err(McpRequestError::new(McpRequestErrorKind::HeadersTooLarge));
    }
    if !has_json_content_type(headers) {
        return Err(McpRequestError::new(
            McpRequestErrorKind::UnsupportedMediaType,
        ));
    }
    if !accepts_required_response_types(headers) {
        return Err(McpRequestError::new(McpRequestErrorKind::NotAcceptable));
    }
    if declared_body_length(headers)? > max_request_bytes {
        return Err(McpRequestError::new(McpRequestErrorKind::BodyTooLarge));
    }

    let protocol_version = required_unique_header(headers, &PROTOCOL_VERSION_HEADER)?;
    if !valid_bounded_text(&protocol_version, MAX_PROTOCOL_VERSION_BYTES) {
        return Err(McpRequestError::new(McpRequestErrorKind::HeaderMismatch));
    }
    let method = required_unique_header(headers, &METHOD_HEADER)?;
    if !valid_bounded_text(&method, MAX_METHOD_BYTES) {
        return Err(McpRequestError::new(McpRequestErrorKind::HeaderMismatch));
    }
    let name = optional_unique_header(headers, &NAME_HEADER)?
        .map(|value| decode_mirrored_value(&value))
        .transpose()?;

    Ok(McpRequestHead {
        protocol_version,
        method,
        name,
    })
}

/// Collect once under the route cap, parse exactly one JSON document, validate
/// modern per-request metadata, and compare every standard mirrored header.
pub(crate) async fn collect_mcp_json_request<B>(
    head: McpRequestHead,
    body: B,
    max_request_bytes: u64,
    supported_versions: &[String],
) -> Result<McpJsonRequest, McpRequestError>
where
    B: hyper::body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    let limit = usize::try_from(max_request_bytes)
        .map_err(|_| McpRequestError::new(McpRequestErrorKind::BodyTooLarge))?;
    let body = Limited::new(body, limit)
        .collect()
        .await
        .map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                McpRequestError::new(McpRequestErrorKind::BodyTooLarge)
            } else {
                McpRequestError::new(McpRequestErrorKind::BodyReadFailed)
            }
        })?
        .to_bytes();

    let document = parse_unique_json(&body)?;
    let object = document
        .as_object()
        .ok_or_else(|| McpRequestError::new(McpRequestErrorKind::InvalidRequest))?;
    let request_id = parse_request_id(object)?;

    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(McpRequestError::for_request(
            McpRequestErrorKind::InvalidRequest,
            request_id,
        ));
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|value| valid_bounded_text(value, MAX_METHOD_BYTES))
        .ok_or_else(|| {
            McpRequestError::for_request(McpRequestErrorKind::InvalidRequest, request_id.clone())
        })?
        .to_owned();
    let params = object
        .get("params")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            McpRequestError::for_request(McpRequestErrorKind::InvalidRequest, request_id.clone())
        })?;
    let metadata = params
        .get("_meta")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            McpRequestError::for_request(McpRequestErrorKind::InvalidRequest, request_id.clone())
        })?;
    let protocol_version = metadata
        .get(PROTOCOL_VERSION_META)
        .and_then(Value::as_str)
        .filter(|value| valid_bounded_text(value, MAX_PROTOCOL_VERSION_BYTES))
        .ok_or_else(|| {
            McpRequestError::for_request(McpRequestErrorKind::InvalidRequest, request_id.clone())
        })?
        .to_owned();
    if !metadata
        .get(CLIENT_CAPABILITIES_META)
        .is_some_and(Value::is_object)
    {
        return Err(McpRequestError::for_request(
            McpRequestErrorKind::InvalidRequest,
            request_id,
        ));
    }
    if let Some(client_info) = metadata.get(CLIENT_INFO_META) {
        validate_client_info(client_info).map_err(|()| {
            McpRequestError::for_request(McpRequestErrorKind::InvalidRequest, request_id.clone())
        })?;
    }

    let name = applicable_name(&method, params).map_err(|()| {
        McpRequestError::for_request(McpRequestErrorKind::InvalidRequest, request_id.clone())
    })?;
    if head.protocol_version != protocol_version
        || head.method != method
        || head.name.as_deref() != name
    {
        return Err(McpRequestError::for_request(
            McpRequestErrorKind::HeaderMismatch,
            request_id,
        ));
    }
    if !supported_versions
        .iter()
        .any(|supported| supported == &protocol_version)
    {
        return Err(McpRequestError::unsupported(request_id, protocol_version));
    }

    Ok(McpJsonRequest {
        body,
        request_id,
        method,
        name: name.map(str::to_owned),
        protocol_version,
    })
}

fn parse_unique_json(body: &[u8]) -> Result<Value, McpRequestError> {
    let mut deserializer = serde_json::Deserializer::from_slice(body);
    let value = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|_| McpRequestError::new(McpRequestErrorKind::InvalidJson))?
        .0;
    deserializer
        .end()
        .map_err(|_| McpRequestError::new(McpRequestErrorKind::InvalidJson))?;
    Ok(value)
}

fn parse_request_id(object: &Map<String, Value>) -> Result<Option<McpRequestId>, McpRequestError> {
    match object.get("id") {
        None => Ok(None),
        Some(Value::String(value))
            if !value.is_empty()
                && value.len() <= MAX_REQUEST_ID_BYTES
                && !value.chars().any(char::is_control) =>
        {
            Ok(Some(McpRequestId(Value::String(value.clone()))))
        }
        Some(Value::Number(value)) if value.is_i64() || value.is_u64() => {
            Ok(Some(McpRequestId(Value::Number(value.clone()))))
        }
        _ => Err(McpRequestError::new(McpRequestErrorKind::InvalidRequest)),
    }
}

fn validate_client_info(value: &Value) -> Result<(), ()> {
    let object = value.as_object().ok_or(())?;
    for field in ["name", "version"] {
        let value = object.get(field).and_then(Value::as_str).ok_or(())?;
        if !valid_bounded_text(value, MAX_CLIENT_IMPLEMENTATION_FIELD_BYTES) {
            return Err(());
        }
    }
    Ok(())
}

fn applicable_name<'a>(
    method: &str,
    params: &'a Map<String, Value>,
) -> Result<Option<&'a str>, ()> {
    let field = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    let Some(field) = field else {
        return Ok(None);
    };
    let value = params.get(field).and_then(Value::as_str).ok_or(())?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return Err(());
    }
    Ok(Some(value))
}

fn required_unique_header(
    headers: &HeaderMap,
    name: &HeaderName,
) -> Result<String, McpRequestError> {
    optional_unique_header(headers, name)?
        .ok_or_else(|| McpRequestError::new(McpRequestErrorKind::HeaderMismatch))
}

fn optional_unique_header(
    headers: &HeaderMap,
    name: &HeaderName,
) -> Result<Option<String>, McpRequestError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(McpRequestError::new(McpRequestErrorKind::HeaderMismatch));
    }
    let value = value
        .to_str()
        .map_err(|_| McpRequestError::new(McpRequestErrorKind::HeaderMismatch))?;
    Ok(Some(value.to_owned()))
}

fn decode_mirrored_value(value: &str) -> Result<String, McpRequestError> {
    if let Some(encoded) = value
        .strip_prefix(BASE64_PREFIX)
        .and_then(|value| value.strip_suffix(BASE64_SUFFIX))
    {
        if encoded.is_empty() {
            return Err(McpRequestError::new(McpRequestErrorKind::HeaderMismatch));
        }
        let decoded = BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| McpRequestError::new(McpRequestErrorKind::HeaderMismatch))?;
        if BASE64_STANDARD.encode(&decoded) != encoded {
            return Err(McpRequestError::new(McpRequestErrorKind::HeaderMismatch));
        }
        return String::from_utf8(decoded)
            .map_err(|_| McpRequestError::new(McpRequestErrorKind::HeaderMismatch));
    }
    if value.starts_with(BASE64_PREFIX)
        || value.ends_with(BASE64_SUFFIX)
        || value.trim_matches([' ', '\t']) != value
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'\t' | b' '..=b'~'))
    {
        return Err(McpRequestError::new(McpRequestErrorKind::HeaderMismatch));
    }
    Ok(value.to_owned())
}

fn valid_bounded_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn header_bytes(headers: &HeaderMap) -> u64 {
    headers.iter().fold(0_u64, |total, (name, value)| {
        total.saturating_add(
            u64::try_from(name.as_str().len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(value.as_bytes().len()).unwrap_or(u64::MAX))
                .saturating_add(4),
        )
    })
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

fn accepts_required_response_types(headers: &HeaderMap) -> bool {
    let mut json = false;
    let mut event_stream = false;
    let mut saw_value = false;
    for value in headers.get_all(ACCEPT) {
        let Ok(value) = value.to_str() else {
            return false;
        };
        saw_value = true;
        for item in value.split(',') {
            let mut fields = item.split(';');
            let media_type = fields.next().unwrap_or_default().trim();
            let mut allowed = true;
            for parameter in fields {
                let parameter = parameter.trim();
                if let Some(quality) = parameter
                    .strip_prefix("q=")
                    .or_else(|| parameter.strip_prefix("Q="))
                {
                    allowed = quality
                        .parse::<f32>()
                        .is_ok_and(|quality| quality > 0.0 && quality <= 1.0);
                }
            }
            if allowed && media_type.eq_ignore_ascii_case("application/json") {
                json = true;
            }
            if allowed && media_type.eq_ignore_ascii_case("text/event-stream") {
                event_stream = true;
            }
        }
    }
    saw_value && json && event_stream
}

fn declared_body_length(headers: &HeaderMap) -> Result<u64, McpRequestError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(0);
    };
    if values.next().is_some() {
        return Err(McpRequestError::new(McpRequestErrorKind::InvalidRequest));
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| McpRequestError::new(McpRequestErrorKind::InvalidRequest))
}

#[derive(Clone, PartialEq)]
struct McpRequestId(Value);

impl McpRequestId {
    fn into_value(self) -> Value {
        self.0
    }
}

impl Eq for McpRequestId {}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("one JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut entries: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = entries.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = entries.next_value::<UniqueJsonValue>()?;
            object.insert(key, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(object)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    const MAX_HEADERS: u64 = 16 * 1024;
    const MAX_BODY: u64 = 64 * 1024;

    fn headers(method: &str, name: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        );
        headers.insert(
            PROTOCOL_VERSION_HEADER,
            HeaderValue::from_static("2026-07-28"),
        );
        headers.insert(METHOD_HEADER, HeaderValue::from_str(method).unwrap());
        if let Some(name) = name {
            headers.insert(NAME_HEADER, HeaderValue::from_str(name).unwrap());
        }
        headers
    }

    fn request_body(method: &str, extra_params: Value) -> Bytes {
        let mut params = serde_json::json!({
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientInfo": {
                    "name": "gateway-test",
                    "version": "1.0.0"
                },
                "io.modelcontextprotocol/clientCapabilities": {}
            }
        });
        params
            .as_object_mut()
            .unwrap()
            .extend(extra_params.as_object().unwrap().clone());
        Bytes::from(
            serde_json::to_vec(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "request-1",
                "method": method,
                "params": params,
            }))
            .unwrap(),
        )
    }

    async fn validate(headers: &HeaderMap, body: Bytes) -> Result<McpJsonRequest, McpRequestError> {
        let head = validate_mcp_request_head(
            &Method::POST,
            &Uri::from_static("/mcp"),
            "/mcp",
            headers,
            MAX_HEADERS,
            MAX_BODY,
        )?;
        collect_mcp_json_request(head, Full::new(body), MAX_BODY, &["2026-07-28".to_owned()]).await
    }

    #[tokio::test]
    async fn accepts_final_modern_discovery_shape_and_preserves_bytes() {
        let headers = headers("server/discover", None);
        let body = request_body("server/discover", serde_json::json!({}));
        let request = validate(&headers, body.clone()).await.unwrap();

        assert_eq!(request.method(), "server/discover");
        assert_eq!(request.name(), None);
        assert_eq!(request.protocol_version(), "2026-07-28");
        assert!(!request.is_notification());
        assert_eq!(request.into_body(), body);
    }

    #[tokio::test]
    async fn accepts_optional_client_info_absence_from_the_final_schema() {
        let headers = headers("server/discover", None);
        let body = Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        );
        validate(&headers, body).await.unwrap();
    }

    #[tokio::test]
    async fn accepts_request_like_extension_notifications_with_metadata() {
        let headers = headers("com.example/events/changed", None);
        let body = Bytes::from_static(
            br#"{"jsonrpc":"2.0","method":"com.example/events/changed","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        );
        let request = validate(&headers, body).await.unwrap();
        assert!(request.is_notification());
    }

    #[tokio::test]
    async fn validates_all_applicable_plain_names() {
        for (method, field, value) in [
            ("tools/call", "name", "get_weather"),
            ("prompts/get", "name", "code_review"),
            ("resources/read", "uri", "file:///project/readme.md"),
        ] {
            let headers = headers(method, Some(value));
            let mut params = Map::new();
            params.insert(field.to_owned(), Value::String(value.to_owned()));
            let body = request_body(method, Value::Object(params));
            let request = validate(&headers, body).await.unwrap();
            assert_eq!(request.name(), Some(value));
        }
    }

    #[tokio::test]
    async fn decodes_canonical_base64_name_before_comparison() {
        let value = "天气";
        let encoded = format!(
            "{BASE64_PREFIX}{}{BASE64_SUFFIX}",
            BASE64_STANDARD.encode(value)
        );
        let headers = headers("tools/call", Some(&encoded));
        let body = request_body("tools/call", serde_json::json!({ "name": value }));

        let request = validate(&headers, body).await.unwrap();
        assert_eq!(request.name(), Some(value));
    }

    #[tokio::test]
    async fn rejects_missing_and_mismatched_standard_headers() {
        let body = request_body("tools/call", serde_json::json!({ "name": "weather" }));

        for missing in [&PROTOCOL_VERSION_HEADER, &METHOD_HEADER, &NAME_HEADER] {
            let mut request_headers = headers("tools/call", Some("weather"));
            request_headers.remove(missing);
            assert_eq!(
                validate(&request_headers, body.clone())
                    .await
                    .unwrap_err()
                    .kind(),
                McpRequestErrorKind::HeaderMismatch
            );
        }

        let mismatches = [
            (PROTOCOL_VERSION_HEADER, "2025-11-25"),
            (METHOD_HEADER, "tools/list"),
            (NAME_HEADER, "other"),
        ];
        for (name, value) in mismatches {
            let mut request_headers = headers("tools/call", Some("weather"));
            request_headers.insert(name, HeaderValue::from_static(value));
            assert_eq!(
                validate(&request_headers, body.clone())
                    .await
                    .unwrap_err()
                    .kind(),
                McpRequestErrorKind::HeaderMismatch
            );
        }
    }

    #[tokio::test]
    async fn rejects_malformed_or_noncanonical_base64_sentinels() {
        let body = request_body("tools/call", serde_json::json!({ "name": "weather" }));
        for value in [
            "=?base64?not-base64!?=",
            "=?base64?d2VhdGhlcg?=",
            "=?BASE64?d2VhdGhlcg==?=",
            "=?base64?d2VhdGhlcg==",
        ] {
            let request_headers = headers("tools/call", Some(value));
            assert_eq!(
                validate(&request_headers, body.clone())
                    .await
                    .unwrap_err()
                    .kind(),
                McpRequestErrorKind::HeaderMismatch
            );
        }
    }

    #[tokio::test]
    async fn rejects_extra_name_header_for_a_method_without_a_name_source() {
        let headers = headers("server/discover", Some("forged"));
        let body = request_body("server/discover", serde_json::json!({}));
        assert_eq!(
            validate(&headers, body).await.unwrap_err().kind(),
            McpRequestErrorKind::HeaderMismatch
        );
    }

    #[tokio::test]
    async fn rejects_batch_response_and_multiple_json_documents() {
        let headers = headers("server/discover", None);
        for body in [
            Bytes::from_static(br#"[]"#),
            Bytes::from_static(br#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}} {}"#,
            ),
        ] {
            let kind = validate(&headers, body).await.unwrap_err().kind();
            assert!(matches!(
                kind,
                McpRequestErrorKind::InvalidJson | McpRequestErrorKind::InvalidRequest
            ));
        }
    }

    #[tokio::test]
    async fn rejects_duplicate_fields_at_any_depth() {
        let headers = headers("tools/call", Some("second"));
        for body in [
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"second"}}"#,
            ),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-11-25","io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"second"}}"#,
            ),
            Bytes::from_static(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"name":"second","arguments":{"key":1,"key":2}}}"#,
            ),
        ] {
            assert_eq!(
                validate(&headers, body).await.unwrap_err().kind(),
                McpRequestErrorKind::InvalidJson
            );
        }
    }

    #[tokio::test]
    async fn validates_required_request_metadata_shapes() {
        let headers = headers("server/discover", None);
        for body in [
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/clientCapabilities":{}}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":[]}}}"#.as_slice(),
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"client"}}}}"#.as_slice(),
        ] {
            assert_eq!(
                validate(&headers, Bytes::copy_from_slice(body))
                    .await
                    .unwrap_err()
                    .kind(),
                McpRequestErrorKind::InvalidRequest
            );
        }
    }

    #[tokio::test]
    async fn distinguishes_mismatch_from_a_matching_unsupported_version() {
        let mut headers = headers("server/discover", None);
        headers.insert(
            PROTOCOL_VERSION_HEADER,
            HeaderValue::from_static("2030-01-01"),
        );
        let mismatch = request_body("server/discover", serde_json::json!({}));
        assert_eq!(
            validate(&headers, mismatch).await.unwrap_err().kind(),
            McpRequestErrorKind::HeaderMismatch
        );

        let unsupported = Bytes::from_static(
            br#"{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2030-01-01","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        );
        let error = validate(&headers, unsupported).await.unwrap_err();
        assert_eq!(
            error.kind(),
            McpRequestErrorKind::UnsupportedProtocolVersion
        );
        let response = error.into_response(&["2026-07-28".to_owned()]);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let document: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(document["error"]["code"], -32_022);
        assert_eq!(document["error"]["data"]["requested"], "2030-01-01");
        assert_eq!(document["error"]["data"]["supported"][0], "2026-07-28");
    }

    #[tokio::test]
    async fn enforces_head_and_observed_body_limits() {
        let mut oversized_headers = headers("server/discover", None);
        oversized_headers.insert(
            HeaderName::from_static("x-padding"),
            HeaderValue::from_str(&"x".repeat(1_024)).unwrap(),
        );
        assert_eq!(
            validate_mcp_request_head(
                &Method::POST,
                &Uri::from_static("/mcp"),
                "/mcp",
                &oversized_headers,
                32,
                MAX_BODY,
            )
            .unwrap_err()
            .kind(),
            McpRequestErrorKind::HeadersTooLarge
        );

        let mut declared = headers("server/discover", None);
        declared.insert(
            CONTENT_LENGTH,
            HeaderValue::from_static("18446744073709551615"),
        );
        assert_eq!(
            validate_mcp_request_head(
                &Method::POST,
                &Uri::from_static("/mcp"),
                "/mcp",
                &declared,
                MAX_HEADERS,
                MAX_BODY,
            )
            .unwrap_err()
            .kind(),
            McpRequestErrorKind::BodyTooLarge
        );

        let request_head = validate_mcp_request_head(
            &Method::POST,
            &Uri::from_static("/mcp"),
            "/mcp",
            &headers("server/discover", None),
            MAX_HEADERS,
            8,
        )
        .unwrap();
        assert_eq!(
            collect_mcp_json_request(
                request_head,
                Full::new(Bytes::from_static(br#"{"more":"than eight bytes"}"#)),
                8,
                &["2026-07-28".to_owned()],
            )
            .await
            .unwrap_err()
            .kind(),
            McpRequestErrorKind::BodyTooLarge
        );
    }

    #[test]
    fn validates_transport_method_media_and_accept_contract() {
        let valid = headers("server/discover", None);
        assert_eq!(
            validate_mcp_request_head(
                &Method::GET,
                &Uri::from_static("/mcp"),
                "/mcp",
                &valid,
                MAX_HEADERS,
                MAX_BODY,
            )
            .unwrap_err()
            .kind(),
            McpRequestErrorKind::MethodNotAllowed
        );

        let mut missing_type = valid.clone();
        missing_type.remove(CONTENT_TYPE);
        assert_eq!(
            validate_mcp_request_head(
                &Method::POST,
                &Uri::from_static("/mcp"),
                "/mcp",
                &missing_type,
                MAX_HEADERS,
                MAX_BODY,
            )
            .unwrap_err()
            .kind(),
            McpRequestErrorKind::UnsupportedMediaType
        );

        let mut incomplete_accept = valid;
        incomplete_accept.insert(ACCEPT, HeaderValue::from_static("application/json"));
        assert_eq!(
            validate_mcp_request_head(
                &Method::POST,
                &Uri::from_static("/mcp"),
                "/mcp",
                &incomplete_accept,
                MAX_HEADERS,
                MAX_BODY,
            )
            .unwrap_err()
            .kind(),
            McpRequestErrorKind::NotAcceptable
        );
    }

    #[test]
    fn rejects_noncanonical_endpoint_uri_before_body_work() {
        let valid = headers("server/discover", None);
        for uri in ["/other", "/mcp?tenant=spoofed"] {
            assert_eq!(
                validate_mcp_request_head(
                    &Method::POST,
                    &uri.parse().unwrap(),
                    "/mcp",
                    &valid,
                    MAX_HEADERS,
                    MAX_BODY,
                )
                .unwrap_err()
                .kind(),
                McpRequestErrorKind::InvalidRequest,
                "{uri}"
            );
        }
    }

    #[test]
    fn stable_errors_are_bounded_and_do_not_echo_mirrored_values() {
        let error = McpRequestError::for_request(
            McpRequestErrorKind::HeaderMismatch,
            Some(McpRequestId(Value::String("safe-id".into()))),
        );
        let debug = format!("{error:?}");
        assert!(!debug.contains("safe-id"));

        let response = error.into_response(&["2026-07-28".to_owned()]);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
        let document: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(document["id"], "safe-id");
        assert_eq!(document["error"]["code"], -32_020);
        assert!(response.body().len() < 512);
    }
}
