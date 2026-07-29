//! Exact-target, single-attempt hosted MCP dispatch.

use super::authorization::McpDispatchTarget;
use super::McpAccessError;
use crate::error::GatewayError;
use crate::proxy::streaming::{forward_streaming, StreamingResponse, StreamingTimeouts};
use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, Method, StatusCode, Uri};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpResponseKind {
    Json,
    EventStream,
    EmptyNotification,
}

/// Dispatch exactly once to the already selected target. This function has no
/// candidate list and no retry loop, so every transport ambiguity after the
/// call begins is terminal.
pub(crate) async fn dispatch_once(
    target: &McpDispatchTarget,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Bytes,
) -> Result<StreamingResponse, McpAccessError> {
    forward_streaming(
        target.backend(),
        method,
        uri,
        headers,
        body,
        StreamingTimeouts::new(
            target.first_response_timeout(),
            target.stream_idle_timeout(),
            target.stream_total_timeout(),
        ),
    )
    .await
    .map_err(|error| match error {
        GatewayError::UpstreamTimeout(_) => McpAccessError::UpstreamTimeout,
        _ => McpAccessError::UpstreamUnavailable,
    })
}

/// Validate response metadata before exposing upstream headers downstream.
/// Once this function runs an upstream response already exists, so every
/// failure is terminal and must never trigger another dispatch.
pub(crate) fn validate_response_head(
    target: &McpDispatchTarget,
    is_notification: bool,
    status: StatusCode,
    headers: &HeaderMap,
) -> Result<McpResponseKind, McpAccessError> {
    if response_header_bytes(headers) > target.max_response_header_bytes() {
        return Err(McpAccessError::InvalidUpstreamResponse);
    }
    if headers.contains_key("mcp-session-id") {
        return Err(McpAccessError::InvalidUpstreamResponse);
    }
    if declared_response_length(headers)? > target.max_response_bytes() {
        return Err(McpAccessError::InvalidUpstreamResponse);
    }
    if is_notification {
        if status != StatusCode::ACCEPTED || declared_response_length(headers)? != 0 {
            return Err(McpAccessError::InvalidUpstreamResponse);
        }
        return Ok(McpResponseKind::EmptyNotification);
    }

    let content_type = unique_content_type(headers)?;
    if content_type.eq_ignore_ascii_case("application/json") {
        Ok(McpResponseKind::Json)
    } else if content_type.eq_ignore_ascii_case("text/event-stream") && target.request_sse() {
        Ok(McpResponseKind::EventStream)
    } else {
        Err(McpAccessError::InvalidUpstreamResponse)
    }
}

fn response_header_bytes(headers: &HeaderMap) -> u64 {
    headers.iter().fold(0_u64, |total, (name, value)| {
        total.saturating_add(
            u64::try_from(name.as_str().len())
                .unwrap_or(u64::MAX)
                .saturating_add(u64::try_from(value.as_bytes().len()).unwrap_or(u64::MAX))
                .saturating_add(4),
        )
    })
}

fn unique_content_type(headers: &HeaderMap) -> Result<&str, McpAccessError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values
        .next()
        .ok_or(McpAccessError::InvalidUpstreamResponse)?;
    if values.next().is_some() {
        return Err(McpAccessError::InvalidUpstreamResponse);
    }
    let value = value
        .to_str()
        .map_err(|_| McpAccessError::InvalidUpstreamResponse)?;
    Ok(value.split(';').next().unwrap_or_default().trim())
}

fn declared_response_length(headers: &HeaderMap) -> Result<u64, McpAccessError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(0);
    };
    if values.next().is_some() {
        return Err(McpAccessError::InvalidUpstreamResponse);
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or(McpAccessError::InvalidUpstreamResponse)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_kind_is_closed_and_rejects_session_headers() {
        let target = McpDispatchTarget::test_target(true, 128);
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(CONTENT_LENGTH, "64".parse().unwrap());
        assert_eq!(
            validate_response_head(&target, false, StatusCode::OK, &headers).unwrap(),
            McpResponseKind::Json
        );

        headers.insert(CONTENT_TYPE, "text/event-stream".parse().unwrap());
        assert_eq!(
            validate_response_head(&target, false, StatusCode::OK, &headers).unwrap(),
            McpResponseKind::EventStream
        );

        headers.insert("mcp-session-id", "legacy-session".parse().unwrap());
        assert!(matches!(
            validate_response_head(&target, false, StatusCode::OK, &headers),
            Err(McpAccessError::InvalidUpstreamResponse)
        ));

        headers.remove("mcp-session-id");
        let no_sse = McpDispatchTarget::test_target(false, 128);
        assert!(validate_response_head(&no_sse, false, StatusCode::OK, &headers).is_err());

        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(CONTENT_LENGTH, "129".parse().unwrap());
        assert!(validate_response_head(&target, false, StatusCode::OK, &headers).is_err());

        headers.insert(CONTENT_LENGTH, "1".parse().unwrap());
        headers.insert("x-padding", "x".repeat(128).parse().unwrap());
        assert!(validate_response_head(&target, false, StatusCode::OK, &headers).is_err());
    }

    #[test]
    fn notification_requires_an_empty_accepted_response() {
        let target = McpDispatchTarget::test_target(true, 128);
        let mut headers = HeaderMap::new();
        assert_eq!(
            validate_response_head(&target, true, StatusCode::ACCEPTED, &headers).unwrap(),
            McpResponseKind::EmptyNotification
        );
        headers.insert(CONTENT_LENGTH, "1".parse().unwrap());
        assert!(validate_response_head(&target, true, StatusCode::ACCEPTED, &headers).is_err());
        headers.insert(CONTENT_LENGTH, "0".parse().unwrap());
        assert!(validate_response_head(&target, true, StatusCode::OK, &headers).is_err());
    }
}
