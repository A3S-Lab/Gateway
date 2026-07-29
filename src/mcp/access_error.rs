//! Stable hosted MCP authentication, authorization, and admission failures.

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE};
use http::{HeaderValue, Response, StatusCode};
use serde_json::Value;

/// Request-path failures produced from one locally applied MCP snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum McpAccessError {
    InvalidOrigin,
    Unauthorized,
    Denied,
    Unavailable,
    RateLimited { retry_after_secs: u64 },
    ConcurrencyLimited,
    DataPlaneUnavailable,
    UpstreamUnavailable,
    UpstreamTimeout,
    InvalidUpstreamResponse,
}

impl McpAccessError {
    pub(crate) const fn status(self) -> StatusCode {
        match self {
            Self::InvalidOrigin => StatusCode::FORBIDDEN,
            Self::Denied => StatusCode::NOT_FOUND,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Unavailable | Self::DataPlaneUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::RateLimited { .. } | Self::ConcurrencyLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::UpstreamUnavailable | Self::InvalidUpstreamResponse => StatusCode::BAD_GATEWAY,
            Self::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    pub(crate) fn into_response(self, request_id: Option<Value>) -> Response<Bytes> {
        let (status, code, message, retry_after_secs) = match self {
            Self::InvalidOrigin => (
                StatusCode::FORBIDDEN,
                -32_041,
                "The request Origin is not allowed.",
                None,
            ),
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                -32_040,
                "Invalid authentication credentials.",
                None,
            ),
            Self::Denied => (
                StatusCode::NOT_FOUND,
                -32_041,
                "The requested MCP operation was not found.",
                None,
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                -32_042,
                "MCP authorization is temporarily unavailable.",
                None,
            ),
            Self::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                -32_043,
                "MCP request rate limit exceeded.",
                Some(retry_after_secs),
            ),
            Self::ConcurrencyLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                -32_044,
                "MCP concurrency limit exceeded.",
                Some(1),
            ),
            Self::DataPlaneUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                -32_045,
                "No eligible MCP upstream is available.",
                None,
            ),
            Self::UpstreamUnavailable => (
                StatusCode::BAD_GATEWAY,
                -32_046,
                "The MCP upstream request failed.",
                None,
            ),
            Self::UpstreamTimeout => (
                StatusCode::GATEWAY_TIMEOUT,
                -32_047,
                "The MCP upstream response timed out.",
                None,
            ),
            Self::InvalidUpstreamResponse => (
                StatusCode::BAD_GATEWAY,
                -32_048,
                "The MCP upstream response is invalid.",
                None,
            ),
        };
        let body = serde_json::to_vec(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_id.unwrap_or(Value::Null),
            "error": {
                "code": code,
                "message": message,
            }
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
        if self == Self::Unauthorized {
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"Bearer realm="a3s-mcp""#),
            );
        }
        if let Some(retry_after_secs) = retry_after_secs {
            if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert(RETRY_AFTER, value);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_errors_are_bounded_modern_responses() {
        let cases = [
            (McpAccessError::InvalidOrigin, StatusCode::FORBIDDEN),
            (McpAccessError::Unauthorized, StatusCode::UNAUTHORIZED),
            (McpAccessError::Denied, StatusCode::NOT_FOUND),
            (McpAccessError::Unavailable, StatusCode::SERVICE_UNAVAILABLE),
            (
                McpAccessError::RateLimited {
                    retry_after_secs: 7,
                },
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                McpAccessError::ConcurrencyLimited,
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                McpAccessError::DataPlaneUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (McpAccessError::UpstreamUnavailable, StatusCode::BAD_GATEWAY),
            (McpAccessError::UpstreamTimeout, StatusCode::GATEWAY_TIMEOUT),
            (
                McpAccessError::InvalidUpstreamResponse,
                StatusCode::BAD_GATEWAY,
            ),
        ];
        for (error, status) in cases {
            assert_eq!(error.status(), status);
            let response = error.into_response(Some(Value::String("request-1".into())));
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[CACHE_CONTROL], "no-store");
            assert!(response.body().len() < 512);
            let body: Value = serde_json::from_slice(response.body()).unwrap();
            assert_eq!(body["jsonrpc"], "2.0");
            assert_eq!(body["id"], "request-1");
        }
    }
}
