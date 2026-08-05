//! HTTP streaming request detection and shared timeout helpers.
//!
//! SSE, NDJSON, and other streaming responses use the same sharded Hyper
//! connection pool and bounded response-body relay as ordinary HTTP traffic.

use crate::error::{GatewayError, Result};
use std::time::Duration;
use tokio::time::Instant;

/// Check whether a request explicitly asks for a Server-Sent Events response.
pub fn is_streaming_request(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"))
}

pub(crate) fn checked_deadline(base: Instant, timeout: Duration, name: &str) -> Result<Instant> {
    base.checked_add(timeout)
        .ok_or_else(|| GatewayError::Config(format!("{name} exceeds the platform timer range")))
}

pub(crate) fn timeout_millis(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_sse_accept_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::ACCEPT, "text/event-stream".parse().unwrap());

        assert!(is_streaming_request(&headers));
    }

    #[test]
    fn ignores_non_streaming_accept_header() {
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::ACCEPT, "application/json".parse().unwrap());

        assert!(!is_streaming_request(&headers));
        assert!(!is_streaming_request(&http::HeaderMap::new()));
    }

    #[test]
    fn timeout_conversion_saturates() {
        assert_eq!(timeout_millis(Duration::from_millis(17)), 17);
    }
}
