//! SSE/Streaming proxy — chunked transfer passthrough for LLM outputs
//!
//! Handles Server-Sent Events (SSE) and other streaming HTTP responses
//! by forwarding the response body as a byte stream without buffering.

use crate::error::{GatewayError, Result};
use crate::service::Backend;
use bytes::Bytes;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// Shared reqwest client for streaming requests — reuses connection pool across calls
static STREAMING_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn streaming_client() -> &'static reqwest::Client {
    STREAMING_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .pool_max_idle_per_host(100)
            .build()
            .unwrap_or_default()
    })
}

/// Check if a request expects a streaming response
pub fn is_streaming_request(headers: &http::HeaderMap) -> bool {
    // Check Accept header for SSE
    if let Some(accept) = headers.get("Accept").or_else(|| headers.get("accept")) {
        if let Ok(value) = accept.to_str() {
            if value.contains("text/event-stream") {
                return true;
            }
        }
    }
    false
}

/// Check if a response is a streaming response
#[allow(dead_code)]
pub fn is_streaming_response(headers: &reqwest::header::HeaderMap) -> bool {
    // Check Content-Type for SSE
    if let Some(ct) = headers
        .get("Content-Type")
        .or_else(|| headers.get("content-type"))
    {
        if let Ok(value) = ct.to_str() {
            if value.contains("text/event-stream")
                || value.contains("application/x-ndjson")
                || value.contains("application/stream+json")
            {
                return true;
            }
        }
    }

    // Check Transfer-Encoding for chunked
    if let Some(te) = headers
        .get("Transfer-Encoding")
        .or_else(|| headers.get("transfer-encoding"))
    {
        if let Ok(value) = te.to_str() {
            if value.contains("chunked") {
                return true;
            }
        }
    }

    false
}

/// Streaming proxy response — holds the response metadata and a byte stream
pub struct StreamingResponse {
    /// HTTP status code
    pub status: reqwest::StatusCode,
    /// Response headers
    pub headers: reqwest::header::HeaderMap,
    /// Byte stream of the response body
    pub body_stream: Box<dyn futures_util::Stream<Item = reqwest::Result<Bytes>> + Send + Unpin>,
}

/// Forward a request to the backend and return a streaming response
pub async fn forward_streaming(
    backend: &Arc<Backend>,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: Bytes,
    timeout_secs: u64,
) -> Result<StreamingResponse> {
    let backend_url = backend.url.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let upstream_url = format!("{}{}", backend_url, path_and_query);

    // Reuse shared client — connection pool survives across streaming requests
    let mut req_builder = streaming_client()
        .request(method.clone(), &upstream_url)
        .timeout(Duration::from_secs(timeout_secs));

    // Forward headers (skip hop-by-hop) — eq_ignore_ascii_case avoids to_lowercase() alloc
    for (key, value) in headers.iter() {
        let name = key.as_str();
        if !name.eq_ignore_ascii_case("connection")
            && !name.eq_ignore_ascii_case("keep-alive")
            && !name.eq_ignore_ascii_case("transfer-encoding")
            && !name.eq_ignore_ascii_case("upgrade")
        {
            req_builder = req_builder.header(key.clone(), value.clone());
        }
    }

    req_builder = req_builder.body(body);

    backend.inc_connections();
    let response = req_builder.send().await.map_err(|e| {
        backend.dec_connections();
        if e.is_timeout() {
            GatewayError::UpstreamTimeout(timeout_secs * 1000)
        } else {
            GatewayError::ServiceUnavailable(format!("Streaming upstream failed: {}", e))
        }
    })?;

    let status = response.status();
    let resp_headers = response.headers().clone();
    let body_stream = Box::new(response.bytes_stream());

    Ok(StreamingResponse {
        status,
        headers: resp_headers,
        body_stream,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_streaming_request_sse() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Accept", "text/event-stream".parse().unwrap());
        assert!(is_streaming_request(&headers));
    }

    #[test]
    fn test_is_streaming_request_not_sse() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Accept", "application/json".parse().unwrap());
        assert!(!is_streaming_request(&headers));
    }

    #[test]
    fn test_is_streaming_request_empty() {
        let headers = http::HeaderMap::new();
        assert!(!is_streaming_request(&headers));
    }

    #[test]
    fn test_is_streaming_response_sse() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "text/event-stream".parse().unwrap());
        assert!(is_streaming_response(&headers));
    }

    #[test]
    fn test_is_streaming_response_ndjson() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/x-ndjson".parse().unwrap());
        assert!(is_streaming_response(&headers));
    }

    #[test]
    fn test_is_streaming_response_stream_json() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/stream+json".parse().unwrap());
        assert!(is_streaming_response(&headers));
    }

    #[test]
    fn test_is_streaming_response_chunked() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Transfer-Encoding", "chunked".parse().unwrap());
        assert!(is_streaming_response(&headers));
    }

    #[test]
    fn test_is_streaming_response_regular() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        assert!(!is_streaming_response(&headers));
    }

    #[test]
    fn test_is_streaming_response_empty() {
        let headers = reqwest::header::HeaderMap::new();
        assert!(!is_streaming_response(&headers));
    }
}
