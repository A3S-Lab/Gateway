//! SSE/Streaming proxy — chunked transfer passthrough for LLM outputs
//!
//! Handles Server-Sent Events (SSE) and other streaming HTTP responses
//! by forwarding the response body as a byte stream without buffering.

use crate::error::{GatewayError, Result};
use crate::service::Backend;
use bytes::Bytes;
use futures_util::Stream;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

/// Shared reqwest client for streaming requests — reuses connection pool across calls
static STREAMING_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Idle read timeout for streaming/SSE responses. This is the max gap the
/// upstream may go silent — NOT a total-request deadline. The API emits an SSE
/// keep-alive every ~10s, so a healthy stream never trips it and can run
/// indefinitely; only a genuinely dead upstream is reaped after this window.
const STREAM_IDLE_TIMEOUT_SECS: u64 = 300;

fn streaming_client() -> &'static reqwest::Client {
    STREAMING_CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .pool_max_idle_per_host(100)
            // read_timeout = per-read (idle) timeout, reset on every byte —
            // unlike .timeout()/RequestBuilder::timeout which caps the *whole*
            // request including the streamed body and hard-killed every SSE
            // stream after 5 minutes regardless of activity.
            .read_timeout(Duration::from_secs(STREAM_IDLE_TIMEOUT_SECS))
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

struct BackendConnectionStream<S> {
    inner: S,
    backend: Option<Arc<Backend>>,
}

impl<S> BackendConnectionStream<S> {
    fn new(inner: S, backend: Arc<Backend>) -> Self {
        Self {
            inner,
            backend: Some(backend),
        }
    }

    fn release(&mut self) {
        if let Some(backend) = self.backend.take() {
            backend.dec_connections();
        }
    }
}

impl<S> Stream for BackendConnectionStream<S>
where
    S: Stream + Unpin,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_mut().get_mut();
        let result = Pin::new(&mut this.inner).poll_next(cx);
        if matches!(&result, Poll::Ready(None)) {
            this.release();
        }
        result
    }
}

impl<S> Drop for BackendConnectionStream<S> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Forward a request to the backend and return a streaming response
pub async fn forward_streaming(
    backend: &Arc<Backend>,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: Bytes,
    first_response_timeout: Duration,
) -> Result<StreamingResponse> {
    let backend_url = backend.url.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let upstream_url = format!("{}{}", backend_url, path_and_query);

    // Reuse shared client — its read_timeout (idle, see STREAM_IDLE_TIMEOUT_SECS)
    // governs streaming liveness. Deliberately NO per-request .timeout() here:
    // reqwest's total-request timeout would cap the whole streamed body and
    // hard-kill every SSE/chunked response after a fixed deadline regardless
    // of activity. The explicit timeout below covers only response-header wait.
    let mut req_builder = streaming_client().request(method.clone(), &upstream_url);

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
    let response = match tokio::time::timeout(first_response_timeout, req_builder.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            backend.dec_connections();
            return Err(GatewayError::UpstreamTransport(format!(
                "Streaming upstream failed before response: {error}"
            )));
        }
        Err(_) => {
            backend.dec_connections();
            return Err(GatewayError::UpstreamTimeout(
                first_response_timeout.as_millis() as u64,
            ));
        }
    };

    let status = response.status();
    let resp_headers = response.headers().clone();
    let body_stream = Box::new(BackendConnectionStream::new(
        response.bytes_stream(),
        backend.clone(),
    ));

    Ok(StreamingResponse {
        status,
        headers: resp_headers,
        body_stream,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a mock HTTP backend that returns a streaming (chunked) response.
    async fn spawn_streaming_backend() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    // Send streaming (chunked) response
                    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
                    let _ = stream.write_all(resp.as_bytes()).await;
                    // Send chunked data
                    let chunk1 = "5\r\nhello\r\n";
                    let chunk2 = "6\r\n world\r\n";
                    let chunk3 = "0\r\n\r\n";
                    let _ = stream.write_all(chunk1.as_bytes()).await;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    let _ = stream.write_all(chunk2.as_bytes()).await;
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    let _ = stream.write_all(chunk3.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

    /// Spawn a mock HTTP backend that returns a regular (non-streaming) response.
    async fn spawn_regular_backend(body: &'static str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let body = body.to_string();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

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

    #[tokio::test]
    async fn test_forward_streaming_success() {
        let backend_addr = spawn_streaming_backend().await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));

        let uri: http::Uri = "/stream".parse().unwrap();
        let result = forward_streaming(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
            Duration::from_secs(5),
        )
        .await;

        assert!(result.is_ok());
        let mut resp = result.unwrap();
        assert_eq!(resp.status, reqwest::StatusCode::OK);
        assert_eq!(backend.connections(), 1);
        while let Some(chunk) = resp.body_stream.next().await {
            chunk.unwrap();
        }
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn test_forward_streaming_regular_response() {
        let backend_addr = spawn_regular_backend("{\"data\": \"test\"}").await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));

        let uri: http::Uri = "/api/data".parse().unwrap();
        let result = forward_streaming(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
            Duration::from_secs(5),
        )
        .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forward_streaming_connection_refused() {
        let backend_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));

        let uri: http::Uri = "/stream".parse().unwrap();
        let result = forward_streaming(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
            Duration::from_secs(5),
        )
        .await;

        assert!(matches!(result, Err(GatewayError::UpstreamTransport(_))));
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn test_forward_streaming_limits_only_first_response_wait() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0_u8; 4096];
            let _ = stream.read(&mut request).await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        });
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));

        let result = forward_streaming(
            &backend,
            &http::Method::GET,
            &"/stream".parse().unwrap(),
            &http::HeaderMap::new(),
            Bytes::new(),
            Duration::from_millis(25),
        )
        .await;

        assert!(matches!(result, Err(GatewayError::UpstreamTimeout(25))));
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn test_forward_streaming_with_body() {
        let backend_addr = spawn_regular_backend("ok").await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));

        let uri: http::Uri = "/upload".parse().unwrap();
        let body = Bytes::from("request body");

        let result = forward_streaming(
            &backend,
            &http::Method::POST,
            &uri,
            &http::HeaderMap::new(),
            body,
            Duration::from_secs(5),
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_forward_streaming_with_headers() {
        let backend_addr = spawn_regular_backend("ok").await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));

        let mut headers = http::HeaderMap::new();
        headers.insert("Authorization", "Bearer token".parse().unwrap());
        headers.insert("Accept", "text/event-stream".parse().unwrap());

        let uri: http::Uri = "/stream".parse().unwrap();
        let result = forward_streaming(
            &backend,
            &http::Method::GET,
            &uri,
            &headers,
            Bytes::new(),
            Duration::from_secs(5),
        )
        .await;

        assert!(result.is_ok());
    }
}
