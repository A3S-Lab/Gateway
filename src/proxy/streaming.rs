//! SSE/Streaming proxy — chunked transfer passthrough for LLM outputs
//!
//! Handles Server-Sent Events (SSE) and other streaming HTTP responses
//! by forwarding the response body as a byte stream without buffering.

use crate::error::{GatewayError, Result};
use crate::service::{Backend, BackendConnectionGuard};
use bytes::Bytes;
use futures_util::Stream;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

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
    pub body_stream: Box<dyn futures_util::Stream<Item = io::Result<Bytes>> + Send + Unpin>,
}

/// Independent bounds for one upstream streaming operation.
#[derive(Debug, Clone, Copy)]
pub struct StreamingTimeouts {
    first_response: Duration,
    idle: Duration,
    total: Duration,
}

impl StreamingTimeouts {
    /// Create response-header, idle-stream, and total-operation bounds.
    pub fn new(first_response: Duration, idle: Duration, total: Duration) -> Self {
        Self {
            first_response,
            idle,
            total,
        }
    }
}

type UpstreamBodyStream = Pin<Box<dyn futures_util::Stream<Item = reqwest::Result<Bytes>> + Send>>;

struct BoundedStreamingStream {
    inner: Option<UpstreamBodyStream>,
    connection: Option<BackendConnectionGuard>,
    idle_timeout: Duration,
    total_timeout: Duration,
    idle_sleep: Pin<Box<tokio::time::Sleep>>,
    total_sleep: Pin<Box<tokio::time::Sleep>>,
    finished: bool,
}

impl BoundedStreamingStream {
    fn new(
        inner: UpstreamBodyStream,
        connection: BackendConnectionGuard,
        operation_started_at: Instant,
        idle_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self> {
        let idle_deadline = checked_deadline(Instant::now(), idle_timeout, "stream_idle_timeout")?;
        let total_deadline =
            checked_deadline(operation_started_at, total_timeout, "stream_total_timeout")?;
        Ok(Self {
            inner: Some(inner),
            connection: Some(connection),
            idle_timeout,
            total_timeout,
            idle_sleep: Box::pin(tokio::time::sleep_until(idle_deadline)),
            total_sleep: Box::pin(tokio::time::sleep_until(total_deadline)),
            finished: false,
        })
    }

    fn release(&mut self) {
        self.inner.take();
        self.connection.take();
    }

    fn finish_with_timeout(&mut self, kind: &str, timeout: Duration) -> io::Error {
        self.finished = true;
        self.release();
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "upstream stream {kind} timeout after {}ms",
                timeout.as_millis()
            ),
        )
    }

    fn reset_idle_deadline(&mut self) -> io::Result<()> {
        let deadline = Instant::now()
            .checked_add(self.idle_timeout)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "stream_idle_timeout exceeds the platform timer range",
                )
            })?;
        self.idle_sleep.as_mut().reset(deadline);
        Ok(())
    }
}

impl Stream for BoundedStreamingStream {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }

        // Total lifetime is absolute, so it wins even if another chunk became
        // available at the same instant.
        if this.total_sleep.as_mut().poll(cx).is_ready() {
            let timeout = this.total_timeout;
            return Poll::Ready(Some(Err(this.finish_with_timeout("total", timeout))));
        }

        let Some(inner) = this.inner.as_mut() else {
            this.finished = true;
            this.release();
            return Poll::Ready(None);
        };
        // Poll the upstream before the idle timer. Buffered upstream data must
        // not be mistaken for upstream silence when downstream backpressure
        // delayed this poll.
        match inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                if let Err(error) = this.reset_idle_deadline() {
                    this.finished = true;
                    this.release();
                    Poll::Ready(Some(Err(error)))
                } else {
                    Poll::Ready(Some(Ok(bytes)))
                }
            }
            Poll::Ready(Some(Err(error))) => {
                this.finished = true;
                this.release();
                Poll::Ready(Some(Err(io::Error::other(error))))
            }
            Poll::Ready(None) => {
                this.finished = true;
                this.release();
                Poll::Ready(None)
            }
            Poll::Pending => {
                if this.idle_sleep.as_mut().poll(cx).is_ready() {
                    let timeout = this.idle_timeout;
                    Poll::Ready(Some(Err(this.finish_with_timeout("idle", timeout))))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl Drop for BoundedStreamingStream {
    fn drop(&mut self) {
        self.release();
    }
}

fn checked_deadline(base: Instant, timeout: Duration, name: &str) -> Result<Instant> {
    base.checked_add(timeout)
        .ok_or_else(|| GatewayError::Config(format!("{name} exceeds the platform timer range")))
}

fn timeout_millis(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)
}

/// Forward a request to the backend and return a streaming response
pub async fn forward_streaming(
    backend: &Arc<Backend>,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: Bytes,
    timeouts: StreamingTimeouts,
) -> Result<StreamingResponse> {
    let operation_started_at = Instant::now();
    let first_response_deadline = checked_deadline(
        operation_started_at,
        timeouts.first_response,
        "request_timeout",
    )?;
    let total_deadline =
        checked_deadline(operation_started_at, timeouts.total, "stream_total_timeout")?;
    let backend_url = backend.url.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let upstream_url = format!("{}{}", backend_url, path_and_query);

    // Reuse one connection pool and apply service-specific stream bounds to the
    // returned body. A reqwest request timeout would combine response-header
    // and body lifetime and could not reset the idle bound after each chunk.
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

    let connection = backend.track_connection();
    let response_deadline = first_response_deadline.min(total_deadline);
    let response = match tokio::time::timeout_at(response_deadline, req_builder.send()).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => {
            return Err(GatewayError::UpstreamTransport(format!(
                "Streaming upstream failed before response: {error}"
            )));
        }
        Err(_) => {
            let elapsed_bound = if total_deadline <= first_response_deadline {
                timeouts.total
            } else {
                timeouts.first_response
            };
            return Err(GatewayError::UpstreamTimeout(timeout_millis(elapsed_bound)));
        }
    };

    let status = response.status();
    let resp_headers = response.headers().clone();
    let body_stream = Box::new(BoundedStreamingStream::new(
        Box::pin(response.bytes_stream()),
        connection,
        operation_started_at,
        timeouts.idle,
        timeouts.total,
    )?);

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

    fn timeouts(first_response: Duration, idle: Duration, total: Duration) -> StreamingTimeouts {
        StreamingTimeouts::new(first_response, idle, total)
    }

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
            timeouts(
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
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

    #[tokio::test(start_paused = true)]
    async fn stream_idle_timeout_releases_the_backend_connection() {
        let backend = Arc::new(Backend::new("http://unused".to_string(), 1));
        let inner = futures_util::stream::pending::<reqwest::Result<Bytes>>();
        let started_at = tokio::time::Instant::now();
        let mut stream = BoundedStreamingStream::new(
            Box::pin(inner),
            backend.track_connection(),
            started_at,
            Duration::from_millis(50),
            Duration::from_secs(1),
        )
        .unwrap();

        let error = stream.next().await.unwrap().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("idle"));
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_idle_timeout_resets_after_each_chunk() {
        let inner = futures_util::stream::unfold(0_u8, |index| async move {
            if index == 3 {
                futures_util::future::pending().await
            } else {
                tokio::time::sleep(Duration::from_millis(40)).await;
                Some((Ok(Bytes::from(vec![index])), index + 1))
            }
        });
        let backend = Arc::new(Backend::new("http://unused".to_string(), 1));
        let started_at = tokio::time::Instant::now();
        let mut stream = BoundedStreamingStream::new(
            Box::pin(inner),
            backend.track_connection(),
            started_at,
            Duration::from_millis(50),
            Duration::from_secs(1),
        )
        .unwrap();

        for expected in 0_u8..3 {
            assert_eq!(
                stream.next().await.unwrap().unwrap(),
                Bytes::from(vec![expected])
            );
        }
        let error = stream.next().await.unwrap().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("idle"));
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_total_timeout_wins_despite_continued_chunks() {
        let inner = futures_util::stream::unfold(0_u8, |index| async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some((Ok(Bytes::from(vec![index])), index.wrapping_add(1)))
        });
        let backend = Arc::new(Backend::new("http://unused".to_string(), 1));
        let started_at = tokio::time::Instant::now();
        let mut stream = BoundedStreamingStream::new(
            Box::pin(inner),
            backend.track_connection(),
            started_at,
            Duration::from_millis(50),
            Duration::from_millis(100),
        )
        .unwrap();

        for expected in 0_u8..4 {
            assert_eq!(
                stream.next().await.unwrap().unwrap(),
                Bytes::from(vec![expected])
            );
        }
        let error = stream.next().await.unwrap().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("total"));
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
            timeouts(
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
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
            timeouts(
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
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
            timeouts(
                Duration::from_millis(25),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
        )
        .await;

        assert!(matches!(result, Err(GatewayError::UpstreamTimeout(25))));
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn test_forward_streaming_total_timeout_includes_first_response_wait() {
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
            timeouts(
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_millis(25),
            ),
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
            timeouts(
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
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
            timeouts(
                Duration::from_secs(5),
                Duration::from_secs(5),
                Duration::from_secs(60),
            ),
        )
        .await;

        assert!(result.is_ok());
    }
}
