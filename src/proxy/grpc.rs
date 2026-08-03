//! gRPC proxy — HTTP/2 (h2c) request forwarding
//!
//! Forwards gRPC requests to upstream backends using HTTP/2 cleartext (h2c).
//! Supports unary, server-streaming, client-streaming, and bidirectional RPCs.

#![allow(dead_code)]

use crate::error::{GatewayError, Result};
use crate::proxy::http_proxy::{
    classify_hyper_error, filter_hop_by_hop_headers, is_connection_scoped_header, is_hop_by_hop,
};
use crate::proxy::streaming::{checked_deadline, timeout_millis};
use crate::service::{Backend, BackendConnectionGuard};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

/// gRPC content type prefix
const GRPC_CONTENT_TYPE: &str = "application/grpc";

type BoxError = Box<dyn Error + Send + Sync>;
type GrpcRequestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;
type GrpcClient = Client<HttpsConnector<HttpConnector>, GrpcRequestBody>;

/// Downstream-compatible gRPC response body with DATA and trailer frames.
pub type GrpcResponseBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

/// Independent bounds for one gRPC operation.
#[derive(Debug, Clone, Copy)]
pub struct GrpcTimeouts {
    first_response: Duration,
    idle: Duration,
    total: Duration,
}

impl GrpcTimeouts {
    /// Create response-header, idle-stream, and total-operation bounds.
    pub fn new(first_response: Duration, idle: Duration, total: Duration) -> Self {
        Self {
            first_response,
            idle,
            total,
        }
    }

    fn uniform(timeout: Duration) -> Self {
        Self::new(timeout, timeout, timeout)
    }
}

/// gRPC proxy — forwards complete HTTP/2 frame streams, including trailers.
pub struct GrpcProxy {
    client: std::result::Result<GrpcClient, String>,
    timeout: Duration,
}

impl GrpcProxy {
    /// Create a new gRPC proxy with default settings
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(60))
    }

    /// Create with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(Arc::new(rustls::crypto::ring::default_provider()))
            .map(|builder| {
                let connector = builder.https_or_http().enable_http2().build();
                Client::builder(TokioExecutor::new())
                    .http2_only(true)
                    .pool_max_idle_per_host(50)
                    .build(connector)
            })
            .map_err(|error| error.to_string());

        Self { client, timeout }
    }

    /// Forward and collect a gRPC request for compatibility with buffered callers.
    pub async fn forward(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<GrpcResponse> {
        let response = self
            .forward_buffered_streaming(
                backend,
                method,
                uri,
                headers,
                body,
                GrpcTimeouts::uniform(self.timeout),
            )
            .await?;
        let GrpcStreamingResponse {
            http_status,
            headers,
            body,
        } = response;
        let collected = body.collect().await.map_err(|error| {
            if error.kind() == io::ErrorKind::TimedOut {
                GatewayError::UpstreamTimeout(timeout_millis(self.timeout))
            } else {
                GatewayError::ServiceUnavailable(format!("Failed to read gRPC response: {error}"))
            }
        })?;
        let trailers = collected.trailers();
        let grpc_status = grpc_metadata(&headers, trailers, "grpc-status")
            .and_then(|value| value.parse::<i32>().ok())
            .unwrap_or(-1);
        let grpc_message = grpc_metadata(&headers, trailers, "grpc-message").map(str::to_string);

        Ok(GrpcResponse {
            http_status,
            headers,
            body: collected.to_bytes(),
            grpc_status,
            grpc_message,
        })
    }

    /// Forward a downstream request body without collecting it first.
    pub async fn forward_streaming_body(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Incoming,
        timeouts: GrpcTimeouts,
    ) -> Result<GrpcStreamingResponse> {
        let body = body
            .map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync();
        self.do_forward(backend, method, uri, headers, body, timeouts)
            .await
    }

    /// Forward a replayable request body while streaming the upstream response.
    pub async fn forward_buffered_streaming(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
        timeouts: GrpcTimeouts,
    ) -> Result<GrpcStreamingResponse> {
        let body = Full::new(body)
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync();
        self.do_forward(backend, method, uri, headers, body, timeouts)
            .await
    }

    async fn do_forward(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: GrpcRequestBody,
        timeouts: GrpcTimeouts,
    ) -> Result<GrpcStreamingResponse> {
        let operation_started_at = Instant::now();
        let first_response_deadline = checked_deadline(
            operation_started_at,
            timeouts.first_response,
            "request_timeout",
        )?;
        let total_deadline =
            checked_deadline(operation_started_at, timeouts.total, "stream_total_timeout")?;
        let backend_url = normalized_grpc_backend(&backend.url);
        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let upstream_url = format!("{}{path}", backend_url.trim_end_matches('/'));
        let mut builder = http::Request::builder()
            .method(method.clone())
            .version(http::Version::HTTP_2)
            .uri(&upstream_url);

        for (key, value) in headers.iter() {
            let name = key.as_str();
            if !is_grpc_hop_by_hop(name) && !is_connection_scoped_header(headers, key) {
                builder = builder.header(key, value);
            }
        }
        if !headers.contains_key(http::header::CONTENT_TYPE) {
            builder = builder.header(http::header::CONTENT_TYPE, GRPC_CONTENT_TYPE);
        }
        let request = builder.body(body).map_err(|error| {
            GatewayError::Config(format!("Failed to build gRPC request: {error}"))
        })?;
        let connection = backend.track_connection();
        let response_deadline = first_response_deadline.min(total_deadline);
        let client = self.client.as_ref().map_err(|error| {
            GatewayError::Tls(format!("Failed to initialize gRPC TLS client: {error}"))
        })?;
        let response = tokio::time::timeout_at(response_deadline, client.request(request))
            .await
            .map_err(|_| {
                let elapsed_bound = if total_deadline <= first_response_deadline {
                    timeouts.total
                } else {
                    timeouts.first_response
                };
                GatewayError::UpstreamTimeout(timeout_millis(elapsed_bound))
            })?
            .map_err(|error| classify_hyper_error(error, &backend.url))?;
        let (mut parts, body) = response.into_parts();
        parts.headers = filter_hop_by_hop_headers(parts.headers);
        let body = BoundedGrpcBody::new(
            body,
            connection,
            operation_started_at,
            timeouts.idle,
            timeouts.total,
        )?
        .boxed_unsync();

        Ok(GrpcStreamingResponse {
            http_status: parts.status,
            headers: parts.headers,
            body,
        })
    }

    /// Get the timeout
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for GrpcProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Streaming response from a gRPC upstream.
pub struct GrpcStreamingResponse {
    /// HTTP status returned by the upstream.
    pub http_status: http::StatusCode,
    /// End-to-end response headers.
    pub headers: http::HeaderMap,
    /// DATA and trailer frames with independent idle and total bounds.
    pub body: GrpcResponseBody,
}

struct BoundedGrpcBody<B> {
    inner: Option<Pin<Box<B>>>,
    connection: Option<BackendConnectionGuard>,
    idle_timeout: Duration,
    total_timeout: Duration,
    idle_sleep: Pin<Box<tokio::time::Sleep>>,
    total_sleep: Pin<Box<tokio::time::Sleep>>,
    finished: bool,
}

impl<B> BoundedGrpcBody<B> {
    fn new(
        inner: B,
        connection: BackendConnectionGuard,
        operation_started_at: Instant,
        idle_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self> {
        let idle_deadline = checked_deadline(Instant::now(), idle_timeout, "stream_idle_timeout")?;
        let total_deadline =
            checked_deadline(operation_started_at, total_timeout, "stream_total_timeout")?;
        Ok(Self {
            inner: Some(Box::pin(inner)),
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
                "upstream gRPC stream {kind} timeout after {}ms",
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

impl<B> Body for BoundedGrpcBody<B>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(None);
        }
        if this.total_sleep.as_mut().poll(context).is_ready() {
            let timeout = this.total_timeout;
            return Poll::Ready(Some(Err(this.finish_with_timeout("total", timeout))));
        }

        let Some(inner) = this.inner.as_mut() else {
            this.finished = true;
            this.release();
            return Poll::Ready(None);
        };
        match inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Err(error) = this.reset_idle_deadline() {
                    this.finished = true;
                    this.release();
                    return Poll::Ready(Some(Err(error)));
                }
                let frame = match frame.into_trailers() {
                    Ok(trailers) => Frame::trailers(filter_hop_by_hop_headers(trailers)),
                    Err(frame) => frame,
                };
                Poll::Ready(Some(Ok(frame)))
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
                if this.idle_sleep.as_mut().poll(context).is_ready() {
                    let timeout = this.idle_timeout;
                    Poll::Ready(Some(Err(this.finish_with_timeout("idle", timeout))))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
            || self
                .inner
                .as_ref()
                .is_some_and(|inner| inner.as_ref().get_ref().is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.as_ref().map_or_else(SizeHint::default, |inner| {
            inner.as_ref().get_ref().size_hint()
        })
    }
}

impl<B> Drop for BoundedGrpcBody<B> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Response from a gRPC upstream
pub struct GrpcResponse {
    /// HTTP status code
    pub http_status: http::StatusCode,
    /// Response headers
    pub headers: http::HeaderMap,
    /// Response body (protobuf-encoded)
    pub body: Bytes,
    /// gRPC status code (0 = OK)
    pub grpc_status: i32,
    /// gRPC status message
    pub grpc_message: Option<String>,
}

impl GrpcResponse {
    /// Check if the gRPC call succeeded
    pub fn is_ok(&self) -> bool {
        self.grpc_status == 0
    }
}

/// Check if a request looks like a gRPC request
pub fn is_grpc_request(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|content_type| {
            let media_type = content_type
                .split_once(';')
                .map_or(content_type, |(media_type, _)| media_type)
                .trim();
            if media_type.len() < GRPC_CONTENT_TYPE.len() {
                return false;
            }
            let (prefix, suffix) = media_type.split_at(GRPC_CONTENT_TYPE.len());
            prefix.eq_ignore_ascii_case(GRPC_CONTENT_TYPE)
                && (suffix.is_empty() || suffix.starts_with('+') && suffix.len() > 1)
        })
        .unwrap_or(false)
}

/// Normalize the h2c alias and bare backend addresses into HTTP URLs.
fn normalized_grpc_backend(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("h2c://") {
        format!("http://{}", rest.trim_end_matches('/'))
    } else if url.starts_with("http://") || url.starts_with("https://") {
        url.trim_end_matches('/').to_string()
    } else {
        format!("http://{}", url.trim_end_matches('/'))
    }
}

/// Headers that should not be forwarded in gRPC proxying
fn is_grpc_hop_by_hop(name: &str) -> bool {
    is_hop_by_hop(name) && !name.eq_ignore_ascii_case("te")
}

fn grpc_metadata<'a>(
    headers: &'a http::HeaderMap,
    trailers: Option<&'a http::HeaderMap>,
    name: &str,
) -> Option<&'a str> {
    headers
        .get(name)
        .or_else(|| trailers.and_then(|trailers| trailers.get(name)))
        .and_then(|value| value.to_str().ok())
}

/// Standard gRPC status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Parse from integer code
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Ok),
            1 => Some(Self::Cancelled),
            2 => Some(Self::Unknown),
            3 => Some(Self::InvalidArgument),
            4 => Some(Self::DeadlineExceeded),
            5 => Some(Self::NotFound),
            6 => Some(Self::AlreadyExists),
            7 => Some(Self::PermissionDenied),
            8 => Some(Self::ResourceExhausted),
            9 => Some(Self::FailedPrecondition),
            10 => Some(Self::Aborted),
            11 => Some(Self::OutOfRange),
            12 => Some(Self::Unimplemented),
            13 => Some(Self::Internal),
            14 => Some(Self::Unavailable),
            15 => Some(Self::DataLoss),
            16 => Some(Self::Unauthenticated),
            _ => None,
        }
    }

    /// Get the status name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
            Self::Unauthenticated => "UNAUTHENTICATED",
        }
    }
}

impl std::fmt::Display for GrpcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), *self as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;

    // --- GrpcProxy construction ---

    #[test]
    fn test_grpc_proxy_default() {
        let proxy = GrpcProxy::default();
        assert_eq!(proxy.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_grpc_proxy_custom_timeout() {
        let proxy = GrpcProxy::with_timeout(Duration::from_secs(120));
        assert_eq!(proxy.timeout(), Duration::from_secs(120));
    }

    // --- is_grpc_request ---

    #[test]
    fn test_is_grpc_request_true() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/grpc".parse().unwrap());
        assert!(is_grpc_request(&headers));
    }

    #[test]
    fn test_is_grpc_request_with_proto() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/grpc+proto".parse().unwrap());
        assert!(is_grpc_request(&headers));
    }

    #[test]
    fn test_is_grpc_request_is_case_insensitive_and_accepts_parameters() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "Application/Grpc+Proto; charset=utf-8".parse().unwrap(),
        );
        assert!(is_grpc_request(&headers));
    }

    #[test]
    fn test_is_grpc_request_rejects_grpc_web_and_invalid_prefixes() {
        for content_type in [
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/grpcjunk",
            "application/grpc+",
        ] {
            let mut headers = http::HeaderMap::new();
            headers.insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
            assert!(!is_grpc_request(&headers), "accepted {content_type}");
        }
    }

    #[test]
    fn test_is_grpc_request_false() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        assert!(!is_grpc_request(&headers));
    }

    #[test]
    fn test_is_grpc_request_no_content_type() {
        let headers = http::HeaderMap::new();
        assert!(!is_grpc_request(&headers));
    }

    // --- normalized_grpc_backend ---

    #[test]
    fn test_normalized_grpc_backend_h2c() {
        assert_eq!(
            normalized_grpc_backend("h2c://127.0.0.1:50051"),
            "http://127.0.0.1:50051"
        );
    }

    #[test]
    fn test_normalized_grpc_backend_http() {
        assert_eq!(
            normalized_grpc_backend("http://grpc.local:50051"),
            "http://grpc.local:50051"
        );
    }

    #[test]
    fn test_normalized_grpc_backend_https() {
        assert_eq!(
            normalized_grpc_backend("https://grpc.local:443"),
            "https://grpc.local:443"
        );
    }

    #[test]
    fn test_normalized_grpc_backend_bare() {
        assert_eq!(
            normalized_grpc_backend("127.0.0.1:50051"),
            "http://127.0.0.1:50051"
        );
    }

    #[test]
    fn test_normalized_grpc_backend_trailing_slash() {
        assert_eq!(
            normalized_grpc_backend("h2c://127.0.0.1:50051/"),
            "http://127.0.0.1:50051"
        );
    }

    // --- is_grpc_hop_by_hop ---

    #[test]
    fn test_grpc_hop_by_hop() {
        assert!(is_grpc_hop_by_hop("connection"));
        assert!(is_grpc_hop_by_hop("Connection"));
        assert!(is_grpc_hop_by_hop("transfer-encoding"));
        assert!(is_grpc_hop_by_hop("upgrade"));
        assert!(is_grpc_hop_by_hop("trailer"));
        assert!(!is_grpc_hop_by_hop("te"));
        assert!(!is_grpc_hop_by_hop("content-type"));
        assert!(!is_grpc_hop_by_hop("grpc-status"));
        assert!(!is_grpc_hop_by_hop("authorization"));
    }

    // --- GrpcStatus ---

    #[test]
    fn test_grpc_status_from_code() {
        assert_eq!(GrpcStatus::from_code(0), Some(GrpcStatus::Ok));
        assert_eq!(GrpcStatus::from_code(1), Some(GrpcStatus::Cancelled));
        assert_eq!(GrpcStatus::from_code(4), Some(GrpcStatus::DeadlineExceeded));
        assert_eq!(GrpcStatus::from_code(13), Some(GrpcStatus::Internal));
        assert_eq!(GrpcStatus::from_code(14), Some(GrpcStatus::Unavailable));
        assert_eq!(GrpcStatus::from_code(16), Some(GrpcStatus::Unauthenticated));
        assert_eq!(GrpcStatus::from_code(99), None);
        assert_eq!(GrpcStatus::from_code(-1), None);
    }

    #[test]
    fn test_grpc_status_name() {
        assert_eq!(GrpcStatus::Ok.name(), "OK");
        assert_eq!(GrpcStatus::NotFound.name(), "NOT_FOUND");
        assert_eq!(GrpcStatus::Internal.name(), "INTERNAL");
        assert_eq!(GrpcStatus::Unavailable.name(), "UNAVAILABLE");
    }

    #[test]
    fn test_grpc_status_display() {
        assert_eq!(GrpcStatus::Ok.to_string(), "OK (0)");
        assert_eq!(GrpcStatus::NotFound.to_string(), "NOT_FOUND (5)");
        assert_eq!(GrpcStatus::Internal.to_string(), "INTERNAL (13)");
    }

    #[test]
    fn test_grpc_status_all_codes() {
        for code in 0..=16 {
            let status = GrpcStatus::from_code(code);
            assert!(status.is_some(), "Code {} should be valid", code);
            assert_eq!(status.unwrap() as i32, code);
        }
    }

    // --- GrpcResponse ---

    #[test]
    fn test_grpc_response_is_ok() {
        let resp = GrpcResponse {
            http_status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            body: Bytes::new(),
            grpc_status: 0,
            grpc_message: None,
        };
        assert!(resp.is_ok());
    }

    #[test]
    fn test_grpc_response_is_not_ok() {
        let resp = GrpcResponse {
            http_status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            body: Bytes::new(),
            grpc_status: 13,
            grpc_message: Some("internal error".to_string()),
        };
        assert!(!resp.is_ok());
        assert_eq!(resp.grpc_message.as_deref(), Some("internal error"));
    }

    #[test]
    fn grpc_metadata_falls_back_to_trailers() {
        let headers = http::HeaderMap::new();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("grpc-message", "complete".parse().unwrap());

        assert_eq!(
            grpc_metadata(&headers, Some(&trailers), "grpc-status"),
            Some("0")
        );
        assert_eq!(
            grpc_metadata(&headers, Some(&trailers), "grpc-message"),
            Some("complete")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn grpc_idle_timeout_releases_backend_connection() {
        let backend = Arc::new(Backend::new("http://unused".to_string(), 1));
        let pending = stream::pending::<std::result::Result<Frame<Bytes>, io::Error>>();
        let body = http_body_util::StreamBody::new(pending);
        let mut bounded = BoundedGrpcBody::new(
            body,
            backend.track_connection(),
            Instant::now(),
            Duration::from_millis(50),
            Duration::from_secs(1),
        )
        .unwrap();

        let error = bounded.frame().await.unwrap().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("idle"));
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn grpc_total_timeout_wins_while_data_remains_active() {
        let backend = Arc::new(Backend::new("http://unused".to_string(), 1));
        let active = stream::unfold((), |_| async {
            tokio::time::sleep(Duration::from_millis(40)).await;
            Some((
                Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"data"))),
                (),
            ))
        });
        let body = http_body_util::StreamBody::new(active);
        let mut bounded = BoundedGrpcBody::new(
            body,
            backend.track_connection(),
            Instant::now(),
            Duration::from_millis(50),
            Duration::from_millis(100),
        )
        .unwrap();

        assert_eq!(
            bounded
                .frame()
                .await
                .unwrap()
                .unwrap()
                .data_ref()
                .unwrap()
                .as_ref(),
            b"data"
        );
        assert_eq!(
            bounded
                .frame()
                .await
                .unwrap()
                .unwrap()
                .data_ref()
                .unwrap()
                .as_ref(),
            b"data"
        );
        let error = bounded.frame().await.unwrap().unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("total"));
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn dropping_grpc_body_releases_backend_connection() {
        let backend = Arc::new(Backend::new("http://unused".to_string(), 1));
        let pending = stream::pending::<std::result::Result<Frame<Bytes>, io::Error>>();
        let body = http_body_util::StreamBody::new(pending);
        let bounded = BoundedGrpcBody::new(
            body,
            backend.track_connection(),
            Instant::now(),
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .unwrap();
        assert_eq!(backend.connections(), 1);

        drop(bounded);

        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn grpc_trailers_strip_connection_nominated_fields() {
        let backend = Arc::new(Backend::new("http://unused".to_string(), 1));
        let mut trailers = http::HeaderMap::new();
        trailers.insert(http::header::CONNECTION, "X-One-Hop".parse().unwrap());
        trailers.insert("X-One-Hop", "removed".parse().unwrap());
        trailers.insert("X-End-To-End", "preserved".parse().unwrap());
        let frames = stream::iter([Ok::<_, io::Error>(Frame::trailers(trailers))]);
        let body = http_body_util::StreamBody::new(frames);
        let mut bounded = BoundedGrpcBody::new(
            body,
            backend.track_connection(),
            Instant::now(),
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .unwrap();

        let trailers = bounded
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert!(!trailers.contains_key(http::header::CONNECTION));
        assert!(!trailers.contains_key("x-one-hop"));
        assert_eq!(trailers["x-end-to-end"], "preserved");
        assert!(bounded.frame().await.is_none());
        assert_eq!(backend.connections(), 0);
    }
}
