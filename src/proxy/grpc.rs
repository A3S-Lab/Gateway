//! gRPC proxy — HTTP/2 (h2c) request forwarding
//!
//! Forwards gRPC requests to upstream backends using HTTP/2 cleartext (h2c).
//! Supports unary, server-streaming, client-streaming, and bidirectional RPCs.

use crate::error::{GatewayError, Result};
use crate::proxy::http_proxy::{
    apply_forwarded_headers, classify_hyper_error, filter_hop_by_hop_headers,
    is_connection_scoped_header, is_forwarded_header, is_hop_by_hop,
};
use crate::proxy::streaming::{checked_deadline, timeout_millis};
use crate::proxy::ForwardedContext;
use crate::service::{Backend, BackendConnectionGuard};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use pin_project_lite::pin_project;
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

type GrpcClient = Client<HttpsConnector<HttpConnector>, GrpcRequestBody>;

pin_project! {
    #[project = GrpcRequestBodyProj]
    enum GrpcRequestBody {
        Buffered {
            #[pin]
            body: Full<Bytes>,
        },
        Streaming {
            #[pin]
            body: Incoming,
        },
    }
}

impl GrpcRequestBody {
    fn buffered(body: Bytes) -> Self {
        Self::Buffered {
            body: Full::new(body),
        }
    }

    fn streaming(body: Incoming) -> Self {
        Self::Streaming { body }
    }
}

impl Body for GrpcRequestBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            GrpcRequestBodyProj::Buffered { body } => match body.poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(sanitize_grpc_frame(frame)))),
                Poll::Ready(Some(Err(never))) => match never {},
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            GrpcRequestBodyProj::Streaming { body } => match body.poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(sanitize_grpc_frame(frame)))),
                Poll::Ready(Some(Err(error))) => Poll::Ready(Some(Err(error))),
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Buffered { body } => body.is_end_stream(),
            Self::Streaming { body } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Buffered { body } => body.size_hint(),
            Self::Streaming { body } => body.size_hint(),
        }
    }
}

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
}

/// Per-request gRPC forwarding policy.
#[derive(Debug, Clone, Copy)]
pub struct GrpcForwardOptions {
    timeouts: GrpcTimeouts,
    forwarded: Option<ForwardedContext>,
}

impl GrpcForwardOptions {
    /// Create options with stream bounds and no downstream forwarding context.
    pub fn new(timeouts: GrpcTimeouts) -> Self {
        Self {
            timeouts,
            forwarded: None,
        }
    }

    /// Regenerate `X-Forwarded-*` metadata from the observed downstream peer.
    pub fn with_forwarded_context(mut self, forwarded: ForwardedContext) -> Self {
        self.forwarded = Some(forwarded);
        self
    }
}

/// gRPC proxy — forwards complete HTTP/2 frame streams, including trailers.
pub struct GrpcProxy {
    client: std::result::Result<GrpcClient, String>,
}

impl GrpcProxy {
    /// Create a new gRPC proxy with default settings
    pub fn new() -> Self {
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

        Self { client }
    }

    /// Forward a downstream request body without collecting it first.
    pub async fn forward_streaming_body(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Incoming,
        options: GrpcForwardOptions,
    ) -> Result<GrpcStreamingResponse> {
        let body = GrpcRequestBody::streaming(body);
        self.do_forward(backend, method, uri, headers, body, options)
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
        options: GrpcForwardOptions,
    ) -> Result<GrpcStreamingResponse> {
        let body = GrpcRequestBody::buffered(body);
        self.do_forward(backend, method, uri, headers, body, options)
            .await
    }

    async fn do_forward(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: GrpcRequestBody,
        options: GrpcForwardOptions,
    ) -> Result<GrpcStreamingResponse> {
        let timeouts = options.timeouts;
        let forwarded = options.forwarded;
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
            if !name.eq_ignore_ascii_case(http::header::TE.as_str())
                && !is_hop_by_hop(name)
                && !is_connection_scoped_header(headers, key)
                && !forwarded.is_some_and(|_| is_forwarded_header(name))
            {
                builder = builder.header(key, value);
            }
        }
        if grpc_te_includes_trailers(headers) {
            builder = builder.header(http::header::TE, "trailers");
        }
        if let Some(context) = forwarded {
            builder = apply_forwarded_headers(builder, headers, context);
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

pin_project! {
    /// gRPC response relay whose body and timer state share one outer box.
    struct BoundedGrpcBody<B> {
        #[pin]
        inner: Option<B>,
        connection: Option<BackendConnectionGuard>,
        idle_timeout: Duration,
        total_timeout: Duration,
        #[pin]
        idle_sleep: tokio::time::Sleep,
        #[pin]
        total_sleep: tokio::time::Sleep,
        finished: bool,
    }
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
            inner: Some(inner),
            connection: Some(connection),
            idle_timeout,
            total_timeout,
            idle_sleep: tokio::time::sleep_until(idle_deadline),
            total_sleep: tokio::time::sleep_until(total_deadline),
            finished: false,
        })
    }
}

fn release_grpc_body<B>(
    mut inner: Pin<&mut Option<B>>,
    connection: &mut Option<BackendConnectionGuard>,
    finished: &mut bool,
) {
    *finished = true;
    inner.as_mut().set(None);
    connection.take();
}

fn grpc_timeout_error(kind: &str, timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "upstream gRPC stream {kind} timeout after {}ms",
            timeout.as_millis()
        ),
    )
}

fn grpc_idle_deadline(idle_timeout: Duration) -> io::Result<Instant> {
    Instant::now().checked_add(idle_timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream_idle_timeout exceeds the platform timer range",
        )
    })
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
        let mut this = self.project();
        if *this.finished {
            return Poll::Ready(None);
        }
        if this.total_sleep.as_mut().poll(context).is_ready() {
            let timeout = *this.total_timeout;
            release_grpc_body(this.inner.as_mut(), this.connection, this.finished);
            return Poll::Ready(Some(Err(grpc_timeout_error("total", timeout))));
        }

        let inner_poll = match this.inner.as_mut().as_pin_mut() {
            Some(mut inner) => inner.as_mut().poll_frame(context),
            None => {
                release_grpc_body(this.inner.as_mut(), this.connection, this.finished);
                return Poll::Ready(None);
            }
        };
        match inner_poll {
            Poll::Ready(Some(Ok(frame))) => {
                let deadline = match grpc_idle_deadline(*this.idle_timeout) {
                    Ok(deadline) => deadline,
                    Err(error) => {
                        release_grpc_body(this.inner.as_mut(), this.connection, this.finished);
                        return Poll::Ready(Some(Err(error)));
                    }
                };
                this.idle_sleep.as_mut().reset(deadline);
                Poll::Ready(Some(Ok(sanitize_grpc_frame(frame))))
            }
            Poll::Ready(Some(Err(error))) => {
                release_grpc_body(this.inner.as_mut(), this.connection, this.finished);
                Poll::Ready(Some(Err(io::Error::other(error))))
            }
            Poll::Ready(None) => {
                release_grpc_body(this.inner.as_mut(), this.connection, this.finished);
                Poll::Ready(None)
            }
            Poll::Pending => {
                if this.idle_sleep.as_mut().poll(context).is_ready() {
                    let timeout = *this.idle_timeout;
                    release_grpc_body(this.inner.as_mut(), this.connection, this.finished);
                    Poll::Ready(Some(Err(grpc_timeout_error("idle", timeout))))
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
                .is_some_and(|inner| inner.is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        self.inner
            .as_ref()
            .map_or_else(SizeHint::default, |inner| inner.size_hint())
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

fn grpc_te_includes_trailers(headers: &http::HeaderMap) -> bool {
    headers.get_all(http::header::TE).iter().any(|value| {
        value
            .as_bytes()
            .split(|byte| *byte == b',')
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"trailers"))
    })
}

fn sanitize_grpc_frame(frame: Frame<Bytes>) -> Frame<Bytes> {
    match frame.into_trailers() {
        Ok(trailers) => Frame::trailers(filter_hop_by_hop_headers(trailers)),
        Err(frame) => frame,
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
        assert!(proxy.client.is_ok());
    }

    #[tokio::test]
    async fn buffered_grpc_request_body_preserves_data() {
        fn assert_unpin<T: Unpin>() {}
        assert_unpin::<GrpcRequestBody>();

        let mut body = GrpcRequestBody::buffered(Bytes::from_static(b"request"));
        assert_eq!(body.size_hint().exact(), Some(7));
        let data = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(data, Bytes::from_static(b"request"));
        assert!(body.frame().await.is_none());
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

    #[test]
    fn test_grpc_te_normalization_detects_only_the_trailers_token() {
        let mut headers = http::HeaderMap::new();
        assert!(!grpc_te_includes_trailers(&headers));

        headers.insert(http::header::TE, "gzip".parse().unwrap());
        assert!(!grpc_te_includes_trailers(&headers));

        headers.insert(http::header::TE, "gzip, Trailers".parse().unwrap());
        assert!(grpc_te_includes_trailers(&headers));
    }

    #[test]
    fn test_grpc_frame_sanitizer_preserves_data_and_filters_trailers() {
        let data = sanitize_grpc_frame(Frame::data(Bytes::from_static(b"frame")))
            .into_data()
            .unwrap();
        assert_eq!(data, Bytes::from_static(b"frame"));

        let mut trailers = http::HeaderMap::new();
        trailers.insert(http::header::CONNECTION, "X-One-Hop".parse().unwrap());
        trailers.insert("X-One-Hop", "removed".parse().unwrap());
        trailers.insert("X-End-To-End", "preserved".parse().unwrap());
        let trailers = sanitize_grpc_frame(Frame::trailers(trailers))
            .into_trailers()
            .unwrap();
        assert!(!trailers.contains_key(http::header::CONNECTION));
        assert!(!trailers.contains_key("x-one-hop"));
        assert_eq!(trailers["x-end-to-end"], "preserved");
    }

    #[tokio::test(start_paused = true)]
    async fn grpc_idle_timeout_releases_backend_connection() {
        let backend = Arc::new(Backend::new("http://unused".to_string(), 1));
        let pending = stream::pending::<std::result::Result<Frame<Bytes>, io::Error>>();
        let body = http_body_util::StreamBody::new(pending);
        let bounded = BoundedGrpcBody::new(
            body,
            backend.track_connection(),
            Instant::now(),
            Duration::from_millis(50),
            Duration::from_secs(1),
        )
        .unwrap();
        tokio::pin!(bounded);

        let error = bounded.as_mut().frame().await.unwrap().unwrap_err();

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
        let bounded = BoundedGrpcBody::new(
            body,
            backend.track_connection(),
            Instant::now(),
            Duration::from_millis(50),
            Duration::from_millis(100),
        )
        .unwrap();
        tokio::pin!(bounded);

        assert_eq!(
            bounded
                .as_mut()
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
                .as_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .data_ref()
                .unwrap()
                .as_ref(),
            b"data"
        );
        let error = bounded.as_mut().frame().await.unwrap().unwrap_err();

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
        let bounded = BoundedGrpcBody::new(
            body,
            backend.track_connection(),
            Instant::now(),
            Duration::from_secs(1),
            Duration::from_secs(2),
        )
        .unwrap();
        tokio::pin!(bounded);

        let trailers = bounded
            .as_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert!(!trailers.contains_key(http::header::CONNECTION));
        assert!(!trailers.contains_key("x-one-hop"));
        assert_eq!(trailers["x-end-to-end"], "preserved");
        assert!(bounded.as_mut().frame().await.is_none());
        assert_eq!(backend.connections(), 0);
    }
}
