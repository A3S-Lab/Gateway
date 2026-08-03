//! HTTP reverse proxy — forwards requests to upstream backends

use crate::error::{GatewayError, Result};
use crate::proxy::http_response_body::bounded_http_body;
use crate::proxy::streaming::{checked_deadline, timeout_millis};
use crate::service::{Backend, BackendConnectionGuard};
use bytes::Bytes;
use http::uri::Authority;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

type BoxError = Box<dyn Error + Send + Sync>;
type ProxyRequestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, BoxError>;

/// Downstream-compatible ordinary HTTP response body.
pub type ProxyResponseBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

/// Independent bounds for one ordinary HTTP upstream operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTimeouts {
    first_response: Duration,
    idle: Duration,
    total: Duration,
}

impl HttpTimeouts {
    /// Create response-header, idle-body, and total-operation bounds.
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

/// HTTP reverse proxy with connection-pooling hyper client.
pub struct HttpProxy {
    client: Client<HttpConnector, ProxyRequestBody>,
    timeout: Duration,
}

impl HttpProxy {
    /// Create a new HTTP proxy with default settings
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new HTTP proxy with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);
        // TCP keepalive 15s (was 90s): detect a dead upstream (e.g. a backend pod
        // terminated during a K8s rollout) and tear the socket down promptly.
        connector.set_keepalive(Some(Duration::from_secs(15)));
        connector.set_reuse_address(true);

        // pool_idle_timeout 5s (was 90s): hyper keys the idle connection pool by hostname,
        // NOT by resolved IP. When a backend pod rolls (Deployment rollout → new pod IP),
        // pooled keep-alive sockets to the OLD pod IP linger and get reused → SendRequest
        // fails → passive-health marks the backend unhealthy → the half-open recovery probe
        // reuses ANOTHER stale socket → permanent 503 "No healthy backends" until the gateway
        // is restarted. Evicting idle sockets after 5s (well under passive-health
        // recovery_time, 10s) guarantees the half-open probe opens a FRESH connection that
        // re-resolves DNS to the new pod IP — so the gateway self-heals after a rollout
        // instead of requiring a manual restart.
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(200)
            .build(connector);

        Self { client, timeout }
    }

    /// Forward an HTTP request to the selected backend (buffered body).
    pub async fn forward(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<ProxyResponse> {
        self.do_forward_buffered(
            backend,
            method,
            uri,
            headers,
            full_request_body(body),
            ForwardOptions::default(),
        )
        .await
    }

    /// Forward a buffered request while relaying the upstream response body.
    pub async fn forward_streaming_response_with_options(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
        options: ForwardOptions,
    ) -> Result<StreamingProxyResponse> {
        self.do_forward_streaming(
            backend,
            method,
            uri,
            headers,
            full_request_body(body),
            options,
        )
        .await
    }

    /// Forward both the downstream request and upstream response without collection.
    pub async fn forward_streaming_exchange(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Incoming,
        options: ForwardOptions,
    ) -> Result<StreamingProxyResponse> {
        self.do_forward_streaming(
            backend,
            method,
            uri,
            headers,
            incoming_request_body(body),
            options,
        )
        .await
    }

    async fn do_forward_buffered(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: ProxyRequestBody,
        options: ForwardOptions,
    ) -> Result<ProxyResponse> {
        let pending = self
            .send_request(backend, method, uri, headers, body, options)
            .await?;
        let status = pending.parts.status;
        let mut body = bounded_http_body(
            pending.body,
            pending.connection,
            pending.operation_started_at,
            pending.timeouts.idle,
            pending.timeouts.total,
        )?;
        while let Some(frame) = body.frame().await {
            frame.map_err(|error| {
                GatewayError::ServiceUnavailable(format!("Failed to read response: {error}"))
            })?;
        }

        Ok(ProxyResponse { status })
    }

    async fn do_forward_streaming(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: ProxyRequestBody,
        options: ForwardOptions,
    ) -> Result<StreamingProxyResponse> {
        let pending = self
            .send_request(backend, method, uri, headers, body, options)
            .await?;
        let body = bounded_http_body(
            pending.body,
            pending.connection,
            pending.operation_started_at,
            pending.timeouts.idle,
            pending.timeouts.total,
        )?;
        Ok(StreamingProxyResponse {
            status: pending.parts.status,
            headers: pending.parts.headers,
            body,
        })
    }

    async fn send_request(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: ProxyRequestBody,
        options: ForwardOptions,
    ) -> Result<PendingProxyResponse> {
        let timeouts = options
            .timeouts
            .unwrap_or_else(|| HttpTimeouts::uniform(self.timeout));
        let operation_started_at = Instant::now();
        let first_response_deadline = checked_deadline(
            operation_started_at,
            timeouts.first_response,
            "request_timeout",
        )?;
        let total_deadline =
            checked_deadline(operation_started_at, timeouts.total, "stream_total_timeout")?;
        let request = build_upstream_request(backend, method, uri, headers, body, options.context)?;
        let connection = backend.track_connection();
        let response_deadline = first_response_deadline.min(total_deadline);
        let response = tokio::time::timeout_at(response_deadline, self.client.request(request))
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
        Ok(PendingProxyResponse {
            parts,
            body,
            connection,
            operation_started_at,
            timeouts,
        })
    }
}

struct PendingProxyResponse {
    parts: http::response::Parts,
    body: Incoming,
    connection: BackendConnectionGuard,
    operation_started_at: Instant,
    timeouts: HttpTimeouts,
}

fn full_request_body(body: Bytes) -> ProxyRequestBody {
    Full::new(body)
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

fn incoming_request_body(body: Incoming) -> ProxyRequestBody {
    body.map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync()
}

fn build_upstream_request(
    backend: &Backend,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: ProxyRequestBody,
    context: Option<ForwardedContext>,
) -> Result<http::Request<ProxyRequestBody>> {
    let backend_url = backend.url.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let mut upstream_uri = String::with_capacity(backend_url.len() + path_and_query.len());
    upstream_uri.push_str(backend_url);
    upstream_uri.push_str(path_and_query);
    let mut builder = http::Request::builder()
        .method(method.clone())
        .uri(&upstream_uri);

    for (key, value) in headers.iter() {
        if !is_hop_by_hop_header(headers, key)
            && !context.is_some_and(|_| is_forwarded_header(key.as_str()))
        {
            builder = builder.header(key, value);
        }
    }
    if let Some(context) = context {
        builder = apply_forwarded_headers(builder, headers, context);
    }
    builder
        .body(body)
        .map_err(|error| GatewayError::Config(format!("Failed to build request: {error}")))
}

pub(crate) fn classify_hyper_error(
    e: hyper_util::client::legacy::Error,
    backend_url: &str,
) -> GatewayError {
    let msg = e.to_string();
    if msg.contains("connect") || msg.contains("Connection refused") || msg.contains("dns") {
        GatewayError::UpstreamTransport(format!("Cannot connect to backend {}: {}", backend_url, e))
    } else {
        GatewayError::UpstreamTransport(format!("Upstream request failed: {}", e))
    }
}

impl Default for HttpProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheme observed on the downstream gateway entrypoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardedProto {
    /// Plain HTTP traffic.
    Http,
    /// TLS-terminated HTTPS traffic.
    Https,
}

impl ForwardedProto {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn default_port(self) -> &'static str {
        match self {
            Self::Http => "80",
            Self::Https => "443",
        }
    }
}

/// Downstream request context used to generate reverse-proxy forwarding headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardedContext {
    /// Client socket address observed by the gateway.
    pub remote_addr: SocketAddr,
    /// Scheme observed by the gateway entrypoint.
    pub proto: ForwardedProto,
}

impl ForwardedContext {
    /// Create a new forwarding context.
    pub fn new(remote_addr: SocketAddr, proto: ForwardedProto) -> Self {
        Self { remote_addr, proto }
    }
}

/// Per-request HTTP proxy options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardOptions {
    /// Downstream request context for X-Forwarded-* generation.
    pub context: Option<ForwardedContext>,
    /// Optional per-service response-header, idle-body, and total bounds.
    pub timeouts: Option<HttpTimeouts>,
}

/// Response from an upstream backend
#[derive(Debug)]
pub struct ProxyResponse {
    /// HTTP status code
    pub status: http::StatusCode,
}

/// Streaming response from an ordinary HTTP upstream.
pub struct StreamingProxyResponse {
    /// HTTP status returned by the upstream.
    pub status: http::StatusCode,
    /// End-to-end response headers.
    pub headers: http::HeaderMap,
    /// DATA and safe trailer frames with independent idle and total bounds.
    pub body: ProxyResponseBody,
}

/// Check if a header is a hop-by-hop header that should not be forwarded
pub(crate) fn is_hop_by_hop(name: &str) -> bool {
    // eq_ignore_ascii_case is zero-allocation; avoids to_lowercase() heap alloc per header
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("trailers")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

/// Check both standard hop-by-hop fields and fields nominated by Connection.
pub(crate) fn is_hop_by_hop_header(
    headers: &http::HeaderMap,
    name: &http::header::HeaderName,
) -> bool {
    is_hop_by_hop(name.as_str()) || is_connection_scoped_header(headers, name)
}

/// Check whether any Connection field nominates this header for one hop only.
pub(crate) fn is_connection_scoped_header(
    headers: &http::HeaderMap,
    name: &http::header::HeaderName,
) -> bool {
    let expected = name.as_str().as_bytes();
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .any(|value| {
            value
                .as_bytes()
                .split(|byte| *byte == b',')
                .any(|option| option.trim_ascii().eq_ignore_ascii_case(expected))
        })
}

/// Move only end-to-end fields out of an upstream or downstream header map.
pub(crate) fn filter_hop_by_hop_headers(headers: http::HeaderMap) -> http::HeaderMap {
    let connection_scoped = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|option| http::header::HeaderName::from_bytes(option.trim_ascii()).ok())
        .collect::<Vec<_>>();
    let mut filtered = http::HeaderMap::with_capacity(headers.len());
    let mut current_name = None;
    for (name, value) in headers {
        if let Some(name) = name {
            current_name = Some(name);
        }
        let Some(name) = current_name.as_ref() else {
            continue;
        };
        if !is_hop_by_hop(name.as_str()) && !connection_scoped.contains(name) {
            filtered.append(name.clone(), value);
        }
    }
    filtered
}

/// Check if a header is generated by the gateway for upstream requests.
pub(crate) fn is_forwarded_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
        || name.eq_ignore_ascii_case("x-forwarded-port")
}

pub(crate) fn apply_forwarded_headers(
    mut builder: http::request::Builder,
    headers: &http::HeaderMap,
    context: ForwardedContext,
) -> http::request::Builder {
    builder = builder.header("x-forwarded-for", forwarded_for_value(headers, context));

    if let Some(host) = forwarded_host_value(headers) {
        builder = builder.header("x-forwarded-host", host);
    }

    builder = builder.header("x-forwarded-proto", context.proto.as_str());
    builder = builder.header("x-forwarded-port", forwarded_port_value(headers, context));
    builder
}

fn forwarded_for_value(headers: &http::HeaderMap, context: ForwardedContext) -> String {
    let client_ip = context.remote_addr.ip().to_string();
    match header_str(headers, "x-forwarded-for") {
        Some(existing) if !existing.trim().is_empty() => {
            format!("{}, {}", existing.trim(), client_ip)
        }
        _ => client_ip,
    }
}

fn forwarded_host_value(headers: &http::HeaderMap) -> Option<String> {
    let host = header_str(headers, "host");
    let existing = header_str(headers, "x-forwarded-host");

    match (existing, host) {
        (Some(existing), Some(host)) if !existing.trim().is_empty() => {
            Some(format!("{}, {}", existing.trim(), host.trim()))
        }
        (_, Some(host)) if !host.trim().is_empty() => Some(host.trim().to_string()),
        (Some(existing), _) if !existing.trim().is_empty() => Some(existing.trim().to_string()),
        _ => None,
    }
}

fn forwarded_port_value(headers: &http::HeaderMap, context: ForwardedContext) -> String {
    let default_port = context.proto.default_port();
    let host = header_str(headers, "host").or_else(|| header_str(headers, "x-forwarded-host"));

    host.and_then(|value| value.trim().parse::<Authority>().ok())
        .and_then(|authority| authority.port_u16())
        .map(|port| port.to_string())
        .unwrap_or_else(|| default_port.to_string())
}

fn header_str<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a mock HTTP backend that returns a configurable response.
    async fn spawn_mock_backend(status: u16, body: &'static str, delay_ms: u64) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let body = body.to_string();
                let status = status;
                let delay = delay_ms;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                    let resp = format!(
                        "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                        status,
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

    /// Spawn a backend that captures one raw HTTP request and returns 200 OK.
    async fn spawn_capture_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(request);

            let body = "ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        (addr, rx)
    }

    fn captured_header(request: &str, name: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("Keep-Alive"));
        assert!(is_hop_by_hop("Transfer-Encoding"));
        assert!(is_hop_by_hop("Upgrade"));
        assert!(is_hop_by_hop("Proxy-Authorization"));
        assert!(is_hop_by_hop("Proxy-Connection"));
        assert!(is_hop_by_hop("Trailer"));

        assert!(!is_hop_by_hop("Content-Type"));
        assert!(!is_hop_by_hop("Authorization"));
        assert!(!is_hop_by_hop("X-Custom-Header"));
        assert!(!is_hop_by_hop("Host"));
    }

    #[test]
    fn test_connection_nominated_headers_are_hop_by_hop() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            "keep-alive, X-First-Hop".parse().unwrap(),
        );
        headers.append(http::header::CONNECTION, "X-Second-Hop".parse().unwrap());
        headers.insert("X-First-Hop", "one".parse().unwrap());
        headers.insert("X-Second-Hop", "two".parse().unwrap());
        headers.insert("X-End-To-End", "preserved".parse().unwrap());
        headers.append(http::header::SET_COOKIE, "first=1".parse().unwrap());
        headers.append(http::header::SET_COOKIE, "second=2".parse().unwrap());

        assert!(is_hop_by_hop_header(
            &headers,
            &http::header::HeaderName::from_static("x-first-hop")
        ));
        assert!(is_hop_by_hop_header(
            &headers,
            &http::header::HeaderName::from_static("x-second-hop")
        ));

        let filtered = filter_hop_by_hop_headers(headers);
        assert!(!filtered.contains_key(http::header::CONNECTION));
        assert!(!filtered.contains_key("x-first-hop"));
        assert!(!filtered.contains_key("x-second-hop"));
        assert_eq!(filtered["x-end-to-end"], "preserved");
        assert_eq!(filtered.get_all(http::header::SET_COOKIE).iter().count(), 2);
    }

    #[test]
    fn test_forwarded_context_helpers() {
        let context =
            ForwardedContext::new("203.0.113.10:50123".parse().unwrap(), ForwardedProto::Https);
        assert_eq!(context.proto.as_str(), "https");
        assert_eq!(context.proto.default_port(), "443");
    }

    #[test]
    fn test_http_proxy_default() {
        let proxy = HttpProxy::default();
        assert_eq!(proxy.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_http_proxy_custom_timeout() {
        let proxy = HttpProxy::with_timeout(Duration::from_secs(60));
        assert_eq!(proxy.timeout, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_forward_with_options_uses_request_timeout() {
        let backend_addr = spawn_mock_backend(200, "slow", 200).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/slow".parse().unwrap();
        let result = proxy
            .forward_streaming_response_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
                ForwardOptions {
                    context: None,
                    timeouts: Some(HttpTimeouts::new(
                        Duration::from_millis(50),
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                    )),
                },
            )
            .await;

        assert!(matches!(result, Err(GatewayError::UpstreamTimeout(50))));
    }

    #[test]
    fn test_proxy_response_fields() {
        let resp = ProxyResponse {
            status: http::StatusCode::OK,
        };
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forward_success() {
        let backend_addr = spawn_mock_backend(200, "hello world", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/test".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forward_404_response() {
        let backend_addr = spawn_mock_backend(404, "not found", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/missing".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_forward_500_response() {
        let backend_addr = spawn_mock_backend(500, "internal error", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/error".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_forward_connection_refused() {
        // Use a port that nothing is listening on
        let backend_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/test".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_forward_with_headers() {
        let backend_addr = spawn_mock_backend(200, "ok", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let mut headers = http::HeaderMap::new();
        headers.insert("X-Custom-Header", "custom-value".parse().unwrap());
        headers.insert("Authorization", "Bearer token".parse().unwrap());
        // Connection header should be filtered (hop-by-hop)
        headers.insert("Connection", "close".parse().unwrap());

        let uri: http::Uri = "/headers".parse().unwrap();
        let result = proxy
            .forward(&backend, &http::Method::GET, &uri, &headers, Bytes::new())
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_forward_with_options_adds_forwarded_headers() {
        let (backend_addr, captured) = spawn_capture_backend().await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let mut headers = http::HeaderMap::new();
        headers.insert("Host", "api.example.test:8443".parse().unwrap());
        headers.insert("Connection", "close".parse().unwrap());

        let context =
            ForwardedContext::new("203.0.113.42:53100".parse().unwrap(), ForwardedProto::Https);
        let uri: http::Uri = "/headers?debug=true".parse().unwrap();
        let result = proxy
            .forward_streaming_response_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &headers,
                Bytes::new(),
                ForwardOptions {
                    context: Some(context),
                    timeouts: None,
                },
            )
            .await;

        assert!(result.is_ok());
        let request = captured.await.unwrap();
        assert_eq!(
            captured_header(&request, "x-forwarded-for").as_deref(),
            Some("203.0.113.42")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-host").as_deref(),
            Some("api.example.test:8443")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-proto").as_deref(),
            Some("https")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-port").as_deref(),
            Some("8443")
        );
        assert!(captured_header(&request, "connection").is_none());
    }

    #[tokio::test]
    async fn test_forward_with_options_appends_forwarded_for() {
        let (backend_addr, captured) = spawn_capture_backend().await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let mut headers = http::HeaderMap::new();
        headers.insert("Host", "api.example.test".parse().unwrap());
        headers.insert("X-Forwarded-For", "198.51.100.10".parse().unwrap());
        headers.insert("X-Forwarded-Proto", "https".parse().unwrap());

        let context =
            ForwardedContext::new("127.0.0.1:53101".parse().unwrap(), ForwardedProto::Http);
        let uri: http::Uri = "/chain".parse().unwrap();
        let result = proxy
            .forward_streaming_response_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &headers,
                Bytes::new(),
                ForwardOptions {
                    context: Some(context),
                    timeouts: None,
                },
            )
            .await;

        assert!(result.is_ok());
        let request = captured.await.unwrap();
        assert_eq!(
            captured_header(&request, "x-forwarded-for").as_deref(),
            Some("198.51.100.10, 127.0.0.1")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-proto").as_deref(),
            Some("http")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-port").as_deref(),
            Some("80")
        );
    }

    #[tokio::test]
    async fn test_forward_with_body() {
        let backend_addr = spawn_mock_backend(200, "received", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/upload".parse().unwrap();
        let body = Bytes::from("request body content");

        let result = proxy
            .forward(
                &backend,
                &http::Method::POST,
                &uri,
                &http::HeaderMap::new(),
                body,
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forward_path_and_query_preserved() {
        let backend_addr = spawn_mock_backend(200, "ok", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        // Test path and query string are preserved
        let uri: http::Uri = "/api/items?id=123&filter=name".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
    }
}
