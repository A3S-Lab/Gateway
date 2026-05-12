//! HTTP reverse proxy — forwards requests to upstream backends

use crate::error::{GatewayError, Result};
use crate::service::Backend;
use bytes::Bytes;
use http::uri::Authority;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// HTTP reverse proxy with connection-pooling hyper client.
pub struct HttpProxy {
    client: Client<HttpConnector, Full<Bytes>>,
    stream_client: Client<HttpConnector, Incoming>,
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
        connector.set_keepalive(Some(Duration::from_secs(90)));
        connector.set_reuse_address(true);

        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(200)
            .build(connector.clone());

        let stream_client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(200)
            .build(connector);

        Self {
            client,
            stream_client,
            timeout,
        }
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
        backend.inc_connections();
        let result = self
            .do_forward(
                backend,
                method,
                uri,
                headers,
                body,
                ForwardOptions::default(),
            )
            .await;
        backend.dec_connections();
        result
    }

    /// Forward an HTTP request with production data-plane options.
    pub async fn forward_with_options(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
        options: ForwardOptions,
    ) -> Result<ProxyResponse> {
        backend.inc_connections();
        let result = self
            .do_forward(backend, method, uri, headers, body, options)
            .await;
        backend.dec_connections();
        result
    }

    /// Forward with streaming body — zero-copy passthrough of the request body.
    pub async fn forward_streaming_body(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Incoming,
        options: ForwardOptions,
    ) -> Result<ProxyResponse> {
        backend.inc_connections();
        let result = self
            .do_forward_stream(backend, method, uri, headers, body, options)
            .await;
        backend.dec_connections();
        result
    }

    async fn do_forward(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
        options: ForwardOptions,
    ) -> Result<ProxyResponse> {
        let backend_url = backend.url.trim_end_matches('/');
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let mut upstream_uri = String::with_capacity(backend_url.len() + path_and_query.len());
        upstream_uri.push_str(backend_url);
        upstream_uri.push_str(path_and_query);

        let mut builder = http::Request::builder()
            .method(method.clone())
            .uri(&upstream_uri);

        for (key, value) in headers.iter() {
            if !is_hop_by_hop(key.as_str())
                && !options
                    .context
                    .as_ref()
                    .is_some_and(|_| is_forwarded_header(key.as_str()))
            {
                builder = builder.header(key, value);
            }
        }

        if let Some(context) = options.context {
            builder = apply_forwarded_headers(builder, headers, context);
        }

        let req = builder
            .body(Full::new(body))
            .map_err(|e| GatewayError::Config(format!("Failed to build request: {}", e)))?;

        let effective_timeout = options.timeout.unwrap_or(self.timeout);
        let response = tokio::time::timeout(effective_timeout, self.client.request(req))
            .await
            .map_err(|_| GatewayError::UpstreamTimeout(effective_timeout.as_millis() as u64))?
            .map_err(|e| classify_hyper_error(e, &backend.url))?;

        let (parts, incoming) = response.into_parts();
        let resp_body = incoming
            .collect()
            .await
            .map_err(|e| {
                GatewayError::ServiceUnavailable(format!("Failed to read response: {}", e))
            })?
            .to_bytes();

        Ok(ProxyResponse {
            status: parts.status,
            headers: parts.headers,
            body: resp_body,
        })
    }

    async fn do_forward_stream(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Incoming,
        options: ForwardOptions,
    ) -> Result<ProxyResponse> {
        let backend_url = backend.url.trim_end_matches('/');
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        let mut upstream_uri = String::with_capacity(backend_url.len() + path_and_query.len());
        upstream_uri.push_str(backend_url);
        upstream_uri.push_str(path_and_query);

        let mut builder = http::Request::builder()
            .method(method.clone())
            .uri(&upstream_uri);

        for (key, value) in headers.iter() {
            if !is_hop_by_hop(key.as_str())
                && !options
                    .context
                    .as_ref()
                    .is_some_and(|_| is_forwarded_header(key.as_str()))
            {
                builder = builder.header(key, value);
            }
        }

        if let Some(context) = options.context {
            builder = apply_forwarded_headers(builder, headers, context);
        }

        let req = builder
            .body(body)
            .map_err(|e| GatewayError::Config(format!("Failed to build request: {}", e)))?;

        let effective_timeout = options.timeout.unwrap_or(self.timeout);
        let response = tokio::time::timeout(effective_timeout, self.stream_client.request(req))
            .await
            .map_err(|_| GatewayError::UpstreamTimeout(effective_timeout.as_millis() as u64))?
            .map_err(|e| classify_hyper_error(e, &backend.url))?;

        let (parts, incoming) = response.into_parts();
        let resp_body = incoming
            .collect()
            .await
            .map_err(|e| {
                GatewayError::ServiceUnavailable(format!("Failed to read response: {}", e))
            })?
            .to_bytes();

        Ok(ProxyResponse {
            status: parts.status,
            headers: parts.headers,
            body: resp_body,
        })
    }
}

fn classify_hyper_error(e: hyper_util::client::legacy::Error, backend_url: &str) -> GatewayError {
    let msg = e.to_string();
    if msg.contains("connect") || msg.contains("Connection refused") || msg.contains("dns") {
        GatewayError::ServiceUnavailable(format!(
            "Cannot connect to backend {}: {}",
            backend_url, e
        ))
    } else {
        GatewayError::ServiceUnavailable(format!("Upstream error: {}", e))
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
    /// Optional per-service upstream timeout.
    pub timeout: Option<Duration>,
}

/// Response from an upstream backend
#[derive(Debug)]
pub struct ProxyResponse {
    /// HTTP status code
    pub status: http::StatusCode,
    /// Response headers
    pub headers: http::HeaderMap,
    /// Response body
    pub body: Bytes,
}

/// Check if a header is a hop-by-hop header that should not be forwarded
fn is_hop_by_hop(name: &str) -> bool {
    // eq_ignore_ascii_case is zero-allocation; avoids to_lowercase() heap alloc per header
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailers")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

/// Check if a header is generated by the gateway for upstream requests.
fn is_forwarded_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
        || name.eq_ignore_ascii_case("x-forwarded-port")
}

fn apply_forwarded_headers(
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

        assert!(!is_hop_by_hop("Content-Type"));
        assert!(!is_hop_by_hop("Authorization"));
        assert!(!is_hop_by_hop("X-Custom-Header"));
        assert!(!is_hop_by_hop("Host"));
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
            .forward_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
                ForwardOptions {
                    context: None,
                    timeout: Some(Duration::from_millis(50)),
                },
            )
            .await;

        assert!(matches!(result, Err(GatewayError::UpstreamTimeout(50))));
    }

    #[test]
    fn test_proxy_response_fields() {
        let resp = ProxyResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: Bytes::from("hello"),
        };
        assert_eq!(resp.status, http::StatusCode::OK);
        assert_eq!(resp.body, Bytes::from("hello"));
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
        assert_eq!(resp.body, Bytes::from("hello world"));
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
            .forward_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &headers,
                Bytes::new(),
                ForwardOptions {
                    context: Some(context),
                    timeout: None,
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
            .forward_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &headers,
                Bytes::new(),
                ForwardOptions {
                    context: Some(context),
                    timeout: None,
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
        assert_eq!(resp.body, Bytes::from("received"));
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
