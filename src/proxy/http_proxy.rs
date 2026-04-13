//! HTTP reverse proxy — forwards requests to upstream backends

use crate::error::{GatewayError, Result};
use crate::service::Backend;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;

/// HTTP reverse proxy
pub struct HttpProxy {
    client: reqwest::Client,
    timeout: Duration,
}

impl HttpProxy {
    /// Create a new HTTP proxy with default settings
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new HTTP proxy with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .pool_max_idle_per_host(100)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_nodelay(true)
            .build()
            .unwrap_or_default();

        Self { client, timeout }
    }

    /// Forward an HTTP request to the selected backend
    pub async fn forward(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<ProxyResponse> {
        backend.inc_connections();
        let result = self.do_forward(backend, method, uri, headers, body).await;
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
    ) -> Result<ProxyResponse> {
        // Build upstream URL
        let backend_url = backend.url.trim_end_matches('/');
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        let upstream_url = format!("{}{}", backend_url, path_and_query);

        // Build the upstream request
        let mut req_builder = self.client.request(method.clone(), &upstream_url);

        // Forward headers (skip hop-by-hop headers)
        for (key, value) in headers.iter() {
            if !is_hop_by_hop(key.as_str()) {
                req_builder = req_builder.header(key.clone(), value.clone());
            }
        }

        // Forward body
        req_builder = req_builder.body(body);

        // Send request
        let response = req_builder.send().await.map_err(|e| {
            if e.is_timeout() {
                GatewayError::UpstreamTimeout(self.timeout.as_millis() as u64)
            } else if e.is_connect() {
                GatewayError::ServiceUnavailable(format!(
                    "Cannot connect to backend {}: {}",
                    backend.url, e
                ))
            } else {
                GatewayError::Http(e)
            }
        })?;

        // Convert response
        let status = response.status();
        let resp_headers = response.headers().clone();
        let resp_body = response.bytes().await.map_err(GatewayError::Http)?;

        Ok(ProxyResponse {
            status,
            headers: resp_headers,
            body: resp_body,
        })
    }
}

impl Default for HttpProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Response from an upstream backend
#[derive(Debug)]
pub struct ProxyResponse {
    /// HTTP status code
    pub status: reqwest::StatusCode,
    /// Response headers
    pub headers: reqwest::header::HeaderMap,
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
    fn test_http_proxy_default() {
        let proxy = HttpProxy::default();
        assert_eq!(proxy.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_http_proxy_custom_timeout() {
        let proxy = HttpProxy::with_timeout(Duration::from_secs(60));
        assert_eq!(proxy.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_proxy_response_fields() {
        let resp = ProxyResponse {
            status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            body: Bytes::from("hello"),
        };
        assert_eq!(resp.status, reqwest::StatusCode::OK);
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
        assert_eq!(resp.status, reqwest::StatusCode::OK);
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
        assert_eq!(resp.status, reqwest::StatusCode::NOT_FOUND);
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
        assert_eq!(resp.status, reqwest::StatusCode::INTERNAL_SERVER_ERROR);
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
