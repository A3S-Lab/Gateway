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
        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
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
    matches!(
        name.to_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
