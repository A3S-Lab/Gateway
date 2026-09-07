//! Forward auth middleware — delegate authentication to an external service
//!
//! Sends a verification request to an external auth service (Keycloak, Auth0,
//! Authelia, etc.) before allowing the request through. On 2xx response,
//! copies configured headers from the auth response to the upstream request.
//! On non-2xx, short-circuits with the auth service's status code.

use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use bytes::BytesMut;
use futures_util::StreamExt;
use http::Response;
use std::time::Duration;

const FORWARD_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const FORWARD_AUTH_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_AUTH_RESPONSE_BYTES: usize = 64 * 1024;

/// Forward auth middleware
pub struct ForwardAuthMiddleware {
    /// URL of the external auth service
    auth_url: String,
    /// Headers to copy from auth response to upstream request
    response_headers: Vec<String>,
    /// HTTP client for auth requests
    client: reqwest::Client,
}

impl ForwardAuthMiddleware {
    /// Create from middleware config
    pub fn new(config: &MiddlewareConfig) -> Result<Self> {
        let auth_url = config.forward_auth_url.as_deref().ok_or_else(|| {
            GatewayError::Config(
                "forward-auth middleware requires 'forward_auth_url' field".to_string(),
            )
        })?;

        validate_auth_url(auth_url)?;
        validate_response_headers(&config.forward_auth_response_headers)?;

        Ok(Self {
            auth_url: auth_url.to_string(),
            response_headers: config.forward_auth_response_headers.clone(),
            client: build_client()?,
        })
    }

    /// Create directly with URL and headers (for programmatic use)
    #[allow(dead_code)]
    pub fn with_url(auth_url: &str, response_headers: Vec<String>) -> Result<Self> {
        validate_auth_url(auth_url)?;
        validate_response_headers(&response_headers)?;
        Ok(Self {
            auth_url: auth_url.to_string(),
            response_headers,
            client: build_client()?,
        })
    }

    /// Create with a custom client (for testing)
    #[cfg(test)]
    fn with_client(auth_url: &str, response_headers: Vec<String>, client: reqwest::Client) -> Self {
        Self {
            auth_url: auth_url.to_string(),
            response_headers,
            client,
        }
    }

    /// Get the configured auth URL
    #[allow(dead_code)]
    pub fn auth_url(&self) -> &str {
        &self.auth_url
    }

    fn unavailable_response() -> Response<Vec<u8>> {
        Response::builder()
            .status(502)
            .header("Content-Type", "application/json")
            .body(crate::error::json_error_body("Auth service unavailable"))
            .expect("static forward-auth response must be valid")
    }
}

#[async_trait]
impl Middleware for ForwardAuthMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        // Build the auth request with forwarded headers
        let mut auth_req = self.client.get(&self.auth_url);

        // Copy original request headers to auth request
        for (key, value) in req.headers.iter() {
            // The auth request is a new HTTP hop. Never forward hop-by-hop
            // fields, the downstream Host, or framing metadata to the auth
            // origin; doing so can create request smuggling and host confusion.
            if key == http::header::HOST
                || key == http::header::CONTENT_LENGTH
                || crate::proxy::http_proxy::is_hop_by_hop_header(&req.headers, key)
                || crate::proxy::http_proxy::is_forwarded_header(key.as_str())
                || key.as_str().eq_ignore_ascii_case("forwarded")
            {
                continue;
            }
            if let Ok(v) = value.to_str() {
                auth_req = auth_req.header(key.as_str(), v);
            }
        }

        // Add X-Forwarded-Method and X-Forwarded-Uri
        auth_req = auth_req.header("X-Forwarded-Method", req.method.as_str());
        auth_req = auth_req.header("X-Forwarded-Uri", req.uri.to_string());

        // Send the auth request
        let auth_resp = match auth_req.send().await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    auth_url = self.auth_url,
                    "Forward auth service unreachable"
                );
                return Ok(Some(Self::unavailable_response()));
            }
        };

        let status = auth_resp.status();
        // Clone only response headers selected by the configured allowlist,
        // then drain the bounded body so the connection can be reused.
        let selected_headers = self
            .response_headers
            .iter()
            .filter_map(|header_name| {
                auth_resp
                    .headers()
                    .get(header_name.as_str())
                    .and_then(|value| {
                        http::header::HeaderName::from_bytes(header_name.as_bytes())
                            .ok()
                            .map(|name| (name, value.clone()))
                    })
            })
            .collect::<Vec<_>>();
        let body_result = read_bounded_body(auth_resp).await;

        if status.is_success() {
            if body_result.is_err() {
                tracing::warn!(
                    auth_url = self.auth_url,
                    "Forward auth response body could not be consumed safely"
                );
                return Ok(Some(Self::unavailable_response()));
            }
            for (name, value) in selected_headers {
                req.headers.insert(name, value);
            }
            return Ok(None);
        }

        let status = if status.is_client_error() || status.is_server_error() {
            status
        } else {
            // Do not relay redirects from an auth service to the caller; that
            // would turn an authentication decision into an external redirect.
            http::StatusCode::FORBIDDEN
        };

        tracing::debug!(
            status = status.as_u16(),
            auth_url = self.auth_url,
            "Forward auth rejected request"
        );

        let body = match body_result {
            Ok(body) if !body.is_empty() => body,
            _ => crate::error::json_error_body("Authentication failed"),
        };

        Ok(Some(
            Response::builder()
                .status(status.as_u16())
                .header("Content-Type", "application/json")
                .body(body)
                .expect("static forward-auth response headers must be valid"),
        ))
    }

    fn name(&self) -> &str {
        "forward-auth"
    }
}

fn validate_auth_url(auth_url: &str) -> Result<()> {
    let parsed = url::Url::parse(auth_url)
        .map_err(|error| GatewayError::Config(format!("Invalid forward_auth_url: {error}")))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(GatewayError::Config(
            "forward_auth_url must use http or https, include a host, and omit credentials"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_response_headers(headers: &[String]) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for header in headers {
        let name = http::header::HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
            GatewayError::Config(format!(
                "Invalid forward_auth_response_headers entry '{}': {error}",
                header
            ))
        })?;
        let canonical = name.as_str().to_ascii_lowercase();
        if !seen.insert(canonical) {
            return Err(GatewayError::Config(format!(
                "Duplicate forward_auth_response_headers entry '{header}'"
            )));
        }
        if name == http::header::HOST
            || name == http::header::CONTENT_LENGTH
            || crate::proxy::http_proxy::is_hop_by_hop(name.as_str())
            || crate::proxy::http_proxy::is_forwarded_header(name.as_str())
            || name.as_str().eq_ignore_ascii_case("forwarded")
        {
            return Err(GatewayError::Config(format!(
                "forward_auth_response_headers entry '{header}' is not safe to copy"
            )));
        }
    }
    Ok(())
}

fn build_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(FORWARD_AUTH_CONNECT_TIMEOUT)
        .timeout(FORWARD_AUTH_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| {
            GatewayError::Other(format!("Could not initialize forward-auth client: {error}"))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthBodyError {
    TooLarge,
    ReadFailed,
}

async fn read_bounded_body(
    response: reqwest::Response,
) -> std::result::Result<Vec<u8>, AuthBodyError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_AUTH_RESPONSE_BYTES as u64)
    {
        return Err(AuthBodyError::TooLarge);
    }
    let mut body = BytesMut::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_AUTH_RESPONSE_BYTES as u64) as usize,
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| AuthBodyError::ReadFailed)?;
        if body.len().saturating_add(chunk.len()) > MAX_AUTH_RESPONSE_BYTES {
            return Err(AuthBodyError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_ctx() -> RequestContext {
        RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        }
    }

    fn make_config(url: &str) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "forward-auth".to_string(),
            forward_auth_url: Some(url.to_string()),
            forward_auth_response_headers: vec!["X-User-Id".to_string(), "X-User-Role".to_string()],
            ..Default::default()
        }
    }

    #[test]
    fn test_forward_auth_name() {
        let mw = ForwardAuthMiddleware::with_url("http://auth.local/verify", vec![]).unwrap();
        assert_eq!(mw.name(), "forward-auth");
    }

    #[test]
    fn test_forward_auth_url() {
        let mw = ForwardAuthMiddleware::with_url("http://auth.local/verify", vec![]).unwrap();
        assert_eq!(mw.auth_url(), "http://auth.local/verify");
    }

    #[test]
    fn test_from_config() {
        let config = make_config("http://auth.local/verify");
        let mw = ForwardAuthMiddleware::new(&config).unwrap();
        assert_eq!(mw.auth_url(), "http://auth.local/verify");
    }

    #[test]
    fn test_requires_auth_url() {
        let config = MiddlewareConfig {
            middleware_type: "forward-auth".to_string(),
            ..Default::default()
        };
        assert!(ForwardAuthMiddleware::new(&config).is_err());
    }

    #[test]
    fn test_empty_url_rejected() {
        assert!(ForwardAuthMiddleware::with_url("", vec![]).is_err());
    }

    #[test]
    fn test_empty_config_url_rejected() {
        let config = MiddlewareConfig {
            middleware_type: "forward-auth".to_string(),
            forward_auth_url: Some(String::new()),
            ..Default::default()
        };
        assert!(ForwardAuthMiddleware::new(&config).is_err());
    }

    #[test]
    fn test_auth_url_rejects_non_http_and_embedded_credentials() {
        for url in [
            "file:///etc/passwd",
            "tcp://127.0.0.1:9000/verify",
            "http://user:password@auth.local/verify",
            "/relative/verify",
        ] {
            assert!(
                ForwardAuthMiddleware::with_url(url, vec![]).is_err(),
                "URL should be rejected: {url}"
            );
        }
    }

    #[test]
    fn test_response_header_allowlist_rejects_hop_by_hop_and_invalid_names() {
        for headers in [
            vec!["Connection".to_string()],
            vec!["Host".to_string()],
            vec!["Content-Length".to_string()],
            vec!["X-Forwarded-For".to_string()],
            vec!["not a header".to_string()],
            vec!["X-User".to_string(), "x-user".to_string()],
        ] {
            assert!(ForwardAuthMiddleware::with_url("http://auth.local/verify", headers).is_err());
        }
    }

    /// Start a mock TCP server that responds with a fixed HTTP response
    async fn start_mock_auth_server(response: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let response = response.to_string();

        tokio::spawn(async move {
            // Accept one connection
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        format!("http://127.0.0.1:{}/verify", addr.port())
    }

    #[tokio::test]
    async fn test_auth_success_200() {
        let url = start_mock_auth_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-User-Id: user-42\r\n\r\nOK",
        )
        .await;

        let mw = ForwardAuthMiddleware::with_client(
            &url,
            vec!["X-User-Id".to_string()],
            reqwest::Client::new(),
        );

        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .header("Authorization", "Bearer token")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none()); // Should pass through
                                   // Auth header should be copied
        assert_eq!(parts.headers.get("x-user-id").unwrap(), "user-42");
    }

    #[tokio::test]
    async fn test_auth_rejected_401() {
        let url = start_mock_auth_server(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\n\r\nUnauthorized",
        )
        .await;

        let mw = ForwardAuthMiddleware::with_client(&url, vec![], reqwest::Client::new());

        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 401);
    }

    #[tokio::test]
    async fn test_auth_rejected_403() {
        let url =
            start_mock_auth_server("HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden")
                .await;

        let mw = ForwardAuthMiddleware::with_client(&url, vec![], reqwest::Client::new());

        let (mut parts, _) = http::Request::builder()
            .uri("/api/admin")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 403);
    }

    #[tokio::test]
    async fn test_auth_service_unreachable() {
        // Use a port that definitely won't have a server
        let mw = ForwardAuthMiddleware::with_client(
            "http://127.0.0.1:1/verify",
            vec![],
            reqwest::Client::builder()
                .timeout(std::time::Duration::from_millis(100))
                .build()
                .unwrap(),
        );

        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 502);
    }

    #[tokio::test]
    async fn test_forwards_method_and_uri() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, mut rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = tx.send(request);
                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK";
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let url = format!("http://127.0.0.1:{}/verify", addr.port());
        let mw = ForwardAuthMiddleware::with_client(&url, vec![], reqwest::Client::new());

        let (mut parts, _) = http::Request::builder()
            .method("POST")
            .uri("/api/users")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let _ = mw.handle_request(&mut parts, &ctx).await.unwrap();

        // Check that X-Forwarded-Method and X-Forwarded-Uri were sent
        let captured = rx.try_recv().unwrap();
        assert!(
            captured.contains("x-forwarded-method: POST")
                || captured.contains("X-Forwarded-Method: POST"),
            "Expected X-Forwarded-Method header, got: {}",
            captured
        );
        assert!(
            captured.contains("x-forwarded-uri: /api/users")
                || captured.contains("X-Forwarded-Uri: /api/users"),
            "Expected X-Forwarded-Uri header, got: {}",
            captured
        );
    }

    #[tokio::test]
    async fn test_does_not_forward_client_supplied_forwarding_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap();
                let _ = tx.send(String::from_utf8_lossy(&buf[..n]).to_string());
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            }
        });

        let url = format!("http://127.0.0.1:{}/verify", addr.port());
        let mw = ForwardAuthMiddleware::with_client(&url, vec![], reqwest::Client::new());
        let (mut parts, _) = http::Request::builder()
            .uri("/api")
            .header("X-Forwarded-For", "198.51.100.99")
            .header("X-Forwarded-Host", "evil.example")
            .header("Forwarded", "for=198.51.100.99")
            .body(())
            .unwrap()
            .into_parts();
        assert!(mw
            .handle_request(&mut parts, &make_ctx())
            .await
            .unwrap()
            .is_none());

        let captured = rx.await.unwrap();
        let lower = captured.to_ascii_lowercase();
        assert!(!lower.contains("x-forwarded-for: 198.51.100.99"));
        assert!(!lower.contains("x-forwarded-host: evil.example"));
        assert!(!lower.contains("forwarded: for=198.51.100.99"));
    }

    #[tokio::test]
    async fn test_no_headers_copied_when_empty() {
        let url = start_mock_auth_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Custom: value\r\n\r\nOK",
        )
        .await;

        // Don't configure any response headers to copy
        let mw = ForwardAuthMiddleware::with_client(&url, vec![], reqwest::Client::new());

        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
        // X-Custom should NOT be copied since it's not in response_headers
        assert!(parts.headers.get("x-custom").is_none());
    }
}
