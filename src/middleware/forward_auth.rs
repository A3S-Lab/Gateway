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
use http::Response;

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

        if auth_url.is_empty() {
            return Err(GatewayError::Config(
                "forward_auth_url cannot be empty".to_string(),
            ));
        }

        Ok(Self {
            auth_url: auth_url.to_string(),
            response_headers: config.forward_auth_response_headers.clone(),
            client: reqwest::Client::new(),
        })
    }

    /// Create directly with URL and headers (for programmatic use)
    pub fn with_url(auth_url: &str, response_headers: Vec<String>) -> Result<Self> {
        if auth_url.is_empty() {
            return Err(GatewayError::Config(
                "forward_auth_url cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            auth_url: auth_url.to_string(),
            response_headers,
            client: reqwest::Client::new(),
        })
    }

    /// Create with a custom client (for testing)
    #[cfg(test)]
    fn with_client(
        auth_url: &str,
        response_headers: Vec<String>,
        client: reqwest::Client,
    ) -> Self {
        Self {
            auth_url: auth_url.to_string(),
            response_headers,
            client,
        }
    }

    /// Get the configured auth URL
    pub fn auth_url(&self) -> &str {
        &self.auth_url
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
                return Ok(Some(
                    Response::builder()
                        .status(502)
                        .header("Content-Type", "application/json")
                        .body(
                            r#"{"error":"Auth service unavailable"}"#
                                .as_bytes()
                                .to_vec(),
                        )
                        .unwrap(),
                ));
            }
        };

        let status = auth_resp.status();

        if status.is_success() {
            // Copy configured headers from auth response to upstream request
            for header_name in &self.response_headers {
                if let Some(value) = auth_resp.headers().get(header_name.as_str()) {
                    if let Ok(v) = value.to_str() {
                        if let Ok(hv) = v.parse() {
                            if let Ok(hn) = http::header::HeaderName::from_bytes(
                                header_name.to_lowercase().as_bytes(),
                            ) {
                                req.headers.insert(hn, hv);
                            }
                        }
                    }
                }
            }
            Ok(None) // Continue pipeline
        } else {
            // Short-circuit with auth service's status code
            let body = auth_resp
                .bytes()
                .await
                .map(|b| b.to_vec())
                .unwrap_or_else(|_| {
                    format!(r#"{{"error":"Authentication failed","status":{}}}"#, status.as_u16())
                        .into_bytes()
                });

            tracing::debug!(
                status = status.as_u16(),
                auth_url = self.auth_url,
                "Forward auth rejected request"
            );

            Ok(Some(
                Response::builder()
                    .status(status.as_u16())
                    .header("Content-Type", "application/json")
                    .body(body)
                    .unwrap(),
            ))
        }
    }

    fn name(&self) -> &str {
        "forward-auth"
    }
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
            forward_auth_response_headers: vec![
                "X-User-Id".to_string(),
                "X-User-Role".to_string(),
            ],
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
        let url = start_mock_auth_server(
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden",
        )
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
        assert!(captured.contains("x-forwarded-method: POST") || captured.contains("X-Forwarded-Method: POST"),
            "Expected X-Forwarded-Method header, got: {}", captured);
        assert!(captured.contains("x-forwarded-uri: /api/users") || captured.contains("X-Forwarded-Uri: /api/users"),
            "Expected X-Forwarded-Uri header, got: {}", captured);
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
