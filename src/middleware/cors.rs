//! CORS middleware — Cross-Origin Resource Sharing

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::Result;
use async_trait::async_trait;
use http::Response;

/// CORS middleware
pub struct CorsMiddleware {
    allowed_origins: Vec<String>,
    allowed_methods: Vec<String>,
    allowed_headers: Vec<String>,
    max_age: u64,
}

impl CorsMiddleware {
    /// Create a new CORS middleware from configuration
    pub fn new(config: &MiddlewareConfig) -> Self {
        Self {
            allowed_origins: if config.allowed_origins.is_empty() {
                vec!["*".to_string()]
            } else {
                config.allowed_origins.clone()
            },
            allowed_methods: if config.allowed_methods.is_empty() {
                vec![
                    "GET".to_string(),
                    "POST".to_string(),
                    "PUT".to_string(),
                    "DELETE".to_string(),
                    "OPTIONS".to_string(),
                ]
            } else {
                config.allowed_methods.clone()
            },
            allowed_headers: if config.allowed_headers.is_empty() {
                vec!["Content-Type".to_string(), "Authorization".to_string()]
            } else {
                config.allowed_headers.clone()
            },
            max_age: config.max_age.unwrap_or(86400),
        }
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == "*" || o == origin)
    }
}

#[async_trait]
impl Middleware for CorsMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        // Handle preflight OPTIONS request
        if req.method == http::Method::OPTIONS {
            let origin = req
                .headers
                .get("Origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("*");

            if !self.origin_allowed(origin) {
                return Ok(Some(
                    Response::builder()
                        .status(403)
                        .body(b"Origin not allowed".to_vec())
                        .unwrap(),
                ));
            }

            let response = Response::builder()
                .status(204)
                .header("Access-Control-Allow-Origin", origin)
                .header(
                    "Access-Control-Allow-Methods",
                    self.allowed_methods.join(", "),
                )
                .header(
                    "Access-Control-Allow-Headers",
                    self.allowed_headers.join(", "),
                )
                .header("Access-Control-Max-Age", self.max_age.to_string())
                .body(Vec::new())
                .unwrap();

            return Ok(Some(response));
        }

        Ok(None)
    }

    async fn handle_response(&self, resp: &mut http::response::Parts) -> Result<()> {
        // Add CORS headers to all responses
        let origin = if self.allowed_origins.contains(&"*".to_string()) {
            "*"
        } else {
            self.allowed_origins
                .first()
                .map(|s| s.as_str())
                .unwrap_or("*")
        };

        resp.headers
            .insert("Access-Control-Allow-Origin", origin.parse().unwrap());

        Ok(())
    }

    fn name(&self) -> &str {
        "cors"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn make_ctx() -> RequestContext {
        RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        }
    }

    fn make_config() -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "cors".to_string(),
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            max_age: Some(3600),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_cors_preflight_allowed() {
        let mw = CorsMiddleware::new(&make_config());
        let (mut parts, _) = Request::builder()
            .method("OPTIONS")
            .header("Origin", "https://example.com")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status(), 204);
        assert!(resp.headers().contains_key("Access-Control-Allow-Origin"));
        assert!(resp.headers().contains_key("Access-Control-Allow-Methods"));
    }

    #[tokio::test]
    async fn test_cors_preflight_denied() {
        let mw = CorsMiddleware::new(&make_config());
        let (mut parts, _) = Request::builder()
            .method("OPTIONS")
            .header("Origin", "https://evil.com")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 403);
    }

    #[tokio::test]
    async fn test_cors_non_preflight_passthrough() {
        let mw = CorsMiddleware::new(&make_config());
        let (mut parts, _) = Request::builder()
            .method("GET")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cors_wildcard_origin() {
        let mut config = make_config();
        config.allowed_origins = vec!["*".to_string()];
        let mw = CorsMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .method("OPTIONS")
            .header("Origin", "https://anything.com")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 204);
    }

    #[tokio::test]
    async fn test_cors_response_headers() {
        let mw = CorsMiddleware::new(&make_config());
        let (mut parts, _body) = Response::builder()
            .status(200)
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_response(&mut parts).await.unwrap();
        assert!(parts.headers.contains_key("Access-Control-Allow-Origin"));
    }

    #[test]
    fn test_cors_defaults() {
        let mut config = make_config();
        config.allowed_origins = vec![];
        config.allowed_methods = vec![];
        config.allowed_headers = vec![];
        config.max_age = None;

        let mw = CorsMiddleware::new(&config);
        assert_eq!(mw.allowed_origins, vec!["*"]);
        assert_eq!(mw.allowed_methods.len(), 5);
        assert_eq!(mw.allowed_headers.len(), 2);
        assert_eq!(mw.max_age, 86400);
    }

    #[test]
    fn test_cors_name() {
        let mw = CorsMiddleware::new(&make_config());
        assert_eq!(mw.name(), "cors");
    }
}
