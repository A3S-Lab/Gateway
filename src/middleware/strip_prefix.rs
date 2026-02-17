//! Strip prefix middleware — remove path prefixes before forwarding

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::Result;
use async_trait::async_trait;
use http::Response;

/// Strip prefix middleware
pub struct StripPrefixMiddleware {
    prefixes: Vec<String>,
}

impl StripPrefixMiddleware {
    /// Create a new strip prefix middleware from configuration
    pub fn new(config: &MiddlewareConfig) -> Self {
        Self {
            prefixes: config.prefixes.clone(),
        }
    }
}

#[async_trait]
impl Middleware for StripPrefixMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        let path = req.uri.path().to_string();

        for prefix in &self.prefixes {
            if path.starts_with(prefix.as_str()) {
                let new_path = &path[prefix.len()..];
                let new_path = if new_path.is_empty() || !new_path.starts_with('/') {
                    format!("/{}", new_path)
                } else {
                    new_path.to_string()
                };

                // Rebuild URI with new path
                let mut builder = http::Uri::builder();
                if let Some(scheme) = req.uri.scheme() {
                    builder = builder.scheme(scheme.clone());
                }
                if let Some(authority) = req.uri.authority() {
                    builder = builder.authority(authority.clone());
                }
                let pq = if let Some(query) = req.uri.query() {
                    format!("{}?{}", new_path, query)
                } else {
                    new_path
                };
                if let Ok(uri) = builder.path_and_query(pq).build() {
                    req.uri = uri;
                }
                break;
            }
        }

        Ok(None)
    }

    fn name(&self) -> &str {
        "strip-prefix"
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

    fn make_config(prefixes: Vec<&str>) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "strip-prefix".to_string(),
            prefixes: prefixes.into_iter().map(String::from).collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_strip_prefix() {
        let config = make_config(vec!["/api/v1"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/api/v1/users")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/users");
    }

    #[tokio::test]
    async fn test_strip_prefix_exact() {
        let config = make_config(vec!["/api"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/api")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/");
    }

    #[tokio::test]
    async fn test_strip_prefix_no_match() {
        let config = make_config(vec!["/api"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/other/path")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/other/path");
    }

    #[tokio::test]
    async fn test_strip_prefix_preserves_query() {
        let config = make_config(vec!["/api"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/api/users?page=1")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/users");
        assert_eq!(parts.uri.query(), Some("page=1"));
    }

    #[tokio::test]
    async fn test_strip_prefix_first_match_wins() {
        let config = make_config(vec!["/api", "/api/v1"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/api/v1/users")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/v1/users");
    }

    #[test]
    fn test_strip_prefix_name() {
        let config = make_config(vec![]);
        let mw = StripPrefixMiddleware::new(&config);
        assert_eq!(mw.name(), "strip-prefix");
    }
}
