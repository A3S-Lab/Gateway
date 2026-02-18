//! Body limit middleware — enforces maximum request body size
//!
//! Checks the Content-Length header and rejects requests that exceed
//! the configured maximum. For chunked transfers without Content-Length,
//! injects an `x-gateway-body-limit` header so the proxy layer can
//! enforce the limit during streaming.

use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use http::Response;

/// Body limit middleware — rejects oversized requests
pub struct BodyLimitMiddleware {
    max_bytes: u64,
}

impl BodyLimitMiddleware {
    /// Create from middleware config
    pub fn new(config: &MiddlewareConfig) -> Result<Self> {
        let max_bytes = config.max_body_bytes.ok_or_else(|| {
            GatewayError::Config(
                "body-limit middleware requires 'max_body_bytes' field".to_string(),
            )
        })?;

        if max_bytes == 0 {
            return Err(GatewayError::Config(
                "max_body_bytes must be greater than 0".to_string(),
            ));
        }

        Ok(Self { max_bytes })
    }

    /// Create directly with a byte limit
    #[allow(dead_code)]
    pub fn with_limit(max_bytes: u64) -> Result<Self> {
        if max_bytes == 0 {
            return Err(GatewayError::Config(
                "max_body_bytes must be greater than 0".to_string(),
            ));
        }
        Ok(Self { max_bytes })
    }

    /// Get the configured limit
    #[allow(dead_code)]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

#[async_trait]
impl Middleware for BodyLimitMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        // Check Content-Length if present
        if let Some(content_length) = req.headers.get("content-length") {
            if let Ok(length_str) = content_length.to_str() {
                if let Ok(length) = length_str.parse::<u64>() {
                    if length > self.max_bytes {
                        tracing::debug!(
                            content_length = length,
                            max_bytes = self.max_bytes,
                            "Request body exceeds size limit"
                        );
                        return Ok(Some(
                            Response::builder()
                                .status(413)
                                .header("Content-Type", "application/json")
                                .body(
                                    format!(
                                        r#"{{"error":"Request body too large","max_bytes":{}}}"#,
                                        self.max_bytes
                                    )
                                    .into_bytes(),
                                )
                                .unwrap(),
                        ));
                    }
                }
            }
        }

        // For requests without Content-Length (chunked), inject a header
        // so the proxy layer can enforce the limit during streaming
        req.headers.insert(
            "x-gateway-body-limit",
            self.max_bytes.to_string().parse().unwrap(),
        );

        Ok(None)
    }

    fn name(&self) -> &str {
        "body-limit"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ctx() -> RequestContext {
        RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        }
    }

    fn make_config(max_bytes: u64) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "body-limit".to_string(),
            max_body_bytes: Some(max_bytes),
            ..Default::default()
        }
    }

    #[test]
    fn test_body_limit_name() {
        let mw = BodyLimitMiddleware::with_limit(1024).unwrap();
        assert_eq!(mw.name(), "body-limit");
    }

    #[test]
    fn test_body_limit_max_bytes() {
        let mw = BodyLimitMiddleware::with_limit(1024).unwrap();
        assert_eq!(mw.max_bytes(), 1024);
    }

    #[test]
    fn test_from_config() {
        let mw = BodyLimitMiddleware::new(&make_config(2048)).unwrap();
        assert_eq!(mw.max_bytes(), 2048);
    }

    #[test]
    fn test_requires_max_body_bytes() {
        let config = MiddlewareConfig {
            middleware_type: "body-limit".to_string(),
            ..Default::default()
        };
        assert!(BodyLimitMiddleware::new(&config).is_err());
    }

    #[test]
    fn test_zero_bytes_rejected() {
        assert!(BodyLimitMiddleware::with_limit(0).is_err());
    }

    #[test]
    fn test_zero_bytes_config_rejected() {
        assert!(BodyLimitMiddleware::new(&make_config(0)).is_err());
    }

    #[tokio::test]
    async fn test_request_within_limit() {
        let mw = BodyLimitMiddleware::with_limit(1024).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/upload")
            .header("Content-Length", "512")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
        // Should inject body-limit header for proxy layer
        assert_eq!(
            parts.headers.get("x-gateway-body-limit").unwrap(),
            "1024"
        );
    }

    #[tokio::test]
    async fn test_request_exceeds_limit() {
        let mw = BodyLimitMiddleware::with_limit(1024).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/upload")
            .header("Content-Length", "2048")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status(), 413);
    }

    #[tokio::test]
    async fn test_request_exact_limit() {
        let mw = BodyLimitMiddleware::with_limit(1024).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/upload")
            .header("Content-Length", "1024")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none()); // Exactly at limit should pass
    }

    #[tokio::test]
    async fn test_request_no_content_length() {
        let mw = BodyLimitMiddleware::with_limit(1024).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/stream")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
        // Should still inject the limit header for proxy-layer enforcement
        assert_eq!(
            parts.headers.get("x-gateway-body-limit").unwrap(),
            "1024"
        );
    }

    #[tokio::test]
    async fn test_response_body_413_includes_limit() {
        let mw = BodyLimitMiddleware::with_limit(500).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/upload")
            .header("Content-Length", "1000")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = make_ctx();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        let resp = result.unwrap();
        let body = String::from_utf8(resp.into_body()).unwrap();
        assert!(body.contains("500"));
        assert!(body.contains("Request body too large"));
    }
}
