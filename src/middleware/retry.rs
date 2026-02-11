//! Retry middleware — configuration for automatic request retries
//!
//! Provides retry configuration that the proxy layer uses when forwarding
//! requests to backends. The middleware itself stores the retry policy;
//! actual retry execution happens in the proxy layer.

use crate::config::MiddlewareConfig;
use crate::error::Result;
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use http::Response;
use serde::{Deserialize, Serialize};

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (excluding the initial request)
    pub max_retries: u32,
    /// Interval between retries in milliseconds
    pub interval_ms: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            interval_ms: 100,
        }
    }
}

/// Retry middleware — attaches retry policy to requests via header
pub struct RetryMiddleware {
    policy: RetryPolicy,
}

impl RetryMiddleware {
    /// Create from middleware config
    pub fn new(config: &MiddlewareConfig) -> Result<Self> {
        let max_retries = config.max_retries.unwrap_or(3);
        let interval_ms = config.retry_interval_ms.unwrap_or(100);

        if max_retries == 0 {
            return Err(crate::error::GatewayError::Config(
                "Retry middleware requires max_retries > 0".to_string(),
            ));
        }

        Ok(Self {
            policy: RetryPolicy {
                max_retries,
                interval_ms,
            },
        })
    }

    /// Get the retry policy
    pub fn policy(&self) -> &RetryPolicy {
        &self.policy
    }
}

#[async_trait]
impl Middleware for RetryMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        // Attach retry metadata as internal headers for the proxy layer
        req.headers.insert(
            "x-gateway-retry-max",
            self.policy.max_retries.to_string().parse().unwrap(),
        );
        req.headers.insert(
            "x-gateway-retry-interval-ms",
            self.policy.interval_ms.to_string().parse().unwrap(),
        );
        Ok(None)
    }

    fn name(&self) -> &str {
        "retry"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config_with_retry(max: Option<u32>, interval: Option<u64>) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "retry".to_string(),
            max_retries: max,
            retry_interval_ms: interval,
            header: None,
            keys: vec![],
            value: None,
            username: None,
            password: None,
            rate: None,
            burst: None,
            allowed_origins: vec![],
            allowed_methods: vec![],
            allowed_headers: vec![],
            max_age: None,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            prefixes: vec![],
            allowed_ips: vec![],
        }
    }

    #[test]
    fn test_retry_name() {
        let mw = RetryMiddleware::new(&config_with_retry(Some(3), Some(100))).unwrap();
        assert_eq!(mw.name(), "retry");
    }

    #[test]
    fn test_retry_policy_defaults() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.interval_ms, 100);
    }

    #[test]
    fn test_retry_from_config() {
        let mw = RetryMiddleware::new(&config_with_retry(Some(5), Some(200))).unwrap();
        assert_eq!(mw.policy().max_retries, 5);
        assert_eq!(mw.policy().interval_ms, 200);
    }

    #[test]
    fn test_retry_config_defaults() {
        let mw = RetryMiddleware::new(&config_with_retry(None, None)).unwrap();
        assert_eq!(mw.policy().max_retries, 3);
        assert_eq!(mw.policy().interval_ms, 100);
    }

    #[test]
    fn test_retry_zero_retries_rejected() {
        let result = RetryMiddleware::new(&config_with_retry(Some(0), None));
        assert!(result.is_err());
    }

    #[test]
    fn test_retry_policy_serialization() {
        let policy = RetryPolicy {
            max_retries: 5,
            interval_ms: 500,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let parsed: RetryPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_retries, 5);
        assert_eq!(parsed.interval_ms, 500);
    }

    #[tokio::test]
    async fn test_retry_sets_headers() {
        let mw = RetryMiddleware::new(&config_with_retry(Some(3), Some(250))).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none()); // Should not short-circuit
        assert_eq!(
            parts.headers.get("x-gateway-retry-max").unwrap(),
            "3"
        );
        assert_eq!(
            parts.headers.get("x-gateway-retry-interval-ms").unwrap(),
            "250"
        );
    }

    #[tokio::test]
    async fn test_retry_passthrough() {
        let mw = RetryMiddleware::new(&config_with_retry(Some(2), Some(50))).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "10.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "api".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
    }
}
