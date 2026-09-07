//! Retry middleware — configuration for automatic request retries
//!
//! Provides retry configuration that protocol handlers use when forwarding
//! replayable requests to backends. The middleware itself only exposes the
//! policy; execution remains at the protocol boundary.

use crate::config::MiddlewareConfig;
use crate::error::Result;
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use http::Response;
use serde::{Deserialize, Serialize};

const MAX_RETRIES: u32 = 10;
const MAX_INTERVAL_MS: u64 = 60_000;

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

/// Retry middleware — exposes retry policy to the protocol handler
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
        if max_retries > MAX_RETRIES {
            return Err(crate::error::GatewayError::Config(format!(
                "Retry middleware max_retries must be at most {MAX_RETRIES}"
            )));
        }
        if interval_ms > MAX_INTERVAL_MS {
            return Err(crate::error::GatewayError::Config(format!(
                "Retry middleware retry_interval_ms must be at most {MAX_INTERVAL_MS}"
            )));
        }

        Ok(Self {
            policy: RetryPolicy {
                max_retries,
                interval_ms,
            },
        })
    }

    /// Get the retry policy
    #[allow(dead_code)]
    pub fn policy(&self) -> &RetryPolicy {
        &self.policy
    }
}

#[async_trait]
impl Middleware for RetryMiddleware {
    async fn handle_request(
        &self,
        _req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        Ok(None)
    }

    fn retry_policy(&self) -> Option<RetryPolicy> {
        Some(self.policy.clone())
    }

    fn name(&self) -> &str {
        "retry"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_retry(max: Option<u32>, interval: Option<u64>) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "retry".to_string(),
            max_retries: max,
            retry_interval_ms: interval,
            ..Default::default()
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
    fn test_retry_bounds_are_rejected() {
        assert!(RetryMiddleware::new(&config_with_retry(Some(11), None)).is_err());
        assert!(RetryMiddleware::new(&config_with_retry(None, Some(60_001))).is_err());
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
    async fn test_retry_does_not_mutate_request_headers() {
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
        assert!(parts.headers.get("x-gateway-retry-max").is_none());
        assert!(parts.headers.get("x-gateway-retry-interval-ms").is_none());
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
