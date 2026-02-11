//! Rate limiting middleware — token bucket algorithm

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use async_trait::async_trait;
use http::Response;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Instant;

/// Token bucket rate limiter middleware
pub struct RateLimitMiddleware {
    bucket: Arc<Mutex<TokenBucket>>,
}

struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate: rate as f64,
            burst: burst as f64,
            tokens: burst as f64,
            last_refill: Instant::now(),
        }
    }

    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl RateLimitMiddleware {
    /// Create a new rate limiter from configuration
    pub fn new(config: &MiddlewareConfig) -> Result<Self> {
        let rate = config.rate.ok_or_else(|| {
            GatewayError::Config("rate-limit middleware requires 'rate'".to_string())
        })?;
        let burst = config.burst.unwrap_or(rate);

        Ok(Self {
            bucket: Arc::new(Mutex::new(TokenBucket::new(rate, burst))),
        })
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    async fn handle_request(
        &self,
        _req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        let mut bucket = self.bucket.lock().await;
        if bucket.try_acquire() {
            Ok(None)
        } else {
            let response = Response::builder()
                .status(429)
                .header("Content-Type", "application/json")
                .header("Retry-After", "1")
                .body(r#"{"error":"Rate limit exceeded"}"#.as_bytes().to_vec())
                .unwrap();
            Ok(Some(response))
        }
    }

    fn name(&self) -> &str {
        "rate-limit"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;
    use std::collections::HashMap;

    fn make_ctx() -> RequestContext {
        RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        }
    }

    fn make_config(rate: u64, burst: u64) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "rate-limit".to_string(),
            rate: Some(rate),
            burst: Some(burst),
            header: None,
            keys: vec![],
            value: None,
            username: None,
            password: None,
            allowed_origins: vec![],
            allowed_methods: vec![],
            allowed_headers: vec![],
            max_age: None,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            prefixes: vec![],
            max_retries: None,
            retry_interval_ms: None,
            allowed_ips: vec![],
        }
    }

    #[test]
    fn test_rate_limit_requires_rate() {
        let mut config = make_config(100, 50);
        config.rate = None;
        assert!(RateLimitMiddleware::new(&config).is_err());
    }

    #[test]
    fn test_rate_limit_default_burst() {
        let mut config = make_config(100, 50);
        config.burst = None;
        let mw = RateLimitMiddleware::new(&config).unwrap();
        assert_eq!(mw.name(), "rate-limit");
    }

    #[tokio::test]
    async fn test_rate_limit_allows_within_burst() {
        let config = make_config(10, 5);
        let mw = RateLimitMiddleware::new(&config).unwrap();
        let ctx = make_ctx();

        // Should allow up to burst (5) requests
        for _ in 0..5 {
            let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
            let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
            assert!(result.is_none(), "Request should be allowed within burst");
        }
    }

    #[tokio::test]
    async fn test_rate_limit_rejects_over_burst() {
        let config = make_config(10, 2);
        let mw = RateLimitMiddleware::new(&config).unwrap();
        let ctx = make_ctx();

        // Exhaust burst
        for _ in 0..2 {
            let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
            mw.handle_request(&mut parts, &ctx).await.unwrap();
        }

        // Next request should be rejected
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 429);
    }

    #[tokio::test]
    async fn test_rate_limit_refills_over_time() {
        let config = make_config(1000, 1); // 1000/sec rate, 1 burst
        let mw = RateLimitMiddleware::new(&config).unwrap();
        let ctx = make_ctx();

        // Use the one token
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());

        // Wait for refill
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Should have tokens again
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_token_bucket_basic() {
        let mut bucket = TokenBucket::new(100, 10);
        assert!(bucket.try_acquire());
        assert!(bucket.try_acquire());
    }
}
