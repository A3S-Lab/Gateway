//! Rate limiting middleware — token bucket algorithm

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use async_trait::async_trait;
use http::Response;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Instant;

const MAX_CLIENT_BUCKETS: usize = 10_000;

/// Token bucket rate limiter middleware
pub struct RateLimitMiddleware {
    /// Per-client buckets keep one caller from consuming another caller's
    /// allowance. The map is bounded to cap memory under high-cardinality
    /// client input.
    buckets: Arc<Mutex<HashMap<String, ClientBucket>>>,
    rate: u64,
    burst: u64,
}

struct ClientBucket {
    bucket: TokenBucket,
    last_seen: Instant,
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

    fn try_acquire_at(&mut self, now: Instant) -> bool {
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
        if rate == 0 || burst == 0 {
            return Err(GatewayError::Config(
                "rate-limit requires rate and burst greater than zero".to_string(),
            ));
        }

        Ok(Self {
            buckets: Arc::new(Mutex::new(HashMap::new())),
            rate,
            burst,
        })
    }
}

#[async_trait]
impl Middleware for RateLimitMiddleware {
    async fn handle_request(
        &self,
        _req: &mut http::request::Parts,
        ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;
        if !buckets.contains_key(&ctx.client_ip) && buckets.len() >= MAX_CLIENT_BUCKETS {
            if let Some(oldest) = buckets
                .iter()
                .min_by_key(|(_, bucket)| bucket.last_seen)
                .map(|(key, _)| key.clone())
            {
                buckets.remove(&oldest);
            }
        }
        let client = buckets
            .entry(ctx.client_ip.clone())
            .or_insert_with(|| ClientBucket {
                bucket: TokenBucket::new(self.rate, self.burst),
                last_seen: now,
            });
        client.last_seen = now;
        if client.bucket.try_acquire_at(now) {
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
            ..Default::default()
        }
    }

    #[test]
    fn test_rate_limit_requires_rate() {
        let mut config = make_config(100, 50);
        config.rate = None;
        assert!(RateLimitMiddleware::new(&config).is_err());
    }

    #[test]
    fn test_rate_limit_rejects_zero_rate_or_burst() {
        assert!(RateLimitMiddleware::new(&make_config(0, 1)).is_err());
        assert!(RateLimitMiddleware::new(&make_config(1, 0)).is_err());
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
    async fn test_rate_limit_isolates_clients() {
        let mw = RateLimitMiddleware::new(&make_config(1, 1)).unwrap();
        let first = make_ctx();
        let mut second = make_ctx();
        second.client_ip = "192.0.2.2".to_string();

        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        assert!(mw
            .handle_request(&mut parts, &first)
            .await
            .unwrap()
            .is_none());
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        assert!(mw
            .handle_request(&mut parts, &first)
            .await
            .unwrap()
            .is_some());
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        assert!(mw
            .handle_request(&mut parts, &second)
            .await
            .unwrap()
            .is_none());
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
        let now = Instant::now();
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));
    }

    #[test]
    fn test_token_bucket_exhaustion() {
        let mut bucket = TokenBucket::new(1, 3);
        let now = Instant::now();
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));
        assert!(bucket.try_acquire_at(now));
        assert!(!bucket.try_acquire_at(now));
    }

    #[test]
    fn test_token_bucket_burst_cap() {
        let mut bucket = TokenBucket::new(1000, 5);
        // Even with high rate, tokens are capped at burst
        let now = Instant::now();
        for _ in 0..5 {
            assert!(bucket.try_acquire_at(now));
        }
        assert!(!bucket.try_acquire_at(now));
    }

    #[tokio::test(start_paused = true)]
    async fn test_rate_limit_deterministic_refill() {
        let config = make_config(10, 1); // 10/sec, burst 1
        let mw = RateLimitMiddleware::new(&config).unwrap();
        let ctx = make_ctx();

        // Use the one token
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        assert!(mw.handle_request(&mut parts, &ctx).await.unwrap().is_none());

        // Immediately rejected
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        assert!(mw.handle_request(&mut parts, &ctx).await.unwrap().is_some());

        // Advance 100ms → should have 1 token (10/sec * 0.1s = 1.0)
        tokio::time::advance(tokio::time::Duration::from_millis(100)).await;
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        assert!(mw.handle_request(&mut parts, &ctx).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_rate_limit_429_has_retry_after() {
        let config = make_config(1, 1);
        let mw = RateLimitMiddleware::new(&config).unwrap();
        let ctx = make_ctx();

        // Exhaust
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        mw.handle_request(&mut parts, &ctx).await.unwrap();

        // Get 429
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        let resp = mw.handle_request(&mut parts, &ctx).await.unwrap().unwrap();
        assert_eq!(resp.status(), 429);
        assert_eq!(resp.headers().get("Retry-After").unwrap(), "1");
    }
}
