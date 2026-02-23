//! Redis-backed distributed rate limiting — token bucket via Lua script
//!
//! Feature-gated behind `redis`. Uses an atomic Lua script for
//! distributed token bucket rate limiting across multiple gateway instances.
//! Fails open on Redis connection errors (logs warning, allows request).

use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use http::Response;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Lua script for atomic token bucket rate limiting
///
/// Arguments: KEYS[1] = rate limit key, ARGV[1] = rate, ARGV[2] = burst, ARGV[3] = now (secs)
/// Returns: 1 if allowed, 0 if denied
const TOKEN_BUCKET_LUA: &str = r#"
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(data[1])
local last_refill = tonumber(data[2])

if tokens == nil then
    tokens = burst
    last_refill = now
end

local elapsed = math.max(0, now - last_refill)
tokens = math.min(burst, tokens + elapsed * rate)

if tokens >= 1 then
    tokens = tokens - 1
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(burst / rate) + 10)
    return 1
else
    redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
    redis.call('EXPIRE', key, math.ceil(burst / rate) + 10)
    return 0
end
"#;

/// Redis-backed distributed rate limiter
pub struct RedisRateLimitMiddleware {
    /// Redis connection (lazily connected)
    connection: Arc<Mutex<Option<redis::aio::MultiplexedConnection>>>,
    /// Redis URL
    redis_url: String,
    /// Rate: tokens per second
    rate: u64,
    /// Burst: max tokens
    burst: u64,
    /// Key prefix for Redis
    key_prefix: String,
}

impl RedisRateLimitMiddleware {
    /// Create from middleware config
    pub fn new(config: &MiddlewareConfig) -> Result<Self> {
        let redis_url = config.redis_url.as_deref().ok_or_else(|| {
            GatewayError::Config(
                "rate-limit-redis middleware requires 'redis_url' field".to_string(),
            )
        })?;

        let rate = config.rate.ok_or_else(|| {
            GatewayError::Config("rate-limit-redis middleware requires 'rate' field".to_string())
        })?;

        let burst = config.burst.unwrap_or(rate);

        Ok(Self {
            connection: Arc::new(Mutex::new(None)),
            redis_url: redis_url.to_string(),
            rate,
            burst,
            key_prefix: "a3s:ratelimit".to_string(),
        })
    }

    /// Create directly (for programmatic use)
    pub fn with_params(redis_url: &str, rate: u64, burst: u64) -> Result<Self> {
        if redis_url.is_empty() {
            return Err(GatewayError::Config(
                "redis_url cannot be empty".to_string(),
            ));
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(None)),
            redis_url: redis_url.to_string(),
            rate,
            burst,
            key_prefix: "a3s:ratelimit".to_string(),
        })
    }

    /// Get or create the Redis connection
    async fn get_connection(
        &self,
    ) -> std::result::Result<redis::aio::MultiplexedConnection, redis::RedisError> {
        let mut guard = self.connection.lock().await;
        if let Some(ref conn) = *guard {
            return Ok(conn.clone());
        }

        let client = redis::Client::open(self.redis_url.as_str())?;
        let conn = client.get_multiplexed_async_connection().await?;
        *guard = Some(conn.clone());
        Ok(conn)
    }
}

#[async_trait]
impl Middleware for RedisRateLimitMiddleware {
    async fn handle_request(
        &self,
        _req: &mut http::request::Parts,
        ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        let key = format!("{}:{}", self.key_prefix, ctx.router);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let conn = match self.get_connection().await {
            Ok(c) => c,
            Err(e) => {
                // Fail open: allow request if Redis is unreachable
                tracing::warn!(
                    error = %e,
                    redis_url = self.redis_url,
                    "Redis rate limiter unavailable, failing open"
                );
                return Ok(None);
            }
        };

        let result: std::result::Result<i32, redis::RedisError> =
            redis::Script::new(TOKEN_BUCKET_LUA)
                .key(&key)
                .arg(self.rate)
                .arg(self.burst)
                .arg(now)
                .invoke_async(&mut conn.clone())
                .await;

        match result {
            Ok(1) => Ok(None), // Allowed
            Ok(_) => {
                // Rate limited
                Ok(Some(
                    Response::builder()
                        .status(429)
                        .header("Content-Type", "application/json")
                        .header("Retry-After", "1")
                        .body(
                            r#"{"error":"Rate limit exceeded (distributed)"}"#.as_bytes().to_vec(),
                        )
                        .unwrap(),
                ))
            }
            Err(e) => {
                // Fail open on Redis errors
                tracing::warn!(
                    error = %e,
                    "Redis rate limit script failed, failing open"
                );
                Ok(None)
            }
        }
    }

    fn name(&self) -> &str {
        "rate-limit-redis"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(redis_url: &str, rate: u64, burst: u64) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "rate-limit-redis".to_string(),
            redis_url: Some(redis_url.to_string()),
            rate: Some(rate),
            burst: Some(burst),
            ..Default::default()
        }
    }

    #[test]
    fn test_redis_rate_limit_name() {
        let mw = RedisRateLimitMiddleware::with_params("redis://127.0.0.1:6379", 100, 50).unwrap();
        assert_eq!(mw.name(), "rate-limit-redis");
    }

    #[test]
    fn test_from_config() {
        let config = make_config("redis://127.0.0.1:6379", 100, 50);
        let mw = RedisRateLimitMiddleware::new(&config).unwrap();
        assert_eq!(mw.rate, 100);
        assert_eq!(mw.burst, 50);
    }

    #[test]
    fn test_requires_redis_url() {
        let config = MiddlewareConfig {
            middleware_type: "rate-limit-redis".to_string(),
            rate: Some(100),
            ..Default::default()
        };
        assert!(RedisRateLimitMiddleware::new(&config).is_err());
    }

    #[test]
    fn test_requires_rate() {
        let config = MiddlewareConfig {
            middleware_type: "rate-limit-redis".to_string(),
            redis_url: Some("redis://127.0.0.1:6379".to_string()),
            ..Default::default()
        };
        assert!(RedisRateLimitMiddleware::new(&config).is_err());
    }

    #[test]
    fn test_default_burst_equals_rate() {
        let mut config = make_config("redis://127.0.0.1:6379", 100, 50);
        config.burst = None;
        let mw = RedisRateLimitMiddleware::new(&config).unwrap();
        assert_eq!(mw.burst, 100); // burst defaults to rate
    }

    #[test]
    fn test_empty_url_rejected() {
        assert!(RedisRateLimitMiddleware::with_params("", 100, 50).is_err());
    }

    #[tokio::test]
    async fn test_fail_open_on_unreachable_redis() {
        // Connect to a port with no Redis server
        let mw = RedisRateLimitMiddleware::with_params("redis://127.0.0.1:1", 100, 50).unwrap();

        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };
        // Should fail open (allow the request)
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
    }
}
