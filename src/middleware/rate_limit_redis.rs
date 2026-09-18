//! Redis-backed distributed rate limiting — token bucket via Lua script
//!
//! Feature-gated behind `redis`. Uses an atomic Lua script for
//! distributed token bucket rate limiting across multiple gateway instances.
//! Fails closed on Redis connection errors by default. Operators can opt into
//! fail-open behaviour explicitly with `redis_fail_open = true`.

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
    /// Whether Redis failures should allow traffic.
    fail_open: bool,
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
        if rate == 0 || burst == 0 {
            return Err(GatewayError::Config(
                "rate-limit-redis requires rate and burst greater than zero".to_string(),
            ));
        }

        Ok(Self {
            connection: Arc::new(Mutex::new(None)),
            redis_url: redis_url.to_string(),
            rate,
            burst,
            key_prefix: "a3s:ratelimit".to_string(),
            fail_open: config.redis_fail_open,
        })
    }

    /// Create directly (for programmatic use)
    #[allow(dead_code)]
    pub fn with_params(redis_url: &str, rate: u64, burst: u64) -> Result<Self> {
        if redis_url.is_empty() {
            return Err(GatewayError::Config(
                "redis_url cannot be empty".to_string(),
            ));
        }
        if rate == 0 || burst == 0 {
            return Err(GatewayError::Config(
                "rate-limit-redis requires rate and burst greater than zero".to_string(),
            ));
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(None)),
            redis_url: redis_url.to_string(),
            rate,
            burst,
            key_prefix: "a3s:ratelimit".to_string(),
            fail_open: false,
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

    /// Probe the same connect surface as the first rate-limit request.
    ///
    /// Used by `validate_activation` when `redis_fail_open = false` so an
    /// unreachable Redis cannot soft-open Running and only return 503 on traffic.
    pub(crate) async fn probe_activation(redis_url: &str) -> Result<()> {
        let client = redis::Client::open(redis_url).map_err(|error| {
            GatewayError::Config(format!(
                "rate-limit-redis cannot activate: invalid redis_url '{redis_url}': {error}"
            ))
        })?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|error| {
                GatewayError::Config(format!(
                    "rate-limit-redis cannot activate: Redis unreachable at '{redis_url}': {error}"
                ))
            })?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(|error| {
                GatewayError::Config(format!(
                    "rate-limit-redis cannot activate: Redis PING failed at '{redis_url}': {error}"
                ))
            })?;
        Ok(())
    }
}

/// Sync activation probe for fail-closed `rate-limit-redis` middlewares.
///
/// Skips `redis_fail_open = true` (explicit degraded contract). Deduplicates by
/// `redis_url` so shared backends are probed once.
pub(crate) fn validate_redis_rate_limit_activation(
    middlewares: &std::collections::HashMap<String, MiddlewareConfig>,
) -> Result<()> {
    let mut probed = std::collections::HashSet::<String>::new();
    for (name, config) in middlewares {
        if config.middleware_type != "rate-limit-redis" || config.redis_fail_open {
            continue;
        }
        let Some(redis_url) = config.redis_url.as_deref() else {
            continue;
        };
        if !probed.insert(redis_url.to_string()) {
            continue;
        }
        probe_redis_url_sync(name, redis_url)?;
    }
    Ok(())
}

fn probe_redis_url_sync(middleware_name: &str, redis_url: &str) -> Result<()> {
    let redis_url = redis_url.to_string();
    let label = middleware_name.to_string();
    let result = match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
        {
            tokio::task::block_in_place(|| {
                handle.block_on(RedisRateLimitMiddleware::probe_activation(&redis_url))
            })
        }
        Ok(_) | Err(_) => std::thread::Builder::new()
            .name("a3s-redis-activation-probe".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| {
                        GatewayError::Config(format!(
                            "rate-limit-redis cannot activate: failed to create probe runtime: {error}"
                        ))
                    })?;
                runtime.block_on(RedisRateLimitMiddleware::probe_activation(&redis_url))
            })
            .map_err(|error| {
                GatewayError::Config(format!(
                    "rate-limit-redis cannot activate: failed to spawn probe thread: {error}"
                ))
            })?
            .join()
            .map_err(|_| {
                GatewayError::Config(
                    "rate-limit-redis cannot activate: probe thread panicked".to_string(),
                )
            })?,
    };
    result.map_err(|error| match error {
        GatewayError::Config(message) => {
            GatewayError::Config(format!("Middleware '{label}': {message}"))
        }
        other => GatewayError::Config(format!("Middleware '{label}': {other}")),
    })
}

#[async_trait]
impl Middleware for RedisRateLimitMiddleware {
    async fn handle_request(
        &self,
        _req: &mut http::request::Parts,
        ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        let key = format!("{}:{}:{}", self.key_prefix, ctx.router, ctx.client_ip);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let conn = match self.get_connection().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    fail_open = self.fail_open,
                    "Redis rate limiter unavailable"
                );
                return if self.fail_open {
                    Ok(None)
                } else {
                    Ok(Some(redis_unavailable_response()))
                };
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
                tracing::warn!(
                    error = %e,
                    fail_open = self.fail_open,
                    "Redis rate limit script failed"
                );
                if self.fail_open {
                    Ok(None)
                } else {
                    Ok(Some(redis_unavailable_response()))
                }
            }
        }
    }

    fn name(&self) -> &str {
        "rate-limit-redis"
    }
}

fn redis_unavailable_response() -> Response<Vec<u8>> {
    match Response::builder()
        .status(503)
        .header("Content-Type", "application/json")
        .header("Retry-After", "1")
        .body(crate::error::json_error_body(
            "Distributed rate limiter unavailable",
        )) {
        Ok(response) => response,
        Err(_) => Response::new(crate::error::json_error_body(
            "Distributed rate limiter unavailable",
        )),
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
    async fn test_fail_closed_on_unreachable_redis_by_default() {
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
        // Protection remains active when the distributed store is unavailable.
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert_eq!(result.unwrap().status(), 503);
    }

    #[tokio::test]
    async fn test_fail_open_requires_explicit_configuration() {
        let mut config = make_config("redis://127.0.0.1:1", 100, 50);
        config.redis_fail_open = true;
        let mw = RedisRateLimitMiddleware::new(&config).unwrap();

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
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn probe_activation_rejects_unreachable_redis() {
        let error = RedisRateLimitMiddleware::probe_activation("redis://127.0.0.1:1")
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("Redis unreachable")
                || error
                    .to_string()
                    .contains("rate-limit-redis cannot activate"),
            "unreachable Redis must fail probe_activation: {error}"
        );
    }

    #[test]
    fn validate_skips_fail_open_middlewares() {
        let mut middlewares = std::collections::HashMap::new();
        middlewares.insert(
            "open".to_string(),
            MiddlewareConfig {
                middleware_type: "rate-limit-redis".to_string(),
                redis_url: Some("redis://127.0.0.1:1".to_string()),
                rate: Some(100),
                burst: Some(50),
                redis_fail_open: true,
                ..Default::default()
            },
        );
        validate_redis_rate_limit_activation(&middlewares)
            .expect("redis_fail_open must skip activation probe");
    }
}
