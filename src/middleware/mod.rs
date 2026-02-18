//! Middleware pipeline — composable request/response transformations
//!
//! Middlewares are applied in order before the request reaches the backend,
//! and in reverse order for the response.

mod auth;
mod body_limit;
pub mod circuit_breaker;
pub mod compress;
mod cors;
mod forward_auth;
mod headers;
mod ip_allow;
pub mod ip_matcher;
pub mod jwt_auth;
mod rate_limit;
#[cfg(feature = "redis")]
mod rate_limit_redis;
mod retry;
mod strip_prefix;
mod tcp_filter;

pub use auth::AuthMiddleware;
pub use body_limit::BodyLimitMiddleware;
pub use circuit_breaker::CircuitBreakerMiddleware;
pub use compress::CompressMiddleware;
pub use cors::CorsMiddleware;
pub use forward_auth::ForwardAuthMiddleware;
pub use headers::HeadersMiddleware;
pub use ip_allow::IpAllowMiddleware;
pub use jwt_auth::JwtAuthMiddleware;
pub use rate_limit::RateLimitMiddleware;
#[cfg(feature = "redis")]
pub use rate_limit_redis::RedisRateLimitMiddleware;
pub use retry::RetryMiddleware;
pub use strip_prefix::StripPrefixMiddleware;
pub use tcp_filter::TcpFilter;

use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use async_trait::async_trait;
use http::Response;
use std::collections::HashMap;
use std::sync::Arc;

/// Request context passed through the middleware pipeline
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// Client IP address
    pub client_ip: String,
    /// Entrypoint name
    #[allow(dead_code)]
    pub entrypoint: String,
    /// Router name that matched
    #[cfg_attr(not(feature = "redis"), allow(dead_code))]
    pub router: String,
}

/// Middleware trait — process a request and optionally short-circuit
#[async_trait]
pub trait Middleware: Send + Sync {
    /// Process the request. Return Ok(None) to continue the pipeline,
    /// or Ok(Some(response)) to short-circuit with an immediate response.
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>>;

    /// Process the response (optional, default is pass-through)
    async fn handle_response(&self, _resp: &mut http::response::Parts) -> Result<()> {
        Ok(())
    }

    /// Middleware name for logging
    fn name(&self) -> &str;
}

/// Ordered middleware pipeline
pub struct Pipeline {
    middlewares: Vec<Arc<dyn Middleware>>,
}

impl Pipeline {
    /// Build a pipeline from middleware names and configurations
    pub fn from_config(
        names: &[String],
        configs: &HashMap<String, MiddlewareConfig>,
    ) -> Result<Self> {
        let mut middlewares: Vec<Arc<dyn Middleware>> = Vec::new();

        for name in names {
            let config = configs.get(name).ok_or_else(|| {
                GatewayError::Config(format!("Middleware '{}' not found in config", name))
            })?;

            let mw: Arc<dyn Middleware> = match config.middleware_type.as_str() {
                "api-key" => Arc::new(AuthMiddleware::api_key(config)?),
                "basic-auth" => Arc::new(AuthMiddleware::basic_auth(config)?),
                "rate-limit" => Arc::new(RateLimitMiddleware::new(config)?),
                "cors" => Arc::new(CorsMiddleware::new(config)),
                "headers" => Arc::new(HeadersMiddleware::new(config)),
                "strip-prefix" => Arc::new(StripPrefixMiddleware::new(config)),
                "ip-allow" => Arc::new(IpAllowMiddleware::new(config)?),
                "retry" => Arc::new(RetryMiddleware::new(config)?),
                "jwt" => Arc::new(JwtAuthMiddleware::new(config)?),
                "circuit-breaker" => Arc::new(CircuitBreakerMiddleware::new(
                    circuit_breaker::CircuitBreakerConfig {
                        failure_threshold: config.failure_threshold.unwrap_or(5),
                        cooldown: std::time::Duration::from_secs(
                            config.cooldown_secs.unwrap_or(30),
                        ),
                        success_threshold: config.success_threshold.unwrap_or(1),
                    },
                )),
                "compress" => Arc::new(CompressMiddleware::default()),
                "body-limit" => Arc::new(BodyLimitMiddleware::new(config)?),
                "forward-auth" => Arc::new(ForwardAuthMiddleware::new(config)?),
                #[cfg(feature = "redis")]
                "rate-limit-redis" => Arc::new(RedisRateLimitMiddleware::new(config)?),
                #[cfg(not(feature = "redis"))]
                "rate-limit-redis" => {
                    return Err(GatewayError::Config(
                        "rate-limit-redis requires the 'redis' feature flag: cargo build --features redis".to_string(),
                    ));
                }
                other => {
                    return Err(GatewayError::Config(format!(
                        "Unknown middleware type: '{}'",
                        other
                    )));
                }
            };

            middlewares.push(mw);
        }

        Ok(Self { middlewares })
    }

    /// Create an empty pipeline
    #[allow(dead_code)]
    pub fn empty() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }

    /// Execute the request through all middlewares.
    /// Returns Some(response) if any middleware short-circuits.
    pub async fn process_request(
        &self,
        parts: &mut http::request::Parts,
        ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        for mw in &self.middlewares {
            if let Some(response) = mw.handle_request(parts, ctx).await? {
                tracing::debug!(middleware = mw.name(), "Middleware short-circuited request");
                return Ok(Some(response));
            }
        }
        Ok(None)
    }

    /// Execute the response through all middlewares (reverse order)
    #[allow(dead_code)]
    pub async fn process_response(&self, parts: &mut http::response::Parts) -> Result<()> {
        for mw in self.middlewares.iter().rev() {
            mw.handle_response(parts).await?;
        }
        Ok(())
    }

    /// Number of middlewares in the pipeline
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.middlewares.len()
    }

    /// Whether the pipeline is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.middlewares.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_pipeline() {
        let pipeline = Pipeline::empty();
        assert!(pipeline.is_empty());
        assert_eq!(pipeline.len(), 0);
    }

    #[test]
    fn test_pipeline_from_config() {
        let mut configs = HashMap::new();
        configs.insert(
            "rate-limit".to_string(),
            MiddlewareConfig {
                middleware_type: "rate-limit".to_string(),
                rate: Some(100),
                burst: Some(50),
                ..default_mw_config()
            },
        );
        configs.insert(
            "cors".to_string(),
            MiddlewareConfig {
                middleware_type: "cors".to_string(),
                allowed_origins: vec!["*".to_string()],
                ..default_mw_config()
            },
        );

        let names = vec!["rate-limit".to_string(), "cors".to_string()];
        let pipeline = Pipeline::from_config(&names, &configs).unwrap();
        assert_eq!(pipeline.len(), 2);
    }

    #[test]
    fn test_pipeline_unknown_middleware_name() {
        let configs = HashMap::new();
        let names = vec!["nonexistent".to_string()];
        let result = Pipeline::from_config(&names, &configs);
        assert!(result.is_err());
    }

    #[test]
    fn test_pipeline_unknown_middleware_type() {
        let mut configs = HashMap::new();
        configs.insert(
            "bad".to_string(),
            MiddlewareConfig {
                middleware_type: "unknown-type".to_string(),
                ..default_mw_config()
            },
        );
        let names = vec!["bad".to_string()];
        let result = Pipeline::from_config(&names, &configs);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("Unknown middleware type")),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[tokio::test]
    async fn test_empty_pipeline_passthrough() {
        let pipeline = Pipeline::empty();
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
        let result = pipeline.process_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_pipeline_circuit_breaker_default_config() {
        let mut configs = HashMap::new();
        configs.insert(
            "cb".to_string(),
            MiddlewareConfig {
                middleware_type: "circuit-breaker".to_string(),
                ..default_mw_config()
            },
        );
        let names = vec!["cb".to_string()];
        let pipeline = Pipeline::from_config(&names, &configs).unwrap();
        assert_eq!(pipeline.len(), 1);
    }

    #[test]
    fn test_pipeline_circuit_breaker_custom_config() {
        let mut configs = HashMap::new();
        configs.insert(
            "cb".to_string(),
            MiddlewareConfig {
                middleware_type: "circuit-breaker".to_string(),
                failure_threshold: Some(3),
                cooldown_secs: Some(60),
                success_threshold: Some(2),
                ..default_mw_config()
            },
        );
        let names = vec!["cb".to_string()];
        let pipeline = Pipeline::from_config(&names, &configs).unwrap();
        assert_eq!(pipeline.len(), 1);
    }

    #[tokio::test]
    async fn test_circuit_breaker_allows_when_closed() {
        let mut configs = HashMap::new();
        configs.insert(
            "cb".to_string(),
            MiddlewareConfig {
                middleware_type: "circuit-breaker".to_string(),
                failure_threshold: Some(3),
                cooldown_secs: Some(30),
                success_threshold: Some(1),
                ..default_mw_config()
            },
        );
        let names = vec!["cb".to_string()];
        let pipeline = Pipeline::from_config(&names, &configs).unwrap();

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
        // Fresh circuit breaker is closed — request should pass through
        let result = pipeline.process_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
    }

    fn default_mw_config() -> MiddlewareConfig {
        MiddlewareConfig::default()
    }
}
