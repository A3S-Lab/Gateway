//! Middleware configuration — request/response transformation

use serde::{Deserialize, Serialize};

/// Middleware configuration
///
/// Each middleware has a type and type-specific parameters.
///
/// # Example
///
/// ```toml
/// [middlewares.auth]
/// type = "api-key"
/// header = "X-API-Key"
/// keys = ["secret-key-1", "secret-key-2"]
///
/// [middlewares.rate-limit]
/// type = "rate-limit"
/// rate = 100
/// burst = 50
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct MiddlewareConfig {
    /// Middleware type identifier
    #[serde(rename = "type")]
    pub middleware_type: String,

    /// API key header name (for api-key auth)
    #[serde(default)]
    pub header: Option<String>,

    /// API key values (for api-key auth)
    #[serde(default)]
    pub keys: Vec<String>,

    /// Single value (for custom-header verification)
    #[serde(default)]
    pub value: Option<String>,

    /// Username (for basic-auth)
    #[serde(default)]
    pub username: Option<String>,

    /// Password (for basic-auth)
    #[serde(default)]
    pub password: Option<String>,

    /// Rate limit: requests per second
    #[serde(default)]
    pub rate: Option<u64>,

    /// Rate limit: burst size
    #[serde(default)]
    pub burst: Option<u64>,

    /// CORS: allowed origins
    #[serde(default)]
    pub allowed_origins: Vec<String>,

    /// CORS: allowed methods
    #[serde(default)]
    pub allowed_methods: Vec<String>,

    /// CORS: allowed headers
    #[serde(default)]
    pub allowed_headers: Vec<String>,

    /// CORS: max age in seconds
    #[serde(default)]
    pub max_age: Option<u64>,

    /// Headers to add to request
    #[serde(default)]
    pub request_headers: std::collections::HashMap<String, String>,

    /// Headers to add to response
    #[serde(default)]
    pub response_headers: std::collections::HashMap<String, String>,

    /// Path prefixes to strip
    #[serde(default)]
    pub prefixes: Vec<String>,

    /// Retry: max attempts
    #[serde(default)]
    pub max_retries: Option<u32>,

    /// Retry: interval in milliseconds
    #[serde(default)]
    pub retry_interval_ms: Option<u64>,

    /// IP allowlist
    #[serde(default)]
    pub allowed_ips: Vec<String>,

    /// Forward auth: URL of the external authentication service
    #[serde(default)]
    pub forward_auth_url: Option<String>,

    /// Forward auth: headers to copy from auth response to upstream request
    #[serde(default)]
    pub forward_auth_response_headers: Vec<String>,

    /// Redis URL for distributed rate limiting (e.g., "redis://127.0.0.1:6379")
    #[serde(default)]
    pub redis_url: Option<String>,

    /// Maximum request body size in bytes (for body-limit middleware)
    #[serde(default)]
    pub max_body_bytes: Option<u64>,

    /// Circuit breaker: number of consecutive failures before opening
    #[serde(default)]
    pub failure_threshold: Option<u32>,

    /// Circuit breaker: seconds the circuit stays open before trying half-open
    #[serde(default)]
    pub cooldown_secs: Option<u64>,

    /// Circuit breaker: number of successes in half-open state to close the circuit
    #[serde(default)]
    pub success_threshold: Option<u32>,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_api_key_middleware() {
        let toml = r#"
            type = "api-key"
            header = "X-API-Key"
            keys = ["key1", "key2"]
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "api-key");
        assert_eq!(mw.header.unwrap(), "X-API-Key");
        assert_eq!(mw.keys, vec!["key1", "key2"]);
    }

    #[test]
    fn test_parse_rate_limit_middleware() {
        let toml = r#"
            type = "rate-limit"
            rate = 100
            burst = 50
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "rate-limit");
        assert_eq!(mw.rate.unwrap(), 100);
        assert_eq!(mw.burst.unwrap(), 50);
    }

    #[test]
    fn test_parse_cors_middleware() {
        let toml = r#"
            type = "cors"
            allowed_origins = ["https://example.com", "https://app.example.com"]
            allowed_methods = ["GET", "POST", "PUT"]
            allowed_headers = ["Content-Type", "Authorization"]
            max_age = 3600
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "cors");
        assert_eq!(mw.allowed_origins.len(), 2);
        assert_eq!(mw.allowed_methods.len(), 3);
        assert_eq!(mw.max_age.unwrap(), 3600);
    }

    #[test]
    fn test_parse_headers_middleware() {
        let toml = r#"
            type = "headers"
            [request_headers]
            "X-Forwarded-Proto" = "https"
            [response_headers]
            "X-Frame-Options" = "DENY"
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "headers");
        assert_eq!(mw.request_headers["X-Forwarded-Proto"], "https");
        assert_eq!(mw.response_headers["X-Frame-Options"], "DENY");
    }

    #[test]
    fn test_parse_strip_prefix_middleware() {
        let toml = r#"
            type = "strip-prefix"
            prefixes = ["/api/v1", "/api/v2"]
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "strip-prefix");
        assert_eq!(mw.prefixes, vec!["/api/v1", "/api/v2"]);
    }

    #[test]
    fn test_parse_basic_auth_middleware() {
        let toml = r#"
            type = "basic-auth"
            username = "admin"
            password = "secret"
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "basic-auth");
        assert_eq!(mw.username.unwrap(), "admin");
        assert_eq!(mw.password.unwrap(), "secret");
    }

    #[test]
    fn test_parse_ip_allow_middleware() {
        let toml = r#"
            type = "ip-allow"
            allowed_ips = ["192.168.1.0/24", "10.0.0.1"]
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "ip-allow");
        assert_eq!(mw.allowed_ips.len(), 2);
    }

    #[test]
    fn test_parse_retry_middleware() {
        let toml = r#"
            type = "retry"
            max_retries = 3
            retry_interval_ms = 500
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "retry");
        assert_eq!(mw.max_retries.unwrap(), 3);
        assert_eq!(mw.retry_interval_ms.unwrap(), 500);
    }

    #[test]
    fn test_parse_forward_auth_middleware() {
        let toml = r#"
            type = "forward-auth"
            forward_auth_url = "http://auth.internal:9090/verify"
            forward_auth_response_headers = ["X-User-Id", "X-User-Role"]
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "forward-auth");
        assert_eq!(
            mw.forward_auth_url.unwrap(),
            "http://auth.internal:9090/verify"
        );
        assert_eq!(mw.forward_auth_response_headers.len(), 2);
    }

    #[test]
    fn test_parse_body_limit_middleware() {
        let toml = r#"
            type = "body-limit"
            max_body_bytes = 1048576
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "body-limit");
        assert_eq!(mw.max_body_bytes.unwrap(), 1_048_576);
    }

    #[test]
    fn test_parse_rate_limit_redis_middleware() {
        let toml = r#"
            type = "rate-limit-redis"
            rate = 200
            burst = 100
            redis_url = "redis://127.0.0.1:6379"
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "rate-limit-redis");
        assert_eq!(mw.redis_url.unwrap(), "redis://127.0.0.1:6379");
        assert_eq!(mw.rate.unwrap(), 200);
    }

    #[test]
    fn test_middleware_defaults() {
        let toml = r#"
            type = "noop"
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert!(mw.header.is_none());
        assert!(mw.keys.is_empty());
        assert!(mw.rate.is_none());
        assert!(mw.burst.is_none());
        assert!(mw.allowed_origins.is_empty());
        assert!(mw.request_headers.is_empty());
        assert!(mw.prefixes.is_empty());
        assert!(mw.allowed_ips.is_empty());
        assert!(mw.forward_auth_url.is_none());
        assert!(mw.forward_auth_response_headers.is_empty());
        assert!(mw.redis_url.is_none());
        assert!(mw.max_body_bytes.is_none());
    }

    #[test]
    fn test_parse_circuit_breaker_middleware() {
        let toml = r#"
            type = "circuit-breaker"
            failure_threshold = 3
            cooldown_secs = 60
            success_threshold = 2
        "#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert_eq!(mw.middleware_type, "circuit-breaker");
        assert_eq!(mw.failure_threshold.unwrap(), 3);
        assert_eq!(mw.cooldown_secs.unwrap(), 60);
        assert_eq!(mw.success_threshold.unwrap(), 2);
    }

    #[test]
    fn test_parse_circuit_breaker_defaults() {
        let toml = r#"type = "circuit-breaker""#;
        let mw: MiddlewareConfig = toml::from_str(toml).unwrap();
        assert!(mw.failure_threshold.is_none());
        assert!(mw.cooldown_secs.is_none());
        assert!(mw.success_threshold.is_none());
    }

    #[test]
    fn test_middleware_config_default_impl() {
        let config = MiddlewareConfig::default();
        assert!(config.middleware_type.is_empty());
        assert!(config.header.is_none());
        assert!(config.keys.is_empty());
        assert!(config.forward_auth_url.is_none());
        assert!(config.max_body_bytes.is_none());
        assert!(config.redis_url.is_none());
        assert!(config.failure_threshold.is_none());
        assert!(config.cooldown_secs.is_none());
        assert!(config.success_threshold.is_none());
    }
}
