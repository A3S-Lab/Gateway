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
    }
}
