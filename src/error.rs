//! Centralized error types for A3S Gateway
//!
//! Provides a unified error type and Result alias for the gateway crate.
//! All errors include context for debugging and are mapped to appropriate
//! HTTP status codes when returned as responses.

use thiserror::Error;

/// Gateway error types
///
/// Covers all error conditions that can occur during gateway operation,
/// from configuration parsing to request proxying.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Configuration file parsing or validation failed
    #[error("Configuration error: {0}")]
    Config(String),

    /// Route matching failed — no route found for the request
    #[error("No route matched for request: {0}")]
    NoRouteMatch(String),

    /// Upstream service is unavailable or all backends are down
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Request to upstream timed out
    #[error("Upstream timeout after {0}ms")]
    UpstreamTimeout(u64),

    /// HTTP request or response error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// IO error (file, network, etc.)
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// TOML configuration parsing error
    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// Middleware rejected the request (auth failure, rate limit, etc.)
    #[error("Middleware rejected: {0}")]
    MiddlewareRejected(String),

    /// TLS configuration error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Generic error with context
    #[error("{0}")]
    Other(String),
}

/// Convenience Result type alias
pub type Result<T> = std::result::Result<T, GatewayError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display_config() {
        let err = GatewayError::Config("invalid entrypoint address".into());
        assert_eq!(
            err.to_string(),
            "Configuration error: invalid entrypoint address"
        );
    }

    #[test]
    fn test_error_display_no_route() {
        let err = GatewayError::NoRouteMatch("GET /unknown".into());
        assert_eq!(
            err.to_string(),
            "No route matched for request: GET /unknown"
        );
    }

    #[test]
    fn test_error_display_service_unavailable() {
        let err = GatewayError::ServiceUnavailable("backend-api".into());
        assert_eq!(err.to_string(), "Service unavailable: backend-api");
    }

    #[test]
    fn test_error_display_upstream_timeout() {
        let err = GatewayError::UpstreamTimeout(5000);
        assert_eq!(err.to_string(), "Upstream timeout after 5000ms");
    }

    #[test]
    fn test_error_display_middleware_rejected() {
        let err = GatewayError::MiddlewareRejected("rate limit exceeded".into());
        assert_eq!(err.to_string(), "Middleware rejected: rate limit exceeded");
    }

    #[test]
    fn test_error_display_tls() {
        let err = GatewayError::Tls("certificate expired".into());
        assert_eq!(err.to_string(), "TLS error: certificate expired");
    }

    #[test]
    fn test_error_display_other() {
        let err = GatewayError::Other("unexpected condition".into());
        assert_eq!(err.to_string(), "unexpected condition");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: GatewayError = io_err.into();
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn test_error_from_serde_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err: GatewayError = json_err.into();
        assert!(matches!(err, GatewayError::Serialization(_)));
    }

    #[test]
    fn test_error_from_toml() {
        let toml_err = toml::from_str::<toml::Value>("= invalid").unwrap_err();
        let err: GatewayError = toml_err.into();
        assert!(matches!(err, GatewayError::TomlParse(_)));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GatewayError>();
    }

    #[test]
    fn test_result_type_alias() {
        let ok: Result<u32> = Ok(42);
        assert_eq!(ok.unwrap(), 42);

        let err: Result<u32> = Err(GatewayError::Other("test".into()));
        assert!(err.is_err());
    }
}
