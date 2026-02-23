//! Centralized error types for A3S Gateway

use thiserror::Error;

/// Gateway error types
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Configuration file parsing or validation failed
    #[error("Configuration error: {0}")]
    Config(String),

    /// Route matching failed
    #[error("No route matched for request: {0}")]
    NoRouteMatch(String),

    /// Upstream service is unavailable
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Request to upstream timed out
    #[error("Upstream timeout after {0}ms")]
    UpstreamTimeout(u64),

    /// HTTP request or response error
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Middleware rejected the request
    #[error("Middleware rejected: {0}")]
    MiddlewareRejected(String),

    /// TLS configuration error
    #[error("TLS error: {0}")]
    Tls(String),

    /// Service discovery error
    #[error("Discovery error: {0}")]
    Discovery(String),

    /// Scaling operation error
    #[error("Scaling error: {0}")]
    Scaling(String),

    /// Request buffer timeout (scale-from-zero)
    #[error("Buffer timeout: {0}")]
    BufferTimeout(String),

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
        let err = GatewayError::Config("invalid entrypoint".into());
        assert_eq!(err.to_string(), "Configuration error: invalid entrypoint");
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
    fn test_error_display_discovery() {
        let err = GatewayError::Discovery("seed unreachable".into());
        assert_eq!(err.to_string(), "Discovery error: seed unreachable");
    }

    #[test]
    fn test_error_display_scaling() {
        let err = GatewayError::Scaling("executor failed".into());
        assert_eq!(err.to_string(), "Scaling error: executor failed");
    }

    #[test]
    fn test_error_display_buffer_timeout() {
        let err = GatewayError::BufferTimeout("service-api".into());
        assert_eq!(err.to_string(), "Buffer timeout: service-api");
    }

    #[test]
    fn test_error_display_other() {
        let err = GatewayError::Other("unexpected".into());
        assert_eq!(err.to_string(), "unexpected");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err: GatewayError = io_err.into();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_error_from_serde_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
        let err: GatewayError = json_err.into();
        assert!(matches!(err, GatewayError::Serialization(_)));
    }

    #[test]
    fn test_error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<GatewayError>();
    }

    #[test]
    fn test_result_type_alias() {
        let ok: Result<u32> = Ok(42);
        assert!(matches!(ok, Ok(42)));

        let err: Result<u32> = Err(GatewayError::Other("test".into()));
        assert!(err.is_err());
    }
}
