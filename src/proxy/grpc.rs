//! gRPC proxy — HTTP/2 (h2c) request forwarding
//!
//! Forwards gRPC requests to upstream backends using HTTP/2 cleartext (h2c).
//! Supports unary, server-streaming, client-streaming, and bidirectional RPCs.

use crate::error::{GatewayError, Result};
use crate::service::Backend;
use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;

/// gRPC content type prefix
const GRPC_CONTENT_TYPE: &str = "application/grpc";

/// gRPC proxy — forwards gRPC requests over HTTP/2
pub struct GrpcProxy {
    client: reqwest::Client,
    timeout: Duration,
}

impl GrpcProxy {
    /// Create a new gRPC proxy with default settings
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(60))
    }

    /// Create with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .http2_prior_knowledge()
            .pool_max_idle_per_host(50)
            .build()
            .unwrap_or_default();

        Self { client, timeout }
    }

    /// Forward a gRPC request to the selected backend
    pub async fn forward(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<GrpcResponse> {
        backend.inc_connections();
        let result = self.do_forward(backend, method, uri, headers, body).await;
        backend.dec_connections();
        result
    }

    async fn do_forward(
        &self,
        backend: &Arc<Backend>,
        _method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<GrpcResponse> {
        // Build upstream URL: h2c://host:port/service/method
        let backend_url = backend.url.trim_end_matches('/');
        let scheme = if backend_url.starts_with("h2c://") {
            "http"
        } else if backend_url.starts_with("https://") {
            "https"
        } else {
            "http"
        };

        let host = extract_grpc_host(backend_url);
        let path = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let upstream_url = format!("{}://{}{}", scheme, host, path);

        // gRPC always uses POST
        let mut req_builder = self.client.post(&upstream_url);

        // Forward headers, preserving gRPC-specific ones
        for (key, value) in headers.iter() {
            let name = key.as_str();
            if !is_grpc_hop_by_hop(name) {
                req_builder = req_builder.header(key.clone(), value.clone());
            }
        }

        // Ensure content-type is set
        req_builder = req_builder.header("content-type", GRPC_CONTENT_TYPE);

        // Forward body
        req_builder = req_builder.body(body);

        let response = req_builder.send().await.map_err(|e| {
            if e.is_timeout() {
                GatewayError::UpstreamTimeout(self.timeout.as_millis() as u64)
            } else if e.is_connect() {
                GatewayError::ServiceUnavailable(format!(
                    "Cannot connect to gRPC backend {}: {}",
                    backend.url, e
                ))
            } else {
                GatewayError::Http(e)
            }
        })?;

        let status = response.status();
        let resp_headers = response.headers().clone();

        // Extract grpc-status from headers (trailers in HTTP/2)
        let grpc_status = resp_headers
            .get("grpc-status")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(-1);

        let grpc_message = resp_headers
            .get("grpc-message")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let resp_body = response.bytes().await.map_err(GatewayError::Http)?;

        Ok(GrpcResponse {
            http_status: status,
            headers: resp_headers,
            body: resp_body,
            grpc_status,
            grpc_message,
        })
    }

    /// Get the timeout
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for GrpcProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Response from a gRPC upstream
pub struct GrpcResponse {
    /// HTTP status code
    pub http_status: reqwest::StatusCode,
    /// Response headers
    pub headers: reqwest::header::HeaderMap,
    /// Response body (protobuf-encoded)
    pub body: Bytes,
    /// gRPC status code (0 = OK)
    pub grpc_status: i32,
    /// gRPC status message
    pub grpc_message: Option<String>,
}

impl GrpcResponse {
    /// Check if the gRPC call succeeded
    pub fn is_ok(&self) -> bool {
        self.grpc_status == 0
    }
}

/// Check if a request looks like a gRPC request
pub fn is_grpc_request(headers: &http::HeaderMap) -> bool {
    headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with(GRPC_CONTENT_TYPE))
        .unwrap_or(false)
}

/// Extract host:port from a gRPC backend URL
fn extract_grpc_host(url: &str) -> &str {
    if let Some(rest) = url.strip_prefix("h2c://") {
        rest.trim_end_matches('/')
    } else if let Some(rest) = url.strip_prefix("http://") {
        rest.trim_end_matches('/')
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest.trim_end_matches('/')
    } else {
        url.trim_end_matches('/')
    }
}

/// Headers that should not be forwarded in gRPC proxying
fn is_grpc_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_lowercase().as_str(),
        "connection" | "keep-alive" | "transfer-encoding" | "upgrade"
    )
}

/// Standard gRPC status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GrpcStatus {
    Ok = 0,
    Cancelled = 1,
    Unknown = 2,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    OutOfRange = 11,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
}

impl GrpcStatus {
    /// Parse from integer code
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            0 => Some(Self::Ok),
            1 => Some(Self::Cancelled),
            2 => Some(Self::Unknown),
            3 => Some(Self::InvalidArgument),
            4 => Some(Self::DeadlineExceeded),
            5 => Some(Self::NotFound),
            6 => Some(Self::AlreadyExists),
            7 => Some(Self::PermissionDenied),
            8 => Some(Self::ResourceExhausted),
            9 => Some(Self::FailedPrecondition),
            10 => Some(Self::Aborted),
            11 => Some(Self::OutOfRange),
            12 => Some(Self::Unimplemented),
            13 => Some(Self::Internal),
            14 => Some(Self::Unavailable),
            15 => Some(Self::DataLoss),
            16 => Some(Self::Unauthenticated),
            _ => None,
        }
    }

    /// Get the status name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Cancelled => "CANCELLED",
            Self::Unknown => "UNKNOWN",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::NotFound => "NOT_FOUND",
            Self::AlreadyExists => "ALREADY_EXISTS",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Aborted => "ABORTED",
            Self::OutOfRange => "OUT_OF_RANGE",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Internal => "INTERNAL",
            Self::Unavailable => "UNAVAILABLE",
            Self::DataLoss => "DATA_LOSS",
            Self::Unauthenticated => "UNAUTHENTICATED",
        }
    }
}

impl std::fmt::Display for GrpcStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), *self as i32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- GrpcProxy construction ---

    #[test]
    fn test_grpc_proxy_default() {
        let proxy = GrpcProxy::default();
        assert_eq!(proxy.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_grpc_proxy_custom_timeout() {
        let proxy = GrpcProxy::with_timeout(Duration::from_secs(120));
        assert_eq!(proxy.timeout(), Duration::from_secs(120));
    }

    // --- is_grpc_request ---

    #[test]
    fn test_is_grpc_request_true() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/grpc".parse().unwrap());
        assert!(is_grpc_request(&headers));
    }

    #[test]
    fn test_is_grpc_request_with_proto() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "content-type",
            "application/grpc+proto".parse().unwrap(),
        );
        assert!(is_grpc_request(&headers));
    }

    #[test]
    fn test_is_grpc_request_false() {
        let mut headers = http::HeaderMap::new();
        headers.insert("content-type", "application/json".parse().unwrap());
        assert!(!is_grpc_request(&headers));
    }

    #[test]
    fn test_is_grpc_request_no_content_type() {
        let headers = http::HeaderMap::new();
        assert!(!is_grpc_request(&headers));
    }

    // --- extract_grpc_host ---

    #[test]
    fn test_extract_grpc_host_h2c() {
        assert_eq!(extract_grpc_host("h2c://127.0.0.1:50051"), "127.0.0.1:50051");
    }

    #[test]
    fn test_extract_grpc_host_http() {
        assert_eq!(extract_grpc_host("http://grpc.local:50051"), "grpc.local:50051");
    }

    #[test]
    fn test_extract_grpc_host_https() {
        assert_eq!(extract_grpc_host("https://grpc.local:443"), "grpc.local:443");
    }

    #[test]
    fn test_extract_grpc_host_bare() {
        assert_eq!(extract_grpc_host("127.0.0.1:50051"), "127.0.0.1:50051");
    }

    #[test]
    fn test_extract_grpc_host_trailing_slash() {
        assert_eq!(extract_grpc_host("h2c://127.0.0.1:50051/"), "127.0.0.1:50051");
    }

    // --- is_grpc_hop_by_hop ---

    #[test]
    fn test_grpc_hop_by_hop() {
        assert!(is_grpc_hop_by_hop("connection"));
        assert!(is_grpc_hop_by_hop("Connection"));
        assert!(is_grpc_hop_by_hop("transfer-encoding"));
        assert!(is_grpc_hop_by_hop("upgrade"));
        assert!(!is_grpc_hop_by_hop("content-type"));
        assert!(!is_grpc_hop_by_hop("grpc-status"));
        assert!(!is_grpc_hop_by_hop("authorization"));
    }

    // --- GrpcStatus ---

    #[test]
    fn test_grpc_status_from_code() {
        assert_eq!(GrpcStatus::from_code(0), Some(GrpcStatus::Ok));
        assert_eq!(GrpcStatus::from_code(1), Some(GrpcStatus::Cancelled));
        assert_eq!(GrpcStatus::from_code(4), Some(GrpcStatus::DeadlineExceeded));
        assert_eq!(GrpcStatus::from_code(13), Some(GrpcStatus::Internal));
        assert_eq!(GrpcStatus::from_code(14), Some(GrpcStatus::Unavailable));
        assert_eq!(GrpcStatus::from_code(16), Some(GrpcStatus::Unauthenticated));
        assert_eq!(GrpcStatus::from_code(99), None);
        assert_eq!(GrpcStatus::from_code(-1), None);
    }

    #[test]
    fn test_grpc_status_name() {
        assert_eq!(GrpcStatus::Ok.name(), "OK");
        assert_eq!(GrpcStatus::NotFound.name(), "NOT_FOUND");
        assert_eq!(GrpcStatus::Internal.name(), "INTERNAL");
        assert_eq!(GrpcStatus::Unavailable.name(), "UNAVAILABLE");
    }

    #[test]
    fn test_grpc_status_display() {
        assert_eq!(GrpcStatus::Ok.to_string(), "OK (0)");
        assert_eq!(GrpcStatus::NotFound.to_string(), "NOT_FOUND (5)");
        assert_eq!(GrpcStatus::Internal.to_string(), "INTERNAL (13)");
    }

    #[test]
    fn test_grpc_status_all_codes() {
        for code in 0..=16 {
            let status = GrpcStatus::from_code(code);
            assert!(status.is_some(), "Code {} should be valid", code);
            assert_eq!(status.unwrap() as i32, code);
        }
    }

    // --- GrpcResponse ---

    #[test]
    fn test_grpc_response_is_ok() {
        let resp = GrpcResponse {
            http_status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            body: Bytes::new(),
            grpc_status: 0,
            grpc_message: None,
        };
        assert!(resp.is_ok());
    }

    #[test]
    fn test_grpc_response_is_not_ok() {
        let resp = GrpcResponse {
            http_status: reqwest::StatusCode::OK,
            headers: reqwest::header::HeaderMap::new(),
            body: Bytes::new(),
            grpc_status: 13,
            grpc_message: Some("internal error".to_string()),
        };
        assert!(!resp.is_ok());
        assert_eq!(resp.grpc_message.as_deref(), Some("internal error"));
    }
}
