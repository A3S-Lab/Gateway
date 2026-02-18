//! Structured access log — JSON-formatted request/response logging
//!
//! Produces structured log entries for each proxied request,
//! suitable for ingestion by log aggregation systems.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// A single access log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogEntry {
    /// ISO 8601 timestamp
    pub timestamp: String,
    /// Client IP address
    pub client_ip: String,
    /// HTTP method
    pub method: String,
    /// Request path
    pub path: String,
    /// Host header value
    pub host: Option<String>,
    /// HTTP status code
    pub status: u16,
    /// Response size in bytes
    pub response_bytes: u64,
    /// Request duration in milliseconds
    pub duration_ms: u64,
    /// Backend URL the request was forwarded to
    pub backend: Option<String>,
    /// Router that matched
    pub router: Option<String>,
    /// Entrypoint name
    pub entrypoint: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
}

/// Access log manager — tracks and emits structured log entries
pub struct AccessLog {
    total_entries: Arc<AtomicU64>,
}

impl AccessLog {
    /// Create a new access log manager
    pub fn new() -> Self {
        Self {
            total_entries: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Start tracking a request. Returns a RequestTracker to measure duration.
    pub fn start_request(&self) -> RequestTracker {
        RequestTracker {
            start: Instant::now(),
        }
    }

    /// Record and emit a log entry
    pub fn record(&self, entry: &AccessLogEntry) {
        self.total_entries.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            target: "access_log",
            client_ip = entry.client_ip,
            method = entry.method,
            path = entry.path,
            status = entry.status,
            duration_ms = entry.duration_ms,
            response_bytes = entry.response_bytes,
            backend = entry.backend.as_deref().unwrap_or("-"),
            router = entry.router.as_deref().unwrap_or("-"),
            "{}",
            serde_json::to_string(entry).unwrap_or_default()
        );
    }

    /// Get total number of logged entries
    #[allow(dead_code)]
    pub fn total_entries(&self) -> u64 {
        self.total_entries.load(Ordering::Relaxed)
    }
}

impl Default for AccessLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Tracks request duration
pub struct RequestTracker {
    start: Instant,
}

impl RequestTracker {
    /// Get elapsed time in milliseconds since the request started
    pub fn elapsed_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Build an access log entry from the tracked request
    #[allow(clippy::too_many_arguments)]
    pub fn build_entry(
        &self,
        client_ip: String,
        method: String,
        path: String,
        host: Option<String>,
        status: u16,
        response_bytes: u64,
        backend: Option<String>,
        router: Option<String>,
        entrypoint: Option<String>,
        user_agent: Option<String>,
    ) -> AccessLogEntry {
        AccessLogEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            client_ip,
            method,
            path,
            host,
            status,
            response_bytes,
            duration_ms: self.elapsed_ms(),
            backend,
            router,
            entrypoint,
            user_agent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> AccessLogEntry {
        AccessLogEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            client_ip: "10.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/api/v1/users".to_string(),
            host: Some("api.example.com".to_string()),
            status: 200,
            response_bytes: 1024,
            duration_ms: 42,
            backend: Some("http://backend:8080".to_string()),
            router: Some("api".to_string()),
            entrypoint: Some("websecure".to_string()),
            user_agent: Some("curl/8.0".to_string()),
        }
    }

    #[test]
    fn test_entry_serialization() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"method\":\"GET\""));
        assert!(json.contains("\"status\":200"));

        let parsed: AccessLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.path, "/api/v1/users");
    }

    #[test]
    fn test_entry_with_none_fields() {
        let entry = AccessLogEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            client_ip: "10.0.0.1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            host: None,
            status: 404,
            response_bytes: 0,
            duration_ms: 1,
            backend: None,
            router: None,
            entrypoint: None,
            user_agent: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AccessLogEntry = serde_json::from_str(&json).unwrap();
        assert!(parsed.host.is_none());
        assert!(parsed.backend.is_none());
    }

    #[test]
    fn test_access_log_total_entries() {
        let log = AccessLog::new();
        assert_eq!(log.total_entries(), 0);
        log.record(&sample_entry());
        assert_eq!(log.total_entries(), 1);
        log.record(&sample_entry());
        assert_eq!(log.total_entries(), 2);
    }

    #[test]
    fn test_access_log_default() {
        let log = AccessLog::default();
        assert_eq!(log.total_entries(), 0);
    }

    #[test]
    fn test_request_tracker_elapsed() {
        let log = AccessLog::new();
        let tracker = log.start_request();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let elapsed = tracker.elapsed_ms();
        assert!(elapsed >= 5); // Allow for timing imprecision
    }

    #[test]
    fn test_request_tracker_build_entry() {
        let log = AccessLog::new();
        let tracker = log.start_request();
        let entry = tracker.build_entry(
            "10.0.0.1".to_string(),
            "POST".to_string(),
            "/api/submit".to_string(),
            Some("api.example.com".to_string()),
            201,
            256,
            Some("http://backend:8080".to_string()),
            Some("api".to_string()),
            Some("websecure".to_string()),
            None,
        );
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.status, 201);
        assert_eq!(entry.response_bytes, 256);
        assert!(!entry.timestamp.is_empty());
    }

    #[test]
    fn test_entry_all_status_codes() {
        for status in [200u16, 201, 301, 400, 403, 404, 500, 502, 503] {
            let entry = AccessLogEntry {
                status,
                ..sample_entry()
            };
            let json = serde_json::to_string(&entry).unwrap();
            let parsed: AccessLogEntry = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed.status, status);
        }
    }
}
