//! Structured access log — JSON-formatted request/response logging
//!
//! Produces structured log entries for each proxied request,
//! suitable for ingestion by log aggregation systems.

use crate::inference::{InferenceAttemptIdentity, InferenceRequestIdentity};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;
use uuid::Uuid;

/// Managed inference identities attached to one terminal access-log entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceAccessLogContext {
    /// Gateway-owned request identity.
    pub request_id: Uuid,
    /// Distributed trace identity used to correlate Gateway and upstream work.
    pub correlation_id: String,
    /// Stable inference route identity from the applied snapshot.
    pub route_id: Uuid,
    /// Immutable route-policy revision from the applied snapshot.
    pub route_policy_revision: u64,
    /// Closed managed inference endpoint name.
    pub endpoint: String,
    /// Stable logical model identity, once model selection succeeds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<Uuid>,
    /// Gateway-owned identity for the concrete upstream attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<Uuid>,
    /// Stable snapshot target identity selected for the attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<Uuid>,
}

impl InferenceAccessLogContext {
    fn from_request(identity: &InferenceRequestIdentity) -> Self {
        Self {
            request_id: identity.request_id(),
            correlation_id: identity.correlation_id().to_string(),
            route_id: identity.route_id(),
            route_policy_revision: identity.route_policy_revision(),
            endpoint: identity.endpoint().to_string(),
            model_id: identity.model_id(),
            attempt_id: None,
            target_id: None,
        }
    }

    fn from_attempt(identity: &InferenceAttemptIdentity) -> Self {
        let mut context = Self::from_request(identity.request());
        context.attempt_id = Some(identity.attempt_id());
        context.target_id = Some(identity.target_id());
        context
    }
}

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
    /// Managed inference identities, omitted for every ordinary request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<InferenceAccessLogContext>,
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

    /// Record and emit a log entry (called from background logging task)
    pub fn record(&self, entry: &AccessLogEntry) {
        self.total_entries.fetch_add(1, Ordering::Relaxed);
        let inference = entry.inference.as_ref();
        let request_id = inference.map(|context| context.request_id.to_string());
        let attempt_id = inference
            .and_then(|context| context.attempt_id.map(|attempt_id| attempt_id.to_string()));
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
            inference_request_id = request_id.as_deref().unwrap_or("-"),
            inference_attempt_id = attempt_id.as_deref().unwrap_or("-"),
            "{}",
            serde_json::to_string(entry).unwrap_or_default()
        );
    }

    /// Increment request counter only — for use with async logging channel.
    /// Callers send the entry to the log channel; a background task calls record().
    #[allow(dead_code)]
    pub fn count(&self) {
        self.total_entries.fetch_add(1, Ordering::Relaxed);
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
        inference: Option<InferenceAccessLogContext>,
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
            inference,
        }
    }
}

/// Request metadata and delivery state for one structured access log entry.
///
/// The request path enriches this value as routing and backend selection
/// succeed, then consumes it exactly once at the response or protocol terminal
/// boundary.
pub struct RequestAccessLog {
    tracker: RequestTracker,
    sender: UnboundedSender<AccessLogEntry>,
    client_ip: String,
    method: String,
    path: String,
    host: Option<String>,
    backend: Option<String>,
    router: Option<String>,
    entrypoint: String,
    user_agent: Option<String>,
    inference: Option<InferenceAccessLogContext>,
}

impl RequestAccessLog {
    /// Create access-log state from request metadata known before routing.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tracker: RequestTracker,
        sender: UnboundedSender<AccessLogEntry>,
        client_ip: String,
        method: String,
        path: String,
        host: Option<String>,
        entrypoint: String,
        user_agent: Option<String>,
    ) -> Self {
        Self {
            tracker,
            sender,
            client_ip,
            method,
            path,
            host,
            backend: None,
            router: None,
            entrypoint,
            user_agent,
            inference: None,
        }
    }

    /// Record the matched router without changing ownership of the request log.
    pub fn set_router(&mut self, router: impl Into<String>) {
        self.router = Some(router.into());
    }

    /// Record the selected backend without changing ownership of the request log.
    pub fn set_backend(&mut self, backend: impl Into<String>) {
        self.backend = Some(backend.into());
    }

    /// Record the managed request identity before middleware or body parsing.
    pub(crate) fn set_inference_request(&mut self, identity: &InferenceRequestIdentity) {
        self.inference = Some(InferenceAccessLogContext::from_request(identity));
    }

    /// Record the concrete managed upstream attempt.
    pub(crate) fn set_inference_attempt(&mut self, identity: &InferenceAttemptIdentity) {
        self.inference = Some(InferenceAccessLogContext::from_attempt(identity));
    }

    /// Build and enqueue the terminal entry.
    pub fn finish(self, status: u16, response_bytes: u64) {
        let entry = self.tracker.build_entry(
            self.client_ip,
            self.method,
            self.path,
            self.host,
            status,
            response_bytes,
            self.backend,
            self.router,
            Some(self.entrypoint),
            self.user_agent,
            self.inference,
        );

        if self.sender.send(entry).is_err() {
            tracing::warn!(
                status,
                "Access log channel closed before the terminal entry was emitted"
            );
        }
    }
}

/// Drop-safe terminal access log for streaming responses and upgraded sessions.
///
/// The guard emits when explicitly finished or when its owning response stream
/// or relay future is dropped during disconnect or shutdown.
pub struct AccessLogGuard {
    request: Option<RequestAccessLog>,
    status: u16,
    response_bytes: u64,
}

impl AccessLogGuard {
    /// Create a terminal guard. A disabled request is represented by `None`.
    pub fn new(request: Option<RequestAccessLog>, status: u16) -> Self {
        Self {
            request,
            status,
            response_bytes: 0,
        }
    }

    /// Add successfully relayed response bytes.
    pub fn record_bytes(&mut self, bytes: u64) {
        if self.request.is_some() {
            self.response_bytes = self.response_bytes.saturating_add(bytes);
        }
    }

    /// Emit now. Dropping an unfinished guard has the same effect.
    pub fn finish(mut self) {
        self.emit();
    }

    fn emit(&mut self) {
        if let Some(request) = self.request.take() {
            request.finish(self.status, self.response_bytes);
        }
    }
}

impl Drop for AccessLogGuard {
    fn drop(&mut self) {
        self.emit();
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
            inference: None,
        }
    }

    #[test]
    fn test_entry_serialization() {
        let entry = sample_entry();
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"method\":\"GET\""));
        assert!(json.contains("\"status\":200"));
        assert!(!json.contains("\"inference\""));

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
            inference: None,
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
    fn test_access_log_count() {
        let log = AccessLog::new();
        assert_eq!(log.total_entries(), 0);
        log.count();
        assert_eq!(log.total_entries(), 1);
        log.count();
        assert_eq!(log.total_entries(), 2);
    }

    #[test]
    fn test_access_log_count_only() {
        // count() only increments, doesn't emit tracing
        let log = AccessLog::new();
        log.count();
        assert_eq!(log.total_entries(), 1);
    }

    #[test]
    fn test_request_tracker_elapsed_increases() {
        let log = AccessLog::new();
        let tracker = log.start_request();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let elapsed1 = tracker.elapsed_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let elapsed2 = tracker.elapsed_ms();
        assert!(elapsed2 > elapsed1);
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

    #[test]
    fn request_access_log_enriches_and_emits_one_entry() {
        let log = AccessLog::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let mut request = RequestAccessLog::new(
            log.start_request(),
            tx,
            "192.0.2.10".to_string(),
            "POST".to_string(),
            "/v1/chat/completions".to_string(),
            Some("api.example.com".to_string()),
            "websecure".to_string(),
            Some("test-client/1.0".to_string()),
        );
        request.set_router("inference");
        request.set_backend("http://127.0.0.1:8000");

        request.finish(201, 512);

        let entry = rx.try_recv().unwrap();
        assert_eq!(entry.client_ip, "192.0.2.10");
        assert_eq!(entry.method, "POST");
        assert_eq!(entry.path, "/v1/chat/completions");
        assert_eq!(entry.status, 201);
        assert_eq!(entry.response_bytes, 512);
        assert_eq!(entry.router.as_deref(), Some("inference"));
        assert_eq!(entry.backend.as_deref(), Some("http://127.0.0.1:8000"));
        assert_eq!(entry.entrypoint.as_deref(), Some("websecure"));
        assert_eq!(entry.user_agent.as_deref(), Some("test-client/1.0"));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn access_log_guard_emits_on_drop_with_streamed_byte_count() {
        let log = AccessLog::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let request = RequestAccessLog::new(
            log.start_request(),
            tx,
            "192.0.2.11".to_string(),
            "GET".to_string(),
            "/events".to_string(),
            None,
            "web".to_string(),
            None,
        );

        {
            let mut guard = AccessLogGuard::new(Some(request), 200);
            guard.record_bytes(7);
            guard.record_bytes(11);
        }

        let entry = rx.try_recv().unwrap();
        assert_eq!(entry.status, 200);
        assert_eq!(entry.response_bytes, 18);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn access_log_request_state_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<RequestAccessLog>();
        assert_send_sync::<AccessLogGuard>();
    }
}
