//! Gateway metrics — lightweight counters and gauges
//!
//! Provides in-process metrics tracking without external dependencies.
//! Metrics can be exported as JSON or rendered as Prometheus text format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Metrics snapshot — a point-in-time view of all metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    /// Total requests received
    pub total_requests: u64,
    /// Total responses by status code class (2xx, 3xx, 4xx, 5xx)
    pub status_classes: HashMap<String, u64>,
    /// Total bytes sent to clients
    pub total_response_bytes: u64,
    /// Currently active connections
    pub active_connections: i64,
    /// Per-router request counts
    pub router_requests: HashMap<String, u64>,
    /// Per-backend request counts
    pub backend_requests: HashMap<String, u64>,
}

/// Gateway metrics collector
pub struct GatewayMetrics {
    total_requests: AtomicU64,
    status_2xx: AtomicU64,
    status_3xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
    total_response_bytes: AtomicU64,
    active_connections: AtomicI64,
    router_requests: Arc<RwLock<HashMap<String, u64>>>,
    backend_requests: Arc<RwLock<HashMap<String, u64>>>,
}

impl GatewayMetrics {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            status_2xx: AtomicU64::new(0),
            status_3xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
            total_response_bytes: AtomicU64::new(0),
            active_connections: AtomicI64::new(0),
            router_requests: Arc::new(RwLock::new(HashMap::new())),
            backend_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Record a completed request
    pub fn record_request(&self, status: u16, response_bytes: u64) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.total_response_bytes
            .fetch_add(response_bytes, Ordering::Relaxed);

        match status / 100 {
            2 => {
                self.status_2xx.fetch_add(1, Ordering::Relaxed);
            }
            3 => {
                self.status_3xx.fetch_add(1, Ordering::Relaxed);
            }
            4 => {
                self.status_4xx.fetch_add(1, Ordering::Relaxed);
            }
            5 => {
                self.status_5xx.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Record a request for a specific router
    pub fn record_router_request(&self, router: &str) {
        let mut map = self.router_requests.write().unwrap();
        *map.entry(router.to_string()).or_insert(0) += 1;
    }

    /// Record a request for a specific backend
    pub fn record_backend_request(&self, backend: &str) {
        let mut map = self.backend_requests.write().unwrap();
        *map.entry(backend.to_string()).or_insert(0) += 1;
    }

    /// Increment active connections
    pub fn inc_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections
    pub fn dec_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current active connections
    pub fn active_connections(&self) -> i64 {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// Get total requests
    pub fn total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    /// Take a snapshot of all metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        let mut status_classes = HashMap::new();
        status_classes.insert("2xx".to_string(), self.status_2xx.load(Ordering::Relaxed));
        status_classes.insert("3xx".to_string(), self.status_3xx.load(Ordering::Relaxed));
        status_classes.insert("4xx".to_string(), self.status_4xx.load(Ordering::Relaxed));
        status_classes.insert("5xx".to_string(), self.status_5xx.load(Ordering::Relaxed));

        MetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            status_classes,
            total_response_bytes: self.total_response_bytes.load(Ordering::Relaxed),
            active_connections: self.active_connections.load(Ordering::Relaxed),
            router_requests: self.router_requests.read().unwrap().clone(),
            backend_requests: self.backend_requests.read().unwrap().clone(),
        }
    }

    /// Render metrics in Prometheus text exposition format
    pub fn render_prometheus(&self) -> String {
        let snap = self.snapshot();
        let mut output = String::new();

        output.push_str("# HELP gateway_requests_total Total number of requests\n");
        output.push_str("# TYPE gateway_requests_total counter\n");
        output.push_str(&format!("gateway_requests_total {}\n", snap.total_requests));

        output.push_str("# HELP gateway_responses_total Total responses by status class\n");
        output.push_str("# TYPE gateway_responses_total counter\n");
        for class in ["2xx", "3xx", "4xx", "5xx"] {
            let count = snap.status_classes.get(class).unwrap_or(&0);
            output.push_str(&format!(
                "gateway_responses_total{{status_class=\"{}\"}} {}\n",
                class, count
            ));
        }

        output.push_str("# HELP gateway_response_bytes_total Total response bytes\n");
        output.push_str("# TYPE gateway_response_bytes_total counter\n");
        output.push_str(&format!(
            "gateway_response_bytes_total {}\n",
            snap.total_response_bytes
        ));

        output.push_str("# HELP gateway_active_connections Current active connections\n");
        output.push_str("# TYPE gateway_active_connections gauge\n");
        output.push_str(&format!(
            "gateway_active_connections {}\n",
            snap.active_connections
        ));

        if !snap.router_requests.is_empty() {
            output.push_str("# HELP gateway_router_requests_total Requests per router\n");
            output.push_str("# TYPE gateway_router_requests_total counter\n");
            for (router, count) in &snap.router_requests {
                output.push_str(&format!(
                    "gateway_router_requests_total{{router=\"{}\"}} {}\n",
                    router, count
                ));
            }
        }

        if !snap.backend_requests.is_empty() {
            output.push_str("# HELP gateway_backend_requests_total Requests per backend\n");
            output.push_str("# TYPE gateway_backend_requests_total counter\n");
            for (backend, count) in &snap.backend_requests {
                output.push_str(&format!(
                    "gateway_backend_requests_total{{backend=\"{}\"}} {}\n",
                    backend, count
                ));
            }
        }

        output
    }

    /// Reset all metrics
    pub fn reset(&self) {
        self.total_requests.store(0, Ordering::Relaxed);
        self.status_2xx.store(0, Ordering::Relaxed);
        self.status_3xx.store(0, Ordering::Relaxed);
        self.status_4xx.store(0, Ordering::Relaxed);
        self.status_5xx.store(0, Ordering::Relaxed);
        self.total_response_bytes.store(0, Ordering::Relaxed);
        self.active_connections.store(0, Ordering::Relaxed);
        self.router_requests.write().unwrap().clear();
        self.backend_requests.write().unwrap().clear();
    }
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Basic counter tests ---

    #[test]
    fn test_initial_state() {
        let m = GatewayMetrics::new();
        assert_eq!(m.total_requests(), 0);
        assert_eq!(m.active_connections(), 0);
    }

    #[test]
    fn test_record_request_increments_total() {
        let m = GatewayMetrics::new();
        m.record_request(200, 100);
        m.record_request(404, 50);
        assert_eq!(m.total_requests(), 2);
    }

    #[test]
    fn test_record_request_status_classes() {
        let m = GatewayMetrics::new();
        m.record_request(200, 0);
        m.record_request(201, 0);
        m.record_request(301, 0);
        m.record_request(400, 0);
        m.record_request(404, 0);
        m.record_request(500, 0);

        let snap = m.snapshot();
        assert_eq!(snap.status_classes["2xx"], 2);
        assert_eq!(snap.status_classes["3xx"], 1);
        assert_eq!(snap.status_classes["4xx"], 2);
        assert_eq!(snap.status_classes["5xx"], 1);
    }

    #[test]
    fn test_record_response_bytes() {
        let m = GatewayMetrics::new();
        m.record_request(200, 1000);
        m.record_request(200, 500);
        let snap = m.snapshot();
        assert_eq!(snap.total_response_bytes, 1500);
    }

    // --- Connection tracking ---

    #[test]
    fn test_connections() {
        let m = GatewayMetrics::new();
        m.inc_connections();
        m.inc_connections();
        assert_eq!(m.active_connections(), 2);
        m.dec_connections();
        assert_eq!(m.active_connections(), 1);
    }

    // --- Router/backend tracking ---

    #[test]
    fn test_router_requests() {
        let m = GatewayMetrics::new();
        m.record_router_request("api");
        m.record_router_request("api");
        m.record_router_request("web");
        let snap = m.snapshot();
        assert_eq!(snap.router_requests["api"], 2);
        assert_eq!(snap.router_requests["web"], 1);
    }

    #[test]
    fn test_backend_requests() {
        let m = GatewayMetrics::new();
        m.record_backend_request("http://b1:8080");
        m.record_backend_request("http://b2:8080");
        m.record_backend_request("http://b1:8080");
        let snap = m.snapshot();
        assert_eq!(snap.backend_requests["http://b1:8080"], 2);
        assert_eq!(snap.backend_requests["http://b2:8080"], 1);
    }

    // --- Snapshot tests ---

    #[test]
    fn test_snapshot_serialization() {
        let m = GatewayMetrics::new();
        m.record_request(200, 100);
        m.inc_connections();
        let snap = m.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let parsed: MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_requests, 1);
        assert_eq!(parsed.active_connections, 1);
    }

    // --- Prometheus format ---

    #[test]
    fn test_prometheus_format() {
        let m = GatewayMetrics::new();
        m.record_request(200, 1024);
        m.record_request(500, 0);
        m.inc_connections();

        let output = m.render_prometheus();
        assert!(output.contains("gateway_requests_total 2"));
        assert!(output.contains("gateway_responses_total{status_class=\"2xx\"} 1"));
        assert!(output.contains("gateway_responses_total{status_class=\"5xx\"} 1"));
        assert!(output.contains("gateway_response_bytes_total 1024"));
        assert!(output.contains("gateway_active_connections 1"));
    }

    #[test]
    fn test_prometheus_format_with_routers() {
        let m = GatewayMetrics::new();
        m.record_router_request("api-router");
        let output = m.render_prometheus();
        assert!(output.contains("gateway_router_requests_total{router=\"api-router\"} 1"));
    }

    #[test]
    fn test_prometheus_format_with_backends() {
        let m = GatewayMetrics::new();
        m.record_backend_request("http://localhost:8080");
        let output = m.render_prometheus();
        assert!(
            output.contains("gateway_backend_requests_total{backend=\"http://localhost:8080\"} 1")
        );
    }

    #[test]
    fn test_prometheus_has_help_and_type() {
        let m = GatewayMetrics::new();
        let output = m.render_prometheus();
        assert!(output.contains("# HELP gateway_requests_total"));
        assert!(output.contains("# TYPE gateway_requests_total counter"));
        assert!(output.contains("# TYPE gateway_active_connections gauge"));
    }

    // --- Reset ---

    #[test]
    fn test_reset() {
        let m = GatewayMetrics::new();
        m.record_request(200, 100);
        m.record_router_request("api");
        m.inc_connections();
        m.reset();
        assert_eq!(m.total_requests(), 0);
        assert_eq!(m.active_connections(), 0);
        let snap = m.snapshot();
        assert!(snap.router_requests.is_empty());
    }

    // --- Default ---

    #[test]
    fn test_default() {
        let m = GatewayMetrics::default();
        assert_eq!(m.total_requests(), 0);
    }

    // --- Edge cases ---

    #[test]
    fn test_unknown_status_class() {
        let m = GatewayMetrics::new();
        m.record_request(100, 0); // 1xx not tracked
        m.record_request(600, 0); // Invalid
        assert_eq!(m.total_requests(), 2);
        let snap = m.snapshot();
        assert_eq!(snap.status_classes["2xx"], 0);
    }
}
