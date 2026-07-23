//! Gateway metrics — lightweight counters and gauges
//!
//! Provides in-process metrics tracking without external dependencies.
//! Metrics can be exported as JSON or rendered as Prometheus text format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

mod prometheus;
mod telemetry;
use telemetry::TelemetryRegistry;
pub(crate) use telemetry::{PreparedTelemetry, ServiceRequestGuard};

#[cfg(test)]
mod telemetry_tests;
#[cfg(test)]
mod tests;

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
    /// Per-service request counts
    pub service_requests: HashMap<String, u64>,
    /// Per-middleware invocation counts
    pub middleware_invocations: HashMap<String, u64>,
    /// Per-router latency in microseconds (cumulative, divide by count for avg)
    pub router_latency_us: HashMap<String, u64>,
    /// Per-router error counts (4xx + 5xx)
    pub router_errors: HashMap<String, u64>,
    /// Per-service error counts (4xx + 5xx)
    pub service_errors: HashMap<String, u64>,
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
    service_requests: Arc<RwLock<HashMap<String, u64>>>,
    middleware_invocations: Arc<RwLock<HashMap<String, u64>>>,
    router_latency_us: Arc<RwLock<HashMap<String, u64>>>,
    router_errors: Arc<RwLock<HashMap<String, u64>>>,
    service_errors: Arc<RwLock<HashMap<String, u64>>>,
    telemetry: TelemetryRegistry,
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
            service_requests: Arc::new(RwLock::new(HashMap::new())),
            middleware_invocations: Arc::new(RwLock::new(HashMap::new())),
            router_latency_us: Arc::new(RwLock::new(HashMap::new())),
            router_errors: Arc::new(RwLock::new(HashMap::new())),
            service_errors: Arc::new(RwLock::new(HashMap::new())),
            telemetry: TelemetryRegistry::new(),
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
        if !self.telemetry.allows_router(router) {
            return;
        }
        increment_map(&self.router_requests, router, 1);
    }

    /// Record a request for a specific backend
    pub fn record_backend_request(&self, backend: &str) {
        let backend = telemetry::opaque_backend_id(backend);
        if !self.telemetry.allows_backend(&backend) {
            return;
        }
        increment_map(&self.backend_requests, &backend, 1);
    }

    /// Record a request against an already-derived backend telemetry identity.
    pub(crate) fn record_backend_request_id(&self, backend_id: &str) {
        if !self.telemetry.allows_backend(backend_id) {
            return;
        }
        increment_map(&self.backend_requests, backend_id, 1);
    }

    /// Record a request for a specific service
    pub fn record_service_request(&self, service: &str) {
        if !self.telemetry.allows_service(service) {
            return;
        }
        increment_map(&self.service_requests, service, 1);
    }

    /// Record a middleware invocation
    pub fn record_middleware_invocation(&self, middleware: &str) {
        if !self.telemetry.allows_middleware(middleware) {
            return;
        }
        increment_map(&self.middleware_invocations, middleware, 1);
    }

    /// Record request latency for a router (in microseconds)
    pub fn record_router_latency(&self, router: &str, latency_us: u64) {
        if !self.telemetry.allows_router(router) {
            return;
        }
        increment_map(&self.router_latency_us, router, latency_us);
    }

    /// Record an error (4xx/5xx) for a router
    pub fn record_router_error(&self, router: &str) {
        if !self.telemetry.allows_router(router) {
            return;
        }
        increment_map(&self.router_errors, router, 1);
    }

    /// Record an error (4xx/5xx) for a service
    pub fn record_service_error(&self, service: &str) {
        if !self.telemetry.allows_service(service) {
            return;
        }
        increment_map(&self.service_errors, service, 1);
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

    /// Track one accepted downstream connection until its task is dropped.
    pub(crate) fn track_connection(self: &Arc<Self>) -> ActiveConnectionGuard {
        self.inc_connections();
        ActiveConnectionGuard {
            metrics: self.clone(),
        }
    }

    /// Prepare a topology-bounded telemetry view without changing the active view.
    pub(crate) fn prepare_telemetry(
        &self,
        config: &crate::config::GatewayConfig,
        service_registry: &crate::service::ServiceRegistry,
        scaling: Option<&crate::entrypoint::ScalingState>,
        enabled: bool,
    ) -> PreparedTelemetry {
        self.telemetry
            .prepare(config, service_registry, scaling, enabled)
    }

    /// Atomically replace the telemetry topology after the matching runtime commits.
    pub(crate) fn activate_telemetry(&self, prepared: PreparedTelemetry) -> PreparedTelemetry {
        let previous = self.telemetry.activate(prepared);
        let labels = self.telemetry.label_budget();
        if labels.enforced {
            retain_map(&self.router_requests, |label| {
                labels.routers.contains(label)
            });
            retain_map(&self.backend_requests, |label| {
                labels.backends.contains(label)
            });
            retain_map(&self.service_requests, |label| {
                labels.services.contains(label)
            });
            retain_map(&self.middleware_invocations, |label| {
                labels.middlewares.contains(label)
            });
            retain_map(&self.router_latency_us, |label| {
                labels.routers.contains(label)
            });
            retain_map(&self.router_errors, |label| labels.routers.contains(label));
            retain_map(&self.service_errors, |label| {
                labels.services.contains(label)
            });
        }
        previous
    }

    /// Track one service request until its protocol operation is dropped.
    pub(crate) fn track_service_request(
        &self,
        service: &str,
        started_at: Instant,
    ) -> Option<ServiceRequestGuard> {
        self.telemetry.track_request(service, started_at)
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
            router_requests: clone_map(&self.router_requests),
            backend_requests: clone_map(&self.backend_requests),
            service_requests: clone_map(&self.service_requests),
            middleware_invocations: clone_map(&self.middleware_invocations),
            router_latency_us: clone_map(&self.router_latency_us),
            router_errors: clone_map(&self.router_errors),
            service_errors: clone_map(&self.service_errors),
        }
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
        clear_map(&self.router_requests);
        clear_map(&self.backend_requests);
        clear_map(&self.service_requests);
        clear_map(&self.middleware_invocations);
        clear_map(&self.router_latency_us);
        clear_map(&self.router_errors);
        clear_map(&self.service_errors);
        self.telemetry.reset_observations();
    }
}

fn increment_map(map: &RwLock<HashMap<String, u64>>, label: &str, increment: u64) {
    let mut map = map.write().unwrap_or_else(|poisoned| poisoned.into_inner());
    let value = map.entry(label.to_string()).or_insert(0);
    *value = value.saturating_add(increment);
}

fn clone_map(map: &RwLock<HashMap<String, u64>>) -> HashMap<String, u64> {
    map.read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn clear_map(map: &RwLock<HashMap<String, u64>>) {
    map.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

fn retain_map(map: &RwLock<HashMap<String, u64>>, mut retain: impl FnMut(&String) -> bool) {
    map.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|label, _| retain(label));
}

/// Drop-safe downstream connection accounting.
pub(crate) struct ActiveConnectionGuard {
    metrics: Arc<GatewayMetrics>,
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.metrics.dec_connections();
    }
}

impl Default for GatewayMetrics {
    fn default() -> Self {
        Self::new()
    }
}
