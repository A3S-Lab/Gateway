//! Load balancer — distributes requests across backend servers

use crate::config::{ManagedTargetConfig, ServerConfig, Strategy};
use crate::error::{GatewayError, Result};
use crate::managed_service::MANAGED_SERVICE_NAME_PREFIX;
use arc_swap::ArcSwap;
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_STREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const BACKEND_CONNECTION_COUNTER_SHARDS: usize = 16;

thread_local! {
    static RANDOM_COUNTER: Cell<u64> = Cell::new(random_counter_seed());
}

#[derive(Debug)]
#[repr(align(64))]
struct ConnectionCounterShard(AtomicUsize);

/// Complete per-service upstream timeout policy.
#[derive(Debug, Clone, Copy)]
pub struct ServiceTimeouts {
    request: Duration,
    stream_idle: Duration,
    stream_total: Duration,
}

impl ServiceTimeouts {
    fn new(request: Duration, stream_idle: Duration, stream_total: Duration) -> Self {
        Self {
            request,
            stream_idle,
            stream_total,
        }
    }

    /// Maximum time to wait for upstream response headers.
    pub fn request_timeout(self) -> Duration {
        self.request
    }

    /// Maximum silence between upstream streaming response chunks.
    pub fn stream_idle_timeout(self) -> Duration {
        self.stream_idle
    }

    /// Maximum lifetime of one upstream streaming operation.
    pub fn stream_total_timeout(self) -> Duration {
        self.stream_total
    }
}

/// A single backend server
#[derive(Debug)]
pub struct Backend {
    /// Server URL
    pub url: String,
    /// Parsed once so the HTTP hot path can replace only scheme and authority.
    http_base_uri: Option<http::Uri>,
    /// Opaque, credential-free identity used in bounded telemetry labels.
    metric_id: String,
    /// Managed-control-plane identity for the exact upstream generation.
    managed_target: Option<ManagedTargetConfig>,
    /// Weight for weighted balancing
    pub weight: u32,
    /// Whether the backend is healthy
    healthy: AtomicBool,
    /// Whether the embedded Managed Service lifecycle owns admission.
    admission_managed: bool,
    /// Exact-generation admission gate, independent from active health probes.
    admission_open: AtomicBool,
    /// Active operation counts split across cache lines for proxy workers.
    active_connections: [ConnectionCounterShard; BACKEND_CONNECTION_COUNTER_SHARDS],
    /// Wakes a lifecycle drain after the last admitted operation leaves.
    drain_notify: tokio::sync::Notify,
}

impl Backend {
    /// Create a new backend
    #[allow(dead_code)]
    pub fn new(url: String, weight: u32) -> Self {
        Self::new_scoped("backend", 0, url, weight)
    }

    fn new_scoped(scope: &str, index: usize, url: String, weight: u32) -> Self {
        Self::with_metric_id(url, weight, scoped_metric_id(scope, index))
    }

    fn new_managed(
        url: String,
        weight: u32,
        target: ManagedTargetConfig,
        admission_managed: bool,
    ) -> Self {
        let metric_id = managed_target_metric_id(&target);
        Self::with_metric_id_and_target(url, weight, metric_id, Some(target), admission_managed)
    }

    fn with_metric_id(url: String, weight: u32, metric_id: String) -> Self {
        Self::with_metric_id_and_target(url, weight, metric_id, None, false)
    }

    fn with_metric_id_and_target(
        url: String,
        weight: u32,
        metric_id: String,
        managed_target: Option<ManagedTargetConfig>,
        admission_managed: bool,
    ) -> Self {
        let http_base_uri = url.parse::<http::Uri>().ok();
        Self {
            url,
            http_base_uri,
            metric_id,
            managed_target,
            weight,
            healthy: AtomicBool::new(true),
            admission_managed,
            admission_open: AtomicBool::new(true),
            active_connections: std::array::from_fn(|_| {
                ConnectionCounterShard(AtomicUsize::new(0))
            }),
            drain_notify: tokio::sync::Notify::new(),
        }
    }

    /// Stable opaque identity for credential-safe telemetry labels.
    pub fn metric_id(&self) -> &str {
        if let Some(target) = self.managed_target() {
            debug_assert_eq!(self.metric_id, managed_target_metric_id(target));
        }
        &self.metric_id
    }

    /// Managed-control-plane identity of this exact upstream generation.
    pub(crate) fn managed_target(&self) -> Option<&ManagedTargetConfig> {
        self.managed_target.as_ref()
    }

    pub(crate) fn http_base_uri(&self) -> Option<&http::Uri> {
        self.http_base_uri.as_ref()
    }

    /// Check if this backend is healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
            && (!self.admission_managed || self.admission_open.load(Ordering::SeqCst))
    }

    /// Set the health status
    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Relaxed);
    }

    /// Increment active connections
    #[allow(dead_code)]
    pub fn inc_connections(&self) {
        self.inc_connections_on(0);
    }

    /// Decrement active connections
    #[allow(dead_code)]
    pub fn dec_connections(&self) {
        self.dec_connections_on(0);
    }

    /// Get active connection count
    pub fn connections(&self) -> usize {
        let ordering = self.connection_ordering();
        self.active_connections
            .iter()
            .map(|shard| shard.0.load(ordering))
            .sum()
    }

    /// Track one active backend operation until the returned guard is dropped.
    #[cfg(test)]
    pub(crate) fn track_connection(self: &Arc<Self>) -> BackendConnectionGuard {
        self.track_connection_on(0)
    }

    /// Track one operation on a stable worker/pool shard.
    #[cfg(test)]
    pub(crate) fn track_connection_on(self: &Arc<Self>, shard: usize) -> BackendConnectionGuard {
        let shard = shard % BACKEND_CONNECTION_COUNTER_SHARDS;
        self.inc_connections_on(shard);
        BackendConnectionGuard {
            backend: self.clone(),
            shard,
        }
    }

    /// Atomically admit one operation unless exact-generation retirement won.
    pub(crate) fn try_track_connection_on(
        self: &Arc<Self>,
        shard: usize,
    ) -> Option<BackendConnectionGuard> {
        if !self.admission_managed {
            let shard = shard % BACKEND_CONNECTION_COUNTER_SHARDS;
            self.inc_connections_on(shard);
            return Some(BackendConnectionGuard {
                backend: self.clone(),
                shard,
            });
        }
        if !self.admission_open.load(Ordering::SeqCst) {
            return None;
        }
        let shard = shard % BACKEND_CONNECTION_COUNTER_SHARDS;
        self.inc_connections_on(shard);
        if !self.admission_open.load(Ordering::SeqCst) {
            self.dec_connections_on(shard);
            if self.connections() == 0 {
                self.drain_notify.notify_waiters();
            }
            return None;
        }
        Some(BackendConnectionGuard {
            backend: self.clone(),
            shard,
        })
    }

    pub(crate) fn close_managed_admission(&self) {
        if self.admission_managed {
            self.admission_open.store(false, Ordering::SeqCst);
            if self.connections() == 0 {
                self.drain_notify.notify_waiters();
            }
        }
    }

    pub(crate) async fn wait_for_managed_drain(
        &self,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<()> {
        loop {
            if self.connections() == 0 {
                return Ok(());
            }
            let notified = self.drain_notify.notified();
            if self.connections() == 0 {
                return Ok(());
            }
            match deadline {
                Some(deadline) => {
                    tokio::time::timeout_at(deadline, notified)
                        .await
                        .map_err(|_| {
                            GatewayError::ServiceUnavailable(
                                "Managed Service drain deadline elapsed with admitted calls"
                                    .to_string(),
                            )
                        })?
                }
                None => notified.await,
            }
        }
    }

    fn inc_connections_on(&self, shard: usize) {
        self.active_connections[shard]
            .0
            .fetch_add(1, self.connection_ordering());
    }

    fn dec_connections_on(&self, shard: usize) {
        self.active_connections[shard]
            .0
            .fetch_sub(1, self.connection_ordering());
    }

    fn connection_ordering(&self) -> Ordering {
        if self.admission_managed {
            Ordering::SeqCst
        } else {
            Ordering::Relaxed
        }
    }
}

fn scoped_metric_id(scope: &str, index: usize) -> String {
    let mut identity = Sha256::new();
    identity.update(b"a3s-gateway-backend-slot-v1");
    identity.update([0]);
    identity.update(scope.as_bytes());
    identity.update([0]);
    identity.update(index.to_be_bytes());
    format!("b_{:x}", identity.finalize())
}

fn managed_target_metric_id(target: &ManagedTargetConfig) -> String {
    let mut identity = Sha256::new();
    identity.update(b"a3s-gateway-managed-target-v1");
    identity.update([0]);
    identity.update(target.target_id.as_bytes());
    identity.update([0]);
    identity.update(target.unit_id.as_bytes());
    identity.update([0]);
    identity.update(target.generation.to_be_bytes());
    format!("b_{:x}", identity.finalize())
}

fn dynamic_metric_prefix(service: &str) -> String {
    let mut identity = Sha256::new();
    identity.update(b"a3s-gateway-box-backend-v1");
    identity.update([0]);
    identity.update(service.as_bytes());
    format!("b_{:x}_s", identity.finalize())
}

/// Drop-safe backend connection accounting for cancelled proxy operations.
pub(crate) struct BackendConnectionGuard {
    backend: Arc<Backend>,
    shard: usize,
}

impl Drop for BackendConnectionGuard {
    fn drop(&mut self) {
        self.backend.dec_connections_on(self.shard);
        if self.backend.admission_managed && self.backend.connections() == 0 {
            self.backend.drain_notify.notify_waiters();
        }
    }
}

/// Load balancer — selects a backend for each request
pub struct LoadBalancer {
    /// Service name
    pub name: String,
    /// Balancing strategy
    strategy: Strategy,
    /// Backend servers
    configured_backends: Vec<Arc<Backend>>,
    /// Configured backends plus the latest executor-owned dynamic overlay.
    backends: ArcSwap<Vec<Arc<Backend>>>,
    /// Opaque telemetry namespace for Box-owned replica slots.
    dynamic_metric_prefix: String,
    /// Monotonic selection counter used by round-robin and weighted strategies.
    rr_counter: AtomicUsize,
    /// Sticky session cookie name
    sticky_cookie: Option<String>,
    /// Complete upstream timeout policy.
    timeouts: ServiceTimeouts,
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(
        name: String,
        strategy: Strategy,
        servers: &[ServerConfig],
        sticky_cookie: Option<String>,
    ) -> Self {
        Self::with_request_timeout(
            name,
            strategy,
            servers,
            sticky_cookie,
            Duration::from_secs(30),
        )
    }

    /// Create a new load balancer with a service-specific request timeout.
    pub fn with_request_timeout(
        name: String,
        strategy: Strategy,
        servers: &[ServerConfig],
        sticky_cookie: Option<String>,
        request_timeout: Duration,
    ) -> Self {
        Self::with_timeouts(
            name,
            strategy,
            servers,
            sticky_cookie,
            request_timeout,
            DEFAULT_STREAM_IDLE_TIMEOUT,
            DEFAULT_STREAM_TOTAL_TIMEOUT,
        )
    }

    /// Create a load balancer with service-specific request and stream bounds.
    pub fn with_timeouts(
        name: String,
        strategy: Strategy,
        servers: &[ServerConfig],
        sticky_cookie: Option<String>,
        request_timeout: Duration,
        stream_idle_timeout: Duration,
        stream_total_timeout: Duration,
    ) -> Self {
        let admission_managed = name.starts_with(MANAGED_SERVICE_NAME_PREFIX);
        let backends: Vec<Arc<Backend>> = servers
            .iter()
            .enumerate()
            .map(|(index, server)| {
                Arc::new(match &server.target {
                    Some(target) => Backend::new_managed(
                        server.url.clone(),
                        server.weight,
                        target.clone(),
                        admission_managed,
                    ),
                    None => Backend::new_scoped(&name, index, server.url.clone(), server.weight),
                })
            })
            .collect();

        Self {
            dynamic_metric_prefix: dynamic_metric_prefix(&name),
            name,
            strategy,
            configured_backends: backends.clone(),
            backends: ArcSwap::from_pointee(backends),
            rr_counter: AtomicUsize::new(0),
            sticky_cookie,
            timeouts: ServiceTimeouts::new(
                request_timeout,
                stream_idle_timeout,
                stream_total_timeout,
            ),
        }
    }

    /// Select the next healthy backend
    ///
    /// Avoids heap allocation and performs only the scans each strategy needs.
    /// For typical backend counts (1–20), this is faster than allocating and
    /// freeing a temporary collection on every request.
    pub fn next_backend(&self) -> Option<Arc<Backend>> {
        let backends = self.backends.load();
        // A single-backend service does not need a shared round-robin counter
        // or a second health scan. Avoiding that contended atomic matters when
        // many runtime workers proxy to the same upstream.
        if let [backend] = backends.as_slice() {
            return backend.is_healthy().then(|| Arc::clone(backend));
        }

        match self.strategy {
            Strategy::RoundRobin => {
                let healthy_count = backends.iter().filter(|b| b.is_healthy()).count();
                if healthy_count == 0 {
                    return None;
                }
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy_count;
                if healthy_count == backends.len() {
                    return Some(Arc::clone(&backends[idx]));
                }
                backends.iter().filter(|b| b.is_healthy()).nth(idx).cloned()
            }
            Strategy::Weighted => {
                let total_weight: u64 = backends
                    .iter()
                    .filter(|b| b.is_healthy())
                    .map(|b| u64::from(b.weight))
                    .sum();
                if total_weight == 0 {
                    return backends.iter().find(|b| b.is_healthy()).cloned();
                }
                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed) as u64;
                let target = counter % total_weight;
                let mut cumulative = 0u64;
                for backend in backends.iter().filter(|b| b.is_healthy()) {
                    cumulative += u64::from(backend.weight);
                    if target < cumulative {
                        return Some(backend.clone());
                    }
                }
                backends.iter().rfind(|b| b.is_healthy()).cloned()
            }
            Strategy::LeastConnections => backends
                .iter()
                .filter(|b| b.is_healthy())
                .min_by_key(|b| b.connections())
                .cloned(),
            Strategy::Random => {
                let healthy_count = backends.iter().filter(|b| b.is_healthy()).count();
                if healthy_count == 0 {
                    return None;
                }
                let idx = random_backend_index(healthy_count);
                if healthy_count == backends.len() {
                    return Some(Arc::clone(&backends[idx]));
                }
                backends.iter().filter(|b| b.is_healthy()).nth(idx).cloned()
            }
        }
    }

    /// Get all backends (for health checking)
    pub fn backends(&self) -> Arc<Vec<Arc<Backend>>> {
        self.backends.load_full()
    }

    /// Replace only executor-owned endpoints while preserving configured
    /// backends and live counters for unchanged dynamic URLs.
    pub(crate) fn replace_dynamic_backends(&self, endpoints: &[(u32, String)]) -> Result<()> {
        let current = self.backends.load();
        let mut next = self.configured_backends.clone();
        let mut endpoints = endpoints.iter().collect::<Vec<_>>();
        endpoints.sort_by_key(|(slot, _)| *slot);
        let mut slots = BTreeSet::new();
        let mut urls = BTreeSet::new();
        for (slot, url) in endpoints {
            if !slots.insert(*slot) {
                return Err(GatewayError::Scaling(format!(
                    "Box returned duplicate dynamic backend slot {slot} for service '{}'",
                    self.name
                )));
            }
            if !urls.insert(url.as_str()) {
                return Err(GatewayError::Scaling(format!(
                    "Box returned duplicate dynamic backend URL for service '{}'",
                    self.name
                )));
            }
            if self
                .configured_backends
                .iter()
                .any(|backend| backend.url == *url)
            {
                continue;
            }
            let metric_id = self.dynamic_metric_id(*slot);
            if let Some(existing) = current
                .iter()
                .find(|backend| backend.metric_id == metric_id && backend.url == *url)
            {
                next.push(Arc::clone(existing));
                continue;
            }
            let backend = Backend::with_metric_id(url.clone(), 1, metric_id);
            if backend.http_base_uri().is_none() {
                return Err(GatewayError::Scaling(format!(
                    "Box returned an invalid dynamic backend URL for service '{}'",
                    self.name
                )));
            }
            next.push(Arc::new(backend));
        }
        self.backends.store(Arc::new(next));
        Ok(())
    }

    /// Prefix shared by the bounded family of Box replica-slot metric IDs.
    pub(crate) fn dynamic_metric_prefix(&self) -> &str {
        &self.dynamic_metric_prefix
    }

    /// Stable metric identity for a Box replica slot, independent of its URL.
    pub(crate) fn dynamic_metric_id(&self, slot: u32) -> String {
        format!("{}{slot}", self.dynamic_metric_prefix)
    }

    /// Number of healthy backends
    pub fn healthy_count(&self) -> usize {
        self.backends
            .load()
            .iter()
            .filter(|b| b.is_healthy())
            .count()
    }

    /// Total number of backends
    #[allow(dead_code)]
    pub fn total_count(&self) -> usize {
        self.backends.load().len()
    }

    /// Get sticky cookie name
    #[allow(dead_code)]
    pub fn sticky_cookie(&self) -> Option<&str> {
        self.sticky_cookie.as_deref()
    }

    /// Maximum time to wait for upstream response headers.
    #[allow(dead_code)]
    pub fn request_timeout(&self) -> Duration {
        self.timeouts.request_timeout()
    }

    /// Maximum silence between upstream streaming response chunks.
    #[allow(dead_code)]
    pub fn stream_idle_timeout(&self) -> Duration {
        self.timeouts.stream_idle_timeout()
    }

    /// Maximum lifetime of one upstream streaming operation.
    #[allow(dead_code)]
    pub fn stream_total_timeout(&self) -> Duration {
        self.timeouts.stream_total_timeout()
    }

    /// Complete upstream timeout policy.
    pub fn timeouts(&self) -> ServiceTimeouts {
        self.timeouts
    }

    /// Get the load balancing strategy
    #[allow(dead_code)]
    pub fn strategy(&self) -> &Strategy {
        &self.strategy
    }
}

fn mixed_counter_index(counter: u64, upper_bound: usize) -> usize {
    debug_assert!(upper_bound > 0);
    let mut hash = counter.wrapping_add(0x9e37_79b9_7f4a_7c15);
    hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^= hash >> 31;
    (hash as usize) % upper_bound
}

fn random_backend_index(upper_bound: usize) -> usize {
    RANDOM_COUNTER.with(|counter| {
        let current = counter.get();
        counter.set(current.wrapping_add(1));
        mixed_counter_index(current, upper_bound)
    })
}

fn random_counter_seed() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64)
        ^ u64::from(std::process::id())
}

#[cfg(test)]
mod tests;
