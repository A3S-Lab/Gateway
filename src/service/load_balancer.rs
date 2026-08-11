//! Load balancer — distributes requests across backend servers

use crate::config::{ManagedTargetConfig, ServerConfig, Strategy};
use crate::error::{GatewayError, Result};
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
    /// Cloud-owned identity for the exact configured upstream generation.
    managed_target: Option<ManagedTargetConfig>,
    /// Weight for weighted balancing
    pub weight: u32,
    /// Whether the backend is healthy
    healthy: AtomicBool,
    /// Active operation counts split across cache lines for proxy workers.
    active_connections: [ConnectionCounterShard; BACKEND_CONNECTION_COUNTER_SHARDS],
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

    fn new_managed(url: String, weight: u32, target: ManagedTargetConfig) -> Self {
        let metric_id = managed_target_metric_id(&target);
        Self::with_metric_id_and_target(url, weight, metric_id, Some(target))
    }

    fn with_metric_id(url: String, weight: u32, metric_id: String) -> Self {
        Self::with_metric_id_and_target(url, weight, metric_id, None)
    }

    fn with_metric_id_and_target(
        url: String,
        weight: u32,
        metric_id: String,
        managed_target: Option<ManagedTargetConfig>,
    ) -> Self {
        let http_base_uri = url.parse::<http::Uri>().ok();
        Self {
            url,
            http_base_uri,
            metric_id,
            managed_target,
            weight,
            healthy: AtomicBool::new(true),
            active_connections: std::array::from_fn(|_| {
                ConnectionCounterShard(AtomicUsize::new(0))
            }),
        }
    }

    /// Stable opaque identity for credential-safe telemetry labels.
    pub fn metric_id(&self) -> &str {
        if let Some(target) = self.managed_target() {
            debug_assert_eq!(self.metric_id, managed_target_metric_id(target));
        }
        &self.metric_id
    }

    /// Cloud-owned identity of this exact configured upstream generation.
    pub(crate) fn managed_target(&self) -> Option<&ManagedTargetConfig> {
        self.managed_target.as_ref()
    }

    pub(crate) fn http_base_uri(&self) -> Option<&http::Uri> {
        self.http_base_uri.as_ref()
    }

    /// Check if this backend is healthy
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
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
        self.active_connections
            .iter()
            .map(|shard| shard.0.load(Ordering::Relaxed))
            .sum()
    }

    /// Track one active backend operation until the returned guard is dropped.
    pub(crate) fn track_connection(self: &Arc<Self>) -> BackendConnectionGuard {
        self.track_connection_on(0)
    }

    /// Track one operation on a stable worker/pool shard.
    pub(crate) fn track_connection_on(self: &Arc<Self>, shard: usize) -> BackendConnectionGuard {
        let shard = shard % BACKEND_CONNECTION_COUNTER_SHARDS;
        self.inc_connections_on(shard);
        BackendConnectionGuard {
            backend: self.clone(),
            shard,
        }
    }

    fn inc_connections_on(&self, shard: usize) {
        self.active_connections[shard]
            .0
            .fetch_add(1, Ordering::Relaxed);
    }

    fn dec_connections_on(&self, shard: usize) {
        self.active_connections[shard]
            .0
            .fetch_sub(1, Ordering::Relaxed);
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
        let backends: Vec<Arc<Backend>> = servers
            .iter()
            .enumerate()
            .map(|(index, server)| {
                Arc::new(match &server.target {
                    Some(target) => {
                        Backend::new_managed(server.url.clone(), server.weight, target.clone())
                    }
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
mod tests {
    use super::*;
    use crate::config::ManagedTargetConfig;

    fn make_servers(urls: Vec<&str>) -> Vec<ServerConfig> {
        urls.into_iter()
            .map(|url| ServerConfig {
                url: url.to_string(),
                weight: 1,
                target: None,
            })
            .collect()
    }

    fn make_weighted_servers() -> Vec<ServerConfig> {
        vec![
            ServerConfig {
                url: "http://a:8001".to_string(),
                weight: 3,
                target: None,
            },
            ServerConfig {
                url: "http://b:8002".to_string(),
                weight: 1,
                target: None,
            },
        ]
    }

    fn managed_server(
        url: &str,
        target_id: uuid::Uuid,
        unit_id: &str,
        generation: u64,
    ) -> ServerConfig {
        ServerConfig {
            url: url.to_string(),
            weight: 1,
            target: Some(ManagedTargetConfig {
                target_id,
                unit_id: unit_id.to_string(),
                generation,
            }),
        }
    }

    #[test]
    fn managed_target_metric_identity_is_generation_bound_and_order_independent() {
        let first_target = uuid::Uuid::new_v4();
        let second_target = uuid::Uuid::new_v4();
        let first = managed_server("http://127.0.0.1:8001", first_target, "workload:first", 3);
        let second = managed_server("http://127.0.0.1:8002", second_target, "workload:second", 5);
        let ordered = LoadBalancer::new(
            "route-a".into(),
            Strategy::RoundRobin,
            &[first.clone(), second.clone()],
            None,
        );
        let reversed = LoadBalancer::new(
            "route-b".into(),
            Strategy::RoundRobin,
            &[second.clone(), first.clone()],
            None,
        );

        let ordered_first = ordered
            .backends()
            .iter()
            .find(|backend| backend.managed_target() == first.target.as_ref())
            .cloned()
            .unwrap();
        let reversed_first = reversed
            .backends()
            .iter()
            .find(|backend| backend.managed_target() == first.target.as_ref())
            .cloned()
            .unwrap();
        assert_eq!(ordered_first.metric_id(), reversed_first.metric_id());

        let next_generation = LoadBalancer::new(
            "route-a".into(),
            Strategy::RoundRobin,
            &[managed_server(
                "http://127.0.0.1:8001",
                first_target,
                "workload:first",
                4,
            )],
            None,
        );
        assert_ne!(
            ordered_first.metric_id(),
            next_generation.backends()[0].metric_id()
        );
        assert!(!ordered_first.metric_id().contains("workload"));
        assert!(!ordered_first
            .metric_id()
            .contains(&first_target.to_string()));
    }

    #[test]
    fn test_round_robin_single() {
        let servers = make_servers(vec!["http://127.0.0.1:8001"]);
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

        let b = lb.next_backend().unwrap();
        assert_eq!(b.url, "http://127.0.0.1:8001");
        assert_eq!(lb.rr_counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_round_robin_cycles() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

        let urls: Vec<String> = (0..6)
            .map(|_| lb.next_backend().unwrap().url.clone())
            .collect();
        assert_eq!(urls[0], "http://a:8001");
        assert_eq!(urls[1], "http://b:8002");
        assert_eq!(urls[2], "http://c:8003");
        assert_eq!(urls[3], "http://a:8001");
        assert_eq!(urls[4], "http://b:8002");
        assert_eq!(urls[5], "http://c:8003");
    }

    #[test]
    fn test_round_robin_skips_unhealthy() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

        lb.backends()[0].set_healthy(false);

        let b = lb.next_backend().unwrap();
        assert_eq!(b.url, "http://b:8002");
    }

    #[test]
    fn test_all_unhealthy_returns_none() {
        let servers = make_servers(vec!["http://a:8001"]);
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

        lb.backends()[0].set_healthy(false);
        assert!(lb.next_backend().is_none());
    }

    #[test]
    fn test_weighted_distribution() {
        let servers = make_weighted_servers();
        let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);

        let mut a_count = 0;
        let mut b_count = 0;
        for _ in 0..100 {
            let b = lb.next_backend().unwrap();
            if b.url.contains("a:") {
                a_count += 1;
            } else {
                b_count += 1;
            }
        }
        // Weight ratio is 3:1, so a should get ~75%
        assert!(a_count > b_count, "a={} should be > b={}", a_count, b_count);
    }

    #[test]
    fn test_least_connections() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
        let lb = LoadBalancer::new("test".into(), Strategy::LeastConnections, &servers, None);

        // Add connections to first backend
        lb.backends()[0].inc_connections();
        lb.backends()[0].inc_connections();

        let b = lb.next_backend().unwrap();
        assert_eq!(b.url, "http://b:8002"); // fewer connections
    }

    #[test]
    fn test_least_connections_all_unhealthy() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
        let lb = LoadBalancer::new("test".into(), Strategy::LeastConnections, &servers, None);
        for backend in lb.backends().iter() {
            backend.set_healthy(false);
        }

        assert!(lb.next_backend().is_none());
    }

    #[test]
    fn test_random_returns_something() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
        let lb = LoadBalancer::new("test".into(), Strategy::Random, &servers, None);

        let b = lb.next_backend();
        assert!(b.is_some());
        assert_eq!(lb.rr_counter.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_mixed_counter_index_visits_every_slot() {
        for upper_bound in [2, 3, 4, 7] {
            let mut seen = vec![false; upper_bound];
            for counter in 0..(upper_bound * 16) {
                seen[mixed_counter_index(counter as u64, upper_bound)] = true;
            }
            assert!(seen.into_iter().all(|visited| visited));
        }
    }

    #[test]
    fn test_backend_health() {
        let b = Backend::new("http://test:8001".to_string(), 1);
        assert!(b.is_healthy());
        b.set_healthy(false);
        assert!(!b.is_healthy());
        b.set_healthy(true);
        assert!(b.is_healthy());
    }

    #[test]
    fn test_backend_connections() {
        let b = Backend::new("http://test:8001".to_string(), 1);
        assert_eq!(b.connections(), 0);
        b.inc_connections();
        b.inc_connections();
        assert_eq!(b.connections(), 2);
        b.dec_connections();
        assert_eq!(b.connections(), 1);
    }

    #[test]
    fn test_backend_connection_guards_sum_shards() {
        let backend = Arc::new(Backend::new("http://test:8001".to_string(), 1));
        let first = backend.track_connection_on(1);
        let second = backend.track_connection_on(9);

        assert_eq!(backend.connections(), 2);
        drop(first);
        assert_eq!(backend.connections(), 1);
        drop(second);
        assert_eq!(backend.connections(), 0);
    }

    #[test]
    fn test_healthy_count() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

        assert_eq!(lb.healthy_count(), 3);
        assert_eq!(lb.total_count(), 3);

        lb.backends()[1].set_healthy(false);
        assert_eq!(lb.healthy_count(), 2);
        assert_eq!(lb.total_count(), 3);
    }

    #[test]
    fn test_sticky_cookie() {
        let servers = make_servers(vec!["http://a:8001"]);
        let lb = LoadBalancer::new(
            "test".into(),
            Strategy::RoundRobin,
            &servers,
            Some("session_id".to_string()),
        );
        assert_eq!(lb.sticky_cookie(), Some("session_id"));

        let lb2 = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);
        assert_eq!(lb2.sticky_cookie(), None);
    }

    #[test]
    fn test_empty_backends() {
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &[], None);
        assert!(lb.next_backend().is_none());
        assert_eq!(lb.healthy_count(), 0);
        assert_eq!(lb.total_count(), 0);
    }

    #[test]
    fn test_weighted_zero_total_weight() {
        // All backends with weight 0 should fall back to find()
        let servers = vec![
            ServerConfig {
                url: "http://a:8001".to_string(),
                weight: 0,
                target: None,
            },
            ServerConfig {
                url: "http://b:8002".to_string(),
                weight: 0,
                target: None,
            },
        ];
        let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);
        // Should return a healthy backend (first one found)
        let b = lb.next_backend();
        assert!(b.is_some());
        assert!(b.unwrap().url.starts_with("http://"));
    }

    #[test]
    fn test_weighted_total_weight_does_not_overflow() {
        let servers = vec![
            ServerConfig {
                url: "http://a:8001".to_string(),
                weight: u32::MAX,
                target: None,
            },
            ServerConfig {
                url: "http://b:8002".to_string(),
                weight: u32::MAX,
                target: None,
            },
        ];
        let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);

        assert!(lb.next_backend().is_some());
    }

    #[test]
    fn test_weighted_all_unhealthy() {
        let servers = vec![
            ServerConfig {
                url: "http://a:8001".to_string(),
                weight: 3,
                target: None,
            },
            ServerConfig {
                url: "http://b:8002".to_string(),
                weight: 1,
                target: None,
            },
        ];
        let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);
        lb.backends()[0].set_healthy(false);
        lb.backends()[1].set_healthy(false);
        assert!(lb.next_backend().is_none());
    }

    #[test]
    fn dynamic_box_backends_replace_atomically_and_preserve_unchanged_state() {
        let lb = LoadBalancer::new(
            "api".to_string(),
            Strategy::RoundRobin,
            &make_servers(vec!["http://static:8000"]),
            None,
        );
        lb.replace_dynamic_backends(&[
            (0, "http://127.0.0.1:18080".to_string()),
            (1, "http://127.0.0.1:18081".to_string()),
        ])
        .unwrap();
        assert_eq!(lb.backends().len(), 3);

        let retained = lb.backends()[1].clone();
        let retained_metric_id = retained.metric_id().to_string();
        retained.set_healthy(false);
        lb.replace_dynamic_backends(&[(0, "http://127.0.0.1:18080".to_string())])
            .unwrap();
        let snapshot = lb.backends();
        assert_eq!(snapshot.len(), 2);
        assert!(Arc::ptr_eq(&snapshot[1], &retained));
        assert!(!snapshot[1].is_healthy());
        assert_eq!(snapshot[1].metric_id(), retained_metric_id);

        lb.replace_dynamic_backends(&[(0, "http://127.0.0.1:28080".to_string())])
            .unwrap();
        let replaced = lb.backends();
        assert!(!Arc::ptr_eq(&replaced[1], &retained));
        assert_eq!(replaced[1].metric_id(), retained_metric_id);

        lb.replace_dynamic_backends(&[]).unwrap();
        assert_eq!(lb.backends().len(), 1);
        assert_eq!(lb.backends()[0].url, "http://static:8000");
    }

    #[test]
    fn dynamic_box_backends_reject_duplicate_slots_and_urls() {
        let lb = LoadBalancer::new("api".to_string(), Strategy::RoundRobin, &[], None);
        assert!(lb
            .replace_dynamic_backends(&[
                (0, "http://127.0.0.1:18080".to_string()),
                (0, "http://127.0.0.1:18081".to_string()),
            ])
            .is_err());
        assert!(lb
            .replace_dynamic_backends(&[
                (0, "http://127.0.0.1:18080".to_string()),
                (1, "http://127.0.0.1:18080".to_string()),
            ])
            .is_err());
        assert!(lb.backends().is_empty());
    }

    #[test]
    fn test_round_robin_healthy_skips_all_unhealthy() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

        // Mark all unhealthy
        for b in lb.backends().iter() {
            b.set_healthy(false);
        }
        assert!(lb.next_backend().is_none());
    }

    #[test]
    fn test_random_skips_unhealthy() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
        let lb = LoadBalancer::new("test".into(), Strategy::Random, &servers, None);

        // Mark two unhealthy, only c remains
        lb.backends()[0].set_healthy(false);
        lb.backends()[1].set_healthy(false);

        // Run multiple times, should always get c
        for _ in 0..10 {
            let b = lb.next_backend().unwrap();
            assert_eq!(b.url, "http://c:8003");
        }
    }

    #[test]
    fn test_random_all_unhealthy() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
        let lb = LoadBalancer::new("test".into(), Strategy::Random, &servers, None);

        lb.backends()[0].set_healthy(false);
        lb.backends()[1].set_healthy(false);
        assert!(lb.next_backend().is_none());
    }
}
