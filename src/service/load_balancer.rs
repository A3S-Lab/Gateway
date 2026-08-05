//! Load balancer — distributes requests across backend servers

use crate::config::{ServerConfig, Strategy};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const DEFAULT_STREAM_TOTAL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const BACKEND_CONNECTION_COUNTER_SHARDS: usize = 16;

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
        let mut identity = Sha256::new();
        identity.update(b"a3s-gateway-backend-slot-v1");
        identity.update([0]);
        identity.update(scope.as_bytes());
        identity.update([0]);
        identity.update(index.to_be_bytes());
        let http_base_uri = url.parse::<http::Uri>().ok();
        Self {
            url,
            http_base_uri,
            metric_id: format!("b_{:x}", identity.finalize()),
            weight,
            healthy: AtomicBool::new(true),
            active_connections: std::array::from_fn(|_| {
                ConnectionCounterShard(AtomicUsize::new(0))
            }),
        }
    }

    /// Stable opaque identity for credential-safe telemetry labels.
    pub fn metric_id(&self) -> &str {
        &self.metric_id
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
    backends: Vec<Arc<Backend>>,
    /// Round-robin counter
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
        let backends = servers
            .iter()
            .enumerate()
            .map(|(index, server)| {
                Arc::new(Backend::new_scoped(
                    &name,
                    index,
                    server.url.clone(),
                    server.weight,
                ))
            })
            .collect();

        Self {
            name,
            strategy,
            backends,
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
    /// Avoids heap allocation by iterating backends twice (count then pick)
    /// instead of collecting into a Vec. For typical backend counts (1–20)
    /// this is faster than Vec alloc + dealloc on every request.
    pub fn next_backend(&self) -> Option<Arc<Backend>> {
        // A single-backend service does not need a shared round-robin counter
        // or a second health scan. Avoiding that contended atomic matters when
        // many runtime workers proxy to the same upstream.
        if let [backend] = self.backends.as_slice() {
            return backend.is_healthy().then(|| Arc::clone(backend));
        }

        let healthy_count = self.backends.iter().filter(|b| b.is_healthy()).count();
        if healthy_count == 0 {
            return None;
        }

        match self.strategy {
            Strategy::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy_count;
                self.backends
                    .iter()
                    .filter(|b| b.is_healthy())
                    .nth(idx)
                    .cloned()
            }
            Strategy::Weighted => {
                let total_weight: u32 = self
                    .backends
                    .iter()
                    .filter(|b| b.is_healthy())
                    .map(|b| b.weight)
                    .sum();
                if total_weight == 0 {
                    return self.backends.iter().find(|b| b.is_healthy()).cloned();
                }
                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed) as u32;
                let target = counter % total_weight;
                let mut cumulative = 0u32;
                for backend in self.backends.iter().filter(|b| b.is_healthy()) {
                    cumulative += backend.weight;
                    if target < cumulative {
                        return Some(backend.clone());
                    }
                }
                self.backends.iter().rfind(|b| b.is_healthy()).cloned()
            }
            Strategy::LeastConnections => self
                .backends
                .iter()
                .filter(|b| b.is_healthy())
                .min_by_key(|b| b.connections())
                .cloned(),
            Strategy::Random => {
                let idx = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as usize)
                    % healthy_count;
                self.backends
                    .iter()
                    .filter(|b| b.is_healthy())
                    .nth(idx)
                    .cloned()
            }
        }
    }

    /// Get all backends (for health checking)
    pub fn backends(&self) -> &[Arc<Backend>] {
        &self.backends
    }

    /// Number of healthy backends
    pub fn healthy_count(&self) -> usize {
        self.backends.iter().filter(|b| b.is_healthy()).count()
    }

    /// Total number of backends
    #[allow(dead_code)]
    pub fn total_count(&self) -> usize {
        self.backends.len()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_servers(urls: Vec<&str>) -> Vec<ServerConfig> {
        urls.into_iter()
            .map(|url| ServerConfig {
                url: url.to_string(),
                weight: 1,
            })
            .collect()
    }

    fn make_weighted_servers() -> Vec<ServerConfig> {
        vec![
            ServerConfig {
                url: "http://a:8001".to_string(),
                weight: 3,
            },
            ServerConfig {
                url: "http://b:8002".to_string(),
                weight: 1,
            },
        ]
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
    fn test_random_returns_something() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
        let lb = LoadBalancer::new("test".into(), Strategy::Random, &servers, None);

        let b = lb.next_backend();
        assert!(b.is_some());
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
            },
            ServerConfig {
                url: "http://b:8002".to_string(),
                weight: 0,
            },
        ];
        let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);
        // Should return a healthy backend (first one found)
        let b = lb.next_backend();
        assert!(b.is_some());
        assert!(b.unwrap().url.starts_with("http://"));
    }

    #[test]
    fn test_weighted_all_unhealthy() {
        let servers = vec![
            ServerConfig {
                url: "http://a:8001".to_string(),
                weight: 3,
            },
            ServerConfig {
                url: "http://b:8002".to_string(),
                weight: 1,
            },
        ];
        let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);
        lb.backends()[0].set_healthy(false);
        lb.backends()[1].set_healthy(false);
        assert!(lb.next_backend().is_none());
    }

    #[test]
    fn test_round_robin_healthy_skips_all_unhealthy() {
        let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

        // Mark all unhealthy
        for b in lb.backends() {
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
