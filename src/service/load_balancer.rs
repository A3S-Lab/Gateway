//! Load balancer — distributes requests across backend servers

use crate::config::{ServerConfig, Strategy};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// A single backend server
#[derive(Debug)]
pub struct Backend {
    /// Server URL
    pub url: String,
    /// Weight for weighted balancing
    pub weight: u32,
    /// Whether the backend is healthy
    healthy: AtomicBool,
    /// Active connection count
    active_connections: AtomicUsize,
}

impl Backend {
    fn new(url: String, weight: u32) -> Self {
        Self {
            url,
            weight,
            healthy: AtomicBool::new(true),
            active_connections: AtomicUsize::new(0),
        }
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
    pub fn inc_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement active connections
    pub fn dec_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get active connection count
    pub fn connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
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
}

impl LoadBalancer {
    /// Create a new load balancer
    pub fn new(
        name: String,
        strategy: Strategy,
        servers: &[ServerConfig],
        sticky_cookie: Option<String>,
    ) -> Self {
        let backends = servers
            .iter()
            .map(|s| Arc::new(Backend::new(s.url.clone(), s.weight)))
            .collect();

        Self {
            name,
            strategy,
            backends,
            rr_counter: AtomicUsize::new(0),
            sticky_cookie,
        }
    }

    /// Select the next healthy backend
    pub fn next_backend(&self) -> Option<Arc<Backend>> {
        let healthy: Vec<_> = self.backends.iter().filter(|b| b.is_healthy()).collect();
        if healthy.is_empty() {
            return None;
        }

        match self.strategy {
            Strategy::RoundRobin => {
                let idx = self.rr_counter.fetch_add(1, Ordering::Relaxed) % healthy.len();
                Some(healthy[idx].clone())
            }
            Strategy::Weighted => {
                let total_weight: u32 = healthy.iter().map(|b| b.weight).sum();
                if total_weight == 0 {
                    return healthy.first().map(|b| (*b).clone());
                }
                let counter = self.rr_counter.fetch_add(1, Ordering::Relaxed) as u32;
                let target = counter % total_weight;
                let mut cumulative = 0u32;
                for backend in &healthy {
                    cumulative += backend.weight;
                    if target < cumulative {
                        return Some((*backend).clone());
                    }
                }
                healthy.last().map(|b| (*b).clone())
            }
            Strategy::LeastConnections => healthy
                .iter()
                .min_by_key(|b| b.connections())
                .map(|b| (*b).clone()),
            Strategy::Random => {
                let idx = (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .subsec_nanos() as usize)
                    % healthy.len();
                Some(healthy[idx].clone())
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
    pub fn total_count(&self) -> usize {
        self.backends.len()
    }

    /// Get sticky cookie name
    pub fn sticky_cookie(&self) -> Option<&str> {
        self.sticky_cookie.as_deref()
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
}
