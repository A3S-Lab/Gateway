//! Concurrency limiter — enforces per-container concurrency caps

use crate::service::Backend;
use std::sync::Arc;

/// Result of a concurrency check against a backend
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConcurrencyCheckResult {
    /// Backend is below its concurrency limit
    Allowed,
    /// Backend has reached its concurrency limit
    AtCapacity { current: usize, limit: u32 },
}

/// Per-service concurrency limiter based on `containerConcurrency`
pub struct ConcurrencyLimiter {
    limit: u32,
}

impl ConcurrencyLimiter {
    /// Create a new limiter. A limit of 0 means unlimited.
    pub fn new(limit: u32) -> Self {
        Self { limit }
    }

    /// Check whether a backend is at capacity
    pub fn check(&self, backend: &Backend) -> ConcurrencyCheckResult {
        if self.limit == 0 {
            return ConcurrencyCheckResult::Allowed;
        }
        let current = backend.connections();
        if current < self.limit as usize {
            ConcurrencyCheckResult::Allowed
        } else {
            ConcurrencyCheckResult::AtCapacity {
                current,
                limit: self.limit,
            }
        }
    }

    /// Select the healthy backend with the fewest connections that is below the limit.
    /// Returns None if all backends are at capacity or unhealthy.
    pub fn select_with_capacity(&self, backends: &[Arc<Backend>]) -> Option<Arc<Backend>> {
        let candidates: Vec<_> = backends
            .iter()
            .filter(|b| b.is_healthy())
            .filter(|b| self.check(b) == ConcurrencyCheckResult::Allowed)
            .collect();

        candidates
            .into_iter()
            .min_by_key(|b| b.connections())
            .cloned()
    }

    /// Total in-flight requests across all backends
    #[allow(dead_code)]
    pub fn total_in_flight(&self, backends: &[Arc<Backend>]) -> usize {
        backends.iter().map(|b| b.connections()).sum()
    }

    /// Number of backends that are at capacity
    #[allow(dead_code)]
    pub fn at_capacity_count(&self, backends: &[Arc<Backend>]) -> usize {
        if self.limit == 0 {
            return 0;
        }
        backends
            .iter()
            .filter(|b| b.connections() >= self.limit as usize)
            .count()
    }

    /// Get the configured limit
    #[allow(dead_code)]
    pub fn limit(&self) -> u32 {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, Strategy};
    use crate::service::LoadBalancer;

    fn make_backends(count: usize) -> Vec<Arc<Backend>> {
        let servers: Vec<ServerConfig> = (0..count)
            .map(|i| ServerConfig {
                url: format!("http://backend-{}:8080", i),
                weight: 1,
            })
            .collect();
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);
        lb.backends().to_vec()
    }

    #[test]
    fn test_unlimited_always_allowed() {
        let limiter = ConcurrencyLimiter::new(0);
        let backends = make_backends(1);
        // Add many connections — should still be allowed
        for _ in 0..100 {
            backends[0].inc_connections();
        }
        assert_eq!(limiter.check(&backends[0]), ConcurrencyCheckResult::Allowed);
    }

    #[test]
    fn test_allowed_under_limit() {
        let limiter = ConcurrencyLimiter::new(5);
        let backends = make_backends(1);
        backends[0].inc_connections();
        backends[0].inc_connections();
        assert_eq!(limiter.check(&backends[0]), ConcurrencyCheckResult::Allowed);
    }

    #[test]
    fn test_at_capacity() {
        let limiter = ConcurrencyLimiter::new(2);
        let backends = make_backends(1);
        backends[0].inc_connections();
        backends[0].inc_connections();
        assert_eq!(
            limiter.check(&backends[0]),
            ConcurrencyCheckResult::AtCapacity {
                current: 2,
                limit: 2
            }
        );
    }

    #[test]
    fn test_select_with_capacity_picks_least_loaded() {
        let limiter = ConcurrencyLimiter::new(10);
        let backends = make_backends(3);
        backends[0].inc_connections();
        backends[0].inc_connections();
        backends[0].inc_connections();
        backends[1].inc_connections();
        // backends[2] has 0 connections
        let selected = limiter.select_with_capacity(&backends).unwrap();
        assert_eq!(selected.url, "http://backend-2:8080");
    }

    #[test]
    fn test_select_with_capacity_skips_unhealthy() {
        let limiter = ConcurrencyLimiter::new(10);
        let backends = make_backends(2);
        // Backend 1 has fewer connections but is unhealthy
        backends[0].inc_connections();
        backends[1].set_healthy(false);
        let selected = limiter.select_with_capacity(&backends).unwrap();
        assert_eq!(selected.url, "http://backend-0:8080");
    }

    #[test]
    fn test_select_with_capacity_skips_at_capacity() {
        let limiter = ConcurrencyLimiter::new(1);
        let backends = make_backends(2);
        backends[0].inc_connections(); // at capacity
        let selected = limiter.select_with_capacity(&backends).unwrap();
        assert_eq!(selected.url, "http://backend-1:8080");
    }

    #[test]
    fn test_select_with_capacity_all_at_capacity() {
        let limiter = ConcurrencyLimiter::new(1);
        let backends = make_backends(2);
        backends[0].inc_connections();
        backends[1].inc_connections();
        assert!(limiter.select_with_capacity(&backends).is_none());
    }

    #[test]
    fn test_total_in_flight() {
        let limiter = ConcurrencyLimiter::new(10);
        let backends = make_backends(3);
        backends[0].inc_connections();
        backends[0].inc_connections();
        backends[1].inc_connections();
        assert_eq!(limiter.total_in_flight(&backends), 3);
    }

    #[test]
    fn test_at_capacity_count() {
        let limiter = ConcurrencyLimiter::new(2);
        let backends = make_backends(3);
        backends[0].inc_connections();
        backends[0].inc_connections(); // at capacity
        backends[1].inc_connections(); // below
                                       // backends[2] has 0
        assert_eq!(limiter.at_capacity_count(&backends), 1);
    }

    #[test]
    fn test_at_capacity_count_unlimited() {
        let limiter = ConcurrencyLimiter::new(0);
        let backends = make_backends(2);
        for _ in 0..100 {
            backends[0].inc_connections();
        }
        assert_eq!(limiter.at_capacity_count(&backends), 0);
    }

    #[test]
    fn test_limiter_limit() {
        let limiter = ConcurrencyLimiter::new(42);
        assert_eq!(limiter.limit(), 42);
    }
}
