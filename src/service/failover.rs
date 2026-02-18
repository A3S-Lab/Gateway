//! Failover service — automatic fallback to a secondary backend pool
//!
//! When the primary service has zero healthy backends, requests are
//! automatically routed to the failover service.

use crate::service::{Backend, LoadBalancer};
use std::sync::Arc;

/// Failover selector — tries primary, falls back to secondary
pub struct FailoverSelector {
    /// Primary service load balancer
    primary: Arc<LoadBalancer>,
    /// Failover service load balancer
    failover: Arc<LoadBalancer>,
}

impl FailoverSelector {
    /// Create a new failover selector
    pub fn new(primary: Arc<LoadBalancer>, failover: Arc<LoadBalancer>) -> Self {
        Self { primary, failover }
    }

    /// Select a backend — primary first, failover if primary has no healthy backends
    pub fn next_backend(&self) -> Option<(Arc<Backend>, bool)> {
        if self.primary.healthy_count() > 0 {
            self.primary.next_backend().map(|b| (b, false))
        } else {
            tracing::warn!(
                primary = self.primary.name,
                failover = self.failover.name,
                "Primary service has no healthy backends, failing over"
            );
            self.failover.next_backend().map(|b| (b, true))
        }
    }

    /// Get the primary service name
    #[allow(dead_code)]
    pub fn primary_name(&self) -> &str {
        &self.primary.name
    }

    /// Get the failover service name
    #[allow(dead_code)]
    pub fn failover_name(&self) -> &str {
        &self.failover.name
    }

    /// Check if currently using failover
    #[allow(dead_code)]
    pub fn is_failed_over(&self) -> bool {
        self.primary.healthy_count() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, Strategy};

    fn make_lb(name: &str, urls: Vec<&str>) -> Arc<LoadBalancer> {
        let servers: Vec<ServerConfig> = urls
            .into_iter()
            .map(|u| ServerConfig {
                url: u.to_string(),
                weight: 1,
            })
            .collect();
        Arc::new(LoadBalancer::new(
            name.to_string(),
            Strategy::RoundRobin,
            &servers,
            None,
        ))
    }

    #[test]
    fn test_failover_uses_primary_when_healthy() {
        let primary = make_lb("primary", vec!["http://primary:8001"]);
        let failover = make_lb("backup", vec!["http://backup:9001"]);
        let selector = FailoverSelector::new(primary, failover);

        let (backend, is_failover) = selector.next_backend().unwrap();
        assert_eq!(backend.url, "http://primary:8001");
        assert!(!is_failover);
        assert!(!selector.is_failed_over());
    }

    #[test]
    fn test_failover_switches_when_primary_unhealthy() {
        let primary = make_lb("primary", vec!["http://primary:8001"]);
        let failover = make_lb("backup", vec!["http://backup:9001"]);

        // Mark primary as unhealthy
        primary.backends()[0].set_healthy(false);

        let selector = FailoverSelector::new(primary, failover);
        let (backend, is_failover) = selector.next_backend().unwrap();
        assert_eq!(backend.url, "http://backup:9001");
        assert!(is_failover);
        assert!(selector.is_failed_over());
    }

    #[test]
    fn test_failover_returns_none_when_both_unhealthy() {
        let primary = make_lb("primary", vec!["http://primary:8001"]);
        let failover = make_lb("backup", vec!["http://backup:9001"]);

        primary.backends()[0].set_healthy(false);
        failover.backends()[0].set_healthy(false);

        let selector = FailoverSelector::new(primary, failover);
        assert!(selector.next_backend().is_none());
    }

    #[test]
    fn test_failover_recovers_to_primary() {
        let primary = make_lb("primary", vec!["http://primary:8001"]);
        let failover = make_lb("backup", vec!["http://backup:9001"]);

        // Start unhealthy
        primary.backends()[0].set_healthy(false);
        let selector = FailoverSelector::new(primary.clone(), failover);

        let (backend, is_failover) = selector.next_backend().unwrap();
        assert!(is_failover);
        assert_eq!(backend.url, "http://backup:9001");

        // Primary recovers
        primary.backends()[0].set_healthy(true);
        let (backend, is_failover) = selector.next_backend().unwrap();
        assert!(!is_failover);
        assert_eq!(backend.url, "http://primary:8001");
    }

    #[test]
    fn test_failover_multiple_primary_backends() {
        let primary = make_lb("primary", vec!["http://p1:8001", "http://p2:8002"]);
        let failover = make_lb("backup", vec!["http://backup:9001"]);

        // Only one primary unhealthy — should still use primary
        primary.backends()[0].set_healthy(false);
        let selector = FailoverSelector::new(primary.clone(), failover);

        let (backend, is_failover) = selector.next_backend().unwrap();
        assert!(!is_failover);
        assert_eq!(backend.url, "http://p2:8002");

        // Both primary unhealthy — failover
        primary.backends()[1].set_healthy(false);
        let (backend, is_failover) = selector.next_backend().unwrap();
        assert!(is_failover);
        assert_eq!(backend.url, "http://backup:9001");
    }

    #[test]
    fn test_failover_names() {
        let primary = make_lb("api", vec!["http://primary:8001"]);
        let failover = make_lb("api-backup", vec!["http://backup:9001"]);
        let selector = FailoverSelector::new(primary, failover);
        assert_eq!(selector.primary_name(), "api");
        assert_eq!(selector.failover_name(), "api-backup");
    }
}
