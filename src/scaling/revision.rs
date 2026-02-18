//! Revision router — weighted traffic splitting across named revisions

use crate::config::RevisionConfig;
use crate::service::{Backend, LoadBalancer};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

/// A single revision — a named backend pool with a traffic weight
pub struct Revision {
    /// Revision name (e.g., "v1")
    pub name: String,
    /// Traffic percentage (0..=100), stored atomically for live updates
    traffic_percent: AtomicU64,
    /// Load balancer for this revision's backends
    lb: Arc<LoadBalancer>,
}

impl Revision {
    /// Create a new revision
    pub fn new(name: String, traffic_percent: u32, lb: Arc<LoadBalancer>) -> Self {
        Self {
            name,
            traffic_percent: AtomicU64::new(traffic_percent as u64),
            lb,
        }
    }

    /// Get the current traffic percentage
    #[allow(dead_code)]
    pub fn traffic_percent(&self) -> u32 {
        self.traffic_percent.load(Ordering::Relaxed) as u32
    }

    /// Set the traffic percentage
    pub fn set_traffic_percent(&self, pct: u32) {
        self.traffic_percent.store(pct as u64, Ordering::Relaxed);
    }

    /// Get the load balancer for this revision
    #[allow(dead_code)]
    pub fn load_balancer(&self) -> &Arc<LoadBalancer> {
        &self.lb
    }
}

/// Router that splits traffic across multiple revisions
pub struct RevisionRouter {
    /// Service name
    service: String,
    /// Ordered list of revisions
    revisions: Vec<Arc<Revision>>,
    /// Counter for weighted selection
    counter: AtomicUsize,
}

impl RevisionRouter {
    /// Build a revision router from configuration
    pub fn from_config(service: &str, configs: &[RevisionConfig]) -> Self {
        let revisions = configs
            .iter()
            .map(|rc| {
                let lb = Arc::new(LoadBalancer::new(
                    format!("{}/{}", service, rc.name),
                    rc.strategy.clone(),
                    &rc.servers,
                    None,
                ));
                Arc::new(Revision::new(rc.name.clone(), rc.traffic_percent, lb))
            })
            .collect();

        Self {
            service: service.to_string(),
            revisions,
            counter: AtomicUsize::new(0),
        }
    }

    /// Select a backend using weighted traffic splitting.
    /// Returns `(backend, revision_name)` or None if no healthy backend is available.
    pub fn next_backend(&self) -> Option<(Arc<Backend>, String)> {
        if self.revisions.is_empty() {
            return None;
        }

        // Build weighted selection from traffic percentages
        let total_weight: u64 = self
            .revisions
            .iter()
            .map(|r| r.traffic_percent.load(Ordering::Relaxed))
            .sum();

        if total_weight == 0 {
            return None;
        }

        let counter = self.counter.fetch_add(1, Ordering::Relaxed) as u64;
        let target = counter % total_weight;
        let mut cumulative = 0u64;

        for rev in &self.revisions {
            cumulative += rev.traffic_percent.load(Ordering::Relaxed);
            if target < cumulative {
                if let Some(backend) = rev.lb.next_backend() {
                    return Some((backend, rev.name.clone()));
                }
                // Fallthrough: if this revision has no healthy backends,
                // try the next one
            }
        }

        // Fallback: try all revisions
        for rev in &self.revisions {
            if let Some(backend) = rev.lb.next_backend() {
                return Some((backend, rev.name.clone()));
            }
        }

        None
    }

    /// Atomically update traffic percentages for two revisions
    #[allow(dead_code)]
    pub fn set_traffic(&self, from_name: &str, from_pct: u32, to_name: &str, to_pct: u32) {
        for rev in &self.revisions {
            if rev.name == from_name {
                rev.set_traffic_percent(from_pct);
            } else if rev.name == to_name {
                rev.set_traffic_percent(to_pct);
            }
        }
    }

    /// Look up a revision by name
    #[allow(dead_code)]
    pub fn get_revision(&self, name: &str) -> Option<&Arc<Revision>> {
        self.revisions.iter().find(|r| r.name == name)
    }

    /// Service name
    #[allow(dead_code)]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// List all revisions
    #[allow(dead_code)]
    pub fn revisions(&self) -> &[Arc<Revision>] {
        &self.revisions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, Strategy};

    fn rev_config(name: &str, pct: u32, urls: Vec<&str>) -> RevisionConfig {
        RevisionConfig {
            name: name.into(),
            traffic_percent: pct,
            servers: urls
                .into_iter()
                .map(|u| ServerConfig {
                    url: u.into(),
                    weight: 1,
                })
                .collect(),
            strategy: Strategy::RoundRobin,
        }
    }

    #[test]
    fn test_single_revision_100() {
        let configs = vec![rev_config("v1", 100, vec!["http://a:8001"])];
        let router = RevisionRouter::from_config("svc", &configs);

        for _ in 0..10 {
            let (backend, rev) = router.next_backend().unwrap();
            assert_eq!(rev, "v1");
            assert_eq!(backend.url, "http://a:8001");
        }
    }

    #[test]
    fn test_90_10_split() {
        let configs = vec![
            rev_config("v1", 90, vec!["http://a:8001"]),
            rev_config("v2", 10, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);

        let mut v1_count = 0;
        let mut v2_count = 0;
        for _ in 0..100 {
            let (_, rev) = router.next_backend().unwrap();
            if rev == "v1" {
                v1_count += 1;
            } else {
                v2_count += 1;
            }
        }
        assert_eq!(v1_count, 90);
        assert_eq!(v2_count, 10);
    }

    #[test]
    fn test_50_50_split() {
        let configs = vec![
            rev_config("v1", 50, vec!["http://a:8001"]),
            rev_config("v2", 50, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);

        let mut v1_count = 0;
        let mut v2_count = 0;
        for _ in 0..100 {
            let (_, rev) = router.next_backend().unwrap();
            if rev == "v1" {
                v1_count += 1;
            } else {
                v2_count += 1;
            }
        }
        assert_eq!(v1_count, 50);
        assert_eq!(v2_count, 50);
    }

    #[test]
    fn test_set_traffic() {
        let configs = vec![
            rev_config("v1", 90, vec!["http://a:8001"]),
            rev_config("v2", 10, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);

        router.set_traffic("v1", 50, "v2", 50);

        let v1 = router.get_revision("v1").unwrap();
        let v2 = router.get_revision("v2").unwrap();
        assert_eq!(v1.traffic_percent(), 50);
        assert_eq!(v2.traffic_percent(), 50);
    }

    #[test]
    fn test_get_revision() {
        let configs = vec![
            rev_config("v1", 80, vec!["http://a:8001"]),
            rev_config("v2", 20, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);

        assert!(router.get_revision("v1").is_some());
        assert!(router.get_revision("v2").is_some());
        assert!(router.get_revision("v3").is_none());
    }

    #[test]
    fn test_empty_revisions() {
        let router = RevisionRouter::from_config("svc", &[]);
        assert!(router.next_backend().is_none());
    }

    #[test]
    fn test_fallback_to_healthy_revision() {
        let configs = vec![
            rev_config("v1", 90, vec!["http://a:8001"]),
            rev_config("v2", 10, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);

        // Make v1's backend unhealthy
        let v1 = router.get_revision("v1").unwrap();
        for b in v1.lb.backends() {
            b.set_healthy(false);
        }

        // All traffic should go to v2
        for _ in 0..10 {
            let (_, rev) = router.next_backend().unwrap();
            assert_eq!(rev, "v2");
        }
    }

    #[test]
    fn test_service_name() {
        let router = RevisionRouter::from_config("my-svc", &[]);
        assert_eq!(router.service(), "my-svc");
    }

    #[test]
    fn test_revisions_list() {
        let configs = vec![
            rev_config("v1", 70, vec!["http://a:8001"]),
            rev_config("v2", 30, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);
        assert_eq!(router.revisions().len(), 2);
    }

    #[test]
    fn test_revision_router_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RevisionRouter>();
    }
}
