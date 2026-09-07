//! Revision router — weighted traffic splitting across named revisions

use crate::config::RevisionConfig;
use crate::scaling::concurrency::ConcurrencyLimiter;
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

#[allow(dead_code)]
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
    pub fn traffic_percent(&self) -> u32 {
        self.traffic_percent.load(Ordering::Relaxed) as u32
    }

    /// Set the traffic percentage
    pub fn set_traffic_percent(&self, pct: u32) {
        self.traffic_percent.store(pct as u64, Ordering::Relaxed);
    }

    /// Get the load balancer for this revision
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
        self.next_backend_with_constraints(None, None)
    }

    /// Select a backend using weighted traffic splitting while honoring a
    /// per-container concurrency limit. Revisions and concurrency are both
    /// service-level policies, so choosing a revision must not bypass the
    /// limiter configured for that service.
    pub(crate) fn next_backend_with_capacity(
        &self,
        limiter: &ConcurrencyLimiter,
    ) -> Option<(Arc<Backend>, String)> {
        self.next_backend_with_constraints(Some(limiter), None)
    }

    /// Select a backend for a replay while honoring concurrency and excluding
    /// the exact backend that just failed.
    pub(crate) fn next_backend_with_capacity_excluding(
        &self,
        limiter: &ConcurrencyLimiter,
        excluded: &Backend,
    ) -> Option<(Arc<Backend>, String)> {
        self.next_backend_with_constraints(Some(limiter), Some(excluded))
    }

    fn next_backend_with_constraints(
        &self,
        limiter: Option<&ConcurrencyLimiter>,
        excluded: Option<&Backend>,
    ) -> Option<(Arc<Backend>, String)> {
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
            let weight = rev.traffic_percent.load(Ordering::Relaxed);
            if weight == 0 {
                continue;
            }
            cumulative += weight;
            if target < cumulative {
                if let Some(backend) = select_backend(rev, limiter, excluded) {
                    return Some((backend, rev.name.clone()));
                }
                // Fallthrough: if this revision has no healthy backends,
                // try the next one
            }
        }

        // Fallback only considers revisions with non-zero traffic. A zero
        // weight is an explicit drain/disable signal and must not receive
        // traffic merely because an enabled revision is temporarily
        // unhealthy.
        for rev in &self.revisions {
            if rev.traffic_percent.load(Ordering::Relaxed) > 0 {
                if let Some(backend) = select_backend(rev, limiter, excluded) {
                    return Some((backend, rev.name.clone()));
                }
            }
        }

        None
    }

    /// Select a healthy backend other than `excluded` for a replayed request.
    ///
    /// The ordinary weighted choice is attempted first.  If it would repeat
    /// the failed backend, each eligible revision is scanned once using its
    /// own load-balancing policy.  This keeps retries inside the configured
    /// revision set and never creates a target outside the active snapshot.
    pub(crate) fn next_backend_excluding(
        &self,
        excluded: &Backend,
    ) -> Option<(Arc<Backend>, String)> {
        self.next_backend_with_constraints(None, Some(excluded))
    }

    /// Whether weighted revision routing can currently select a healthy backend.
    pub(crate) fn has_healthy_backend(&self) -> bool {
        self.revisions
            .iter()
            .map(|revision| revision.traffic_percent.load(Ordering::Relaxed))
            .sum::<u64>()
            > 0
            && self.revisions.iter().any(|revision| {
                revision.traffic_percent.load(Ordering::Relaxed) > 0
                    && revision.lb.healthy_count() > 0
            })
    }

    /// Number of healthy backends across all configured revisions.
    pub(crate) fn healthy_backend_count(&self) -> usize {
        self.revisions
            .iter()
            .map(|revision| revision.lb.healthy_count())
            .sum()
    }

    /// Total active operations across all revision backends.
    pub(crate) fn total_in_flight(&self) -> usize {
        self.revisions
            .iter()
            .map(|revision| {
                revision
                    .lb
                    .backends()
                    .iter()
                    .map(|backend| backend.connections())
                    .sum::<usize>()
            })
            .sum()
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

    /// Apply the service-level concurrency limit to every revision pool.
    /// Revision routing and ordinary service routing share the same admission
    /// contract, so a revision backend must reserve capacity before it can be
    /// selected for an operation.
    pub(crate) fn set_concurrency_limit(&self, limit: u32) {
        for revision in &self.revisions {
            revision.load_balancer().set_concurrency_limit(limit);
        }
    }
}

fn select_backend(
    revision: &Revision,
    limiter: Option<&ConcurrencyLimiter>,
    excluded: Option<&Backend>,
) -> Option<Arc<Backend>> {
    match (limiter, excluded) {
        (Some(limiter), Some(excluded)) => limiter.select_with_capacity_excluding(
            revision.load_balancer().backends().as_slice(),
            Some(excluded),
        ),
        (Some(limiter), None) => {
            limiter.select_with_capacity(revision.load_balancer().backends().as_slice())
        }
        (None, Some(excluded)) => revision.load_balancer().next_backend_excluding(excluded),
        (None, None) => revision.load_balancer().next_backend(),
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
                    target: None,
                })
                .collect(),
            strategy: Strategy::RoundRobin,
        }
    }

    #[test]
    fn test_single_revision_100() {
        let configs = vec![rev_config("v1", 100, vec!["http://a:8001"])];
        let router = RevisionRouter::from_config("svc", &configs);
        assert!(router.has_healthy_backend());

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
        assert!(!router.has_healthy_backend());
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
        for b in v1.lb.backends().iter() {
            b.set_healthy(false);
        }

        assert!(router.has_healthy_backend());
        // All traffic should go to v2
        for _ in 0..10 {
            let (_, rev) = router.next_backend().unwrap();
            assert_eq!(rev, "v2");
        }
    }

    #[test]
    fn test_retry_selection_skips_failed_revision_backend() {
        let configs = vec![
            rev_config("v1", 90, vec!["http://a:8001"]),
            rev_config("v2", 10, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);
        let failed = router
            .get_revision("v1")
            .unwrap()
            .load_balancer()
            .backends()[0]
            .clone();

        let (backend, revision) = router.next_backend_excluding(&failed).unwrap();
        assert_eq!(backend.url, "http://b:8001");
        assert_eq!(revision, "v2");
    }

    #[test]
    fn zero_weight_revision_never_receives_fallback_traffic() {
        let configs = vec![
            rev_config("v1", 100, vec!["http://a:8001"]),
            rev_config("v2", 0, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);
        let failed = router
            .get_revision("v1")
            .unwrap()
            .load_balancer()
            .backends()[0]
            .clone();
        failed.set_healthy(false);

        assert!(router.next_backend().is_none());
        assert!(router.next_backend_excluding(&failed).is_none());
        assert!(!router.has_healthy_backend());
    }

    #[test]
    fn revision_selection_honors_container_capacity() {
        let configs = vec![
            rev_config("v1", 100, vec!["http://a:8001"]),
            rev_config("v2", 0, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);
        let v1 = router
            .get_revision("v1")
            .unwrap()
            .load_balancer()
            .backends()[0]
            .clone();
        v1.inc_connections();
        let limiter = ConcurrencyLimiter::new(1);

        assert!(router.next_backend_with_capacity(&limiter).is_none());
    }

    #[test]
    fn revision_selection_falls_through_to_an_enabled_revision_below_capacity() {
        let configs = vec![
            rev_config("v1", 50, vec!["http://a:8001"]),
            rev_config("v2", 50, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);
        let v1 = router
            .get_revision("v1")
            .unwrap()
            .load_balancer()
            .backends()[0]
            .clone();
        v1.inc_connections();
        let limiter = ConcurrencyLimiter::new(1);

        let (backend, revision) = router.next_backend_with_capacity(&limiter).unwrap();
        assert_eq!(backend.url, "http://b:8001");
        assert_eq!(revision, "v2");
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

    #[test]
    fn test_zero_total_weight_returns_none() {
        let configs = vec![
            rev_config("v1", 0, vec!["http://a:8001"]),
            rev_config("v2", 0, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);
        assert!(router.next_backend().is_none());
        assert!(!router.has_healthy_backend());
    }

    #[test]
    fn test_revision_set_traffic_unknown_revision() {
        let configs = vec![rev_config("v1", 100, vec!["http://a:8001"])];
        let router = RevisionRouter::from_config("svc", &configs);
        // Setting traffic for unknown revision should not panic
        router.set_traffic("unknown", 0, "also-unknown", 100);
        // v1 should still be at 100
        let v1 = router.get_revision("v1").unwrap();
        assert_eq!(v1.traffic_percent(), 100);
    }

    #[test]
    fn test_set_traffic_one_unknown_revision() {
        let configs = vec![
            rev_config("v1", 80, vec!["http://a:8001"]),
            rev_config("v2", 20, vec!["http://b:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);

        // Set traffic with one unknown revision - should only update the known one
        router.set_traffic("v1", 60, "unknown-revision", 40);

        let v1 = router.get_revision("v1").unwrap();
        let v2 = router.get_revision("v2").unwrap();
        assert_eq!(v1.traffic_percent(), 60);
        assert_eq!(v2.traffic_percent(), 20); // unchanged
    }

    #[test]
    fn test_revision_traffic_percent_clamping() {
        let configs = vec![rev_config("v1", 100, vec!["http://a:8001"])];
        let router = RevisionRouter::from_config("svc", &configs);
        let v1 = router.get_revision("v1").unwrap();

        // Verify initial traffic percent
        assert_eq!(v1.traffic_percent(), 100);

        // Update traffic
        router.set_traffic("v1", 75, "nonexistent", 0);
        assert_eq!(v1.traffic_percent(), 75);
    }

    #[test]
    fn test_revision_traffic_percent_set_get() {
        let configs = vec![rev_config("v1", 50, vec!["http://a:8001"])];
        let router = RevisionRouter::from_config("svc", &configs);
        let v1 = router.get_revision("v1").unwrap();

        // Directly test traffic_percent getter
        assert_eq!(v1.traffic_percent(), 50);

        // Modify and verify
        router.set_traffic("v1", 25, "nonexistent", 0);
        assert_eq!(v1.traffic_percent(), 25);

        router.set_traffic("v1", 0, "nonexistent", 0);
        assert_eq!(v1.traffic_percent(), 0);
    }

    #[test]
    fn test_revision_load_balancer_access() {
        let configs = vec![rev_config(
            "v1",
            100,
            vec!["http://a:8001", "http://b:8002"],
        )];
        let router = RevisionRouter::from_config("svc", &configs);
        let v1 = router.get_revision("v1").unwrap();

        // Access load balancer through the getter
        let lb = v1.load_balancer();
        assert!(!lb.backends().is_empty());
    }

    #[test]
    fn test_revision_load_balancer_backends() {
        let configs = vec![
            rev_config("v1", 60, vec!["http://a:8001"]),
            rev_config("v2", 40, vec!["http://b:8001", "http://c:8002"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);

        let v1 = router.get_revision("v1").unwrap();
        assert_eq!(v1.load_balancer().backends().len(), 1);

        let v2 = router.get_revision("v2").unwrap();
        assert_eq!(v2.load_balancer().backends().len(), 2);
    }

    #[test]
    fn test_multiple_revisions_three_way_split() {
        let configs = vec![
            rev_config("v1", 60, vec!["http://a:8001"]),
            rev_config("v2", 30, vec!["http://b:8001"]),
            rev_config("v3", 10, vec!["http://c:8001"]),
        ];
        let router = RevisionRouter::from_config("svc", &configs);

        let mut v1_count = 0;
        let mut v2_count = 0;
        let mut v3_count = 0;
        for _ in 0..100 {
            let (_, rev) = router.next_backend().unwrap();
            match rev.as_str() {
                "v1" => v1_count += 1,
                "v2" => v2_count += 1,
                "v3" => v3_count += 1,
                _ => unreachable!(),
            }
        }
        assert_eq!(v1_count, 60);
        assert_eq!(v2_count, 30);
        assert_eq!(v3_count, 10);
    }
}
