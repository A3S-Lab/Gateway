use crate::config::GatewayConfig;
use crate::entrypoint::ScalingState;
use crate::service::{Backend, LoadBalancer, ServiceRegistry};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod prometheus;

const HISTOGRAM_BUCKETS: &[(u64, &str)] = &[
    (5_000, "0.005"),
    (10_000, "0.01"),
    (25_000, "0.025"),
    (50_000, "0.05"),
    (100_000, "0.1"),
    (250_000, "0.25"),
    (500_000, "0.5"),
    (1_000_000, "1"),
    (2_500_000, "2.5"),
    (5_000_000, "5"),
    (10_000_000, "10"),
    (30_000_000, "30"),
    (60_000_000, "60"),
    (300_000_000, "300"),
    (600_000_000, "600"),
];

pub(super) struct TelemetryRegistry {
    active: RwLock<Arc<TelemetryTopology>>,
}

impl TelemetryRegistry {
    pub(super) fn new() -> Self {
        Self {
            active: RwLock::new(Arc::new(TelemetryTopology::default())),
        }
    }

    pub(super) fn prepare(
        &self,
        config: &GatewayConfig,
        service_registry: &ServiceRegistry,
        scaling: Option<&ScalingState>,
        enabled: bool,
    ) -> PreparedTelemetry {
        if !enabled {
            return PreparedTelemetry(Arc::new(TelemetryTopology {
                labels: MetricLabelBudget {
                    enforced: true,
                    ..MetricLabelBudget::default()
                },
                ..TelemetryTopology::default()
            }));
        }

        let active = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut services = BTreeMap::new();
        let mut labels = MetricLabelBudget {
            enforced: true,
            routers: config.routers.keys().cloned().collect(),
            services: config.services.keys().cloned().collect(),
            middlewares: config.middlewares.keys().cloned().collect(),
            backends: BTreeSet::new(),
            dynamic_backend_slots: BTreeMap::new(),
        };
        for (service_name, load_balancer) in service_registry.iter() {
            let statistics = active
                .services
                .get(service_name)
                .map(|source| source.statistics.clone())
                .unwrap_or_else(|| Arc::new(ServiceStatistics::new()));
            let mut revision_backends = BTreeMap::new();
            for backend in load_balancer.backends().iter() {
                labels.backends.insert(backend.metric_id().to_string());
            }
            if let Some(revision_router) =
                scaling.and_then(|state| state.revision_routers.get(service_name))
            {
                for revision in revision_router.revisions() {
                    for backend in revision.load_balancer().backends().iter() {
                        revision_backends.insert(backend.metric_id().to_string(), backend.clone());
                    }
                }
            }
            labels.backends.extend(revision_backends.keys().cloned());
            if let Some(box_scaling) = config
                .services
                .get(service_name)
                .filter(|service| service.uses_box_endpoint_discovery())
                .and_then(|service| service.scaling.as_ref())
            {
                labels.dynamic_backend_slots.insert(
                    load_balancer.dynamic_metric_prefix().to_string(),
                    box_scaling.max_replicas,
                );
            }

            services.insert(
                service_name.clone(),
                ServiceSource {
                    statistics,
                    queue: scaling
                        .and_then(|state| state.buffers.get(service_name))
                        .cloned(),
                    load_balancer: load_balancer.clone(),
                    revision_backends,
                },
            );
        }
        PreparedTelemetry(Arc::new(TelemetryTopology { services, labels }))
    }

    pub(super) fn activate(&self, prepared: PreparedTelemetry) -> PreparedTelemetry {
        let mut active = self
            .active
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        PreparedTelemetry(std::mem::replace(&mut *active, prepared.0))
    }

    pub(super) fn track_request(
        &self,
        service: &str,
        started_at: Instant,
    ) -> Option<ServiceRequestGuard> {
        let topology = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        ServiceRequestGuard::new(topology, service, started_at)
    }

    pub(super) fn render_prometheus(&self, output: &mut String) {
        let topology = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        topology.render_prometheus(output);
    }

    pub(super) fn reset_observations(&self) {
        let topology = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        for source in topology.services.values() {
            source.statistics.request_duration.reset();
            source.statistics.ttft.reset();
        }
    }

    pub(super) fn allows_router(&self, router: &str) -> bool {
        let active = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !active.labels.enforced || active.labels.routers.contains(router)
    }

    pub(super) fn allows_service(&self, service: &str) -> bool {
        let active = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !active.labels.enforced || active.labels.services.contains(service)
    }

    pub(super) fn allows_middleware(&self, middleware: &str) -> bool {
        let active = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !active.labels.enforced || active.labels.middlewares.contains(middleware)
    }

    pub(super) fn allows_backend(&self, backend: &str) -> bool {
        let active = self
            .active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        active.labels.allows_backend(backend)
    }

    pub(super) fn label_budget(&self) -> MetricLabelBudget {
        self.active
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .labels
            .clone()
    }
}

#[derive(Clone)]
pub(crate) struct PreparedTelemetry(Arc<TelemetryTopology>);

#[derive(Default)]
struct TelemetryTopology {
    services: BTreeMap<String, ServiceSource>,
    labels: MetricLabelBudget,
}

#[derive(Clone, Default)]
pub(super) struct MetricLabelBudget {
    pub(super) enforced: bool,
    pub(super) routers: BTreeSet<String>,
    pub(super) services: BTreeSet<String>,
    pub(super) middlewares: BTreeSet<String>,
    pub(super) backends: BTreeSet<String>,
    dynamic_backend_slots: BTreeMap<String, u32>,
}

impl MetricLabelBudget {
    pub(super) fn allows_backend(&self, backend: &str) -> bool {
        !self.enforced
            || self.backends.contains(backend)
            || self.dynamic_backend_slots.iter().any(|(prefix, limit)| {
                backend
                    .strip_prefix(prefix)
                    .and_then(|slot| slot.parse::<u32>().ok())
                    .is_some_and(|slot| slot < *limit)
            })
    }
}

struct ServiceSource {
    statistics: Arc<ServiceStatistics>,
    queue: Option<Arc<crate::scaling::buffer::RequestBuffer>>,
    load_balancer: Arc<LoadBalancer>,
    revision_backends: BTreeMap<String, Arc<Backend>>,
}

impl ServiceSource {
    fn backends(&self) -> BTreeMap<String, Arc<Backend>> {
        let mut backends = self.revision_backends.clone();
        for backend in self.load_balancer.backends().iter() {
            backends.insert(backend.metric_id().to_string(), backend.clone());
        }
        backends
    }
}

struct ServiceStatistics {
    active_requests: AtomicU64,
    request_duration: DurationHistogram,
    ttft: DurationHistogram,
}

impl ServiceStatistics {
    fn new() -> Self {
        Self {
            active_requests: AtomicU64::new(0),
            request_duration: DurationHistogram::new(),
            ttft: DurationHistogram::new(),
        }
    }
}

struct DurationHistogram {
    buckets: Box<[AtomicU64]>,
    count: AtomicU64,
    sum_microseconds: AtomicU64,
    observed_at_unix_millis: AtomicU64,
}

impl DurationHistogram {
    fn new() -> Self {
        Self {
            buckets: (0..HISTOGRAM_BUCKETS.len())
                .map(|_| AtomicU64::new(0))
                .collect(),
            count: AtomicU64::new(0),
            sum_microseconds: AtomicU64::new(0),
            observed_at_unix_millis: AtomicU64::new(0),
        }
    }

    fn observe(&self, duration: Duration) {
        let microseconds = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX);
        for ((upper_bound, _), count) in HISTOGRAM_BUCKETS.iter().zip(self.buckets.iter()) {
            if microseconds <= *upper_bound {
                count.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum_microseconds
            .fetch_add(microseconds, Ordering::Relaxed);
        self.observed_at_unix_millis
            .store(unix_millis(), Ordering::Release);
    }

    fn reset(&self) {
        for bucket in self.buckets.iter() {
            bucket.store(0, Ordering::Relaxed);
        }
        self.count.store(0, Ordering::Relaxed);
        self.sum_microseconds.store(0, Ordering::Relaxed);
        self.observed_at_unix_millis.store(0, Ordering::Release);
    }
}

/// Drop-safe service request accounting and latency observation.
pub(crate) struct ServiceRequestGuard {
    topology: Arc<TelemetryTopology>,
    statistics: Option<Arc<ServiceStatistics>>,
    started_at: Instant,
    ttft_recorded: bool,
}

impl ServiceRequestGuard {
    fn new(topology: Arc<TelemetryTopology>, service: &str, started_at: Instant) -> Option<Self> {
        let statistics = topology.services.get(service)?.statistics.clone();
        statistics.active_requests.fetch_add(1, Ordering::Relaxed);
        Some(Self {
            topology,
            statistics: Some(statistics),
            started_at,
            ttft_recorded: false,
        })
    }

    /// Observe TTFT at most once for the first non-empty response chunk.
    pub(crate) fn record_ttft_once(&mut self) {
        if self.ttft_recorded {
            return;
        }
        if let Some(statistics) = self.statistics.as_ref() {
            statistics.ttft.observe(self.started_at.elapsed());
            self.ttft_recorded = true;
        }
    }

    /// Finish the current service attempt and begin accounting for a fallback.
    pub(crate) fn retarget(&mut self, service: &str) -> bool {
        let Some(next) = self
            .topology
            .services
            .get(service)
            .map(|source| source.statistics.clone())
        else {
            return false;
        };
        self.finish();
        next.active_requests.fetch_add(1, Ordering::Relaxed);
        self.statistics = Some(next);
        self.started_at = Instant::now();
        self.ttft_recorded = false;
        true
    }

    fn finish(&mut self) {
        if let Some(statistics) = self.statistics.take() {
            statistics.active_requests.fetch_sub(1, Ordering::Relaxed);
            statistics
                .request_duration
                .observe(self.started_at.elapsed());
        }
    }
}

impl Drop for ServiceRequestGuard {
    fn drop(&mut self) {
        self.finish();
    }
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub(super) fn opaque_backend_id(locator: &str) -> String {
    let safe_origin = url::Url::parse(locator)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| "invalid-backend-origin".to_string());
    let mut identity = Sha256::new();
    identity.update(b"gateway-backend-telemetry-v1");
    identity.update([0]);
    identity.update(safe_origin.as_bytes());
    format!("b_{:x}", identity.finalize())
}
