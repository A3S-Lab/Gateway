//! Autoscaler — periodic decision engine that monitors metrics and emits scale decisions
//!
//! Implements a Knative-style autoscaling formula:
//! `desired = ceil((in_flight + queue_depth) / (container_concurrency * target_utilization))`
//! clamped to `[min_replicas, max_replicas]`.

use crate::config::ScalingConfig;
use crate::error::Result;
use crate::scaling::executor::{ScaleDecision, ScaleDirection, ScaleExecutor};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_EXECUTOR_TIMEOUT: Duration = Duration::from_secs(5);

/// A snapshot of metrics for a single service
#[derive(Debug, Clone)]
pub struct ServiceMetricsSnapshot {
    /// Service name
    pub service: String,
    /// Number of healthy backends
    #[allow(dead_code)]
    pub healthy_backends: usize,
    /// Total in-flight requests across all backends
    pub in_flight: usize,
    /// Requests waiting in the buffer (scale-from-zero)
    pub queue_depth: usize,
}

/// Per-service autoscaler state
struct ServiceScaleState {
    /// Scaling configuration
    config: ScalingConfig,
    /// Last time a request was observed for this service
    last_request_at: Instant,
    /// Last accepted or initially observed replica count
    current_replicas: Option<u32>,
}

/// Autoscaler that periodically evaluates metrics and executes scaling decisions
pub struct Autoscaler {
    /// Scale executor
    executor: Arc<dyn ScaleExecutor>,
    /// Per-service state
    services: HashMap<String, ServiceScaleState>,
    /// Maximum time allowed for one executor operation
    executor_timeout: Duration,
}

impl Autoscaler {
    /// Create a new autoscaler with the given executor and service configs
    pub fn new(executor: Arc<dyn ScaleExecutor>, configs: HashMap<String, ScalingConfig>) -> Self {
        let now = Instant::now();
        let services = configs
            .into_iter()
            .map(|(name, config)| {
                let state = ServiceScaleState {
                    config,
                    last_request_at: now,
                    current_replicas: None,
                };
                (name, state)
            })
            .collect();

        Self {
            executor,
            services,
            executor_timeout: DEFAULT_EXECUTOR_TIMEOUT,
        }
    }

    /// Compute the desired replica count using the Knative formula.
    ///
    /// `desired = ceil((in_flight + queue_depth) / (cc * utilization))`
    /// clamped to `[min, max]`.
    ///
    /// Special cases:
    /// - `cc == 0` (unlimited): returns current replicas (no autoscaling decision)
    /// - `in_flight + queue_depth == 0` and past cooldown: returns `min_replicas`
    pub fn compute_desired_replicas(
        config: &ScalingConfig,
        snapshot: &ServiceMetricsSnapshot,
    ) -> u32 {
        let cc = config.container_concurrency;
        if cc == 0 {
            // Unlimited concurrency — no autoscaling signal from concurrency
            return config.min_replicas.max(1);
        }

        let total_load = (snapshot.in_flight + snapshot.queue_depth) as f64;
        if total_load == 0.0 {
            return config.min_replicas;
        }

        let effective_capacity = cc as f64 * config.target_utilization;
        if effective_capacity <= 0.0 {
            return config.max_replicas;
        }

        let desired = (total_load / effective_capacity).ceil() as u32;
        desired.clamp(config.min_replicas, config.max_replicas)
    }

    /// Evaluate a metrics snapshot and return a scaling decision if needed.
    ///
    /// Returns `None` if no scaling action is required (desired == current,
    /// or scale-down is blocked by cooldown).
    pub fn evaluate(&mut self, snapshot: &ServiceMetricsSnapshot) -> Option<ScaleDecision> {
        let state = self.services.get_mut(&snapshot.service)?;

        // Update last_request_at if there's active load
        if snapshot.in_flight > 0 || snapshot.queue_depth > 0 {
            state.last_request_at = Instant::now();
        }

        let desired = Self::compute_desired_replicas(&state.config, snapshot);
        let current = *state
            .current_replicas
            .get_or_insert(snapshot.healthy_backends as u32);

        if desired == current {
            return None;
        }

        // Scale-down cooldown: only scale down if enough time has passed since last request
        if desired < current {
            let elapsed = state.last_request_at.elapsed().as_secs();
            if elapsed < state.config.scale_down_delay_secs {
                return None;
            }
        }

        let direction = if desired > current {
            ScaleDirection::Up
        } else {
            ScaleDirection::Down
        };

        let reason = format!(
            "{}: in_flight={}, queue={}, cc={}, util={:.0}%, current={}, desired={}",
            direction,
            snapshot.in_flight,
            snapshot.queue_depth,
            state.config.container_concurrency,
            state.config.target_utilization * 100.0,
            current,
            desired,
        );

        Some(ScaleDecision {
            service: snapshot.service.clone(),
            direction,
            current_replicas: current,
            desired_replicas: desired,
            reason,
        })
    }

    /// Execute a single evaluation cycle for all services using the provided metrics function.
    pub async fn tick<F>(&mut self, metrics_fn: F) -> Vec<Result<()>>
    where
        F: Fn(&str) -> Option<ServiceMetricsSnapshot>,
    {
        let service_names: Vec<String> = self.services.keys().cloned().collect();
        let mut results = Vec::new();

        for name in &service_names {
            if let Some(snapshot) = metrics_fn(name) {
                if let Some(decision) = self.evaluate(&snapshot) {
                    tracing::info!(
                        service = decision.service,
                        direction = %decision.direction,
                        from = decision.current_replicas,
                        to = decision.desired_replicas,
                        reason = decision.reason,
                        "Autoscaler decision"
                    );
                    let execution = tokio::time::timeout(
                        self.executor_timeout,
                        self.executor.execute(&decision),
                    )
                    .await;
                    let result = match execution {
                        Ok(Ok(result)) if result.accepted => {
                            self.set_current_replicas(&decision.service, result.actual_replicas);
                            Ok(())
                        }
                        Ok(Ok(result)) => Err(crate::error::GatewayError::Scaling(format!(
                            "Autoscaler executor rejected service '{}': {}",
                            decision.service, result.message
                        ))),
                        Ok(Err(error)) => Err(error),
                        Err(_) => Err(crate::error::GatewayError::Scaling(format!(
                            "Autoscaler executor timed out after {} ms for service '{}'",
                            self.executor_timeout.as_millis(),
                            decision.service
                        ))),
                    };
                    results.push(result);
                }
            }
        }

        results
    }

    /// Get the executor reference
    #[allow(dead_code)]
    pub fn executor(&self) -> &Arc<dyn ScaleExecutor> {
        &self.executor
    }

    /// Check if a service is registered with the autoscaler
    #[allow(dead_code)]
    pub fn has_service(&self, name: &str) -> bool {
        self.services.contains_key(name)
    }

    /// Number of services being autoscaled
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Update the current replica count for a service (e.g., after querying the executor)
    #[allow(dead_code)]
    pub fn set_current_replicas(&mut self, service: &str, replicas: u32) {
        if let Some(state) = self.services.get_mut(service) {
            state.current_replicas = Some(replicas);
        }
    }

    #[cfg(test)]
    fn set_executor_timeout(&mut self, timeout: Duration) {
        self.executor_timeout = timeout;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GatewayError;
    use crate::scaling::executor::{MockScaleExecutor, ScaleResult};
    use async_trait::async_trait;
    use std::sync::Mutex;

    struct FailingScaleExecutor {
        decisions: Mutex<Vec<ScaleDecision>>,
    }

    impl FailingScaleExecutor {
        fn new() -> Self {
            Self {
                decisions: Mutex::new(Vec::new()),
            }
        }

        fn decisions(&self) -> Vec<ScaleDecision> {
            self.decisions.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ScaleExecutor for FailingScaleExecutor {
        async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
            self.decisions.lock().unwrap().push(decision.clone());
            Err(GatewayError::Scaling("executor unavailable".to_string()))
        }

        async fn current_replicas(&self, _service: &str) -> Result<u32> {
            Ok(0)
        }

        fn name(&self) -> &str {
            "failing"
        }
    }

    struct HangingScaleExecutor;

    #[async_trait]
    impl ScaleExecutor for HangingScaleExecutor {
        async fn execute(&self, _decision: &ScaleDecision) -> Result<ScaleResult> {
            std::future::pending().await
        }

        async fn current_replicas(&self, _service: &str) -> Result<u32> {
            Ok(0)
        }

        fn name(&self) -> &str {
            "hanging"
        }
    }

    fn default_config() -> ScalingConfig {
        ScalingConfig {
            min_replicas: 0,
            max_replicas: 10,
            container_concurrency: 10,
            target_utilization: 0.7,
            scale_down_delay_secs: 300,
            ..ScalingConfig::default()
        }
    }

    fn snapshot(service: &str, in_flight: usize, queue_depth: usize) -> ServiceMetricsSnapshot {
        ServiceMetricsSnapshot {
            service: service.into(),
            healthy_backends: 2,
            in_flight,
            queue_depth,
        }
    }

    // --- compute_desired_replicas ---

    #[test]
    fn test_formula_basic() {
        let config = default_config();
        // 10 in-flight, cc=10, util=0.7 → ceil(10 / 7.0) = ceil(1.43) = 2
        let snap = snapshot("svc", 10, 0);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 2);
    }

    #[test]
    fn test_formula_includes_queue_depth() {
        let config = default_config();
        // 5 in-flight + 5 queue = 10, cc=10, util=0.7 → ceil(10/7) = 2
        let snap = snapshot("svc", 5, 5);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 2);
    }

    #[test]
    fn test_formula_high_load() {
        let config = default_config();
        // 70 in-flight, cc=10, util=0.7 → ceil(70/7) = 10
        let snap = snapshot("svc", 70, 0);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 10);
    }

    #[test]
    fn test_formula_clamped_to_max() {
        let config = default_config();
        // 100 in-flight, cc=10, util=0.7 → ceil(100/7) = 15, clamped to 10
        let snap = snapshot("svc", 100, 0);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 10);
    }

    #[test]
    fn test_formula_clamped_to_min() {
        let config = ScalingConfig {
            min_replicas: 2,
            ..default_config()
        };
        // 1 in-flight, cc=10, util=0.7 → ceil(1/7) = 1, clamped to min=2
        let snap = snapshot("svc", 1, 0);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 2);
    }

    #[test]
    fn test_formula_zero_load_returns_min() {
        let config = default_config();
        let snap = snapshot("svc", 0, 0);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 0);
    }

    #[test]
    fn test_formula_zero_load_with_min() {
        let config = ScalingConfig {
            min_replicas: 1,
            ..default_config()
        };
        let snap = snapshot("svc", 0, 0);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 1);
    }

    #[test]
    fn test_formula_cc_zero_unlimited() {
        let config = ScalingConfig {
            container_concurrency: 0,
            min_replicas: 1,
            ..default_config()
        };
        let snap = snapshot("svc", 50, 0);
        // cc=0 means unlimited, returns max(min_replicas, 1)
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 1);
    }

    #[test]
    fn test_formula_utilization_100_percent() {
        let config = ScalingConfig {
            target_utilization: 1.0,
            ..default_config()
        };
        // 10 in-flight, cc=10, util=1.0 → ceil(10/10) = 1
        let snap = snapshot("svc", 10, 0);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 1);
    }

    #[test]
    fn test_formula_zero_utilization_returns_max() {
        let config = ScalingConfig {
            target_utilization: 0.0,
            ..default_config()
        };
        // cc=10, util=0.0 → effective_capacity=0 → returns max_replicas
        let snap = snapshot("svc", 10, 0);
        assert_eq!(Autoscaler::compute_desired_replicas(&config, &snap), 10);
    }

    // --- evaluate ---

    #[test]
    fn test_evaluate_scale_up() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock, configs);

        let snap = snapshot("svc", 20, 0);
        let decision = autoscaler.evaluate(&snap).unwrap();
        assert_eq!(decision.direction, ScaleDirection::Up);
        assert_eq!(decision.current_replicas, 2);
        assert_eq!(decision.desired_replicas, 3); // ceil(20/7) = 3
    }

    #[test]
    fn test_evaluate_no_change() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock, configs);

        // Set current to match desired
        autoscaler.set_current_replicas("svc", 3);
        // 20 in-flight → desired=3, current=3 → no change
        let snap = snapshot("svc", 20, 0);
        assert!(autoscaler.evaluate(&snap).is_none());
    }

    #[test]
    fn test_evaluate_scale_down_blocked_by_cooldown() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock, configs);

        // Set current replicas high
        autoscaler.set_current_replicas("svc", 5);

        // Zero load → desired=0, but cooldown blocks it (last_request_at is recent)
        let snap = snapshot("svc", 0, 0);
        assert!(autoscaler.evaluate(&snap).is_none());
    }

    #[test]
    fn test_evaluate_unknown_service() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut autoscaler = Autoscaler::new(mock, HashMap::new());

        let snap = snapshot("unknown", 10, 0);
        assert!(autoscaler.evaluate(&snap).is_none());
    }

    #[test]
    fn test_evaluate_reason_formatting() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock, configs);

        let snap = snapshot("svc", 15, 5);
        let decision = autoscaler.evaluate(&snap).unwrap();
        assert!(decision.reason.contains("in_flight=15"));
        assert!(decision.reason.contains("queue=5"));
        assert!(decision.reason.contains("cc=10"));
    }

    // --- tick ---

    #[tokio::test]
    async fn test_tick_executes_decisions() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock.clone(), configs);

        let results = autoscaler
            .tick(|name| {
                if name == "svc" {
                    Some(snapshot("svc", 20, 0))
                } else {
                    None
                }
            })
            .await;

        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
        assert_eq!(mock.decisions().len(), 1);

        let results = autoscaler.tick(|_| Some(snapshot("svc", 20, 0))).await;
        assert!(results.is_empty());
        assert_eq!(mock.decisions().len(), 1);
    }

    #[tokio::test]
    async fn test_failed_execution_retries_without_advancing_replica_state() {
        let executor = Arc::new(FailingScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(executor.clone(), configs);

        for _ in 0..2 {
            let results = autoscaler.tick(|_| Some(snapshot("svc", 20, 0))).await;
            assert_eq!(results.len(), 1);
            assert!(results[0].is_err());
        }

        let decisions = executor.decisions();
        assert_eq!(decisions.len(), 2);
        assert!(decisions
            .iter()
            .all(|decision| decision.current_replicas == 2));
        assert!(decisions
            .iter()
            .all(|decision| decision.desired_replicas == 3));
    }

    #[tokio::test]
    async fn test_executor_call_is_bounded_by_timeout() {
        let executor = Arc::new(HangingScaleExecutor);
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(executor, configs);
        autoscaler.set_executor_timeout(Duration::from_millis(1));

        let results = autoscaler.tick(|_| Some(snapshot("svc", 20, 0))).await;

        assert_eq!(results.len(), 1);
        let error = results[0].as_ref().unwrap_err().to_string();
        assert!(error.contains("timed out"));
    }

    #[tokio::test]
    async fn test_tick_no_metrics_no_decision() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock.clone(), configs);

        let results = autoscaler.tick(|_| None).await;
        assert!(results.is_empty());
        assert!(mock.decisions().is_empty());
    }

    // --- Autoscaler::new ---

    #[test]
    fn test_autoscaler_new() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc1".into(), default_config());
        configs.insert("svc2".into(), default_config());
        let autoscaler = Autoscaler::new(mock, configs);
        assert_eq!(autoscaler.service_count(), 2);
        assert!(autoscaler.has_service("svc1"));
        assert!(autoscaler.has_service("svc2"));
    }

    #[test]
    fn test_autoscaler_empty() {
        let mock = Arc::new(MockScaleExecutor::new());
        let autoscaler = Autoscaler::new(mock, HashMap::new());
        assert_eq!(autoscaler.service_count(), 0);
    }

    // --- evaluate: additional edge cases ---

    #[test]
    fn test_evaluate_scale_down_allowed_after_cooldown() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert(
            "svc".into(),
            ScalingConfig {
                scale_down_delay_secs: 0, // no cooldown
                ..default_config()
            },
        );
        let mut autoscaler = Autoscaler::new(mock, configs);

        // Set current replicas high
        autoscaler.set_current_replicas("svc", 5);

        // Zero load → desired=0, should scale down immediately
        let snap = snapshot("svc", 0, 0);
        let decision = autoscaler.evaluate(&snap).unwrap();
        assert_eq!(decision.direction, ScaleDirection::Down);
        assert_eq!(decision.desired_replicas, 0);
    }

    #[test]
    fn test_evaluate_does_not_advance_before_executor_accepts() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock, configs);

        let snap = snapshot("svc", 20, 0);
        let first = autoscaler.evaluate(&snap).unwrap();
        let second = autoscaler.evaluate(&snap).unwrap();

        assert_eq!(first.current_replicas, 2);
        assert_eq!(first.desired_replicas, 3);
        assert_eq!(second.current_replicas, 2);
        assert_eq!(second.desired_replicas, 3);
    }

    // --- construction ---

    #[test]
    fn test_autoscaler_has_service() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("api".into(), default_config());
        let autoscaler = Autoscaler::new(mock, configs);

        assert!(autoscaler.has_service("api"));
        assert!(!autoscaler.has_service("web"));
        assert_eq!(autoscaler.service_count(), 1);
    }

    #[test]
    fn test_autoscaler_executor_name() {
        let mock = Arc::new(MockScaleExecutor::new());
        let autoscaler = Autoscaler::new(mock, HashMap::new());
        assert_eq!(autoscaler.executor().name(), "mock");
    }
}
