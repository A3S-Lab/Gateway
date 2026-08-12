mod tests {
    use super::*;
    use crate::error::GatewayError;
    use crate::scaling::executor::{MockScaleExecutor, ScaleResult};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
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

        async fn current_replicas(&self, _service: &str) -> Result<ReplicaState> {
            Ok(ReplicaState {
                replicas: 0,
                revision: None,
                ready_replicas: 0,
                endpoints: Vec::new(),
            })
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

        async fn current_replicas(&self, _service: &str) -> Result<ReplicaState> {
            Ok(ReplicaState {
                replicas: 0,
                revision: None,
                ready_replicas: 0,
                endpoints: Vec::new(),
            })
        }

        fn name(&self) -> &str {
            "hanging"
        }
    }

    struct ReplicaStateExecutor {
        replicas: AtomicU32,
        queries: AtomicUsize,
        decisions: Mutex<Vec<ScaleDecision>>,
        fail_next_after_apply: AtomicBool,
    }

    impl ReplicaStateExecutor {
        fn new(replicas: u32) -> Self {
            Self {
                replicas: AtomicU32::new(replicas),
                queries: AtomicUsize::new(0),
                decisions: Mutex::new(Vec::new()),
                fail_next_after_apply: AtomicBool::new(false),
            }
        }

        fn fail_next_after_apply(&self) {
            self.fail_next_after_apply.store(true, Ordering::SeqCst);
        }

        fn query_count(&self) -> usize {
            self.queries.load(Ordering::SeqCst)
        }

        fn decisions(&self) -> Vec<ScaleDecision> {
            self.decisions.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ScaleExecutor for ReplicaStateExecutor {
        async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
            self.decisions.lock().unwrap().push(decision.clone());
            self.replicas
                .store(decision.desired_replicas, Ordering::SeqCst);
            if self.fail_next_after_apply.swap(false, Ordering::SeqCst) {
                return Err(GatewayError::Scaling(
                    "executor response lost after apply".to_string(),
                ));
            }

            Ok(ScaleResult {
                accepted: true,
                actual_replicas: decision.desired_replicas,
                revision: Some(format!("revision-{}", decision.desired_replicas)),
                ready_replicas: decision.desired_replicas,
                endpoints: Vec::new(),
                message: "applied".to_string(),
            })
        }

        async fn current_replicas(&self, _service: &str) -> Result<ReplicaState> {
            self.queries.fetch_add(1, Ordering::SeqCst);
            let replicas = self.replicas.load(Ordering::SeqCst);
            Ok(ReplicaState {
                replicas,
                revision: Some(format!("revision-{replicas}")),
                ready_replicas: replicas,
                endpoints: Vec::new(),
            })
        }

        fn name(&self) -> &str {
            "replica-state"
        }
    }

    struct HangingReplicaQueryExecutor {
        executions: AtomicUsize,
    }

    struct OrderedDownscaleExecutor {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[derive(Clone, Copy)]
    enum DownscaleFailure {
        Rejected,
        Ambiguous,
    }

    struct FailingDownscaleExecutor {
        failure: DownscaleFailure,
    }

    #[async_trait]
    impl ScaleExecutor for FailingDownscaleExecutor {
        async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
            match self.failure {
                DownscaleFailure::Rejected => Ok(ScaleResult {
                    accepted: false,
                    actual_replicas: decision.current_replicas,
                    revision: decision.expected_revision.clone(),
                    ready_replicas: decision.current_replicas,
                    endpoints: two_scale_endpoints(),
                    message: "rejected".to_string(),
                }),
                DownscaleFailure::Ambiguous => Err(GatewayError::Scaling(
                    "response lost after mutation".to_string(),
                )),
            }
        }

        async fn current_replicas(&self, _service: &str) -> Result<ReplicaState> {
            Ok(ReplicaState {
                replicas: 2,
                revision: Some("revision-1".to_string()),
                ready_replicas: 2,
                endpoints: two_scale_endpoints(),
            })
        }

        fn name(&self) -> &str {
            "failing-downscale"
        }
    }

    fn two_scale_endpoints() -> Vec<ScaleEndpoint> {
        vec![
            ScaleEndpoint {
                instance_id: "box-api-0".to_string(),
                slot: 0,
                url: "http://127.0.0.1:18080".to_string(),
            },
            ScaleEndpoint {
                instance_id: "box-api-1".to_string(),
                slot: 1,
                url: "http://127.0.0.1:18081".to_string(),
            },
        ]
    }

    #[async_trait]
    impl ScaleExecutor for OrderedDownscaleExecutor {
        async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
            assert_eq!(decision.direction, ScaleDirection::Down);
            self.events.lock().unwrap().push("execute");
            Ok(ScaleResult {
                accepted: true,
                actual_replicas: decision.desired_replicas,
                revision: Some("revision-2".to_string()),
                ready_replicas: decision.desired_replicas,
                endpoints: two_scale_endpoints()
                    .into_iter()
                    .filter(|endpoint| endpoint.slot < decision.desired_replicas)
                    .collect(),
                message: "scaled down".to_string(),
            })
        }

        async fn current_replicas(&self, _service: &str) -> Result<ReplicaState> {
            self.events.lock().unwrap().push("observe");
            Ok(ReplicaState {
                replicas: 2,
                revision: Some("revision-1".to_string()),
                ready_replicas: 2,
                endpoints: vec![
                    ScaleEndpoint {
                        instance_id: "box-api-0".to_string(),
                        slot: 0,
                        url: "http://127.0.0.1:18080".to_string(),
                    },
                    ScaleEndpoint {
                        instance_id: "box-api-1".to_string(),
                        slot: 1,
                        url: "http://127.0.0.1:18081".to_string(),
                    },
                ],
            })
        }

        fn name(&self) -> &str {
            "ordered-downscale"
        }
    }

    #[async_trait]
    impl ScaleExecutor for HangingReplicaQueryExecutor {
        async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
            self.executions.fetch_add(1, Ordering::SeqCst);
            Ok(ScaleResult {
                accepted: true,
                actual_replicas: decision.desired_replicas,
                revision: None,
                ready_replicas: decision.desired_replicas,
                endpoints: Vec::new(),
                message: "unexpected execution".to_string(),
            })
        }

        async fn current_replicas(&self, _service: &str) -> Result<ReplicaState> {
            std::future::pending().await
        }

        fn name(&self) -> &str {
            "hanging-replica-query"
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
    fn test_evaluate_waits_for_executor_replica_observation() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock, configs);

        assert!(autoscaler.evaluate(&snapshot("svc", 20, 0)).is_none());
    }

    #[test]
    fn test_evaluate_scale_up() {
        let mock = Arc::new(MockScaleExecutor::new());
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(mock, configs);
        autoscaler.set_current_replicas("svc", 2);

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
        autoscaler.set_current_replicas("svc", 2);

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
    async fn test_tick_uses_authoritative_executor_replica_count() {
        let executor = Arc::new(ReplicaStateExecutor::new(7));
        let mut configs = HashMap::new();
        configs.insert(
            "svc".into(),
            ScalingConfig {
                scale_down_delay_secs: 0,
                ..default_config()
            },
        );
        let mut autoscaler = Autoscaler::new(executor.clone(), configs);

        let results = autoscaler.tick(|_| Some(snapshot("svc", 20, 0))).await;

        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
        assert_eq!(executor.query_count(), 1);
        let decisions = executor.decisions();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].current_replicas, 7);
        assert_eq!(decisions[0].desired_replicas, 3);
        assert_eq!(decisions[0].direction, ScaleDirection::Down);
        assert_eq!(decisions[0].schema_version, 1);
        assert_eq!(
            decisions[0].expected_revision.as_deref(),
            Some("revision-7")
        );
        assert!(decisions[0].operation_id.starts_with("scale-v1-"));
    }

    #[tokio::test]
    async fn downscale_withdraws_surplus_endpoints_before_executor_mutation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let executor = Arc::new(OrderedDownscaleExecutor {
            events: Arc::clone(&events),
        });
        let mut configs = HashMap::new();
        configs.insert(
            "svc".into(),
            ScalingConfig {
                min_replicas: 0,
                scale_down_delay_secs: 0,
                ..default_config()
            },
        );
        let mut autoscaler = Autoscaler::new(executor, configs);
        let hook_events = Arc::clone(&events);

        let results = autoscaler
            .tick_with_before_execute(
                |_| Some(snapshot("svc", 1, 0)),
                move |decision, endpoints| {
                    assert_eq!(decision.desired_replicas, 1);
                    assert_eq!(endpoints.len(), 1);
                    assert_eq!(endpoints[0].slot, 0);
                    hook_events.lock().unwrap().push("withdraw");
                    Ok(())
                },
            )
            .await;

        assert_eq!(
            &*events.lock().unwrap(),
            &["observe", "withdraw", "execute"]
        );
        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
    }

    #[tokio::test]
    async fn rejected_downscale_restores_endpoints_but_ambiguous_result_keeps_them_withdrawn() {
        for (failure, expected_endpoints) in [
            (DownscaleFailure::Rejected, 2),
            (DownscaleFailure::Ambiguous, 0),
        ] {
            let mut configs = HashMap::new();
            configs.insert(
                "svc".into(),
                ScalingConfig {
                    min_replicas: 0,
                    scale_down_delay_secs: 0,
                    ..default_config()
                },
            );
            let mut autoscaler =
                Autoscaler::new(Arc::new(FailingDownscaleExecutor { failure }), configs);

            let results = autoscaler
                .tick_with_before_execute(
                    |_| Some(snapshot("svc", 0, 0)),
                    |_, endpoints| {
                        assert!(endpoints.is_empty());
                        Ok(())
                    },
                )
                .await;

            assert_eq!(results.len(), 1);
            assert!(results[0].is_err());
            assert_eq!(
                autoscaler.endpoint_observations()[0].2.len(),
                expected_endpoints
            );
        }
    }

    #[tokio::test]
    async fn test_ambiguous_execution_reconciles_before_retry() {
        let executor = Arc::new(ReplicaStateExecutor::new(0));
        executor.fail_next_after_apply();
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(executor.clone(), configs);

        let first = autoscaler.tick(|_| Some(snapshot("svc", 20, 0))).await;
        assert_eq!(first.len(), 1);
        assert!(first[0].is_err());

        let second = autoscaler.tick(|_| Some(snapshot("svc", 20, 0))).await;
        assert!(second.is_empty());
        assert_eq!(executor.query_count(), 2);
        assert_eq!(executor.decisions().len(), 1);
    }

    #[test]
    fn operation_identity_is_stable_and_revision_bound() {
        let first = scale_operation_id("api", Some("17"), 1, 3);
        assert_eq!(first, scale_operation_id("api", Some("17"), 1, 3));
        assert_ne!(first, scale_operation_id("api", Some("18"), 1, 3));
        assert_ne!(first, scale_operation_id("api", Some("17"), 1, 4));
        assert_ne!(first, scale_operation_id("other", Some("17"), 1, 3));
    }

    #[tokio::test(start_paused = true)]
    async fn test_replica_query_is_bounded_by_executor_timeout() {
        let executor = Arc::new(HangingReplicaQueryExecutor {
            executions: AtomicUsize::new(0),
        });
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());
        let mut autoscaler = Autoscaler::new(executor.clone(), configs);
        autoscaler.set_executor_timeout(Duration::from_millis(1));

        let results = autoscaler.tick(|_| Some(snapshot("svc", 20, 0))).await;

        assert_eq!(results.len(), 1);
        let error = results[0].as_ref().unwrap_err().to_string();
        assert!(error.contains("replica query timed out"));
        assert_eq!(executor.executions.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_recreated_controller_recovers_without_duplicate_decision() {
        let executor = Arc::new(ReplicaStateExecutor::new(3));
        let mut configs = HashMap::new();
        configs.insert("svc".into(), default_config());

        for _ in 0..2 {
            let mut autoscaler = Autoscaler::new(executor.clone(), configs.clone());
            let results = autoscaler.tick(|_| Some(snapshot("svc", 20, 0))).await;
            assert!(results.is_empty());
        }

        assert_eq!(executor.query_count(), 2);
        assert!(executor.decisions().is_empty());
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
            .all(|decision| decision.current_replicas == 0));
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
        autoscaler.set_current_replicas("svc", 2);

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
