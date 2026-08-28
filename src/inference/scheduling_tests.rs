use super::*;
use crate::config::{
    InferenceDistributedServingConfig, InferenceModelConfig, InferencePhaseRole,
    InferenceRouteConfig, InferenceTargetConfig, InferenceTransferHealth,
};

fn target(unit_id: &str, generation: u64) -> ManagedTargetConfig {
    ManagedTargetConfig {
        target_id: Uuid::from_u128(1),
        unit_id: unit_id.to_string(),
        generation,
    }
}

fn worker(target: ManagedTargetConfig, active: u64, waiting: u64) -> InferenceWorkerConfig {
    let observed_at = Utc::now();
    InferenceWorkerConfig {
        target,
        schema: POWER_WORKER_OBSERVATION_SCHEMA.to_string(),
        worker_epoch: Uuid::new_v4(),
        execution_profile_sha256: None,
        observation_generation: 1,
        observed_at,
        expires_at: observed_at + chrono::Duration::seconds(15),
        phases: vec![InferencePhaseRole::Aggregated],
        prompt_cache_capable: true,
        state_transfer_capable: false,
        ready_phases: vec![InferencePhaseRole::Aggregated],
        active_limit: Some(10),
        active,
        waiting,
        prompt_cache_supported: true,
        prompt_cache_entries: 1,
        prompt_cache_capacity: 4,
        prompt_cache_pressure_basis_points: 2_500,
        transfer_health: InferenceTransferHealth::Unsupported,
        certified_latency_ms: None,
    }
}

fn scheduling() -> InferenceSchedulingConfig {
    InferenceSchedulingConfig {
        phase: InferencePhaseRole::Aggregated,
        max_concurrent_requests: 1,
        max_queued_requests: 1,
        queue_timeout_ms: 1_000,
        prompt_cache_affinity: true,
        distributed_serving: None,
    }
}

fn distributed_scheduling() -> InferenceSchedulingConfig {
    InferenceSchedulingConfig {
        phase: InferencePhaseRole::Decode,
        max_concurrent_requests: 4,
        max_queued_requests: 8,
        queue_timeout_ms: 1_000,
        prompt_cache_affinity: true,
        distributed_serving: Some(InferenceDistributedServingConfig {
            api_key_env: "A3S_POWER_API_KEY".to_string(),
            execution_timeout_ms: 30_000,
        }),
    }
}

fn distributed_worker(
    target: ManagedTargetConfig,
    phase: InferencePhaseRole,
    active: u64,
) -> InferenceWorkerConfig {
    let mut worker = worker(target, active, 0);
    worker.execution_profile_sha256 = Some(match phase {
        InferencePhaseRole::Prefill => "a".repeat(64),
        InferencePhaseRole::Decode => "b".repeat(64),
        InferencePhaseRole::Aggregated => "c".repeat(64),
    });
    worker.phases = vec![phase];
    worker.ready_phases = vec![phase];
    worker.state_transfer_capable = true;
    worker.transfer_health = InferenceTransferHealth::Ready;
    worker
}

#[test]
fn selection_filters_exact_identity_phase_expiry_health_and_capacity() {
    let first = target("unit-a", 7);
    let second = target("unit-b", 7);
    let stale = target("unit-c", 7);
    let now = Utc::now();
    let mut workers = HashMap::from([
        (first.unit_id.clone(), worker(first.clone(), 9, 0)),
        (second.unit_id.clone(), worker(second.clone(), 2, 0)),
        (stale.unit_id.clone(), worker(stale.clone(), 0, 0)),
    ]);
    workers.get_mut(&stale.unit_id).unwrap().expires_at = now;
    let candidates = [
        InferenceWorkerCandidate {
            target: Some(&first),
            healthy: true,
            local_connections: 0,
        },
        InferenceWorkerCandidate {
            target: Some(&second),
            healthy: true,
            local_connections: 0,
        },
        InferenceWorkerCandidate {
            target: Some(&stale),
            healthy: true,
            local_connections: 0,
        },
        InferenceWorkerCandidate {
            target: None,
            healthy: true,
            local_connections: 0,
        },
    ];

    let selected = select_worker(
        &workers,
        &scheduling(),
        first.target_id,
        &candidates,
        now,
        b"request",
        None,
    )
    .unwrap();
    assert_eq!(selected.index, 1);
    assert_eq!(selected.pressure_basis_points, 2_000);
    assert!(!selected.cache_affinity_applied);
}

#[test]
fn cache_affinity_is_deterministic_inside_the_low_load_band() {
    let first = target("unit-a", 7);
    let second = target("unit-b", 7);
    let workers = HashMap::from([
        (first.unit_id.clone(), worker(first.clone(), 1, 0)),
        (second.unit_id.clone(), worker(second.clone(), 2, 0)),
    ]);
    let candidates = [
        InferenceWorkerCandidate {
            target: Some(&first),
            healthy: true,
            local_connections: 0,
        },
        InferenceWorkerCandidate {
            target: Some(&second),
            healthy: true,
            local_connections: 0,
        },
    ];

    let first_pick = select_worker(
        &workers,
        &scheduling(),
        first.target_id,
        &candidates,
        Utc::now(),
        b"request-a",
        Some("scoped-cache-key"),
    )
    .unwrap();
    let second_pick = select_worker(
        &workers,
        &scheduling(),
        first.target_id,
        &candidates,
        Utc::now(),
        b"request-b",
        Some("scoped-cache-key"),
    )
    .unwrap();
    assert_eq!(first_pick.index, second_pick.index);
    assert!(first_pick.cache_affinity_applied);
}

#[test]
fn distributed_selection_returns_distinct_prefill_and_decode_bindings() {
    let prefill_a = target("prefill-a", 7);
    let prefill_b = target("prefill-b", 7);
    let decode = target("decode-a", 7);
    let mut workers = HashMap::from([
        (
            prefill_a.unit_id.clone(),
            distributed_worker(prefill_a.clone(), InferencePhaseRole::Prefill, 2),
        ),
        (
            prefill_b.unit_id.clone(),
            distributed_worker(prefill_b.clone(), InferencePhaseRole::Prefill, 1),
        ),
        (
            decode.unit_id.clone(),
            distributed_worker(decode.clone(), InferencePhaseRole::Decode, 1),
        ),
    ]);
    workers
        .get_mut(&prefill_b.unit_id)
        .unwrap()
        .prompt_cache_entries = 0;
    workers
        .get_mut(&prefill_b.unit_id)
        .unwrap()
        .prompt_cache_pressure_basis_points = 0;
    let candidates = [
        InferenceWorkerCandidate {
            target: Some(&prefill_a),
            healthy: true,
            local_connections: 0,
        },
        InferenceWorkerCandidate {
            target: Some(&prefill_b),
            healthy: true,
            local_connections: 0,
        },
        InferenceWorkerCandidate {
            target: Some(&decode),
            healthy: true,
            local_connections: 0,
        },
    ];

    let pair = select_worker_pair(
        &workers,
        &distributed_scheduling(),
        decode.target_id,
        &candidates,
        Utc::now(),
        b"request",
        Some("a3s-gw-pcache-v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    )
    .unwrap();

    assert_eq!(pair.decode.index, 2);
    assert!(matches!(pair.decode.phase, InferencePhaseRole::Decode));
    assert!(matches!(pair.prefill.phase, InferencePhaseRole::Prefill));
    assert_ne!(pair.prefill.unit_id, pair.decode.unit_id);
    assert_eq!(pair.prefill.execution_profile_sha256, "a".repeat(64));
    assert_eq!(pair.decode.execution_profile_sha256, "b".repeat(64));
}

#[test]
fn distributed_selection_fails_closed_on_profile_transfer_or_distinctness() {
    let dual = target("dual", 7);
    let mut dual_worker = distributed_worker(dual.clone(), InferencePhaseRole::Prefill, 0);
    dual_worker.phases.push(InferencePhaseRole::Decode);
    dual_worker.ready_phases.push(InferencePhaseRole::Decode);
    let candidates = [InferenceWorkerCandidate {
        target: Some(&dual),
        healthy: true,
        local_connections: 0,
    }];
    let workers = HashMap::from([(dual.unit_id.clone(), dual_worker)]);
    assert!(select_worker_pair(
        &workers,
        &distributed_scheduling(),
        dual.target_id,
        &candidates,
        Utc::now(),
        b"request",
        None,
    )
    .is_none());

    let prefill = target("prefill", 7);
    let decode = target("decode", 7);
    let mut prefill_worker = distributed_worker(prefill.clone(), InferencePhaseRole::Prefill, 0);
    prefill_worker.execution_profile_sha256 = None;
    let mut decode_worker = distributed_worker(decode.clone(), InferencePhaseRole::Decode, 0);
    decode_worker.transfer_health = InferenceTransferHealth::Unavailable;
    let workers = HashMap::from([
        (prefill.unit_id.clone(), prefill_worker),
        (decode.unit_id.clone(), decode_worker),
    ]);
    let candidates = [
        InferenceWorkerCandidate {
            target: Some(&prefill),
            healthy: true,
            local_connections: 0,
        },
        InferenceWorkerCandidate {
            target: Some(&decode),
            healthy: true,
            local_connections: 0,
        },
    ];
    assert!(select_worker_pair(
        &workers,
        &distributed_scheduling(),
        decode.target_id,
        &candidates,
        Utc::now(),
        b"request",
        None,
    )
    .is_none());
}

fn pool_policy() -> (InferenceConfig, InferencePoolIdentity) {
    let route_id = Uuid::new_v4();
    let model_id = Uuid::new_v4();
    let identity = InferencePoolIdentity { route_id, model_id };
    (
        InferenceConfig {
            expires_at: Utc::now() + chrono::Duration::hours(1),
            credentials: HashMap::new(),
            routes: HashMap::from([(
                route_id,
                InferenceRouteConfig {
                    route_id,
                    router: "inference".into(),
                    environment_id: Uuid::new_v4(),
                    policy_revision: 1,
                    models: HashMap::from([(
                        "model".into(),
                        InferenceModelConfig {
                            model_id,
                            targets: vec![InferenceTargetConfig {
                                target_id: Uuid::new_v4(),
                                service: "service".into(),
                                upstream_model: "model".into(),
                                priority: 0,
                                weight: 1,
                            }],
                            scheduling: Some(scheduling()),
                        },
                    )]),
                    grants: HashMap::new(),
                },
            )]),
            workers: HashMap::new(),
        },
        identity,
    )
}

#[tokio::test]
async fn pool_queue_is_bounded_and_reused_across_snapshot_refresh() {
    let (policy, identity) = pool_policy();
    let scheduler = Arc::new(InferenceScheduler::new(&policy, None));
    let active = scheduler.admit(identity).await.unwrap().unwrap();

    let waiting_scheduler = scheduler.clone();
    let waiting = tokio::spawn(async move { waiting_scheduler.admit(identity).await });
    tokio::task::yield_now().await;
    assert!(matches!(
        scheduler.admit(identity).await,
        Err(InferenceAccessError::PoolQueueFull)
    ));

    let refreshed = InferenceScheduler::new(&policy, Some(&scheduler));
    assert!(matches!(
        refreshed.admit(identity).await,
        Err(InferenceAccessError::PoolQueueFull)
    ));
    drop(active);
    let admitted = waiting.await.unwrap().unwrap();
    assert!(admitted.is_some());
}

#[tokio::test]
async fn pool_queue_timeout_and_cancellation_release_capacity() {
    let (mut policy, identity) = pool_policy();
    policy
        .routes
        .get_mut(&identity.route_id)
        .unwrap()
        .models
        .get_mut("model")
        .unwrap()
        .scheduling
        .as_mut()
        .unwrap()
        .queue_timeout_ms = 20;
    let scheduler = Arc::new(InferenceScheduler::new(&policy, None));
    let active = scheduler.admit(identity).await.unwrap().unwrap();

    assert!(matches!(
        scheduler.admit(identity).await,
        Err(InferenceAccessError::PoolQueueTimeout)
    ));
    drop(active);

    policy
        .routes
        .get_mut(&identity.route_id)
        .unwrap()
        .models
        .get_mut("model")
        .unwrap()
        .scheduling
        .as_mut()
        .unwrap()
        .queue_timeout_ms = 5_000;
    let scheduler = Arc::new(InferenceScheduler::new(&policy, None));
    let active = scheduler.admit(identity).await.unwrap().unwrap();

    let waiting_scheduler = scheduler.clone();
    let waiting = tokio::spawn(async move { waiting_scheduler.admit(identity).await });
    tokio::task::yield_now().await;
    let pool = scheduler.pools.get(&identity).unwrap();
    assert_eq!(pool.queued.available_permits(), 0);
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    assert_eq!(pool.queued.available_permits(), 1);

    let next_scheduler = scheduler.clone();
    let next = tokio::spawn(async move { next_scheduler.admit(identity).await });
    tokio::task::yield_now().await;
    drop(active);
    assert!(next.await.unwrap().unwrap().is_some());
}

#[test]
fn scheduling_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<InferenceScheduler>();
    assert_send_sync::<InferencePoolAdmissionGuard>();
    assert_send_sync::<InferenceWorkerPairSelection>();
}
