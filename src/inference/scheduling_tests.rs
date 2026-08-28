use super::*;
use crate::config::{
    InferenceModelConfig, InferencePhaseRole, InferenceRouteConfig, InferenceTargetConfig,
    InferenceTransferHealth,
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
    }
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
}
