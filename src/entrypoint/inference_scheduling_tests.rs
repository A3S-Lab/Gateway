use super::inference_tests::{
    gateway_state, inference_config, inference_key, read_http_request, spawn_blocking_backend,
    spawn_capturing_backend, start_test_entrypoint, stop_test_entrypoint,
};
use crate::config::{
    GatewayConfig, InferenceLimitsConfig, InferencePhaseRole, InferenceSchedulingConfig,
    InferenceTransferHealth, InferenceWorkerConfig, ManagedTargetConfig, ServerConfig,
    POWER_WORKER_OBSERVATION_SCHEMA,
};
use chrono::{Duration as ChronoDuration, Utc};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use uuid::Uuid;

fn set_limits(config: &mut GatewayConfig, limits: InferenceLimitsConfig) {
    let policy = config.inference.as_mut().expect("inference policy");
    let route = policy.routes.values_mut().next().expect("inference route");
    let grant = route.grants.values_mut().next().expect("inference grant");
    grant.limits = limits;
}

pub(super) fn enable_worker_scheduling(
    config: &mut GatewayConfig,
    workers: &[(SocketAddr, &str, u64, u64)],
    max_concurrent_requests: u64,
    max_queued_requests: u64,
    queue_timeout_ms: u64,
) {
    let policy = config.inference.as_mut().expect("inference policy");
    let route = policy.routes.values_mut().next().expect("inference route");
    let model = route
        .models
        .get_mut("allowed-model")
        .expect("allowed model");
    let target_id = model.targets[0].target_id;
    model.scheduling = Some(InferenceSchedulingConfig {
        phase: InferencePhaseRole::Aggregated,
        max_concurrent_requests,
        max_queued_requests,
        queue_timeout_ms,
        prompt_cache_affinity: true,
        distributed_serving: None,
    });

    let observed_at = Utc::now();
    let expires_at = observed_at + ChronoDuration::seconds(15);
    let servers = workers
        .iter()
        .enumerate()
        .map(|(index, (address, unit_id, active, waiting))| {
            let target = ManagedTargetConfig {
                target_id,
                unit_id: (*unit_id).to_string(),
                generation: 5,
            };
            let index_u128 = u128::try_from(index).unwrap();
            let index_u64 = u64::try_from(index).unwrap();
            policy.workers.insert(
                (*unit_id).to_string(),
                InferenceWorkerConfig {
                    target: target.clone(),
                    schema: POWER_WORKER_OBSERVATION_SCHEMA.to_string(),
                    worker_epoch: Uuid::from_u128(100 + index_u128),
                    execution_profile_sha256: None,
                    observation_generation: 9,
                    observed_at,
                    expires_at,
                    phases: vec![InferencePhaseRole::Aggregated],
                    prompt_cache_capable: true,
                    state_transfer_capable: false,
                    ready_phases: vec![InferencePhaseRole::Aggregated],
                    active_limit: Some(10),
                    active: *active,
                    waiting: *waiting,
                    prompt_cache_supported: true,
                    prompt_cache_entries: 1,
                    prompt_cache_capacity: 4,
                    prompt_cache_pressure_basis_points: 2_500,
                    transfer_health: InferenceTransferHealth::Unsupported,
                    certified_latency_ms: Some(20 + index_u64),
                },
            );
            ServerConfig {
                url: format!("http://{address}"),
                weight: 1,
                target: Some(target),
            }
        })
        .collect();
    config
        .services
        .get_mut("model-service")
        .expect("model service")
        .load_balancer
        .servers = servers;
}

async fn spawn_failing_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_http_request(&mut stream).await;
        let _ = request_tx.send(());
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

#[tokio::test]
async fn managed_inference_selects_the_eligible_worker_and_forwards_only_scoped_cache_affinity() {
    let key = inference_key('a');
    let (pressured, pressured_request) = spawn_capturing_backend().await;
    let (available, available_request) = spawn_capturing_backend().await;
    let mut config = inference_config(pressured, &key, Utc::now() + ChronoDuration::hours(1));
    enable_worker_scheduling(
        &mut config,
        &[(pressured, "power-a", 9, 1), (available, "power-b", 1, 0)],
        8,
        8,
        500,
    );
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","prompt_cache_key":"private-session","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let request = tokio::time::timeout(Duration::from_secs(2), available_request)
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), pressured_request)
            .await
            .is_err()
    );
    let body_offset = request
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .unwrap()
        + 4;
    let routed: serde_json::Value = serde_json::from_slice(&request[body_offset..]).unwrap();
    let scoped = routed["prompt_cache_key"].as_str().unwrap();
    assert!(scoped.starts_with("a3s-gw-pcache-v1:"));
    assert!(!scoped.contains("private-session"));
    assert_eq!(routed["model"], "internal-allowed-model");

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_pool_rejects_when_its_bounded_queue_is_disabled() {
    let key = inference_key('a');
    let (backend, request_started, release_request) = spawn_blocking_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 3,
            requests_per_minute: 600,
            request_burst: 3,
            tokens_per_minute: 10_000,
        },
    );
    enable_worker_scheduling(&mut config, &[(backend, "power-a", 0, 0)], 1, 0, 500);
    config
        .services
        .get_mut("model-service")
        .unwrap()
        .load_balancer
        .request_timeout = "5s".into();
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();
    let first_client = client.clone();
    let first_key = key.clone();
    let first = tokio::spawn(async move {
        first_client
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(first_key)
            .header("content-type", "application/json")
            .body(r#"{"model":"allowed-model","messages":[]}"#)
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), request_started)
        .await
        .unwrap()
        .unwrap();

    let rejected = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 429);
    assert_eq!(
        rejected.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "pool_queue_full"
    );

    release_request.send(()).unwrap();
    assert_eq!(first.await.unwrap().status(), 200);
    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_retries_another_worker_within_the_same_target_generation() {
    let key = inference_key('a');
    let (failing, failed_request) = spawn_failing_backend().await;
    let (healthy, healthy_request) = spawn_capturing_backend().await;
    let mut config = inference_config(failing, &key, Utc::now() + ChronoDuration::hours(1));
    enable_worker_scheduling(
        &mut config,
        &[(failing, "power-a", 0, 0), (healthy, "power-b", 2, 0)],
        8,
        8,
        500,
    );
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    tokio::time::timeout(Duration::from_secs(2), failed_request)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), healthy_request)
        .await
        .unwrap()
        .unwrap();

    stop_test_entrypoint(shutdown_tx, handle).await;
}
