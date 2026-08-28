use super::inference_distributed_tests::{
    enable_distributed_scheduling, spawn_successful_power_pair, API_KEY, KEY_ENV,
};
use super::inference_tests::{
    gateway_state_with_distributed_key, inference_config, inference_key, read_http_request,
    start_test_entrypoint, stop_test_entrypoint,
};
use crate::config::{
    GatewayConfig, InferencePhaseRole, InferenceTransferHealth, InferenceWorkerConfig,
    ManagedTargetConfig, ServerConfig, POWER_WORKER_OBSERVATION_SCHEMA,
};
use chrono::{Duration as ChronoDuration, Utc};
use http::StatusCode;
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use uuid::Uuid;

async fn spawn_connection_closer(
    expected_requests: usize,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        for _ in 0..expected_requests {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_http_request(&mut stream).await;
            stream.shutdown().await.unwrap();
        }
    });
    (address, task)
}

fn add_preferred_failing_pair(
    config: &mut GatewayConfig,
    prefill_address: SocketAddr,
    decode_address: SocketAddr,
) {
    let policy = config.inference.as_mut().expect("inference policy");
    let target_id =
        policy.routes.values().next().unwrap().models["allowed-model"].targets[0].target_id;
    for worker in policy.workers.values_mut() {
        worker.active = 2;
    }
    let specs = [
        (
            "power-prefill-failing",
            prefill_address,
            InferencePhaseRole::Prefill,
            Uuid::from_u128(201),
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        (
            "power-decode-failing",
            decode_address,
            InferencePhaseRole::Decode,
            Uuid::from_u128(202),
            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        ),
    ];
    let observed_at = Utc::now();
    let expires_at = observed_at + ChronoDuration::seconds(30);
    for (unit_id, address, phase, worker_epoch, profile) in specs.into_iter().rev() {
        let target = ManagedTargetConfig {
            target_id,
            unit_id: unit_id.to_string(),
            generation: 5,
        };
        policy.workers.insert(
            unit_id.to_string(),
            InferenceWorkerConfig {
                target: target.clone(),
                schema: POWER_WORKER_OBSERVATION_SCHEMA.to_string(),
                worker_epoch,
                execution_profile_sha256: Some(profile.to_string()),
                observation_generation: 10,
                observed_at,
                expires_at,
                phases: vec![phase],
                prompt_cache_capable: false,
                state_transfer_capable: true,
                ready_phases: vec![phase],
                active_limit: Some(8),
                active: 0,
                waiting: 0,
                prompt_cache_supported: false,
                prompt_cache_entries: 0,
                prompt_cache_capacity: 0,
                prompt_cache_pressure_basis_points: 0,
                transfer_health: InferenceTransferHealth::Ready,
                certified_latency_ms: Some(5),
            },
        );
        config
            .services
            .get_mut("model-service")
            .unwrap()
            .load_balancer
            .servers
            .insert(
                0,
                ServerConfig {
                    url: format!("http://{address}"),
                    weight: 1,
                    target: Some(target),
                },
            );
    }
}

#[tokio::test]
async fn pre_response_transport_failure_reselects_a_distinct_worker_pair() {
    let key = inference_key('c');
    let (backup_prefill, backup_decode, backup_prefill_task, backup_decode_task) =
        spawn_successful_power_pair().await;
    let (failing_prefill, failing_prefill_task) = spawn_connection_closer(1).await;
    let (failing_decode, failing_decode_task) = spawn_connection_closer(2).await;
    let mut config = inference_config(backup_decode, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, backup_prefill, backup_decode);
    add_preferred_failing_pair(&mut config, failing_prefill, failing_decode);
    config.validate().unwrap();
    let state = gateway_state_with_distributed_key(&config, KEY_ENV, API_KEY);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.json::<Value>().await.unwrap()["choices"][0]["message"]["content"],
        "entrypoint P/D response"
    );

    for task in [
        failing_prefill_task,
        failing_decode_task,
        backup_prefill_task,
        backup_decode_task,
    ] {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}
