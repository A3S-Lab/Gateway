use super::inference_distributed_tests::{
    enable_distributed_scheduling, spawn_successful_power_pair, API_KEY, KEY_ENV,
};
use super::inference_scheduling_tests::enable_worker_scheduling;
use super::inference_tests::{
    gateway_state, gateway_state_with_distributed_key, inference_config, inference_key,
    spawn_blocking_backend, start_test_runtime, stop_test_entrypoint,
};
use super::GatewayRuntime;
use chrono::{Duration as ChronoDuration, Utc};
use http::StatusCode;
use serde_json::Value;
use std::time::Duration;

#[tokio::test]
async fn rolling_snapshot_moves_new_requests_to_distributed_workers_without_rebinding_inflight_v1()
{
    let key = inference_key('e');
    let (aggregated, aggregated_started, release_aggregated) = spawn_blocking_backend().await;
    let mut aggregated_config =
        inference_config(aggregated, &key, Utc::now() + ChronoDuration::hours(1));
    enable_worker_scheduling(
        &mut aggregated_config,
        &[(aggregated, "power-aggregated-v1", 0, 0)],
        8,
        8,
        500,
    );
    aggregated_config
        .services
        .get_mut("model-service")
        .unwrap()
        .load_balancer
        .request_timeout = "5s".to_string();
    aggregated_config.validate().unwrap();
    assert!(
        aggregated_config.inference.as_ref().unwrap().workers["power-aggregated-v1"]
            .execution_profile_sha256
            .is_none()
    );

    let runtime = GatewayRuntime::new(gateway_state(&aggregated_config));
    let (address, shutdown_tx, gateway_task) = start_test_runtime(runtime.clone()).await;
    let client = reqwest::Client::new();
    let inflight_client = client.clone();
    let inflight_key = key.clone();
    let inflight = tokio::spawn(async move {
        inflight_client
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(inflight_key)
            .header("content-type", "application/json")
            .body(r#"{"model":"allowed-model","messages":[],"stream":false}"#)
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), aggregated_started)
        .await
        .unwrap()
        .unwrap();

    let (prefill, decode, prefill_task, decode_task) = spawn_successful_power_pair().await;
    let mut distributed_config = aggregated_config.clone();
    distributed_config
        .inference
        .as_mut()
        .unwrap()
        .workers
        .clear();
    distributed_config
        .inference
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap()
        .policy_revision += 1;
    enable_distributed_scheduling(&mut distributed_config, prefill, decode);
    distributed_config.validate().unwrap();
    runtime.replace(gateway_state_with_distributed_key(
        &distributed_config,
        KEY_ENV,
        API_KEY,
    ));

    let distributed = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(distributed.status(), StatusCode::OK);
    assert_eq!(
        distributed.json::<Value>().await.unwrap()["choices"][0]["message"]["content"],
        "entrypoint P/D response"
    );

    release_aggregated.send(()).unwrap();
    let aggregated = inflight.await.unwrap();
    assert_eq!(aggregated.status(), StatusCode::OK);
    assert_eq!(aggregated.text().await.unwrap(), "{}");

    for task in [prefill_task, decode_task] {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}
