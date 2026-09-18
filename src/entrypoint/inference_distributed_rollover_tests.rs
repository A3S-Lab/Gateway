use super::inference_distributed_tests::{
    enable_distributed_scheduling, spawn_releasable_holding_power_pair,
    spawn_successful_power_pair, API_KEY, KEY_ENV,
};
use super::inference_scheduling_tests::enable_worker_scheduling;
use super::inference_tests::{
    gateway_state, gateway_state_with_distributed_key, inference_config, inference_key,
    spawn_blocking_backend, spawn_holding_streaming_backend, start_test_runtime,
    stop_test_entrypoint,
};
use super::GatewayRuntime;
use chrono::{Duration as ChronoDuration, Utc};
use futures_util::StreamExt;
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

#[tokio::test]
async fn rolling_snapshot_drains_inflight_aggregated_sse_while_new_requests_use_pd_snapshot() {
    let key = inference_key('f');
    let (aggregated, aggregated_started, release_aggregated) =
        spawn_holding_streaming_backend().await;
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
    aggregated_config
        .services
        .get_mut("model-service")
        .unwrap()
        .load_balancer
        .stream_idle_timeout = "30s".to_string();
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
        let response = inflight_client
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(inflight_key)
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
            .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut body = response.bytes_stream();
        let mut collected = Vec::new();
        while let Some(chunk) = body.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        String::from_utf8(collected).unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), aggregated_started)
        .await
        .expect("aggregated SSE upstream should start before snapshot rollover")
        .unwrap();
    // Give the gateway a moment to forward the first SSE frame to the client.
    tokio::time::sleep(Duration::from_millis(50)).await;

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
    let aggregated_body = tokio::time::timeout(Duration::from_secs(2), inflight)
        .await
        .expect("inflight aggregated SSE must drain after release")
        .unwrap();
    assert!(
        aggregated_body.contains("aggregated-sse-first") && aggregated_body.contains("[DONE]"),
        "inflight aggregated SSE incomplete after rollover: {aggregated_body}"
    );

    for task in [prefill_task, decode_task] {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn rolling_snapshot_drains_inflight_pd_sse_while_new_requests_use_successor_pd_snapshot() {
    let key = inference_key('p');
    let (prefill_a, decode_a, stream_started, release_a) =
        spawn_releasable_holding_power_pair().await;
    let mut snapshot_a = inference_config(decode_a, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut snapshot_a, prefill_a, decode_a);
    snapshot_a
        .services
        .get_mut("model-service")
        .unwrap()
        .load_balancer
        .stream_idle_timeout = "30s".to_string();
    snapshot_a.validate().unwrap();

    let runtime = GatewayRuntime::new(gateway_state_with_distributed_key(
        &snapshot_a,
        KEY_ENV,
        API_KEY,
    ));
    let (address, shutdown_tx, gateway_task) = start_test_runtime(runtime.clone()).await;
    let client = reqwest::Client::new();
    let inflight_client = client.clone();
    let inflight_key = key.clone();
    let inflight = tokio::spawn(async move {
        let response = inflight_client
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(inflight_key)
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
            .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut body = response.bytes_stream();
        let mut collected = Vec::new();
        while let Some(chunk) = body.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        String::from_utf8(collected).unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .expect("snapshot-A decode stream should start before P/D rollover")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (prefill_b, decode_b, prefill_task, decode_task) = spawn_successful_power_pair().await;
    let mut snapshot_b = snapshot_a.clone();
    snapshot_b.inference.as_mut().unwrap().workers.clear();
    snapshot_b
        .inference
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap()
        .policy_revision += 1;
    enable_distributed_scheduling(&mut snapshot_b, prefill_b, decode_b);
    snapshot_b.validate().unwrap();
    runtime.replace(gateway_state_with_distributed_key(
        &snapshot_b,
        KEY_ENV,
        API_KEY,
    ));

    let successor = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(successor.status(), StatusCode::OK);
    assert_eq!(
        successor.json::<Value>().await.unwrap()["choices"][0]["message"]["content"],
        "entrypoint P/D response"
    );

    release_a.send(()).unwrap();
    let inflight_body = tokio::time::timeout(Duration::from_secs(5), inflight)
        .await
        .expect("inflight P/D SSE must drain on snapshot A after release")
        .unwrap();
    assert!(
        inflight_body.contains("pd-snapshot-a-first")
            && inflight_body.contains("pd-snapshot-a-done")
            && inflight_body.contains("[DONE]"),
        "inflight P/D SSE incomplete or rebound after rollover: {inflight_body}"
    );
    assert!(
        !inflight_body.contains("entrypoint P/D response"),
        "inflight P/D SSE must not rebind to successor snapshot workers"
    );

    for task in [prefill_task, decode_task] {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn rolling_snapshot_drains_inflight_pd_json_while_new_requests_use_successor_pd_snapshot() {
    // I0.3 §4: P/D→P/D buffered JSON must drain on snapshot A while new
    // requests admit only on the successor P/D pair (no rebind).
    let key = inference_key('j');
    let (prefill_a, decode_a, decode_started, release_a) =
        spawn_releasable_holding_power_pair().await;
    let mut snapshot_a = inference_config(decode_a, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut snapshot_a, prefill_a, decode_a);
    snapshot_a
        .services
        .get_mut("model-service")
        .unwrap()
        .load_balancer
        .request_timeout = "5s".to_string();
    snapshot_a.validate().unwrap();

    let runtime = GatewayRuntime::new(gateway_state_with_distributed_key(
        &snapshot_a,
        KEY_ENV,
        API_KEY,
    ));
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
    tokio::time::timeout(Duration::from_secs(2), decode_started)
        .await
        .expect("snapshot-A decode should start before P/D JSON rollover")
        .unwrap();

    let (prefill_b, decode_b, prefill_task, decode_task) = spawn_successful_power_pair().await;
    let mut snapshot_b = snapshot_a.clone();
    snapshot_b.inference.as_mut().unwrap().workers.clear();
    snapshot_b
        .inference
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap()
        .policy_revision += 1;
    enable_distributed_scheduling(&mut snapshot_b, prefill_b, decode_b);
    snapshot_b.validate().unwrap();
    runtime.replace(gateway_state_with_distributed_key(
        &snapshot_b,
        KEY_ENV,
        API_KEY,
    ));

    let successor = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":false}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(successor.status(), StatusCode::OK);
    assert_eq!(
        successor.json::<Value>().await.unwrap()["choices"][0]["message"]["content"],
        "entrypoint P/D response"
    );

    release_a.send(()).unwrap();
    let prior = tokio::time::timeout(Duration::from_secs(5), inflight)
        .await
        .expect("inflight P/D JSON must drain on snapshot A after release")
        .unwrap();
    assert_eq!(prior.status(), StatusCode::OK);
    let prior_body = prior.json::<Value>().await.unwrap();
    assert_eq!(
        prior_body["choices"][0]["message"]["content"], "pd-snapshot-a-firstpd-snapshot-a-done",
        "inflight buffered JSON must keep snapshot-A Power chunks: {prior_body}"
    );

    for task in [prefill_task, decode_task] {
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
    }
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}
