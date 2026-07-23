use super::inference_tests::{
    gateway_state, inference_config, inference_key, read_http_request, spawn_blocking_backend,
    spawn_capturing_backend, spawn_streaming_backend, start_test_entrypoint, stop_test_entrypoint,
};
use crate::usage::{UsageSpool, UsageSpoolOptions};
use chrono::{Duration as ChronoDuration, Utc};
use futures_util::StreamExt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub(super) async fn usage_state(
    config: &crate::config::GatewayConfig,
    directory: &std::path::Path,
    max_bytes: u64,
) -> (Arc<super::GatewayState>, Arc<UsageSpool>) {
    let spool = Arc::new(
        UsageSpool::open(UsageSpoolOptions {
            directory: directory.join("usage-spool"),
            gateway_id: config.managed.gateway_id.unwrap(),
            max_bytes,
        })
        .await
        .unwrap(),
    );
    let mut state = gateway_state(config);
    Arc::get_mut(&mut state)
        .expect("unshared Gateway test state")
        .usage_spool = Some(spool.clone());
    (state, spool)
}

pub(super) async fn lifecycle_events(spool: &UsageSpool, expected: u64) -> Vec<serde_json::Value> {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if spool.status().retained_records >= expected {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("durable usage terminal append timeout");

    spool
        .read_batch(None, usize::try_from(expected).unwrap())
        .await
        .unwrap()
        .into_iter()
        .map(|record| serde_json::from_slice(&record.payload).unwrap())
        .collect()
}

async fn spawn_repeating_idle_streaming_backend() -> (
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<()>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = tokio::sync::mpsc::unbounded_channel();
    let (disconnected_tx, disconnected_rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let started_tx = started_tx.clone();
            let disconnected_tx = disconnected_tx.clone();
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nd\r\ndata: hello\n\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = started_tx.send(());

                let mut buffer = [0_u8; 1];
                loop {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
                let _ = disconnected_tx.send(());
            });
        }
    });

    (address, started_rx, disconnected_rx)
}

#[tokio::test]
async fn managed_inference_persists_prompt_free_request_and_attempt_lifecycle() {
    const PROMPT_MARKER: &str = "prompt-must-never-enter-usage";

    let key = inference_key('u');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state(&config, directory.path(), 1024 * 1024).await;
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"model":"allowed-model","messages":[{{"role":"user","content":"{PROMPT_MARKER}"}}]}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap(), "{}");
    let _ = captured_request.await.unwrap();

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(
        events
            .iter()
            .map(|event| event["kind"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "request_started",
            "attempt_started",
            "attempt_terminal",
            "request_terminal"
        ]
    );
    assert_eq!(events[2]["outcome"], "succeeded");
    assert_eq!(events[3]["outcome"], "succeeded");
    assert_eq!(events[3]["http_status"], 200);
    assert_eq!(events[3]["measurement_completeness"], "unknown");
    assert_eq!(
        events[0]["request"]["request_id"],
        events[3]["request"]["request_id"]
    );

    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains(PROMPT_MARKER));
    assert!(!serialized.contains(&key));
    assert!(!serialized.contains("messages"));
    assert!(!serialized.contains("authorization"));

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_inference_fails_closed_before_dispatch_when_usage_capacity_is_full() {
    let key = inference_key('v');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state(&config, directory.path(), 128 * 1024).await;
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "usage_unavailable"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(150), captured_request)
            .await
            .is_err()
    );
    assert_eq!(spool.status().retained_records, 0);
    assert!(spool.status().reason.is_some());

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_sse_disconnect_persists_terminal_disconnect_outcomes() {
    let key = inference_key('w');
    let (backend, started, disconnected) = spawn_streaming_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state(&config, directory.path(), 1024 * 1024).await;
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    started.await.unwrap();
    let mut stream = response.bytes_stream();
    assert!(stream.next().await.unwrap().unwrap().starts_with(b"data:"));
    drop(stream);
    tokio::time::timeout(Duration::from_secs(2), disconnected)
        .await
        .unwrap()
        .unwrap();

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[2]["kind"], "attempt_terminal");
    assert_eq!(events[2]["outcome"], "disconnected");
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "disconnected");

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_sse_idle_timeout_releases_admission_and_persists_failed_terminals() {
    let key = inference_key('t');
    let (backend, mut started, mut disconnected) = spawn_repeating_idle_streaming_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let service = config.services.get_mut("model-service").unwrap();
    service.load_balancer.stream_idle_timeout = "25ms".into();
    service.load_balancer.stream_total_timeout = "1s".into();
    let route = config
        .inference
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap();
    route
        .grants
        .values_mut()
        .next()
        .unwrap()
        .limits
        .max_concurrent_requests = 1;
    config.validate().unwrap();

    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state(&config, directory.path(), 1024 * 1024).await;
    let selected_backend = state
        .service_registry
        .get("model-service")
        .unwrap()
        .backends()[0]
        .clone();
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();

    for _ in 0..2 {
        let response = client
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(&key)
            .header("content-type", "application/json")
            .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        started.recv().await.unwrap();
        let mut body = response.bytes_stream();
        assert!(body.next().await.unwrap().unwrap().starts_with(b"data:"));
        assert!(tokio::time::timeout(Duration::from_secs(2), body.next())
            .await
            .unwrap()
            .unwrap()
            .is_err());
        drop(body);
        tokio::time::timeout(Duration::from_secs(2), disconnected.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected_backend.connections(), 0);
    }

    let events = lifecycle_events(&spool, 8).await;
    let terminals = events
        .iter()
        .filter(|event| {
            matches!(
                event["kind"].as_str(),
                Some("attempt_terminal" | "request_terminal")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(terminals.len(), 4);
    assert!(terminals.iter().all(|event| event["outcome"] == "failed"));
    assert_eq!(spool.status().reserved_bytes, 0);

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn forced_drain_persists_terminal_cancellation_outcomes() {
    let key = inference_key('x');
    let (backend, started, release) = spawn_blocking_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    config.shutdown_timeout_secs = 0;
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state(&config, directory.path(), 1024 * 1024).await;
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let request = tokio::spawn(async move {
        reqwest::Client::new()
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(key)
            .header("content-type", "application/json")
            .body(r#"{"model":"allowed-model","messages":[]}"#)
            .send()
            .await
    });
    started.await.unwrap();
    assert_eq!(spool.status().retained_records, 2);
    assert!(spool.status().reserved_bytes > 0);
    stop_test_entrypoint(shutdown_tx, handle).await;
    drop(release);
    let _ = request.await;

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[2]["kind"], "attempt_terminal");
    assert_eq!(events[2]["outcome"], "cancelled");
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "cancelled");
    assert_eq!(spool.status().reserved_bytes, 0);
    spool.shutdown().await;
}
