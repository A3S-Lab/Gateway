use super::inference_tests::{
    gateway_state, gateway_state_with_previous, inference_config, inference_key, read_http_request,
    render_inference_snapshot_acl, spawn_blocking_backend, spawn_capturing_backend,
    spawn_multi_ok_backend, start_test_entrypoint, start_test_runtime, stop_test_entrypoint,
};
use super::GatewayRuntime;
use crate::config::{
    GatewayConfig, InferenceLimitsConfig, InferencePhaseRole, InferenceSchedulingConfig,
    InferenceTransferHealth, InferenceWorkerConfig, ManagedTargetConfig, ServerConfig,
    POWER_WORKER_OBSERVATION_SCHEMA,
};
use chrono::{Duration as ChronoDuration, Utc};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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
async fn managed_inference_pool_rejects_when_queue_deadline_elapses() {
    let key = inference_key('q');
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
    // One active slot + one queued waiter; short queue deadline fails closed.
    enable_worker_scheduling(&mut config, &[(backend, "power-a", 0, 0)], 1, 1, 40);
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
        "pool_queue_timeout"
    );

    release_request.send(()).unwrap();
    assert_eq!(first.await.unwrap().status(), 200);
    stop_test_entrypoint(shutdown_tx, handle).await;
}

async fn spawn_multi_holding_backend() -> (
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<()>,
    tokio::sync::watch::Sender<bool>,
) {
    use tokio::sync::{mpsc, watch};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = mpsc::unbounded_channel();
    let (release_tx, release_rx) = watch::channel(false);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let started_tx = started_tx.clone();
            let mut release_rx = release_rx.clone();
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let _ = started_tx.send(());
                while !*release_rx.borrow() {
                    if release_rx.changed().await.is_err() {
                        return;
                    }
                }
                let response =
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, started_rx, release_tx)
}

#[tokio::test]
async fn managed_inference_pool_releases_queue_slot_when_waiting_client_aborts() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let key = inference_key('c');
    let (backend, mut request_started, release_streams) = spawn_multi_holding_backend().await;
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
    // One active slot + one queue slot; long deadline so abort wins over timeout.
    enable_worker_scheduling(&mut config, &[(backend, "power-a", 0, 0)], 1, 1, 5_000);
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
    tokio::time::timeout(Duration::from_secs(2), request_started.recv())
        .await
        .unwrap()
        .unwrap();

    let body = r#"{"model":"allowed-model","messages":[]}"#;
    let waiting_raw = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut waiting = TcpStream::connect(address).await.unwrap();
    waiting.write_all(waiting_raw.as_bytes()).await.unwrap();
    waiting.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;

    let full = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(full.status(), 429);
    assert_eq!(
        full.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "pool_queue_full"
    );

    drop(waiting);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let third_client = client.clone();
    let third_key = key.clone();
    let third = tokio::spawn(async move {
        third_client
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(third_key)
            .header("content-type", "application/json")
            .body(r#"{"model":"allowed-model","messages":[]}"#)
            .send()
            .await
            .unwrap()
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        !third.is_finished(),
        "aborted waiter must free the queue slot so a follow-up can wait"
    );

    let _ = release_streams.send(true);
    assert_eq!(first.await.unwrap().status(), 200);
    let third_response = tokio::time::timeout(Duration::from_secs(3), third)
        .await
        .expect("follow-up must admit after queued client abort")
        .unwrap();
    assert_eq!(third_response.status(), 200);
    tokio::time::timeout(Duration::from_secs(2), request_started.recv())
        .await
        .expect("follow-up must reach upstream")
        .expect("holding backend stopped");

    stop_test_entrypoint(shutdown_tx, handle).await;
}

async fn spawn_repeating_holding_streaming_backend() -> (
    SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<()>,
    tokio::sync::mpsc::UnboundedReceiver<()>,
) {
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = mpsc::unbounded_channel();
    let (disconnected_tx, disconnected_rx) = mpsc::unbounded_channel();
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
async fn managed_inference_pool_releases_active_slot_when_streaming_client_aborts() {
    use futures_util::StreamExt;

    let key = inference_key('p');
    let (backend, mut started, mut disconnected) =
        spawn_repeating_holding_streaming_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    // Grant concurrency stays above the pool so the binding limit is the
    // scheduling active slot (pool_queue_full), not concurrency_limit_exceeded.
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 3,
            requests_per_minute: 600,
            request_burst: 10,
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

    let response = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    started.recv().await.unwrap();

    let mut body = response.bytes_stream();
    let first = body.next().await.unwrap().unwrap();
    assert!(
        first
            .windows(b"data:".len())
            .any(|window| window == b"data:"),
        "client must observe the first SSE chunk before abort"
    );

    let rejected = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), 429);
    assert_eq!(
        rejected.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "pool_queue_full",
        "live SSE must hold the scheduling active slot"
    );

    drop(body);
    tokio::time::timeout(Duration::from_secs(2), disconnected.recv())
        .await
        .expect("upstream must see client cancel after SSE body drop")
        .unwrap();

    let admitted = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = client
                .post(format!("http://{address}/v1/chat/completions"))
                .bearer_auth(&key)
                .header("content-type", "application/json")
                .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
                .send()
                .await
                .unwrap();
            if response.status() == 200 {
                return response;
            }
            assert_eq!(response.status(), 429);
            assert_eq!(
                response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
                "pool_queue_full"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("scheduling active slot must release after streaming client abort");
    assert_eq!(admitted.status(), 200);
    started.recv().await.unwrap();
    drop(admitted);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn expired_worker_observations_fail_closed_without_upstream_contact() {
    // Dual-track I0 / PW0 freshness: a scheduled model whose Power
    // observations have all expired must not invent availability or contact
    // upstream. Cloud must refresh observations before service resumes.
    let key = inference_key('e');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    enable_worker_scheduling(&mut config, &[(backend, "power-a", 0, 0)], 8, 8, 500);
    config.validate().unwrap();

    let initial = gateway_state(&config);
    let runtime = GatewayRuntime::new(initial);
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let old_state = runtime.load();
    let previous = old_state
        .inference_authorizer
        .as_deref()
        .expect("inference authorizer");
    for worker in config.inference.as_mut().unwrap().workers.values_mut() {
        worker.expires_at = Utc::now() - ChronoDuration::seconds(1);
    }
    runtime.replace(gateway_state_with_previous(&config, Some(previous)));
    drop(old_state);
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
        "authorization_unavailable"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err(),
        "expired Power observations must never contact upstream"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_snapshot_apply_empty_worker_successor_retains_prior_scheduled_routing_on_listener()
{
    // Dual-track I0: an empty-worker scheduled successor must fail closed on
    // ManagedSnapshotStore::apply without replacing the live listener that
    // already routes from a ready scheduled snapshot.
    use crate::managed_snapshot::{
        digest_acl, ManagedSnapshot, ManagedSnapshotIdentity, ManagedSnapshotReloadCallback,
        ManagedSnapshotStore,
    };

    let key = inference_key('w');
    let (backend, upstream_hits) = spawn_multi_ok_backend(2).await;
    let snapshot_expires = Utc::now() + ChronoDuration::hours(1);
    let mut first = inference_config(backend, &key, snapshot_expires);
    first.inference.as_mut().unwrap().expires_at = snapshot_expires;
    enable_worker_scheduling(&mut first, &[(backend, "power-a", 0, 0)], 8, 8, 500);
    first.validate().unwrap();
    let gateway_id = first.managed.gateway_id.expect("managed gateway id");
    let first_acl = render_inference_snapshot_acl(&first);
    let first_identity = ManagedSnapshotIdentity {
        gateway_id,
        revision: 1,
        snapshot_digest: digest_acl(&first_acl),
    };

    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id), None));
    let runtime =
        GatewayRuntime::new(gateway_state(&first)).with_managed_snapshot_store(store.clone());
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let previous_config = Arc::new(Mutex::new(first.clone()));
    let reload_calls = Arc::new(AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let runtime = runtime.clone();
        let previous_config = previous_config.clone();
        let reload_calls = reload_calls.clone();
        Arc::new(move |config| {
            let runtime = runtime.clone();
            let previous_config = previous_config.clone();
            let reload_calls = reload_calls.clone();
            Box::pin(async move {
                reload_calls.fetch_add(1, Ordering::SeqCst);
                let old = previous_config.lock().unwrap().clone();
                let old_state = runtime.load();
                let previous = old_state.inference_authorizer.as_deref();
                let next_state = gateway_state_with_previous(&config, previous);
                drop(old_state);
                *previous_config.lock().unwrap() = config.clone();
                runtime.replace(next_state);
                Ok(old)
            })
        })
    };

    let applied = store
        .apply(
            ManagedSnapshot::new(gateway_id, 1, None, Utc::now(), snapshot_expires, first_acl),
            Some(&callback),
        )
        .await;
    assert_eq!(applied.status_code, 200);
    assert!(applied.status.ready);
    assert_eq!(reload_calls.load(Ordering::SeqCst), 1);

    let admitted = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let mut empty_workers = first.clone();
    empty_workers.inference.as_mut().unwrap().workers.clear();
    let empty_expires = Utc::now() + ChronoDuration::hours(1);
    empty_workers.inference.as_mut().unwrap().expires_at = empty_expires;
    let rejected = store
        .apply(
            ManagedSnapshot::new(
                gateway_id,
                2,
                Some(1),
                Utc::now(),
                empty_expires,
                render_inference_snapshot_acl(&empty_workers),
            ),
            Some(&callback),
        )
        .await;
    assert_eq!(rejected.status_code, 422);
    assert!(
        rejected
            .status
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("no worker observation"),
        "empty scheduled workers must fail closed: {:?}",
        rejected.status.reason
    );
    assert_eq!(reload_calls.load(Ordering::SeqCst), 1);
    assert!(store.status(Some(first_identity), Utc::now()).ready);

    let retained = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(retained.status(), 200);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "rejected empty-worker successor must retain prior scheduled routing to the same upstream"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_snapshot_apply_stale_worker_successor_retains_prior_scheduled_routing_on_listener()
{
    // Dual-track I0: a scheduled successor whose Power observations are already
    // outside the freshness window must fail closed on apply and leave the live
    // listener on the prior ready scheduled snapshot.
    use crate::managed_snapshot::{
        digest_acl, ManagedSnapshot, ManagedSnapshotIdentity, ManagedSnapshotReloadCallback,
        ManagedSnapshotStore,
    };

    let key = inference_key('f');
    let (backend, upstream_hits) = spawn_multi_ok_backend(2).await;
    let snapshot_expires = Utc::now() + ChronoDuration::hours(1);
    let mut first = inference_config(backend, &key, snapshot_expires);
    first.inference.as_mut().unwrap().expires_at = snapshot_expires;
    enable_worker_scheduling(&mut first, &[(backend, "power-a", 0, 0)], 8, 8, 500);
    first.validate().unwrap();
    let gateway_id = first.managed.gateway_id.expect("managed gateway id");
    let first_acl = render_inference_snapshot_acl(&first);
    let first_identity = ManagedSnapshotIdentity {
        gateway_id,
        revision: 1,
        snapshot_digest: digest_acl(&first_acl),
    };

    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id), None));
    let runtime =
        GatewayRuntime::new(gateway_state(&first)).with_managed_snapshot_store(store.clone());
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let previous_config = Arc::new(Mutex::new(first.clone()));
    let reload_calls = Arc::new(AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let runtime = runtime.clone();
        let previous_config = previous_config.clone();
        let reload_calls = reload_calls.clone();
        Arc::new(move |config| {
            let runtime = runtime.clone();
            let previous_config = previous_config.clone();
            let reload_calls = reload_calls.clone();
            Box::pin(async move {
                reload_calls.fetch_add(1, Ordering::SeqCst);
                let old = previous_config.lock().unwrap().clone();
                let old_state = runtime.load();
                let previous = old_state.inference_authorizer.as_deref();
                let next_state = gateway_state_with_previous(&config, previous);
                drop(old_state);
                *previous_config.lock().unwrap() = config.clone();
                runtime.replace(next_state);
                Ok(old)
            })
        })
    };

    let applied = store
        .apply(
            ManagedSnapshot::new(gateway_id, 1, None, Utc::now(), snapshot_expires, first_acl),
            Some(&callback),
        )
        .await;
    assert_eq!(applied.status_code, 200);
    assert!(applied.status.ready);
    assert_eq!(reload_calls.load(Ordering::SeqCst), 1);

    let admitted = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let mut stale_workers = first.clone();
    {
        let inference = stale_workers.inference.as_mut().unwrap();
        for worker in inference.workers.values_mut() {
            worker.observed_at = Utc::now() - ChronoDuration::seconds(10);
            worker.expires_at = Utc::now();
        }
        inference.expires_at = Utc::now() + ChronoDuration::hours(1);
    }
    let stale_expires = stale_workers.inference.as_ref().unwrap().expires_at;
    let rejected = store
        .apply(
            ManagedSnapshot::new(
                gateway_id,
                2,
                Some(1),
                Utc::now(),
                stale_expires,
                render_inference_snapshot_acl(&stale_workers),
            ),
            Some(&callback),
        )
        .await;
    assert_eq!(rejected.status_code, 422);
    assert!(
        rejected
            .status
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("freshness"),
        "stale scheduled workers must fail closed: {:?}",
        rejected.status.reason
    );
    assert_eq!(reload_calls.load(Ordering::SeqCst), 1);
    assert!(store.status(Some(first_identity), Utc::now()).ready);

    let retained = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(retained.status(), 200);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "rejected stale-worker successor must retain prior scheduled routing to the same upstream"
    );

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
