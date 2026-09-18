use super::inference_tests::{
    gateway_state_with_distributed_key, gateway_state_with_distributed_key_and_registry,
    inference_config, inference_key, read_http_request, set_limits, start_test_entrypoint,
    stop_test_entrypoint,
};
use super::inference_usage_tests::lifecycle_events;
use crate::config::{
    GatewayConfig, InferenceDistributedServingConfig, InferenceLimitsConfig, InferencePhaseRole,
    InferenceSchedulingConfig, InferenceTransferHealth, InferenceWorkerConfig, ManagedTargetConfig,
    ServerConfig, POWER_WORKER_OBSERVATION_SCHEMA,
};
use crate::usage::{UsageSpool, UsageSpoolOptions};
use chrono::{Duration as ChronoDuration, Utc};
use futures_util::StreamExt;
use http::StatusCode;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

pub(super) const KEY_ENV: &str = "A3S_POWER_ENTRYPOINT_TEST_KEY";
pub(super) const API_KEY: &str = "power-entrypoint-secret";
const POWER_SCHEMA: &str = "a3s.power.distributed-serving.v1";
const POWER_STREAM_SCHEMA: &str = "a3s.power.distributed-serving-stream.v1";
const PREFILL_PROFILE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DECODE_PROFILE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Debug, Clone, Copy)]
enum WorkerRole {
    Prefill,
    Decode,
}

#[derive(Debug)]
struct CapturedPowerRequest {
    path: String,
    authorization: Option<String>,
    body: Value,
}

async fn read_power_request(stream: &mut TcpStream) -> CapturedPowerRequest {
    let request = read_http_request(stream).await;
    let body_offset = request
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .expect("request headers")
        + 4;
    let headers = String::from_utf8_lossy(&request[..body_offset - 4]);
    let path = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("request path")
        .to_string();
    let authorization = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_string())
    });
    CapturedPowerRequest {
        path,
        authorization,
        body: serde_json::from_slice(&request[body_offset..]).expect("Power JSON request"),
    }
}

async fn write_json(stream: &mut TcpStream, body: Value) {
    let body = serde_json::to_vec(&body).expect("Power JSON response");
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.shutdown().await.unwrap();
}

async fn write_decode_stream(stream: &mut TcpStream, request: &CapturedPowerRequest) {
    let binding = (
        request.body["execution_id"].clone(),
        request.body["worker_epoch"].clone(),
        request.body["execution_profile_sha256"].clone(),
    );
    let frames = [
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {"event": "ready"}
        }),
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {
                "event": "chunk",
                "sequence": 0,
                "response": {
                    "endpoint": "chat-completions",
                    "chunk": {
                        "content": "entrypoint P/D response",
                        "done": true,
                        "prompt_tokens": 3,
                        "done_reason": "stop"
                    }
                }
            }
        }),
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {"event": "completed", "sequence": 1}
        }),
    ]
    .into_iter()
    .map(|frame| serde_json::to_string(&frame).unwrap())
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        frames.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(frames.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

/// Terminal decode stream with no Power prompt tokens and no completion text,
/// so Gateway must omit OpenAI SSE `usage` and keep the TPM reservation charged.
async fn write_decode_stream_without_usage(stream: &mut TcpStream, request: &CapturedPowerRequest) {
    let binding = (
        request.body["execution_id"].clone(),
        request.body["worker_epoch"].clone(),
        request.body["execution_profile_sha256"].clone(),
    );
    let frames = [
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {"event": "ready"}
        }),
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {
                "event": "chunk",
                "sequence": 0,
                "response": {
                    "endpoint": "chat-completions",
                    "chunk": {
                        "content": "",
                        "done": true,
                        "done_reason": "stop"
                    }
                }
            }
        }),
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {"event": "completed", "sequence": 1}
        }),
    ]
    .into_iter()
    .map(|frame| serde_json::to_string(&frame).unwrap())
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        frames.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(frames.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
}

fn bound_response(request: &CapturedPowerRequest, outcome: Value) -> Value {
    json!({
        "schema": POWER_SCHEMA,
        "execution_id": request.body["execution_id"],
        "worker_epoch": request.body["worker_epoch"],
        "execution_profile_sha256": request.body["execution_profile_sha256"],
        "outcome": outcome
    })
}

fn abort_response(request: &CapturedPowerRequest) -> Value {
    json!({
        "schema": POWER_SCHEMA,
        "execution_id": request.body["execution_id"],
        "worker_epoch": request.body["worker_epoch"],
        "execution_profile_sha256": request.body["execution_profile_sha256"],
        "accepted": true
    })
}

async fn spawn_power_worker(
    role: WorkerRole,
) -> (
    SocketAddr,
    Arc<Mutex<Vec<CapturedPowerRequest>>>,
    tokio::task::JoinHandle<()>,
) {
    spawn_power_workers(role, 1, true).await
}

async fn spawn_power_worker_for_executions(
    role: WorkerRole,
    executions: usize,
) -> (
    SocketAddr,
    Arc<Mutex<Vec<CapturedPowerRequest>>>,
    tokio::task::JoinHandle<()>,
) {
    spawn_power_workers(role, executions, true).await
}

async fn spawn_power_workers(
    role: WorkerRole,
    executions: usize,
    emit_usage: bool,
) -> (
    SocketAddr,
    Arc<Mutex<Vec<CapturedPowerRequest>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::new()));
    let task_records = records.clone();
    let expected_requests = match role {
        WorkerRole::Prefill => 2 * executions,
        WorkerRole::Decode => 3 * executions,
    };
    let task = tokio::spawn(async move {
        for _ in 0..expected_requests {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_power_request(&mut stream).await;
            assert_eq!(
                request.authorization.as_deref(),
                Some("Bearer power-entrypoint-secret")
            );
            match (role, request.path.as_str()) {
                (WorkerRole::Decode, "/internal/v1/distributed-serving/decode/prepare") => {
                    assert_eq!(
                        request.body["request"]["body"]["model"],
                        "internal-allowed-model"
                    );
                    if let Some(content) = request.body["request"]["body"]["messages"]
                        .get(0)
                        .and_then(|message| message["content"].as_str())
                    {
                        assert_eq!(content, "private entrypoint prompt");
                    }
                    write_json(
                        &mut stream,
                        bound_response(
                            &request,
                            json!({
                                "decision": "ready",
                                "result": {"target": {"transport": "memory", "nonce": "target"}}
                            }),
                        ),
                    )
                    .await;
                }
                (WorkerRole::Prefill, "/internal/v1/distributed-serving/prefill/execute") => {
                    assert_eq!(request.body["target"]["nonce"], "target");
                    write_json(
                        &mut stream,
                        bound_response(
                            &request,
                            json!({
                                "decision": "ready",
                                "result": {"source": {"transport": "memory", "nonce": "source"}}
                            }),
                        ),
                    )
                    .await;
                }
                (WorkerRole::Decode, "/internal/v1/distributed-serving/decode/execute") => {
                    assert_eq!(request.body["source"]["nonce"], "source");
                    if emit_usage {
                        write_decode_stream(&mut stream, &request).await;
                    } else {
                        write_decode_stream_without_usage(&mut stream, &request).await;
                    }
                }
                (_, "/internal/v1/distributed-serving/abort") => {
                    let response = abort_response(&request);
                    write_json(&mut stream, response).await;
                }
                (role, path) => panic!("unexpected {role:?} Power path {path}"),
            }
            task_records.lock().unwrap().push(request);
        }
    });
    (address, records, task)
}

pub(super) async fn spawn_successful_power_pair() -> (
    SocketAddr,
    SocketAddr,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (prefill, _, prefill_task) = spawn_power_worker(WorkerRole::Prefill).await;
    let (decode, _, decode_task) = spawn_power_worker(WorkerRole::Decode).await;
    (prefill, decode, prefill_task, decode_task)
}

/// Prefill/decode pair that holds the decode NDJSON body open until released.
pub(super) async fn spawn_releasable_holding_power_pair() -> (
    SocketAddr,
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let (stream_started_tx, stream_started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();

    let prefill_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let prefill_address = prefill_listener.local_addr().unwrap();
    let decode_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decode_address = decode_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = prefill_listener.accept().await.unwrap();
        let request = read_power_request(&mut stream).await;
        assert_eq!(
            request.path,
            "/internal/v1/distributed-serving/prefill/execute"
        );
        write_json(
            &mut stream,
            bound_response(
                &request,
                json!({
                    "decision": "ready",
                    "result": {"source": {"transport": "memory", "nonce": "source-a"}}
                }),
            ),
        )
        .await;
    });

    tokio::spawn(async move {
        // prepare
        let (mut stream, _) = decode_listener.accept().await.unwrap();
        let request = read_power_request(&mut stream).await;
        assert_eq!(
            request.path,
            "/internal/v1/distributed-serving/decode/prepare"
        );
        write_json(
            &mut stream,
            bound_response(
                &request,
                json!({
                    "decision": "ready",
                    "result": {"target": {"transport": "memory", "nonce": "target-a"}}
                }),
            ),
        )
        .await;

        // execute — hold this connection until the test releases it
        let (mut stream, _) = decode_listener.accept().await.unwrap();
        let request = read_power_request(&mut stream).await;
        assert_eq!(
            request.path,
            "/internal/v1/distributed-serving/decode/execute"
        );
        write_releasable_holding_decode_stream(
            &mut stream,
            &request,
            stream_started_tx,
            release_rx,
        )
        .await;
    });

    (
        prefill_address,
        decode_address,
        stream_started_rx,
        release_tx,
    )
}

pub(super) fn enable_distributed_scheduling(
    config: &mut GatewayConfig,
    prefill_address: SocketAddr,
    decode_address: SocketAddr,
) {
    let policy = config.inference.as_mut().expect("inference policy");
    let route = policy.routes.values_mut().next().expect("inference route");
    let model = route
        .models
        .get_mut("allowed-model")
        .expect("allowed model");
    let target_id = model.targets[0].target_id;
    model.scheduling = Some(InferenceSchedulingConfig {
        phase: InferencePhaseRole::Decode,
        max_concurrent_requests: 8,
        max_queued_requests: 8,
        queue_timeout_ms: 500,
        prompt_cache_affinity: true,
        distributed_serving: Some(InferenceDistributedServingConfig {
            api_key_env: KEY_ENV.to_string(),
            execution_timeout_ms: 5_000,
        }),
    });

    let observed_at = Utc::now();
    let expires_at = observed_at + ChronoDuration::seconds(30);
    let workers = [
        (
            WorkerRole::Prefill,
            prefill_address,
            "power-prefill",
            Uuid::from_u128(101),
            PREFILL_PROFILE,
        ),
        (
            WorkerRole::Decode,
            decode_address,
            "power-decode",
            Uuid::from_u128(102),
            DECODE_PROFILE,
        ),
    ];
    let servers = workers
        .into_iter()
        .map(|(role, address, unit_id, worker_epoch, profile)| {
            let phase = match role {
                WorkerRole::Prefill => InferencePhaseRole::Prefill,
                WorkerRole::Decode => InferencePhaseRole::Decode,
            };
            let target = ManagedTargetConfig {
                target_id,
                unit_id: unit_id.to_string(),
                generation: 5,
            };
            let prompt_cache = matches!(role, WorkerRole::Prefill);
            policy.workers.insert(
                unit_id.to_string(),
                InferenceWorkerConfig {
                    target: target.clone(),
                    schema: POWER_WORKER_OBSERVATION_SCHEMA.to_string(),
                    worker_epoch,
                    execution_profile_sha256: Some(profile.to_string()),
                    observation_generation: 9,
                    observed_at,
                    expires_at,
                    phases: vec![phase],
                    prompt_cache_capable: prompt_cache,
                    state_transfer_capable: true,
                    ready_phases: vec![phase],
                    active_limit: Some(8),
                    active: 0,
                    waiting: 0,
                    prompt_cache_supported: prompt_cache,
                    prompt_cache_entries: u64::from(prompt_cache),
                    prompt_cache_capacity: if prompt_cache { 4 } else { 0 },
                    prompt_cache_pressure_basis_points: if prompt_cache { 2_500 } else { 0 },
                    transfer_health: InferenceTransferHealth::Ready,
                    certified_latency_ms: Some(10),
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

#[tokio::test]
async fn managed_openai_request_executes_through_the_power_prefill_decode_contract() {
    let key = inference_key('a');
    let (prefill_address, prefill_records, prefill_task) =
        spawn_power_worker(WorkerRole::Prefill).await;
    let (decode_address, decode_records, decode_task) =
        spawn_power_worker(WorkerRole::Decode).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    config.validate().unwrap();
    let state = gateway_state_with_distributed_key(&config, KEY_ENV, API_KEY);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(
            r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":false}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert!(response.headers().contains_key("x-request-id"));
    let response = response.json::<Value>().await.unwrap();
    assert_eq!(response["model"], "allowed-model");
    assert_eq!(
        response["choices"][0]["message"]["content"],
        "entrypoint P/D response"
    );
    assert_eq!(response["usage"]["prompt_tokens"], 3);
    assert_eq!(response["usage"]["completion_tokens"], 1);
    assert_eq!(response["usage"]["total_tokens"], 4);

    tokio::time::timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(prefill_records.lock().unwrap().len(), 2);
    assert_eq!(decode_records.lock().unwrap().len(), 3);
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn managed_streaming_request_exposes_only_openai_sse() {
    let key = inference_key('b');
    let (prefill_address, _, prefill_task) = spawn_power_worker(WorkerRole::Prefill).await;
    let (decode_address, _, decode_task) = spawn_power_worker(WorkerRole::Decode).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    config.validate().unwrap();
    let state = gateway_state_with_distributed_key(&config, KEY_ENV, API_KEY);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(response.headers()["x-accel-buffering"], "no");
    let body = response.text().await.unwrap();
    assert!(body.contains("\"object\":\"chat.completion.chunk\""));
    assert!(body.contains("entrypoint P/D response"));
    assert!(body.contains("\"usage\""));
    assert!(body.contains("\"prompt_tokens\":3"));
    assert!(body.contains("\"total_tokens\":4"));
    assert!(body.ends_with("data: [DONE]\n\n"));
    assert!(!body.contains(POWER_STREAM_SCHEMA));

    tokio::time::timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn response_middleware_error_fails_closed_on_distributed_json_listener_without_power_body() {
    use crate::error::{GatewayError, Result};
    use crate::middleware::{Middleware, MiddlewareRegistry, RequestContext};
    use async_trait::async_trait;

    struct FailResponseMiddleware;

    #[async_trait]
    impl Middleware for FailResponseMiddleware {
        async fn handle_request(
            &self,
            _req: &mut http::request::Parts,
            _ctx: &RequestContext,
        ) -> Result<Option<http::Response<Vec<u8>>>> {
            Ok(None)
        }

        async fn handle_response(&self, _resp: &mut http::response::Parts) -> Result<()> {
            Err(GatewayError::Other(
                "response policy deliberately failed".to_string(),
            ))
        }

        fn name(&self) -> &str {
            "fail-response"
        }
    }

    let key = inference_key('c');
    let (prefill_address, _, prefill_task) = spawn_power_worker(WorkerRole::Prefill).await;
    let (decode_address, _, decode_task) = spawn_power_worker(WorkerRole::Decode).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("fail-response".to_string());
    let custom = std::collections::HashSet::from(["fail-response".to_string()]);
    config.validate_with_custom_middlewares(&custom).unwrap();

    let mut registry = MiddlewareRegistry::new();
    registry
        .register("fail-response", FailResponseMiddleware)
        .unwrap();
    let state =
        gateway_state_with_distributed_key_and_registry(&config, KEY_ENV, API_KEY, &registry);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .body(
            r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":false}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.text().await.unwrap();
    assert!(body.contains("Middleware error"), "unexpected body: {body}");
    assert!(
        !body.contains("entrypoint P/D response"),
        "Power completion body must not leak after response middleware failure: {body}"
    );

    // Workers may still finish execution; fail-closed is about the client surface.
    let _ = tokio::time::timeout(Duration::from_secs(2), prefill_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), decode_task).await;
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn response_middleware_error_fails_closed_on_distributed_sse_listener_without_power_body() {
    use crate::error::{GatewayError, Result};
    use crate::middleware::{Middleware, MiddlewareRegistry, RequestContext};
    use async_trait::async_trait;

    struct FailResponseMiddleware;

    #[async_trait]
    impl Middleware for FailResponseMiddleware {
        async fn handle_request(
            &self,
            _req: &mut http::request::Parts,
            _ctx: &RequestContext,
        ) -> Result<Option<http::Response<Vec<u8>>>> {
            Ok(None)
        }

        async fn handle_response(&self, _resp: &mut http::response::Parts) -> Result<()> {
            Err(GatewayError::Other(
                "response policy deliberately failed".to_string(),
            ))
        }

        fn name(&self) -> &str {
            "fail-response"
        }
    }

    let key = inference_key('d');
    let (prefill_address, _, prefill_task) = spawn_power_worker(WorkerRole::Prefill).await;
    let (decode_address, _, decode_task) = spawn_power_worker(WorkerRole::Decode).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("fail-response".to_string());
    let custom = std::collections::HashSet::from(["fail-response".to_string()]);
    config.validate_with_custom_middlewares(&custom).unwrap();

    let mut registry = MiddlewareRegistry::new();
    registry
        .register("fail-response", FailResponseMiddleware)
        .unwrap();
    let state =
        gateway_state_with_distributed_key_and_registry(&config, KEY_ENV, API_KEY, &registry);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = response.text().await.unwrap();
    assert!(body.contains("Middleware error"), "unexpected body: {body}");
    assert!(
        !body.contains("entrypoint P/D response"),
        "Power SSE payload must not leak after response middleware failure: {body}"
    );
    assert!(
        !body.contains("chat.completion.chunk"),
        "OpenAI SSE frames must not leak after response middleware failure: {body}"
    );

    let _ = tokio::time::timeout(Duration::from_secs(2), prefill_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), decode_task).await;
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

async fn usage_state_with_distributed(
    config: &GatewayConfig,
    directory: &std::path::Path,
) -> (Arc<super::GatewayState>, Arc<UsageSpool>) {
    let spool = Arc::new(
        UsageSpool::open(UsageSpoolOptions {
            directory: directory.join("usage-spool"),
            gateway_id: config.managed.gateway_id.unwrap(),
            max_bytes: 1024 * 1024,
        })
        .await
        .unwrap(),
    );
    let mut state = gateway_state_with_distributed_key(config, KEY_ENV, API_KEY);
    Arc::get_mut(&mut state)
        .expect("unshared Gateway test state")
        .usage_spool = Some(spool.clone());
    (state, spool)
}

#[tokio::test]
async fn managed_distributed_json_persists_upstream_usage_on_request_terminal() {
    let key = inference_key('d');
    let (prefill_address, _, prefill_task) = spawn_power_worker(WorkerRole::Prefill).await;
    let (decode_address, _, decode_task) = spawn_power_worker(WorkerRole::Decode).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    config.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state_with_distributed(&config, directory.path()).await;
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(
            r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":false}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["usage"]["total_tokens"], 4);

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "succeeded");
    assert_eq!(events[3]["measurement_completeness"], "upstream_usage");
    assert_eq!(events[3]["total_tokens"], 4);

    tokio::time::timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_distributed_sse_persists_upstream_usage_on_request_terminal() {
    let key = inference_key('g');
    let (prefill_address, _, prefill_task) = spawn_power_worker(WorkerRole::Prefill).await;
    let (decode_address, _, decode_task) = spawn_power_worker(WorkerRole::Decode).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    config.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state_with_distributed(&config, directory.path()).await;
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(
            r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":true}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await.unwrap();
    assert!(body.contains("\"total_tokens\":4"));
    assert!(body.ends_with("data: [DONE]\n\n"));

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "succeeded");
    assert_eq!(events[3]["measurement_completeness"], "upstream_usage");
    assert_eq!(events[3]["total_tokens"], 4);

    tokio::time::timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_distributed_json_upstream_usage_reconciles_token_budget_for_follow_up_request() {
    let key = inference_key('h');
    let (prefill_address, _, prefill_task) =
        spawn_power_worker_for_executions(WorkerRole::Prefill, 2).await;
    let (decode_address, _, decode_task) =
        spawn_power_worker_for_executions(WorkerRole::Decode, 2).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 4,
            requests_per_minute: 60,
            request_burst: 10,
            // Headroom must cover two provisional reservations after refunding
            // Power-derived total_tokens=4 from the first buffered response.
            tokens_per_minute: 80,
        },
    );
    config.validate().unwrap();
    let state = gateway_state_with_distributed_key(&config, KEY_ENV, API_KEY);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let request_body = r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"max_tokens":30,"stream":false}"#;

    let first = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = first.json::<Value>().await.unwrap();
    assert_eq!(first_body["usage"]["total_tokens"], 4);

    let second = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "P/D JSON usage must reconcile the provisional token reservation"
    );
    let _ = second.bytes().await.unwrap();

    tokio::time::timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn managed_distributed_sse_without_usage_keeps_provisional_token_reservation_charged() {
    let key = inference_key('i');
    let (prefill_address, _, prefill_task) =
        spawn_power_workers(WorkerRole::Prefill, 1, false).await;
    let (decode_address, _, decode_task) = spawn_power_workers(WorkerRole::Decode, 1, false).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 4,
            requests_per_minute: 60,
            request_burst: 10,
            tokens_per_minute: 40,
        },
    );
    config.validate().unwrap();
    let state = gateway_state_with_distributed_key(&config, KEY_ENV, API_KEY);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let request_body = r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"max_tokens":30,"stream":true}"#;

    let first = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = first.text().await.unwrap();
    assert!(
        !first_body.contains("\"usage\""),
        "P/D SSE without Power tokens must omit OpenAI usage"
    );
    assert!(first_body.ends_with("data: [DONE]\n\n"));

    let second = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second.json::<Value>().await.unwrap()["error"]["code"],
        "rate_limit_exceeded"
    );

    tokio::time::timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn managed_distributed_json_without_usage_keeps_provisional_token_reservation_charged() {
    let key = inference_key('k');
    let (prefill_address, _, prefill_task) =
        spawn_power_workers(WorkerRole::Prefill, 1, false).await;
    let (decode_address, _, decode_task) = spawn_power_workers(WorkerRole::Decode, 1, false).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 4,
            requests_per_minute: 60,
            request_burst: 10,
            tokens_per_minute: 40,
        },
    );
    config.validate().unwrap();
    let state = gateway_state_with_distributed_key(&config, KEY_ENV, API_KEY);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let request_body = r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"max_tokens":30,"stream":false}"#;

    let first = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = first.json::<Value>().await.unwrap();
    assert!(
        first_body.get("usage").is_none(),
        "P/D JSON without Power tokens must omit invented usage"
    );

    let second = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        second.json::<Value>().await.unwrap()["error"]["code"],
        "rate_limit_exceeded"
    );

    tokio::time::timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn managed_distributed_sse_upstream_usage_reconciles_token_budget_for_follow_up_request() {
    let key = inference_key('e');
    let (prefill_address, _, prefill_task) =
        spawn_power_worker_for_executions(WorkerRole::Prefill, 2).await;
    let (decode_address, _, decode_task) =
        spawn_power_worker_for_executions(WorkerRole::Decode, 2).await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 4,
            requests_per_minute: 60,
            request_burst: 10,
            // Headroom must cover two provisional reservations after refunding
            // Power-derived total_tokens=4 from the first stream.
            tokens_per_minute: 80,
        },
    );
    config.validate().unwrap();
    let state = gateway_state_with_distributed_key(&config, KEY_ENV, API_KEY);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let request_body = r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"max_tokens":30,"stream":true}"#;

    let first = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = first.text().await.unwrap();
    assert!(first_body.contains("\"total_tokens\":4"));
    assert!(first_body.ends_with("data: [DONE]\n\n"));

    let second = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        second.status(),
        StatusCode::OK,
        "P/D SSE usage must reconcile the provisional token reservation"
    );
    let _ = second.text().await.unwrap();

    tokio::time::timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

/// Write ready + one decode chunk, signal start, then hold until `release`
/// before emitting the terminal Power frames.
async fn write_releasable_holding_decode_stream(
    stream: &mut TcpStream,
    request: &CapturedPowerRequest,
    started: tokio::sync::oneshot::Sender<()>,
    release: tokio::sync::oneshot::Receiver<()>,
) {
    let binding = (
        request.body["execution_id"].clone(),
        request.body["worker_epoch"].clone(),
        request.body["execution_profile_sha256"].clone(),
    );
    let first_frames = [
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {"event": "ready"}
        }),
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {
                "event": "chunk",
                "sequence": 0,
                "response": {
                    "endpoint": "chat-completions",
                    "chunk": {
                        "content": "pd-snapshot-a-first",
                        "done": false,
                        "prompt_tokens": 3
                    }
                }
            }
        }),
    ]
    .into_iter()
    .map(|frame| serde_json::to_string(&frame).unwrap())
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        first_frames.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(first_frames.as_bytes()).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.flush().await.unwrap();
    let _ = started.send(());
    release.await.expect("decode stream release");

    let last_frames = [
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {
                "event": "chunk",
                "sequence": 1,
                "response": {
                    "endpoint": "chat-completions",
                    "chunk": {
                        "content": "pd-snapshot-a-done",
                        "done": true,
                        "prompt_tokens": 3,
                        "done_reason": "stop"
                    }
                }
            }
        }),
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {"event": "completed", "sequence": 2}
        }),
    ]
    .into_iter()
    .map(|frame| serde_json::to_string(&frame).unwrap())
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let chunk = format!("{:x}\r\n{last_frames}\r\n0\r\n\r\n", last_frames.len());
    stream.write_all(chunk.as_bytes()).await.unwrap();
    stream.flush().await.unwrap();
    let _ = stream.shutdown().await;
}

/// Write ready + one decode chunk, signal start, then hold the Power stream open
/// until the peer closes (client cancel / Gateway drop).
async fn write_holding_decode_stream(
    stream: &mut TcpStream,
    request: &CapturedPowerRequest,
    started: tokio::sync::oneshot::Sender<()>,
) {
    let binding = (
        request.body["execution_id"].clone(),
        request.body["worker_epoch"].clone(),
        request.body["execution_profile_sha256"].clone(),
    );
    let frames = [
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {"event": "ready"}
        }),
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {
                "event": "chunk",
                "sequence": 0,
                "response": {
                    "endpoint": "chat-completions",
                    "chunk": {
                        "content": "partial P/D",
                        "done": false,
                        "prompt_tokens": 3
                    }
                }
            }
        }),
    ]
    .into_iter()
    .map(|frame| serde_json::to_string(&frame).unwrap())
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        frames.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(frames.as_bytes()).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.flush().await.unwrap();
    let _ = started.send(());

    let mut buffer = [0_u8; 1];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Keep emitting decode chunks on a short cadence so stream idle never fires,
/// while the service `stream_total_timeout` (from request start) can expire.
async fn write_dripping_decode_stream(
    stream: &mut TcpStream,
    request: &CapturedPowerRequest,
    started: tokio::sync::oneshot::Sender<()>,
) {
    let binding = (
        request.body["execution_id"].clone(),
        request.body["worker_epoch"].clone(),
        request.body["execution_profile_sha256"].clone(),
    );
    let first = [
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {"event": "ready"}
        }),
        json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {
                "event": "chunk",
                "sequence": 0,
                "response": {
                    "endpoint": "chat-completions",
                    "chunk": {
                        "content": "partial P/D",
                        "done": false,
                        "prompt_tokens": 3
                    }
                }
            }
        }),
    ]
    .into_iter()
    .map(|frame| serde_json::to_string(&frame).unwrap())
    .collect::<Vec<_>>()
    .join("\n")
        + "\n";
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
        first.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(first.as_bytes()).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.flush().await.unwrap();
    let _ = started.send(());

    let mut sequence = 1_u64;
    loop {
        let frame = json!({
            "schema": POWER_STREAM_SCHEMA,
            "execution_id": binding.0,
            "worker_epoch": binding.1,
            "execution_profile_sha256": binding.2,
            "payload": {
                "event": "chunk",
                "sequence": sequence,
                "response": {
                    "endpoint": "chat-completions",
                    "chunk": {
                        "content": format!("drip-{sequence}"),
                        "done": false
                    }
                }
            }
        });
        let line = serde_json::to_string(&frame).unwrap() + "\n";
        let chunk = format!("{:x}\r\n{}\r\n", line.len(), line);
        if stream.write_all(chunk.as_bytes()).await.is_err() {
            break;
        }
        if stream.flush().await.is_err() {
            break;
        }
        sequence = sequence.saturating_add(1);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn spawn_dripping_power_pair_for_total_timeout() -> (
    SocketAddr,
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (stream_started_tx, stream_started_rx) = tokio::sync::oneshot::channel();
    let (prefill_abort_tx, prefill_abort_rx) = tokio::sync::oneshot::channel();
    let (decode_abort_tx, decode_abort_rx) = tokio::sync::oneshot::channel();

    let prefill_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let prefill_address = prefill_listener.local_addr().unwrap();
    let decode_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decode_address = decode_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut abort_sent = false;
        let mut execute_seen = false;
        let mut prefill_abort_tx = Some(prefill_abort_tx);
        while !(abort_sent && execute_seen) {
            let (mut stream, _) = prefill_listener.accept().await.unwrap();
            let request = read_power_request(&mut stream).await;
            match request.path.as_str() {
                "/internal/v1/distributed-serving/prefill/execute" => {
                    execute_seen = true;
                    write_json(
                        &mut stream,
                        bound_response(
                            &request,
                            json!({
                                "decision": "ready",
                                "result": {"source": {"transport": "memory", "nonce": "source"}}
                            }),
                        ),
                    )
                    .await;
                }
                "/internal/v1/distributed-serving/abort" => {
                    write_json(&mut stream, abort_response(&request)).await;
                    abort_sent = true;
                    if let Some(tx) = prefill_abort_tx.take() {
                        let _ = tx.send(());
                    }
                }
                path => panic!("unexpected prefill path {path}"),
            }
        }
    });

    tokio::spawn(async move {
        let mut abort_sent = false;
        let mut prepare_seen = false;
        let mut execute_seen = false;
        let mut started = Some(stream_started_tx);
        let mut decode_abort_tx = Some(decode_abort_tx);
        while !(abort_sent && prepare_seen && execute_seen) {
            let (mut stream, _) = decode_listener.accept().await.unwrap();
            let request = read_power_request(&mut stream).await;
            match request.path.as_str() {
                "/internal/v1/distributed-serving/decode/prepare" => {
                    prepare_seen = true;
                    write_json(
                        &mut stream,
                        bound_response(
                            &request,
                            json!({
                                "decision": "ready",
                                "result": {"target": {"transport": "memory", "nonce": "target"}}
                            }),
                        ),
                    )
                    .await;
                }
                "/internal/v1/distributed-serving/decode/execute" => {
                    execute_seen = true;
                    let started = started.take().expect("decode execute once");
                    tokio::spawn(async move {
                        write_dripping_decode_stream(&mut stream, &request, started).await;
                    });
                }
                "/internal/v1/distributed-serving/abort" => {
                    write_json(&mut stream, abort_response(&request)).await;
                    abort_sent = true;
                    if let Some(tx) = decode_abort_tx.take() {
                        let _ = tx.send(());
                    }
                }
                path => panic!("unexpected decode path {path}"),
            }
        }
    });

    (
        prefill_address,
        decode_address,
        stream_started_rx,
        prefill_abort_rx,
        decode_abort_rx,
    )
}

async fn spawn_holding_power_pair_for_client_cancel() -> (
    SocketAddr,
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (stream_started_tx, stream_started_rx) = tokio::sync::oneshot::channel();
    let (prefill_abort_tx, prefill_abort_rx) = tokio::sync::oneshot::channel();
    let (decode_abort_tx, decode_abort_rx) = tokio::sync::oneshot::channel();

    let prefill_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let prefill_address = prefill_listener.local_addr().unwrap();
    let decode_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decode_address = decode_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut abort_sent = false;
        let mut execute_seen = false;
        let mut prefill_abort_tx = Some(prefill_abort_tx);
        while !(abort_sent && execute_seen) {
            let (mut stream, _) = prefill_listener.accept().await.unwrap();
            let request = read_power_request(&mut stream).await;
            match request.path.as_str() {
                "/internal/v1/distributed-serving/prefill/execute" => {
                    execute_seen = true;
                    write_json(
                        &mut stream,
                        bound_response(
                            &request,
                            json!({
                                "decision": "ready",
                                "result": {"source": {"transport": "memory", "nonce": "source"}}
                            }),
                        ),
                    )
                    .await;
                }
                "/internal/v1/distributed-serving/abort" => {
                    write_json(&mut stream, abort_response(&request)).await;
                    abort_sent = true;
                    if let Some(tx) = prefill_abort_tx.take() {
                        let _ = tx.send(());
                    }
                }
                path => panic!("unexpected prefill path {path}"),
            }
        }
    });

    tokio::spawn(async move {
        let mut abort_sent = false;
        let mut prepare_seen = false;
        let mut execute_seen = false;
        let mut started = Some(stream_started_tx);
        let mut decode_abort_tx = Some(decode_abort_tx);
        while !(abort_sent && prepare_seen && execute_seen) {
            let (mut stream, _) = decode_listener.accept().await.unwrap();
            let request = read_power_request(&mut stream).await;
            match request.path.as_str() {
                "/internal/v1/distributed-serving/decode/prepare" => {
                    prepare_seen = true;
                    write_json(
                        &mut stream,
                        bound_response(
                            &request,
                            json!({
                                "decision": "ready",
                                "result": {"target": {"transport": "memory", "nonce": "target"}}
                            }),
                        ),
                    )
                    .await;
                }
                "/internal/v1/distributed-serving/decode/execute" => {
                    execute_seen = true;
                    let started = started.take().expect("decode execute once");
                    // Hold the execute stream off the accept loop so /abort can
                    // arrive while the NDJSON body is still open.
                    tokio::spawn(async move {
                        write_holding_decode_stream(&mut stream, &request, started).await;
                    });
                }
                "/internal/v1/distributed-serving/abort" => {
                    write_json(&mut stream, abort_response(&request)).await;
                    abort_sent = true;
                    if let Some(tx) = decode_abort_tx.take() {
                        let _ = tx.send(());
                    }
                }
                path => panic!("unexpected decode path {path}"),
            }
        }
    });

    (
        prefill_address,
        decode_address,
        stream_started_rx,
        prefill_abort_rx,
        decode_abort_rx,
    )
}

#[tokio::test]
async fn managed_distributed_sse_client_cancel_aborts_both_workers_and_releases_concurrency() {
    let key = inference_key('f');
    let (prefill_address, decode_address, stream_started, prefill_abort, decode_abort) =
        spawn_holding_power_pair_for_client_cancel().await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 600,
            request_burst: 10,
            tokens_per_minute: 10_000,
        },
    );
    config.validate().unwrap();
    let state = gateway_state_with_distributed_key(&config, KEY_ENV, API_KEY);
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(
            r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":true}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .expect("decode stream should start before client cancel")
        .unwrap();

    let mut body = response.bytes_stream();
    let first = body.next().await.unwrap().unwrap();
    assert!(
        first
            .windows(b"partial P/D".len())
            .any(|w| w == b"partial P/D"),
        "client must observe the first OpenAI SSE chunk before cancel"
    );

    let limited = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(
        limited.json::<Value>().await.unwrap()["error"]["code"],
        "concurrency_limit_exceeded"
    );

    drop(body);

    tokio::time::timeout(Duration::from_secs(2), prefill_abort)
        .await
        .expect("prefill must receive abort on client cancel")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_abort)
        .await
        .expect("decode must receive abort on client cancel")
        .unwrap();

    let admitted = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = client
                .get(format!("http://{address}/v1/models"))
                .bearer_auth(&key)
                .send()
                .await
                .unwrap();
            if response.status() == 200 {
                return response;
            }
            assert_eq!(response.status(), 429);
            assert_eq!(
                response.json::<Value>().await.unwrap()["error"]["code"],
                "concurrency_limit_exceeded"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("concurrency permit must release after P/D SSE client cancel");
    assert_eq!(admitted.status(), 200);

    stop_test_entrypoint(shutdown_tx, gateway_task).await;
}

#[tokio::test]
async fn managed_distributed_sse_client_cancel_persists_terminal_disconnect_outcomes() {
    let key = inference_key('j');
    let (prefill_address, decode_address, stream_started, prefill_abort, decode_abort) =
        spawn_holding_power_pair_for_client_cancel().await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    config.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state_with_distributed(&config, directory.path()).await;
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(
            r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":true}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .expect("decode stream should start before client cancel")
        .unwrap();

    let mut body = response.bytes_stream();
    let first = body.next().await.unwrap().unwrap();
    assert!(first
        .windows(b"partial P/D".len())
        .any(|w| w == b"partial P/D"));
    drop(body);

    tokio::time::timeout(Duration::from_secs(2), prefill_abort)
        .await
        .expect("prefill abort on cancel")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_abort)
        .await
        .expect("decode abort on cancel")
        .unwrap();

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[2]["kind"], "attempt_terminal");
    assert_eq!(events[2]["outcome"], "disconnected");
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "disconnected");

    stop_test_entrypoint(shutdown_tx, gateway_task).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_distributed_sse_idle_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals(
) {
    let key = inference_key('k');
    let (prefill_address, decode_address, stream_started, prefill_abort, decode_abort) =
        spawn_holding_power_pair_for_client_cancel().await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    let service = config.services.get_mut("model-service").unwrap();
    service.load_balancer.stream_idle_timeout = "25ms".into();
    service.load_balancer.stream_total_timeout = "1s".into();
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 600,
            request_burst: 10,
            tokens_per_minute: 10_000,
        },
    );
    config.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state_with_distributed(&config, directory.path()).await;
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(
            r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":true}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .expect("decode stream should start before idle timeout")
        .unwrap();

    let mut body = response.bytes_stream();
    let first = body.next().await.unwrap().unwrap();
    assert!(
        first
            .windows(b"partial P/D".len())
            .any(|w| w == b"partial P/D"),
        "client must observe the first OpenAI SSE chunk before idle timeout"
    );

    let limited = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(
        limited.json::<Value>().await.unwrap()["error"]["code"],
        "concurrency_limit_exceeded"
    );

    assert!(tokio::time::timeout(Duration::from_secs(2), body.next())
        .await
        .expect("idle timeout should end the downstream body")
        .unwrap()
        .is_err());
    drop(body);

    tokio::time::timeout(Duration::from_secs(2), prefill_abort)
        .await
        .expect("prefill must receive abort after stream idle timeout")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_abort)
        .await
        .expect("decode must receive abort after stream idle timeout")
        .unwrap();

    let admitted = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = client
                .get(format!("http://{address}/v1/models"))
                .bearer_auth(&key)
                .send()
                .await
                .unwrap();
            if response.status() == 200 {
                return response;
            }
            assert_eq!(response.status(), 429);
            assert_eq!(
                response.json::<Value>().await.unwrap()["error"]["code"],
                "concurrency_limit_exceeded"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("concurrency permit must release after P/D SSE idle timeout");
    assert_eq!(admitted.status(), 200);

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[2]["kind"], "attempt_terminal");
    assert_eq!(events[2]["outcome"], "failed");
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "failed");
    assert_eq!(spool.status().reserved_bytes, 0);

    stop_test_entrypoint(shutdown_tx, gateway_task).await;
    spool.shutdown().await;
}

async fn spawn_holding_power_pair_for_execution_timeout() -> (
    SocketAddr,
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let (prepare_started_tx, prepare_started_rx) = tokio::sync::oneshot::channel();
    let (prefill_abort_tx, prefill_abort_rx) = tokio::sync::oneshot::channel();
    let (decode_abort_tx, decode_abort_rx) = tokio::sync::oneshot::channel();

    let prefill_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let prefill_address = prefill_listener.local_addr().unwrap();
    let decode_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decode_address = decode_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let mut prefill_abort_tx = Some(prefill_abort_tx);
        loop {
            let (mut stream, _) = prefill_listener.accept().await.unwrap();
            let request = read_power_request(&mut stream).await;
            match request.path.as_str() {
                "/internal/v1/distributed-serving/abort" => {
                    write_json(&mut stream, abort_response(&request)).await;
                    if let Some(tx) = prefill_abort_tx.take() {
                        let _ = tx.send(());
                    }
                    break;
                }
                path => panic!("unexpected prefill path before abort: {path}"),
            }
        }
    });

    tokio::spawn(async move {
        let mut abort_sent = false;
        let mut prepare_seen = false;
        let mut prepare_started_tx = Some(prepare_started_tx);
        let mut decode_abort_tx = Some(decode_abort_tx);
        while !(abort_sent && prepare_seen) {
            let (mut stream, _) = decode_listener.accept().await.unwrap();
            let request = read_power_request(&mut stream).await;
            match request.path.as_str() {
                "/internal/v1/distributed-serving/decode/prepare" => {
                    prepare_seen = true;
                    let started = prepare_started_tx.take().expect("decode prepare once");
                    // Hold prepare off the accept loop so /abort can arrive while
                    // the execution deadline expires without a response body.
                    tokio::spawn(async move {
                        let _ = started.send(());
                        let mut buffer = [0_u8; 1];
                        loop {
                            match stream.read(&mut buffer).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    });
                }
                "/internal/v1/distributed-serving/abort" => {
                    write_json(&mut stream, abort_response(&request)).await;
                    abort_sent = true;
                    if let Some(tx) = decode_abort_tx.take() {
                        let _ = tx.send(());
                    }
                }
                path => panic!("unexpected decode path {path}"),
            }
        }
    });

    (
        prefill_address,
        decode_address,
        prepare_started_rx,
        prefill_abort_rx,
        decode_abort_rx,
    )
}

#[tokio::test]
async fn managed_distributed_execution_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals(
) {
    let key = inference_key('m');
    let (prefill_address, decode_address, prepare_started, prefill_abort, decode_abort) =
        spawn_holding_power_pair_for_execution_timeout().await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    let distributed = config
        .inference
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap()
        .models
        .get_mut("allowed-model")
        .unwrap()
        .scheduling
        .as_mut()
        .unwrap()
        .distributed_serving
        .as_mut()
        .unwrap();
    distributed.execution_timeout_ms = 50;
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 600,
            request_burst: 10,
            tokens_per_minute: 10_000,
        },
    );
    config.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state_with_distributed(&config, directory.path()).await;
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();

    let chat = {
        let client = client.clone();
        let key = key.clone();
        let address = address;
        tokio::spawn(async move {
            client
                .post(format!("http://{address}/v1/chat/completions"))
                .bearer_auth(&key)
                .header("content-type", "application/json")
                .body(
                    r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":true}"#,
                )
                .send()
                .await
        })
    };

    tokio::time::timeout(Duration::from_secs(2), prepare_started)
        .await
        .expect("decode prepare should start before execution timeout")
        .unwrap();

    let limited = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(
        limited.json::<Value>().await.unwrap()["error"]["code"],
        "concurrency_limit_exceeded"
    );

    let response = tokio::time::timeout(Duration::from_secs(5), chat)
        .await
        .expect("execution timeout should complete the client request")
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    let body = response.json::<Value>().await.unwrap();
    assert_eq!(body["error"]["code"], "distributed_inference_timeout");

    tokio::time::timeout(Duration::from_secs(2), prefill_abort)
        .await
        .expect("prefill must receive abort after execution timeout")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_abort)
        .await
        .expect("decode must receive abort after execution timeout")
        .unwrap();

    let admitted = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = client
                .get(format!("http://{address}/v1/models"))
                .bearer_auth(&key)
                .send()
                .await
                .unwrap();
            if response.status() == 200 {
                return response;
            }
            assert_eq!(response.status(), 429);
            assert_eq!(
                response.json::<Value>().await.unwrap()["error"]["code"],
                "concurrency_limit_exceeded"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("concurrency permit must release after P/D execution timeout");
    assert_eq!(admitted.status(), 200);

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[2]["kind"], "attempt_terminal");
    assert_eq!(events[2]["outcome"], "failed");
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "failed");
    assert_eq!(spool.status().reserved_bytes, 0);

    stop_test_entrypoint(shutdown_tx, gateway_task).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_distributed_sse_total_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals(
) {
    let key = inference_key('n');
    let (prefill_address, decode_address, stream_started, prefill_abort, decode_abort) =
        spawn_dripping_power_pair_for_total_timeout().await;
    let mut config = inference_config(decode_address, &key, Utc::now() + ChronoDuration::hours(1));
    enable_distributed_scheduling(&mut config, prefill_address, decode_address);
    let service = config.services.get_mut("model-service").unwrap();
    // Idle is long enough that 5ms Power drips never trip it; total is the
    // wall-clock bound from request start that must win on an active stream.
    // Budget includes prepare/prefill/decode startup so the first SSE chunk is
    // observed before the total deadline.
    service.load_balancer.stream_idle_timeout = "2s".into();
    service.load_balancer.stream_total_timeout = "400ms".into();
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 600,
            request_burst: 10,
            tokens_per_minute: 10_000,
        },
    );
    config.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state_with_distributed(&config, directory.path()).await;
    let (address, shutdown_tx, gateway_task) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(
            r#"{"model":"allowed-model","messages":[{"role":"user","content":"private entrypoint prompt"}],"stream":true}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .expect("decode stream should start before total timeout")
        .unwrap();

    let mut body = response.bytes_stream();
    let first = body.next().await.unwrap().unwrap();
    assert!(
        first
            .windows(b"partial P/D".len())
            .any(|w| w == b"partial P/D"),
        "client must observe the first OpenAI SSE chunk before total timeout"
    );

    let limited = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(
        limited.json::<Value>().await.unwrap()["error"]["code"],
        "concurrency_limit_exceeded"
    );

    // Keep reading while Power drips; total timeout must end the body despite
    // active chunks refreshing the idle deadline.
    let mut saw_drip = false;
    let mut saw_error = false;
    for _ in 0..128 {
        match tokio::time::timeout(Duration::from_secs(2), body.next()).await {
            Ok(Some(Ok(chunk))) => {
                if chunk.windows(b"drip-".len()).any(|w| w == b"drip-") {
                    saw_drip = true;
                }
            }
            Ok(Some(Err(_))) => {
                saw_error = true;
                break;
            }
            Ok(None) => panic!("stream ended cleanly; expected total timeout error"),
            Err(_) => panic!("timed out waiting for stream_total_timeout"),
        }
    }
    assert!(
        saw_drip,
        "Power must keep dripping after the first chunk so idle cannot explain the failure"
    );
    assert!(
        saw_error,
        "stream_total_timeout must fail the downstream body"
    );
    drop(body);

    tokio::time::timeout(Duration::from_secs(2), prefill_abort)
        .await
        .expect("prefill must receive abort after stream total timeout")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), decode_abort)
        .await
        .expect("decode must receive abort after stream total timeout")
        .unwrap();

    let admitted = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let response = client
                .get(format!("http://{address}/v1/models"))
                .bearer_auth(&key)
                .send()
                .await
                .unwrap();
            if response.status() == 200 {
                return response;
            }
            assert_eq!(response.status(), 429);
            assert_eq!(
                response.json::<Value>().await.unwrap()["error"]["code"],
                "concurrency_limit_exceeded"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("concurrency permit must release after P/D SSE total timeout");
    assert_eq!(admitted.status(), 200);

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[2]["kind"], "attempt_terminal");
    assert_eq!(events[2]["outcome"], "failed");
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "failed");
    assert_eq!(spool.status().reserved_bytes, 0);

    stop_test_entrypoint(shutdown_tx, gateway_task).await;
    spool.shutdown().await;
}
