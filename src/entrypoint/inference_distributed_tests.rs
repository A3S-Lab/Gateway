use super::inference_tests::{
    gateway_state_with_distributed_key, inference_config, inference_key, read_http_request,
    start_test_entrypoint, stop_test_entrypoint,
};
use crate::config::{
    GatewayConfig, InferenceDistributedServingConfig, InferencePhaseRole,
    InferenceSchedulingConfig, InferenceTransferHealth, InferenceWorkerConfig, ManagedTargetConfig,
    ServerConfig, POWER_WORKER_OBSERVATION_SCHEMA,
};
use chrono::{Duration as ChronoDuration, Utc};
use http::StatusCode;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::new()));
    let task_records = records.clone();
    let expected_requests = match role {
        WorkerRole::Prefill => 2,
        WorkerRole::Decode => 3,
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
                    write_decode_stream(&mut stream, &request).await;
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
