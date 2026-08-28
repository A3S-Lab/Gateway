use super::contract::{
    ProtocolBinding, RecomputeReason, TerminalFailureReason, DISTRIBUTED_SERVING_SCHEMA,
    DISTRIBUTED_SERVING_STREAM_SCHEMA,
};
use super::orchestrator::{
    DistributedExecutionRequest, DistributedInferenceResponse, DistributedServingError,
    DistributedServingOrchestrator, DistributedWorkerEndpoint,
};
use super::response::StreamContractError;
use crate::config::InferenceEndpoint;
use bytes::Bytes;
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use uuid::Uuid;

const KEY_ENV: &str = "A3S_POWER_TEST_KEY";
const API_KEY: &str = "power-internal-secret";
const PREFILL_PROFILE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DECODE_PROFILE: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

#[derive(Debug)]
struct CapturedRequest {
    path: String,
    authorization: Option<String>,
    body: Value,
}

fn bindings() -> (ProtocolBinding, ProtocolBinding) {
    let execution_id = Uuid::from_u128(11);
    (
        ProtocolBinding {
            execution_id,
            worker_epoch: Uuid::from_u128(21),
            execution_profile_sha256: PREFILL_PROFILE.to_string(),
        },
        ProtocolBinding {
            execution_id,
            worker_epoch: Uuid::from_u128(22),
            execution_profile_sha256: DECODE_PROFILE.to_string(),
        },
    )
}

async fn read_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let (header_end, body_length) = loop {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
        if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let body_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or_default();
            break (header_end, body_length);
        }
    };
    let expected = header_end + 4 + body_length;
    while request.len() < expected {
        let read = stream.read(&mut buffer).await.unwrap();
        assert!(read > 0);
        request.extend_from_slice(&buffer[..read]);
    }
    let headers = String::from_utf8_lossy(&request[..header_end]);
    let path = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap()
        .to_string();
    let authorization = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("authorization")
            .then(|| value.trim().to_string())
    });
    let body = serde_json::from_slice(&request[header_end + 4..expected]).unwrap();
    CapturedRequest {
        path,
        authorization,
        body,
    }
}

async fn write_json(stream: &mut TcpStream, status: &str, body: Value) {
    let body = serde_json::to_vec(&body).unwrap();
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
    stream.shutdown().await.unwrap();
}

async fn write_ndjson(stream: &mut TcpStream, body: &str, trailing_data: bool) {
    let trailing = if trailing_data { "{}\n" } else { "" };
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len() + trailing.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    if trailing_data {
        stream.flush().await.unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        stream.write_all(trailing.as_bytes()).await.unwrap();
    }
    stream.shutdown().await.unwrap();
}

fn phase_response(binding: &ProtocolBinding, outcome: Value) -> Value {
    json!({
        "schema": DISTRIBUTED_SERVING_SCHEMA,
        "execution_id": binding.execution_id,
        "worker_epoch": binding.worker_epoch,
        "execution_profile_sha256": binding.execution_profile_sha256,
        "outcome": outcome
    })
}

fn abort_response(request: &CapturedRequest) -> Value {
    json!({
        "schema": DISTRIBUTED_SERVING_SCHEMA,
        "execution_id": request.body["execution_id"],
        "worker_epoch": request.body["worker_epoch"],
        "execution_profile_sha256": request.body["execution_profile_sha256"],
        "accepted": true
    })
}

async fn spawn_decode_worker(
    binding: ProtocolBinding,
    records: Arc<Mutex<Vec<CapturedRequest>>>,
    trailing_data: bool,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(
                request.authorization.as_deref(),
                Some("Bearer power-internal-secret")
            );
            match request.path.as_str() {
                "/internal/v1/distributed-serving/decode/prepare" => {
                    assert_eq!(
                        request.body["request"]["body"]["messages"][0]["content"],
                        "private prompt"
                    );
                    write_json(
                        &mut stream,
                        "200 OK",
                        phase_response(
                            &binding,
                            json!({
                                "decision": "ready",
                                "result": {"target": {"protocol": "memory", "nonce": "decode-target"}}
                            }),
                        ),
                    )
                    .await;
                }
                "/internal/v1/distributed-serving/decode/execute" => {
                    assert_eq!(request.body["source"]["nonce"], "prefill-source");
                    let frames = [
                        json!({
                            "schema": DISTRIBUTED_SERVING_STREAM_SCHEMA,
                            "execution_id": binding.execution_id,
                            "worker_epoch": binding.worker_epoch,
                            "execution_profile_sha256": binding.execution_profile_sha256,
                            "payload": {"event": "ready"}
                        }),
                        json!({
                            "schema": DISTRIBUTED_SERVING_STREAM_SCHEMA,
                            "execution_id": binding.execution_id,
                            "worker_epoch": binding.worker_epoch,
                            "execution_profile_sha256": binding.execution_profile_sha256,
                            "payload": {
                                "event": "chunk",
                                "sequence": 0,
                                "response": {
                                    "endpoint": "chat-completions",
                                    "chunk": {
                                        "content": "hello from P/D",
                                        "done": true,
                                        "prompt_tokens": 4,
                                        "done_reason": "stop"
                                    }
                                }
                            }
                        }),
                        json!({
                            "schema": DISTRIBUTED_SERVING_STREAM_SCHEMA,
                            "execution_id": binding.execution_id,
                            "worker_epoch": binding.worker_epoch,
                            "execution_profile_sha256": binding.execution_profile_sha256,
                            "payload": {"event": "completed", "sequence": 1}
                        }),
                    ]
                    .into_iter()
                    .map(|frame| serde_json::to_string(&frame).unwrap())
                    .collect::<Vec<_>>()
                    .join("\n")
                        + "\n";
                    write_ndjson(&mut stream, &frames, trailing_data).await;
                }
                "/internal/v1/distributed-serving/abort" => {
                    let response = abort_response(&request);
                    write_json(&mut stream, "200 OK", response).await;
                }
                path => panic!("unexpected decode path {path}"),
            }
            records.lock().unwrap().push(request);
        }
    });
    (format!("http://{address}"), handle)
}

async fn spawn_prefill_worker(
    binding: ProtocolBinding,
    records: Arc<Mutex<Vec<CapturedRequest>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await;
            assert_eq!(
                request.authorization.as_deref(),
                Some("Bearer power-internal-secret")
            );
            match request.path.as_str() {
                "/internal/v1/distributed-serving/prefill/execute" => {
                    assert_eq!(request.body["target"]["nonce"], "decode-target");
                    write_json(
                        &mut stream,
                        "200 OK",
                        phase_response(
                            &binding,
                            json!({
                                "decision": "ready",
                                "result": {"source": {"protocol": "memory", "nonce": "prefill-source"}}
                            }),
                        ),
                    )
                    .await;
                }
                "/internal/v1/distributed-serving/abort" => {
                    let response = abort_response(&request);
                    write_json(&mut stream, "200 OK", response).await;
                }
                path => panic!("unexpected prefill path {path}"),
            }
            records.lock().unwrap().push(request);
        }
    });
    (format!("http://{address}"), handle)
}

async fn setup(
    trailing_data: bool,
) -> (
    DistributedServingOrchestrator,
    DistributedExecutionRequest,
    Arc<Mutex<Vec<CapturedRequest>>>,
    Arc<Mutex<Vec<CapturedRequest>>>,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let (prefill_binding, decode_binding) = bindings();
    let prefill_records = Arc::new(Mutex::new(Vec::new()));
    let decode_records = Arc::new(Mutex::new(Vec::new()));
    let (prefill_url, prefill_task) =
        spawn_prefill_worker(prefill_binding.clone(), prefill_records.clone()).await;
    let (decode_url, decode_task) = spawn_decode_worker(
        decode_binding.clone(),
        decode_records.clone(),
        trailing_data,
    )
    .await;
    let request = DistributedExecutionRequest {
        execution_id: decode_binding.execution_id,
        endpoint: InferenceEndpoint::ChatCompletions,
        external_model: "public-model".to_string(),
        body: Bytes::from_static(
            br#"{"model":"internal/model-v1","messages":[{"role":"user","content":"private prompt"}],"stream":false}"#,
        ),
        stream: false,
        api_key_env: KEY_ENV.to_string(),
        execution_timeout_ms: 5_000,
        prefill: DistributedWorkerEndpoint {
            url: prefill_url,
            binding: prefill_binding,
        },
        decode: DistributedWorkerEndpoint {
            url: decode_url,
            binding: decode_binding,
        },
    };
    (
        DistributedServingOrchestrator::with_test_key(KEY_ENV, API_KEY),
        request,
        prefill_records,
        decode_records,
        prefill_task,
        decode_task,
    )
}

#[tokio::test]
async fn orchestrator_executes_three_phases_translates_buffered_output_and_cleans_both_workers() {
    let (orchestrator, request, prefill_records, decode_records, prefill_task, decode_task) =
        setup(false).await;
    let debug = format!("{request:?}");
    assert!(!debug.contains("private prompt"));

    let DistributedInferenceResponse::Buffered(body) = orchestrator.execute(request).await.unwrap()
    else {
        panic!("expected buffered response");
    };
    let response: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(response["object"], "chat.completion");
    assert_eq!(response["model"], "public-model");
    assert_eq!(
        response["choices"][0]["message"]["content"],
        "hello from P/D"
    );

    timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        prefill_records
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.path.as_str())
            .collect::<Vec<_>>(),
        [
            "/internal/v1/distributed-serving/prefill/execute",
            "/internal/v1/distributed-serving/abort"
        ]
    );
    assert_eq!(
        decode_records
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.path.as_str())
            .collect::<Vec<_>>(),
        [
            "/internal/v1/distributed-serving/decode/prepare",
            "/internal/v1/distributed-serving/decode/execute",
            "/internal/v1/distributed-serving/abort"
        ]
    );
}

#[tokio::test]
async fn streaming_response_is_backpressured_openai_sse_and_cleans_after_completion() {
    let (orchestrator, mut request, _, _, prefill_task, decode_task) = setup(false).await;
    request.stream = true;
    let DistributedInferenceResponse::Streaming(mut stream) =
        orchestrator.execute(request).await.unwrap()
    else {
        panic!("expected streaming response");
    };
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk.unwrap());
    }
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains("\"object\":\"chat.completion.chunk\""));
    assert!(body.contains("hello from P/D"));
    assert!(body.ends_with("data: [DONE]\n\n"));
    timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn buffered_response_rejects_data_after_the_completed_frame() {
    let (orchestrator, request, _, _, prefill_task, decode_task) = setup(true).await;
    let error = orchestrator.execute(request).await.unwrap_err();
    assert_eq!(
        error,
        DistributedServingError::Stream(StreamContractError::InvalidSequence)
    );
    timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn streaming_response_withholds_done_when_data_follows_completion() {
    let (orchestrator, mut request, _, _, prefill_task, decode_task) = setup(true).await;
    request.stream = true;
    let DistributedInferenceResponse::Streaming(mut stream) =
        orchestrator.execute(request).await.unwrap()
    else {
        panic!("expected streaming response");
    };
    let mut body = Vec::new();
    let mut failed = false;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(chunk) => body.extend_from_slice(&chunk),
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    assert!(failed);
    assert!(!body.ends_with(b"data: [DONE]\n\n"));
    timeout(Duration::from_secs(2), prefill_task)
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), decode_task)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn only_closed_pre_response_failures_are_retryable() {
    let recompute = DistributedServingError::Recompute(RecomputeReason::Stale);
    assert!(recompute.retryable_before_response());
    assert_eq!(recompute.status_code(), 503);

    let terminal = DistributedServingError::Terminal(TerminalFailureReason::PolicyViolation);
    assert!(!terminal.retryable_before_response());
    assert_eq!(terminal.status_code(), 502);
}
