use super::inference_tests::{
    gateway_state, inference_config, inference_key, read_http_request, set_limits,
    spawn_blocking_backend, spawn_capturing_backend, spawn_streaming_backend,
    start_test_entrypoint, stop_test_entrypoint,
};
use crate::config::InferenceLimitsConfig;
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

async fn spawn_dripping_streaming_backend() -> (
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
                let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                if stream.write_all(headers.as_bytes()).await.is_err() {
                    return;
                }
                let mut buffer = [0_u8; 1];
                let mut sequence = 0_u64;
                loop {
                    let payload = format!("data: drip-{sequence}\n\n");
                    let chunk = format!("{:x}\r\n{payload}\r\n", payload.len());
                    if stream.write_all(chunk.as_bytes()).await.is_err() {
                        break;
                    }
                    if stream.flush().await.is_err() {
                        break;
                    }
                    if sequence == 0 {
                        let _ = started_tx.send(());
                    }
                    sequence = sequence.saturating_add(1);
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_millis(20)) => {}
                        read = stream.read(&mut buffer) => {
                            match read {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    }
                }
                let _ = disconnected_tx.send(());
            });
        }
    });

    (address, started_rx, disconnected_rx)
}

async fn spawn_capturing_backend_with_json_body(
    body: &'static str,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

async fn spawn_sse_backend_with_body(
    body: String,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

fn sse_body_with_terminal_usage(padding_bytes: usize, total_tokens: u64) -> String {
    let padding_line = "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n";
    let mut body = String::new();
    while body.len() < padding_bytes {
        body.push_str(padding_line);
    }
    body.push_str(&format!(
        "data: {{\"usage\":{{\"prompt_tokens\":10,\"completion_tokens\":32,\"total_tokens\":{total_tokens}}}}}\n\ndata: [DONE]\n\n"
    ));
    body
}

async fn spawn_repeating_sse_backend_with_body(body: String) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let body = body.clone();
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    address
}

async fn spawn_repeating_json_backend_with_body(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = read_http_request(&mut stream).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    address
}

async fn spawn_json_backend_with_owned_body(
    body: String,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

fn large_json_completion_with_terminal_usage(padding_bytes: usize, total_tokens: u64) -> String {
    let mut body = String::from(
        r#"{"id":"chatcmpl-large","object":"chat.completion","choices":[{"message":{"role":"assistant","content":""#,
    );
    while body.len() < padding_bytes {
        body.push('x');
    }
    body.push_str(&format!(
        r#""}}],"usage":{{"prompt_tokens":2,"completion_tokens":3,"total_tokens":{total_tokens}}}}}"#
    ));
    body
}

#[tokio::test]
async fn managed_inference_persists_upstream_usage_on_request_terminal() {
    const PROMPT_MARKER: &str = "prompt-must-never-enter-usage-with-tokens";
    const TOTAL_TOKENS: u64 = 42;

    let key = inference_key('x');
    let (backend, captured_request) = spawn_capturing_backend_with_json_body(
        r#"{"id":"chatcmpl-test","object":"chat.completion","choices":[],"usage":{"prompt_tokens":10,"completion_tokens":32,"total_tokens":42}}"#,
    )
    .await;
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
    let body = response.bytes().await.unwrap();
    assert!(body
        .windows(b"total_tokens".len())
        .any(|w| w == b"total_tokens"));
    let _ = captured_request.await.unwrap();

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "succeeded");
    assert_eq!(events[3]["measurement_completeness"], "upstream_usage");
    assert_eq!(events[3]["total_tokens"], TOTAL_TOKENS);

    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains(PROMPT_MARKER));
    assert!(!serialized.contains(&key));
    assert!(!serialized.contains("messages"));

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_sse_persists_upstream_usage_on_request_terminal() {
    const PROMPT_MARKER: &str = "prompt-must-never-enter-sse-usage";
    const TOTAL_TOKENS: u64 = 42;

    let key = inference_key('s');
    let body = sse_body_with_terminal_usage(0, TOTAL_TOKENS);
    let (backend, captured_request) = spawn_sse_backend_with_body(body).await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state(&config, directory.path(), 1024 * 1024).await;
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"model":"allowed-model","messages":[{{"role":"user","content":"{PROMPT_MARKER}"}}],"stream":true}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    let response_body = response.bytes().await.unwrap();
    assert!(response_body
        .windows(b"total_tokens".len())
        .any(|w| w == b"total_tokens"));
    let _ = captured_request.await.unwrap();

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "succeeded");
    assert_eq!(events[3]["measurement_completeness"], "upstream_usage");
    assert_eq!(events[3]["total_tokens"], TOTAL_TOKENS);

    let serialized = serde_json::to_string(&events).unwrap();
    assert!(!serialized.contains(PROMPT_MARKER));
    assert!(!serialized.contains(&key));
    assert!(!serialized.contains("messages"));

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_sse_persists_upstream_usage_after_body_exceeds_json_prefix_budget() {
    const TOTAL_TOKENS: u64 = 77;
    // Exceed the JSON prefix observe budget so terminal SSE usage cannot rely
    // on a whole-body prefix buffer.
    const PADDING_BYTES: usize = 256 * 1024 + 4096;

    let key = inference_key('p');
    let body = sse_body_with_terminal_usage(PADDING_BYTES, TOTAL_TOKENS);
    let (backend, captured_request) = spawn_sse_backend_with_body(body).await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state(&config, directory.path(), 4 * 1024 * 1024).await;
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.bytes().await.unwrap();
    assert!(response_body.len() > PADDING_BYTES);
    let _ = captured_request.await.unwrap();

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "succeeded");
    assert_eq!(events[3]["measurement_completeness"], "upstream_usage");
    assert_eq!(events[3]["total_tokens"], TOTAL_TOKENS);

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_sse_upstream_usage_reconciles_token_budget_for_follow_up_request() {
    // Reserve max_tokens=30 against TPM=40. Without upstream usage reconcile the
    // provisional charge blocks a second identical reservation; with SSE usage
    // total_tokens=5 the unused reservation is refunded and the follow-up admits.
    const OBSERVED_TOTAL_TOKENS: u64 = 5;

    let key = inference_key('r');
    let body = sse_body_with_terminal_usage(0, OBSERVED_TOTAL_TOKENS);
    let backend = spawn_repeating_sse_backend_with_body(body).await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
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
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();
    let request_body = r#"{"model":"allowed-model","messages":[{"role":"user","content":"hi"}],"max_tokens":30,"stream":true}"#;

    let first = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let first_body = first.bytes().await.unwrap();
    assert!(first_body
        .windows(b"total_tokens".len())
        .any(|w| w == b"total_tokens"));

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
        200,
        "SSE upstream usage must reconcile the provisional token reservation"
    );
    let _ = second.bytes().await.unwrap();

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_json_upstream_usage_reconciles_token_budget_for_follow_up_request() {
    // Mirror the SSE reconcile lock for non-streaming JSON completions.
    const OBSERVED_TOTAL_TOKENS: u64 = 5;

    let key = inference_key('j');
    let backend = spawn_repeating_json_backend_with_body(
        r#"{"id":"chatcmpl-test","object":"chat.completion","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":3,"total_tokens":5}}"#,
    )
    .await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
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
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();
    let request_body =
        r#"{"model":"allowed-model","messages":[{"role":"user","content":"hi"}],"max_tokens":30}"#;

    let first = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let first_body = first.bytes().await.unwrap();
    assert!(
        first_body
            .windows(b"\"total_tokens\":5".len())
            .any(|w| w == b"\"total_tokens\":5"),
        "upstream JSON must carry observed total_tokens={OBSERVED_TOTAL_TOKENS}"
    );

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
        200,
        "JSON upstream usage must reconcile the provisional token reservation"
    );
    let _ = second.bytes().await.unwrap();

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_json_persists_upstream_usage_after_body_exceeds_json_prefix_budget() {
    const TOTAL_TOKENS: u64 = 91;
    const PADDING_BYTES: usize = 256 * 1024 + 4096;

    let key = inference_key('l');
    let body = large_json_completion_with_terminal_usage(PADDING_BYTES, TOTAL_TOKENS);
    let (backend, captured_request) = spawn_json_backend_with_owned_body(body).await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) = usage_state(&config, directory.path(), 4 * 1024 * 1024).await;
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"max_tokens":16}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response_body = response.bytes().await.unwrap();
    assert!(response_body.len() > PADDING_BYTES);
    let _ = captured_request.await.unwrap();

    let events = lifecycle_events(&spool, 4).await;
    assert_eq!(events[3]["kind"], "request_terminal");
    assert_eq!(events[3]["outcome"], "succeeded");
    assert_eq!(events[3]["measurement_completeness"], "upstream_usage");
    assert_eq!(events[3]["total_tokens"], TOTAL_TOKENS);

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}

#[tokio::test]
async fn managed_sse_without_usage_keeps_provisional_token_reservation_charged() {
    let key = inference_key('q');
    let body =
        "data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n\n".to_string();
    let backend = spawn_repeating_sse_backend_with_body(body).await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
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
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();
    let request_body = r#"{"model":"allowed-model","messages":[{"role":"user","content":"hi"}],"max_tokens":30,"stream":true}"#;

    let first = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let _ = first.bytes().await.unwrap();

    let second = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 429);
    assert_eq!(
        second.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "rate_limit_exceeded"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_json_without_usage_keeps_provisional_token_reservation_charged() {
    // Symmetric with managed_sse_without_usage_keeps_provisional_token_reservation_charged:
    // a completed JSON body without usage must not invent a refund.
    let key = inference_key('n');
    let backend = spawn_repeating_json_backend_with_body(
        r#"{"id":"chatcmpl-test","object":"chat.completion","choices":[]}"#,
    )
    .await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
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
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();
    let request_body =
        r#"{"model":"allowed-model","messages":[{"role":"user","content":"hi"}],"max_tokens":30}"#;

    let first = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);
    let _ = first.bytes().await.unwrap();

    let second = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 429);
    assert_eq!(
        second.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "rate_limit_exceeded"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
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
async fn managed_sse_total_timeout_releases_admission_and_persists_failed_terminals() {
    let key = inference_key('u');
    let (backend, mut started, mut disconnected) = spawn_dripping_streaming_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let service = config.services.get_mut("model-service").unwrap();
    // Idle is long enough that 20ms drips never trip it; total is the wall-clock
    // bound from request start that must win on an active stream.
    service.load_balancer.stream_idle_timeout = "2s".into();
    service.load_balancer.stream_total_timeout = "500ms".into();
    let route = config
        .inference
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap();
    route.grants.values_mut().next().unwrap().limits = InferenceLimitsConfig {
        max_concurrent_requests: 1,
        requests_per_minute: 600,
        request_burst: 10,
        tokens_per_minute: 10_000,
    };
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
            .windows(b"drip-".len())
            .any(|window| window == b"drip-"),
        "client must observe the first SSE drip before total timeout"
    );

    let limited = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(
        limited.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "concurrency_limit_exceeded"
    );

    let mut saw_drip = false;
    let mut saw_error = false;
    for _ in 0..128 {
        match tokio::time::timeout(Duration::from_secs(2), body.next()).await {
            Ok(Some(Ok(chunk))) => {
                if chunk
                    .windows(b"drip-".len())
                    .any(|window| window == b"drip-")
                {
                    saw_drip = true;
                }
            }
            Ok(Some(Err(_))) => {
                saw_error = true;
                break;
            }
            Ok(None) => panic!("stream ended cleanly; expected stream_total_timeout error"),
            Err(_) => panic!("timed out waiting for stream_total_timeout"),
        }
    }
    assert!(
        saw_drip,
        "upstream must keep dripping so idle cannot explain the failure"
    );
    assert!(
        saw_error,
        "stream_total_timeout must fail the downstream body"
    );
    drop(body);

    tokio::time::timeout(Duration::from_secs(2), disconnected.recv())
        .await
        .expect("upstream must disconnect after total timeout")
        .unwrap();
    assert_eq!(selected_backend.connections(), 0);

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
                response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
                "concurrency_limit_exceeded"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("concurrency permit must release after aggregated SSE total timeout");
    assert_eq!(admitted.status(), 200);

    let events = lifecycle_events(&spool, 4).await;
    let terminals = events
        .iter()
        .filter(|event| {
            matches!(
                event["kind"].as_str(),
                Some("attempt_terminal" | "request_terminal")
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(terminals.len(), 2);
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
