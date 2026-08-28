use super::client::{api_key_is_valid_for_test, PowerClientError, PowerDistributedClient};
use super::contract::{
    DecodePrepareRequest, PhaseDecision, PhaseRequestPayload, ProtocolBinding, ProtocolErrorCode,
    DISTRIBUTED_SERVING_SCHEMA,
};
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};
use uuid::Uuid;

const KEY_ENV: &str = "A3S_POWER_TEST_KEY";
const API_KEY: &str = "power-internal-secret";
const PROFILE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn binding() -> ProtocolBinding {
    ProtocolBinding {
        execution_id: Uuid::from_u128(1),
        worker_epoch: Uuid::from_u128(2),
        execution_profile_sha256: PROFILE.to_string(),
    }
}

fn request(binding: &ProtocolBinding) -> DecodePrepareRequest {
    DecodePrepareRequest {
        schema: DISTRIBUTED_SERVING_SCHEMA,
        execution_id: binding.execution_id,
        worker_epoch: binding.worker_epoch,
        execution_profile_sha256: binding.execution_profile_sha256.clone(),
        expires_at: Utc::now() + ChronoDuration::seconds(30),
        request: PhaseRequestPayload::ChatCompletions {
            body: json!({
                "model": "internal/model-v1",
                "messages": [{"role": "user", "content": "private prompt"}]
            }),
        },
    }
}

fn phase_response(binding: &ProtocolBinding, outcome: serde_json::Value) -> String {
    json!({
        "schema": DISTRIBUTED_SERVING_SCHEMA,
        "execution_id": binding.execution_id,
        "worker_epoch": binding.worker_epoch,
        "execution_profile_sha256": binding.execution_profile_sha256,
        "outcome": outcome
    })
    .to_string()
}

fn http_response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn one_shot_server(response: Vec<u8>) -> (String, oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (captured_tx, captured_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let mut expected = None;
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            if expected.is_none() {
                if let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or_default();
                    expected = Some(header_end + 4 + length);
                }
            }
            if expected.is_some_and(|expected| request.len() >= expected) {
                break;
            }
        }
        let _ = captured_tx.send(request);
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    (format!("http://{address}/ignored/base"), captured_rx)
}

#[tokio::test]
async fn prepare_decode_uses_exact_path_auth_and_binding_without_logging_secrets() {
    let binding = binding();
    let response = phase_response(
        &binding,
        json!({"decision": "ready", "result": {"target": {"kind": "memory", "token": "opaque"}}}),
    );
    let (base_url, captured) = one_shot_server(http_response(
        "200 OK",
        "application/json; charset=utf-8",
        &response,
    ))
    .await;
    let client = PowerDistributedClient::with_test_key(KEY_ENV, API_KEY);

    let outcome = client
        .prepare_decode(
            &base_url,
            KEY_ENV,
            Instant::now() + Duration::from_secs(2),
            &request(&binding),
            &binding,
        )
        .await
        .unwrap();
    assert!(matches!(outcome, PhaseDecision::Ready { .. }));

    let request = String::from_utf8(captured.await.unwrap()).unwrap();
    assert!(
        request.starts_with("POST /internal/v1/distributed-serving/decode/prepare HTTP/1.1\r\n")
    );
    assert!(request
        .to_ascii_lowercase()
        .contains(&format!("authorization: bearer {API_KEY}").to_ascii_lowercase()));
    assert!(request.contains("private prompt"));
    let debug = format!(
        "{client:?} {:?}",
        super::client::PowerClientError::Transport
    );
    assert!(!debug.contains(API_KEY));
    assert!(!debug.contains("private prompt"));
}

#[tokio::test]
async fn client_rejects_mismatched_binding_and_oversized_json() {
    let binding = binding();
    let mut wrong = binding.clone();
    wrong.worker_epoch = Uuid::from_u128(99);
    let response = phase_response(
        &wrong,
        json!({"decision": "ready", "result": {"target": {"kind": "memory"}}}),
    );
    let (base_url, _) =
        one_shot_server(http_response("200 OK", "application/json", &response)).await;
    let client = PowerDistributedClient::with_test_key(KEY_ENV, API_KEY);
    assert_eq!(
        client
            .prepare_decode(
                &base_url,
                KEY_ENV,
                Instant::now() + Duration::from_secs(2),
                &request(&binding),
                &binding,
            )
            .await
            .unwrap_err(),
        PowerClientError::InvalidResponse
    );

    let response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 999999\r\nConnection: close\r\n\r\n".to_vec();
    let (base_url, _) = one_shot_server(response).await;
    assert_eq!(
        client
            .prepare_decode(
                &base_url,
                KEY_ENV,
                Instant::now() + Duration::from_secs(2),
                &request(&binding),
                &binding,
            )
            .await
            .unwrap_err(),
        PowerClientError::ResponseTooLarge
    );
}

#[tokio::test]
async fn client_does_not_follow_redirects_and_classifies_protocol_errors() {
    let binding = binding();
    let redirect = b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/leak\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec();
    let (base_url, _) = one_shot_server(redirect).await;
    let client = PowerDistributedClient::with_test_key(KEY_ENV, API_KEY);
    assert_eq!(
        client
            .prepare_decode(
                &base_url,
                KEY_ENV,
                Instant::now() + Duration::from_secs(2),
                &request(&binding),
                &binding,
            )
            .await
            .unwrap_err(),
        PowerClientError::UnsupportedMediaType
    );

    let body = json!({
        "schema": DISTRIBUTED_SERVING_SCHEMA,
        "code": "stale-worker",
        "message": "content-free stable error"
    })
    .to_string();
    let (base_url, _) =
        one_shot_server(http_response("409 Conflict", "application/json", &body)).await;
    assert_eq!(
        client
            .prepare_decode(
                &base_url,
                KEY_ENV,
                Instant::now() + Duration::from_secs(2),
                &request(&binding),
                &binding,
            )
            .await
            .unwrap_err(),
        PowerClientError::Protocol(ProtocolErrorCode::StaleWorker)
    );

    let (base_url, _) = one_shot_server(http_response("200 OK", "application/json", &body)).await;
    assert_eq!(
        client
            .prepare_decode(
                &base_url,
                KEY_ENV,
                Instant::now() + Duration::from_secs(2),
                &request(&binding),
                &binding,
            )
            .await
            .unwrap_err(),
        PowerClientError::InvalidResponse
    );
}

#[tokio::test]
async fn missing_runtime_key_reports_only_the_configured_environment_name() {
    let binding = binding();
    let client = PowerDistributedClient::with_test_key(KEY_ENV, API_KEY);
    let environment = "A3S_POWER_UNCONFIGURED_KEY";

    let error = client
        .prepare_decode(
            "http://127.0.0.1:1",
            environment,
            Instant::now() + Duration::from_secs(2),
            &request(&binding),
            &binding,
        )
        .await
        .unwrap_err();

    assert_eq!(
        error,
        PowerClientError::MissingCredential {
            environment: environment.to_string()
        }
    );
    let diagnostic = error.to_string();
    assert!(diagnostic.contains(environment));
    assert!(!diagnostic.contains(API_KEY));
}

#[test]
fn client_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PowerDistributedClient>();
    assert_send_sync::<PowerClientError>();
}

#[test]
fn api_keys_are_bounded_visible_ascii_header_values() {
    assert!(api_key_is_valid_for_test(API_KEY));
    assert!(!api_key_is_valid_for_test(""));
    assert!(!api_key_is_valid_for_test("contains space"));
    assert!(!api_key_is_valid_for_test("contains\nnewline"));
    assert!(!api_key_is_valid_for_test("non-\u{00e9}-ascii"));
    assert!(!api_key_is_valid_for_test(&"x".repeat(4097)));
}
