use super::inference_tests::{
    gateway_state, inference_config, inference_key, read_http_request, spawn_capturing_backend,
    start_test_entrypoint, stop_test_entrypoint,
};
use super::GatewayState;
use crate::inference::{ATTEMPT_ID_HEADER, REQUEST_ID_HEADER};
use crate::observability::access_log::AccessLogEntry;
use chrono::{Duration as ChronoDuration, Utc};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use uuid::Uuid;

const TRACE_ID: &str = "11111111111111111111111111111111";
const CLIENT_REQUEST_ID: &str = "client-request";
const CLIENT_ATTEMPT_ID: &str = "client-attempt";

pub(super) fn state_with_access_log(
    config: &crate::config::GatewayConfig,
) -> (
    Arc<GatewayState>,
    tokio::sync::mpsc::UnboundedReceiver<AccessLogEntry>,
) {
    let mut state = gateway_state(config);
    let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state_mut = Arc::get_mut(&mut state).expect("unshared Gateway test state");
    state_mut.log_tx = log_tx;
    state_mut.access_log_enabled = true;
    state_mut.tracing_enabled = true;
    (state, log_rx)
}

pub(super) async fn next_log(
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<AccessLogEntry>,
) -> AccessLogEntry {
    tokio::time::timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("access log timeout")
        .expect("access log channel closed")
}

pub(super) fn raw_header<'a>(request: &'a str, expected_name: &str) -> Option<&'a str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case(expected_name)
            .then_some(value.trim())
    })
}

pub(super) fn uuid_v4(value: &str) -> Uuid {
    let value = Uuid::parse_str(value).expect("valid UUID");
    assert_eq!(value.get_version_num(), 4);
    value
}

pub(super) fn response_request_id(response: &reqwest::Response) -> Uuid {
    uuid_v4(
        response.headers()[REQUEST_ID_HEADER]
            .to_str()
            .expect("request ID header"),
    )
}

async fn spawn_finite_streaming_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<Vec<u8>>,
    &'static str,
) {
    const BODY: &str = "data: hello\n\ndata: [DONE]\n\n";

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{BODY}",
            BODY.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx, BODY)
}

#[tokio::test]
async fn managed_dispatch_replaces_spoofed_ids_and_logs_snapshot_identity() {
    let key = inference_key('a');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    config.validate().unwrap();

    let policy = config.inference.as_ref().unwrap();
    let route = policy.routes.values().next().unwrap();
    let credential_id = *policy.credentials.keys().next().unwrap();
    let model = &route.models["allowed-model"];
    let target = &model.targets[0];
    let expected_route_id = route.route_id;
    let expected_revision = route.policy_revision;
    let expected_model_id = model.model_id;
    let expected_target_id = target.target_id;

    let (state, mut log_rx) = state_with_access_log(&config);
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let traceparent = format!("00-{TRACE_ID}-2222222222222222-01");

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .header("traceparent", traceparent)
        .header(REQUEST_ID_HEADER, CLIENT_REQUEST_ID)
        .header(ATTEMPT_ID_HEADER, CLIENT_ATTEMPT_ID)
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response_request_id = response_request_id(&response);
    let _ = response.bytes().await.unwrap();

    let upstream = tokio::time::timeout(Duration::from_secs(2), captured_request)
        .await
        .unwrap()
        .unwrap();
    let upstream = String::from_utf8(upstream).unwrap();
    let upstream_request_id = uuid_v4(raw_header(&upstream, REQUEST_ID_HEADER).unwrap());
    let upstream_attempt_id = uuid_v4(raw_header(&upstream, ATTEMPT_ID_HEADER).unwrap());
    assert_eq!(upstream_request_id, response_request_id);
    assert_ne!(
        raw_header(&upstream, REQUEST_ID_HEADER),
        Some(CLIENT_REQUEST_ID)
    );
    assert_ne!(
        raw_header(&upstream, ATTEMPT_ID_HEADER),
        Some(CLIENT_ATTEMPT_ID)
    );
    assert!(raw_header(&upstream, "authorization").is_none());
    assert!(!upstream.contains(&key));
    assert!(raw_header(&upstream, "traceparent").is_some_and(|value| value.contains(TRACE_ID)));

    let entry = next_log(&mut log_rx).await;
    let inference = entry.inference.as_ref().expect("inference access context");
    assert_eq!(inference.request_id, response_request_id);
    assert_eq!(inference.attempt_id, Some(upstream_attempt_id));
    assert_eq!(inference.correlation_id, TRACE_ID);
    assert_eq!(inference.route_id, expected_route_id);
    assert_eq!(inference.route_policy_revision, expected_revision);
    assert_eq!(inference.endpoint, "chat-completions");
    assert_eq!(inference.model_id, Some(expected_model_id));
    assert_eq!(inference.target_id, Some(expected_target_id));

    let serialized = serde_json::to_string(&entry).unwrap();
    assert!(!serialized.contains(&key));
    assert!(!serialized.contains(&credential_id.to_string()));
    assert!(!serialized.contains("authorization"));

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_models_has_a_request_id_without_an_upstream_attempt() {
    let key = inference_key('a');
    let backend = SocketAddr::from(([127, 0, 0, 1], 9));
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let (state, mut log_rx) = state_with_access_log(&config);
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .header(REQUEST_ID_HEADER, CLIENT_REQUEST_ID)
        .header(ATTEMPT_ID_HEADER, CLIENT_ATTEMPT_ID)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert!(!response.headers().contains_key(ATTEMPT_ID_HEADER));
    let request_id = response_request_id(&response);
    let _ = response.bytes().await.unwrap();

    let entry = next_log(&mut log_rx).await;
    let inference = entry.inference.as_ref().expect("inference access context");
    assert_eq!(inference.request_id, request_id);
    assert_eq!(inference.endpoint, "models");
    assert_eq!(inference.model_id, None);
    assert_eq!(inference.attempt_id, None);
    assert_eq!(inference.target_id, None);
    let serialized = serde_json::to_string(&entry).unwrap();
    assert!(!serialized.contains("attempt_id"));
    assert!(!serialized.contains("target_id"));

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn authenticated_parse_error_has_request_identity_without_attempt_identity() {
    let key = inference_key('a');
    let backend = SocketAddr::from(([127, 0, 0, 1], 9));
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let (state, mut log_rx) = state_with_access_log(&config);
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let request_id = response_request_id(&response);
    let _ = response.bytes().await.unwrap();

    let entry = next_log(&mut log_rx).await;
    let inference = entry.inference.expect("inference access context");
    assert_eq!(inference.request_id, request_id);
    assert_eq!(inference.endpoint, "chat-completions");
    assert_eq!(inference.model_id, None);
    assert_eq!(inference.attempt_id, None);
    assert_eq!(inference.target_id, None);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_sse_retains_request_and_attempt_identity_through_completion() {
    let key = inference_key('a');
    let (backend, captured_request, expected_body) = spawn_finite_streaming_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let (state, mut log_rx) = state_with_access_log(&config);
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .header("accept", "text/event-stream")
        .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let request_id = response_request_id(&response);
    assert_eq!(response.text().await.unwrap(), expected_body);

    let upstream = tokio::time::timeout(Duration::from_secs(2), captured_request)
        .await
        .unwrap()
        .unwrap();
    let upstream = String::from_utf8(upstream).unwrap();
    assert_eq!(
        uuid_v4(raw_header(&upstream, REQUEST_ID_HEADER).unwrap()),
        request_id
    );
    let attempt_id = uuid_v4(raw_header(&upstream, ATTEMPT_ID_HEADER).unwrap());

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.response_bytes, expected_body.len() as u64);
    let inference = entry.inference.expect("inference access context");
    assert_eq!(inference.request_id, request_id);
    assert_eq!(inference.attempt_id, Some(attempt_id));

    stop_test_entrypoint(shutdown_tx, handle).await;
}
