use super::inference_identity_tests::{
    next_log, raw_header, response_request_id, state_with_access_log, uuid_v4,
};
use super::inference_tests::{
    inference_config, inference_key, read_http_request, start_test_entrypoint, stop_test_entrypoint,
};
use crate::config::{InferenceTargetConfig, ServerConfig};
use crate::inference::{ATTEMPT_ID_HEADER, REQUEST_ID_HEADER};
use chrono::{Duration as ChronoDuration, Utc};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use uuid::Uuid;

fn add_fallback_target(
    config: &mut crate::config::GatewayConfig,
    fallback_backend: SocketAddr,
) -> (Uuid, Uuid) {
    let mut fallback_service = config.services["model-service"].clone();
    fallback_service.load_balancer.servers = vec![ServerConfig {
        url: format!("http://{fallback_backend}"),
        weight: 1,
    }];
    config
        .services
        .insert("fallback-service".into(), fallback_service);

    let route = config
        .inference
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap();
    let model = route.models.get_mut("allowed-model").unwrap();
    model.targets[0].upstream_model = "primary-upstream".into();
    let primary_target_id = model.targets[0].target_id;
    let fallback_target_id = Uuid::new_v4();
    model.targets.push(InferenceTargetConfig {
        target_id: fallback_target_id,
        service: "fallback-service".into(),
        upstream_model: "fallback-upstream".into(),
        priority: 1,
        weight: 1,
    });
    (primary_target_id, fallback_target_id)
}

async fn spawn_response_backend(
    status: u16,
    content_type: &'static str,
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
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

async fn spawn_drop_before_response_backend(
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

async fn spawn_partial_response_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

async fn spawn_hanging_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;
        let _ = request_tx.send(request);
        tokio::time::sleep(Duration::from_secs(2)).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

fn request_model(request: &[u8]) -> String {
    let request = String::from_utf8(request.to_vec()).unwrap();
    let body_offset = request.find("\r\n\r\n").unwrap() + 4;
    serde_json::from_str::<serde_json::Value>(&request[body_offset..]).unwrap()["model"]
        .as_str()
        .unwrap()
        .to_string()
}

fn request_identity(request: &[u8]) -> (Uuid, Uuid) {
    let request = String::from_utf8(request.to_vec()).unwrap();
    (
        uuid_v4(raw_header(&request, REQUEST_ID_HEADER).unwrap()),
        uuid_v4(raw_header(&request, ATTEMPT_ID_HEADER).unwrap()),
    )
}

#[tokio::test]
async fn managed_http_falls_back_after_pre_response_transport_failure() {
    let key = inference_key('a');
    let (primary, primary_request) = spawn_drop_before_response_backend().await;
    let (fallback, fallback_request) =
        spawn_response_backend(200, "application/json", r#"{"source":"fallback"}"#).await;
    let mut config = inference_config(primary, &key, Utc::now() + ChronoDuration::hours(1));
    let (_, fallback_target_id) = add_fallback_target(&mut config, fallback);
    config.validate().unwrap();
    let (state, mut log_rx) = state_with_access_log(&config);
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let response_request_id = response_request_id(&response);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["source"],
        "fallback"
    );

    let primary_request = primary_request.await.unwrap();
    let fallback_request = fallback_request.await.unwrap();
    assert_eq!(request_model(&primary_request), "primary-upstream");
    assert_eq!(request_model(&fallback_request), "fallback-upstream");
    let (primary_request_id, primary_attempt_id) = request_identity(&primary_request);
    let (fallback_request_id, fallback_attempt_id) = request_identity(&fallback_request);
    assert_eq!(primary_request_id, response_request_id);
    assert_eq!(fallback_request_id, response_request_id);
    assert_ne!(primary_attempt_id, fallback_attempt_id);

    let entry = next_log(&mut log_rx).await;
    let inference = entry.inference.expect("inference access context");
    assert_eq!(inference.request_id, response_request_id);
    assert_eq!(inference.attempt_id, Some(fallback_attempt_id));
    assert_eq!(inference.target_id, Some(fallback_target_id));
    let expected_backend = format!("http://{fallback}");
    assert_eq!(entry.backend.as_deref(), Some(expected_backend.as_str()));

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_http_falls_back_after_first_response_timeout() {
    let key = inference_key('a');
    let (primary, primary_request) = spawn_hanging_backend().await;
    let (fallback, fallback_request) =
        spawn_response_backend(200, "application/json", r#"{"source":"fallback"}"#).await;
    let mut config = inference_config(primary, &key, Utc::now() + ChronoDuration::hours(1));
    add_fallback_target(&mut config, fallback);
    config
        .services
        .get_mut("model-service")
        .unwrap()
        .load_balancer
        .request_timeout = "50ms".into();
    config.validate().unwrap();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(super::inference_tests::gateway_state(&config)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let _ = response.bytes().await.unwrap();

    let primary_request = primary_request.await.unwrap();
    let fallback_request = fallback_request.await.unwrap();
    let (_, primary_attempt_id) = request_identity(&primary_request);
    let (_, fallback_attempt_id) = request_identity(&fallback_request);
    assert_ne!(primary_attempt_id, fallback_attempt_id);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_http_does_not_fallback_after_an_upstream_status() {
    let key = inference_key('a');
    let (primary, primary_request) =
        spawn_response_backend(503, "application/json", r#"{"source":"primary"}"#).await;
    let (fallback, fallback_request) =
        spawn_response_backend(200, "application/json", r#"{"source":"fallback"}"#).await;
    let mut config = inference_config(primary, &key, Utc::now() + ChronoDuration::hours(1));
    let (primary_target_id, _) = add_fallback_target(&mut config, fallback);
    config.validate().unwrap();
    let (state, mut log_rx) = state_with_access_log(&config);
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
        response.json::<serde_json::Value>().await.unwrap()["source"],
        "primary"
    );
    let _ = primary_request.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), fallback_request)
            .await
            .is_err()
    );

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.inference.unwrap().target_id, Some(primary_target_id));

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_http_does_not_fallback_after_upstream_response_start() {
    let key = inference_key('a');
    let (primary, primary_request) = spawn_partial_response_backend().await;
    let (fallback, fallback_request) =
        spawn_response_backend(200, "application/json", r#"{"source":"fallback"}"#).await;
    let mut config = inference_config(primary, &key, Utc::now() + ChronoDuration::hours(1));
    add_fallback_target(&mut config, fallback);
    config.validate().unwrap();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(super::inference_tests::gateway_state(&config)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    let _ = response.bytes().await.unwrap();
    let _ = primary_request.await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), fallback_request)
            .await
            .is_err()
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_sse_falls_back_only_before_the_upstream_response() {
    let key = inference_key('a');
    let (primary, primary_request) = spawn_drop_before_response_backend().await;
    let (fallback, fallback_request) =
        spawn_response_backend(200, "text/event-stream", "data: hello\n\ndata: [DONE]\n\n").await;
    let mut config = inference_config(primary, &key, Utc::now() + ChronoDuration::hours(1));
    add_fallback_target(&mut config, fallback);
    config.validate().unwrap();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(super::inference_tests::gateway_state(&config)).await;

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
    let response_request_id = response_request_id(&response);
    assert_eq!(
        response.text().await.unwrap(),
        "data: hello\n\ndata: [DONE]\n\n"
    );

    let primary_request = primary_request.await.unwrap();
    let fallback_request = fallback_request.await.unwrap();
    let (primary_request_id, primary_attempt_id) = request_identity(&primary_request);
    let (fallback_request_id, fallback_attempt_id) = request_identity(&fallback_request);
    assert_eq!(primary_request_id, response_request_id);
    assert_eq!(fallback_request_id, response_request_id);
    assert_ne!(primary_attempt_id, fallback_attempt_id);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_fallback_persists_ordered_attempt_boundaries() {
    let key = inference_key('y');
    let (primary, primary_request) = spawn_drop_before_response_backend().await;
    let (fallback, fallback_request) =
        spawn_response_backend(200, "application/json", r#"{"source":"fallback"}"#).await;
    let mut config = inference_config(primary, &key, Utc::now() + ChronoDuration::hours(1));
    add_fallback_target(&mut config, fallback);
    config.validate().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let (state, spool) =
        super::inference_usage_tests::usage_state(&config, directory.path(), 2 * 1024 * 1024).await;
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let _ = response.bytes().await.unwrap();
    let _ = primary_request.await.unwrap();
    let _ = fallback_request.await.unwrap();

    let events = super::inference_usage_tests::lifecycle_events(&spool, 6).await;
    assert_eq!(
        events
            .iter()
            .map(|event| event["kind"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "request_started",
            "attempt_started",
            "attempt_terminal",
            "attempt_started",
            "attempt_terminal",
            "request_terminal"
        ]
    );
    assert_eq!(events[2]["outcome"], "fallback");
    assert_eq!(events[4]["outcome"], "succeeded");
    assert_eq!(events[5]["outcome"], "succeeded");
    assert_ne!(
        events[1]["attempt"]["attempt_id"],
        events[3]["attempt"]["attempt_id"]
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
    spool.shutdown().await;
}
