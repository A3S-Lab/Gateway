use super::*;
use crate::config::{
    EntrypointConfig, GatewayConfig, LoadBalancerConfig, MiddlewareConfig, Protocol, RouterConfig,
    ServerConfig, ServiceConfig, Strategy,
};
use crate::gateway::builders::{
    build_passive_health, build_pipeline_cache, build_route_plans, build_scaling_state,
    build_sticky_managers,
};
use crate::observability::access_log::{AccessLog, AccessLogEntry};
use crate::observability::metrics::GatewayMetrics;
use futures_util::{stream, StreamExt};
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn routed_config(backend: SocketAddr) -> GatewayConfig {
    let mut config = GatewayConfig::default();
    config.routers.insert(
        "test-router".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/`)".to_string(),
            service: "test-service".to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: vec![],
            priority: 0,
        },
    );
    config.services.insert(
        "test-service".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers: vec![ServerConfig {
                    url: format!("http://{backend}"),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        },
    );
    config
}

fn gateway_state(
    config: &GatewayConfig,
    log_tx: tokio::sync::mpsc::UnboundedSender<AccessLogEntry>,
    access_log_enabled: bool,
) -> Arc<GatewayState> {
    let service_registry =
        Arc::new(ServiceRegistry::from_config(&config.services).expect("service registry"));
    let router_table =
        Arc::new(RouterTable::from_config(&config.routers).expect("compiled HTTP router table"));
    let pipeline_cache = build_pipeline_cache(
        config,
        &config.middlewares,
        &crate::middleware::MiddlewareRegistry::new(),
    )
    .expect("middleware pipeline cache");
    let passive_health = build_passive_health(config);
    let route_plans = build_route_plans(
        config,
        &router_table,
        &pipeline_cache,
        &service_registry,
        &passive_health,
    )
    .expect("compiled route plans");
    let scaling = build_scaling_state(config);
    let metrics = Arc::new(GatewayMetrics::new());
    let telemetry =
        metrics.prepare_telemetry(config, service_registry.as_ref(), scaling.as_deref(), true);
    metrics.activate_telemetry(telemetry);

    Arc::new(GatewayState {
        router_table,
        route_plans,
        service_registry,
        inference_authorizer: config
            .inference
            .as_ref()
            .map(InferenceAuthorizer::new)
            .map(Arc::new),
        usage_spool: None,
        http_proxy: Arc::new(HttpProxy::new()),
        grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
        scaling,
        mirrors: HashMap::new(),
        failovers: HashMap::new(),
        access_log: Arc::new(AccessLog::new()),
        log_tx,
        sticky_managers: build_sticky_managers(config),
        passive_health,
        metrics,
        shutdown_timeout: Duration::from_secs(config.shutdown_timeout_secs),
        metrics_enabled: true,
        access_log_enabled,
        tracing_enabled: false,
    })
}

fn feature_free_gateway_state(
    config: &GatewayConfig,
    log_tx: tokio::sync::mpsc::UnboundedSender<AccessLogEntry>,
) -> Arc<GatewayState> {
    let mut state = gateway_state(config, log_tx, false);
    Arc::get_mut(&mut state)
        .expect("new gateway state is uniquely owned")
        .metrics_enabled = false;
    state
}

async fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[test]
fn disabled_tracing_does_not_create_a_request_context() {
    let headers = http::HeaderMap::new();

    assert!(request_trace_context(&headers, false).is_none());
}

#[test]
fn enabled_tracing_reuses_the_inbound_trace_id() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        "traceparent",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
            .parse()
            .unwrap(),
    );

    let context = request_trace_context(&headers, true).expect("trace context");

    assert_eq!(context.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
    assert_eq!(context.parent_span_id, "00f067aa0ba902b7");
}

#[test]
fn gateway_runtime_replaces_the_snapshot_without_invalidating_readers() {
    let config = routed_config("127.0.0.1:9".parse().unwrap());
    let (initial_log_tx, _initial_log_rx) = tokio::sync::mpsc::unbounded_channel();
    let initial = gateway_state(&config, initial_log_tx, false);
    let runtime = GatewayRuntime::new(initial.clone());
    let loaded_before_replace = runtime.load();

    let (replacement_log_tx, _replacement_log_rx) = tokio::sync::mpsc::unbounded_channel();
    let replacement = gateway_state(&config, replacement_log_tx, true);
    runtime.replace(replacement.clone());

    assert!(Arc::ptr_eq(&loaded_before_replace, &initial));
    assert!(Arc::ptr_eq(&runtime.load(), &replacement));
    assert!(!loaded_before_replace.access_log_enabled);
    assert!(runtime.load().access_log_enabled);
}

async fn start_test_entrypoint(
    state: Arc<GatewayState>,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let address = free_address().await;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = start_http_entrypoint(
        "web".to_string(),
        address,
        None,
        GatewayRuntime::new(state),
        shutdown_rx,
    )
    .await
    .unwrap()
    .into_task();
    (address, shutdown_tx, handle)
}

async fn stop_test_entrypoint(
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    mut handle: tokio::task::JoinHandle<()>,
) {
    let _ = shutdown_tx.send(true);
    if tokio::time::timeout(Duration::from_secs(2), &mut handle)
        .await
        .is_err()
    {
        handle.abort();
        let _ = handle.await;
    }
}

async fn next_log(
    receiver: &mut tokio::sync::mpsc::UnboundedReceiver<AccessLogEntry>,
) -> AccessLogEntry {
    tokio::time::timeout(Duration::from_secs(2), receiver.recv())
        .await
        .expect("access log timeout")
        .expect("access log channel closed")
}

async fn spawn_http_backend(body: &'static str, content_type: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    content_type,
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    address
}

async fn spawn_streaming_grpc_backend() -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (continue_tx, continue_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let continue_rx = Arc::new(std::sync::Mutex::new(Some(continue_rx)));
        let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let continue_rx = continue_rx.clone();
            async move {
                request.into_body().collect().await.unwrap();
                let continue_rx = continue_rx.lock().unwrap().take().unwrap();
                let frames = stream::unfold(
                    (0_u8, Some(continue_rx)),
                    |(stage, continue_rx)| async move {
                        match stage {
                            0 => Some((
                                Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"first"))),
                                (1, continue_rx),
                            )),
                            1 => {
                                let _ = continue_rx.unwrap().await;
                                Some((Ok(Frame::data(Bytes::from_static(b"second"))), (2, None)))
                            }
                            2 => {
                                let mut trailers = http::HeaderMap::new();
                                trailers.insert("grpc-status", "0".parse().unwrap());
                                Some((Ok(Frame::trailers(trailers)), (3, None)))
                            }
                            _ => None,
                        }
                    },
                );
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .header(http::header::CONTENT_TYPE, "application/grpc")
                        .body(StreamBody::new(frames))
                        .unwrap(),
                )
            }
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });

    (address, continue_tx)
}

struct CapturedHttpRequest {
    headers: String,
    body: Vec<u8>,
}

async fn spawn_capturing_http_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<CapturedHttpRequest>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (body_tx, body_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
            if let Some(offset) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break offset + 4;
            }
        };

        let headers = String::from_utf8_lossy(&request[..header_end]).into_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }

        let body_end = (header_end + content_length).min(request.len());
        let _ = body_tx.send(CapturedHttpRequest {
            headers,
            body: request[header_end..body_end].to_vec(),
        });
        let response =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, body_rx)
}

async fn spawn_websocket_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(message) = websocket.next().await {
            if message.is_err() {
                break;
            }
        }
    });

    address
}

#[test]
fn test_invalid_address() {
    let config = GatewayConfig {
        entrypoints: {
            let mut entrypoints = HashMap::new();
            entrypoints.insert(
                "bad".to_string(),
                EntrypointConfig {
                    address: "not-an-address".to_string(),
                    protocol: Protocol::Http,
                    tls: None,
                    max_connections: None,
                    tcp_allowed_ips: vec![],
                    udp_session_timeout_secs: None,
                    udp_max_sessions: None,
                },
            );
            entrypoints
        },
        ..GatewayConfig::default()
    };
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let runtime = GatewayRuntime::new(gateway_state(&config, log_tx, true));

    let rt = tokio::runtime::Runtime::new().unwrap();
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let result = rt.block_on(start_entrypoints(&config, runtime, shutdown_rx));
    assert!(result.is_err());
    let error = match result {
        Ok(handles) => {
            for handle in handles.values() {
                handle.abort();
            }
            panic!("invalid address unexpectedly started");
        }
        Err(error) => error,
    };
    assert!(error.to_string().contains("Invalid address"));
}

#[tokio::test]
async fn no_route_emits_terminal_access_log() {
    let config = GatewayConfig::default();
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/missing"))
        .header("connection", "close")
        .header("user-agent", "access-log-test/1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 404);
    assert_eq!(entry.path, "/missing");
    assert_eq!(entry.entrypoint.as_deref(), Some("web"));
    assert_eq!(entry.user_agent.as_deref(), Some("access-log-test/1.0"));
    assert!(entry.router.is_none());
    assert!(entry.backend.is_none());
    assert!(entry.response_bytes > 0);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn middleware_rejection_emits_router_without_backend() {
    let backend = free_address().await;
    let mut config = routed_config(backend);
    config.middlewares.insert(
        "auth".to_string(),
        MiddlewareConfig {
            middleware_type: "api-key".to_string(),
            header: Some("x-api-key".to_string()),
            keys: vec!["allowed".to_string()],
            ..MiddlewareConfig::default()
        },
    );
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("auth".to_string());

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/protected"))
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 401);
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert!(entry.backend.is_none());
    assert!(entry.response_bytes > 0);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn http_success_emits_backend_and_response_size() {
    let backend = spawn_http_backend("hello", "text/plain").await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/ok"))
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "hello");

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 200);
    assert_eq!(entry.response_bytes, 5);
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}").as_str())
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn ordinary_http_fast_path_sets_forwarding_headers_once() {
    let (backend, captured_request) = spawn_capturing_http_backend().await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(feature_free_gateway_state(&config, log_tx)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/headers"))
        .header(http::header::HOST, "api.example.test:8443")
        .header("x-forwarded-for", "192.0.2.1")
        .header("connection", "close, x-forwarded-for")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let captured = captured_request.await.unwrap();
    assert!(captured.body.is_empty());
    for (name, expected) in [
        ("x-forwarded-for", "192.0.2.1, 127.0.0.1"),
        ("x-forwarded-host", "api.example.test:8443"),
        ("x-forwarded-proto", "http"),
        ("x-forwarded-port", "8443"),
    ] {
        let values = captured
            .headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
            .collect::<Vec<_>>();
        assert_eq!(values, [expected], "unexpected {name} values");
    }

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn feature_free_sse_fast_path_sets_forwarding_headers_once() {
    let (backend, captured_request) = spawn_capturing_http_backend().await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(feature_free_gateway_state(&config, log_tx)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/events"))
        .header(http::header::ACCEPT, "text/event-stream")
        .header(http::header::HOST, "api.example.test:8443")
        .header("x-forwarded-for", "192.0.2.1")
        .header("connection", "close, x-forwarded-for")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    let captured = captured_request.await.unwrap();
    for (name, expected) in [
        ("x-forwarded-for", "192.0.2.1, 127.0.0.1"),
        ("x-forwarded-host", "api.example.test:8443"),
        ("x-forwarded-proto", "http"),
        ("x-forwarded-port", "8443"),
    ] {
        let values = captured
            .headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.trim())
            .collect::<Vec<_>>();
        assert_eq!(values, [expected], "unexpected {name} values");
    }

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn feature_free_openai_fast_path_preserves_validation_and_body() {
    let (backend, captured_request) = spawn_capturing_http_backend().await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(feature_free_gateway_state(&config, log_tx)).await;
    let request_body = r#"{ "model": "local-alias", "stream": true, "messages": [] }"#;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(
        captured_request.await.unwrap().body,
        request_body.as_bytes()
    );

    stop_test_entrypoint(shutdown_tx, handle).await;

    let unavailable_backend = free_address().await;
    let config = routed_config(unavailable_backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(feature_free_gateway_state(&config, log_tx)).await;
    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(r#"{"stream":true}"#)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "missing_model");

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn openai_profile_forwards_valid_json_bytes_unchanged() {
    let (backend, captured_request) = spawn_capturing_http_backend().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let request_body = r#"{ "model": "local-alias", "messages": [] }"#;

    let response = reqwest::Client::new()
        .post(format!(
            "http://{address}/v1/chat/completions?request=preserve"
        ))
        .header("connection", "close")
        .header("content-type", "Application/JSON; charset=utf-8")
        .body(request_body)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(
        captured_request.await.unwrap().body,
        request_body.as_bytes()
    );
    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 200);
    assert_eq!(entry.path, "/v1/chat/completions");
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}").as_str())
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn openai_profile_returns_stable_content_type_and_json_errors() {
    let backend = free_address().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://{address}/v1/embeddings"))
        .header("content-type", "text/plain")
        .body(r#"{"model":"local-alias","input":"hello"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 415);
    assert_eq!(response.headers()["content-type"], "application/json");
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "invalid_request_error");
    assert_eq!(body["error"]["code"], "unsupported_media_type");
    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 415);
    assert!(entry.backend.is_none());

    let response = client
        .post(format!("http://{address}/v1/completions"))
        .header("content-type", "application/json")
        .body(r#"{"model":"local-alias""#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "invalid_request_error");
    assert_eq!(body["error"]["param"], serde_json::Value::Null);
    assert_eq!(body["error"]["code"], "invalid_json");
    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 400);
    assert!(entry.backend.is_none());

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn openai_profile_rejects_missing_or_invalid_models_before_backend_selection() {
    let backend = free_address().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let client = reqwest::Client::new();

    for (request_body, expected_code, expected_param) in [
        (r#"{}"#, "missing_model", "model"),
        (r#"{"model":42}"#, "invalid_model", "model"),
        (r#"[]"#, "invalid_request_body", ""),
    ] {
        let response = client
            .post(format!("http://{address}/v1/chat/completions"))
            .header("content-type", "application/json")
            .body(request_body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["error"]["type"], "invalid_request_error");
        assert_eq!(body["error"]["code"], expected_code);
        if expected_param.is_empty() {
            assert_eq!(body["error"]["param"], serde_json::Value::Null);
        } else {
            assert_eq!(body["error"]["param"], expected_param);
        }

        let entry = next_log(&mut log_rx).await;
        assert_eq!(entry.status, 400);
        assert!(entry.backend.is_none());
    }

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn openai_profile_runs_route_middleware_before_body_validation() {
    let backend = free_address().await;
    let mut config = routed_config(backend);
    config.middlewares.insert(
        "auth".to_string(),
        MiddlewareConfig {
            middleware_type: "api-key".to_string(),
            header: Some("x-api-key".to_string()),
            keys: vec!["allowed".to_string()],
            ..MiddlewareConfig::default()
        },
    );
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("auth".to_string());
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .header("content-type", "text/plain")
        .body("not-json")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 401);
    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 401);
    assert!(entry.backend.is_none());

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn openai_profile_rejects_oversized_declared_length_without_reading_body() {
    const OVER_LIMIT: usize = 8 * 1024 * 1024 + 1;

    let backend = free_address().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {address}\r\nContent-Type: application/json\r\nContent-Length: {OVER_LIMIT}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.contains(r#""code":"request_too_large""#));
    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 413);
    assert!(entry.backend.is_none());

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn openai_profile_enforces_limit_for_chunked_requests() {
    const LIMIT: usize = 8 * 1024 * 1024;

    let backend = free_address().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let chunks = futures_util::stream::iter([
        Ok::<_, std::io::Error>(Bytes::from(vec![b' '; LIMIT])),
        Ok(Bytes::from_static(b"x")),
    ]);

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/embeddings"))
        .header("content-type", "application/json")
        .body(reqwest::Body::wrap_stream(chunks))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "request_too_large");
    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 413);
    assert!(entry.backend.is_none());

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn openai_near_miss_path_retains_ordinary_proxy_semantics() {
    let backend = spawn_http_backend("ordinary", "text/plain").await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions/"))
        .header("content-type", "text/plain")
        .body("not-json")
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ordinary");

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn http_proxy_error_emits_terminal_access_log() {
    let backend = free_address().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/unavailable"))
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    assert!((500..600).contains(&status));
    let response_bytes = response.bytes().await.unwrap().len() as u64;

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, status);
    assert_eq!(entry.response_bytes, response_bytes);
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}").as_str())
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn grpc_proxy_error_emits_terminal_access_log() {
    let backend = free_address().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/grpc.Service/Call"))
        .header("connection", "close")
        .header("content-type", "application/grpc")
        .body(Vec::new())
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    assert!(matches!(status, 503 | 504));

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, status);
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}").as_str())
    );
    assert!(entry.response_bytes > 0);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn grpc_stream_accounting_follows_the_response_body_lifetime() {
    let (backend, continue_response) = spawn_streaming_grpc_backend().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, true);
    let metrics = state.metrics.clone();
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();
    let request = http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri(format!("http://{address}/grpc.echo.Echo/Stream"))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers")
        .body(Full::new(Bytes::from_static(b"request")))
        .unwrap();

    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let mut response_body = response.into_body();
    assert_eq!(
        response_body
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        Bytes::from_static(b"first")
    );
    assert!(matches!(
        log_rx.try_recv(),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty)
    ));
    let during = metrics.render_prometheus();
    assert!(during.contains("gateway_service_active_requests{service=\"test-service\"} 1"));
    assert!(during.contains("gateway_service_ttft_seconds_count{service=\"test-service\"} 1"));

    continue_response.send(()).unwrap();
    let mut response_bytes = 5_u64;
    let mut grpc_status = None;
    while let Some(frame) = response_body.frame().await {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref() {
            response_bytes += data.len() as u64;
        }
        if let Some(trailers) = frame.trailers_ref() {
            grpc_status = trailers.get("grpc-status").cloned();
        }
    }
    assert_eq!(grpc_status.unwrap(), "0");
    assert_eq!(response_bytes, 11);

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 200);
    assert_eq!(entry.response_bytes, response_bytes);
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}").as_str())
    );
    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_active_requests{service=\"test-service\"} 0"));
    assert_eq!(metrics.snapshot().total_response_bytes, response_bytes);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn sse_stream_emits_bytes_when_response_body_finishes() {
    let body = "data: ready\n\n";
    let backend = spawn_http_backend(body, "text/event-stream").await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/events"))
        .header("connection", "close")
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.bytes().await.unwrap().as_ref(), body.as_bytes());

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 200);
    assert_eq!(entry.response_bytes, body.len() as u64);
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}").as_str())
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn sse_ttft_and_active_request_follow_the_body_lifetime() {
    let (backend, stream_started, upstream_disconnected) =
        super::inference_tests::spawn_streaming_backend().await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    let metrics = state.metrics.clone();
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/events"))
        .header("connection", "close")
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .unwrap()
        .unwrap();

    let mut body = response.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(first.starts_with(b"data:"));

    let during = metrics.render_prometheus();
    assert!(during.contains("gateway_service_active_requests{service=\"test-service\"} 1"));
    assert!(during.contains("gateway_service_ttft_seconds_count{service=\"test-service\"} 1"));

    drop(body);
    tokio::time::timeout(Duration::from_secs(2), upstream_disconnected)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if metrics
                .render_prometheus()
                .contains("gateway_service_active_requests{service=\"test-service\"} 0")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_request_duration_seconds_count{service=\"test-service\"} 1"));

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn websocket_session_emits_when_relay_finishes() {
    let backend = spawn_websocket_backend().await;
    let config = routed_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let (mut websocket, response) =
        tokio_tungstenite::connect_async(format!("ws://{address}/socket"))
            .await
            .unwrap();
    assert_eq!(response.status(), 101);
    websocket.close(None).await.unwrap();

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 101);
    assert_eq!(entry.response_bytes, 0);
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}").as_str())
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn disabled_access_logging_does_not_enqueue_entries() {
    let config = GatewayConfig::default();
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/missing"))
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), log_rx.recv())
            .await
            .is_err()
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}
