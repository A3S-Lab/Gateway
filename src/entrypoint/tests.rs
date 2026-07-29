use super::*;
use crate::config::{
    EntrypointConfig, GatewayConfig, LoadBalancerConfig, MiddlewareConfig, Protocol, RouterConfig,
    ServerConfig, ServiceConfig, Strategy,
};
use crate::gateway::builders::{
    build_passive_health, build_pipeline_cache, build_scaling_state, build_sticky_managers,
};
use crate::observability::access_log::{AccessLog, AccessLogEntry};
use crate::observability::metrics::GatewayMetrics;
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use futures_util::StreamExt;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const MCP_TEST_TOKEN: &str = "a3s_mcp_abc12345abcdefghijklmnopqrstuvwxyz012345";

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

fn routed_mcp_config(backend: SocketAddr) -> GatewayConfig {
    let mut config = GatewayConfig::from_acl(include_str!(
        "../../tests/fixtures/mcp-modern-stateless-snapshot.acl"
    ))
    .unwrap();
    config
        .services
        .get_mut("mcp-target-1")
        .unwrap()
        .load_balancer
        .servers[0]
        .url = format!("http://{backend}/");
    config
        .mcp
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap()
        .targets[0]
        .endpoint = format!("http://{backend}/");
    let salt = SaltString::encode_b64(b"a3s-entrypoint-mcp").unwrap();
    config
        .mcp
        .as_mut()
        .unwrap()
        .credentials
        .values_mut()
        .next()
        .unwrap()
        .verifier_hash = Argon2::default()
        .hash_password(MCP_TEST_TOKEN.as_bytes(), &salt)
        .unwrap()
        .to_string();
    config
}

fn gateway_state(
    config: &GatewayConfig,
    log_tx: tokio::sync::mpsc::UnboundedSender<AccessLogEntry>,
    access_log_enabled: bool,
) -> Arc<GatewayState> {
    let service_registry =
        Arc::new(ServiceRegistry::from_config(&config.services).expect("service registry"));
    let middleware_configs = Arc::new(config.middlewares.clone());
    let pipeline_cache = Arc::new(build_pipeline_cache(config, &middleware_configs));
    let scaling = build_scaling_state(config);
    let metrics = Arc::new(GatewayMetrics::new());
    let telemetry =
        metrics.prepare_telemetry(config, service_registry.as_ref(), scaling.as_deref(), true);
    metrics.activate_telemetry(telemetry);

    Arc::new(GatewayState {
        router_table: Arc::new(RouterTable::from_config(&config.routers).expect("router table")),
        service_registry,
        inference_authorizer: config
            .inference
            .as_ref()
            .map(InferenceAuthorizer::new)
            .map(Arc::new),
        mcp_authorizer: config.mcp.as_ref().map(McpAuthorizer::new).map(Arc::new),
        usage_spool: None,
        middleware_configs,
        pipeline_cache,
        http_proxy: Arc::new(HttpProxy::new()),
        grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
        scaling,
        mirrors: HashMap::new(),
        failovers: HashMap::new(),
        access_log: Arc::new(AccessLog::new()),
        log_tx,
        sticky_managers: build_sticky_managers(config),
        passive_health: build_passive_health(config),
        metrics,
        shutdown_timeout: Duration::from_secs(config.shutdown_timeout_secs),
        metrics_enabled: true,
        access_log_enabled,
        tracing_enabled: false,
    })
}

async fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
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

async fn spawn_capturing_http_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    spawn_capturing_http_backend_with_response("{}").await
}

async fn spawn_capturing_http_backend_with_response(
    response_body: &'static str,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    spawn_capturing_http_backend_response("200 OK", Some("application/json"), response_body).await
}

async fn spawn_capturing_http_backend_response(
    status: &'static str,
    content_type: Option<&'static str>,
    response_body: &'static str,
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
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

        let headers = String::from_utf8_lossy(&request[..header_end]);
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
        let _ = body_tx.send(request[header_end..body_end].to_vec());
        let content_type = content_type
            .map(|content_type| format!("Content-Type: {content_type}\r\n"))
            .unwrap_or_default();
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\n{content_type}Connection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, body_rx)
}

async fn spawn_ambiguous_mcp_backend() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = attempts.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(_) => break,
            };
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, attempts)
}

async fn spawn_open_mcp_sse_backend() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = attempts.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(_) => break,
            };
            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nD\r\ndata: ready\n\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, attempts)
}

async fn send_mcp_tool_call(
    client: &reqwest::Client,
    address: SocketAddr,
    request_id: &str,
) -> reqwest::Response {
    client
        .post(format!("http://{address}/mcp"))
        .header("host", "mcp.example.com")
        .header("connection", "close")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "weather")
        .bearer_auth(MCP_TEST_TOKEN)
        .body(format!(
            r#"{{"jsonrpc":"2.0","id":"{request_id}","method":"tools/call","params":{{"name":"weather","arguments":{{}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{{}}}}}}}}"#
        ))
        .send()
        .await
        .unwrap()
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
async fn mcp_discovery_dispatches_once_and_relays_the_server_response() {
    let server_response = r#"{"jsonrpc":"2.0","id":"discover-1","result":{"serverInfo":{"name":"weather","version":"1.0.0"},"capabilities":{"tools":{}}}}"#;
    let (backend, captured) = spawn_capturing_http_backend_with_response(server_response).await;
    let config = routed_mcp_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let request_body = r#"{"jsonrpc":"2.0","id":"discover-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("host", "mcp.example.com")
        .header("connection", "close")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "server/discover")
        .bearer_auth(MCP_TEST_TOKEN)
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), server_response);
    assert_eq!(captured.await.unwrap(), request_body.as_bytes());

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 200);
    assert_eq!(entry.router.as_deref(), Some("mcp"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}/").as_str())
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn mcp_never_replays_after_an_ambiguous_upstream_dispatch() {
    let (backend, attempts) = spawn_ambiguous_mcp_backend().await;
    let config = routed_mcp_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("host", "mcp.example.com")
        .header("connection", "close")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/call")
        .header("mcp-name", "weather")
        .bearer_auth(MCP_TEST_TOKEN)
        .body(
            r#"{"jsonrpc":"2.0","id":"call-1","method":"tools/call","params":{"name":"weather","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["id"], "call-1");
    assert_eq!(body["error"]["code"], -32_046);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "an ambiguous dispatch must never be replayed"
    );

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 502);
    assert_eq!(entry.router.as_deref(), Some("mcp"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}/").as_str())
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn mcp_notification_is_forwarded_once_and_accepts_only_empty_202() {
    let (backend, captured) = spawn_capturing_http_backend_response("202 Accepted", None, "").await;
    let mut config = routed_mcp_config(backend);
    config
        .mcp
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap()
        .grants
        .values_mut()
        .next()
        .unwrap()
        .methods
        .push("com.example/events/changed".to_owned());
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;
    let request_body = r#"{"jsonrpc":"2.0","method":"com.example/events/changed","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("host", "mcp.example.com")
        .header("connection", "close")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "com.example/events/changed")
        .bearer_auth(MCP_TEST_TOKEN)
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    assert!(response.bytes().await.unwrap().is_empty());
    assert_eq!(captured.await.unwrap(), request_body.as_bytes());

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn mcp_subscription_event_order_passes_through_unchanged() {
    let events = "event: update\ndata: first\n\nevent: update\ndata: second\n\n";
    let (backend, captured) =
        spawn_capturing_http_backend_response("200 OK", Some("text/event-stream"), events).await;
    let mut config = routed_mcp_config(backend);
    config
        .mcp
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap()
        .grants
        .values_mut()
        .next()
        .unwrap()
        .methods
        .push("subscriptions/listen".to_owned());
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;
    let request_body = r#"{"jsonrpc":"2.0","id":"listen-1","method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("host", "mcp.example.com")
        .header("connection", "close")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "subscriptions/listen")
        .bearer_auth(MCP_TEST_TOKEN)
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    assert_eq!(response.text().await.unwrap(), events);
    assert_eq!(captured.await.unwrap(), request_body.as_bytes());

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn mcp_sse_holds_admission_until_downstream_closes() {
    let (backend, attempts) = spawn_open_mcp_sse_backend().await;
    let mut config = routed_mcp_config(backend);
    config
        .mcp
        .as_mut()
        .unwrap()
        .routes
        .values_mut()
        .next()
        .unwrap()
        .grants
        .values_mut()
        .next()
        .unwrap()
        .limits
        .max_concurrent_requests = 1;
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let client = reqwest::Client::new();

    let first = send_mcp_tool_call(&client, address, "stream-1").await;
    assert_eq!(first.status(), 200);
    assert_eq!(first.headers()["content-type"], "text/event-stream");

    let denied = send_mcp_tool_call(&client, address, "stream-2").await;
    assert_eq!(denied.status(), 429);
    let body: serde_json::Value = denied.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32_044);
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a concurrency rejection must perform no upstream work"
    );

    drop(first);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let third = send_mcp_tool_call(&client, address, "stream-3").await;
    assert_eq!(third.status(), 200);
    assert_eq!(
        attempts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "closing the downstream stream must release admission"
    );
    drop(third);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn mcp_authentication_precedes_body_parse_and_never_reaches_upstream() {
    let (backend, captured) = spawn_capturing_http_backend().await;
    let config = routed_mcp_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("host", "mcp.example.com")
        .header("connection", "close")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "server/discover")
        .bearer_auth("a3s_mcp_abc12345wrongwrongwrongwrong")
        .body("{not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["www-authenticate"],
        r#"Bearer realm="a3s-mcp""#
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], -32_040);
    assert!(tokio::time::timeout(Duration::from_millis(100), captured)
        .await
        .is_err());

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 401);
    assert_eq!(entry.router.as_deref(), Some("mcp"));
    assert!(entry.backend.is_none());

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn mcp_body_header_mismatch_is_rejected_after_auth_without_upstream_work() {
    let (backend, captured) = spawn_capturing_http_backend().await;
    let config = routed_mcp_config(backend);
    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/mcp"))
        .header("host", "mcp.example.com")
        .header("connection", "close")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", "2026-07-28")
        .header("mcp-method", "tools/list")
        .bearer_auth(MCP_TEST_TOKEN)
        .body(
            r#"{"jsonrpc":"2.0","id":"mismatch-1","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["id"], "mismatch-1");
    assert_eq!(body["error"]["code"], -32_020);
    assert!(tokio::time::timeout(Duration::from_millis(100), captured)
        .await
        .is_err());

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 400);
    assert_eq!(entry.router.as_deref(), Some("mcp"));
    assert!(entry.backend.is_none());

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
async fn openai_profile_forwards_valid_json_bytes_unchanged() {
    let (backend, captured_body) = spawn_capturing_http_backend().await;
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
    assert_eq!(captured_body.await.unwrap(), request_body.as_bytes());
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
    assert_eq!(response.status(), 502);

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 502);
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert_eq!(
        entry.backend.as_deref(),
        Some(format!("http://{backend}").as_str())
    );
    assert!(entry.response_bytes > 0);

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
