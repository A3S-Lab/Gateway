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
use futures_util::StreamExt;
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

fn gateway_state(
    config: &GatewayConfig,
    log_tx: tokio::sync::mpsc::UnboundedSender<AccessLogEntry>,
    access_log_enabled: bool,
) -> Arc<GatewayState> {
    let service_registry =
        Arc::new(ServiceRegistry::from_config(&config.services).expect("service registry"));
    let middleware_configs = Arc::new(config.middlewares.clone());
    let pipeline_cache = Arc::new(build_pipeline_cache(config, &middleware_configs));

    Arc::new(GatewayState {
        router_table: Arc::new(RouterTable::from_config(&config.routers).expect("router table")),
        service_registry,
        middleware_configs,
        pipeline_cache,
        http_proxy: Arc::new(HttpProxy::new()),
        grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
        scaling: build_scaling_state(config),
        mirrors: HashMap::new(),
        failovers: HashMap::new(),
        access_log: Arc::new(AccessLog::new()),
        log_tx,
        sticky_managers: build_sticky_managers(config),
        passive_health: build_passive_health(config),
        metrics: Arc::new(GatewayMetrics::new()),
        metrics_enabled: false,
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
