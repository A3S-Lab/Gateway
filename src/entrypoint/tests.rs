use super::*;
use crate::config::{
    EntrypointConfig, FailoverConfig, GatewayConfig, HealthCheckConfig, LoadBalancerConfig,
    MiddlewareConfig, MirrorConfig, Protocol, RouterConfig, ServerConfig, ServiceConfig,
    StaticBundleConfig, StaticBundleManifestConfig, StickyConfig, Strategy,
};
use crate::gateway::builders::{
    build_mirror_failover_state, build_passive_health, build_pipeline_cache, build_route_plans,
    build_scaling_state, build_static_bundle_runtimes, build_sticky_managers,
};
use crate::observability::access_log::{AccessLog, AccessLogEntry};
use crate::observability::metrics::GatewayMetrics;
use crate::static_object::{sha256_hex, StaticObjectEntry};
use futures_util::{stream, SinkExt, StreamExt};
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::collections::{BTreeMap, HashMap};
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
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: format!("http://{backend}"),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
                tls_ca_file: None,
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
    gateway_state_with_registry(
        config,
        log_tx,
        access_log_enabled,
        &crate::middleware::MiddlewareRegistry::new(),
    )
}

fn gateway_state_with_registry(
    config: &GatewayConfig,
    log_tx: tokio::sync::mpsc::UnboundedSender<AccessLogEntry>,
    access_log_enabled: bool,
    middleware_registry: &crate::middleware::MiddlewareRegistry,
) -> Arc<GatewayState> {
    let static_bundles = build_static_bundle_runtimes(config).expect("static bundles");
    let passive_health = build_passive_health(config);
    gateway_state_with_static_bundles(
        config,
        log_tx,
        access_log_enabled,
        static_bundles,
        passive_health,
        middleware_registry,
    )
}

fn gateway_state_with_passive_config(
    config: &GatewayConfig,
    log_tx: tokio::sync::mpsc::UnboundedSender<AccessLogEntry>,
    access_log_enabled: bool,
    passive_config: crate::service::passive_health::PassiveHealthConfig,
) -> Arc<GatewayState> {
    let static_bundles = build_static_bundle_runtimes(config).expect("static bundles");
    let passive_health = config
        .services
        .keys()
        .map(|name| {
            let phc = Arc::new(crate::service::passive_health::PassiveHealthCheck::new(
                passive_config.clone(),
            ));
            phc.spawn_recovery();
            (name.clone(), phc)
        })
        .collect();
    gateway_state_with_static_bundles(
        config,
        log_tx,
        access_log_enabled,
        static_bundles,
        passive_health,
        &crate::middleware::MiddlewareRegistry::new(),
    )
}

fn gateway_state_with_static_bundles(
    config: &GatewayConfig,
    log_tx: tokio::sync::mpsc::UnboundedSender<AccessLogEntry>,
    access_log_enabled: bool,
    static_bundles: HashMap<String, Arc<crate::static_object::StaticBundleRuntime>>,
    passive_health: HashMap<String, Arc<crate::service::passive_health::PassiveHealthCheck>>,
    middleware_registry: &crate::middleware::MiddlewareRegistry,
) -> Arc<GatewayState> {
    let service_registry =
        Arc::new(ServiceRegistry::from_config(&config.services).expect("service registry"));
    let router_table =
        Arc::new(RouterTable::from_config(&config.routers).expect("compiled HTTP router table"));
    let pipeline_cache = build_pipeline_cache(config, &config.middlewares, middleware_registry)
        .expect("middleware pipeline cache");
    let route_plans = build_route_plans(
        config,
        &router_table,
        &pipeline_cache,
        &service_registry,
        &passive_health,
        &static_bundles,
    )
    .expect("compiled route plans");
    let scaling = build_scaling_state(config);
    let metrics = Arc::new(GatewayMetrics::new());
    let telemetry =
        metrics.prepare_telemetry(config, service_registry.as_ref(), scaling.as_deref(), true);
    metrics.activate_telemetry(telemetry);

    let http_proxy = Arc::new(HttpProxy::new());
    let service_http_proxies = HashMap::new();
    let (mirrors, failovers) = build_mirror_failover_state(
        config,
        &service_registry,
        &http_proxy,
        &service_http_proxies,
    )
    .expect("mirror/failover state");

    Arc::new(GatewayState {
        router_table,
        tcp_router_table: Arc::new(
            crate::router::TcpRouterTable::from_config(&config.routers).expect("tcp sni table"),
        ),
        route_plans,
        service_registry,
        inference_authorizer: config
            .inference
            .as_ref()
            .map(InferenceAuthorizer::new)
            .map(Arc::new),
        distributed_serving: Arc::new(
            crate::inference::DistributedServingOrchestrator::from_policy(
                config.inference.as_ref(),
            )
            .expect("distributed-serving runtime"),
        ),
        usage_spool: None,
        http_proxy,
        service_http_proxies,
        grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
        service_grpc_proxies: HashMap::new(),
        service_ws_tls: HashMap::new(),
        scaling,
        mirrors,
        failovers,
        access_log: Arc::new(AccessLog::new()),
        log_tx: log_tx.into(),
        sticky_managers: build_sticky_managers(config).expect("sticky managers"),
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

#[test]
fn failover_backend_uses_backup_upstream_tls_service() {
    fn service(url: &str, failover: Option<&str>) -> ServiceConfig {
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: url.to_string(),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
                tls_ca_file: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: failover.map(|name| FailoverConfig {
                service: name.to_string(),
            }),
        }
    }

    let mut config = GatewayConfig::default();
    config.services.insert(
        "primary".to_string(),
        service("http://127.0.0.1:8001", Some("backup")),
    );
    config.services.insert(
        "backup".to_string(),
        service("https://127.0.0.1:8443", None),
    );
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    let primary = state
        .service_registry
        .get("primary")
        .expect("primary")
        .backends()[0]
        .clone();
    assert_eq!(state.upstream_service_for("primary", &primary), "primary");
    primary.set_healthy(false);
    let selected =
        super::select_backend_for_service_request(&state, "primary", None).expect("backup backend");
    assert_eq!(selected.backend.url, "https://127.0.0.1:8443");
    assert_eq!(
        state.upstream_service_for("primary", &selected.backend),
        "backup"
    );
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
fn protocol_selection_keeps_revision_policy_authoritative() {
    let mut config = routed_config("127.0.0.1:18000".parse().unwrap());
    let service = config.services.get_mut("test-service").unwrap();
    service.revisions = vec![crate::config::RevisionConfig {
        name: "stable".to_string(),
        traffic_percent: 100,
        servers: vec![ServerConfig {
            url: "http://revision:18001".to_string(),
            weight: 1,
            target: None,
        }],
        strategy: Strategy::RoundRobin,
    }];

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    let revision = state
        .scaling
        .as_ref()
        .unwrap()
        .revision_routers
        .get("test-service")
        .unwrap()
        .clone();

    let selected = select_backend_for_service(&state, "test-service").unwrap();
    assert_eq!(selected.url, "http://revision:18001");

    // A configured revision pool must not silently fall back to the legacy
    // service-level servers when every weighted revision is unavailable.
    revision.revisions()[0].load_balancer().backends()[0].set_healthy(false);
    assert!(select_backend_for_service(&state, "test-service").is_none());
}

#[test]
fn request_host_authority_prefers_uri_authority_then_host_header() {
    // HTTP/2 requests often omit Host and only carry :authority on the URI.
    let without_host = http::Request::builder()
        .uri("https://bx0.local:8081/v1/models")
        .body(())
        .unwrap();
    assert!(without_host.headers().get(http::header::HOST).is_none());
    assert_eq!(
        super::request_host_authority(&without_host),
        Some("bx0.local:8081")
    );

    // When both are present, URI authority wins (HTTP/2 :authority).
    let with_both = http::Request::builder()
        .uri("https://bx0.local:8081/v1/models")
        .header(http::header::HOST, "from-header.local")
        .body(())
        .unwrap();
    assert_eq!(
        super::request_host_authority(&with_both),
        Some("bx0.local:8081")
    );

    // HTTP/1.1 origin-form: no URI authority, Host is required.
    let host_only = http::Request::builder()
        .uri("/v1/models")
        .header(http::header::HOST, "from-header.local")
        .body(())
        .unwrap();
    assert!(host_only.uri().authority().is_none());
    assert_eq!(
        super::request_host_authority(&host_only),
        Some("from-header.local")
    );
}

#[tokio::test]
async fn http2_host_router_matches_uri_authority_when_host_header_is_absent() {
    let backend = spawn_http_backend("ok", "text/plain").await;
    let mut config = routed_config(backend);
    config.routers.get_mut("test-router").unwrap().rule =
        "Host(`127.0.0.1`) && PathPrefix(`/`)".to_string();

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();

    let without_host = http::Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_2)
        .uri(format!("http://{address}/v1/ping"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    assert!(without_host.headers().get(http::header::HOST).is_none());
    let response = client.request(without_host).await.unwrap();
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"ok");

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.router.as_deref(), Some("test-router"));
    assert_eq!(entry.host.as_deref(), Some(address.to_string().as_str()));

    // URI :authority wins over a conflicting Host header (HTTP/2 stacks may
    // still populate Host; routing must follow the URI authority).
    let conflicting_host = http::Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_2)
        .uri(format!("http://{address}/v1/ping"))
        .header(http::header::HOST, "wrong.example.com")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = client.request(conflicting_host).await.unwrap();
    assert_eq!(response.status(), 200);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn http2_host_router_misses_when_uri_authority_does_not_match() {
    let backend = spawn_http_backend("ok", "text/plain").await;
    let mut config = routed_config(backend);
    config.routers.get_mut("test-router").unwrap().rule =
        "Host(`app.example.com`) && PathPrefix(`/`)".to_string();

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let client: Client<HttpConnector, Full<Bytes>> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();

    let request = http::Request::builder()
        .method(http::Method::GET)
        .version(http::Version::HTTP_2)
        .uri(format!("http://{address}/v1/ping"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let response = client.request(request).await.unwrap();
    assert_eq!(response.status(), 404);

    stop_test_entrypoint(shutdown_tx, handle).await;
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

#[tokio::test]
async fn managed_runtime_stops_admitting_traffic_at_snapshot_expiry() {
    let config = GatewayConfig::default();
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    let gateway_id = uuid::Uuid::new_v4();
    let store = Arc::new(crate::managed_snapshot::ManagedSnapshotStore::new(
        Some(gateway_id),
        None,
    ));
    let runtime = GatewayRuntime::new(state).with_managed_snapshot_store(store.clone());
    assert!(runtime.allows_traffic());

    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + chrono::Duration::milliseconds(10);
    let snapshot = crate::managed_snapshot::ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        issued_at,
        expires_at,
        format!("mode {{ kind = \"cloud-managed\" }}\nmanaged {{ gateway_id = \"{gateway_id}\" }}"),
    );
    let callback: crate::managed_snapshot::ManagedSnapshotReloadCallback =
        Arc::new(|_| Box::pin(async { Ok(GatewayConfig::default()) }));
    assert!(store.apply(snapshot, Some(&callback)).await.status.ready);
    assert!(runtime.allows_traffic());
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(!runtime.allows_traffic());
}

#[tokio::test]
async fn managed_snapshot_expiry_rejects_new_requests_on_the_listener_with_503() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let backend = {
        let hits = hits.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(connection) => connection,
                    Err(_) => break,
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 4096];
                    let _ = stream.read(&mut request).await;
                    hits.fetch_add(1, Ordering::SeqCst);
                    let body = b"upstream-ok";
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        std::str::from_utf8(body).unwrap()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        address
    };

    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    let gateway_id = uuid::Uuid::new_v4();
    let store = Arc::new(crate::managed_snapshot::ManagedSnapshotStore::new(
        Some(gateway_id),
        None,
    ));
    let runtime = GatewayRuntime::new(state).with_managed_snapshot_store(store.clone());
    let (address, shutdown_tx, handle, runtime) = start_test_entrypoint_with_runtime(runtime).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/probe");

    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + chrono::Duration::milliseconds(150);
    let snapshot = crate::managed_snapshot::ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        issued_at,
        expires_at,
        format!("mode {{ kind = \"cloud-managed\" }}\nmanaged {{ gateway_id = \"{gateway_id}\" }}"),
    );
    let callback: crate::managed_snapshot::ManagedSnapshotReloadCallback =
        Arc::new(|_| Box::pin(async { Ok(GatewayConfig::default()) }));
    assert!(store.apply(snapshot, Some(&callback)).await.status.ready);
    assert!(runtime.allows_traffic());

    let before = client.get(&url).send().await.unwrap();
    assert_eq!(before.status(), 200);
    assert_eq!(before.text().await.unwrap(), "upstream-ok");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while runtime.allows_traffic() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "managed snapshot should expire within the test deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let after = client.get(&url).send().await.unwrap();
    assert_eq!(after.status(), 503);
    let body = after.text().await.unwrap();
    assert!(
        body.contains("Managed snapshot expired"),
        "expected managed snapshot expiry message, got {body}"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "expired snapshot must fail closed before upstream"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

fn protocol_routed_config(backend: SocketAddr, protocol: Protocol, scheme: &str) -> GatewayConfig {
    let mut config = GatewayConfig::default();
    config.entrypoints.insert(
        "traffic".to_string(),
        EntrypointConfig {
            address: "127.0.0.1:0".to_string(),
            protocol: protocol.clone(),
            tls: None,
            max_connections: None,
            tcp_allowed_ips: Vec::new(),
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
            trust_forwarded_headers: false,
        },
    );
    config.routers.insert(
        "test-router".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/`)".to_string(),
            service: "test-service".to_string(),
            entrypoints: vec!["traffic".to_string()],
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
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: format!("{scheme}://{backend}"),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
                tls_ca_file: None,
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

#[tokio::test]
async fn managed_snapshot_expiry_rejects_new_tcp_connections_without_upstream() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpStream;

    let hits = Arc::new(AtomicUsize::new(0));
    let backend = {
        let hits = hits.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let hits = hits.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let _ = stream.read(&mut buf).await;
                    hits.fetch_add(1, Ordering::SeqCst);
                    let _ = stream.write_all(b"tcp-ok").await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        address
    };

    let config = protocol_routed_config(backend, Protocol::Tcp, "tcp");
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    let gateway_id = uuid::Uuid::new_v4();
    let store = Arc::new(crate::managed_snapshot::ManagedSnapshotStore::new(
        Some(gateway_id),
        None,
    ));
    let runtime = GatewayRuntime::new(state).with_managed_snapshot_store(store.clone());
    let address = free_address().await;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = start_tcp_entrypoint(
        "traffic".to_string(),
        address,
        None,
        &[],
        runtime.clone(),
        shutdown_rx,
    )
    .await
    .unwrap()
    .into_task();

    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + chrono::Duration::milliseconds(150);
    let snapshot = crate::managed_snapshot::ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        issued_at,
        expires_at,
        format!("mode {{ kind = \"cloud-managed\" }}\nmanaged {{ gateway_id = \"{gateway_id}\" }}"),
    );
    let callback: crate::managed_snapshot::ManagedSnapshotReloadCallback =
        Arc::new(|_| Box::pin(async { Ok(GatewayConfig::default()) }));
    assert!(store.apply(snapshot, Some(&callback)).await.status.ready);
    assert!(runtime.allows_traffic());

    let mut before = TcpStream::connect(address).await.unwrap();
    before.write_all(b"ping").await.unwrap();
    let mut label = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), before.read(&mut label))
        .await
        .expect("pre-expiry TCP relay timed out")
        .unwrap();
    assert_eq!(&label[..n], b"tcp-ok");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while runtime.allows_traffic() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "managed snapshot should expire within the test deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let mut after = TcpStream::connect(address).await.unwrap();
    after.write_all(b"ping").await.unwrap();
    let n = tokio::time::timeout(Duration::from_millis(400), after.read(&mut label))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    assert_eq!(n, 0, "expired TCP snapshot must not relay upstream bytes");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "expired TCP snapshot must fail closed before upstream"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_snapshot_expiry_rejects_new_udp_datagrams_without_upstream() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::UdpSocket;

    let hits = Arc::new(AtomicUsize::new(0));
    let backend = {
        let hits = hits.clone();
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                if n == 0 {
                    continue;
                }
                hits.fetch_add(1, Ordering::SeqCst);
                let _ = socket.send_to(b"udp-ok", peer).await;
            }
        });
        address
    };

    let config = protocol_routed_config(backend, Protocol::Udp, "udp");
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    let gateway_id = uuid::Uuid::new_v4();
    let store = Arc::new(crate::managed_snapshot::ManagedSnapshotStore::new(
        Some(gateway_id),
        None,
    ));
    let runtime = GatewayRuntime::new(state).with_managed_snapshot_store(store.clone());
    let address = free_address().await;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let ep = EntrypointConfig {
        address: address.to_string(),
        protocol: Protocol::Udp,
        ..EntrypointConfig::new(address.to_string())
    };
    let (handle, _control) = super::udp_listener::start(
        "traffic".to_string(),
        address,
        &ep,
        runtime.clone(),
        shutdown_rx,
    )
    .await
    .unwrap();

    let issued_at = chrono::Utc::now();
    let expires_at = issued_at + chrono::Duration::milliseconds(150);
    let snapshot = crate::managed_snapshot::ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        issued_at,
        expires_at,
        format!("mode {{ kind = \"cloud-managed\" }}\nmanaged {{ gateway_id = \"{gateway_id}\" }}"),
    );
    let callback: crate::managed_snapshot::ManagedSnapshotReloadCallback =
        Arc::new(|_| Box::pin(async { Ok(GatewayConfig::default()) }));
    assert!(store.apply(snapshot, Some(&callback)).await.status.ready);
    assert!(runtime.allows_traffic());

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(address).await.unwrap();
    client.send(b"ping").await.unwrap();
    let mut label = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut label))
        .await
        .expect("pre-expiry UDP relay timed out")
        .unwrap();
    assert_eq!(&label[..n], b"udp-ok");
    assert_eq!(hits.load(Ordering::SeqCst), 1);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while runtime.allows_traffic() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "managed snapshot should expire within the test deadline"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    client.send(b"ping").await.unwrap();
    let after = tokio::time::timeout(Duration::from_millis(400), client.recv(&mut label)).await;
    assert!(
        after.is_err(),
        "expired UDP snapshot must not relay a datagram response"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "expired UDP snapshot must fail closed before upstream"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn acme_http01_challenge_is_served_from_runtime_store_before_routes() {
    use std::sync::atomic::Ordering;

    let (backend, hits) = spawn_counting_http_backend("should-not-hit").await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let runtime = GatewayRuntime::new(gateway_state(&config, log_tx, false));
    let challenges = Arc::new(crate::proxy::acme::ChallengeStore::new());
    challenges.add(
        "test-token".to_string(),
        "test-token.thumbprint".to_string(),
    );
    runtime.set_acme_challenges(Some(challenges));

    let (address, shutdown_tx, handle, _runtime) =
        start_test_entrypoint_with_runtime(runtime).await;
    let client = reqwest::Client::new();

    let ok = client
        .get(format!(
            "http://{address}/.well-known/acme-challenge/test-token"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    assert_eq!(
        ok.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/plain")
    );
    assert_eq!(ok.text().await.unwrap(), "test-token.thumbprint");
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "ACME HTTP-01 must not soft-open into PathPrefix(`/`) upstream"
    );

    let missing = client
        .get(format!(
            "http://{address}/.well-known/acme-challenge/unknown"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "unknown ACME tokens must 404 without upstream contact"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn acme_certificate_install_hot_swaps_live_https_acceptor() {
    use crate::config::TlsConfig;
    use crate::proxy::tls::build_tls_acceptor_from_pem;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/tls")
            .join(name)
    }

    let backend = spawn_http_backend("ok", "text/plain").await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let runtime = GatewayRuntime::new(gateway_state(&config, log_tx, false));

    let address = free_address().await;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let bootstrap = TlsConfig {
        cert_file: fixture("revision-1.crt").display().to_string(),
        key_file: fixture("revision-1.key").display().to_string(),
        acme: true,
        min_version: "1.2".to_string(),
        acme_email: Some("ops@example.com".to_string()),
        acme_domains: vec!["localhost".to_string()],
        acme_staging: true,
        acme_storage_path: None,
    };
    let handle = start_http_entrypoint(
        "web".to_string(),
        address,
        Some(&bootstrap),
        false,
        runtime,
        shutdown_rx,
    )
    .await
    .unwrap();

    let cert2 = std::fs::read_to_string(fixture("revision-2.crt")).unwrap();
    let key2 = std::fs::read_to_string(fixture("revision-2.key")).unwrap();
    let next = build_tls_acceptor_from_pem(&cert2, &key2, "1.2").unwrap();
    handle
        .install_http_tls_acceptor(next)
        .expect("ACME install must hot-swap the live HTTPS acceptor");

    let ca_v2 =
        reqwest::Certificate::from_pem(&std::fs::read(fixture("revision-2-ca.crt")).unwrap())
            .unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_v2)
        .build()
        .unwrap();
    let response = client
        .get(format!("https://{address}/"))
        .send()
        .await
        .expect("client trusting revision-2 CA must complete handshake after ACME install");
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "ok");

    let ca_v1 =
        reqwest::Certificate::from_pem(&std::fs::read(fixture("revision-1-ca.crt")).unwrap())
            .unwrap();
    let stale = reqwest::Client::builder()
        .add_root_certificate(ca_v1)
        .build()
        .unwrap();
    assert!(
        stale
            .get(format!("https://{address}/"))
            .send()
            .await
            .is_err(),
        "bootstrap revision-1 must not remain on the live acceptor after ACME install"
    );

    let _ = shutdown_tx.send(true);
    let mut task = handle.into_task();
    if tokio::time::timeout(Duration::from_secs(2), &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

async fn start_test_entrypoint(
    state: Arc<GatewayState>,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let (address, shutdown_tx, handle, _runtime) =
        start_test_entrypoint_with_runtime(GatewayRuntime::new(state)).await;
    (address, shutdown_tx, handle)
}

async fn start_test_entrypoint_with_runtime(
    runtime: GatewayRuntime,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
    GatewayRuntime,
) {
    let address = free_address().await;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = start_http_entrypoint(
        "web".to_string(),
        address,
        None,
        false,
        runtime.clone(),
        shutdown_rx,
    )
    .await
    .unwrap()
    .into_task();
    (address, shutdown_tx, handle, runtime)
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

async fn spawn_identifiable_websocket_backend(id: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let id = id;
            tokio::spawn(async move {
                let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
                use tokio_tungstenite::tungstenite::Message;
                websocket.send(Message::Text(id.into())).await.unwrap();
                while let Some(message) = websocket.next().await {
                    if message.is_err() {
                        break;
                    }
                }
            });
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
                    trust_forwarded_headers: false,
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
        ("x-forwarded-for", "127.0.0.1"),
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
        ("x-forwarded-for", "127.0.0.1"),
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
async fn body_limit_rejects_chunked_requests_before_backend_dispatch() {
    let backend = free_address().await;
    let mut config = routed_config(backend);
    config.middlewares.insert(
        "limit".to_string(),
        MiddlewareConfig {
            middleware_type: "body-limit".to_string(),
            max_body_bytes: Some(4),
            ..MiddlewareConfig::default()
        },
    );
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("limit".to_string());

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let request = format!(
        "POST /upload HTTP/1.1\r\nHost: {address}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    let response = String::from_utf8(response).unwrap();

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
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
async fn response_middleware_error_fails_closed_instead_of_returning_upstream_body() {
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

    let backend = spawn_http_backend("secret-upstream-body", "text/plain").await;
    let mut config = routed_config(backend);
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("fail-response".to_string());

    let mut registry = MiddlewareRegistry::new();
    registry
        .register("fail-response", FailResponseMiddleware)
        .unwrap();

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state_with_registry(
        &config, log_tx, true, &registry,
    ))
    .await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/"))
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
    let body = response.text().await.unwrap();
    assert!(body.contains("Middleware error"), "unexpected body: {body}");
    assert!(
        !body.contains("secret-upstream-body"),
        "unpolicied upstream body must not leak after response middleware failure"
    );

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 500);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn response_middleware_error_fails_closed_on_proxy_failure() {
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

    // Discard port: connection fails so the proxy-failure decoration path runs.
    let mut config = routed_config("127.0.0.1:9".parse().unwrap());
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("fail-response".to_string());

    let mut registry = MiddlewareRegistry::new();
    registry
        .register("fail-response", FailResponseMiddleware)
        .unwrap();

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state_with_registry(
        &config, log_tx, true, &registry,
    ))
    .await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/"))
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        500,
        "proxy-failure responses must fail closed when response middleware errors"
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("Middleware error"), "unexpected body: {body}");

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 500);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn response_middleware_error_fails_closed_on_sse_listener_without_upstream_body() {
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

    let secret = "data: secret-upstream-sse-chunk\n\n";
    let backend = spawn_http_backend(secret, "text/event-stream").await;
    let mut config = routed_config(backend);
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("fail-response".to_string());

    let mut registry = MiddlewareRegistry::new();
    registry
        .register("fail-response", FailResponseMiddleware)
        .unwrap();

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state_with_registry(
        &config, log_tx, true, &registry,
    ))
    .await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/events"))
        .header("connection", "close")
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
    let body = response.text().await.unwrap();
    assert!(
        body.contains("Middleware error"),
        "unexpected SSE fail-closed body: {body}"
    );
    assert!(
        !body.contains("secret-upstream-sse-chunk"),
        "unpolicied SSE upstream body must not leak after response middleware failure"
    );

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 500);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn response_middleware_error_fails_closed_on_grpc_listener_without_upstream_stream() {
    use crate::error::{GatewayError, Result};
    use crate::middleware::{Middleware, MiddlewareRegistry, RequestContext};
    use async_trait::async_trait;
    use http_body_util::BodyExt;

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

    let (backend, continue_response) = spawn_streaming_grpc_backend().await;
    let mut config = routed_config(backend);
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("fail-response".to_string());

    let mut registry = MiddlewareRegistry::new();
    registry
        .register("fail-response", FailResponseMiddleware)
        .unwrap();

    let (log_tx, mut log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state_with_registry(
        &config, log_tx, true, &registry,
    ))
    .await;
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
    assert_eq!(response.status(), 500);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_text = String::from_utf8_lossy(&body);
    assert!(
        body_text.contains("Middleware error"),
        "unexpected gRPC fail-closed body: {body_text}"
    );
    assert!(
        !body_text.contains("first") && !body_text.contains("second"),
        "unpolicied gRPC upstream frames must not leak after response middleware failure: {body_text}"
    );
    // Upstream may still be holding the probe stream; release it so the fixture exits.
    let _ = continue_response.send(());

    let entry = next_log(&mut log_rx).await;
    assert_eq!(entry.status, 500);

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

#[tokio::test]
async fn static_bundle_listener_serves_get_spa_and_honors_middleware() {
    let index = b"<html>home</html>";
    let asset = b"console.log(1)";
    let encoded = b"\x1f\x8bencoded-js";
    let index_digest = sha256_hex(index);
    let asset_digest = sha256_hex(asset);
    let encoded_digest = sha256_hex(encoded);
    let directory = tempfile::tempdir().unwrap();
    tokio::fs::write(directory.path().join(&index_digest), index)
        .await
        .unwrap();
    tokio::fs::write(directory.path().join(&asset_digest), asset)
        .await
        .unwrap();
    tokio::fs::write(directory.path().join(&encoded_digest), encoded)
        .await
        .unwrap();

    let mut entries = BTreeMap::new();
    entries.insert(
        "index.html".into(),
        StaticObjectEntry {
            digest: index_digest.clone(),
            size: index.len() as u64,
            media_type: "text/html".into(),
            content_encoding: None,
        },
    );
    entries.insert(
        "assets/app.js".into(),
        StaticObjectEntry {
            digest: asset_digest,
            size: asset.len() as u64,
            media_type: "application/javascript".into(),
            content_encoding: None,
        },
    );
    entries.insert(
        "assets/app.encoded.js".into(),
        StaticObjectEntry {
            digest: encoded_digest,
            size: encoded.len() as u64,
            media_type: "application/javascript".into(),
            content_encoding: Some("gzip".into()),
        },
    );

    let mut config = GatewayConfig::default();
    config.middlewares.insert(
        "auth".into(),
        MiddlewareConfig {
            middleware_type: "api-key".into(),
            header: Some("x-api-key".into()),
            keys: vec!["allowed".into()],
            ..MiddlewareConfig::default()
        },
    );
    config.routers.insert(
        "site".into(),
        RouterConfig {
            rule: "PathPrefix(`/`)".into(),
            service: "web".into(),
            entrypoints: vec!["web".into()],
            middlewares: vec!["auth".into()],
            priority: 0,
        },
    );
    config.static_bundles.insert(
        "web".into(),
        StaticBundleConfig {
            release_digest: index_digest,
            object_namespace: "org/proj/rel".into(),
            base_path: "/".into(),
            spa_fallback: Some("index.html".into()),
            provenance_digest: None,
            manifest: StaticBundleManifestConfig {
                entry_document: "index.html".into(),
                entries,
            },
            local_digest_store: Some(directory.path().to_path_buf()),
        },
    );
    config.validate().unwrap();

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let client = reqwest::Client::new();

    let denied = client
        .get(format!("http://{address}/"))
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);

    let home = client
        .get(format!("http://{address}/"))
        .header("x-api-key", "allowed")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(home.status(), 200);
    assert_eq!(home.headers()["x-content-type-options"], "nosniff");
    assert_eq!(home.headers()["content-type"], "text/html");
    assert_eq!(home.bytes().await.unwrap().as_ref(), index);

    let js = client
        .get(format!("http://{address}/assets/app.js"))
        .header("x-api-key", "allowed")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(js.status(), 200);
    let asset_etag = js.headers()["etag"].to_str().unwrap().to_owned();
    assert_eq!(js.headers()["accept-ranges"], "bytes");
    assert_eq!(js.bytes().await.unwrap().as_ref(), asset);

    let not_modified = client
        .get(format!("http://{address}/assets/app.js"))
        .header("x-api-key", "allowed")
        .header("if-none-match", &asset_etag)
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(not_modified.status(), 304);
    assert!(not_modified.bytes().await.unwrap().is_empty());

    let partial = client
        .get(format!("http://{address}/assets/app.js"))
        .header("x-api-key", "allowed")
        .header("range", "bytes=0-6")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(partial.status(), 206);
    assert_eq!(partial.headers()["content-range"], "bytes 0-6/14");
    assert_eq!(partial.bytes().await.unwrap().as_ref(), b"console");

    let if_range_hit = client
        .get(format!("http://{address}/assets/app.js"))
        .header("x-api-key", "allowed")
        .header("range", "bytes=0-6")
        .header("if-range", &asset_etag)
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(if_range_hit.status(), 206);
    assert_eq!(if_range_hit.headers()["content-range"], "bytes 0-6/14");
    assert_eq!(if_range_hit.bytes().await.unwrap().as_ref(), b"console");

    let if_range_miss = client
        .get(format!("http://{address}/assets/app.js"))
        .header("x-api-key", "allowed")
        .header("range", "bytes=0-6")
        .header("if-range", "\"deadbeef\"")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(if_range_miss.status(), 200);
    assert_eq!(if_range_miss.bytes().await.unwrap().as_ref(), asset);

    let encoded_response = client
        .get(format!("http://{address}/assets/app.encoded.js"))
        .header("x-api-key", "allowed")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(encoded_response.status(), 200);
    assert_eq!(encoded_response.headers()["content-encoding"], "gzip");
    assert_eq!(
        encoded_response.headers()["content-type"],
        "application/javascript"
    );
    assert_eq!(encoded_response.bytes().await.unwrap().as_ref(), encoded);

    let spa = client
        .get(format!("http://{address}/settings"))
        .header("x-api-key", "allowed")
        .header("accept", "text/html")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(spa.status(), 200);
    assert_eq!(spa.bytes().await.unwrap().as_ref(), index);

    let missing = client
        .get(format!("http://{address}/assets/missing.js"))
        .header("x-api-key", "allowed")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    let posted = client
        .post(format!("http://{address}/"))
        .header("x-api-key", "allowed")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), 405);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn static_bundle_listener_preserves_sealed_bytes_under_compress() {
    // Compressible identity-encoded body above the default compress min_size.
    let asset = format!("console.log({});\n", "x".repeat(1200)).into_bytes();
    let asset_digest = sha256_hex(&asset);
    let directory = tempfile::tempdir().unwrap();
    tokio::fs::write(directory.path().join(&asset_digest), &asset)
        .await
        .unwrap();

    let mut entries = BTreeMap::new();
    entries.insert(
        "assets/app.js".into(),
        StaticObjectEntry {
            digest: asset_digest.clone(),
            size: asset.len() as u64,
            media_type: "application/javascript".into(),
            content_encoding: None,
        },
    );

    let mut config = GatewayConfig::default();
    config.middlewares.insert(
        "gzip".into(),
        MiddlewareConfig {
            middleware_type: "compress".into(),
            ..MiddlewareConfig::default()
        },
    );
    config.routers.insert(
        "site".into(),
        RouterConfig {
            rule: "PathPrefix(`/`)".into(),
            service: "web".into(),
            entrypoints: vec!["web".into()],
            middlewares: vec!["gzip".into()],
            priority: 0,
        },
    );
    config.static_bundles.insert(
        "web".into(),
        StaticBundleConfig {
            release_digest: asset_digest.clone(),
            object_namespace: "org/proj/rel".into(),
            base_path: "/".into(),
            spa_fallback: None,
            provenance_digest: None,
            manifest: StaticBundleManifestConfig {
                entry_document: "assets/app.js".into(),
                entries,
            },
            local_digest_store: Some(directory.path().to_path_buf()),
        },
    );
    config.validate().unwrap();

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, true)).await;
    let client = reqwest::Client::new();

    let response = client
        .get(format!("http://{address}/assets/app.js"))
        .header("accept-encoding", "gzip")
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["cache-control"],
        "no-cache, no-transform"
    );
    assert_eq!(response.headers()["etag"], format!("\"{asset_digest}\""));
    assert!(
        response.headers().get("content-encoding").is_none(),
        "compress must not invent Content-Encoding for sealed static objects"
    );
    assert!(
        response.headers().get("vary").is_none(),
        "compress must not add Vary: Accept-Encoding for sealed static objects"
    );
    assert_eq!(response.bytes().await.unwrap().as_ref(), asset.as_slice());

    stop_test_entrypoint(shutdown_tx, handle).await;
}

struct GatedDigestStore {
    inner: crate::static_object::DirectoryObjectAuthority,
    started: tokio::sync::mpsc::UnboundedSender<()>,
    release: Arc<tokio::sync::Semaphore>,
}

#[async_trait::async_trait]
impl crate::static_object::port::ReadOnlyObjectPort for GatedDigestStore {
    async fn head(
        &self,
        digest: &str,
    ) -> Result<crate::static_object::port::StaticObjectMeta, crate::static_object::StaticObjectError>
    {
        self.inner.head(digest).await
    }

    async fn get(
        &self,
        digest: &str,
    ) -> Result<
        crate::static_object::port::StaticObjectBytes,
        crate::static_object::StaticObjectError,
    > {
        let _ = self.started.send(());
        let _permit = self
            .release
            .acquire()
            .await
            .expect("static object gate closed");
        self.inner.get(digest).await
    }
}

fn static_release_config(
    directory: &std::path::Path,
    release_marker: &[u8],
    index: &[u8],
) -> GatewayConfig {
    let index_digest = sha256_hex(index);
    let mut entries = BTreeMap::new();
    entries.insert(
        "index.html".into(),
        StaticObjectEntry {
            digest: index_digest.clone(),
            size: index.len() as u64,
            media_type: "text/html".into(),
            content_encoding: None,
        },
    );

    let mut config = GatewayConfig::default();
    config.routers.insert(
        "site".into(),
        RouterConfig {
            rule: "PathPrefix(`/`)".into(),
            service: "web".into(),
            entrypoints: vec!["web".into()],
            middlewares: vec![],
            priority: 0,
        },
    );
    config.static_bundles.insert(
        "web".into(),
        StaticBundleConfig {
            release_digest: sha256_hex(release_marker),
            object_namespace: "org/proj/rel".into(),
            base_path: "/".into(),
            spa_fallback: None,
            provenance_digest: None,
            manifest: StaticBundleManifestConfig {
                entry_document: "index.html".into(),
                entries,
            },
            local_digest_store: Some(directory.to_path_buf()),
        },
    );
    config.validate().unwrap();
    config
}

#[tokio::test]
async fn static_bundle_listener_drains_inflight_get_across_runtime_replace() {
    let old_index = b"<html>old-release</html>";
    let new_index = b"<html>new-release</html>";
    let directory = tempfile::tempdir().unwrap();
    tokio::fs::write(directory.path().join(sha256_hex(old_index)), old_index)
        .await
        .unwrap();
    tokio::fs::write(directory.path().join(sha256_hex(new_index)), new_index)
        .await
        .unwrap();

    let old_config = static_release_config(directory.path(), b"release-old", old_index);
    let new_config = static_release_config(directory.path(), b"release-new", new_index);

    let (started_tx, mut started_rx) = tokio::sync::mpsc::unbounded_channel();
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let mut old_bundles = build_static_bundle_runtimes(&old_config).expect("old static bundles");
    {
        let runtime = Arc::get_mut(old_bundles.get_mut("web").expect("web bundle"))
            .expect("unshared static bundle runtime");
        runtime.port = Arc::new(GatedDigestStore {
            inner: crate::static_object::DirectoryObjectAuthority::new(directory.path()),
            started: started_tx,
            release: release.clone(),
        });
    }

    let (old_log_tx, _old_log_rx) = tokio::sync::mpsc::unbounded_channel();
    let old_state = gateway_state_with_static_bundles(
        &old_config,
        old_log_tx,
        false,
        old_bundles,
        build_passive_health(&old_config),
        &crate::middleware::MiddlewareRegistry::new(),
    );
    let runtime = GatewayRuntime::new(old_state);
    let (address, shutdown_tx, handle, runtime) = start_test_entrypoint_with_runtime(runtime).await;
    let client = reqwest::Client::new();

    let inflight_address = address;
    let inflight = tokio::spawn(async move {
        client
            .get(format!("http://{inflight_address}/"))
            .header("connection", "close")
            .send()
            .await
            .unwrap()
    });

    tokio::time::timeout(Duration::from_secs(2), started_rx.recv())
        .await
        .expect("inflight static GET should reach object authority")
        .expect("gated digest store closed");

    let (new_log_tx, _new_log_rx) = tokio::sync::mpsc::unbounded_channel();
    let new_state = gateway_state(&new_config, new_log_tx, false);
    runtime.replace(new_state);

    let successor = reqwest::Client::new()
        .get(format!("http://{address}/"))
        .header("connection", "close")
        .send()
        .await
        .unwrap();
    assert_eq!(successor.status(), 200);
    assert_eq!(successor.bytes().await.unwrap().as_ref(), new_index);

    release.add_permits(1);
    let drained = tokio::time::timeout(Duration::from_secs(2), inflight)
        .await
        .expect("inflight static GET should finish on prior runtime")
        .unwrap();
    assert_eq!(drained.status(), 200);
    assert_eq!(drained.bytes().await.unwrap().as_ref(), old_index);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

async fn spawn_status_switchable_backend(status: Arc<std::sync::atomic::AtomicU16>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(_) => break,
            };
            let status = status.clone();
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let code = status.load(std::sync::atomic::Ordering::SeqCst);
                let body = if code == 200 { "recovered" } else { "broken" };
                let response = format!(
                    "HTTP/1.1 {code} {}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
                    if code == 200 { "OK" } else { "Error" },
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

#[tokio::test]
async fn passive_health_half_open_recovery_readmits_traffic_after_recovery_time() {
    use crate::service::passive_health::PassiveHealthConfig;
    use std::sync::atomic::{AtomicU16, Ordering};

    let status = Arc::new(AtomicU16::new(503));
    let backend = spawn_status_switchable_backend(status.clone()).await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state_with_passive_config(
        &config,
        log_tx,
        false,
        PassiveHealthConfig {
            error_threshold: 2,
            window: Duration::from_secs(30),
            error_status_codes: vec![500, 502, 503, 504],
            recovery_time: Duration::from_millis(100),
        },
    );
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/probe");

    let first = client.get(&url).send().await.unwrap();
    assert_eq!(first.status(), 503);
    let second = client.get(&url).send().await.unwrap();
    assert_eq!(second.status(), 503);

    // Backend is now passively unhealthy: Gateway must fail closed without a
    // healthy target until the half-open ticker re-enables it.
    let denied = client.get(&url).send().await.unwrap();
    assert_eq!(denied.status(), 503);

    status.store(200, Ordering::SeqCst);
    let mut recovered = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let response = client.get(&url).send().await.unwrap();
        if response.status() == 200 {
            assert_eq!(response.text().await.unwrap(), "recovered");
            recovered = Some(());
            break;
        }
        assert_eq!(response.status(), 503);
    }
    assert!(
        recovered.is_some(),
        "passive half-open recovery did not re-admit traffic after recovery_time"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn passive_health_half_open_still_broken_reblacklists_after_threshold() {
    use crate::service::passive_health::PassiveHealthConfig;
    use std::sync::atomic::{AtomicU16, Ordering};

    let status = Arc::new(AtomicU16::new(503));
    let backend = spawn_status_switchable_backend(status.clone()).await;
    let config = routed_config(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state_with_passive_config(
        &config,
        log_tx,
        false,
        PassiveHealthConfig {
            error_threshold: 2,
            window: Duration::from_secs(30),
            error_status_codes: vec![500, 502, 503, 504],
            recovery_time: Duration::from_millis(100),
        },
    );
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/probe");

    let first = client.get(&url).send().await.unwrap();
    assert_eq!(first.status(), 503);
    assert_eq!(first.text().await.unwrap(), "broken");
    let second = client.get(&url).send().await.unwrap();
    assert_eq!(second.status(), 503);
    assert_eq!(second.text().await.unwrap(), "broken");

    let denied = client.get(&url).send().await.unwrap();
    assert_eq!(denied.status(), 503);
    assert_eq!(
        denied.text().await.unwrap(),
        r#"{"error":"No healthy backends"}"#
    );

    // Keep the upstream broken: after recovery_time the half-open probe must
    // contact it again, then re-trip and fail closed without a Gateway restart.
    assert_eq!(status.load(Ordering::SeqCst), 503);
    let mut saw_probe = false;
    let mut reblacklisted = false;
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 503);
        let body = response.text().await.unwrap();
        match body.as_str() {
            "broken" => saw_probe = true,
            r#"{"error":"No healthy backends"}"# if saw_probe => {
                reblacklisted = true;
                break;
            }
            r#"{"error":"No healthy backends"}"# => {}
            other => panic!("unexpected passive-health body: {other}"),
        }
    }
    assert!(
        saw_probe,
        "half-open recovery did not re-admit a probe to the still-broken backend"
    );
    assert!(
        reblacklisted,
        "still-broken backend was not re-blacklisted after the error threshold"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

fn routed_config_with_circuit_breaker(backend: SocketAddr) -> GatewayConfig {
    let mut config = routed_config(backend);
    config.middlewares.insert(
        "cb".to_string(),
        MiddlewareConfig {
            middleware_type: "circuit-breaker".to_string(),
            failure_threshold: Some(2),
            cooldown_secs: Some(1),
            success_threshold: Some(1),
            ..MiddlewareConfig::default()
        },
    );
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("cb".to_string());
    config
}

const CIRCUIT_BREAKER_OPEN_BODY: &str = r#"{"error":"Service unavailable (circuit breaker open)"}"#;

#[tokio::test]
async fn circuit_breaker_half_open_probe_closes_after_success_on_listener() {
    use std::sync::atomic::{AtomicU16, Ordering};

    let status = Arc::new(AtomicU16::new(503));
    let backend = spawn_status_switchable_backend(status.clone()).await;
    let config = routed_config_with_circuit_breaker(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/probe");

    for _ in 0..2 {
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(response.text().await.unwrap(), "broken");
    }

    let open = client.get(&url).send().await.unwrap();
    assert_eq!(open.status(), 503);
    assert_eq!(open.text().await.unwrap(), CIRCUIT_BREAKER_OPEN_BODY);

    status.store(200, Ordering::SeqCst);
    let mut recovered = None;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let response = client.get(&url).send().await.unwrap();
        if response.status() == 200 {
            assert_eq!(response.text().await.unwrap(), "recovered");
            recovered = Some(());
            break;
        }
        assert_eq!(response.status(), 503);
        let body = response.text().await.unwrap();
        assert!(
            body == CIRCUIT_BREAKER_OPEN_BODY || body == "broken",
            "unexpected body while waiting for half-open close: {body}"
        );
    }
    assert!(
        recovered.is_some(),
        "circuit breaker half-open success did not close the circuit on the listener"
    );

    let follow_up = client.get(&url).send().await.unwrap();
    assert_eq!(follow_up.status(), 200);
    assert_eq!(follow_up.text().await.unwrap(), "recovered");

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn circuit_breaker_half_open_still_failing_reopens_on_listener() {
    use std::sync::atomic::{AtomicU16, Ordering};

    let status = Arc::new(AtomicU16::new(503));
    let backend = spawn_status_switchable_backend(status.clone()).await;
    let config = routed_config_with_circuit_breaker(backend);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/probe");

    for _ in 0..2 {
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(response.text().await.unwrap(), "broken");
    }

    let open = client.get(&url).send().await.unwrap();
    assert_eq!(open.status(), 503);
    assert_eq!(open.text().await.unwrap(), CIRCUIT_BREAKER_OPEN_BODY);

    assert_eq!(status.load(Ordering::SeqCst), 503);
    let mut saw_probe = false;
    let mut reopened = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 503);
        let body = response.text().await.unwrap();
        match body.as_str() {
            "broken" => saw_probe = true,
            CIRCUIT_BREAKER_OPEN_BODY if saw_probe => {
                reopened = true;
                break;
            }
            CIRCUIT_BREAKER_OPEN_BODY => {}
            other => panic!("unexpected circuit-breaker body: {other}"),
        }
    }
    assert!(
        saw_probe,
        "half-open probe did not reach the still-failing upstream"
    );
    assert!(
        reopened,
        "still-failing probe did not re-open the circuit breaker on the listener"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn active_health_check_evicts_backend_on_listener_then_readmits_when_healthy() {
    use crate::service::passive_health::PassiveHealthConfig;
    use std::sync::atomic::{AtomicU16, Ordering};

    let status = Arc::new(AtomicU16::new(200));
    let backend = spawn_status_switchable_backend(status.clone()).await;
    let mut config = routed_config(backend);
    config
        .services
        .get_mut("test-service")
        .unwrap()
        .load_balancer
        .health_check = Some(HealthCheckConfig {
        path: "/health".to_string(),
        interval: "20ms".to_string(),
        timeout: "1s".to_string(),
        unhealthy_threshold: 1,
        healthy_threshold: 1,
    });

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    // Keep passive health from racing the active probe contract under test.
    let state = gateway_state_with_passive_config(
        &config,
        log_tx,
        false,
        PassiveHealthConfig {
            error_threshold: 100,
            window: Duration::from_secs(30),
            error_status_codes: vec![500, 502, 503, 504],
            recovery_time: Duration::from_secs(30),
        },
    );
    let health_tasks = state
        .service_registry
        .prepare_health_checks(&config.services, None)
        .expect("prepare active health checks")
        .start();
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/probe");

    let healthy = client.get(&url).send().await.unwrap();
    assert_eq!(healthy.status(), 200);
    assert_eq!(healthy.text().await.unwrap(), "recovered");

    status.store(503, Ordering::SeqCst);
    let mut evicted = None;
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 503);
        let body = response.text().await.unwrap();
        if body == r#"{"error":"No healthy backends"}"# {
            evicted = Some(());
            break;
        }
        assert_eq!(body, "broken");
    }
    assert!(
        evicted.is_some(),
        "active health check did not evict the backend from the live listener"
    );

    status.store(200, Ordering::SeqCst);
    let mut readmitted = None;
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let response = client.get(&url).send().await.unwrap();
        let status_code = response.status();
        let body = response.text().await.unwrap();
        if status_code == 200 {
            assert_eq!(body, "recovered");
            readmitted = Some(());
            break;
        }
        assert_eq!(status_code, 503);
        assert_eq!(body, r#"{"error":"No healthy backends"}"#);
    }
    assert!(
        readmitted.is_some(),
        "active health check did not re-admit the recovered backend on the live listener"
    );

    health_tasks.shutdown().await;
    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn active_health_check_evicts_revision_only_backend_on_listener_then_readmits_when_healthy() {
    use crate::config::RevisionConfig;
    use crate::service::passive_health::PassiveHealthConfig;
    use std::sync::atomic::{AtomicU16, Ordering};

    let status = Arc::new(AtomicU16::new(200));
    let backend = spawn_status_switchable_backend(status.clone()).await;
    let mut config = routed_config(backend);
    let service = config.services.get_mut("test-service").unwrap();
    // Revision-only pool: empty service-level servers so traffic and active
    // probes must both use RevisionRouter backends (not the legacy LB).
    service.load_balancer.servers.clear();
    service.revisions = vec![RevisionConfig {
        name: "v1".to_string(),
        traffic_percent: 100,
        servers: vec![ServerConfig {
            url: format!("http://{backend}"),
            weight: 1,
            target: None,
        }],
        strategy: Strategy::RoundRobin,
    }];
    service.load_balancer.health_check = Some(HealthCheckConfig {
        path: "/health".to_string(),
        interval: "20ms".to_string(),
        timeout: "1s".to_string(),
        unhealthy_threshold: 1,
        healthy_threshold: 1,
    });

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state_with_passive_config(
        &config,
        log_tx,
        false,
        PassiveHealthConfig {
            error_threshold: 100,
            window: Duration::from_secs(30),
            error_status_codes: vec![500, 502, 503, 504],
            recovery_time: Duration::from_secs(30),
        },
    );
    let revision_routers = state
        .scaling
        .as_ref()
        .expect("revision-only service must build ScalingState")
        .revision_routers
        .clone();
    assert!(
        revision_routers.contains_key("test-service"),
        "revision router missing for revision-only service"
    );
    let health_tasks = state
        .service_registry
        .prepare_health_checks(&config.services, Some(&revision_routers))
        .expect("prepare revision active health checks")
        .start();
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/probe");

    let healthy = client.get(&url).send().await.unwrap();
    assert_eq!(healthy.status(), 200);
    assert_eq!(healthy.text().await.unwrap(), "recovered");

    status.store(503, Ordering::SeqCst);
    let mut evicted = None;
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let response = client.get(&url).send().await.unwrap();
        assert_eq!(response.status(), 503);
        let body = response.text().await.unwrap();
        if body == r#"{"error":"No healthy backends"}"# {
            evicted = Some(());
            break;
        }
        assert_eq!(body, "broken");
    }
    assert!(
        evicted.is_some(),
        "revision active health check did not evict the revision-only backend on the live listener"
    );

    status.store(200, Ordering::SeqCst);
    let mut readmitted = None;
    for _ in 0..80 {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let response = client.get(&url).send().await.unwrap();
        let status_code = response.status();
        let body = response.text().await.unwrap();
        if status_code == 200 {
            assert_eq!(body, "recovered");
            readmitted = Some(());
            break;
        }
        assert_eq!(status_code, 503);
        assert_eq!(body, r#"{"error":"No healthy backends"}"#);
    }
    assert!(
        readmitted.is_some(),
        "revision active health check did not re-admit the recovered revision backend on the live listener"
    );

    health_tasks.shutdown().await;
    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn failover_routes_to_backup_on_listener_when_primary_unhealthy() {
    let primary = spawn_http_backend("primary", "text/plain").await;
    let backup = spawn_http_backend("backup", "text/plain").await;
    let mut config = routed_config(primary);
    config.services.insert(
        "backup-service".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: format!("http://{backup}"),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
                tls_ca_file: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        },
    );
    config.services.get_mut("test-service").unwrap().failover = Some(FailoverConfig {
        service: "backup-service".to_string(),
    });

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    assert!(
        state.failovers.contains_key("test-service"),
        "failover selector must be built for the primary service"
    );
    state
        .service_registry
        .get("test-service")
        .expect("primary service")
        .backends()[0]
        .set_healthy(false);

    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let response = reqwest::Client::new()
        .get(format!("http://{address}/probe"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.text().await.unwrap(),
        "backup",
        "unhealthy primary must fail over to the backup service on the live listener"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

async fn spawn_counting_http_backend(
    body: &'static str,
) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits_accept = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(_) => break,
            };
            hits_accept.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = [0u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, hits)
}

async fn spawn_fixed_status_http_backend(status: u16, body: &'static str) -> SocketAddr {
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
                let reason = if status == 200 { "OK" } else { "Error" };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

fn routed_config_with_forward_auth(backend: SocketAddr, auth_url: &str) -> GatewayConfig {
    let mut config = routed_config(backend);
    config.middlewares.insert(
        "gate".to_string(),
        MiddlewareConfig {
            middleware_type: "forward-auth".to_string(),
            forward_auth_url: Some(auth_url.to_string()),
            ..MiddlewareConfig::default()
        },
    );
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("gate".to_string());
    config
}

#[tokio::test]
async fn forward_auth_unreachable_returns_502_on_listener_without_upstream_contact() {
    use std::sync::atomic::Ordering;

    let (upstream, upstream_hits) = spawn_counting_http_backend("secret-upstream-body").await;
    let config = routed_config_with_forward_auth(upstream, "http://127.0.0.1:1/verify");
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/probe"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(
        response.text().await.unwrap(),
        r#"{"error":"Auth service unavailable"}"#
    );
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "unreachable forward-auth must not contact the upstream on the live listener"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn forward_auth_deny_returns_auth_status_on_listener_without_upstream_contact() {
    use std::sync::atomic::Ordering;

    let auth = spawn_fixed_status_http_backend(403, r#"{"error":"denied"}"#).await;
    let (upstream, upstream_hits) = spawn_counting_http_backend("secret-upstream-body").await;
    let config = routed_config_with_forward_auth(upstream, &format!("http://{auth}/verify"));
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/probe"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert_eq!(response.text().await.unwrap(), r#"{"error":"denied"}"#);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "denied forward-auth must not contact the upstream on the live listener"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn sticky_session_cookie_pins_backend_on_listener() {
    let backend_a = spawn_http_backend("backend-a", "text/plain").await;
    let backend_b = spawn_http_backend("backend-b", "text/plain").await;
    let mut config = routed_config(backend_a);
    let service = config.services.get_mut("test-service").unwrap();
    service.load_balancer.servers = vec![
        ServerConfig {
            url: format!("http://{backend_a}"),
            weight: 1,
            target: None,
        },
        ServerConfig {
            url: format!("http://{backend_b}"),
            weight: 1,
            target: None,
        },
    ];
    service.load_balancer.sticky = Some(StickyConfig {
        cookie: "gw_sticky".to_string(),
    });

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    assert!(
        state.sticky_managers.contains_key("test-service"),
        "sticky manager must be built for the sticky service"
    );
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let client = reqwest::Client::new();
    let url = format!("http://{address}/probe");

    let first = client.get(&url).send().await.unwrap();
    assert_eq!(first.status(), 200);
    let set_cookie = first
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("gw_sticky="))
        .expect("sticky Set-Cookie must be emitted on first response")
        .to_string();
    let session = set_cookie
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string();
    let first_body = first.text().await.unwrap();
    assert!(
        first_body == "backend-a" || first_body == "backend-b",
        "unexpected first sticky response body: {first_body}"
    );

    for _ in 0..6 {
        let response = client
            .get(&url)
            .header(http::header::COOKIE, &session)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.text().await.unwrap(),
            first_body,
            "sticky cookie must pin subsequent requests to the same backend"
        );
    }

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn sticky_session_cookie_pins_websocket_backend_on_listener() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::Message;

    let backend_a = spawn_identifiable_websocket_backend("backend-a").await;
    let backend_b = spawn_identifiable_websocket_backend("backend-b").await;
    let mut config = routed_config(backend_a);
    let service = config.services.get_mut("test-service").unwrap();
    service.load_balancer.servers = vec![
        ServerConfig {
            url: format!("http://{backend_a}"),
            weight: 1,
            target: None,
        },
        ServerConfig {
            url: format!("http://{backend_b}"),
            weight: 1,
            target: None,
        },
    ];
    service.load_balancer.sticky = Some(StickyConfig {
        cookie: "gw_sticky".to_string(),
    });

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    assert!(
        state.sticky_managers.contains_key("test-service"),
        "sticky manager must be built for the sticky service"
    );
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let (mut first_ws, first_response) =
        tokio_tungstenite::connect_async(format!("ws://{address}/socket"))
            .await
            .unwrap();
    assert_eq!(first_response.status(), 101);
    let set_cookie = first_response
        .headers()
        .get_all(http::header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with("gw_sticky="))
        .expect("sticky Set-Cookie must be emitted on first WebSocket upgrade")
        .to_string();
    let session = set_cookie
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string();
    let first_id = match first_ws.next().await.unwrap().unwrap() {
        Message::Text(text) => text.to_string(),
        other => panic!("expected backend identity text frame, got {other:?}"),
    };
    assert!(
        first_id == "backend-a" || first_id == "backend-b",
        "unexpected first sticky websocket identity: {first_id}"
    );
    first_ws.close(None).await.unwrap();

    for _ in 0..6 {
        let mut request = format!("ws://{address}/socket")
            .into_client_request()
            .unwrap();
        request
            .headers_mut()
            .insert(http::header::COOKIE, session.parse().unwrap());
        let (mut websocket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
        assert_eq!(response.status(), 101);
        let pinned_id = match websocket.next().await.unwrap().unwrap() {
            Message::Text(text) => text.to_string(),
            other => panic!("expected backend identity text frame, got {other:?}"),
        };
        assert_eq!(
            pinned_id, first_id,
            "sticky cookie must pin subsequent WebSocket upgrades to the same backend"
        );
        websocket.close(None).await.unwrap();
    }

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn traffic_mirror_copies_buffered_request_to_shadow_on_listener() {
    let primary = spawn_http_backend("primary-ok", "text/plain").await;
    let (shadow, shadow_rx) = spawn_capturing_http_backend().await;
    let mut config = routed_config(primary);
    config.services.insert(
        "shadow-service".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: format!("http://{shadow}"),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
                tls_ca_file: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        },
    );
    config.services.get_mut("test-service").unwrap().mirror = Some(MirrorConfig {
        service: "shadow-service".to_string(),
        percentage: 100,
    });

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    assert!(
        state.mirrors.contains_key("test-service"),
        "traffic mirror must be built for the primary service"
    );
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;
    let payload = b"mirror-payload";
    let response = reqwest::Client::new()
        .post(format!("http://{address}/probe"))
        .header("connection", "close")
        .body(payload.as_slice())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "primary-ok");

    let captured = tokio::time::timeout(Duration::from_secs(2), shadow_rx)
        .await
        .expect("shadow mirror request timed out")
        .expect("shadow capture channel closed");
    assert_eq!(
        captured.body.as_slice(),
        payload.as_slice(),
        "100% traffic mirror must copy the buffered request body to the shadow backend"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[cfg(feature = "redis")]
fn routed_config_with_redis_rate_limit(
    backend: SocketAddr,
    redis_url: &str,
    redis_fail_open: bool,
) -> GatewayConfig {
    let mut config = routed_config(backend);
    config.middlewares.insert(
        "rl".to_string(),
        MiddlewareConfig {
            middleware_type: "rate-limit-redis".to_string(),
            redis_url: Some(redis_url.to_string()),
            rate: Some(100),
            burst: Some(50),
            redis_fail_open,
            ..MiddlewareConfig::default()
        },
    );
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("rl".to_string());
    config
}

#[cfg(feature = "redis")]
#[tokio::test]
async fn rate_limit_redis_unreachable_returns_503_on_listener_without_upstream_contact() {
    use std::sync::atomic::Ordering;

    let (upstream, upstream_hits) = spawn_counting_http_backend("secret-upstream-body").await;
    let config = routed_config_with_redis_rate_limit(upstream, "redis://127.0.0.1:1", false);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/probe"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        response.text().await.unwrap(),
        r#"{"error":"Distributed rate limiter unavailable"}"#
    );
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        0,
        "fail-closed rate-limit-redis must not contact upstream when Redis is unreachable"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[cfg(feature = "redis")]
#[tokio::test]
async fn rate_limit_redis_fail_open_reaches_upstream_on_listener_when_redis_unreachable() {
    use std::sync::atomic::Ordering;

    let (upstream, upstream_hits) = spawn_counting_http_backend("redis-fail-open-ok").await;
    let config = routed_config_with_redis_rate_limit(upstream, "redis://127.0.0.1:1", true);
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state(&config, log_tx, false)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/probe"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "redis-fail-open-ok");
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        1,
        "explicit redis_fail_open must still reach upstream when Redis is unreachable"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn traffic_mirror_primary_still_succeeds_when_shadow_unreachable_on_listener() {
    let primary = spawn_http_backend("primary-ok", "text/plain").await;
    let mut config = routed_config(primary);
    config.services.insert(
        "shadow-service".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    // Discard port: shadow connect fails; primary must still succeed.
                    url: "http://127.0.0.1:9".to_string(),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
                tls_ca_file: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        },
    );
    config.services.get_mut("test-service").unwrap().mirror = Some(MirrorConfig {
        service: "shadow-service".to_string(),
        percentage: 100,
    });

    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
    let state = gateway_state(&config, log_tx, false);
    assert!(state.mirrors.contains_key("test-service"));
    let (address, shutdown_tx, handle) = start_test_entrypoint(state).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/probe"))
        .header("connection", "close")
        .body("mirror-payload")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.text().await.unwrap(),
        "primary-ok",
        "unreachable shadow must not block or fail the primary response"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}
