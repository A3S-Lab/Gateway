use super::*;
use crate::config::{
    GatewayConfig, InferenceConfig, InferenceCredentialConfig, InferenceEndpoint,
    InferenceGrantConfig, InferenceLimitsConfig, InferenceModelConfig, InferenceRouteConfig,
    InferenceTargetConfig, LoadBalancerConfig, MirrorConfig, OperatingMode, RouterConfig,
    ServerConfig, ServiceConfig, Strategy,
};
use crate::gateway::builders::{
    build_mirror_failover_state, build_passive_health, build_pipeline_cache, build_route_plans,
    build_scaling_state, build_static_bundle_runtimes, build_sticky_managers,
};
use crate::observability::access_log::{AccessLog, AccessLogEntry};
use crate::observability::metrics::GatewayMetrics;
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const KEY_PREFIX: &str = "a3s_inf_abc12345";

pub(super) fn inference_key(character: char) -> String {
    format!("{KEY_PREFIX}{}", character.to_string().repeat(64))
}

fn verifier(secret: &str) -> String {
    let salt = SaltString::encode_b64(b"a3s-entrypoint-test").unwrap();
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

pub(super) fn inference_config(
    backend: SocketAddr,
    key: &str,
    policy_expires_at: DateTime<Utc>,
) -> GatewayConfig {
    let gateway_id = Uuid::new_v4();
    let environment_id = Uuid::new_v4();
    let credential_id = Uuid::new_v4();
    let route_id = Uuid::new_v4();
    let mut config = GatewayConfig {
        mode: OperatingMode::CloudManaged,
        managed: crate::config::ManagedConfig {
            gateway_id: Some(gateway_id),
            state_file: None,
            usage_spool: None,
        },
        ..GatewayConfig::default()
    };
    config.routers.insert(
        "test-router".into(),
        RouterConfig {
            rule: "PathPrefix(`/`)".into(),
            service: "default-service".into(),
            entrypoints: vec!["web".into()],
            middlewares: vec![],
            priority: 0,
        },
    );
    config.services.insert(
        "default-service".into(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".into(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: "http://127.0.0.1:9".into(),
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
    config.services.insert(
        "model-service".into(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".into(),
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

    let models = ["allowed-model", "hidden-model"]
        .into_iter()
        .map(|alias| {
            (
                alias.to_string(),
                InferenceModelConfig {
                    model_id: Uuid::new_v4(),
                    targets: vec![InferenceTargetConfig {
                        target_id: Uuid::new_v4(),
                        service: "model-service".into(),
                        upstream_model: format!("internal-{alias}"),
                        priority: 0,
                        weight: 1,
                    }],
                    scheduling: None,
                },
            )
        })
        .collect();
    config.inference = Some(InferenceConfig {
        expires_at: policy_expires_at,
        tokenizer_revision: crate::config::INFERENCE_TOKENIZER_REVISION.into(),
        credentials: HashMap::from([(
            credential_id,
            InferenceCredentialConfig {
                credential_id,
                environment_id,
                audience: "cloud-inference".into(),
                prefix: KEY_PREFIX.into(),
                verifier_hash: verifier(key),
                generation: 3,
                expires_at: Utc::now() + ChronoDuration::hours(1),
                revoked: false,
            },
        )]),
        routes: HashMap::from([(
            route_id,
            InferenceRouteConfig {
                route_id,
                router: "test-router".into(),
                environment_id,
                policy_revision: 7,
                models,
                grants: HashMap::from([(
                    credential_id,
                    InferenceGrantConfig {
                        credential_generation: 3,
                        models: vec!["allowed-model".into()],
                        endpoints: vec![
                            InferenceEndpoint::Models,
                            InferenceEndpoint::ChatCompletions,
                        ],
                        limits: InferenceLimitsConfig {
                            max_concurrent_requests: 2,
                            requests_per_minute: 60,
                            request_burst: 2,
                            tokens_per_minute: 10_000,
                        },
                    },
                )]),
            },
        )]),
        workers: HashMap::new(),
    });
    config
}

pub(super) fn gateway_state(config: &GatewayConfig) -> Arc<GatewayState> {
    gateway_state_with_runtime(
        config,
        None,
        None,
        &crate::middleware::MiddlewareRegistry::new(),
    )
}

pub(super) fn gateway_state_with_registry(
    config: &GatewayConfig,
    middleware_registry: &crate::middleware::MiddlewareRegistry,
) -> Arc<GatewayState> {
    gateway_state_with_runtime(config, None, None, middleware_registry)
}

pub(super) fn gateway_state_with_previous(
    config: &GatewayConfig,
    previous: Option<&InferenceAuthorizer>,
) -> Arc<GatewayState> {
    gateway_state_with_runtime(
        config,
        previous,
        None,
        &crate::middleware::MiddlewareRegistry::new(),
    )
}

pub(super) fn gateway_state_with_distributed_key(
    config: &GatewayConfig,
    name: &str,
    value: &str,
) -> Arc<GatewayState> {
    gateway_state_with_runtime(
        config,
        None,
        Some(crate::inference::DistributedServingOrchestrator::with_test_key(name, value)),
        &crate::middleware::MiddlewareRegistry::new(),
    )
}

pub(super) fn gateway_state_with_distributed_key_and_registry(
    config: &GatewayConfig,
    name: &str,
    value: &str,
    middleware_registry: &crate::middleware::MiddlewareRegistry,
) -> Arc<GatewayState> {
    gateway_state_with_runtime(
        config,
        None,
        Some(crate::inference::DistributedServingOrchestrator::with_test_key(name, value)),
        middleware_registry,
    )
}

fn gateway_state_with_runtime(
    config: &GatewayConfig,
    previous: Option<&InferenceAuthorizer>,
    distributed_serving: Option<crate::inference::DistributedServingOrchestrator>,
    middleware_registry: &crate::middleware::MiddlewareRegistry,
) -> Arc<GatewayState> {
    let service_registry =
        Arc::new(ServiceRegistry::from_config(&config.services).expect("service registry"));
    let router_table =
        Arc::new(RouterTable::from_config(&config.routers).expect("compiled HTTP router table"));
    let pipeline_cache = build_pipeline_cache(config, &config.middlewares, middleware_registry)
        .expect("middleware pipeline cache");
    let passive_health = build_passive_health(config);
    let static_bundles = build_static_bundle_runtimes(config).expect("static bundles");
    let route_plans = build_route_plans(
        config,
        &router_table,
        &pipeline_cache,
        &service_registry,
        &passive_health,
        &static_bundles,
    )
    .expect("compiled route plans");
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel::<AccessLogEntry>();
    let http_proxy = Arc::new(HttpProxy::new());
    let service_http_proxies = HashMap::new();
    let (mirrors, failovers) = build_mirror_failover_state(
        config,
        &service_registry,
        &http_proxy,
        &service_http_proxies,
    )
    .expect("mirror/failover runtime");

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
            .map(|policy| InferenceAuthorizer::with_previous(policy, previous))
            .map(Arc::new),
        distributed_serving: Arc::new(distributed_serving.unwrap_or_else(|| {
            crate::inference::DistributedServingOrchestrator::from_policy(config.inference.as_ref())
                .expect("distributed-serving runtime")
        })),
        usage_spool: None,
        http_proxy,
        service_http_proxies,
        grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
        service_grpc_proxies: HashMap::new(),
        service_ws_tls: HashMap::new(),
        scaling: build_scaling_state(config),
        mirrors,
        failovers,
        access_log: Arc::new(AccessLog::new()),
        log_tx: log_tx.into(),
        sticky_managers: build_sticky_managers(config).expect("sticky managers"),
        passive_health,
        metrics: Arc::new(GatewayMetrics::new()),
        shutdown_timeout: Duration::from_secs(config.shutdown_timeout_secs),
        metrics_enabled: false,
        access_log_enabled: false,
        tracing_enabled: false,
    })
}

pub(super) fn set_limits(config: &mut GatewayConfig, limits: InferenceLimitsConfig) {
    let policy = config.inference.as_mut().expect("inference policy");
    let route = policy.routes.values_mut().next().expect("inference route");
    let grant = route.grants.values_mut().next().expect("inference grant");
    grant.limits = limits;
}

pub(super) async fn start_test_entrypoint(
    state: Arc<GatewayState>,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    start_test_runtime(GatewayRuntime::new(state)).await
}

pub(super) async fn start_test_runtime(
    runtime: GatewayRuntime,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = start_http_entrypoint(
        "web".to_string(),
        address,
        None,
        false,
        runtime,
        shutdown_rx,
    )
    .await
    .unwrap()
    .into_task();
    (address, shutdown_tx, handle)
}

pub(super) async fn stop_test_entrypoint(
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

pub(super) async fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end = loop {
        let read = stream.read(&mut buffer).await.unwrap();
        if read == 0 {
            return request;
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(offset) = request.windows(4).position(|part| part == b"\r\n\r\n") {
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
    request
}

pub(super) async fn spawn_capturing_backend(
) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_http_request(&mut stream).await;

        let _ = request_tx.send(request);
        let response =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
}

pub(super) async fn spawn_blocking_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_http_request(&mut stream).await;
        let _ = request_tx.send(());
        let _ = release_rx.await;
        let response =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx, release_tx)
}

/// Aggregated OpenAI SSE upstream that emits one event, then holds until released.
pub(super) async fn spawn_holding_streaming_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let _ = read_http_request(&mut stream).await;
        let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
        let first = "data: aggregated-sse-first\n\n";
        let first_chunk = format!("{:x}\r\n{first}\r\n", first.len());
        if stream.write_all(headers.as_bytes()).await.is_err() {
            return;
        }
        if stream.write_all(first_chunk.as_bytes()).await.is_err() {
            return;
        }
        let _ = stream.flush().await;
        let _ = started_tx.send(());
        let _ = release_rx.await;
        let last = "data: [DONE]\n\n";
        let last_chunk = format!("{:x}\r\n{last}\r\n0\r\n\r\n", last.len());
        let _ = stream.write_all(last_chunk.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, started_rx, release_tx)
}

pub(super) async fn spawn_streaming_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (disconnected_tx, disconnected_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
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

    (address, started_rx, disconnected_rx)
}

#[tokio::test]
async fn managed_inference_authenticates_before_body_and_strips_authorization() {
    let key = inference_key('a');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://{address}/v1/chat/completions"))
        .header("content-type", "text/plain")
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers()["www-authenticate"],
        r#"Bearer realm="a3s-inference""#
    );

    let request_body = r#"{"model":"allowed-model","messages":[]}"#;
    let response = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(request_body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let request = tokio::time::timeout(Duration::from_secs(2), captured_request)
        .await
        .unwrap()
        .unwrap();
    let request_text = String::from_utf8(request).unwrap();
    assert!(!request_text.to_ascii_lowercase().contains("authorization:"));
    assert!(!request_text.contains(&key));
    let body_offset = request_text.find("\r\n\r\n").unwrap() + 4;
    let routed_body: serde_json::Value =
        serde_json::from_str(&request_text[body_offset..]).unwrap();
    assert_eq!(routed_body["model"], "internal-allowed-model");
    assert_eq!(routed_body["messages"], serde_json::json!([]));

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_samples_mirror_after_resolving_target_service() {
    let key = inference_key('a');
    let (primary, primary_request) = spawn_capturing_backend().await;
    let (shadow, shadow_request) = spawn_capturing_backend().await;
    let mut config = inference_config(primary, &key, Utc::now() + ChronoDuration::hours(1));
    let mut shadow_service = config.services["model-service"].clone();
    shadow_service.load_balancer.servers[0].url = format!("http://{shadow}");
    shadow_service.mirror = None;
    config
        .services
        .insert("shadow-service".to_string(), shadow_service);
    config.services.get_mut("model-service").unwrap().mirror = Some(MirrorConfig {
        service: "shadow-service".to_string(),
        percentage: 100,
    });
    config.validate().unwrap();

    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    let primary_request = tokio::time::timeout(Duration::from_secs(2), primary_request)
        .await
        .unwrap()
        .unwrap();
    let shadow_request = tokio::time::timeout(Duration::from_secs(2), shadow_request)
        .await
        .expect("resolved target service should be mirrored")
        .unwrap();
    let body = |request: Vec<u8>| {
        let offset = request
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        request[offset..].to_vec()
    };
    let primary_body = body(primary_request);
    let shadow_body = body(shadow_request);
    assert_eq!(shadow_body, primary_body);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&primary_body).unwrap()["model"],
        "internal-allowed-model"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_returns_only_granted_models_without_an_upstream() {
    let key = inference_key('a');
    let backend = SocketAddr::from(([127, 0, 0, 1], 9));
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["object"], "list");
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["id"], "allowed-model");
    assert_eq!(body["data"][0]["object"], "model");
    assert!(!body.to_string().contains("hidden-model"));

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn response_middleware_error_fails_closed_on_native_models_listener_without_policy_body() {
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

    let key = inference_key('n');
    let backend = SocketAddr::from(([127, 0, 0, 1], 9));
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("fail-response".to_string());
    let custom = std::collections::HashSet::from(["fail-response".to_string()]);
    config.validate_with_custom_middlewares(&custom).unwrap();

    let mut registry = MiddlewareRegistry::new();
    registry
        .register("fail-response", FailResponseMiddleware)
        .unwrap();
    let (address, shutdown_tx, handle) =
        start_test_entrypoint(gateway_state_with_registry(&config, &registry)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
    let body = response.text().await.unwrap();
    assert!(body.contains("Middleware error"), "unexpected body: {body}");
    assert!(
        !body.contains("allowed-model"),
        "native models list must not leak after response middleware failure: {body}"
    );
    assert!(
        !body.contains("\"object\":\"list\""),
        "native models envelope must not leak after response middleware failure: {body}"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_denies_ungranted_endpoints_and_models() {
    let key = inference_key('a');
    let backend = SocketAddr::from(([127, 0, 0, 1], 9));
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();

    let response = client
        .post(format!("http://{address}/v1/embeddings"))
        .bearer_auth(inference_key('b'))
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","input":"hello"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);

    let response = client
        .post(format!("http://{address}/v1/embeddings"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","input":"hello"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );

    let response = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"hidden-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn credential_successor_runtime_revokes_prior_key_without_upstream() {
    let key = inference_key('s');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let runtime = GatewayRuntime::new(gateway_state(&config));
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let admitted = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);

    let old_state = runtime.load();
    let previous = old_state
        .inference_authorizer
        .as_deref()
        .expect("inference authorizer");
    let mut revoked = config.clone();
    {
        let inference = revoked.inference.as_mut().unwrap();
        let credential = inference.credentials.values_mut().next().unwrap();
        credential.revoked = true;
        for route in inference.routes.values_mut() {
            route.grants.clear();
        }
    }
    revoked.validate().unwrap();
    runtime.replace(gateway_state_with_previous(&revoked, Some(previous)));
    drop(old_state);

    let denied = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    assert_eq!(
        denied.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_api_key"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err(),
        "revoked successor must never contact upstream"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn credential_generation_bump_invalidates_prior_authenticated_generation() {
    let key = inference_key('g');
    let rotated = inference_key('h');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let runtime = GatewayRuntime::new(gateway_state(&config));
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let admitted = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);

    let old_state = runtime.load();
    let previous = old_state
        .inference_authorizer
        .as_deref()
        .expect("inference authorizer");
    let mut bumped = config.clone();
    {
        let inference = bumped.inference.as_mut().unwrap();
        let credential_id = *inference.credentials.keys().next().unwrap();
        let credential = inference.credentials.get_mut(&credential_id).unwrap();
        // Identity rotation replaces verifier material and bumps generation
        // together; grants must track the new generation or validate fails.
        credential.verifier_hash = verifier(&rotated);
        credential.generation = credential.generation.saturating_add(1);
        for route in inference.routes.values_mut() {
            if let Some(grant) = route.grants.get_mut(&credential_id) {
                grant.credential_generation = credential.generation;
            }
        }
    }
    bumped.validate().unwrap();
    runtime.replace(gateway_state_with_previous(&bumped, Some(previous)));
    drop(old_state);

    let denied = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    assert_eq!(
        denied.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_api_key"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err(),
        "stale generation bearer must never contact upstream"
    );

    let admitted_rotated = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&rotated)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted_rotated.status(), 200);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn grant_successor_runtime_denies_prior_model_without_upstream() {
    let key = inference_key('r');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let runtime = GatewayRuntime::new(gateway_state(&config));
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let listed = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 200);
    let listed_body = listed.json::<serde_json::Value>().await.unwrap();
    assert_eq!(listed_body["data"][0]["id"], "allowed-model");

    let old_state = runtime.load();
    let previous = old_state
        .inference_authorizer
        .as_deref()
        .expect("inference authorizer");
    let mut successor = config.clone();
    {
        let inference = successor.inference.as_mut().unwrap();
        let credential = inference.credentials.values().next().unwrap().clone();
        assert!(!credential.revoked);
        for route in inference.routes.values_mut() {
            // Grant-only succession: credential stays authenticatable; surface
            // moves from allowed-model to hidden-model without revoke.
            let grant = route.grants.values_mut().next().unwrap();
            grant.models = vec!["hidden-model".into()];
        }
    }
    successor.validate().unwrap();
    runtime.replace(gateway_state_with_previous(&successor, Some(previous)));
    drop(old_state);

    let models = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(models.status(), 200);
    let models_body = models.json::<serde_json::Value>().await.unwrap();
    assert_eq!(models_body["data"].as_array().unwrap().len(), 1);
    assert_eq!(models_body["data"][0]["id"], "hidden-model");

    let denied = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);
    assert_eq!(
        denied.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err(),
        "grant successor must never contact upstream for the withdrawn model"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_snapshot_apply_grant_successor_denies_withdrawn_model_without_upstream() {
    use crate::managed_snapshot::{
        ManagedSnapshot, ManagedSnapshotReloadCallback, ManagedSnapshotStore,
    };

    let key = inference_key('s');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let snapshot_expires = Utc::now() + ChronoDuration::hours(1);
    let mut first = inference_config(backend, &key, snapshot_expires);
    first.inference.as_mut().unwrap().expires_at = snapshot_expires;
    let gateway_id = first.managed.gateway_id.expect("managed gateway id");

    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id), None));
    let runtime =
        GatewayRuntime::new(gateway_state(&first)).with_managed_snapshot_store(store.clone());
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let listed = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(listed.status(), 200);
    assert_eq!(
        listed.json::<serde_json::Value>().await.unwrap()["data"][0]["id"],
        "allowed-model"
    );

    let mut successor = first.clone();
    {
        let inference = successor.inference.as_mut().unwrap();
        for route in inference.routes.values_mut() {
            let grant = route.grants.values_mut().next().unwrap();
            grant.models = vec!["hidden-model".into()];
        }
    }
    successor.validate().unwrap();

    let previous_config = Arc::new(Mutex::new(first.clone()));
    let callback: ManagedSnapshotReloadCallback = {
        let runtime = runtime.clone();
        let previous_config = previous_config.clone();
        Arc::new(move |config| {
            let runtime = runtime.clone();
            let previous_config = previous_config.clone();
            Box::pin(async move {
                let old = previous_config.lock().unwrap().clone();
                let old_state = runtime.load();
                let previous = old_state.inference_authorizer.as_deref();
                let next_state = gateway_state_with_previous(&config, previous);
                drop(old_state);
                *previous_config.lock().unwrap() = config.clone();
                runtime.replace(next_state);
                Ok(old)
            })
        })
    };

    let issued_at = Utc::now();
    let first_snapshot = ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        issued_at,
        snapshot_expires,
        render_inference_snapshot_acl(&first),
    );
    assert!(
        store
            .apply(first_snapshot, Some(&callback))
            .await
            .status
            .ready
    );

    let successor_expires = Utc::now() + ChronoDuration::hours(1);
    successor.inference.as_mut().unwrap().expires_at = successor_expires;
    let successor_snapshot = ManagedSnapshot::new(
        gateway_id,
        2,
        Some(1),
        Utc::now(),
        successor_expires,
        render_inference_snapshot_acl(&successor),
    );
    assert!(
        store
            .apply(successor_snapshot, Some(&callback))
            .await
            .status
            .ready
    );

    let models = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(models.status(), 200);
    let models_body = models.json::<serde_json::Value>().await.unwrap();
    assert_eq!(models_body["data"].as_array().unwrap().len(), 1);
    assert_eq!(models_body["data"][0]["id"], "hidden-model");

    let denied = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);
    assert_eq!(
        denied.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "not_found"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err(),
        "managed snapshot grant successor must never contact upstream for the withdrawn model"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_snapshot_apply_credential_successor_revokes_prior_key_without_upstream() {
    use crate::managed_snapshot::{
        ManagedSnapshot, ManagedSnapshotReloadCallback, ManagedSnapshotStore,
    };

    let key = inference_key('v');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let snapshot_expires = Utc::now() + ChronoDuration::hours(1);
    let mut first = inference_config(backend, &key, snapshot_expires);
    first.inference.as_mut().unwrap().expires_at = snapshot_expires;
    let gateway_id = first.managed.gateway_id.expect("managed gateway id");

    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id), None));
    let runtime =
        GatewayRuntime::new(gateway_state(&first)).with_managed_snapshot_store(store.clone());
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let admitted = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);

    let mut revoked = first.clone();
    {
        let inference = revoked.inference.as_mut().unwrap();
        let credential = inference.credentials.values_mut().next().unwrap();
        credential.revoked = true;
        for route in inference.routes.values_mut() {
            route.grants.clear();
        }
    }
    revoked.validate().unwrap();

    let previous_config = Arc::new(Mutex::new(first.clone()));
    let callback: ManagedSnapshotReloadCallback = {
        let runtime = runtime.clone();
        let previous_config = previous_config.clone();
        Arc::new(move |config| {
            let runtime = runtime.clone();
            let previous_config = previous_config.clone();
            Box::pin(async move {
                let old = previous_config.lock().unwrap().clone();
                let old_state = runtime.load();
                let previous = old_state.inference_authorizer.as_deref();
                let next_state = gateway_state_with_previous(&config, previous);
                drop(old_state);
                *previous_config.lock().unwrap() = config.clone();
                runtime.replace(next_state);
                Ok(old)
            })
        })
    };

    let first_snapshot = ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        Utc::now(),
        snapshot_expires,
        render_inference_snapshot_acl(&first),
    );
    assert!(
        store
            .apply(first_snapshot, Some(&callback))
            .await
            .status
            .ready
    );

    let successor_expires = Utc::now() + ChronoDuration::hours(1);
    revoked.inference.as_mut().unwrap().expires_at = successor_expires;
    let successor_snapshot = ManagedSnapshot::new(
        gateway_id,
        2,
        Some(1),
        Utc::now(),
        successor_expires,
        render_inference_snapshot_acl(&revoked),
    );
    assert!(
        store
            .apply(successor_snapshot, Some(&callback))
            .await
            .status
            .ready
    );

    let denied_models = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(denied_models.status(), 401);
    assert_eq!(
        denied_models.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_api_key"
    );

    let denied_chat = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(denied_chat.status(), 401);
    assert_eq!(
        denied_chat.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_api_key"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err(),
        "managed snapshot credential successor must never contact upstream for the prior bearer"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_snapshot_apply_credential_generation_bump_invalidates_prior_bearer_without_upstream(
) {
    use crate::managed_snapshot::{
        ManagedSnapshot, ManagedSnapshotReloadCallback, ManagedSnapshotStore,
    };

    let key = inference_key('g');
    let rotated = inference_key('h');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let snapshot_expires = Utc::now() + ChronoDuration::hours(1);
    let mut first = inference_config(backend, &key, snapshot_expires);
    first.inference.as_mut().unwrap().expires_at = snapshot_expires;
    let gateway_id = first.managed.gateway_id.expect("managed gateway id");

    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id), None));
    let runtime =
        GatewayRuntime::new(gateway_state(&first)).with_managed_snapshot_store(store.clone());
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let admitted = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);

    let mut bumped = first.clone();
    {
        let inference = bumped.inference.as_mut().unwrap();
        let credential_id = *inference.credentials.keys().next().unwrap();
        let credential = inference.credentials.get_mut(&credential_id).unwrap();
        credential.verifier_hash = verifier(&rotated);
        credential.generation = credential.generation.saturating_add(1);
        for route in inference.routes.values_mut() {
            if let Some(grant) = route.grants.get_mut(&credential_id) {
                grant.credential_generation = credential.generation;
            }
        }
    }
    bumped.validate().unwrap();

    let previous_config = Arc::new(Mutex::new(first.clone()));
    let callback: ManagedSnapshotReloadCallback = {
        let runtime = runtime.clone();
        let previous_config = previous_config.clone();
        Arc::new(move |config| {
            let runtime = runtime.clone();
            let previous_config = previous_config.clone();
            Box::pin(async move {
                let old = previous_config.lock().unwrap().clone();
                let old_state = runtime.load();
                let previous = old_state.inference_authorizer.as_deref();
                let next_state = gateway_state_with_previous(&config, previous);
                drop(old_state);
                *previous_config.lock().unwrap() = config.clone();
                runtime.replace(next_state);
                Ok(old)
            })
        })
    };

    let first_snapshot = ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        Utc::now(),
        snapshot_expires,
        render_inference_snapshot_acl(&first),
    );
    assert!(
        store
            .apply(first_snapshot, Some(&callback))
            .await
            .status
            .ready
    );

    let successor_expires = Utc::now() + ChronoDuration::hours(1);
    bumped.inference.as_mut().unwrap().expires_at = successor_expires;
    let successor_snapshot = ManagedSnapshot::new(
        gateway_id,
        2,
        Some(1),
        Utc::now(),
        successor_expires,
        render_inference_snapshot_acl(&bumped),
    );
    assert!(
        store
            .apply(successor_snapshot, Some(&callback))
            .await
            .status
            .ready
    );

    let denied = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
    assert_eq!(
        denied.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "invalid_api_key"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err(),
        "managed snapshot generation bump must never contact upstream for the prior bearer"
    );

    let admitted_rotated = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&rotated)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted_rotated.status(), 200);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_snapshot_apply_unknown_tokenizer_successor_retains_prior_routing_on_listener() {
    // I0.2b item 5: unknown tokenizer_revision must fail closed on apply and
    // leave the live listener on the prior ready snapshot (no soft-open).
    use crate::managed_snapshot::{
        digest_acl, ManagedSnapshot, ManagedSnapshotIdentity, ManagedSnapshotReloadCallback,
        ManagedSnapshotStore,
    };

    let key = inference_key('k');
    let (backend, upstream_hits) = spawn_multi_ok_backend(2).await;
    let snapshot_expires = Utc::now() + ChronoDuration::hours(1);
    let mut first = inference_config(backend, &key, snapshot_expires);
    first.inference.as_mut().unwrap().expires_at = snapshot_expires;
    first.validate().unwrap();
    let gateway_id = first.managed.gateway_id.expect("managed gateway id");
    let first_acl = render_inference_snapshot_acl(&first);
    let first_identity = ManagedSnapshotIdentity {
        gateway_id,
        revision: 1,
        snapshot_digest: digest_acl(&first_acl),
    };

    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id), None));
    let runtime =
        GatewayRuntime::new(gateway_state(&first)).with_managed_snapshot_store(store.clone());
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let previous_config = Arc::new(Mutex::new(first.clone()));
    let reload_calls = Arc::new(AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let runtime = runtime.clone();
        let previous_config = previous_config.clone();
        let reload_calls = reload_calls.clone();
        Arc::new(move |config| {
            let runtime = runtime.clone();
            let previous_config = previous_config.clone();
            let reload_calls = reload_calls.clone();
            Box::pin(async move {
                reload_calls.fetch_add(1, Ordering::SeqCst);
                let old = previous_config.lock().unwrap().clone();
                let old_state = runtime.load();
                let previous = old_state.inference_authorizer.as_deref();
                let next_state = gateway_state_with_previous(&config, previous);
                drop(old_state);
                *previous_config.lock().unwrap() = config.clone();
                runtime.replace(next_state);
                Ok(old)
            })
        })
    };

    let applied = store
        .apply(
            ManagedSnapshot::new(gateway_id, 1, None, Utc::now(), snapshot_expires, first_acl),
            Some(&callback),
        )
        .await;
    assert_eq!(applied.status_code, 200);
    assert!(applied.status.ready);
    assert_eq!(reload_calls.load(Ordering::SeqCst), 1);

    let admitted = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let mut bad_tokenizer = first.clone();
    bad_tokenizer.inference.as_mut().unwrap().tokenizer_revision =
        "a3s.gateway.tokenizer.v0".into();
    let bad_expires = Utc::now() + ChronoDuration::hours(1);
    bad_tokenizer.inference.as_mut().unwrap().expires_at = bad_expires;
    let rejected = store
        .apply(
            ManagedSnapshot::new(
                gateway_id,
                2,
                Some(1),
                Utc::now(),
                bad_expires,
                render_inference_snapshot_acl(&bad_tokenizer),
            ),
            Some(&callback),
        )
        .await;
    assert_eq!(rejected.status_code, 422);
    assert!(
        rejected
            .status
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("tokenizer_revision"),
        "unknown tokenizer must fail closed: {:?}",
        rejected.status.reason
    );
    assert_eq!(reload_calls.load(Ordering::SeqCst), 1);
    assert!(store.status(Some(first_identity), Utc::now()).ready);

    let retained = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(retained.status(), 200);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "rejected unknown-tokenizer successor must retain prior routing to the same upstream"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_snapshot_apply_stale_cas_successor_retains_prior_routing_on_listener() {
    // I0.2b item 5: expected_revision CAS mismatch must 409 without reload,
    // even when the stale ACL would revoke the live credential.
    use crate::managed_snapshot::{
        digest_acl, ManagedSnapshot, ManagedSnapshotIdentity, ManagedSnapshotReloadCallback,
        ManagedSnapshotStore,
    };

    let key = inference_key('c');
    let (backend, upstream_hits) = spawn_multi_ok_backend(2).await;
    let snapshot_expires = Utc::now() + ChronoDuration::hours(1);
    let mut first = inference_config(backend, &key, snapshot_expires);
    first.inference.as_mut().unwrap().expires_at = snapshot_expires;
    first.validate().unwrap();
    let gateway_id = first.managed.gateway_id.expect("managed gateway id");
    let first_acl = render_inference_snapshot_acl(&first);
    let first_identity = ManagedSnapshotIdentity {
        gateway_id,
        revision: 1,
        snapshot_digest: digest_acl(&first_acl),
    };

    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id), None));
    let runtime =
        GatewayRuntime::new(gateway_state(&first)).with_managed_snapshot_store(store.clone());
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;

    let previous_config = Arc::new(Mutex::new(first.clone()));
    let reload_calls = Arc::new(AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let runtime = runtime.clone();
        let previous_config = previous_config.clone();
        let reload_calls = reload_calls.clone();
        Arc::new(move |config| {
            let runtime = runtime.clone();
            let previous_config = previous_config.clone();
            let reload_calls = reload_calls.clone();
            Box::pin(async move {
                reload_calls.fetch_add(1, Ordering::SeqCst);
                let old = previous_config.lock().unwrap().clone();
                let old_state = runtime.load();
                let previous = old_state.inference_authorizer.as_deref();
                let next_state = gateway_state_with_previous(&config, previous);
                drop(old_state);
                *previous_config.lock().unwrap() = config.clone();
                runtime.replace(next_state);
                Ok(old)
            })
        })
    };

    let applied = store
        .apply(
            ManagedSnapshot::new(gateway_id, 1, None, Utc::now(), snapshot_expires, first_acl),
            Some(&callback),
        )
        .await;
    assert_eq!(applied.status_code, 200);
    assert!(applied.status.ready);
    assert_eq!(reload_calls.load(Ordering::SeqCst), 1);

    let admitted = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    let mut revoked = first.clone();
    {
        let inference = revoked.inference.as_mut().unwrap();
        let credential = inference.credentials.values_mut().next().unwrap();
        credential.revoked = true;
        for route in inference.routes.values_mut() {
            route.grants.clear();
        }
    }
    let stale_expires = Utc::now() + ChronoDuration::hours(1);
    revoked.inference.as_mut().unwrap().expires_at = stale_expires;
    let rejected = store
        .apply(
            ManagedSnapshot::new(
                gateway_id,
                3,
                Some(2),
                Utc::now(),
                stale_expires,
                render_inference_snapshot_acl(&revoked),
            ),
            Some(&callback),
        )
        .await;
    assert_eq!(rejected.status_code, 409);
    assert!(
        rejected
            .status
            .reason
            .as_deref()
            .unwrap_or_default()
            .contains("expected revision"),
        "stale CAS must fail closed: {:?}",
        rejected.status.reason
    );
    assert_eq!(reload_calls.load(Ordering::SeqCst), 1);
    assert!(store.status(Some(first_identity), Utc::now()).ready);

    let retained = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(retained.status(), 200);
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        2,
        "rejected stale-CAS successor must retain prior routing despite revoke-bearing ACL"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

pub(super) async fn spawn_multi_ok_backend(expected: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_bg = hits.clone();

    tokio::spawn(async move {
        for _ in 0..expected {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = read_http_request(&mut stream).await;
            hits_bg.fetch_add(1, Ordering::SeqCst);
            let response =
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    });

    (address, hits)
}

pub(super) fn render_inference_snapshot_acl(config: &GatewayConfig) -> String {
    let gateway_id = config.managed.gateway_id.expect("managed gateway id");
    let inference = config.inference.as_ref().expect("inference policy");
    let credential = inference.credentials.values().next().expect("credential");
    let route = inference.routes.values().next().expect("route");
    let mut service_names = route
        .models
        .values()
        .flat_map(|model| model.targets.iter().map(|target| target.service.clone()))
        .collect::<Vec<_>>();
    service_names.sort();
    service_names.dedup();
    let services = service_names
        .iter()
        .map(|name| {
            let service = config
                .services
                .get(name)
                .unwrap_or_else(|| panic!("service {name}"));
            let servers = service
                .load_balancer
                .servers
                .iter()
                .map(|server| {
                    let url = server.url.trim_start_matches("http://");
                    match &server.target {
                        Some(target) => format!(
                            r#"
    servers {{
      url = "http://{url}"
      target {{
        target_id = "{target_id}"
        unit_id = "{unit_id}"
        generation = {generation}
      }}
    }}
"#,
                            target_id = target.target_id,
                            unit_id = target.unit_id,
                            generation = target.generation,
                        ),
                        None => format!(
                            r#"
    servers = [{{ url = "http://{url}" }}]
"#
                        ),
                    }
                })
                .collect::<String>();
            format!(
                r#"
services "{name}" {{
  load_balancer {{
{servers}
  }}
}}
"#
            )
        })
        .collect::<String>();
    let workers = inference
        .workers
        .iter()
        .map(|(unit_id, worker)| {
            let phases = worker
                .phases
                .iter()
                .map(|phase| format!("\"{}\"", phase.as_str()))
                .collect::<Vec<_>>()
                .join(", ");
            let ready_phases = worker
                .ready_phases
                .iter()
                .map(|phase| format!("\"{}\"", phase.as_str()))
                .collect::<Vec<_>>()
                .join(", ");
            let active_limit = worker
                .active_limit
                .map(|limit| format!("    active_limit = {limit}\n"))
                .unwrap_or_default();
            let certified = worker
                .certified_latency_ms
                .map(|latency| format!("    certified_latency_ms = {latency}\n"))
                .unwrap_or_default();
            let profile = worker
                .execution_profile_sha256
                .as_ref()
                .map(|digest| format!("    execution_profile_sha256 = \"{digest}\"\n"))
                .unwrap_or_default();
            format!(
                r#"
  workers "{unit_id}" {{
    target_id = "{target_id}"
    generation = {generation}
    schema = "{schema}"
    worker_epoch = "{worker_epoch}"
{profile}    observation_generation = {observation_generation}
    observed_at = "{observed_at}"
    expires_at = "{expires_at}"
    phases = [{phases}]
    prompt_cache_capable = {prompt_cache_capable}
    state_transfer_capable = {state_transfer_capable}
    ready_phases = [{ready_phases}]
{active_limit}    active = {active}
    waiting = {waiting}
    prompt_cache_supported = {prompt_cache_supported}
    prompt_cache_entries = {prompt_cache_entries}
    prompt_cache_capacity = {prompt_cache_capacity}
    prompt_cache_pressure_basis_points = {pressure}
    transfer_health = "{transfer_health}"
{certified}  }}
"#,
                target_id = worker.target.target_id,
                generation = worker.target.generation,
                schema = worker.schema,
                worker_epoch = worker.worker_epoch,
                observation_generation = worker.observation_generation,
                observed_at = worker.observed_at.to_rfc3339(),
                expires_at = worker.expires_at.to_rfc3339(),
                prompt_cache_capable = worker.prompt_cache_capable,
                state_transfer_capable = worker.state_transfer_capable,
                active = worker.active,
                waiting = worker.waiting,
                prompt_cache_supported = worker.prompt_cache_supported,
                prompt_cache_entries = worker.prompt_cache_entries,
                prompt_cache_capacity = worker.prompt_cache_capacity,
                pressure = worker.prompt_cache_pressure_basis_points,
                transfer_health = worker.transfer_health.as_str(),
            )
        })
        .collect::<String>();
    let models = route
        .models
        .iter()
        .map(|(alias, model)| {
            let targets = model
                .targets
                .iter()
                .map(|target| {
                    format!(
                        r#"
      targets "{target_id}" {{
        service = "{service}"
        upstream_model = "{upstream}"
        priority = {priority}
        weight = {weight}
      }}
"#,
                        target_id = target.target_id,
                        service = target.service,
                        upstream = target.upstream_model,
                        priority = target.priority,
                        weight = target.weight,
                    )
                })
                .collect::<String>();
            let scheduling = model
                .scheduling
                .as_ref()
                .map(|scheduling| {
                    format!(
                        r#"
      scheduling {{
        phase = "{phase}"
        max_concurrent_requests = {max_concurrent}
        max_queued_requests = {max_queued}
        queue_timeout_ms = {queue_timeout}
        prompt_cache_affinity = {affinity}
      }}
"#,
                        phase = scheduling.phase.as_str(),
                        max_concurrent = scheduling.max_concurrent_requests,
                        max_queued = scheduling.max_queued_requests,
                        queue_timeout = scheduling.queue_timeout_ms,
                        affinity = scheduling.prompt_cache_affinity,
                    )
                })
                .unwrap_or_default();
            format!(
                r#"
    models "{alias}" {{
      model_id = "{model_id}"
      {targets}
      {scheduling}
    }}
"#,
                model_id = model.model_id,
            )
        })
        .collect::<String>();
    let grants = route
        .grants
        .get(&credential.credential_id)
        .map(|grant| {
            let granted = grant
                .models
                .iter()
                .map(|model| format!("\"{model}\""))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                r#"
    grants "{credential_id}" {{
      credential_generation = {generation}
      models = [{granted}]
      endpoints = ["models", "chat-completions"]
      limits {{
        max_concurrent_requests = 2
        requests_per_minute = 60
        request_burst = 2
        tokens_per_minute = 10000
      }}
    }}
"#,
                credential_id = credential.credential_id,
                generation = grant.credential_generation,
            )
        })
        .unwrap_or_default();
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
entrypoints "web" {{ address = "127.0.0.1:8080" }}
routers "test-router" {{
  rule = "PathPrefix(`/`)"
  service = "default-service"
  entrypoints = ["web"]
}}
services "default-service" {{
  load_balancer {{
    servers = [{{ url = "http://127.0.0.1:9" }}]
  }}
}}
{services}
inference {{
  tokenizer_revision = "{tokenizer}"
  expires_at = "{expires}"
  {workers}
  credentials "{credential_id}" {{
    environment_id = "{environment_id}"
    audience = "cloud-inference"
    prefix = "{prefix}"
    verifier_hash = "{verifier}"
    generation = {generation}
    expires_at = "{credential_expires}"
    revoked = {revoked}
  }}
  routes "{route_id}" {{
    router = "test-router"
    environment_id = "{environment_id}"
    policy_revision = {policy_revision}
    {models}
    {grants}
  }}
}}
"#,
        tokenizer = inference.tokenizer_revision,
        expires = inference.expires_at.to_rfc3339(),
        credential_id = credential.credential_id,
        environment_id = credential.environment_id,
        prefix = credential.prefix,
        verifier = credential.verifier_hash,
        generation = credential.generation,
        credential_expires = credential.expires_at.to_rfc3339(),
        revoked = credential.revoked,
        route_id = route.route_id,
        policy_revision = route.policy_revision,
    )
}

#[tokio::test]
async fn managed_inference_policy_expiry_fails_closed_at_request_time() {
    let key = inference_key('a');
    let backend = SocketAddr::from(([127, 0, 0, 1], 9));
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::milliseconds(50));
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    tokio::time::sleep(Duration::from_millis(75)).await;

    let response = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(
        response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "authorization_unavailable"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_revoked_or_expired_credentials_fail_closed_without_upstream() {
    let key = inference_key('r');
    let (backend, captured_request) = spawn_capturing_backend().await;

    for revoke in [true, false] {
        let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
        let credential = config
            .inference
            .as_mut()
            .unwrap()
            .credentials
            .values_mut()
            .next()
            .unwrap();
        if revoke {
            credential.revoked = true;
        } else {
            credential.expires_at = Utc::now() - ChronoDuration::seconds(1);
        }
        let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
        let response = reqwest::Client::new()
            .get(format!("http://{address}/v1/models"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 401, "revoke={revoke}");
        assert_eq!(
            response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
            "invalid_api_key"
        );
        stop_test_entrypoint(shutdown_tx, handle).await;
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err(),
        "revoked/expired credentials must never contact upstream"
    );
}

#[tokio::test]
async fn managed_inference_rechecks_policy_expiry_after_body_collection() {
    let key = inference_key('a');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let policy_expires_at = Utc::now() + ChronoDuration::seconds(5);
    let config = inference_config(backend, &key, policy_expires_at);
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;

    let warm_response = reqwest::Client::new()
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(warm_response.status(), 200);

    let body = r#"{"model":"allowed-model","messages":[]}"#;
    let mut stream = TcpStream::connect(address).await.unwrap();
    let headers = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();

    let until_expiry = (policy_expires_at - Utc::now())
        .to_std()
        .unwrap_or_default();
    tokio::time::sleep(until_expiry + Duration::from_millis(100)).await;
    stream.write_all(body.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8(response).unwrap();
    assert!(response.starts_with("HTTP/1.1 503"), "{response}");
    assert!(response.contains("authorization_unavailable"));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err()
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_router_rejects_near_miss_paths() {
    let key = inference_key('a');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;

    let response = reqwest::Client::new()
        .post(format!("http://{address}/v1/chat/completions/"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), captured_request)
            .await
            .is_err()
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_models_enforces_request_burst_with_retry_after() {
    let key = inference_key('a');
    let backend = SocketAddr::from(([127, 0, 0, 1], 9));
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 2,
            requests_per_minute: 60,
            request_burst: 1,
            tokens_per_minute: 10_000,
        },
    );
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();

    let first = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    let limited = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(limited.headers()["retry-after"], "1");
    assert_eq!(
        limited.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "rate_limit_exceeded"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_inference_enforces_tokens_per_minute_reservation() {
    let key = inference_key('t');
    let (backend, captured_request) = spawn_capturing_backend().await;
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

    let admitted = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[{"role":"user","content":"hi"}],"max_tokens":30}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);
    tokio::time::timeout(Duration::from_secs(2), captured_request)
        .await
        .unwrap()
        .unwrap();

    let limited = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[{"role":"user","content":"hi"}],"max_tokens":30}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(limited.status(), 429);
    assert_eq!(
        limited.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "rate_limit_exceeded"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn rejected_inference_requests_do_not_consume_request_allowance() {
    let key = inference_key('a');
    let (backend, captured_request) = spawn_capturing_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 2,
            requests_per_minute: 60,
            request_burst: 1,
            tokens_per_minute: 10_000,
        },
    );
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();

    let invalid_key = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(inference_key('b'))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid_key.status(), 401);

    let endpoint_denied = client
        .post(format!("http://{address}/v1/embeddings"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","input":"hello"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(endpoint_denied.status(), 404);

    let model_denied = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"hidden-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(model_denied.status(), 404);

    let malformed = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body("not-json")
        .send()
        .await
        .unwrap();
    assert_eq!(malformed.status(), 400);

    let admitted = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);
    tokio::time::timeout(Duration::from_secs(2), captured_request)
        .await
        .unwrap()
        .unwrap();

    let exhausted = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(exhausted.status(), 429);
    assert_eq!(
        exhausted.json::<serde_json::Value>().await.unwrap()["error"]["code"],
        "rate_limit_exceeded"
    );

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn snapshot_refresh_preserves_active_inference_concurrency() {
    let key = inference_key('a');
    let (backend, request_started, release_request) = spawn_blocking_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 60,
            request_burst: 3,
            tokens_per_minute: 10_000,
        },
    );
    config
        .services
        .get_mut("model-service")
        .unwrap()
        .load_balancer
        .request_timeout = "5s".into();
    config.validate().unwrap();

    let initial_state = gateway_state(&config);
    let runtime = GatewayRuntime::new(initial_state);
    let (address, shutdown_tx, handle) = start_test_runtime(runtime.clone()).await;
    let client = reqwest::Client::new();
    let request_client = client.clone();
    let request_key = key.clone();
    let first_request = tokio::spawn(async move {
        request_client
            .post(format!("http://{address}/v1/chat/completions"))
            .bearer_auth(request_key)
            .header("content-type", "application/json")
            .body(r#"{"model":"allowed-model","messages":[]}"#)
            .send()
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), request_started)
        .await
        .unwrap()
        .unwrap();

    let old_state = runtime.load();
    let previous = old_state
        .inference_authorizer
        .as_deref()
        .expect("inference authorizer");
    let mut refreshed_config = config.clone();
    refreshed_config.inference.as_mut().unwrap().expires_at += ChronoDuration::minutes(5);
    runtime.replace(gateway_state_with_previous(
        &refreshed_config,
        Some(previous),
    ));
    drop(old_state);

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

    release_request.send(()).unwrap();
    assert_eq!(first_request.await.unwrap().status(), 200);

    let admitted = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn openai_stream_field_selects_sse_without_an_accept_header() {
    let key = inference_key('a');
    let (backend, stream_started, upstream_disconnected) = spawn_streaming_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 600,
            request_burst: 10,
            tokens_per_minute: 10_000,
        },
    );
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();

    let stream_response = client
        .post(format!("http://{address}/v1/chat/completions"))
        .bearer_auth(&key)
        .header("content-type", "application/json")
        .body(r#"{"model":"allowed-model","messages":[],"stream":true}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(stream_response.status(), 200);
    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .unwrap()
        .unwrap();

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

    drop(stream_response);
    tokio::time::timeout(Duration::from_secs(2), upstream_disconnected)
        .await
        .unwrap()
        .unwrap();

    let admitted = client
        .get(format!("http://{address}/v1/models"))
        .bearer_auth(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), 200);

    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn client_abort_before_upstream_response_releases_concurrency_permit() {
    let key = inference_key('c');
    let (backend, request_started, release_request) = spawn_blocking_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 600,
            request_burst: 10,
            tokens_per_minute: 10_000,
        },
    );
    config
        .services
        .get_mut("model-service")
        .unwrap()
        .load_balancer
        .request_timeout = "5s".into();
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
    let client = reqwest::Client::new();

    let body = r#"{"model":"allowed-model","messages":[]}"#;
    let raw = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {key}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut inbound = TcpStream::connect(address).await.unwrap();
    inbound.write_all(raw.as_bytes()).await.unwrap();
    inbound.flush().await.unwrap();

    tokio::time::timeout(Duration::from_secs(2), request_started)
        .await
        .expect("upstream should see the request before client abort")
        .unwrap();

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

    // Abort before upstream responds: close the client TCP stream.
    drop(inbound);

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
            assert_eq!(
                response.status(),
                429,
                "only concurrency exhaustion is expected while draining"
            );
            assert_eq!(
                response.json::<serde_json::Value>().await.unwrap()["error"]["code"],
                "concurrency_limit_exceeded"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("concurrency permit must release after client abort before upstream response");
    assert_eq!(admitted.status(), 200);

    drop(release_request);
    stop_test_entrypoint(shutdown_tx, handle).await;
}

#[tokio::test]
async fn managed_sse_client_drop_after_headers_releases_concurrency_permit() {
    use futures_util::StreamExt;

    let key = inference_key('s');
    let (backend, stream_started, upstream_disconnected) = spawn_streaming_backend().await;
    let mut config = inference_config(backend, &key, Utc::now() + ChronoDuration::hours(1));
    set_limits(
        &mut config,
        InferenceLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 600,
            request_burst: 10,
            tokens_per_minute: 10_000,
        },
    );
    config.validate().unwrap();
    let (address, shutdown_tx, handle) = start_test_entrypoint(gateway_state(&config)).await;
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
    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .expect("upstream SSE should start before client drop")
        .unwrap();

    let mut body = response.bytes_stream();
    let first = body.next().await.unwrap().unwrap();
    assert!(
        first
            .windows(b"data:".len())
            .any(|window| window == b"data:"),
        "client must observe the first SSE chunk before drop"
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

    drop(body);

    tokio::time::timeout(Duration::from_secs(2), upstream_disconnected)
        .await
        .expect("upstream must see client cancel after SSE body drop")
        .unwrap();

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
    .expect("concurrency permit must release after aggregated SSE client drop");
    assert_eq!(admitted.status(), 200);

    stop_test_entrypoint(shutdown_tx, handle).await;
}
