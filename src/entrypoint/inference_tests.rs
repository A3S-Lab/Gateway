use super::*;
use crate::config::{
    GatewayConfig, InferenceConfig, InferenceCredentialConfig, InferenceEndpoint,
    InferenceGrantConfig, InferenceLimitsConfig, InferenceModelConfig, InferenceRouteConfig,
    InferenceTargetConfig, LoadBalancerConfig, OperatingMode, RouterConfig, ServerConfig,
    ServiceConfig, Strategy,
};
use crate::gateway::builders::{
    build_passive_health, build_pipeline_cache, build_scaling_state, build_sticky_managers,
};
use crate::observability::access_log::{AccessLog, AccessLogEntry};
use crate::observability::metrics::GatewayMetrics;
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::Argon2;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

const KEY_PREFIX: &str = "a3s_inf_abc12345";

fn inference_key(character: char) -> String {
    format!("{KEY_PREFIX}{}", character.to_string().repeat(64))
}

fn verifier(secret: &str) -> String {
    let salt = SaltString::encode_b64(b"a3s-entrypoint-test").unwrap();
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .unwrap()
        .to_string()
}

fn inference_config(
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
                servers: vec![ServerConfig {
                    url: "http://127.0.0.1:9".into(),
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
    config.services.insert(
        "model-service".into(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".into(),
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
                },
            )
        })
        .collect();
    config.inference = Some(InferenceConfig {
        expires_at: policy_expires_at,
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
    });
    config
}

fn gateway_state(config: &GatewayConfig) -> Arc<GatewayState> {
    let service_registry =
        Arc::new(ServiceRegistry::from_config(&config.services).expect("service registry"));
    let middleware_configs = Arc::new(config.middlewares.clone());
    let pipeline_cache = Arc::new(build_pipeline_cache(config, &middleware_configs));
    let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel::<AccessLogEntry>();

    Arc::new(GatewayState {
        router_table: Arc::new(RouterTable::from_config(&config.routers).expect("router table")),
        service_registry,
        inference_authorizer: config
            .inference
            .as_ref()
            .map(InferenceAuthorizer::new)
            .map(Arc::new),
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
        access_log_enabled: false,
        tracing_enabled: false,
    })
}

async fn start_test_entrypoint(
    state: Arc<GatewayState>,
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

async fn spawn_capturing_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();

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

        let _ = request_tx.send(request);
        let response =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}";
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (address, request_rx)
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
