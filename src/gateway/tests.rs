use super::*;

fn minimal_config() -> GatewayConfig {
    let mut config = GatewayConfig::default();
    config.routers.clear();
    config.services.clear();
    config.middlewares.clear();
    config
}

/// Minimal Docker API stand-in for `/_ping` + `/containers/json`.
async fn spawn_mock_docker_daemon() -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 8192];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let (status, body) = if request.contains("/_ping") {
                    ("200 OK", "OK")
                } else if request.contains("/containers/json") {
                    ("200 OK", "[]")
                } else {
                    ("404 Not Found", "")
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    let host = format!("tcp://127.0.0.1:{}", address.port());
    // Prove the listen socket accepts before Gateway::new probes from another thread.
    crate::provider::docker::DockerProvider::new(crate::config::DockerProviderConfig {
        host: host.clone(),
        poll_interval_secs: 60,
        ..crate::config::DockerProviderConfig::default()
    })
    .probe_activation()
    .await
    .expect("mock Docker daemon must accept /_ping before tests use it");
    (host, handle)
}

fn custom_middleware_config() -> GatewayConfig {
    use crate::config::{LoadBalancerConfig, RouterConfig, ServerConfig, ServiceConfig, Strategy};

    let mut config = minimal_config();
    config.entrypoints.clear();
    config.services.insert(
        "api".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: "http://127.0.0.1:8080".to_string(),
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
    config.routers.insert(
        "api".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/`)".to_string(),
            service: "api".to_string(),
            entrypoints: vec![],
            middlewares: vec!["tenant-policy".to_string()],
            priority: 0,
        },
    );
    config
}

struct TenantPolicy;

#[async_trait::async_trait]
impl crate::middleware::Middleware for TenantPolicy {
    async fn handle_request(
        &self,
        request: &mut http::request::Parts,
        _context: &crate::middleware::RequestContext,
    ) -> crate::Result<Option<http::Response<Vec<u8>>>> {
        request
            .headers
            .insert("x-tenant-policy", http::HeaderValue::from_static("applied"));
        Ok(None)
    }

    fn name(&self) -> &str {
        "tenant-policy"
    }
}

#[test]
fn test_gateway_new() {
    let gw = Gateway::new(minimal_config()).unwrap();
    assert_eq!(gw.state(), GatewayState::Created);
    assert!(!gw.is_running());
    assert!(!gw.is_shutdown());
}

#[test]
fn test_gateway_new_invalid_config() {
    use crate::config::RouterConfig;
    let mut config = minimal_config();
    config.routers.insert(
        "bad".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/api`)".to_string(),
            service: "nonexistent".to_string(),
            entrypoints: vec![],
            middlewares: vec![],
            priority: 0,
        },
    );
    let result = Gateway::new(config);
    assert!(result.is_err());
}

#[test]
fn custom_middleware_must_be_registered_and_cannot_shadow_acl() {
    use crate::config::MiddlewareConfig;
    use crate::middleware::MiddlewareRegistry;

    let config = custom_middleware_config();
    let error = match Gateway::new(config.clone()) {
        Ok(_) => panic!("an unregistered custom middleware reference must fail validation"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("unknown middleware 'tenant-policy'"));

    let mut registry = MiddlewareRegistry::new();
    registry.register("tenant-policy", TenantPolicy).unwrap();
    assert!(Gateway::with_middlewares(config, registry).is_ok());

    let mut conflicting = custom_middleware_config();
    conflicting.middlewares.insert(
        "tenant-policy".to_string(),
        MiddlewareConfig {
            middleware_type: "cors".to_string(),
            allowed_origins: vec!["*".to_string()],
            ..Default::default()
        },
    );
    let mut registry = MiddlewareRegistry::new();
    registry.register("tenant-policy", TenantPolicy).unwrap();
    let error = match Gateway::with_middlewares(conflicting, registry) {
        Ok(_) => panic!("custom middleware must not shadow an ACL definition"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("conflicts with an ACL middleware"));
}

#[test]
fn with_middlewares_fails_closed_on_dual_retry_with_custom_policy() {
    use crate::config::MiddlewareConfig;
    use crate::middleware::MiddlewareRegistry;
    use crate::middleware::RetryPolicy;

    struct CustomRetry;

    #[async_trait::async_trait]
    impl crate::middleware::Middleware for CustomRetry {
        async fn handle_request(
            &self,
            _request: &mut http::request::Parts,
            _context: &crate::middleware::RequestContext,
        ) -> crate::Result<Option<http::Response<Vec<u8>>>> {
            Ok(None)
        }

        fn retry_policy(&self) -> Option<RetryPolicy> {
            Some(RetryPolicy::default())
        }

        fn name(&self) -> &str {
            "custom-retry"
        }
    }

    let mut config = custom_middleware_config();
    config.middlewares.insert(
        "acl-retry".to_string(),
        MiddlewareConfig {
            middleware_type: "retry".to_string(),
            max_retries: Some(2),
            ..Default::default()
        },
    );
    config.routers.get_mut("api").unwrap().middlewares =
        vec!["acl-retry".to_string(), "custom-retry".to_string()];

    let mut registry = MiddlewareRegistry::new();
    registry.register("custom-retry", CustomRetry).unwrap();

    // Structural ACL validate only counts ACL retry types — custom retry_policy
    // surfaces only when pipelines compile. Construct must fail closed here.
    let error = match Gateway::with_middlewares(config, registry) {
        Ok(_) => panic!(
            "ACL retry + custom retry_policy on one router must fail Gateway::with_middlewares"
        ),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("at most one retry policy") || message.contains("middleware pipeline"),
        "dual retry must fail pipeline activate at construct: {message}"
    );
}

#[tokio::test]
async fn custom_middleware_registry_survives_configuration_reload() {
    use crate::middleware::MiddlewareRegistry;

    let config = custom_middleware_config();
    let mut registry = MiddlewareRegistry::new();
    registry.register("tenant-policy", TenantPolicy).unwrap();
    let gateway = Gateway::with_middlewares(config.clone(), registry).unwrap();

    gateway.start().await.unwrap();
    gateway
        .reload_handle()
        .reload(config, "test-custom-middleware")
        .await
        .unwrap();

    assert!(gateway.is_running());
    assert_eq!(
        gateway.config().routers["api"].middlewares,
        vec!["tenant-policy"]
    );
    gateway.shutdown().await;
}

#[test]
fn test_gateway_health() {
    let gw = Gateway::new(minimal_config()).unwrap();
    let health = gw.health();
    assert_eq!(health.state, GatewayState::Created);
    assert_eq!(health.total_requests, 0);
}

#[test]
fn test_gateway_config() {
    let config = minimal_config();
    let gw = Gateway::new(config.clone()).unwrap();
    let retrieved = gw.config();
    assert_eq!(retrieved.entrypoints.len(), config.entrypoints.len());
}

#[test]
fn test_entrypoints_support_hot_swap_for_unchanged_http_entrypoints() {
    use crate::config::{EntrypointConfig, Protocol};

    let mut old_config = minimal_config();
    old_config.entrypoints.insert(
        "web".to_string(),
        EntrypointConfig {
            address: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
            trust_forwarded_headers: false,
        },
    );
    let new_config = old_config.clone();

    assert!(entrypoints_support_hot_swap(&old_config, &new_config));
}

#[test]
fn test_entrypoints_do_not_hot_swap_udp_entrypoints() {
    use crate::config::{EntrypointConfig, Protocol};

    let mut old_config = minimal_config();
    old_config.entrypoints.insert(
        "dns".to_string(),
        EntrypointConfig {
            address: "127.0.0.1:5353".to_string(),
            protocol: Protocol::Udp,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
            trust_forwarded_headers: false,
        },
    );
    let new_config = old_config.clone();

    assert!(!entrypoints_support_hot_swap(&old_config, &new_config));
}

#[test]
fn test_gateway_metrics() {
    let gw = Gateway::new(minimal_config()).unwrap();
    let metrics = gw.metrics();
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.total_requests, 0);
}

#[test]
fn test_state_transitions() {
    let gw = Gateway::new(minimal_config()).unwrap();
    assert_eq!(gw.state(), GatewayState::Created);

    gw.set_state(GatewayState::Starting);
    assert_eq!(gw.state(), GatewayState::Starting);

    gw.set_state(GatewayState::Running);
    assert!(gw.is_running());

    gw.set_state(GatewayState::Stopping);
    assert!(!gw.is_running());

    gw.set_state(GatewayState::Stopped);
    assert_eq!(gw.state(), GatewayState::Stopped);
}

#[tokio::test]
async fn test_gateway_shutdown() {
    let gw = Gateway::new(minimal_config()).unwrap();
    assert!(!gw.is_shutdown());
    gw.shutdown().await;
    assert!(gw.is_shutdown());
    assert_eq!(gw.state(), GatewayState::Stopped);
}

#[tokio::test]
async fn test_gateway_double_shutdown() {
    let gw = Gateway::new(minimal_config()).unwrap();
    gw.shutdown().await;
    gw.shutdown().await;
    assert_eq!(gw.state(), GatewayState::Stopped);
}

#[tokio::test]
async fn test_gateway_rejects_reload_before_start() {
    let gw = Gateway::new(minimal_config()).unwrap();
    let error = gw.reload(minimal_config()).await.unwrap_err();

    assert!(error.to_string().contains("cannot reload"));
    assert_eq!(gw.state(), GatewayState::Created);
}

#[tokio::test]
async fn test_gateway_rejects_repeated_start() {
    let mut config = minimal_config();
    config.entrypoints.clear();
    let gw = Gateway::new(config).unwrap();
    gw.start().await.unwrap();

    let error = gw.start().await.unwrap_err();
    assert!(error.to_string().contains("cannot start"));
    assert_eq!(gw.state(), GatewayState::Running);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_gateway_rejects_start_after_shutdown() {
    let gw = Gateway::new(minimal_config()).unwrap();
    gw.shutdown().await;

    let error = gw.start().await.unwrap_err();
    assert!(error.to_string().contains("cannot start"));
    assert_eq!(gw.state(), GatewayState::Stopped);
}

#[test]
fn test_gateway_discovery_handle_initially_none() {
    let gw = Gateway::new(minimal_config()).unwrap();
    let handle = gw.discovery_handle.read().unwrap();
    assert!(handle.is_none());
    assert!(gw.provider_handles.read().unwrap().is_empty());
}

#[tokio::test]
async fn test_gateway_shutdown_with_no_discovery() {
    let gw = Gateway::new(minimal_config()).unwrap();
    gw.shutdown().await;
    assert_eq!(gw.state(), GatewayState::Stopped);
    let handle = gw.discovery_handle.read().unwrap();
    assert!(handle.is_none());
    assert!(gw.provider_handles.read().unwrap().is_empty());
}

#[test]
fn test_gateway_config_with_discovery() {
    use crate::config::{DiscoveryConfig, DiscoverySeedConfig};
    let mut config = minimal_config();
    config.providers.discovery = Some(DiscoveryConfig {
        seeds: vec![DiscoverySeedConfig {
            url: "http://10.0.0.1:8080".to_string(),
        }],
        poll_interval_secs: 30,
        timeout_secs: 5,
    });
    let gw = Gateway::new(config).unwrap();
    let retrieved = gw.config();
    assert!(retrieved.providers.discovery.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_gateway_start_tracks_docker_provider_handles() {
    use crate::config::DockerProviderConfig;

    let (docker_host, _mock) = spawn_mock_docker_daemon().await;
    let mut config = minimal_config();
    config.entrypoints.clear();
    config.providers.docker = Some(DockerProviderConfig {
        host: docker_host,
        poll_interval_secs: 60,
        ..DockerProviderConfig::default()
    });

    let gw = Gateway::new(config).unwrap();
    gw.start().await.unwrap();
    assert!(gw.provider_handles.read().unwrap().len() >= 2);

    gw.shutdown().await;
    assert!(gw.provider_handles.read().unwrap().is_empty());
}

#[tokio::test]
async fn test_reload_handle_updates_live_components() {
    use crate::config::{LoadBalancerConfig, ServerConfig, ServiceConfig, Strategy};

    let mut initial = minimal_config();
    initial.entrypoints.clear();
    let gw = Gateway::new(initial).unwrap();
    gw.start().await.unwrap();
    let mut config = minimal_config();
    config.entrypoints.clear();
    config.services.insert(
        "api".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: "http://127.0.0.1:8080".to_string(),
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

    gw.reload_handle().reload(config, "test").await.unwrap();

    assert!(gw.is_running());
    assert!(gw.config().services.contains_key("api"));
    gw.shutdown().await;
}

#[tokio::test]
async fn reload_adding_discovery_starts_poll_loop() {
    use crate::config::{DiscoveryConfig, DiscoverySeedConfig};

    let mut initial = minimal_config();
    initial.entrypoints.clear();
    let gw = Gateway::new(initial).unwrap();
    gw.start().await.unwrap();
    assert!(gw.discovery_handle.read().unwrap().is_none());

    let mut config = minimal_config();
    config.entrypoints.clear();
    config.providers.discovery = Some(DiscoveryConfig {
        seeds: vec![DiscoverySeedConfig {
            url: "http://127.0.0.1:9".to_string(),
        }],
        poll_interval_secs: 60,
        timeout_secs: 1,
    });
    gw.reload_handle()
        .reload(config, "test-add-discovery")
        .await
        .unwrap();
    assert!(
        gw.discovery_handle.read().unwrap().is_some(),
        "reload that adds providers.discovery must start the discovery poll loop"
    );
    gw.shutdown().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_removing_docker_aborts_provider_handles() {
    use crate::config::DockerProviderConfig;

    let (docker_host, _mock) = spawn_mock_docker_daemon().await;
    let mut initial = minimal_config();
    initial.entrypoints.clear();
    initial.providers.docker = Some(DockerProviderConfig {
        host: docker_host,
        poll_interval_secs: 60,
        ..DockerProviderConfig::default()
    });
    let gw = Gateway::new(initial).unwrap();
    gw.start().await.unwrap();
    let handles_with_docker = gw.provider_handles.read().unwrap().len();
    assert!(handles_with_docker >= 2);

    let mut config = minimal_config();
    config.entrypoints.clear();
    gw.reload_handle()
        .reload(config, "test-remove-docker")
        .await
        .unwrap();
    // Receiver coordinator remains; docker poll loop must be gone.
    let handles_without_docker = gw.provider_handles.read().unwrap().len();
    assert!(
        handles_without_docker < handles_with_docker,
        "reload that removes providers.docker must abort the docker provider handle \
         (before={handles_with_docker}, after={handles_without_docker})"
    );
    gw.shutdown().await;
}

#[tokio::test]
async fn reload_disabling_acme_aborts_manager() {
    let directory = tempfile::tempdir().unwrap();
    let storage = directory.path().join("acme");
    std::fs::create_dir_all(&storage).unwrap();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
    let mut initial = minimal_config();
    initial.entrypoints.clear();
    initial.entrypoints.insert("websecure".to_string(), {
        let mut entrypoint = crate::config::EntrypointConfig::new("127.0.0.1:0".to_string());
        entrypoint.tls = Some(crate::config::TlsConfig {
            // Same bootstrap PEM surface as live HTTPS ACME listener tests —
            // invalid placeholders must not soft-pass this reload proof.
            cert_file: fixture.join("revision-1.crt").display().to_string(),
            key_file: fixture.join("revision-1.key").display().to_string(),
            acme: true,
            min_version: "1.2".to_string(),
            acme_email: Some("ops@example.com".to_string()),
            acme_domains: vec!["app.example.com".to_string()],
            acme_staging: true,
            acme_storage_path: Some(storage.to_string_lossy().into_owned()),
        });
        entrypoint
    });

    let gw = Gateway::new(initial)
        .expect("ACME entrypoint with fixture PEMs and writable storage must construct");
    gw.start()
        .await
        .expect("ACME entrypoint must start so reload can abort the manager");
    assert!(
        gw.acme_handle.read().unwrap().is_some(),
        "start with ACME enabled must spawn the ACME manager"
    );

    let mut config = minimal_config();
    config.entrypoints.clear();
    gw.reload_handle()
        .reload(config, "test-disable-acme")
        .await
        .expect("reload that clears ACME entrypoints must succeed");
    assert!(
        gw.acme_handle.read().unwrap().is_none(),
        "reload that disables ACME must abort the ACME manager"
    );
    gw.shutdown().await;
}

fn managed_usage_config(gateway_id: uuid::Uuid, directory: std::path::PathBuf) -> GatewayConfig {
    let mut config = minimal_config();
    config.entrypoints.clear();
    config.mode = crate::config::OperatingMode::CloudManaged;
    config.managed.gateway_id = Some(gateway_id);
    config.managed.usage_spool = Some(crate::config::UsageSpoolConfig {
        directory,
        max_bytes: crate::config::MIN_USAGE_SPOOL_MAX_BYTES,
        cloud_ingest_endpoint: None,
        cloud_ingest_token_env: None,
        cloud_ingest_client_identity_file: None,
        cloud_ingest_server_ca_file: None,
    });
    config
}

#[tokio::test]
async fn gateway_start_opens_and_recovers_the_configured_usage_spool() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    let event_id = uuid::Uuid::new_v4();
    let first_epoch = {
        let gateway =
            Gateway::new(managed_usage_config(gateway_id, spool_directory.clone())).unwrap();
        assert_eq!(gateway.health().usage_spool, None);
        gateway.start().await.unwrap();
        let status = gateway.health().usage_spool.unwrap();
        assert!(status.writable);
        assert_eq!(status.gateway_id, gateway_id);
        assert_eq!(status.retained_records, 0);
        let spool = gateway
            .usage_spool
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        spool.append(event_id, b"durable").await.unwrap();
        gateway.shutdown().await;
        status.boot_epoch
    };

    let gateway = Gateway::new(managed_usage_config(gateway_id, spool_directory)).unwrap();
    gateway.start().await.unwrap();
    let status = gateway.health().usage_spool.unwrap();
    assert_ne!(status.boot_epoch, first_epoch);
    assert_eq!(status.retained_records, 1);
    let spool = gateway
        .usage_spool
        .read()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    let records = spool.read_batch(None, 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event_id, event_id);
    assert_eq!(records[0].payload, b"durable");
    gateway.shutdown().await;
}

#[tokio::test]
async fn gateway_start_launches_cloud_ingest_uploader_when_configured() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = vec![0_u8; 16_384];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request = buf[..n].to_vec();
            let body_start = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .unwrap_or(request.len());
            let body = &request[body_start..];
            let batch: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let batch_id = batch
                .get("batch_id")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let record = batch
                .get("records")
                .and_then(|records| records.as_array())
                .and_then(|records| records.first())
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let cursor = record
                .get("cursor")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let ack = serde_json::json!({
                "schema": "a3s.gateway.usage-batch-receipt.v1",
                "gateway_id": gateway_id,
                "batch_id": batch_id,
                "acknowledged_through": cursor,
            });
            let body = ack.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = seen_tx.send(request);
        }
    });

    let token_env = format!("A3S_USAGE_INGEST_TOKEN_{}", gateway_id.simple());
    std::env::set_var(&token_env, "fixture-token");
    let mut config = managed_usage_config(gateway_id, spool_directory);
    {
        let spool = config.managed.usage_spool.as_mut().unwrap();
        spool.cloud_ingest_endpoint = Some(format!(
            "http://{address}/v1/inference-control/usage-batches"
        ));
        spool.cloud_ingest_token_env = Some(token_env.clone());
    }

    let gateway = Gateway::new(config).unwrap();
    gateway.start().await.unwrap();
    assert!(gateway.usage_uploader_handle.read().unwrap().is_some());
    let spool = gateway
        .usage_spool
        .read()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    spool
        .append(uuid::Uuid::new_v4(), br#"{"kind":"request_started"}"#)
        .await
        .unwrap();

    let request = tokio::time::timeout(std::time::Duration::from_secs(5), seen_rx.recv())
        .await
        .expect("uploader did not contact Cloud ingest endpoint")
        .expect("Cloud ingest channel closed");
    let request_text = String::from_utf8_lossy(&request);
    let request_lower = request_text.to_ascii_lowercase();
    assert!(
        request_lower.contains("authorization: bearer fixture-token"),
        "missing bearer auth in request: {request_text}"
    );
    assert!(
        request_text.contains("a3s.gateway.usage-batch.v1"),
        "missing batch schema in request: {request_text}"
    );
    assert!(
        request_text.contains("payload_base64") && request_text.contains("payload_sha256"),
        "missing integrity fields in request: {request_text}"
    );

    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if spool.status().acknowledged_through.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("local spool did not apply Cloud ACK");

    gateway.shutdown().await;
    std::env::remove_var(&token_env);
}

#[test]
fn validate_activation_fails_closed_when_usage_cloud_ingest_bearer_env_unset() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    let token_env = format!("A3S_USAGE_INGEST_UNSET_{}", gateway_id.simple());
    std::env::remove_var(&token_env);

    let mut config = managed_usage_config(gateway_id, spool_directory);
    {
        let spool = config.managed.usage_spool.as_mut().unwrap();
        spool.cloud_ingest_endpoint =
            Some("http://127.0.0.1:9/v1/inference-control/usage-batches".to_string());
        spool.cloud_ingest_token_env = Some(token_env.clone());
    }

    let error = crate::validate_activation(&config).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains(&token_env) && message.contains("is not set"),
        "expected unset bearer env fail-closed, got: {message}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed when usage Cloud ingest bearer env is unset");
    };
    assert!(
        gateway_error.to_string().contains(&token_env),
        "Gateway::new must share validate_activation fail-closed: {gateway_error}"
    );
}

#[test]
fn validate_activation_fails_closed_when_usage_cloud_ingest_mtls_identity_missing() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    let missing_identity = directory.path().join("missing-client-identity.pem");
    let ca_file = directory.path().join("server-ca.pem");
    std::fs::write(
        &ca_file,
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    let mut config = managed_usage_config(gateway_id, spool_directory);
    {
        let spool = config.managed.usage_spool.as_mut().unwrap();
        spool.cloud_ingest_endpoint =
            Some("https://127.0.0.1:9/v1/inference-control/usage-batches".to_string());
        spool.cloud_ingest_client_identity_file = Some(missing_identity.clone());
        spool.cloud_ingest_server_ca_file = Some(ca_file);
    }

    let error = crate::validate_activation(&config).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("mTLS") || message.contains("identity") || message.contains("invalid"),
        "expected missing mTLS identity fail-closed, got: {message}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed when usage Cloud ingest mTLS identity is missing");
    };
    let gateway_message = gateway_error.to_string();
    assert!(
        gateway_message.contains("mTLS")
            || gateway_message.contains("identity")
            || gateway_message.contains("invalid"),
        "Gateway::new must share validate_activation fail-closed: {gateway_message}"
    );
}

#[tokio::test]
async fn gateway_new_fails_closed_on_a_usage_spool_identity_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let first_gateway_id = uuid::Uuid::new_v4();
    {
        let gateway = Gateway::new(managed_usage_config(
            first_gateway_id,
            spool_directory.clone(),
        ))
        .unwrap();
        gateway.start().await.unwrap();
        gateway.shutdown().await;
    }

    let mismatched = managed_usage_config(uuid::Uuid::new_v4(), spool_directory);
    let error = crate::validate_activation(&mismatched).unwrap_err();
    assert!(
        error.to_string().contains("belongs to Gateway"),
        "validate_activation must fail closed on spool identity mismatch: {error}"
    );
    let Err(gateway_error) = Gateway::new(mismatched) else {
        panic!("Gateway::new must fail closed on usage spool identity mismatch");
    };
    assert!(gateway_error.to_string().contains("belongs to Gateway"));
}

#[tokio::test]
async fn validate_activation_fails_closed_when_usage_spool_has_untracked_file() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    {
        let gateway =
            Gateway::new(managed_usage_config(gateway_id, spool_directory.clone())).unwrap();
        gateway.start().await.unwrap();
        gateway.shutdown().await;
    }
    std::fs::write(spool_directory.join("stray.bin"), b"not part of the spool").unwrap();

    let config = managed_usage_config(gateway_id, spool_directory);
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("untracked"),
        "validate_activation must fail closed on untracked spool paths: {error}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed on untracked usage spool paths");
    };
    assert!(
        gateway_error.to_string().contains("untracked"),
        "Gateway::new must share validate_activation fail-closed: {gateway_error}"
    );
}

#[tokio::test]
async fn validate_activation_fails_closed_when_usage_spool_locked() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    let held = crate::usage::UsageSpool::open(crate::usage::UsageSpoolOptions {
        directory: spool_directory.clone(),
        gateway_id,
        max_bytes: crate::config::MIN_USAGE_SPOOL_MAX_BYTES,
    })
    .await
    .unwrap();

    let config = managed_usage_config(gateway_id, spool_directory);
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("usage_spool") && error.to_string().contains("locked"),
        "validate_activation must fail closed on spool lock contention: {error}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed when usage spool .lock is held");
    };
    assert!(
        gateway_error.to_string().contains("locked"),
        "Gateway::new must share validate_activation fail-closed on lock: {gateway_error}"
    );

    drop(held);
}

#[tokio::test]
async fn validate_activation_fails_closed_when_usage_spool_parent_unusable() {
    let directory = tempfile::tempdir().unwrap();
    let blocker = directory.path().join("not-a-directory");
    std::fs::write(&blocker, b"blocker").unwrap();
    let spool_directory = blocker.join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    let config = managed_usage_config(gateway_id, spool_directory);
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("usage_spool")
            && (error.to_string().contains("create directory")
                || error.to_string().contains("Could not")),
        "validate_activation must fail closed on unusable spool parent: {error}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed when usage spool parent is unusable");
    };
    assert!(
        gateway_error.to_string().contains("usage_spool")
            || gateway_error.to_string().contains("create directory"),
        "Gateway::new must share validate_activation fail-closed: {gateway_error}"
    );
}

#[tokio::test]
#[cfg(unix)]
async fn validate_activation_fails_closed_when_usage_spool_directory_is_not_writable() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    {
        let gateway =
            Gateway::new(managed_usage_config(gateway_id, spool_directory.clone())).unwrap();
        gateway.start().await.unwrap();
        gateway.shutdown().await;
    }
    let mut permissions = std::fs::metadata(&spool_directory).unwrap().permissions();
    permissions.set_mode(0o555);
    std::fs::set_permissions(&spool_directory, permissions).unwrap();

    let config = managed_usage_config(gateway_id, spool_directory.clone());
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("usage_spool") && error.to_string().contains("activation probe"),
        "validate_activation must fail closed when the spool directory rejects create_new: {error}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed when the usage spool directory is not writable");
    };
    assert!(
        gateway_error.to_string().contains("activation probe"),
        "Gateway::new must share validate_activation fail-closed: {gateway_error}"
    );

    let mut permissions = std::fs::metadata(&spool_directory).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&spool_directory, permissions).unwrap();
}

#[tokio::test]
async fn validate_activation_fails_closed_when_usage_spool_epoch_record_corrupt() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    {
        let gateway =
            Gateway::new(managed_usage_config(gateway_id, spool_directory.clone())).unwrap();
        gateway.start().await.unwrap();
        gateway.shutdown().await;
    }
    let epoch = std::fs::read_dir(&spool_directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().starts_with("epoch-"))
        .expect("shutdown must leave a Ready epoch file");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(epoch.path())
        .unwrap();
    std::io::Write::write_all(&mut file, b"truncated").unwrap();
    drop(file);

    let config = managed_usage_config(gateway_id, spool_directory);
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("incomplete"),
        "validate_activation must fail closed on a corrupt Ready epoch record: {error}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed when a Ready usage epoch record is corrupt");
    };
    assert!(
        gateway_error.to_string().contains("incomplete"),
        "Gateway::new must share validate_activation fail-closed: {gateway_error}"
    );
}

#[tokio::test]
async fn validate_activation_fails_closed_when_usage_spool_prepared_epoch_corrupt() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    {
        let gateway =
            Gateway::new(managed_usage_config(gateway_id, spool_directory.clone())).unwrap();
        gateway.start().await.unwrap();
        gateway.shutdown().await;
    }
    let manifest_path = spool_directory.join("manifest.json");
    let manifest = std::fs::read_to_string(&manifest_path).unwrap();
    let updated = manifest.replacen("\"phase\":\"ready\"", "\"phase\":\"prepared\"", 1);
    assert_ne!(
        manifest, updated,
        "shutdown manifest must contain a ready epoch"
    );
    std::fs::write(&manifest_path, updated).unwrap();
    let epoch = std::fs::read_dir(&spool_directory)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().starts_with("epoch-"))
        .expect("shutdown must leave an epoch file");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(epoch.path())
        .unwrap();
    std::io::Write::write_all(&mut file, b"truncated").unwrap();
    drop(file);

    let config = managed_usage_config(gateway_id, spool_directory);
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("incomplete"),
        "validate_activation must fail closed on a corrupt Prepared epoch: {error}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed when a Prepared usage epoch record is corrupt");
    };
    assert!(
        gateway_error.to_string().contains("incomplete"),
        "Gateway::new must share validate_activation fail-closed: {gateway_error}"
    );
}

#[tokio::test]
async fn validate_activation_fails_closed_when_usage_spool_recovery_artifact_is_a_directory() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    {
        let gateway =
            Gateway::new(managed_usage_config(gateway_id, spool_directory.clone())).unwrap();
        gateway.start().await.unwrap();
        gateway.shutdown().await;
    }
    std::fs::create_dir(spool_directory.join(".manifest-blocked.tmp")).unwrap();

    let config = managed_usage_config(gateway_id, spool_directory);
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("recovery artifact")
            || error.to_string().contains("directory"),
        "validate_activation must fail closed when a spool recovery artifact is a directory: {error}"
    );
    let Err(gateway_error) = Gateway::new(config) else {
        panic!("Gateway::new must fail closed when a usage spool recovery artifact is a directory");
    };
    assert!(
        gateway_error.to_string().contains("recovery artifact")
            || gateway_error.to_string().contains("directory"),
        "Gateway::new must share validate_activation fail-closed: {gateway_error}"
    );
}
