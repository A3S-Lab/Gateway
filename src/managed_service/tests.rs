use super::{
    ManagedServiceBindingIdentity, ManagedServiceBindingRequest, ManagedServiceHealthCheck,
    ManagedServicePhase, StoredManagedServiceBinding,
};
use crate::config::{
    EntrypointConfig, GatewayConfig, LoadBalancerConfig, ManagedTargetConfig, RouterConfig,
    ServerConfig, ServiceConfig, Strategy,
};
use crate::managed_snapshot::ManagedSnapshot;
use crate::Gateway;
use chrono::{Duration as ChronoDuration, Utc};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

struct TestBackend {
    address: SocketAddr,
    requests: mpsc::UnboundedReceiver<String>,
    release_streams: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl TestBackend {
    async fn spawn() -> Self {
        Self::spawn_with_health_status(200).await
    }

    async fn spawn_with_health_status(health_status: u16) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (requests_tx, requests) = mpsc::unbounded_channel();
        let (release_streams, release_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let requests = requests_tx.clone();
                let mut release = release_rx.clone();
                tokio::spawn(async move {
                    let mut bytes = Vec::new();
                    let mut chunk = [0_u8; 1024];
                    loop {
                        let read = stream.read(&mut chunk).await.unwrap_or(0);
                        if read == 0 {
                            return;
                        }
                        bytes.extend_from_slice(&chunk[..read]);
                        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let request = String::from_utf8_lossy(&bytes);
                    let path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let _ = requests.send(path.clone());
                    if path == "/held-health" {
                        while !*release.borrow() {
                            if release.changed().await.is_err() {
                                return;
                            }
                        }
                    }
                    if path == "/hold" {
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n",
                            )
                            .await
                            .unwrap();
                        while !*release.borrow() {
                            if release.changed().await.is_err() {
                                return;
                            }
                        }
                        let _ = stream.write_all(b"0\r\n\r\n").await;
                        return;
                    }
                    if path == "/healthz" && !(200..300).contains(&health_status) {
                        let response = format!(
                            "HTTP/1.1 {health_status} Unhealthy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        stream.write_all(response.as_bytes()).await.unwrap();
                        return;
                    }
                    let body = path.as_bytes();
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                    stream.write_all(body).await.unwrap();
                });
            }
        });
        Self {
            address,
            requests,
            release_streams,
            task,
        }
    }

    async fn next_path(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(2), self.requests.recv())
            .await
            .expect("backend request timeout")
            .expect("backend request channel closed")
    }

    async fn next_service_path(&mut self) -> String {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let path = self
                    .requests
                    .recv()
                    .await
                    .expect("backend request channel closed");
                if path != "/healthz" {
                    return path;
                }
            }
        })
        .await
        .expect("backend service request timeout")
    }
}

impl Drop for TestBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn digest(label: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(label.as_bytes()))
}

fn reserve_gateway_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn gateway_config(address: SocketAddr) -> GatewayConfig {
    let mut config = GatewayConfig::default();
    config.entrypoints.clear();
    config.entrypoints.insert(
        "plugins".to_string(),
        EntrypointConfig::new(address.to_string()),
    );
    config.routers.clear();
    config.services.clear();
    config.middlewares.clear();
    config.observability.metrics_enabled = false;
    config.observability.access_log_enabled = false;
    config.observability.tracing_enabled = false;
    config
}

fn add_base_route(config: &mut GatewayConfig, upstream: SocketAddr, path: &str) {
    config.services.insert(
        "base-service".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "1s".to_string(),
                stream_idle_timeout: "1m".to_string(),
                stream_total_timeout: "5m".to_string(),
                servers: vec![ServerConfig {
                    url: format!("http://{upstream}"),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
            },
            scaling: None,
            revisions: Vec::new(),
            rollout: None,
            mirror: None,
            failover: None,
        },
    );
    config.routers.insert(
        "base-router".to_string(),
        RouterConfig {
            rule: format!("PathPrefix(`{path}`)"),
            service: "base-service".to_string(),
            entrypoints: vec!["plugins".to_string()],
            middlewares: Vec::new(),
            priority: 0,
        },
    );
}

fn cloud_managed_acl(
    gateway_id: Uuid,
    gateway_address: SocketAddr,
    management_address: SocketAddr,
    base_upstream: Option<SocketAddr>,
) -> String {
    let traffic = base_upstream.map_or_else(String::new, |upstream| {
        format!(
            r#"
routers "base-router" {{
  rule        = "PathPrefix(`/base`)"
  service     = "base-service"
  entrypoints = ["plugins"]
}}

services "base-service" {{
  load_balancer {{
    servers = [{{ url = "http://{upstream}" }}]
  }}
}}
"#,
        )
    });
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}

entrypoints "plugins" {{ address = "{gateway_address}" }}

management {{
  enabled        = true
  address        = "{management_address}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
{traffic}
"#,
    )
}

fn target(generation: u64) -> ManagedTargetConfig {
    ManagedTargetConfig {
        target_id: Uuid::parse_str("018f0000-0000-7000-8000-000000000001").unwrap(),
        unit_id: "use:workspace-01:acme-search:mcp-query".to_string(),
        generation,
    }
}

fn request(
    label: &str,
    generation: u64,
    upstream: SocketAddr,
    service_path: &str,
) -> ManagedServiceBindingRequest {
    ManagedServiceBindingRequest::new(
        digest(label),
        "plugins",
        target(generation),
        upstream,
        service_path,
        ManagedServiceHealthCheck::new("/healthz", 20, 250, 1, 2).unwrap(),
    )
    .unwrap()
}

fn deadline() -> Option<tokio::time::Instant> {
    Some(tokio::time::Instant::now() + Duration::from_secs(3))
}

fn write_private(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

async fn wait_until_hidden(endpoint: &str) {
    for _ in 0..100 {
        if reqwest::get(endpoint)
            .await
            .is_ok_and(|response| response.status() == reqwest::StatusCode::NOT_FOUND)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("managed route remained visible");
}

#[test]
fn managed_service_state_requires_an_absolute_file_path() {
    let error = Gateway::with_managed_service_state(
        gateway_config(reserve_gateway_address()),
        "relative-managed-services.json",
    )
    .err()
    .expect("relative state path must fail");
    assert!(error.to_string().contains("absolute normalized file path"));

    let ambiguous = std::env::temp_dir()
        .join("a3s-managed-state-parent")
        .join("..")
        .join("managed-services.json");
    let error =
        Gateway::with_managed_service_state(gateway_config(reserve_gateway_address()), ambiguous)
            .err()
            .expect("parent traversal in state path must fail");
    assert!(error.to_string().contains("absolute normalized file path"));
}

#[test]
fn managed_service_state_cannot_overlap_the_snapshot_journal() {
    let directory = tempfile::tempdir().unwrap();
    let snapshot = directory.path().join("managed-snapshot.json");
    let mut config = gateway_config(reserve_gateway_address());
    config.managed.state_file = Some(snapshot.clone());

    let error =
        Gateway::with_managed_service_state(config, snapshot.join("managed-runtime-services.json"))
            .err()
            .expect("nested Managed Service state must fail");
    assert!(error.to_string().contains("separate from snapshot"));
}

#[test]
fn managed_service_public_contracts_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<ManagedServiceHealthCheck>();
    assert_send_sync::<ManagedServiceBindingRequest>();
    assert_send_sync::<super::ManagedServiceBinding>();
    assert_send_sync::<ManagedServiceBindingIdentity>();
    assert_send_sync::<super::ManagedServiceStatus>();
}

#[test]
fn managed_service_paths_must_be_valid_http_uri_paths() {
    let health = ManagedServiceHealthCheck::new("/healthz", 20, 250, 1, 2).unwrap();
    let error = ManagedServiceBindingRequest::new(
        digest("invalid-service-path"),
        "plugins",
        target(1),
        "127.0.0.1:31337".parse().unwrap(),
        "/invalid<path",
        health,
    )
    .unwrap_err();
    assert!(error.to_string().contains("canonical absolute HTTP path"));
}

#[tokio::test]
async fn managed_service_upstream_cannot_recurse_into_its_gateway_entrypoint() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_address = reserve_gateway_address();
    let gateway = Gateway::with_managed_service_state(
        gateway_config(gateway_address),
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();

    let error = gateway
        .bind_managed_service(
            request("recursive-upstream", 1, gateway_address, "/mcp"),
            deadline(),
        )
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("must not be its Gateway entrypoint"));
    gateway.shutdown().await;
}

#[tokio::test]
async fn maximum_priority_base_router_cannot_shadow_a_managed_route() {
    let directory = tempfile::tempdir().unwrap();
    let backend = TestBackend::spawn().await;
    let mut config = gateway_config(reserve_gateway_address());
    add_base_route(&mut config, backend.address, "/");
    config.routers.get_mut("base-router").unwrap().priority = i32::MAX;
    let gateway =
        Gateway::with_managed_service_state(config, directory.path().join("managed-services.json"))
            .unwrap();
    gateway.start().await.unwrap();

    let error = gateway
        .bind_managed_service(
            request("shadowed-route", 1, backend.address, "/mcp"),
            deadline(),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("maximum-priority router"));
    gateway.shutdown().await;
}

#[tokio::test]
async fn corrupt_managed_service_state_fails_gateway_startup_closed() {
    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-services.json");
    write_private(&state_file, b"{");
    let gateway =
        Gateway::with_managed_service_state(gateway_config(reserve_gateway_address()), state_file)
            .unwrap();

    let error = gateway.start().await.unwrap_err();
    assert!(error.to_string().contains("invalid JSON"));
}

#[tokio::test]
async fn one_gateway_exclusively_owns_the_managed_service_state() {
    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-services.json");
    let first = Gateway::with_managed_service_state(
        gateway_config(reserve_gateway_address()),
        state_file.clone(),
    )
    .unwrap();
    let second =
        Gateway::with_managed_service_state(gateway_config(reserve_gateway_address()), state_file)
            .unwrap();
    first.start().await.unwrap();

    let error = second.start().await.unwrap_err();
    assert!(error.to_string().contains("already owned"));

    first.shutdown().await;
    second.start().await.unwrap();
    second.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn linked_managed_service_state_fails_gateway_startup_closed() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let target_file = directory.path().join("target.json");
    let state_file = directory.path().join("managed-services.json");
    write_private(
        &target_file,
        br#"{"schema":"a3s.gateway.managed-service-state.v1","bindings":[]}"#,
    );
    symlink(&target_file, &state_file).unwrap();
    let gateway =
        Gateway::with_managed_service_state(gateway_config(reserve_gateway_address()), state_file)
            .unwrap();

    let error = gateway.start().await.unwrap_err();
    assert!(error.to_string().contains("non-symlink"));
}

#[cfg(unix)]
#[tokio::test]
async fn broadly_readable_managed_service_state_fails_gateway_startup_closed() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-services.json");
    write_private(
        &state_file,
        br#"{"schema":"a3s.gateway.managed-service-state.v1","bindings":[]}"#,
    );
    std::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o640)).unwrap();
    let gateway =
        Gateway::with_managed_service_state(gateway_config(reserve_gateway_address()), state_file)
            .unwrap();

    let error = gateway.start().await.unwrap_err();
    assert!(error.to_string().contains("group or other users"));
}

#[tokio::test]
async fn retiring_state_without_the_exact_drain_key_fails_startup_closed() {
    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-services.json");
    let mut record = super::StoredManagedServiceBinding::new(request(
        "invalid-drain-state",
        15,
        "127.0.0.1:31337".parse().unwrap(),
        "/mcp",
    ))
    .unwrap();
    record.phase = ManagedServicePhase::Draining;
    let state = serde_json::json!({
        "schema": super::model::STATE_SCHEMA,
        "bindings": [record],
    });
    write_private(&state_file, &serde_json::to_vec(&state).unwrap());
    let gateway =
        Gateway::with_managed_service_state(gateway_config(reserve_gateway_address()), state_file)
            .unwrap();

    let error = gateway.start().await.unwrap_err();
    assert!(error.to_string().contains("identity is inconsistent"));
}

mod lifecycle;
