use a3s_gateway::managed_snapshot::{ManagedSnapshot, ManagedSnapshotState, ManagedSnapshotStatus};
use chrono::{Duration, Utc};
use futures_util::{SinkExt, StreamExt};
use http::header::{CONNECTION, CONTENT_TYPE, HOST};
use http::HeaderValue;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashSet;
use std::io::Cursor;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

const MANAGED_HOST: &str = "managed.example.test";
const SSE_BODY: &str = "data: snapshot-ready\n\n";

#[derive(Clone, Copy)]
struct ProtocolBackends {
    http_a: SocketAddr,
    http_b: SocketAddr,
    sse: SocketAddr,
    websocket: SocketAddr,
}

struct GatewayProcess {
    child: Child,
}

impl GatewayProcess {
    fn start(config_path: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_a3s-gateway"));
        command
            .arg("--config")
            .arg(config_path)
            .arg("--log-level")
            .arg("error")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        Self {
            child: command.spawn().expect("failed to start Gateway binary"),
        }
    }

    async fn wait_for_management(&mut self, management_port: u16) {
        let client = reqwest::Client::builder()
            .timeout(StdDuration::from_millis(200))
            .build()
            .unwrap();
        for _ in 0..200 {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("Gateway exited before management became ready: {status}");
            }
            if let Ok(response) = client
                .get(format!(
                    "http://127.0.0.1:{management_port}/api/gateway/health"
                ))
                .send()
                .await
            {
                if response.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(StdDuration::from_millis(25)).await;
        }
        panic!("Gateway management listener did not become ready");
    }

    async fn stop(mut self) {
        if self.child.try_wait().unwrap().is_none() {
            tokio::time::timeout(StdDuration::from_secs(3), self.child.kill())
                .await
                .expect("Gateway process termination timed out")
                .unwrap();
        }
        let _ = tokio::time::timeout(StdDuration::from_secs(3), self.child.wait())
            .await
            .expect("Gateway process reap timed out");
    }
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_ports_released(ports: &[u16]) {
    for _ in 0..200 {
        let mut listeners = Vec::with_capacity(ports.len());
        let mut all_available = true;
        for port in ports {
            match TcpListener::bind(("127.0.0.1", *port)).await {
                Ok(listener) => listeners.push(listener),
                Err(_) => {
                    all_available = false;
                    break;
                }
            }
        }
        if all_available {
            return;
        }
        drop(listeners);
        tokio::time::sleep(StdDuration::from_millis(25)).await;
    }
    panic!("Gateway listener ports were not released");
}

async fn spawn_http_backend(body: &'static str, content_type: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
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
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let Ok(mut websocket) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(message)) = websocket.next().await {
                    if message.is_close() || websocket.send(message).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    address
}

fn tls_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

fn acl_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn bootstrap_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    state_file: &Path,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
  state_file = "{}"
}}

shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}

entrypoints "web" {{
  address = "127.0.0.1:{traffic_port}"
}}

management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}

observability {{
  metrics_enabled    = false
  access_log_enabled = false
  tracing_enabled    = false
}}
"#,
        acl_path(state_file)
    )
}

fn snapshot_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    state_file: &Path,
    backends: ProtocolBackends,
    websocket_service: &str,
) -> String {
    let certificate = tls_fixture("revision-1.crt");
    let private_key = tls_fixture("revision-1.key");
    let ProtocolBackends {
        http_a,
        http_b,
        sse,
        websocket,
    } = backends;
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
  state_file = "{}"
}}

shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}

entrypoints "web" {{
  address = "127.0.0.1:{traffic_port}"
  tls {{
    cert_file = "{}"
    key_file  = "{}"
  }}
}}

routers "api" {{
  rule        = "Host(`{MANAGED_HOST}`) && PathPrefix(`/api`)"
  service     = "api"
  entrypoints = ["web"]
}}

routers "events" {{
  rule        = "Host(`{MANAGED_HOST}`) && PathPrefix(`/events`)"
  service     = "events"
  entrypoints = ["web"]
}}

routers "socket" {{
  rule        = "Host(`{MANAGED_HOST}`) && PathPrefix(`/socket`)"
  service     = "{websocket_service}"
  entrypoints = ["web"]
}}

services "api" {{
  load_balancer {{
    strategy = "round-robin"
    servers = [
      {{ url = "http://{http_a}" }},
      {{ url = "http://{http_b}" }}
    ]
  }}
}}

services "events" {{
  load_balancer {{
    servers = [
      {{ url = "http://{sse}" }}
    ]
  }}
}}

services "socket" {{
  load_balancer {{
    servers = [
      {{ url = "http://{websocket}" }}
    ]
  }}
}}

management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}

observability {{
  metrics_enabled    = false
  access_log_enabled = false
  tracing_enabled    = false
}}
"#,
        acl_path(state_file),
        acl_path(&certificate),
        acl_path(&private_key)
    )
}

fn snapshot(
    gateway_id: Uuid,
    revision: u64,
    expected_revision: Option<u64>,
    acl: String,
) -> ManagedSnapshot {
    let now = Utc::now();
    ManagedSnapshot::new(
        gateway_id,
        revision,
        expected_revision,
        now,
        now + Duration::hours(1),
        acl,
    )
}

async fn apply(
    client: &reqwest::Client,
    management_port: u16,
    snapshot: &ManagedSnapshot,
) -> (reqwest::StatusCode, ManagedSnapshotStatus) {
    let response = client
        .post(format!(
            "http://127.0.0.1:{management_port}/api/gateway/snapshots/apply"
        ))
        .json(snapshot)
        .send()
        .await
        .unwrap();
    let status_code = response.status();
    let status = response.json::<ManagedSnapshotStatus>().await.unwrap();
    (status_code, status)
}

async fn exact_status(
    client: &reqwest::Client,
    management_port: u16,
    snapshot: &ManagedSnapshot,
) -> ManagedSnapshotStatus {
    client
        .get(format!(
            "http://127.0.0.1:{management_port}/api/gateway/snapshots/status"
        ))
        .query(&[
            ("gateway_id", snapshot.gateway_id.to_string()),
            ("revision", snapshot.revision.to_string()),
            ("snapshot_digest", snapshot.snapshot_digest.clone()),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

fn tls_http_client() -> reqwest::Client {
    let certificate =
        reqwest::Certificate::from_pem(&std::fs::read(tls_fixture("revision-1-ca.crt")).unwrap())
            .unwrap();
    reqwest::Client::builder()
        .add_root_certificate(certificate)
        .timeout(StdDuration::from_secs(3))
        .build()
        .unwrap()
}

async fn assert_http_targets(client: &reqwest::Client, traffic_port: u16) {
    let mut bodies = HashSet::new();
    for _ in 0..6 {
        let response = client
            .get(format!("https://127.0.0.1:{traffic_port}/api/models"))
            .header(HOST, MANAGED_HOST)
            .header(CONNECTION, "close")
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        bodies.insert(response.text().await.unwrap());
    }
    assert_eq!(
        bodies,
        HashSet::from(["target-a".to_string(), "target-b".to_string()])
    );
}

async fn assert_sse(client: &reqwest::Client, traffic_port: u16) {
    let response = client
        .get(format!("https://127.0.0.1:{traffic_port}/events"))
        .header(HOST, MANAGED_HOST)
        .header(http::header::ACCEPT, "text/event-stream")
        .header(CONNECTION, "close")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(
        response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("text/event-stream")
    );
    assert_eq!(response.text().await.unwrap(), SSE_BODY);
}

async fn assert_websocket(traffic_port: u16) {
    let ca_bytes = tokio::fs::read(tls_fixture("revision-1-ca.crt"))
        .await
        .unwrap();
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut Cursor::new(ca_bytes)) {
        roots.add(certificate.unwrap()).unwrap();
    }
    let connector = TlsConnector::from(Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ));
    let tcp = tokio::time::timeout(
        StdDuration::from_secs(2),
        TcpStream::connect(("127.0.0.1", traffic_port)),
    )
    .await
    .expect("WebSocket TCP connection timed out")
    .unwrap();
    let tls = tokio::time::timeout(
        StdDuration::from_secs(2),
        connector.connect(ServerName::try_from("127.0.0.1").unwrap(), tcp),
    )
    .await
    .expect("WebSocket TLS handshake timed out")
    .unwrap();
    let mut request = format!("wss://127.0.0.1:{traffic_port}/socket")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_static(MANAGED_HOST));
    let (mut websocket, response) = tokio::time::timeout(
        StdDuration::from_secs(2),
        tokio_tungstenite::client_async(request, tls),
    )
    .await
    .expect("WebSocket upgrade timed out")
    .unwrap();
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);

    websocket
        .send(Message::Text("managed-echo".into()))
        .await
        .unwrap();
    let echoed = tokio::time::timeout(StdDuration::from_secs(2), websocket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(echoed, Message::Text("managed-echo".into()));
    websocket.close(None).await.unwrap();
}

async fn assert_protocol_matrix(client: &reqwest::Client, traffic_port: u16) {
    assert_http_targets(client, traffic_port).await;
    assert_sse(client, traffic_port).await;
    assert_websocket(traffic_port).await;
}

#[tokio::test]
async fn real_gateway_recovers_exact_managed_tls_protocol_snapshot_after_process_loss() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("gateway.acl");
    let state_file = directory.path().join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backends = ProtocolBackends {
        http_a: spawn_http_backend("target-a", "text/plain").await,
        http_b: spawn_http_backend("target-b", "text/plain").await,
        sse: spawn_http_backend(SSE_BODY, "text/event-stream").await,
        websocket: spawn_websocket_backend().await,
    };

    tokio::fs::write(
        &config_path,
        bootstrap_acl(gateway_id, traffic_port, management_port, &state_file),
    )
    .await
    .unwrap();
    let snapshot_v1 = snapshot(
        gateway_id,
        1,
        None,
        snapshot_acl(
            gateway_id,
            traffic_port,
            management_port,
            &state_file,
            backends,
            "socket",
        ),
    );
    let management_client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(3))
        .build()
        .unwrap();
    let traffic_client = tls_http_client();

    let mut first = GatewayProcess::start(&config_path);
    first.wait_for_management(management_port).await;
    let (status_code, applied) = apply(&management_client, management_port, &snapshot_v1).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert_eq!(applied.state, ManagedSnapshotState::Applied);
    assert!(applied.ready);
    let applied_identity = applied.applied.unwrap();
    assert_eq!(applied_identity.gateway_id, gateway_id);
    assert_eq!(applied_identity.revision, snapshot_v1.revision);
    assert_eq!(
        applied_identity.snapshot_digest,
        snapshot_v1.snapshot_digest
    );
    assert_protocol_matrix(&traffic_client, traffic_port).await;

    let invalid_v2 = snapshot(
        gateway_id,
        2,
        Some(1),
        snapshot_acl(
            gateway_id,
            traffic_port,
            management_port,
            &state_file,
            backends,
            "missing-service",
        ),
    );
    let (status_code, rejected) = apply(&management_client, management_port, &invalid_v2).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert!(!rejected.ready);
    assert!(rejected
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("unknown service")));
    assert!(
        exact_status(&management_client, management_port, &snapshot_v1)
            .await
            .ready
    );
    assert_protocol_matrix(&traffic_client, traffic_port).await;

    first.stop().await;
    wait_for_ports_released(&[traffic_port, management_port]).await;

    let mut restarted = GatewayProcess::start(&config_path);
    restarted.wait_for_management(management_port).await;
    let recovered = exact_status(&management_client, management_port, &snapshot_v1).await;
    assert_eq!(recovered.state, ManagedSnapshotState::Applied);
    assert!(recovered.ready);
    assert_protocol_matrix(&traffic_client, traffic_port).await;

    let (status_code, replayed) = apply(&management_client, management_port, &snapshot_v1).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert_eq!(replayed.state, ManagedSnapshotState::Applied);
    assert!(replayed.ready);
    assert!(replayed.replayed);
    assert_protocol_matrix(&traffic_client, traffic_port).await;

    restarted.stop().await;
    wait_for_ports_released(&[traffic_port, management_port]).await;
}
