use a3s_gateway::managed_snapshot::{ManagedSnapshot, ManagedSnapshotState, ManagedSnapshotStatus};
use a3s_gateway::{config::GatewayConfig, Gateway};
use chrono::{Duration, Utc};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use uuid::Uuid;

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn free_udp_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn spawn_http_backend(body: &'static str) -> SocketAddr {
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
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

async fn spawn_tcp_backend(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

async fn spawn_udp_backend(body: &'static str) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut request = [0_u8; 65_535];
        loop {
            let Ok((_, client)) = socket.recv_from(&mut request).await else {
                return;
            };
            let _ = socket.send_to(body.as_bytes(), client).await;
        }
    });
    address
}

async fn wait_ready(port: u16) {
    for _ in 0..100 {
        if TcpListener::bind(("127.0.0.1", port)).await.is_err()
            && TcpStream::connect(("127.0.0.1", port)).await.is_ok()
        {
            return;
        }
        tokio::time::sleep(StdDuration::from_millis(20)).await;
    }
    panic!("port {port} did not become ready");
}

fn bootstrap_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    protocol: &str,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
}}

shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}

entrypoints "web" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "{protocol}"
}}

management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
"#
    )
}

fn tls_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: SocketAddr,
    cert_file: &Path,
    key_file: &Path,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
}}

shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}

entrypoints "web" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "http"
  tls {{
    cert_file = "{}"
    key_file  = "{}"
  }}
}}

routers "managed" {{
  rule        = "PathPrefix(`/`)"
  service     = "managed"
  entrypoints = ["web"]
}}

services "managed" {{
  load_balancer {{
    servers = [
      {{ url = "http://{backend}" }}
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
"#,
        cert_file.display(),
        key_file.display()
    )
}

fn tcp_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: SocketAddr,
    allowed_ip: &str,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
}}

shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}

entrypoints "web" {{
  address         = "127.0.0.1:{traffic_port}"
  protocol        = "tcp"
  tcp_allowed_ips = ["{allowed_ip}"]
}}

routers "managed" {{
  rule        = "PathPrefix(`/`)"
  service     = "managed"
  entrypoints = ["web"]
}}

services "managed" {{
  load_balancer {{
    servers = [
      {{ url = "tcp://{backend}" }}
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
"#
    )
}

fn udp_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: SocketAddr,
    max_sessions: usize,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
}}

shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}

entrypoints "web" {{
  address                  = "127.0.0.1:{traffic_port}"
  protocol                 = "udp"
  udp_session_timeout_secs = 5
  udp_max_sessions         = {max_sessions}
}}

routers "managed" {{
  rule        = "PathPrefix(`/`)"
  service     = "managed"
  entrypoints = ["web"]
}}

services "managed" {{
  load_balancer {{
    servers = [
      {{ url = "udp://{backend}" }}
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
"#
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

fn tls_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

fn tls_client(cert_file: &Path) -> reqwest::Client {
    let certificate = reqwest::Certificate::from_pem(&std::fs::read(cert_file).unwrap()).unwrap();
    reqwest::Client::builder()
        .add_root_certificate(certificate)
        .build()
        .unwrap()
}

async fn tls_body(client: &reqwest::Client, traffic_port: u16) -> reqwest::Result<String> {
    client
        .get(format!("https://127.0.0.1:{traffic_port}/"))
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await?
        .error_for_status()?
        .text()
        .await
}

async fn tcp_body(traffic_port: u16) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(("127.0.0.1", traffic_port)).await?;
    let mut bytes = Vec::new();
    tokio::time::timeout(StdDuration::from_secs(1), stream.read_to_end(&mut bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "TCP read timed out"))??;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

async fn udp_body(
    client: &UdpSocket,
    traffic_port: u16,
    request: &[u8],
) -> std::io::Result<String> {
    client.send_to(request, ("127.0.0.1", traffic_port)).await?;
    let mut bytes = [0_u8; 1_024];
    let (length, _) = tokio::time::timeout(StdDuration::from_secs(1), client.recv_from(&mut bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "UDP read timed out"))??;
    Ok(String::from_utf8_lossy(&bytes[..length]).into_owned())
}

#[tokio::test]
async fn managed_snapshot_rotates_tls_in_place_and_preserves_the_last_valid_certificate() {
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_http_backend("tls-revision-1").await;
    let backend_v2 = spawn_http_backend("tls-revision-2").await;
    let backend_invalid = spawn_http_backend("must-not-activate").await;
    let cert_v1 = tls_fixture("revision-1.crt");
    let key_v1 = tls_fixture("revision-1.key");
    let ca_v1 = tls_fixture("revision-1-ca.crt");
    let cert_v2 = tls_fixture("revision-2.crt");
    let key_v2 = tls_fixture("revision-2.key");
    let ca_v2 = tls_fixture("revision-2-ca.crt");

    let gateway = Arc::new(
        Gateway::new(
            GatewayConfig::from_acl(&bootstrap_acl(
                gateway_id,
                traffic_port,
                management_port,
                "http",
            ))
            .unwrap(),
        )
        .unwrap(),
    );
    gateway.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;
    let management_client = reqwest::Client::new();

    let revision_1 = snapshot(
        gateway_id,
        1,
        None,
        tls_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_v1,
            &cert_v1,
            &key_v1,
        ),
    );
    let (status_code, applied_v1) = apply(&management_client, management_port, &revision_1).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert_eq!(applied_v1.state, ManagedSnapshotState::Applied);
    assert!(applied_v1.ready);
    assert_eq!(
        tls_body(&tls_client(&ca_v1), traffic_port).await.unwrap(),
        "tls-revision-1"
    );

    let revision_2 = snapshot(
        gateway_id,
        2,
        Some(1),
        tls_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_v2,
            &cert_v2,
            &key_v2,
        ),
    );
    let (status_code, applied_v2) = apply(&management_client, management_port, &revision_2).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert_eq!(applied_v2.state, ManagedSnapshotState::Applied);
    assert!(applied_v2.ready);
    assert_eq!(
        tls_body(&tls_client(&ca_v2), traffic_port).await.unwrap(),
        "tls-revision-2"
    );
    assert!(
        tls_body(&tls_client(&ca_v1), traffic_port).await.is_err(),
        "the superseded certificate must not be served to new connections"
    );

    let missing_dir = tempfile::tempdir().unwrap();
    let invalid = snapshot(
        gateway_id,
        3,
        Some(2),
        tls_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_invalid,
            &missing_dir.path().join("missing.crt"),
            &missing_dir.path().join("missing.key"),
        ),
    );
    let (status_code, rejected) = apply(&management_client, management_port, &invalid).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert!(rejected
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("certificate file")));
    assert!(
        exact_status(&management_client, management_port, &revision_2)
            .await
            .ready
    );
    assert_eq!(
        tls_body(&tls_client(&ca_v2), traffic_port).await.unwrap(),
        "tls-revision-2"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn managed_snapshot_reconfigures_tcp_filter_without_releasing_the_listener() {
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_tcp_backend("tcp-revision-1").await;
    let backend_v2 = spawn_tcp_backend("tcp-revision-2").await;

    let gateway = Arc::new(
        Gateway::new(
            GatewayConfig::from_acl(&bootstrap_acl(
                gateway_id,
                traffic_port,
                management_port,
                "tcp",
            ))
            .unwrap(),
        )
        .unwrap(),
    );
    gateway.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;
    let management_client = reqwest::Client::new();

    let revision_1 = snapshot(
        gateway_id,
        1,
        None,
        tcp_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_v1,
            "127.0.0.1",
        ),
    );
    assert_eq!(
        apply(&management_client, management_port, &revision_1)
            .await
            .0,
        reqwest::StatusCode::OK
    );
    assert_eq!(tcp_body(traffic_port).await.unwrap(), "tcp-revision-1");

    let revision_2 = snapshot(
        gateway_id,
        2,
        Some(1),
        tcp_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_v2,
            "192.0.2.1",
        ),
    );
    let (status_code, applied_v2) = apply(&management_client, management_port, &revision_2).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert!(applied_v2.ready);
    assert_ne!(
        tcp_body(traffic_port).await.unwrap_or_default(),
        "tcp-revision-2"
    );

    let invalid_filter = snapshot(
        gateway_id,
        3,
        Some(2),
        tcp_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_v2,
            "not-an-ip",
        ),
    );
    let (status_code, rejected) = apply(&management_client, management_port, &invalid_filter).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert!(
        exact_status(&management_client, management_port, &revision_2)
            .await
            .ready
    );
    assert_ne!(
        tcp_body(traffic_port).await.unwrap_or_default(),
        "tcp-revision-2"
    );

    let revision_3 = snapshot(
        gateway_id,
        3,
        Some(2),
        tcp_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_v2,
            "127.0.0.1",
        ),
    );
    let (status_code, applied_v3) = apply(&management_client, management_port, &revision_3).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert!(applied_v3.ready);
    assert_eq!(tcp_body(traffic_port).await.unwrap(), "tcp-revision-2");

    gateway.shutdown().await;
}

#[tokio::test]
async fn managed_snapshot_reconciles_udp_policy_and_target_without_releasing_the_listener() {
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_udp_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_udp_backend("udp-revision-1").await;
    let backend_v2 = spawn_udp_backend("udp-revision-2").await;

    let gateway = Arc::new(
        Gateway::new(
            GatewayConfig::from_acl(&bootstrap_acl(
                gateway_id,
                traffic_port,
                management_port,
                "udp",
            ))
            .unwrap(),
        )
        .unwrap(),
    );
    gateway.start().await.unwrap();
    wait_ready(management_port).await;
    assert!(
        UdpSocket::bind(("127.0.0.1", traffic_port)).await.is_err(),
        "the bootstrap UDP listener must own its socket before the first snapshot"
    );
    let management_client = reqwest::Client::new();
    let traffic_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let revision_1 = snapshot(
        gateway_id,
        1,
        None,
        udp_acl(gateway_id, traffic_port, management_port, backend_v1, 100),
    );
    let (status_code, applied_v1) = apply(&management_client, management_port, &revision_1).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert!(applied_v1.ready);
    assert_eq!(
        udp_body(&traffic_client, traffic_port, b"revision-1")
            .await
            .unwrap(),
        "udp-revision-1"
    );

    let revision_2 = snapshot(
        gateway_id,
        2,
        Some(1),
        udp_acl(gateway_id, traffic_port, management_port, backend_v2, 100),
    );
    let (status_code, applied_v2) = apply(&management_client, management_port, &revision_2).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert!(applied_v2.ready);
    assert!(
        UdpSocket::bind(("127.0.0.1", traffic_port)).await.is_err(),
        "same-address UDP reconciliation must retain the bound socket"
    );
    assert_eq!(
        udp_body(&traffic_client, traffic_port, b"revision-2")
            .await
            .unwrap(),
        "udp-revision-2",
        "an existing client session must not keep the superseded target active"
    );

    let revision_3 = snapshot(
        gateway_id,
        3,
        Some(2),
        udp_acl(gateway_id, traffic_port, management_port, backend_v2, 200),
    );
    let (status_code, applied_v3) = apply(&management_client, management_port, &revision_3).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert!(applied_v3.ready);
    assert_eq!(
        udp_body(&traffic_client, traffic_port, b"policy-revision")
            .await
            .unwrap(),
        "udp-revision-2"
    );

    let invalid = snapshot(
        gateway_id,
        4,
        Some(3),
        udp_acl(gateway_id, traffic_port, management_port, backend_v1, 0),
    );
    let (status_code, rejected) = apply(&management_client, management_port, &invalid).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert!(rejected
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("udp_max_sessions")));
    assert!(
        exact_status(&management_client, management_port, &revision_3)
            .await
            .ready
    );
    assert_eq!(
        udp_body(&traffic_client, traffic_port, b"after-rejection")
            .await
            .unwrap(),
        "udp-revision-2",
        "a rejected UDP policy must preserve the prior target and session policy"
    );

    gateway.shutdown().await;
}
