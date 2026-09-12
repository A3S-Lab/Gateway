//! H0.3 local evidence: Cloud managed target generation replacement drains
//! in-flight work on the retired generation while new requests move to the
//! successor. This is Gateway-local; multi-replica joint gates remain open.

use a3s_gateway::managed_snapshot::{ManagedSnapshot, ManagedSnapshotState, ManagedSnapshotStatus};
use a3s_gateway::{config::GatewayConfig, Gateway};
use chrono::{Duration, Utc};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uuid::Uuid;

async fn free_tcp_ports() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (
        first.local_addr().unwrap().port(),
        second.local_addr().unwrap().port(),
    )
}

async fn start_bootstrap_gateway(gateway_id: Uuid) -> (Arc<Gateway>, u16, u16) {
    let mut last_bind_error = None;
    for _ in 0..10 {
        let (traffic_port, management_port) = free_tcp_ports().await;
        let gateway = Arc::new(
            Gateway::new(
                GatewayConfig::from_acl(&bootstrap_acl(gateway_id, traffic_port, management_port))
                    .unwrap(),
            )
            .unwrap(),
        );
        match gateway.start().await {
            Ok(()) => return (gateway, traffic_port, management_port),
            Err(error) if error.to_string().contains("Address already in use") => {
                last_bind_error = Some(error);
            }
            Err(error) => panic!("bootstrap Gateway failed: {error}"),
        }
    }
    panic!(
        "bootstrap Gateway could not reserve ports: {}",
        last_bind_error.unwrap()
    );
}

fn bootstrap_acl(gateway_id: Uuid, traffic_port: u16, management_port: u16) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}
entrypoints "web" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "http"
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

fn traffic_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: SocketAddr,
    target_id: Uuid,
    unit_id: &str,
    generation: u64,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}
entrypoints "web" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "http"
}}
routers "managed" {{
  rule        = "PathPrefix(`/`)"
  service     = "managed"
  entrypoints = ["web"]
}}
services "managed" {{
  load_balancer {{
    request_timeout = "5s"
    servers {{
      url = "http://{backend}"
      target {{
        target_id = "{target_id}"
        unit_id = "{unit_id}"
        generation = {generation}
      }}
    }}
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
) -> ManagedSnapshotStatus {
    let response = client
        .post(format!(
            "http://127.0.0.1:{management_port}/api/gateway/snapshots/apply"
        ))
        .json(snapshot)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "snapshot apply failed: {}",
        response.status()
    );
    let status = response.json::<ManagedSnapshotStatus>().await.unwrap();
    assert_eq!(status.state, ManagedSnapshotState::Applied);
    assert!(status.ready);
    status
}

async fn spawn_blocking_labeled_backend(
    label: &'static str,
) -> (SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await;
        let _ = started_tx.send(());
        let _ = release_rx.await;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            label.len(),
            label
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    (address, started_rx, release_tx)
}

async fn spawn_echo_backend(label: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let label = label;
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    label.len(),
                    label
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

async fn write_chunk(stream: &mut tokio::net::TcpStream, payload: &[u8]) {
    let header = format!("{:x}\r\n", payload.len());
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(payload).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
}

async fn spawn_blocking_sse_backend() -> (SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .unwrap();
        write_chunk(&mut stream, b"data: generation-1-first\n\n").await;
        let _ = started_tx.send(());
        let _ = finish_rx.await;
        write_chunk(&mut stream, b"data: generation-1-done\n\n").await;
        stream.write_all(b"0\r\n\r\n").await.unwrap();
        let _ = stream.shutdown().await;
    });
    (address, started_rx, finish_tx)
}

#[tokio::test]
async fn generation_bump_keeps_inflight_on_retired_target_while_new_requests_use_successor() {
    let gateway_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let unit_id = "workload:unit";
    let (gateway, traffic_port, management_port) = start_bootstrap_gateway(gateway_id).await;
    let client = reqwest::Client::new();

    let (retired_backend, request_started, release_retired) =
        spawn_blocking_labeled_backend("generation-1").await;
    let first = snapshot(
        gateway_id,
        1,
        None,
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            retired_backend,
            target_id,
            unit_id,
            1,
        ),
    );
    apply(&client, management_port, &first).await;

    let in_flight = tokio::spawn(async move {
        reqwest::Client::new()
            .get(format!("http://127.0.0.1:{traffic_port}/"))
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    tokio::time::timeout(StdDuration::from_secs(2), request_started)
        .await
        .expect("retired generation did not accept the in-flight request")
        .unwrap();

    let successor_backend = spawn_echo_backend("generation-2").await;
    let second = snapshot(
        gateway_id,
        2,
        Some(1),
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            successor_backend,
            target_id,
            unit_id,
            2,
        ),
    );
    apply(&client, management_port, &second).await;

    let successor_body = client
        .get(format!("http://127.0.0.1:{traffic_port}/"))
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        successor_body, "generation-2",
        "new requests must use the successor managed generation"
    );

    release_retired.send(()).unwrap();
    let retired_body = tokio::time::timeout(StdDuration::from_secs(2), in_flight)
        .await
        .expect("retired generation in-flight work must finish")
        .unwrap();
    assert_eq!(
        retired_body, "generation-1",
        "in-flight work must complete on the retired generation"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn generation_bump_preserves_inflight_sse_on_retired_target() {
    let gateway_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let unit_id = "workload:sse-unit";
    let (gateway, traffic_port, management_port) = start_bootstrap_gateway(gateway_id).await;
    let client = reqwest::Client::new();

    let (retired_backend, stream_started, finish_retired) = spawn_blocking_sse_backend().await;
    let first = snapshot(
        gateway_id,
        1,
        None,
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            retired_backend,
            target_id,
            unit_id,
            1,
        ),
    );
    apply(&client, management_port, &first).await;

    let in_flight = tokio::spawn(async move {
        reqwest::Client::new()
            .get(format!("http://127.0.0.1:{traffic_port}/stream"))
            .header("accept", "text/event-stream")
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    tokio::time::timeout(StdDuration::from_secs(2), stream_started)
        .await
        .expect("retired generation did not start SSE")
        .unwrap();

    let successor_backend = spawn_echo_backend("generation-2").await;
    let second = snapshot(
        gateway_id,
        2,
        Some(1),
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            successor_backend,
            target_id,
            unit_id,
            2,
        ),
    );
    apply(&client, management_port, &second).await;

    let successor_body = client
        .get(format!("http://127.0.0.1:{traffic_port}/"))
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(successor_body, "generation-2");

    finish_retired.send(()).unwrap();
    let retired_body = tokio::time::timeout(StdDuration::from_secs(2), in_flight)
        .await
        .expect("retired SSE must finish after generation bump")
        .unwrap();
    assert!(
        retired_body.contains("generation-1-first") && retired_body.contains("generation-1-done"),
        "SSE body incomplete after generation bump: {retired_body}"
    );

    gateway.shutdown().await;
}
