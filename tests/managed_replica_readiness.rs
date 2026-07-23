use a3s_gateway::managed_snapshot::{ManagedSnapshot, ManagedSnapshotState, ManagedSnapshotStatus};
use chrono::{Duration, Utc};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use uuid::Uuid;

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

    async fn terminate(&mut self) {
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

struct ReplicaFixture {
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    config_path: PathBuf,
    state_file: PathBuf,
}

impl ReplicaFixture {
    async fn write_bootstrap(&self) {
        tokio::fs::write(
            &self.config_path,
            bootstrap_acl(
                self.gateway_id,
                self.traffic_port,
                self.management_port,
                &self.state_file,
            ),
        )
        .await
        .unwrap();
    }

    fn snapshot(
        &self,
        revision: u64,
        expected_revision: Option<u64>,
        backend: SocketAddr,
        route_service: &str,
    ) -> ManagedSnapshot {
        let now = Utc::now();
        ManagedSnapshot::new(
            self.gateway_id,
            revision,
            expected_revision,
            now,
            now + Duration::hours(1),
            snapshot_acl(
                self.gateway_id,
                self.traffic_port,
                self.management_port,
                &self.state_file,
                backend,
                route_service,
            ),
        )
    }
}

async fn free_ports(count: usize) -> Vec<u16> {
    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect()
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

async fn spawn_backend(body: &'static str) -> SocketAddr {
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
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
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
    backend: SocketAddr,
    route_service: &str,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
  state_file = "{}"
}}

entrypoints "web" {{
  address = "127.0.0.1:{traffic_port}"
}}

routers "api" {{
  rule        = "PathPrefix(`/`)"
  service     = "{route_service}"
  entrypoints = ["web"]
}}

services "api" {{
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

observability {{
  metrics_enabled    = false
  access_log_enabled = false
  tracing_enabled    = false
}}
"#,
        acl_path(state_file)
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

async fn traffic_body(client: &reqwest::Client, traffic_port: u16) -> String {
    client
        .get(format!("http://127.0.0.1:{traffic_port}/"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap()
}

async fn assert_exact_state(
    client: &reqwest::Client,
    replica: &ReplicaFixture,
    snapshot: &ManagedSnapshot,
    expected_state: ManagedSnapshotState,
    expected_ready: bool,
) {
    let status = exact_status(client, replica.management_port, snapshot).await;
    assert_eq!(status.state, expected_state);
    assert_eq!(status.ready, expected_ready);
}

async fn assert_traffic(client: &reqwest::Client, replica: &ReplicaFixture, expected_body: &str) {
    assert_eq!(
        traffic_body(client, replica.traffic_port).await,
        expected_body
    );
}

#[tokio::test]
async fn replicated_gateways_report_independent_exact_readiness_across_skew_and_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let backend_v1 = spawn_backend("revision-1").await;
    let backend_v2 = spawn_backend("revision-2").await;
    let ports = free_ports(4).await;
    let replica_a = ReplicaFixture {
        gateway_id: Uuid::new_v4(),
        traffic_port: ports[0],
        management_port: ports[1],
        config_path: directory.path().join("replica-a.acl"),
        state_file: directory.path().join("replica-a-state.json"),
    };
    let replica_b = ReplicaFixture {
        gateway_id: Uuid::new_v4(),
        traffic_port: ports[2],
        management_port: ports[3],
        config_path: directory.path().join("replica-b.acl"),
        state_file: directory.path().join("replica-b-state.json"),
    };
    replica_a.write_bootstrap().await;
    replica_b.write_bootstrap().await;

    let snapshot_a_v1 = replica_a.snapshot(1, None, backend_v1, "api");
    let snapshot_b_v1 = replica_b.snapshot(1, None, backend_v1, "api");
    let snapshot_a_v2 = replica_a.snapshot(2, Some(1), backend_v2, "api");
    let invalid_b_v2 = replica_b.snapshot(2, Some(1), backend_v2, "missing-service");
    let snapshot_b_v2 = replica_b.snapshot(2, Some(1), backend_v2, "api");

    let management_client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(3))
        .build()
        .unwrap();
    let traffic_client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(3))
        .build()
        .unwrap();
    let mut process_a = GatewayProcess::start(&replica_a.config_path);
    let mut process_b = GatewayProcess::start(&replica_b.config_path);
    process_a
        .wait_for_management(replica_a.management_port)
        .await;
    process_b
        .wait_for_management(replica_b.management_port)
        .await;

    for (replica, snapshot) in [(&replica_a, &snapshot_a_v1), (&replica_b, &snapshot_b_v1)] {
        let (status_code, applied) =
            apply(&management_client, replica.management_port, snapshot).await;
        assert_eq!(status_code, reqwest::StatusCode::OK);
        assert_eq!(applied.state, ManagedSnapshotState::Applied);
        assert!(applied.ready);
    }
    assert_traffic(&traffic_client, &replica_a, "revision-1").await;
    assert_traffic(&traffic_client, &replica_b, "revision-1").await;

    let (status_code, applied_a_v2) = apply(
        &management_client,
        replica_a.management_port,
        &snapshot_a_v2,
    )
    .await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert!(applied_a_v2.ready);

    let (status_code, rejected_b_v2) =
        apply(&management_client, replica_b.management_port, &invalid_b_v2).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rejected_b_v2.state, ManagedSnapshotState::Rejected);
    assert!(!rejected_b_v2.ready);
    assert_eq!(rejected_b_v2.applied.as_ref().unwrap().revision, 1);

    assert_exact_state(
        &management_client,
        &replica_a,
        &snapshot_a_v1,
        ManagedSnapshotState::NotApplied,
        false,
    )
    .await;
    assert_exact_state(
        &management_client,
        &replica_b,
        &snapshot_b_v1,
        ManagedSnapshotState::Applied,
        true,
    )
    .await;
    assert_exact_state(
        &management_client,
        &replica_b,
        &snapshot_a_v2,
        ManagedSnapshotState::NotApplied,
        false,
    )
    .await;
    assert_traffic(&traffic_client, &replica_a, "revision-2").await;
    assert_traffic(&traffic_client, &replica_b, "revision-1").await;

    process_a.terminate().await;
    wait_for_ports_released(&[replica_a.traffic_port, replica_a.management_port]).await;
    assert_exact_state(
        &management_client,
        &replica_b,
        &snapshot_b_v1,
        ManagedSnapshotState::Applied,
        true,
    )
    .await;
    assert_traffic(&traffic_client, &replica_b, "revision-1").await;

    process_a = GatewayProcess::start(&replica_a.config_path);
    process_a
        .wait_for_management(replica_a.management_port)
        .await;
    assert_exact_state(
        &management_client,
        &replica_a,
        &snapshot_a_v2,
        ManagedSnapshotState::Applied,
        true,
    )
    .await;
    assert_traffic(&traffic_client, &replica_a, "revision-2").await;

    let (status_code, applied_b_v2) = apply(
        &management_client,
        replica_b.management_port,
        &snapshot_b_v2,
    )
    .await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert!(applied_b_v2.ready);
    assert_exact_state(
        &management_client,
        &replica_a,
        &snapshot_a_v2,
        ManagedSnapshotState::Applied,
        true,
    )
    .await;
    assert_exact_state(
        &management_client,
        &replica_b,
        &snapshot_b_v2,
        ManagedSnapshotState::Applied,
        true,
    )
    .await;
    assert_traffic(&traffic_client, &replica_b, "revision-2").await;

    process_a.terminate().await;
    process_b.terminate().await;
    wait_for_ports_released(&ports).await;
}
