use a3s_gateway::managed_snapshot::{ManagedSnapshot, ManagedSnapshotState, ManagedSnapshotStatus};
use a3s_gateway::{config::GatewayConfig, Gateway};
use chrono::{Duration, Utc};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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
                let mut request = vec![0_u8; 4096];
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

async fn wait_ready(port: u16) {
    for _ in 0..100 {
        if TcpListener::bind(("127.0.0.1", port)).await.is_err()
            && tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("port {port} did not become ready");
}

fn managed_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: impl std::fmt::Display,
    rule: &str,
) -> String {
    managed_acl_with_state(
        gateway_id,
        traffic_port,
        management_port,
        backend,
        rule,
        None,
    )
}

fn managed_acl_with_state(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: impl std::fmt::Display,
    rule: &str,
    state_file: Option<&std::path::Path>,
) -> String {
    let durable_state = state_file.map_or_else(String::new, |path| {
        format!("  state_file = \"{}\"\n", path.display())
    });
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
{durable_state}
}}

entrypoints "web" {{
  address = "127.0.0.1:{traffic_port}"
}}

routers "managed" {{
  rule        = "{rule}"
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
"#
    )
}

fn managed_bootstrap_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    state_file: Option<&std::path::Path>,
) -> String {
    let durable_state = state_file.map_or_else(String::new, |path| {
        format!("  state_file = \"{}\"\n", path.display())
    });
    format!(
        r#"
mode {{ kind = "cloud-managed" }}

managed {{
  gateway_id = "{gateway_id}"
{durable_state}
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
"#
    )
}

fn durable_bootstrap_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    state_file: &std::path::Path,
) -> String {
    managed_bootstrap_acl(gateway_id, traffic_port, management_port, Some(state_file))
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

async fn start_gateway(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: SocketAddr,
) -> (Arc<Gateway>, String) {
    let snapshot_acl = managed_acl(
        gateway_id,
        traffic_port,
        management_port,
        backend,
        "PathPrefix(`/`)",
    );
    let bootstrap_acl = managed_bootstrap_acl(gateway_id, traffic_port, management_port, None);
    let gateway = Arc::new(Gateway::new(GatewayConfig::from_acl(&bootstrap_acl).unwrap()).unwrap());
    gateway.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;
    (gateway, snapshot_acl)
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

#[tokio::test]
async fn managed_snapshot_apply_replay_and_exact_readiness_are_process_native() {
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("revision-1").await;
    let (gateway, acl) = start_gateway(gateway_id, traffic_port, management_port, backend).await;
    let client = reqwest::Client::new();
    let snapshot = snapshot(gateway_id, 1, None, acl.clone());

    let (status_code, applied) = apply(&client, management_port, &snapshot).await;
    assert_eq!(status_code, reqwest::StatusCode::OK);
    assert_eq!(applied.state, ManagedSnapshotState::Applied);
    assert!(applied.ready);
    assert!(!applied.replayed);
    assert_eq!(applied.applied.as_ref().unwrap().revision, 1);

    let (_, replayed) = apply(&client, management_port, &snapshot).await;
    assert_eq!(replayed.state, ManagedSnapshotState::Applied);
    assert!(replayed.ready);
    assert!(replayed.replayed);

    let exact = exact_status(&client, management_port, &snapshot).await;
    assert_eq!(exact.state, ManagedSnapshotState::Applied);
    assert!(exact.ready);

    let generic = client
        .get(format!(
            "http://127.0.0.1:{management_port}/api/gateway/snapshots/status"
        ))
        .send()
        .await
        .unwrap()
        .json::<ManagedSnapshotStatus>()
        .await
        .unwrap();
    assert_eq!(generic.state, ManagedSnapshotState::Applied);
    assert!(!generic.ready, "readiness must require an exact selector");

    let raw_reload = client
        .post(format!(
            "http://127.0.0.1:{management_port}/api/gateway/config/reload"
        ))
        .header(reqwest::header::CONTENT_TYPE, "text/plain")
        .body(acl)
        .send()
        .await
        .unwrap();
    assert_eq!(raw_reload.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(raw_reload
        .text()
        .await
        .unwrap()
        .contains("/snapshots/apply"));

    let events = client
        .get(format!(
            "http://127.0.0.1:{management_port}/api/gateway/events"
        ))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(events.contains("snapshot-applied"));
    assert!(events.contains("snapshot-replayed"));

    gateway.shutdown().await;
}

#[tokio::test]
async fn managed_snapshot_rejects_expired_stale_and_conflicting_revisions() {
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_backend("revision-1").await;
    let backend_v2 = spawn_backend("revision-2").await;
    let backend_conflict = spawn_backend("conflict").await;
    let (gateway, acl_v1) =
        start_gateway(gateway_id, traffic_port, management_port, backend_v1).await;
    let client = reqwest::Client::new();
    let revision_1 = snapshot(gateway_id, 1, None, acl_v1);
    assert_eq!(
        apply(&client, management_port, &revision_1).await.0,
        reqwest::StatusCode::OK
    );

    let acl_v2 = managed_acl(
        gateway_id,
        traffic_port,
        management_port,
        backend_v2,
        "PathPrefix(`/`)",
    );
    let mut expired = snapshot(gateway_id, 2, Some(1), acl_v2.clone());
    expired.issued_at = Utc::now() - Duration::hours(2);
    expired.expires_at = Utc::now() - Duration::hours(1);
    let (status_code, rejected) = apply(&client, management_port, &expired).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert!(!rejected.ready);
    assert!(rejected.reason.unwrap().contains("expired"));
    assert!(
        exact_status(&client, management_port, &revision_1)
            .await
            .ready
    );

    let mut excessive_validity = snapshot(gateway_id, 2, Some(1), acl_v2.clone());
    excessive_validity.expires_at = excessive_validity.issued_at + Duration::hours(25);
    let (status_code, rejected) = apply(&client, management_port, &excessive_validity).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert!(rejected.reason.unwrap().contains("24 hours"));

    let wrong_gateway_id = Uuid::new_v4();
    let wrong_gateway = snapshot(
        wrong_gateway_id,
        2,
        Some(1),
        managed_acl(
            wrong_gateway_id,
            traffic_port,
            management_port,
            backend_v2,
            "PathPrefix(`/`)",
        ),
    );
    let (status_code, rejected) = apply(&client, management_port, &wrong_gateway).await;
    assert_eq!(status_code, reqwest::StatusCode::CONFLICT);
    assert!(rejected.reason.unwrap().contains("targets Gateway"));

    let expected_mismatch = snapshot(gateway_id, 3, Some(2), acl_v2.clone());
    let (status_code, rejected) = apply(&client, management_port, &expected_mismatch).await;
    assert_eq!(status_code, reqwest::StatusCode::CONFLICT);
    assert!(rejected.reason.unwrap().contains("expected revision 2"));

    let mut digest_mismatch = snapshot(gateway_id, 2, Some(1), acl_v2.clone());
    digest_mismatch.snapshot_digest =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let (status_code, rejected) = apply(&client, management_port, &digest_mismatch).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert!(rejected.reason.unwrap().contains("exact ACL bytes"));

    let revision_2 = snapshot(gateway_id, 2, Some(1), acl_v2);
    assert_eq!(
        apply(&client, management_port, &revision_2).await.0,
        reqwest::StatusCode::OK
    );

    let (status_code, stale) = apply(&client, management_port, &revision_1).await;
    assert_eq!(status_code, reqwest::StatusCode::CONFLICT);
    assert_eq!(stale.state, ManagedSnapshotState::Rejected);
    assert!(stale.reason.unwrap().contains("stale"));

    let conflict = snapshot(
        gateway_id,
        2,
        Some(1),
        managed_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_conflict,
            "PathPrefix(`/`)",
        ),
    );
    let (status_code, rejected) = apply(&client, management_port, &conflict).await;
    assert_eq!(status_code, reqwest::StatusCode::CONFLICT);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert!(rejected.reason.unwrap().contains("conflicts"));

    let current = exact_status(&client, management_port, &revision_2).await;
    assert_eq!(current.state, ManagedSnapshotState::Applied);
    assert!(current.ready);
    let traffic = reqwest::get(format!("http://127.0.0.1:{traffic_port}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(traffic, "revision-2");

    gateway.shutdown().await;
}

#[tokio::test]
async fn failed_managed_snapshot_parse_and_bind_preserve_the_proven_runtime() {
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_backend("proven").await;
    let backend_v2 = spawn_backend("candidate").await;
    let (gateway, acl_v1) =
        start_gateway(gateway_id, traffic_port, management_port, backend_v1).await;
    let client = reqwest::Client::new();
    let revision_1 = snapshot(gateway_id, 1, None, acl_v1);
    assert_eq!(
        apply(&client, management_port, &revision_1).await.0,
        reqwest::StatusCode::OK
    );

    let invalid_rule = snapshot(
        gateway_id,
        2,
        Some(1),
        managed_acl(
            gateway_id,
            traffic_port,
            management_port,
            backend_v2,
            "NotARule()",
        ),
    );
    let (status_code, rejected) = apply(&client, management_port, &invalid_rule).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert_eq!(gateway.config().managed.gateway_id, Some(gateway_id));
    assert!(
        exact_status(&client, management_port, &revision_1)
            .await
            .ready
    );

    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let occupied_port = occupied.local_addr().unwrap().port();
    let bind_failure = snapshot(
        gateway_id,
        2,
        Some(1),
        managed_acl(
            gateway_id,
            occupied_port,
            management_port,
            backend_v2,
            "PathPrefix(`/`)",
        ),
    );
    let (status_code, rejected) = apply(&client, management_port, &bind_failure).await;
    assert_eq!(status_code, reqwest::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert!(rejected.reason.unwrap().contains("Failed to bind"));

    let traffic = reqwest::get(format!("http://127.0.0.1:{traffic_port}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(traffic, "proven");
    assert!(
        exact_status(&client, management_port, &revision_1)
            .await
            .ready
    );

    drop(occupied);
    gateway.shutdown().await;
}

#[tokio::test]
async fn durable_snapshot_recovers_across_gateway_restart_and_preserves_cas() {
    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_backend("durable-revision-1").await;
    let backend_v2 = spawn_backend("durable-revision-2").await;
    let bootstrap_acl =
        durable_bootstrap_acl(gateway_id, traffic_port, management_port, &state_file);
    let snapshot_v1 = snapshot(
        gateway_id,
        1,
        None,
        managed_acl_with_state(
            gateway_id,
            traffic_port,
            management_port,
            backend_v1,
            "PathPrefix(`/`)",
            Some(&state_file),
        ),
    );
    let client = reqwest::Client::new();

    let first = Arc::new(Gateway::new(GatewayConfig::from_acl(&bootstrap_acl).unwrap()).unwrap());
    first.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;
    let (_, applied) = apply(&client, management_port, &snapshot_v1).await;
    assert!(applied.ready);
    let applied_at = applied.applied.unwrap().applied_at;
    let journal: serde_json::Value =
        serde_json::from_slice(&tokio::fs::read(&state_file).await.unwrap()).unwrap();
    assert_eq!(journal["phase"], "applied");
    first.shutdown().await;
    drop(first);

    let restarted =
        Arc::new(Gateway::new(GatewayConfig::from_acl(&bootstrap_acl).unwrap()).unwrap());
    restarted.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;
    let restarted_client = reqwest::Client::new();

    let recovered = exact_status(&restarted_client, management_port, &snapshot_v1).await;
    assert_eq!(recovered.state, ManagedSnapshotState::Applied);
    assert!(recovered.ready, "{recovered:?}");
    assert_eq!(recovered.applied.unwrap().applied_at, applied_at);
    let (_, replayed) = apply(&restarted_client, management_port, &snapshot_v1).await;
    assert!(replayed.replayed);

    let recovered_traffic = reqwest::get(format!("http://127.0.0.1:{traffic_port}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(recovered_traffic, "durable-revision-1");

    let snapshot_v2 = snapshot(
        gateway_id,
        2,
        Some(1),
        managed_acl_with_state(
            gateway_id,
            traffic_port,
            management_port,
            backend_v2,
            "PathPrefix(`/`)",
            Some(&state_file),
        ),
    );
    let (_, applied_v2) = apply(&restarted_client, management_port, &snapshot_v2).await;
    assert_eq!(applied_v2.state, ManagedSnapshotState::Applied);
    assert!(applied_v2.ready);
    let traffic_v2 = reqwest::get(format!("http://127.0.0.1:{traffic_port}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(traffic_v2, "durable-revision-2");

    restarted.shutdown().await;
}

#[tokio::test]
async fn durable_prepare_failure_keeps_the_proven_runtime_ready() {
    let directory = tempfile::tempdir().unwrap();
    let state_directory = directory.path().join("state");
    let backup_directory = directory.path().join("state-backup");
    let state_file = state_directory.join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_backend("proven-durable").await;
    let backend_v2 = spawn_backend("must-not-activate").await;
    let bootstrap_acl =
        durable_bootstrap_acl(gateway_id, traffic_port, management_port, &state_file);
    let gateway = Arc::new(Gateway::new(GatewayConfig::from_acl(&bootstrap_acl).unwrap()).unwrap());
    gateway.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;
    let client = reqwest::Client::new();
    let snapshot_v1 = snapshot(
        gateway_id,
        1,
        None,
        managed_acl_with_state(
            gateway_id,
            traffic_port,
            management_port,
            backend_v1,
            "PathPrefix(`/`)",
            Some(&state_file),
        ),
    );
    assert_eq!(
        apply(&client, management_port, &snapshot_v1).await.0,
        reqwest::StatusCode::OK
    );

    tokio::fs::rename(&state_directory, &backup_directory)
        .await
        .unwrap();
    tokio::fs::write(&state_directory, b"not-a-directory")
        .await
        .unwrap();
    let snapshot_v2 = snapshot(
        gateway_id,
        2,
        Some(1),
        managed_acl_with_state(
            gateway_id,
            traffic_port,
            management_port,
            backend_v2,
            "PathPrefix(`/`)",
            Some(&state_file),
        ),
    );
    let (status_code, rejected) = apply(&client, management_port, &snapshot_v2).await;
    assert_eq!(status_code, reqwest::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.state, ManagedSnapshotState::Rejected);
    assert!(rejected.reason.unwrap().contains("journal"));
    assert!(
        exact_status(&client, management_port, &snapshot_v1)
            .await
            .ready
    );
    let traffic = reqwest::get(format!("http://127.0.0.1:{traffic_port}/"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(traffic, "proven-durable");

    tokio::fs::remove_file(&state_directory).await.unwrap();
    tokio::fs::rename(&backup_directory, &state_directory)
        .await
        .unwrap();
    gateway.shutdown().await;
}
