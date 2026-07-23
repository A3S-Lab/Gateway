use super::{
    error_response, json_http_response, DashboardState, ManagementAuditEventKind, ResponseBody,
    MAX_CONFIG_BODY_BYTES,
};
use crate::managed_snapshot::{ManagedSnapshot, ManagedSnapshotIdentity, ManagedSnapshotState};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response};
use std::net::SocketAddr;

const MAX_MANAGED_SNAPSHOT_BODY_BYTES: usize = MAX_CONFIG_BODY_BYTES * 6 + 64 * 1024;

pub(super) async fn handle_apply(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    state: &DashboardState,
) -> Response<ResponseBody> {
    let body = match Limited::new(req.into_body(), MAX_MANAGED_SNAPSHOT_BODY_BYTES)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            let reason = format!(
                "Managed snapshot request exceeds {} bytes or could not be read",
                MAX_MANAGED_SNAPSHOT_BODY_BYTES
            );
            state.audit_log.record_event(
                ManagementAuditEventKind::SnapshotRejected,
                Some(remote_addr),
                Some("/snapshots/apply".to_string()),
                Some(413),
                &reason,
            );
            return error_response(413, reason);
        }
    };
    let snapshot = match serde_json::from_slice::<ManagedSnapshot>(&body) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let reason = format!("Invalid managed snapshot JSON: {error}");
            state.audit_log.record_event(
                ManagementAuditEventKind::SnapshotRejected,
                Some(remote_addr),
                Some("/snapshots/apply".to_string()),
                Some(400),
                &reason,
            );
            return error_response(400, reason);
        }
    };

    let result = state
        .managed_snapshots
        .apply(snapshot, state.reload_managed_snapshot.as_ref())
        .await;
    let kind = if result.status.state == ManagedSnapshotState::Applied {
        if result.status.replayed {
            ManagementAuditEventKind::SnapshotReplayed
        } else {
            ManagementAuditEventKind::SnapshotApplied
        }
    } else {
        ManagementAuditEventKind::SnapshotRejected
    };
    let reason = result
        .status
        .reason
        .as_deref()
        .unwrap_or(if result.status.replayed {
            "Managed snapshot replay confirmed"
        } else {
            "Managed snapshot applied"
        });
    state.audit_log.record_event(
        kind,
        Some(remote_addr),
        Some("/snapshots/apply".to_string()),
        Some(result.status_code),
        reason,
    );
    json_http_response(result.status_code, &result.status)
}

pub(super) fn handle_status(
    query: Option<&str>,
    remote_addr: SocketAddr,
    state: &DashboardState,
) -> Response<ResponseBody> {
    let requested = match ManagedSnapshotIdentity::from_query(query) {
        Ok(requested) => requested,
        Err(reason) => {
            state.audit_log.record_event(
                ManagementAuditEventKind::SnapshotRejected,
                Some(remote_addr),
                Some("/snapshots/status".to_string()),
                Some(400),
                &reason,
            );
            return error_response(400, reason);
        }
    };
    let mut status = state
        .managed_snapshots
        .status(requested, chrono::Utc::now());
    if *state.lifecycle_state.read().unwrap() != crate::GatewayState::Running {
        if status.ready {
            status.reason = Some("Gateway lifecycle is not running".to_string());
        }
        status.ready = false;
    }
    json_http_response(200, &status)
}
