use super::{error_response, json_http_response, NodeApiState, ResponseBody};
use crate::managed_snapshot::{ManagedSnapshot, ManagedSnapshotIdentity, ManagedSnapshotState};
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response};
use std::net::SocketAddr;

const MAX_MANAGED_SNAPSHOT_BODY_BYTES: usize = 6 * 1024 * 1024 + 64 * 1024;

pub(super) async fn handle_apply(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    state: &NodeApiState,
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
            tracing::warn!(
                %remote_addr,
                path = "/snapshots/apply",
                status = 413,
                %reason,
                "Managed snapshot rejected"
            );
            return error_response(413, reason);
        }
    };
    let snapshot = match serde_json::from_slice::<ManagedSnapshot>(&body) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            let reason = format!("Invalid managed snapshot JSON: {error}");
            tracing::warn!(
                %remote_addr,
                path = "/snapshots/apply",
                status = 400,
                %reason,
                "Managed snapshot rejected"
            );
            return error_response(400, reason);
        }
    };

    let result = state
        .managed_snapshots
        .apply(snapshot, state.reload_managed_snapshot.as_ref())
        .await;
    let reason = result
        .status
        .reason
        .as_deref()
        .unwrap_or(if result.status.replayed {
            "Managed snapshot replay confirmed"
        } else {
            "Managed snapshot applied"
        });
    if result.status.state == ManagedSnapshotState::Applied {
        tracing::info!(
            %remote_addr,
            path = "/snapshots/apply",
            status = result.status_code,
            replayed = result.status.replayed,
            reason,
            "Managed snapshot accepted"
        );
    } else {
        tracing::warn!(
            %remote_addr,
            path = "/snapshots/apply",
            status = result.status_code,
            reason,
            "Managed snapshot rejected"
        );
    }
    json_http_response(result.status_code, &result.status)
}

pub(super) fn handle_status(
    query: Option<&str>,
    remote_addr: SocketAddr,
    state: &NodeApiState,
) -> Response<ResponseBody> {
    let requested = match ManagedSnapshotIdentity::from_query(query) {
        Ok(requested) => requested,
        Err(reason) => {
            tracing::warn!(
                %remote_addr,
                path = "/snapshots/status",
                status = 400,
                %reason,
                "Managed snapshot status query rejected"
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
