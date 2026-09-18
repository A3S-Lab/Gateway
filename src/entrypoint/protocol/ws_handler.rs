//! WebSocket protocol handler

use crate::entrypoint::protocol::{ResponseBody, WsContext};
use crate::observability::access_log::AccessLogGuard;
use crate::proxy::websocket;
use hyper::Response;
use std::future::Future;
use std::pin::Pin;

pub fn handle_ws_upgrade(
    upgrade: hyper::upgrade::OnUpgrade,
    ctx: WsContext,
    handshake: websocket::ValidatedWebSocketHandshake,
    prepared: websocket::PreparedWebSocket,
) -> (
    Response<ResponseBody>,
    Pin<Box<dyn Future<Output = ()> + Send>>,
) {
    let accept = handshake.accept_header().clone();
    let selected_protocol = prepared.selected_protocol.clone();
    let ws_upstream = prepared.stream;
    let remote_addr = ctx.remote_addr;
    let route = ctx.route.clone();
    let state = ctx.state.clone();
    let sticky_new_session = ctx.sticky_new_session;
    let request_start = ctx.request_start;
    let access_log = AccessLogGuard::new(ctx.access_log, 101);
    let service_request = ctx.service_request;
    let backend_connection = ctx.backend_connection;
    // Hyper's connection future ends after the upgrade, so the relay owns a
    // separate guard for the upgraded downstream socket lifetime.
    let downstream_connection = state.metrics.track_connection();

    let relay_future = Box::pin(async move {
        let _downstream_connection = downstream_connection;
        let _backend_connection = backend_connection;
        let _service_request = service_request;
        match upgrade.await {
            Ok(upgraded) => {
                let ws_client = tokio_tungstenite::WebSocketStream::from_raw_socket(
                    hyper_util::rt::TokioIo::new(upgraded),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;
                websocket::relay_websocket(ws_client, ws_upstream).await;
            }
            Err(e) => tracing::error!(error = %e, "WebSocket connection upgrade failed"),
        }
        access_log.finish();
    });

    tracing::debug!(remote = %remote_addr, "WebSocket upgrade dispatched");
    if state.metrics_enabled {
        state.metrics.record_request(101, 0);
        state.metrics.record_router_latency(
            &route.router_name,
            request_start.elapsed().as_micros() as u64,
        );
    }

    let mut resp = Response::new(crate::entrypoint::protocol::empty_body());
    *resp.status_mut() = http::StatusCode::SWITCHING_PROTOCOLS;
    resp.headers_mut().insert(
        http::header::UPGRADE,
        http::HeaderValue::from_static("websocket"),
    );
    resp.headers_mut().insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("Upgrade"),
    );
    resp.headers_mut()
        .insert(http::header::SEC_WEBSOCKET_ACCEPT, accept);
    if let Some(protocol) = selected_protocol {
        resp.headers_mut()
            .insert(http::header::SEC_WEBSOCKET_PROTOCOL, protocol);
    }
    if let (Some(new_id), Some(sticky_mgr)) = (
        sticky_new_session.as_ref(),
        state.sticky_managers.get(&route.service_name),
    ) {
        // Cookie validity was checked before upgrade so Set-Cookie cannot soft-skip.
        let cookie = http::HeaderValue::from_str(&sticky_mgr.build_cookie(new_id))
            .expect("sticky cookie validated before WebSocket upgrade");
        resp.headers_mut().append(http::header::SET_COOKIE, cookie);
    }

    (resp, relay_future)
}
