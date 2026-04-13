//! WebSocket protocol handler

use crate::entrypoint::protocol::{ResponseBody, WsContext};
use crate::proxy::websocket;
use hyper::body::Incoming;
use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;

pub fn handle_ws_upgrade(
    req: Request<Incoming>,
    ctx: WsContext,
) -> (
    Response<ResponseBody>,
    Pin<Box<dyn Future<Output = ()> + Send>>,
) {
    let backend = ctx.backend.clone();
    let ws_url = {
        let uri = req.uri();
        let ws_key = req
            .headers()
            .get("Sec-WebSocket-Key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let accept = websocket::compute_accept_key(&ws_key);
        let ws_url = websocket::build_ws_url(&backend.url, uri);
        (accept, ws_url)
    };

    let (accept, ws_url) = ws_url;
    let remote_addr = ctx.remote_addr;
    let route = ctx.route.clone();
    let state = ctx.state.clone();
    let request_start = ctx.request_start;

    let upgrade = hyper::upgrade::on(req);
    backend.inc_connections();

    let relay_future = Box::pin(async move {
        match upgrade.await {
            Ok(upgraded) => {
                let ws_client = tokio_tungstenite::WebSocketStream::from_raw_socket(
                    hyper_util::rt::TokioIo::new(upgraded),
                    tokio_tungstenite::tungstenite::protocol::Role::Server,
                    None,
                )
                .await;

                match websocket::connect_upstream(&ws_url).await {
                    Ok(ws_upstream) => websocket::relay_websocket(ws_client, ws_upstream).await,
                    Err(e) => {
                        tracing::error!(error = %e, backend = backend.url, "WebSocket upstream connection failed")
                    }
                }
            }
            Err(e) => tracing::error!(error = %e, "WebSocket connection upgrade failed"),
        }
        backend.dec_connections();
    });

    tracing::debug!(remote = %remote_addr, "WebSocket upgrade dispatched");
    state.metrics.record_request(101, 0);
    state.metrics.record_router_latency(
        &route.router_name,
        request_start.elapsed().as_micros() as u64,
    );

    let resp = Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept)
        .body(crate::entrypoint::protocol::empty_body())
        .unwrap();

    (resp, relay_future)
}
