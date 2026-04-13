//! Protocol handlers for HTTP request dispatch

pub use grpc_handler::handle_grpc_dispatch;
pub use http_handler::handle_http_dispatch;
pub use streaming_handler::handle_sse_dispatch;
pub use ws_handler::handle_ws_upgrade;

use crate::entrypoint::GatewayState;
use crate::middleware::Pipeline;
use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt};
use std::net::SocketAddr;
use std::sync::Arc;

pub type ResponseBody = UnsyncBoxBody<Bytes, std::io::Error>;

pub fn full_body(bytes: impl Into<Bytes>) -> ResponseBody {
    http_body_util::Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub fn empty_body() -> ResponseBody {
    http_body_util::Empty::new()
        .map_err(|never| match never {})
        .boxed_unsync()
}

pub struct ProtocolContext {
    pub route: crate::router::ResolvedRoute,
    pub backend: Arc<crate::service::Backend>,
    pub req_parts: http::request::Parts,
    pub body_bytes: Bytes,
    pub pipeline: Arc<Pipeline>,
    pub state: Arc<GatewayState>,
    pub remote_addr: SocketAddr,
    pub entrypoint: String,
    pub trace_ctx: crate::observability::tracing::TraceContext,
    pub access_tracker: crate::observability::access_log::RequestTracker,
    pub method_str: String,
    pub path: String,
    pub host: Option<String>,
    pub sticky_new_session: Option<String>,
    pub request_start: std::time::Instant,
}

pub struct WsContext {
    pub route: crate::router::ResolvedRoute,
    pub backend: Arc<crate::service::Backend>,
    pub pipeline: Arc<Pipeline>,
    pub state: Arc<GatewayState>,
    pub remote_addr: SocketAddr,
    pub request_start: std::time::Instant,
}

mod grpc_handler;
mod http_handler;
mod streaming_handler;
mod ws_handler;
