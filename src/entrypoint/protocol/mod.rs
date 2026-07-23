//! Protocol handlers for HTTP request dispatch

pub use grpc_handler::handle_grpc_dispatch;
pub use http_handler::handle_http_dispatch;
pub use streaming_handler::handle_sse_dispatch;
pub use ws_handler::handle_ws_upgrade;

use crate::entrypoint::GatewayState;
use crate::middleware::Pipeline;
use crate::observability::access_log::RequestAccessLog;
use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt};
use std::sync::Arc;
use std::time::Duration;

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
    pub streaming_body: Option<hyper::body::Incoming>,
    pub pipeline: Arc<Pipeline>,
    pub state: Arc<GatewayState>,
    pub forwarded: crate::proxy::ForwardedContext,
    pub request_timeout: Duration,
    pub access_log: Option<RequestAccessLog>,
    pub sticky_new_session: Option<String>,
    pub request_start: std::time::Instant,
    pub inference_admission: Option<crate::inference::InferenceAdmissionGuard>,
    pub inference_attempt: Option<crate::inference::InferenceAttemptIdentity>,
    pub(super) inference_dispatch:
        Option<crate::entrypoint::inference_dispatch::InferenceDispatchState>,
}

pub struct WsContext {
    pub route: crate::router::ResolvedRoute,
    pub backend: Arc<crate::service::Backend>,
    pub state: Arc<GatewayState>,
    pub remote_addr: std::net::SocketAddr,
    pub access_log: Option<RequestAccessLog>,
    pub request_start: std::time::Instant,
}

mod grpc_handler;
mod http_handler;
mod streaming_handler;
mod ws_handler;
