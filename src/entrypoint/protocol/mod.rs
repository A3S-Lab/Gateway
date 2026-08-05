//! Protocol handlers for HTTP request dispatch

pub use grpc_handler::handle_grpc_dispatch;
pub use http_handler::handle_http_dispatch;
pub(super) use http_handler::proxy_error_status;
pub use streaming_handler::handle_sse_dispatch;
pub use ws_handler::handle_ws_upgrade;

use crate::entrypoint::GatewayState;
use crate::middleware::Pipeline;
use crate::observability::access_log::RequestAccessLog;
pub(crate) use crate::response_body::ResponseBody;
use bytes::Bytes;
use std::sync::Arc;

pub fn full_body(bytes: impl Into<Bytes>) -> ResponseBody {
    ResponseBody::full(bytes)
}

pub fn empty_body() -> ResponseBody {
    ResponseBody::full(Bytes::new())
}

pub struct ProtocolContext {
    pub route: Arc<crate::router::ResolvedRoute>,
    pub backend: Arc<crate::service::Backend>,
    pub req_parts: http::request::Parts,
    pub body_bytes: Bytes,
    pub streaming_body: Option<hyper::body::Incoming>,
    pub pipeline: Arc<Pipeline>,
    pub state: Arc<GatewayState>,
    pub forwarded: crate::proxy::ForwardedContext,
    pub prepared_forwarded: Option<Arc<crate::proxy::PreparedForwardedContext>>,
    pub timeouts: crate::service::ServiceTimeouts,
    pub access_log: Option<RequestAccessLog>,
    pub sticky_new_session: Option<String>,
    pub request_start: std::time::Instant,
    pub inference_admission: Option<crate::inference::InferenceAdmissionGuard>,
    pub inference_attempt: Option<crate::inference::InferenceAttemptIdentity>,
    pub usage_lifecycle: Option<crate::usage::UsageRequestLifecycle>,
    pub(super) inference_dispatch:
        Option<crate::entrypoint::inference_dispatch::InferenceDispatchState>,
    pub service_request: Option<crate::observability::metrics::ServiceRequestGuard>,
}

pub struct WsContext {
    pub route: Arc<crate::router::ResolvedRoute>,
    pub state: Arc<GatewayState>,
    pub remote_addr: std::net::SocketAddr,
    pub access_log: Option<RequestAccessLog>,
    pub request_start: std::time::Instant,
    pub service_request: Option<crate::observability::metrics::ServiceRequestGuard>,
    pub backend_connection: crate::service::BackendConnectionGuard,
}

mod body_buffer;
mod grpc_handler;
mod http_handler;
mod streaming_handler;
mod ws_handler;
