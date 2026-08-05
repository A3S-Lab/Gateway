//! Proxy layer — request forwarding to backends
//!
//! Handles HTTP, WebSocket, SSE/streaming, gRPC, TCP, and UDP proxying.

pub mod acme;
pub(crate) mod acme_account;
pub mod acme_client;
pub(crate) mod acme_csr;
pub mod acme_dns;
pub mod acme_manager;
pub(crate) mod acme_types;
pub mod grpc;
pub mod http_proxy;
mod http_response_body;
pub mod streaming;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod websocket;

pub(crate) use http_proxy::{
    BackendOperationTracking, OwnedBufferedRequest, OwnedStreamingRequest, PreparedForwardedContext,
};
pub use http_proxy::{ForwardOptions, ForwardedContext, ForwardedProto, HttpProxy, HttpTimeouts};
