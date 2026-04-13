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
pub mod streaming;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod websocket;
pub mod ws_mux;

pub use http_proxy::HttpProxy;
