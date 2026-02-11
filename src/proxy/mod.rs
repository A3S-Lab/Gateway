//! Proxy layer — request forwarding to backends
//!
//! Handles HTTP, WebSocket, SSE/streaming, and TCP proxying.

pub mod http_proxy;
pub mod streaming;
pub mod tcp;
pub mod tls;
pub mod websocket;

pub use http_proxy::HttpProxy;
