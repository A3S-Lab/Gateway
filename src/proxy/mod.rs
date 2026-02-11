//! Proxy layer — actual request forwarding to backends
//!
//! Handles HTTP, WebSocket, and SSE/streaming proxying.

mod http_proxy;

pub use http_proxy::HttpProxy;
