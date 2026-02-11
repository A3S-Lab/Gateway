//! Observability — metrics, access logging, and tracing
//!
//! Provides structured access logging, Prometheus-compatible metrics,
//! and OpenTelemetry tracing integration.

pub mod access_log;
pub mod metrics;

pub use access_log::{AccessLog, AccessLogEntry};
pub use metrics::{GatewayMetrics, MetricsSnapshot};
