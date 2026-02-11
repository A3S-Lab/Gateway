//! OpenTelemetry tracing — distributed trace context propagation
//!
//! Provides trace context extraction, injection, and span management
//! for distributed tracing across gateway hops. Supports W3C Trace Context
//! and B3 propagation formats.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

/// W3C Trace Context header name
const TRACEPARENT_HEADER: &str = "traceparent";
/// W3C Trace State header name
const TRACESTATE_HEADER: &str = "tracestate";
/// B3 single header
const B3_HEADER: &str = "b3";
/// B3 trace ID header
const B3_TRACE_ID_HEADER: &str = "x-b3-traceid";
/// B3 span ID header
const B3_SPAN_ID_HEADER: &str = "x-b3-spanid";
/// B3 sampled header
const B3_SAMPLED_HEADER: &str = "x-b3-sampled";

/// Trace context — carries distributed trace information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// Trace ID (128-bit hex string)
    pub trace_id: String,
    /// Parent span ID (64-bit hex string)
    pub parent_span_id: String,
    /// Current span ID (64-bit hex string)
    pub span_id: String,
    /// Trace flags (sampled, etc.)
    pub trace_flags: u8,
    /// Optional trace state (vendor-specific key-value pairs)
    pub trace_state: Option<String>,
}

impl TraceContext {
    /// Create a new root trace context with random IDs
    pub fn new_root() -> Self {
        Self {
            trace_id: generate_trace_id(),
            parent_span_id: String::new(),
            span_id: generate_span_id(),
            trace_flags: 1, // sampled by default
            trace_state: None,
        }
    }

    /// Create a child span from this context
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            parent_span_id: self.span_id.clone(),
            span_id: generate_span_id(),
            trace_flags: self.trace_flags,
            trace_state: self.trace_state.clone(),
        }
    }

    /// Check if this trace is sampled
    pub fn is_sampled(&self) -> bool {
        self.trace_flags & 0x01 != 0
    }

    /// Format as W3C traceparent header value
    /// Format: version-trace_id-parent_id-flags
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.trace_flags
        )
    }

    /// Parse from W3C traceparent header value
    pub fn from_traceparent(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.trim().split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        let version = parts[0];
        if version != "00" {
            return None;
        }

        let trace_id = parts[1];
        let parent_span_id = parts[2];
        let flags_str = parts[3];

        // Validate lengths
        if trace_id.len() != 32 || parent_span_id.len() != 16 || flags_str.len() != 2 {
            return None;
        }

        // Validate hex
        if !is_hex(trace_id) || !is_hex(parent_span_id) || !is_hex(flags_str) {
            return None;
        }

        let trace_flags = u8::from_str_radix(flags_str, 16).ok()?;

        Some(Self {
            trace_id: trace_id.to_string(),
            parent_span_id: parent_span_id.to_string(),
            span_id: generate_span_id(),
            trace_flags,
            trace_state: None,
        })
    }

    /// Format as B3 single header value
    /// Format: {trace_id}-{span_id}-{sampled}-{parent_span_id}
    pub fn to_b3_single(&self) -> String {
        let sampled = if self.is_sampled() { "1" } else { "0" };
        if self.parent_span_id.is_empty() {
            format!("{}-{}-{}", self.trace_id, self.span_id, sampled)
        } else {
            format!(
                "{}-{}-{}-{}",
                self.trace_id, self.span_id, sampled, self.parent_span_id
            )
        }
    }

    /// Parse from B3 single header value
    pub fn from_b3_single(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.trim().split('-').collect();
        if parts.len() < 3 {
            return None;
        }

        let trace_id = parts[0];
        let span_id = parts[1];
        let sampled = parts[2];

        if !is_hex(trace_id) || !is_hex(span_id) {
            return None;
        }

        let trace_flags = if sampled == "1" || sampled == "true" {
            1
        } else {
            0
        };

        let parent_span_id = if parts.len() >= 4 {
            parts[3].to_string()
        } else {
            String::new()
        };

        Some(Self {
            trace_id: trace_id.to_string(),
            parent_span_id,
            span_id: generate_span_id(),
            trace_flags,
            trace_state: None,
        })
    }
}

impl fmt::Display for TraceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trace_id={} span_id={} sampled={}",
            self.trace_id,
            self.span_id,
            self.is_sampled()
        )
    }
}

/// Propagation format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationFormat {
    /// W3C Trace Context (traceparent/tracestate)
    W3C,
    /// Zipkin B3 (single or multi-header)
    B3,
}

/// Extract trace context from request headers
pub fn extract_trace_context(headers: &HashMap<String, String>) -> Option<TraceContext> {
    // Try W3C traceparent first
    if let Some(traceparent) = headers.get(TRACEPARENT_HEADER) {
        if let Some(mut ctx) = TraceContext::from_traceparent(traceparent) {
            ctx.trace_state = headers.get(TRACESTATE_HEADER).cloned();
            return Some(ctx);
        }
    }

    // Try B3 single header
    if let Some(b3) = headers.get(B3_HEADER) {
        return TraceContext::from_b3_single(b3);
    }

    // Try B3 multi-header
    if let Some(trace_id) = headers.get(B3_TRACE_ID_HEADER) {
        if let Some(span_id) = headers.get(B3_SPAN_ID_HEADER) {
            let sampled = headers
                .get(B3_SAMPLED_HEADER)
                .map(|s| s == "1" || s == "true")
                .unwrap_or(true);

            return Some(TraceContext {
                trace_id: trace_id.clone(),
                parent_span_id: span_id.clone(),
                span_id: generate_span_id(),
                trace_flags: if sampled { 1 } else { 0 },
                trace_state: None,
            });
        }
    }

    None
}

/// Inject trace context into request headers
pub fn inject_trace_context(
    ctx: &TraceContext,
    headers: &mut HashMap<String, String>,
    format: PropagationFormat,
) {
    match format {
        PropagationFormat::W3C => {
            headers.insert(TRACEPARENT_HEADER.to_string(), ctx.to_traceparent());
            if let Some(ref state) = ctx.trace_state {
                headers.insert(TRACESTATE_HEADER.to_string(), state.clone());
            }
        }
        PropagationFormat::B3 => {
            headers.insert(B3_HEADER.to_string(), ctx.to_b3_single());
        }
    }
}

/// A gateway span — tracks timing for a single operation
#[derive(Debug, Clone)]
pub struct GatewaySpan {
    /// Span name (e.g., "gateway.proxy", "gateway.middleware.auth")
    pub name: String,
    /// Trace context
    pub trace_context: TraceContext,
    /// Start time
    pub start: Instant,
    /// End time (set when span is finished)
    pub end: Option<Instant>,
    /// Span attributes
    pub attributes: HashMap<String, String>,
    /// Span status
    pub status: SpanStatus,
}

impl GatewaySpan {
    /// Create a new span
    pub fn new(name: impl Into<String>, trace_context: TraceContext) -> Self {
        Self {
            name: name.into(),
            trace_context,
            start: Instant::now(),
            end: None,
            attributes: HashMap::new(),
            status: SpanStatus::Unset,
        }
    }

    /// Set an attribute
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Finish the span
    pub fn finish(&mut self) {
        self.end = Some(Instant::now());
    }

    /// Finish with error status
    pub fn finish_with_error(&mut self, message: impl Into<String>) {
        self.status = SpanStatus::Error(message.into());
        self.end = Some(Instant::now());
    }

    /// Get the duration (if finished)
    pub fn duration(&self) -> Option<std::time::Duration> {
        self.end.map(|end| end.duration_since(self.start))
    }

    /// Check if the span is finished
    pub fn is_finished(&self) -> bool {
        self.end.is_some()
    }
}

/// Span status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpanStatus {
    /// Status not set
    Unset,
    /// Operation completed successfully
    Ok,
    /// Operation failed
    Error(String),
}

impl fmt::Display for SpanStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unset => write!(f, "UNSET"),
            Self::Ok => write!(f, "OK"),
            Self::Error(msg) => write!(f, "ERROR: {}", msg),
        }
    }
}

/// Tracing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// OTLP endpoint for exporting traces
    #[serde(default)]
    pub otlp_endpoint: Option<String>,
    /// Propagation format
    #[serde(default = "default_propagation")]
    pub propagation: String,
    /// Sampling rate (0.0 to 1.0)
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    /// Service name for traces
    #[serde(default = "default_service_name")]
    pub service_name: String,
}

fn default_propagation() -> String {
    "w3c".to_string()
}

fn default_sample_rate() -> f64 {
    1.0
}

fn default_service_name() -> String {
    "a3s-gateway".to_string()
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            otlp_endpoint: None,
            propagation: default_propagation(),
            sample_rate: default_sample_rate(),
            service_name: default_service_name(),
        }
    }
}

impl TracingConfig {
    /// Get the propagation format
    pub fn propagation_format(&self) -> PropagationFormat {
        match self.propagation.to_lowercase().as_str() {
            "b3" | "zipkin" => PropagationFormat::B3,
            _ => PropagationFormat::W3C,
        }
    }

    /// Check if tracing export is enabled
    pub fn is_export_enabled(&self) -> bool {
        self.otlp_endpoint.is_some()
    }
}

/// Generate a random 128-bit trace ID (32 hex chars)
fn generate_trace_id() -> String {
    format!("{:032x}", uuid::Uuid::new_v4().as_u128())
}

/// Generate a random 64-bit span ID (16 hex chars)
fn generate_span_id() -> String {
    let bytes: [u8; 8] = rand_bytes();
    hex_encode(&bytes)
}

/// Generate random bytes using a simple approach
fn rand_bytes() -> [u8; 8] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seed = now.as_nanos() as u64;
    seed.to_le_bytes()
}

/// Encode bytes as hex string
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Check if a string is valid hexadecimal
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- TraceContext ---

    #[test]
    fn test_new_root() {
        let ctx = TraceContext::new_root();
        assert_eq!(ctx.trace_id.len(), 32);
        assert_eq!(ctx.span_id.len(), 16);
        assert!(ctx.parent_span_id.is_empty());
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_child_span() {
        let root = TraceContext::new_root();
        let child = root.child();
        assert_eq!(child.trace_id, root.trace_id);
        assert_eq!(child.parent_span_id, root.span_id);
        assert_ne!(child.span_id, root.span_id);
        assert_eq!(child.trace_flags, root.trace_flags);
    }

    #[test]
    fn test_is_sampled() {
        let mut ctx = TraceContext::new_root();
        assert!(ctx.is_sampled());
        ctx.trace_flags = 0;
        assert!(!ctx.is_sampled());
    }

    // --- W3C traceparent ---

    #[test]
    fn test_to_traceparent() {
        let ctx = TraceContext {
            trace_id: "0af7651916cd43dd8448eb211c80319c".to_string(),
            parent_span_id: "00f067aa0ba902b7".to_string(),
            span_id: "b7ad6b7169203331".to_string(),
            trace_flags: 1,
            trace_state: None,
        };
        let tp = ctx.to_traceparent();
        assert!(tp.starts_with("00-0af7651916cd43dd8448eb211c80319c-"));
        assert!(tp.ends_with("-01"));
    }

    #[test]
    fn test_from_traceparent_valid() {
        let tp = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01";
        let ctx = TraceContext::from_traceparent(tp).unwrap();
        assert_eq!(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(ctx.parent_span_id, "00f067aa0ba902b7");
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_from_traceparent_not_sampled() {
        let tp = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-00";
        let ctx = TraceContext::from_traceparent(tp).unwrap();
        assert!(!ctx.is_sampled());
    }

    #[test]
    fn test_from_traceparent_invalid_version() {
        let tp = "01-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01";
        assert!(TraceContext::from_traceparent(tp).is_none());
    }

    #[test]
    fn test_from_traceparent_invalid_format() {
        assert!(TraceContext::from_traceparent("invalid").is_none());
        assert!(TraceContext::from_traceparent("00-short-id-01").is_none());
        assert!(TraceContext::from_traceparent("").is_none());
    }

    #[test]
    fn test_from_traceparent_invalid_hex() {
        let tp = "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-00f067aa0ba902b7-01";
        assert!(TraceContext::from_traceparent(tp).is_none());
    }

    // --- B3 format ---

    #[test]
    fn test_to_b3_single_with_parent() {
        let ctx = TraceContext {
            trace_id: "463ac35c9f6413ad48485a3953bb6124".to_string(),
            parent_span_id: "0020000000000001".to_string(),
            span_id: "b7ad6b7169203331".to_string(),
            trace_flags: 1,
            trace_state: None,
        };
        let b3 = ctx.to_b3_single();
        assert!(b3.contains("463ac35c9f6413ad48485a3953bb6124"));
        assert!(b3.contains("-1-"));
    }

    #[test]
    fn test_to_b3_single_no_parent() {
        let ctx = TraceContext {
            trace_id: "463ac35c9f6413ad48485a3953bb6124".to_string(),
            parent_span_id: String::new(),
            span_id: "b7ad6b7169203331".to_string(),
            trace_flags: 0,
            trace_state: None,
        };
        let b3 = ctx.to_b3_single();
        assert!(b3.contains("-0"));
        // Should not have 4th segment
        assert_eq!(b3.split('-').count(), 3);
    }

    #[test]
    fn test_from_b3_single_sampled() {
        let b3 = "463ac35c9f6413ad48485a3953bb6124-0020000000000001-1";
        let ctx = TraceContext::from_b3_single(b3).unwrap();
        assert_eq!(ctx.trace_id, "463ac35c9f6413ad48485a3953bb6124");
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_from_b3_single_with_parent() {
        let b3 = "463ac35c9f6413ad48485a3953bb6124-0020000000000001-1-00f067aa0ba902b7";
        let ctx = TraceContext::from_b3_single(b3).unwrap();
        assert_eq!(ctx.parent_span_id, "00f067aa0ba902b7");
    }

    #[test]
    fn test_from_b3_single_invalid() {
        assert!(TraceContext::from_b3_single("invalid").is_none());
        assert!(TraceContext::from_b3_single("a-b").is_none());
    }

    // --- Extract/Inject ---

    #[test]
    fn test_extract_w3c() {
        let mut headers = HashMap::new();
        headers.insert(
            "traceparent".to_string(),
            "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01".to_string(),
        );
        headers.insert("tracestate".to_string(), "vendor=value".to_string());

        let ctx = extract_trace_context(&headers).unwrap();
        assert_eq!(ctx.trace_id, "0af7651916cd43dd8448eb211c80319c");
        assert_eq!(ctx.trace_state.as_deref(), Some("vendor=value"));
    }

    #[test]
    fn test_extract_b3_single() {
        let mut headers = HashMap::new();
        headers.insert(
            "b3".to_string(),
            "463ac35c9f6413ad48485a3953bb6124-0020000000000001-1".to_string(),
        );

        let ctx = extract_trace_context(&headers).unwrap();
        assert_eq!(ctx.trace_id, "463ac35c9f6413ad48485a3953bb6124");
    }

    #[test]
    fn test_extract_b3_multi() {
        let mut headers = HashMap::new();
        headers.insert(
            "x-b3-traceid".to_string(),
            "463ac35c9f6413ad48485a3953bb6124".to_string(),
        );
        headers.insert(
            "x-b3-spanid".to_string(),
            "0020000000000001".to_string(),
        );
        headers.insert("x-b3-sampled".to_string(), "1".to_string());

        let ctx = extract_trace_context(&headers).unwrap();
        assert_eq!(ctx.trace_id, "463ac35c9f6413ad48485a3953bb6124");
        assert!(ctx.is_sampled());
    }

    #[test]
    fn test_extract_no_trace() {
        let headers = HashMap::new();
        assert!(extract_trace_context(&headers).is_none());
    }

    #[test]
    fn test_inject_w3c() {
        let ctx = TraceContext {
            trace_id: "0af7651916cd43dd8448eb211c80319c".to_string(),
            parent_span_id: String::new(),
            span_id: "00f067aa0ba902b7".to_string(),
            trace_flags: 1,
            trace_state: Some("vendor=value".to_string()),
        };
        let mut headers = HashMap::new();
        inject_trace_context(&ctx, &mut headers, PropagationFormat::W3C);

        assert!(headers.contains_key("traceparent"));
        assert_eq!(headers.get("tracestate").unwrap(), "vendor=value");
    }

    #[test]
    fn test_inject_b3() {
        let ctx = TraceContext {
            trace_id: "463ac35c9f6413ad48485a3953bb6124".to_string(),
            parent_span_id: String::new(),
            span_id: "0020000000000001".to_string(),
            trace_flags: 1,
            trace_state: None,
        };
        let mut headers = HashMap::new();
        inject_trace_context(&ctx, &mut headers, PropagationFormat::B3);

        assert!(headers.contains_key("b3"));
    }

    // --- GatewaySpan ---

    #[test]
    fn test_span_new() {
        let ctx = TraceContext::new_root();
        let span = GatewaySpan::new("gateway.proxy", ctx);
        assert_eq!(span.name, "gateway.proxy");
        assert!(!span.is_finished());
        assert!(span.duration().is_none());
        assert_eq!(span.status, SpanStatus::Unset);
    }

    #[test]
    fn test_span_attributes() {
        let ctx = TraceContext::new_root();
        let mut span = GatewaySpan::new("test", ctx);
        span.set_attribute("http.method", "GET");
        span.set_attribute("http.url", "/api/data");
        assert_eq!(span.attributes.get("http.method").unwrap(), "GET");
        assert_eq!(span.attributes.get("http.url").unwrap(), "/api/data");
    }

    #[test]
    fn test_span_finish() {
        let ctx = TraceContext::new_root();
        let mut span = GatewaySpan::new("test", ctx);
        assert!(!span.is_finished());
        span.finish();
        assert!(span.is_finished());
        assert!(span.duration().is_some());
        assert_eq!(span.status, SpanStatus::Unset);
    }

    #[test]
    fn test_span_finish_with_error() {
        let ctx = TraceContext::new_root();
        let mut span = GatewaySpan::new("test", ctx);
        span.finish_with_error("connection refused");
        assert!(span.is_finished());
        assert_eq!(span.status, SpanStatus::Error("connection refused".to_string()));
    }

    // --- SpanStatus ---

    #[test]
    fn test_span_status_display() {
        assert_eq!(SpanStatus::Unset.to_string(), "UNSET");
        assert_eq!(SpanStatus::Ok.to_string(), "OK");
        assert_eq!(
            SpanStatus::Error("fail".to_string()).to_string(),
            "ERROR: fail"
        );
    }

    // --- TracingConfig ---

    #[test]
    fn test_config_default() {
        let config = TracingConfig::default();
        assert!(config.otlp_endpoint.is_none());
        assert_eq!(config.propagation, "w3c");
        assert_eq!(config.sample_rate, 1.0);
        assert_eq!(config.service_name, "a3s-gateway");
        assert!(!config.is_export_enabled());
    }

    #[test]
    fn test_config_propagation_format() {
        let mut config = TracingConfig::default();
        assert_eq!(config.propagation_format(), PropagationFormat::W3C);

        config.propagation = "b3".to_string();
        assert_eq!(config.propagation_format(), PropagationFormat::B3);

        config.propagation = "zipkin".to_string();
        assert_eq!(config.propagation_format(), PropagationFormat::B3);
    }

    #[test]
    fn test_config_export_enabled() {
        let mut config = TracingConfig::default();
        assert!(!config.is_export_enabled());
        config.otlp_endpoint = Some("http://localhost:4317".to_string());
        assert!(config.is_export_enabled());
    }

    #[test]
    fn test_config_serialization() {
        let config = TracingConfig {
            otlp_endpoint: Some("http://localhost:4317".to_string()),
            propagation: "b3".to_string(),
            sample_rate: 0.5,
            service_name: "my-gateway".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: TracingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.otlp_endpoint.as_deref(), Some("http://localhost:4317"));
        assert_eq!(parsed.sample_rate, 0.5);
    }

    // --- Display ---

    #[test]
    fn test_trace_context_display() {
        let ctx = TraceContext {
            trace_id: "abc123".to_string(),
            parent_span_id: String::new(),
            span_id: "def456".to_string(),
            trace_flags: 1,
            trace_state: None,
        };
        let display = ctx.to_string();
        assert!(display.contains("trace_id=abc123"));
        assert!(display.contains("span_id=def456"));
        assert!(display.contains("sampled=true"));
    }

    // --- Utility functions ---

    #[test]
    fn test_is_hex() {
        assert!(is_hex("0af7651916cd43dd"));
        assert!(is_hex("ABCDEF0123456789"));
        assert!(!is_hex("xyz"));
        assert!(!is_hex(""));
        assert!(!is_hex("0af765-invalid"));
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x0a, 0xf7]), "0af7");
        assert_eq!(hex_encode(&[0x00, 0xff]), "00ff");
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn test_generate_trace_id_length() {
        let id = generate_trace_id();
        assert_eq!(id.len(), 32);
        assert!(is_hex(&id));
    }

    #[test]
    fn test_generate_span_id_length() {
        let id = generate_span_id();
        assert_eq!(id.len(), 16);
        assert!(is_hex(&id));
    }
}
