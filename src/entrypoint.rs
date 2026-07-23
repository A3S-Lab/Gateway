//! Entrypoint — network listeners for HTTP/HTTPS/TCP
//!
//! Manages the lifecycle of network listeners that accept incoming
//! connections and dispatch them to the router. Supports HTTP, WebSocket,
//! gRPC, SSE/streaming, TCP, and UDP protocols.

mod listener;
pub(crate) mod protocol;
#[cfg(test)]
mod tests;
mod udp_listener;

#[cfg(test)]
use listener::start_http_entrypoint;
pub(crate) use listener::{
    start_entrypoints, validate_entrypoints, EntryPointHandles, PreparedEntrypointReconfigure,
};

use protocol::{ProtocolContext, WsContext};

use crate::inference::{collect_json_body, OpenAiRequestProfile};
use crate::middleware::{Pipeline, RequestContext};
use crate::observability::access_log::RequestAccessLog;
use crate::proxy::{ForwardedContext, ForwardedProto, HttpProxy};
use crate::router::RouterTable;
use crate::scaling::buffer::RequestBuffer;
use crate::scaling::concurrency::ConcurrencyLimiter;
use crate::scaling::revision::RevisionRouter;
use crate::service::passive_health::PassiveHealthCheck;
use crate::service::sticky::StickySessionManager;
use crate::service::ServiceRegistry;
use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::BodyExt;
use hyper::body::{Body, Incoming};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

/// Unified response body type supporting both full-buffered and streaming responses.
///
/// `UnsyncBoxBody` (rather than `BoxBody`) is used because the SSE streaming
/// body wraps a `reqwest` byte stream which is `Send` but not `Sync`.
/// hyper 1.x only requires the body to be `Send + 'static`, so this is fine.
type ResponseBody = UnsyncBoxBody<Bytes, std::io::Error>;

/// Wrap a full byte payload into the unified body type.
fn full_body(bytes: impl Into<Bytes>) -> ResponseBody {
    http_body_util::Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Build a simple JSON error response with the given status code.
fn error_response(status: u16, message: &str) -> hyper::Response<ResponseBody> {
    hyper::Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(full_body(Bytes::from(format!(
            r#"{{"error":"{}"}}"#,
            message
        ))))
        .unwrap()
}

/// Emit a terminal access-log entry for an immediately available response.
fn finish_access_log(
    access_log: Option<RequestAccessLog>,
    response: hyper::Response<ResponseBody>,
) -> hyper::Response<ResponseBody> {
    if let Some(access_log) = access_log {
        let response_bytes = response.body().size_hint().exact().unwrap_or(0);
        access_log.finish(response.status().as_u16(), response_bytes);
    }
    response
}

/// Apply response-phase middleware to a native data-plane response.
async fn apply_native_response_pipeline(
    pipeline: &Pipeline,
    response: hyper::Response<Bytes>,
) -> hyper::Response<ResponseBody> {
    let (mut parts, body) = response.into_parts();
    if let Err(error) = pipeline.process_response(&mut parts).await {
        tracing::warn!(error = %error, "Response middleware error on native response");
    }
    hyper::Response::from_parts(parts, full_body(body))
}

/// Scaling-related state for services with autoscaling enabled
pub struct ScalingState {
    /// Per-service request buffers (for scale-from-zero)
    pub buffers: HashMap<String, Arc<RequestBuffer>>,
    /// Per-service concurrency limiters
    pub limiters: HashMap<String, Arc<ConcurrencyLimiter>>,
    /// Per-service revision routers
    pub revision_routers: HashMap<String, Arc<RevisionRouter>>,
}

/// Shared state for request handling
pub struct GatewayState {
    pub router_table: Arc<RouterTable>,
    pub service_registry: Arc<ServiceRegistry>,
    pub middleware_configs: Arc<HashMap<String, crate::config::MiddlewareConfig>>,
    /// Pre-compiled middleware pipelines keyed by router name.
    /// Built once at startup; avoids re-parsing config on every request.
    pub pipeline_cache: Arc<HashMap<String, Arc<Pipeline>>>,
    pub http_proxy: Arc<HttpProxy>,
    /// gRPC proxy (HTTP/2 with h2c support)
    pub grpc_proxy: Arc<crate::proxy::grpc::GrpcProxy>,
    /// Scaling state (None if no service has scaling config)
    pub scaling: Option<Arc<ScalingState>>,
    /// Traffic mirrors: service_name → TrafficMirror
    pub mirrors: HashMap<String, Arc<crate::service::TrafficMirror>>,
    /// Failover selectors: service_name → FailoverSelector
    pub failovers: HashMap<String, Arc<crate::service::FailoverSelector>>,
    /// Structured access log (counter + background task target)
    pub access_log: Arc<crate::observability::access_log::AccessLog>,
    /// Channel for fire-and-forget log entries — background task does JSON + tracing
    pub log_tx:
        tokio::sync::mpsc::UnboundedSender<crate::observability::access_log::AccessLogEntry>,
    /// Sticky session managers (only for services with sticky config)
    pub sticky_managers: HashMap<String, Arc<StickySessionManager>>,
    /// Passive health checkers for all services
    pub passive_health: HashMap<String, Arc<PassiveHealthCheck>>,
    /// Gateway-wide metrics collector
    pub metrics: Arc<crate::observability::metrics::GatewayMetrics>,
    /// Whether metrics recording is enabled (hot-path flag)
    pub metrics_enabled: bool,
    /// Whether access logging is enabled (hot-path flag)
    pub access_log_enabled: bool,
    /// Whether distributed tracing is enabled (hot-path flag)
    pub tracing_enabled: bool,
}

/// Shared runtime snapshot used by entrypoints.
///
/// Listeners keep this handle for their lifetime and clone the current
/// `GatewayState` for each new request/connection. Reload can replace the
/// snapshot without rebinding unchanged traffic ports.
#[derive(Clone)]
pub struct GatewayRuntime {
    current: Arc<RwLock<Arc<GatewayState>>>,
}

impl GatewayRuntime {
    pub fn new(state: Arc<GatewayState>) -> Self {
        Self {
            current: Arc::new(RwLock::new(state)),
        }
    }

    pub fn load(&self) -> Arc<GatewayState> {
        self.current.read().unwrap().clone()
    }

    pub fn replace(&self, state: Arc<GatewayState>) {
        *self.current.write().unwrap() = state;
    }
}

/// Handle an individual HTTP request, dispatching to the correct protocol proxy.
///
/// Protocol detection order:
/// 1. WebSocket upgrade (Upgrade: websocket) → bidirectional relay
/// 2. gRPC (Content-Type: application/grpc) → HTTP/2 h2c proxy
/// 3. SSE (Accept: text/event-stream) → streaming passthrough
/// 4. Plain HTTP → buffered reverse proxy
async fn handle_http_request(
    req: hyper::Request<Incoming>,
    remote_addr: SocketAddr,
    entrypoint: String,
    forwarded_proto: ForwardedProto,
    state: Arc<GatewayState>,
) -> std::result::Result<hyper::Response<ResponseBody>, hyper::Error> {
    // Extract routing and protocol info by reference (before consuming the request).
    let host = req
        .headers()
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let path = req.uri().path().to_string();
    let method_str = req.method().as_str().to_string();
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    // Detect protocol from request headers.
    let is_ws = crate::proxy::websocket::is_websocket_upgrade(req.headers());
    let is_grpc = crate::proxy::grpc::is_grpc_request(req.headers());
    let is_sse = crate::proxy::streaming::is_streaming_request(req.headers());

    let mut access_log = if state.access_log_enabled {
        Some(RequestAccessLog::new(
            state.access_log.start_request(),
            state.log_tx.clone(),
            remote_addr.ip().to_string(),
            method_str.clone(),
            path.clone(),
            host.clone(),
            entrypoint.clone(),
            user_agent,
        ))
    } else {
        None
    };

    // Extract incoming trace context and create a child span.
    let trace_ctx = if state.tracing_enabled {
        crate::observability::tracing::extract_trace_context(req.headers())
            .map(|ctx| ctx.child())
            .unwrap_or_else(crate::observability::tracing::TraceContext::new_root)
    } else {
        crate::observability::tracing::TraceContext::new_root()
    };

    // Route the request.
    let route = match state.router_table.match_request(
        host.as_deref(),
        &path,
        &method_str,
        req.headers(),
        &entrypoint,
    ) {
        Some(route) => route,
        None => {
            if state.metrics_enabled {
                state.metrics.record_request(404, 0);
            }
            return Ok(finish_access_log(
                access_log,
                error_response(404, "No route matched"),
            ));
        }
    };
    if let Some(access_log) = access_log.as_mut() {
        access_log.set_router(route.router_name.clone());
    }

    // Record per-router and per-service request counts.
    if state.metrics_enabled {
        state.metrics.record_router_request(&route.router_name);
        state.metrics.record_service_request(&route.service_name);
    }
    let request_start = std::time::Instant::now();
    let forwarded = ForwardedContext::new(remote_addr, forwarded_proto);

    // Look up pre-compiled pipeline (built once at startup, not per-request).
    // Arc clone is O(1) — just an atomic ref-count increment.
    let pipeline: Arc<Pipeline> = if let Some(cached) = state.pipeline_cache.get(&route.router_name)
    {
        cached.clone()
    } else {
        match Pipeline::from_config(&route.middlewares, &state.middleware_configs) {
            Ok(p) => Arc::new(p),
            Err(e) => {
                tracing::error!(error = %e, "Failed to build middleware pipeline");
                return Ok(finish_access_log(
                    access_log,
                    error_response(500, "Internal server error"),
                ));
            }
        }
    };

    let ctx = RequestContext {
        client_ip: remote_addr.ip().to_string(),
        entrypoint: entrypoint.clone(),
        router: route.router_name.clone(),
    };

    // ── WebSocket upgrade path ───────────────────────────────────────────────
    // Must be handled before req.into_parts() since hyper::upgrade::on() needs
    // the full Request<Incoming>.
    if is_ws {
        // Run middleware on cloned parts for auth / rate-limit checks.
        let (mut temp_parts, _) = http::Request::builder()
            .method(req.method())
            .uri(req.uri())
            .version(req.version())
            .body(())
            .unwrap()
            .into_parts();
        temp_parts.headers = req.headers().clone();

        match pipeline.process_request(&mut temp_parts, &ctx).await {
            Ok(Some(response)) => {
                let (resp_parts, body) = response.into_parts();
                let response = hyper::Response::from_parts(resp_parts, full_body(body));
                return Ok(finish_access_log(access_log, response));
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "Middleware error (WebSocket)");
                return Ok(finish_access_log(
                    access_log,
                    error_response(500, "Middleware error"),
                ));
            }
        }

        // Select backend.
        let lb = match state.service_registry.get(&route.service_name) {
            Some(lb) => lb,
            None => {
                return Ok(finish_access_log(
                    access_log,
                    error_response(502, "Service not found"),
                ));
            }
        };
        let backend = state
            .scaling
            .as_ref()
            .and_then(|s| s.revision_routers.get(&route.service_name))
            .and_then(|rev_router| {
                rev_router
                    .next_backend()
                    .map(|(backend, _rev_name)| backend)
            })
            .or_else(|| lb.next_backend());
        let backend = match backend {
            Some(b) => b,
            None => {
                return Ok(finish_access_log(
                    access_log,
                    error_response(503, "No healthy backends"),
                ));
            }
        };
        if let Some(access_log) = access_log.as_mut() {
            access_log.set_backend(backend.url.clone());
        }

        let ws_ctx = WsContext {
            route: route.clone(),
            backend: backend.clone(),
            state: state.clone(),
            remote_addr,
            access_log,
            request_start,
        };

        let (ws_resp, relay_future) = protocol::handle_ws_upgrade(req, ws_ctx);
        tokio::spawn(relay_future);

        return Ok(ws_resp);
    }

    // ── Non-WebSocket path: consume request body ─────────────────────────────
    let (mut req_parts, body) = req.into_parts();

    // Run request-phase middleware.
    match pipeline.process_request(&mut req_parts, &ctx).await {
        Ok(Some(response)) => {
            let (resp_parts, body) = response.into_parts();
            let response = hyper::Response::from_parts(resp_parts, full_body(body));
            return Ok(finish_access_log(access_log, response));
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "Middleware error");
            return Ok(finish_access_log(
                access_log,
                error_response(500, "Middleware error"),
            ));
        }
    }

    // Match the closed native OpenAI surface after request middleware so a
    // configured strip-prefix or header policy is reflected in the profile.
    // Non-matching method/path combinations retain ordinary proxy semantics.
    let openai_profile =
        OpenAiRequestProfile::match_request(&req_parts.method, req_parts.uri.path());

    // gRPC, SSE, mirrored traffic, and OpenAI POST endpoints require a
    // buffered body. Native OpenAI JSON collection has its own fixed 8 MiB
    // cap; ordinary HTTP requests continue to stream directly upstream.
    let needs_buffered_body = is_grpc
        || is_sse
        || state.mirrors.contains_key(&route.service_name)
        || openai_profile.is_some_and(OpenAiRequestProfile::requires_json_body);

    let (body_bytes, streaming_body) =
        if openai_profile.is_some_and(OpenAiRequestProfile::requires_json_body) {
            match collect_json_body(&req_parts.headers, body).await {
                Ok(collected) => (collected, None),
                Err(error) => {
                    let response =
                        apply_native_response_pipeline(&pipeline, error.into_response()).await;
                    let status = response.status().as_u16();
                    let response_bytes = response.body().size_hint().exact().unwrap_or(0);
                    if state.metrics_enabled {
                        state.metrics.record_request(status, response_bytes);
                        state.metrics.record_router_latency(
                            &route.router_name,
                            request_start.elapsed().as_micros() as u64,
                        );
                        state.metrics.record_router_error(&route.router_name);
                        state.metrics.record_service_error(&route.service_name);
                    }
                    return Ok(finish_access_log(access_log, response));
                }
            }
        } else if needs_buffered_body {
            let collected = match BodyExt::collect(body).await {
                Ok(c) => c.to_bytes(),
                Err(_) => Bytes::new(),
            };
            (collected, None)
        } else {
            (Bytes::new(), Some(body))
        };

    // ── Backend selection ─────────────────────────────────────────────────────
    let lb = match state.service_registry.get(&route.service_name) {
        Some(lb) => lb,
        None => {
            return Ok(finish_access_log(
                access_log,
                error_response(502, "Service not found"),
            ));
        }
    };
    let request_timeout = lb.request_timeout();

    let scaling = state.scaling.as_ref();

    // Step 1: Sticky session — try to honour an existing affinity cookie.
    let mut sticky_new_session: Option<String> = None;
    let backend_from_sticky = state
        .sticky_managers
        .get(&route.service_name)
        .and_then(|mgr| {
            let session_id = req_parts
                .headers
                .get("cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|cookie| mgr.extract_session_id(cookie))
                .map(|s| s.to_string());
            match mgr.select_backend(session_id.as_deref(), lb.backends()) {
                Some((backend, new_id)) => {
                    sticky_new_session = new_id;
                    Some(backend)
                }
                None => None,
            }
        });

    // Step 2: Normal selection (revision router → concurrency limiter → standard LB).
    let backend = if let Some(b) = backend_from_sticky {
        Some(b)
    } else if let Some(rev_router) =
        scaling.and_then(|s| s.revision_routers.get(&route.service_name))
    {
        rev_router.next_backend().map(|(b, _rev_name)| b)
    } else if let Some(limiter) = scaling.and_then(|s| s.limiters.get(&route.service_name)) {
        limiter.select_with_capacity(lb.backends())
    } else {
        lb.next_backend()
    };

    let backend = match backend {
        Some(b) => b,
        None => {
            // Step 3: Scale-from-zero buffer or failover.
            if let Some(buffer) = scaling.and_then(|s| s.buffers.get(&route.service_name)) {
                if buffer.needs_scale_up() {
                    tracing::info!(
                        service = route.service_name,
                        "Scale-from-zero triggered, buffering request"
                    );
                }

                match buffer.wait_for_backend().await {
                    crate::scaling::buffer::BufferResult::Ready => match lb.next_backend() {
                        Some(b) => b,
                        None => {
                            return Ok(finish_access_log(
                                access_log,
                                error_response(503, "No healthy backends after scale-up"),
                            ));
                        }
                    },
                    crate::scaling::buffer::BufferResult::Timeout => {
                        return Ok(finish_access_log(
                            access_log,
                            error_response(504, "Backend scale-up timed out"),
                        ));
                    }
                    crate::scaling::buffer::BufferResult::Overflow => {
                        return Ok(finish_access_log(
                            access_log,
                            error_response(503, "Request buffer full"),
                        ));
                    }
                    crate::scaling::buffer::BufferResult::Shutdown => {
                        return Ok(finish_access_log(
                            access_log,
                            error_response(503, "Gateway shutting down"),
                        ));
                    }
                }
            } else if let Some(failover) = state.failovers.get(&route.service_name) {
                match failover.next_backend() {
                    Some((b, _is_failover)) => b,
                    None => {
                        return Ok(finish_access_log(
                            access_log,
                            error_response(503, "No healthy backends (primary + failover)"),
                        ));
                    }
                }
            } else {
                return Ok(finish_access_log(
                    access_log,
                    error_response(503, "No healthy backends"),
                ));
            }
        }
    };
    if let Some(access_log) = access_log.as_mut() {
        access_log.set_backend(backend.url.clone());
    }

    // Record per-backend request.
    if state.metrics_enabled {
        state.metrics.record_backend_request(&backend.url);
    }

    // Mirror traffic if configured (fire-and-forget, before primary forward).
    if let Some(mirror) = state.mirrors.get(&route.service_name) {
        mirror.mirror_request(
            req_parts.method.clone(),
            req_parts.uri.clone(),
            req_parts.headers.clone(),
            body_bytes.clone(),
        );
    }

    // Inject outbound trace context (W3C traceparent).
    if state.tracing_enabled {
        let traceparent = trace_ctx.to_traceparent();
        if let Ok(hval) = hyper::header::HeaderValue::from_str(&traceparent) {
            req_parts
                .headers
                .insert(hyper::header::HeaderName::from_static("traceparent"), hval);
        }
    }

    // ── gRPC dispatch ─────────────────────────────────────────────────────────
    if is_grpc {
        let ctx = ProtocolContext {
            route,
            backend,
            req_parts,
            body_bytes,
            streaming_body: None,
            pipeline,
            state: state.clone(),
            forwarded,
            request_timeout,
            access_log,
            sticky_new_session,
            request_start,
        };
        return Ok(protocol::handle_grpc_dispatch(ctx, state.grpc_proxy.clone()).await);
    }

    // ── SSE / streaming dispatch ──────────────────────────────────────────────
    if is_sse {
        let ctx = ProtocolContext {
            route,
            backend,
            req_parts,
            body_bytes,
            streaming_body: None,
            pipeline,
            state: state.clone(),
            forwarded,
            request_timeout,
            access_log,
            sticky_new_session,
            request_start,
        };
        return Ok(protocol::handle_sse_dispatch(ctx).await);
    }

    // ── Plain HTTP dispatch ───────────────────────────────────────────────────
    {
        let ctx = ProtocolContext {
            route,
            backend,
            req_parts,
            body_bytes,
            streaming_body,
            pipeline,
            state: state.clone(),
            forwarded,
            request_timeout,
            access_log,
            sticky_new_session,
            request_start,
        };
        Ok(protocol::handle_http_dispatch(ctx).await)
    }
}
