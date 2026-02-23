//! Entrypoint — network listeners for HTTP/HTTPS/TCP
//!
//! Manages the lifecycle of network listeners that accept incoming
//! connections and dispatch them to the router. Supports HTTP, WebSocket,
//! gRPC, SSE/streaming, TCP, and UDP protocols.

use crate::config::{GatewayConfig, Protocol};
use crate::error::{GatewayError, Result};
use crate::middleware::{Pipeline, RequestContext, TcpFilter};
use crate::proxy::tcp;
use crate::proxy::udp::{self, UdpProxyConfig};
use crate::proxy::HttpProxy;
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
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

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

/// Create an empty body (used for 101/204 responses).
fn empty_body() -> ResponseBody {
    http_body_util::Empty::new()
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
}

/// Start all entrypoints defined in the configuration
pub async fn start_entrypoints(
    config: &GatewayConfig,
    state: Arc<GatewayState>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<Vec<tokio::task::JoinHandle<()>>> {
    let mut handles = Vec::new();

    for (name, ep_config) in &config.entrypoints {
        let addr: SocketAddr = ep_config.address.parse().map_err(|e| {
            GatewayError::Config(format!(
                "Invalid address '{}' for entrypoint '{}': {}",
                ep_config.address, name, e
            ))
        })?;

        match ep_config.protocol {
            Protocol::Http => {
                let handle = start_http_entrypoint(
                    name.clone(),
                    addr,
                    ep_config.tls.as_ref(),
                    state.clone(),
                    shutdown_rx.clone(),
                )
                .await?;
                handles.push(handle);
            }
            Protocol::Tcp => {
                let handle = start_tcp_entrypoint(
                    name.clone(),
                    addr,
                    ep_config.max_connections,
                    &ep_config.tcp_allowed_ips,
                    state.clone(),
                )
                .await?;
                handles.push(handle);
            }
            Protocol::Udp => {
                let handle = start_udp_entrypoint(
                    name.clone(),
                    addr,
                    ep_config.udp_session_timeout_secs,
                    ep_config.udp_max_sessions,
                    state.clone(),
                )
                .await?;
                handles.push(handle);
            }
        }
    }

    Ok(handles)
}

/// Start an HTTP/HTTPS entrypoint
async fn start_http_entrypoint(
    name: String,
    addr: SocketAddr,
    tls_config: Option<&crate::config::TlsConfig>,
    state: Arc<GatewayState>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| GatewayError::Other(format!("Failed to bind {}: {}", addr, e)))?;

    let tls_acceptor = if let Some(tls) = tls_config {
        Some(crate::proxy::tls::build_tls_acceptor(tls)?)
    } else {
        None
    };

    tracing::info!(
        entrypoint = name,
        address = %addr,
        tls = tls_acceptor.is_some(),
        "HTTP entrypoint listening"
    );

    let ep_name = name.clone();
    let handle = tokio::spawn(async move {
        // Track in-flight connection tasks for graceful drain.
        let mut conn_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        loop {
            // Clean up completed connection handles periodically.
            conn_handles.retain(|h| !h.is_finished());

            tokio::select! {
                result = listener.accept() => {
                    let (stream, remote_addr) = match result {
                        Ok(conn) => conn,
                        Err(e) => {
                            tracing::error!(error = %e, "Failed to accept connection");
                            continue;
                        }
                    };

                    let state = state.clone();
                    let ep_name = ep_name.clone();
                    let tls_acceptor = tls_acceptor.clone();

                    let conn_handle = tokio::spawn(async move {
                        state.metrics.inc_connections();
                        if let Some(acceptor) = tls_acceptor {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let io = TokioIo::new(tls_stream);
                                    let _ = auto::Builder::new(TokioExecutor::new())
                                        .serve_connection_with_upgrades(
                                            io,
                                            service_fn(|req| {
                                                handle_http_request(
                                                    req,
                                                    remote_addr,
                                                    ep_name.clone(),
                                                    state.clone(),
                                                )
                                            }),
                                        )
                                        .await;
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "TLS handshake failed");
                                }
                            }
                        } else {
                            let io = TokioIo::new(stream);
                            let _ = auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(
                                    io,
                                    service_fn(|req| {
                                        handle_http_request(
                                            req,
                                            remote_addr,
                                            ep_name.clone(),
                                            state.clone(),
                                        )
                                    }),
                                )
                                .await;
                        }
                        state.metrics.dec_connections();
                    });
                    conn_handles.push(conn_handle);
                }
                _ = shutdown_rx.changed() => {
                    tracing::info!(entrypoint = ep_name, "Shutdown signal received, draining connections");
                    break;
                }
            }
        }

        // Drain: wait for in-flight connections with a timeout.
        let drain_timeout = Duration::from_secs(30);
        let drain_deadline = tokio::time::Instant::now() + drain_timeout;
        for handle in conn_handles {
            let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                handle.abort();
            } else {
                tokio::select! {
                    _ = handle => {}
                    _ = tokio::time::sleep(remaining) => {
                        tracing::warn!(entrypoint = ep_name, "Connection drain timeout, aborting remaining");
                        break;
                    }
                }
            }
        }
    });

    Ok(handle)
}

/// Start a TCP entrypoint
async fn start_tcp_entrypoint(
    name: String,
    addr: SocketAddr,
    max_connections: Option<u32>,
    tcp_allowed_ips: &[String],
    state: Arc<GatewayState>,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| GatewayError::Other(format!("Failed to bind TCP {}: {}", addr, e)))?;

    let tcp_filter = Arc::new(TcpFilter::new(max_connections, tcp_allowed_ips)?);

    tracing::info!(
        entrypoint = name,
        address = %addr,
        max_connections = ?max_connections,
        ip_filter = !tcp_allowed_ips.is_empty(),
        "TCP entrypoint listening"
    );

    let handle = tokio::spawn(async move {
        loop {
            let (client_stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to accept TCP connection");
                    continue;
                }
            };

            let permit = match tcp_filter.check_connection(&remote_addr.ip().to_string()) {
                Ok(permit) => permit,
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        remote = %remote_addr,
                        "TCP connection rejected by filter"
                    );
                    continue;
                }
            };

            let state = state.clone();
            let ep_name = name.clone();

            tokio::spawn(async move {
                let _permit = permit;

                let headers = http::HeaderMap::new();
                if let Some(route) = state
                    .router_table
                    .match_request(None, "/", "TCP", &headers, &ep_name)
                {
                    if let Some(lb) = state.service_registry.get(&route.service_name) {
                        if let Some(backend) = lb.next_backend() {
                            let address = tcp::extract_address(&backend.url);
                            match tcp::connect_upstream(address).await {
                                Ok(upstream_stream) => {
                                    backend.inc_connections();
                                    let result =
                                        tcp::relay_tcp(client_stream, upstream_stream).await;
                                    backend.dec_connections();

                                    if let Err(e) = result {
                                        tracing::debug!(
                                            error = %e,
                                            remote = %remote_addr,
                                            "TCP relay ended"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        backend = backend.url,
                                        "TCP upstream connection failed"
                                    );
                                }
                            }
                        }
                    }
                } else {
                    tracing::debug!(
                        remote = %remote_addr,
                        "No TCP route matched"
                    );
                }
            });
        }
    });

    Ok(handle)
}

/// Start a UDP entrypoint
async fn start_udp_entrypoint(
    name: String,
    addr: SocketAddr,
    session_timeout_secs: Option<u64>,
    max_sessions: Option<usize>,
    state: Arc<GatewayState>,
) -> Result<tokio::task::JoinHandle<()>> {
    let headers = http::HeaderMap::new();
    let upstream_addr = state
        .router_table
        .match_request(None, "/", "UDP", &headers, &name)
        .and_then(|route| state.service_registry.get(&route.service_name))
        .and_then(|lb| lb.next_backend())
        .map(|backend| crate::proxy::tcp::extract_address(&backend.url).to_string())
        .ok_or_else(|| {
            GatewayError::Config(format!(
                "UDP entrypoint '{}' has no matching router/service with a healthy backend",
                name
            ))
        })?;

    let timeout = Duration::from_secs(session_timeout_secs.unwrap_or(30));
    let max_sess = max_sessions.unwrap_or(10000);

    let (socket, _) = udp::start_udp_listener(&addr.to_string(), &upstream_addr, timeout).await?;

    let proxy = udp::UdpProxy::new(UdpProxyConfig {
        session_timeout: timeout,
        max_sessions: max_sess,
        upstream_addr: upstream_addr.clone(),
    });
    let proxy = Arc::new(proxy);

    tracing::info!(
        entrypoint = name,
        address = %addr,
        upstream = upstream_addr,
        session_timeout_secs = timeout.as_secs(),
        max_sessions = max_sess,
        "UDP entrypoint listening"
    );

    let handle = tokio::spawn(async move {
        udp::run_udp_proxy(socket, proxy).await;
    });

    Ok(handle)
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
    let uri = req.uri().clone();

    // Detect protocol from request headers.
    let is_ws = crate::proxy::websocket::is_websocket_upgrade(req.headers());
    let is_grpc = crate::proxy::grpc::is_grpc_request(req.headers());
    let is_sse = crate::proxy::streaming::is_streaming_request(req.headers());

    let access_tracker = state.access_log.start_request();

    // Extract incoming trace context and create a child span.
    let trace_ctx = crate::observability::tracing::extract_trace_context(req.headers())
        .map(|ctx| ctx.child())
        .unwrap_or_else(crate::observability::tracing::TraceContext::new_root);

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
            state.metrics.record_request(404, 0);
            return Ok(error_response(404, "No route matched"));
        }
    };

    // Record per-router and per-service request counts.
    state.metrics.record_router_request(&route.router_name);
    state.metrics.record_service_request(&route.service_name);
    let request_start = std::time::Instant::now();

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
                return Ok(error_response(500, "Internal server error"));
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
                return Ok(hyper::Response::from_parts(resp_parts, full_body(body)));
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "Middleware error (WebSocket)");
                return Ok(error_response(500, "Middleware error"));
            }
        }

        // Select backend.
        let lb = match state.service_registry.get(&route.service_name) {
            Some(lb) => lb,
            None => return Ok(error_response(502, "Service not found")),
        };
        let backend = match lb.next_backend() {
            Some(b) => b,
            None => return Ok(error_response(503, "No healthy backends")),
        };

        let ws_key = req
            .headers()
            .get("Sec-WebSocket-Key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let accept = crate::proxy::websocket::compute_accept_key(&ws_key);
        let ws_url = crate::proxy::websocket::build_ws_url(&backend.url, &uri);

        // Consume the request to get the upgrade future.
        let upgrade = hyper::upgrade::on(req);
        backend.inc_connections();

        tokio::spawn(async move {
            match upgrade.await {
                Ok(upgraded) => {
                    // hyper::upgrade::Upgraded doesn't implement tokio's
                    // AsyncRead/AsyncWrite directly; wrap it with TokioIo.
                    let ws_client = tokio_tungstenite::WebSocketStream::from_raw_socket(
                        hyper_util::rt::TokioIo::new(upgraded),
                        tokio_tungstenite::tungstenite::protocol::Role::Server,
                        None,
                    )
                    .await;

                    match crate::proxy::websocket::connect_upstream(&ws_url).await {
                        Ok(ws_upstream) => {
                            crate::proxy::websocket::relay_websocket(ws_client, ws_upstream).await;
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                backend = backend.url,
                                "WebSocket upstream connection failed"
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "WebSocket connection upgrade failed");
                }
            }
            backend.dec_connections();
        });

        tracing::debug!(
            remote = %remote_addr,
            "WebSocket upgrade dispatched"
        );

        state.metrics.record_request(101, 0);
        state.metrics.record_router_latency(
            &route.router_name,
            request_start.elapsed().as_micros() as u64,
        );

        return Ok(hyper::Response::builder()
            .status(101)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Accept", accept)
            .body(empty_body())
            .unwrap());
    }

    // ── Non-WebSocket path: consume request body ─────────────────────────────
    let (mut req_parts, body) = req.into_parts();

    let body_bytes = match BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };

    // Run request-phase middleware.
    match pipeline.process_request(&mut req_parts, &ctx).await {
        Ok(Some(response)) => {
            let (resp_parts, body) = response.into_parts();
            return Ok(hyper::Response::from_parts(resp_parts, full_body(body)));
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!(error = %e, "Middleware error");
            return Ok(error_response(500, "Middleware error"));
        }
    }

    // ── Backend selection ─────────────────────────────────────────────────────
    let lb = match state.service_registry.get(&route.service_name) {
        Some(lb) => lb,
        None => {
            return Ok(error_response(502, "Service not found"));
        }
    };

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
                            return Ok(error_response(503, "No healthy backends after scale-up"));
                        }
                    },
                    crate::scaling::buffer::BufferResult::Timeout => {
                        return Ok(error_response(504, "Backend scale-up timed out"));
                    }
                    crate::scaling::buffer::BufferResult::Overflow => {
                        return Ok(error_response(503, "Request buffer full"));
                    }
                    crate::scaling::buffer::BufferResult::Shutdown => {
                        return Ok(error_response(503, "Gateway shutting down"));
                    }
                }
            } else if let Some(failover) = state.failovers.get(&route.service_name) {
                match failover.next_backend() {
                    Some((b, _is_failover)) => b,
                    None => {
                        return Ok(error_response(
                            503,
                            "No healthy backends (primary + failover)",
                        ));
                    }
                }
            } else {
                return Ok(error_response(503, "No healthy backends"));
            }
        }
    };

    // Record per-backend request.
    state.metrics.record_backend_request(&backend.url);

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
    let traceparent = trace_ctx.to_traceparent();
    if let Ok(hval) = hyper::header::HeaderValue::from_str(&traceparent) {
        req_parts
            .headers
            .insert(hyper::header::HeaderName::from_static("traceparent"), hval);
    }

    // ── gRPC dispatch ─────────────────────────────────────────────────────────
    if is_grpc {
        match state
            .grpc_proxy
            .forward(
                &backend,
                &req_parts.method,
                &req_parts.uri,
                &req_parts.headers,
                body_bytes,
            )
            .await
        {
            Ok(grpc_resp) => {
                let status_code = grpc_resp.http_status.as_u16();
                let _ = state.log_tx.send(
                    access_tracker.build_entry(
                        remote_addr.ip().to_string(),
                        method_str,
                        path,
                        host,
                        status_code,
                        grpc_resp.body.len() as u64,
                        Some(backend.url.clone()),
                        Some(route.router_name.clone()),
                        Some(entrypoint),
                        req_parts
                            .headers
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string()),
                    ),
                );

                // Record passive health from HTTP status.
                if let Some(phc) = state.passive_health.get(&route.service_name) {
                    if phc.is_error_status(status_code) {
                        phc.record_error(&backend, status_code);
                    } else {
                        phc.record_success(&backend);
                    }
                }

                // Build response parts for response-phase middleware.
                let mut resp_builder =
                    http::Response::builder().status(grpc_resp.http_status.as_u16());
                for (key, value) in grpc_resp.headers.iter() {
                    resp_builder = resp_builder.header(key, value);
                }
                let (mut resp_parts, _) = resp_builder.body(()).unwrap().into_parts();

                // Run response-phase middleware (e.g. CORS / security headers).
                if let Err(e) = pipeline.process_response(&mut resp_parts).await {
                    tracing::warn!(error = %e, "Response middleware error (gRPC)");
                }

                let mut builder = hyper::Response::builder().status(resp_parts.status);
                for (key, value) in resp_parts.headers.iter() {
                    builder = builder.header(key, value);
                }

                let body_len = grpc_resp.body.len() as u64;
                state.metrics.record_request(status_code, body_len);
                state.metrics.record_router_latency(
                    &route.router_name,
                    request_start.elapsed().as_micros() as u64,
                );
                if status_code >= 400 {
                    state.metrics.record_router_error(&route.router_name);
                    state.metrics.record_service_error(&route.service_name);
                }

                return Ok(builder.body(full_body(grpc_resp.body)).unwrap());
            }
            Err(e) => {
                tracing::error!(error = %e, backend = backend.url, "gRPC proxy error");
                let _ = state.log_tx.send(
                    access_tracker.build_entry(
                        remote_addr.ip().to_string(),
                        method_str,
                        path,
                        host,
                        502,
                        0,
                        Some(backend.url.clone()),
                        Some(route.router_name.clone()),
                        Some(entrypoint),
                        req_parts
                            .headers
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string()),
                    ),
                );
                if let Some(phc) = state.passive_health.get(&route.service_name) {
                    phc.record_error(&backend, 502);
                }

                state.metrics.record_request(502, 0);
                state.metrics.record_router_latency(
                    &route.router_name,
                    request_start.elapsed().as_micros() as u64,
                );
                state.metrics.record_router_error(&route.router_name);
                state.metrics.record_service_error(&route.service_name);

                // Run response-phase middleware on error path.
                let (mut err_parts, _) = http::Response::builder()
                    .status(502)
                    .body(())
                    .unwrap()
                    .into_parts();
                if let Err(mw_err) = pipeline.process_response(&mut err_parts).await {
                    tracing::warn!(error = %mw_err, "Response middleware error on gRPC 502");
                }
                let mut builder = hyper::Response::builder().status(502);
                for (key, value) in err_parts.headers.iter() {
                    builder = builder.header(key, value);
                }
                return Ok(builder
                    .body(full_body(Bytes::from(format!(r#"{{"error":"{}"}}"#, e))))
                    .unwrap());
            }
        }
    }

    // ── SSE / streaming dispatch ──────────────────────────────────────────────
    if is_sse {
        match crate::proxy::streaming::forward_streaming(
            &backend,
            &req_parts.method,
            &req_parts.uri,
            &req_parts.headers,
            body_bytes,
            300, // 5-minute timeout for SSE streams
        )
        .await
        {
            Ok(stream_resp) => {
                let status_code = stream_resp.status.as_u16();
                let _ = state.log_tx.send(
                    access_tracker.build_entry(
                        remote_addr.ip().to_string(),
                        method_str,
                        path,
                        host,
                        status_code,
                        0, // body size unknown for streaming
                        Some(backend.url.clone()),
                        Some(route.router_name.clone()),
                        Some(entrypoint),
                        req_parts
                            .headers
                            .get("user-agent")
                            .and_then(|v| v.to_str().ok())
                            .map(|s| s.to_string()),
                    ),
                );

                if let Some(phc) = state.passive_health.get(&route.service_name) {
                    if phc.is_error_status(status_code) {
                        phc.record_error(&backend, status_code);
                    } else {
                        phc.record_success(&backend);
                    }
                }

                // Wrap the byte stream into a hyper-compatible streaming body.
                use futures_util::StreamExt;
                use hyper::body::Frame;
                let mapped = stream_resp
                    .body_stream
                    .map(|result| result.map(Frame::data).map_err(std::io::Error::other));
                let stream_body =
                    http_body_util::BodyExt::boxed_unsync(http_body_util::StreamBody::new(mapped));

                // Build response parts for response-phase middleware.
                let mut resp_builder =
                    http::Response::builder().status(stream_resp.status.as_u16());
                for (key, value) in stream_resp.headers.iter() {
                    resp_builder = resp_builder.header(key, value);
                }
                let (mut resp_parts, _) = resp_builder.body(()).unwrap().into_parts();

                // Run response-phase middleware (e.g. CORS / security headers).
                if let Err(e) = pipeline.process_response(&mut resp_parts).await {
                    tracing::warn!(error = %e, "Response middleware error (SSE)");
                }

                let mut builder = hyper::Response::builder().status(resp_parts.status);
                for (key, value) in resp_parts.headers.iter() {
                    builder = builder.header(key, value);
                }

                // Inject sticky session cookie if a new session was created.
                if let (Some(new_id), Some(sticky_mgr)) = (
                    &sticky_new_session,
                    state.sticky_managers.get(&route.service_name),
                ) {
                    builder = builder.header("Set-Cookie", sticky_mgr.build_cookie(new_id));
                }

                // Record metrics (body size unknown for streaming).
                state.metrics.record_request(status_code, 0);
                state.metrics.record_router_latency(
                    &route.router_name,
                    request_start.elapsed().as_micros() as u64,
                );
                if status_code >= 400 {
                    state.metrics.record_router_error(&route.router_name);
                    state.metrics.record_service_error(&route.service_name);
                }

                return Ok(builder.body(stream_body).unwrap());
            }
            Err(e) => {
                tracing::error!(error = %e, backend = backend.url, "SSE proxy error");
                if let Some(phc) = state.passive_health.get(&route.service_name) {
                    phc.record_error(&backend, 502);
                }

                state.metrics.record_request(502, 0);
                state.metrics.record_router_latency(
                    &route.router_name,
                    request_start.elapsed().as_micros() as u64,
                );
                state.metrics.record_router_error(&route.router_name);
                state.metrics.record_service_error(&route.service_name);

                // Run response-phase middleware on error path.
                let (mut err_parts, _) = http::Response::builder()
                    .status(502)
                    .body(())
                    .unwrap()
                    .into_parts();
                if let Err(mw_err) = pipeline.process_response(&mut err_parts).await {
                    tracing::warn!(error = %mw_err, "Response middleware error on SSE 502");
                }
                let mut builder = hyper::Response::builder().status(502);
                for (key, value) in err_parts.headers.iter() {
                    builder = builder.header(key, value);
                }
                return Ok(builder
                    .body(full_body(Bytes::from(format!(r#"{{"error":"{}"}}"#, e))))
                    .unwrap());
            }
        }
    }

    // ── Plain HTTP dispatch ───────────────────────────────────────────────────
    match state
        .http_proxy
        .forward(
            &backend,
            &req_parts.method,
            &req_parts.uri,
            &req_parts.headers,
            body_bytes,
        )
        .await
    {
        Ok(proxy_resp) => {
            let status_code = proxy_resp.status.as_u16();

            let _ = state.log_tx.send(
                access_tracker.build_entry(
                    remote_addr.ip().to_string(),
                    method_str,
                    path,
                    host,
                    status_code,
                    proxy_resp.body.len() as u64,
                    Some(backend.url.clone()),
                    Some(route.router_name.clone()),
                    Some(entrypoint),
                    req_parts
                        .headers
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string()),
                ),
            );

            // Passive health: record 5xx errors.
            if let Some(phc) = state.passive_health.get(&route.service_name) {
                if phc.is_error_status(status_code) {
                    phc.record_error(&backend, status_code);
                } else {
                    phc.record_success(&backend);
                }
            }

            // Build response parts for the response-phase middleware.
            let mut resp_builder = http::Response::builder().status(proxy_resp.status.as_u16());
            for (key, value) in proxy_resp.headers.iter() {
                resp_builder = resp_builder.header(key, value);
            }
            let (mut resp_parts, _) = resp_builder.body(()).unwrap().into_parts();

            // Run response-phase middleware (e.g. inject CORS / security headers).
            if let Err(e) = pipeline.process_response(&mut resp_parts).await {
                tracing::warn!(error = %e, "Response middleware error");
            }

            let mut builder = hyper::Response::builder().status(resp_parts.status);
            for (key, value) in resp_parts.headers.iter() {
                builder = builder.header(key, value);
            }

            // Inject sticky session Set-Cookie if a new session was created.
            if let (Some(new_id), Some(sticky_mgr)) = (
                &sticky_new_session,
                state.sticky_managers.get(&route.service_name),
            ) {
                builder = builder.header("Set-Cookie", sticky_mgr.build_cookie(new_id));
            }

            // Record metrics.
            state
                .metrics
                .record_request(status_code, proxy_resp.body.len() as u64);
            state.metrics.record_router_latency(
                &route.router_name,
                request_start.elapsed().as_micros() as u64,
            );
            if status_code >= 400 {
                state.metrics.record_router_error(&route.router_name);
                state.metrics.record_service_error(&route.service_name);
            }

            Ok(builder.body(full_body(proxy_resp.body)).unwrap())
        }
        Err(e) => {
            tracing::error!(error = %e, backend = backend.url, "Proxy error");

            if let Some(phc) = state.passive_health.get(&route.service_name) {
                phc.record_error(&backend, 502);
            }

            let _ = state.log_tx.send(
                access_tracker.build_entry(
                    remote_addr.ip().to_string(),
                    method_str,
                    path,
                    host,
                    502,
                    0,
                    Some(backend.url.clone()),
                    Some(route.router_name.clone()),
                    Some(entrypoint),
                    req_parts
                        .headers
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string()),
                ),
            );

            state.metrics.record_request(502, 0);
            state.metrics.record_router_latency(
                &route.router_name,
                request_start.elapsed().as_micros() as u64,
            );
            state.metrics.record_router_error(&route.router_name);
            state.metrics.record_service_error(&route.service_name);

            let (mut err_parts, _) = http::Response::builder()
                .status(502)
                .body(())
                .unwrap()
                .into_parts();
            if let Err(mw_err) = pipeline.process_response(&mut err_parts).await {
                tracing::warn!(error = %mw_err, "Response middleware error on 502");
            }

            let mut builder = hyper::Response::builder().status(502);
            for (key, value) in err_parts.headers.iter() {
                builder = builder.header(key, value);
            }
            Ok(builder
                .body(full_body(Bytes::from(format!(r#"{{"error":"{}"}}"#, e))))
                .unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EntrypointConfig;

    #[test]
    fn test_invalid_address() {
        let config = GatewayConfig {
            entrypoints: {
                let mut m = HashMap::new();
                m.insert(
                    "bad".to_string(),
                    EntrypointConfig {
                        address: "not-an-address".to_string(),
                        protocol: Protocol::Http,
                        tls: None,
                        max_connections: None,
                        tcp_allowed_ips: vec![],
                        udp_session_timeout_secs: None,
                        udp_max_sessions: None,
                    },
                );
                m
            },
            ..GatewayConfig::default()
        };

        let state = Arc::new(GatewayState {
            router_table: Arc::new(RouterTable::from_config(&HashMap::new()).unwrap()),
            service_registry: Arc::new(ServiceRegistry::from_config(&HashMap::new()).unwrap()),
            middleware_configs: Arc::new(HashMap::new()),
            pipeline_cache: Arc::new(HashMap::new()),
            http_proxy: Arc::new(HttpProxy::new()),
            grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
            scaling: None,
            mirrors: HashMap::new(),
            failovers: HashMap::new(),
            access_log: Arc::new(crate::observability::access_log::AccessLog::new()),
            log_tx: tokio::sync::mpsc::unbounded_channel().0,
            sticky_managers: HashMap::new(),
            passive_health: HashMap::new(),
            metrics: Arc::new(crate::observability::metrics::GatewayMetrics::new()),
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let result = rt.block_on(start_entrypoints(&config, state, shutdown_rx));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid address"));
    }
}
