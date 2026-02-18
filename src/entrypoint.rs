//! Entrypoint — network listeners for HTTP/HTTPS/TCP
//!
//! Manages the lifecycle of network listeners that accept incoming
//! connections and dispatch them to the router.

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
use crate::service::ServiceRegistry;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

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
    pub http_proxy: Arc<HttpProxy>,
    /// Scaling state (None if no service has scaling config)
    pub scaling: Option<Arc<ScalingState>>,
    /// Traffic mirrors: service_name → TrafficMirror
    pub mirrors: HashMap<String, Arc<crate::service::TrafficMirror>>,
    /// Failover selectors: service_name → FailoverSelector
    pub failovers: HashMap<String, Arc<crate::service::FailoverSelector>>,
    /// Structured access log
    pub access_log: Arc<crate::observability::access_log::AccessLog>,
}

/// Start all entrypoints defined in the configuration
pub async fn start_entrypoints(
    config: &GatewayConfig,
    state: Arc<GatewayState>,
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
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to accept connection");
                    continue;
                }
            };

            let state = state.clone();
            let ep_name = ep_name.clone();
            let tls_acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                if let Some(acceptor) = tls_acceptor {
                    // TLS connection
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            let _ = http1::Builder::new()
                                .serve_connection(
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
                                .with_upgrades()
                                .await;
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "TLS handshake failed");
                        }
                    }
                } else {
                    // Plain HTTP connection
                    let io = TokioIo::new(stream);
                    let _ = http1::Builder::new()
                        .serve_connection(
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
                        .with_upgrades()
                        .await;
                }
            });
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

            // Check TCP filter (IP allowlist + connection limit)
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
                // Hold the permit for the duration of the connection
                let _permit = permit;

                // For TCP, use the first router that matches this entrypoint
                let headers = HashMap::new();
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
    // Find the first router that matches this entrypoint to determine the upstream
    let headers = HashMap::new();
    let upstream_addr = state
        .router_table
        .match_request(None, "/", "UDP", &headers, &name)
        .and_then(|route| state.service_registry.get(&route.service_name))
        .and_then(|lb| lb.next_backend())
        .map(|backend| {
            // Extract host:port from URL (strip scheme)
            crate::proxy::tcp::extract_address(&backend.url).to_string()
        })
        .ok_or_else(|| {
            GatewayError::Config(format!(
                "UDP entrypoint '{}' has no matching router/service with a healthy backend",
                name
            ))
        })?;

    let timeout = Duration::from_secs(session_timeout_secs.unwrap_or(30));
    let max_sess = max_sessions.unwrap_or(10000);

    let (socket, _) = udp::start_udp_listener(
        &addr.to_string(),
        &upstream_addr,
        timeout,
    )
    .await?;

    // Override max_sessions if configured
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

/// Handle an individual HTTP request
async fn handle_http_request(
    req: hyper::Request<Incoming>,
    remote_addr: SocketAddr,
    entrypoint: String,
    state: Arc<GatewayState>,
) -> std::result::Result<hyper::Response<http_body_util::Full<Bytes>>, hyper::Error> {
    let (parts, body) = req.into_parts();

    // Collect request body
    let body_bytes = match http_body_util::BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };

    // Extract routing info
    let host = parts
        .headers
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let path = parts.uri.path().to_string();
    let method = parts.method.as_str().to_string();

    let mut header_map = HashMap::new();
    for (key, value) in parts.headers.iter() {
        if let Ok(v) = value.to_str() {
            header_map.insert(key.as_str().to_string(), v.to_string());
        }
    }

    // Start access log timer
    let access_tracker = state.access_log.start_request();

    // Extract incoming trace context (W3C traceparent or B3) and create a child span
    let trace_ctx = crate::observability::tracing::extract_trace_context(&header_map)
        .map(|ctx| ctx.child())
        .unwrap_or_else(crate::observability::tracing::TraceContext::new_root);

    // Route the request
    let route = match state.router_table.match_request(
        host.as_deref(),
        &path,
        &method,
        &header_map,
        &entrypoint,
    ) {
        Some(route) => route,
        None => {
            return Ok(hyper::Response::builder()
                .status(404)
                .body(http_body_util::Full::new(Bytes::from(
                    r#"{"error":"No route matched"}"#,
                )))
                .unwrap());
        }
    };

    // Build middleware pipeline
    let pipeline = match Pipeline::from_config(&route.middlewares, &state.middleware_configs) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "Failed to build middleware pipeline");
            return Ok(hyper::Response::builder()
                .status(500)
                .body(http_body_util::Full::new(Bytes::from(
                    r#"{"error":"Internal server error"}"#,
                )))
                .unwrap());
        }
    };

    // Run middleware pipeline
    let ctx = RequestContext {
        client_ip: remote_addr.ip().to_string(),
        entrypoint: entrypoint.clone(),
        router: route.router_name.clone(),
    };

    let mut req_parts = parts;
    match pipeline.process_request(&mut req_parts, &ctx).await {
        Ok(Some(response)) => {
            // Middleware short-circuited
            let (resp_parts, body) = response.into_parts();
            return Ok(hyper::Response::from_parts(
                resp_parts,
                http_body_util::Full::new(Bytes::from(body)),
            ));
        }
        Ok(None) => {} // Continue
        Err(e) => {
            tracing::error!(error = %e, "Middleware error");
            return Ok(hyper::Response::builder()
                .status(500)
                .body(http_body_util::Full::new(Bytes::from(
                    r#"{"error":"Middleware error"}"#,
                )))
                .unwrap());
        }
    }

    // Select backend (with optional scaling integration)
    let lb = match state.service_registry.get(&route.service_name) {
        Some(lb) => lb,
        None => {
            return Ok(hyper::Response::builder()
                .status(502)
                .body(http_body_util::Full::new(Bytes::from(
                    r#"{"error":"Service not found"}"#,
                )))
                .unwrap());
        }
    };

    let scaling = state.scaling.as_ref();

    // 1. Try revision router if configured
    let backend = if let Some(rev_router) = scaling
        .and_then(|s| s.revision_routers.get(&route.service_name))
    {
        rev_router
            .next_backend()
            .map(|(b, _rev_name)| b)
    } else if let Some(limiter) = scaling
        .and_then(|s| s.limiters.get(&route.service_name))
    {
        // 2. Try concurrency-limited selection
        limiter.select_with_capacity(lb.backends())
    } else {
        // 3. Standard path
        lb.next_backend()
    };

    let backend = match backend {
        Some(b) => b,
        None => {
            // Try the request buffer for scale-from-zero
            if let Some(buffer) = scaling
                .and_then(|s| s.buffers.get(&route.service_name))
            {
                if buffer.needs_scale_up() {
                    tracing::info!(
                        service = route.service_name,
                        "Scale-from-zero triggered, buffering request"
                    );
                }

                match buffer.wait_for_backend().await {
                    crate::scaling::buffer::BufferResult::Ready => {
                        // Retry backend selection after scale-up
                        match lb.next_backend() {
                            Some(b) => b,
                            None => {
                                return Ok(hyper::Response::builder()
                                    .status(503)
                                    .body(http_body_util::Full::new(Bytes::from(
                                        r#"{"error":"No healthy backends after scale-up"}"#,
                                    )))
                                    .unwrap());
                            }
                        }
                    }
                    crate::scaling::buffer::BufferResult::Timeout => {
                        return Ok(hyper::Response::builder()
                            .status(504)
                            .body(http_body_util::Full::new(Bytes::from(
                                r#"{"error":"Backend scale-up timed out"}"#,
                            )))
                            .unwrap());
                    }
                    crate::scaling::buffer::BufferResult::Overflow => {
                        return Ok(hyper::Response::builder()
                            .status(503)
                            .body(http_body_util::Full::new(Bytes::from(
                                r#"{"error":"Request buffer full"}"#,
                            )))
                            .unwrap());
                    }
                    crate::scaling::buffer::BufferResult::Shutdown => {
                        return Ok(hyper::Response::builder()
                            .status(503)
                            .body(http_body_util::Full::new(Bytes::from(
                                r#"{"error":"Gateway shutting down"}"#,
                            )))
                            .unwrap());
                    }
                }
            } else {
                // Try failover service if configured
                if let Some(failover) = state.failovers.get(&route.service_name) {
                    match failover.next_backend() {
                        Some((b, _is_failover)) => b,
                        None => {
                            return Ok(hyper::Response::builder()
                                .status(503)
                                .body(http_body_util::Full::new(Bytes::from(
                                    r#"{"error":"No healthy backends (primary + failover)"}"#,
                                )))
                                .unwrap());
                        }
                    }
                } else {
                    return Ok(hyper::Response::builder()
                        .status(503)
                        .body(http_body_util::Full::new(Bytes::from(
                            r#"{"error":"No healthy backends"}"#,
                        )))
                        .unwrap());
                }
            }
        }
    };

    // Mirror traffic if configured (fire-and-forget, before primary forward)
    if let Some(mirror) = state.mirrors.get(&route.service_name) {
        mirror.mirror_request(
            req_parts.method.clone(),
            req_parts.uri.clone(),
            req_parts.headers.clone(),
            body_bytes.clone(),
        );
    }

    // Inject outbound trace context (W3C traceparent)
    let traceparent = trace_ctx.to_traceparent();
    if let Ok(hval) = hyper::header::HeaderValue::from_str(&traceparent) {
        req_parts
            .headers
            .insert(hyper::header::HeaderName::from_static("traceparent"), hval);
    }

    // Forward to backend
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
            state.access_log.record(&access_tracker.build_entry(
                remote_addr.ip().to_string(),
                method,
                path,
                host,
                proxy_resp.status.as_u16(),
                proxy_resp.body.len() as u64,
                Some(backend.url.clone()),
                Some(route.router_name.clone()),
                Some(entrypoint),
                header_map.get("user-agent").cloned(),
            ));

            // Build http::response::Parts so response-phase middleware can modify headers
            let mut resp_builder =
                http::Response::builder().status(proxy_resp.status.as_u16());
            for (key, value) in proxy_resp.headers.iter() {
                resp_builder = resp_builder.header(key, value);
            }
            let (mut resp_parts, _) = resp_builder.body(()).unwrap().into_parts();

            // Run response-phase middleware (e.g. inject response headers)
            if let Err(e) = pipeline.process_response(&mut resp_parts).await {
                tracing::warn!(error = %e, "Response middleware error");
            }

            let mut builder = hyper::Response::builder().status(resp_parts.status);
            for (key, value) in resp_parts.headers.iter() {
                builder = builder.header(key, value);
            }
            Ok(builder
                .body(http_body_util::Full::new(proxy_resp.body))
                .unwrap())
        }
        Err(e) => {
            tracing::error!(error = %e, backend = backend.url, "Proxy error");
            state.access_log.record(&access_tracker.build_entry(
                remote_addr.ip().to_string(),
                method,
                path,
                host,
                502,
                0,
                Some(backend.url.clone()),
                Some(route.router_name.clone()),
                Some(entrypoint),
                header_map.get("user-agent").cloned(),
            ));

            // Run response-phase middleware on connection errors too:
            // circuit breaker records the failure, CORS/security headers are applied.
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
                .body(http_body_util::Full::new(Bytes::from(format!(
                    r#"{{"error":"{}"}}"#,
                    e
                ))))
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
            http_proxy: Arc::new(HttpProxy::new()),
            scaling: None,
            mirrors: HashMap::new(),
            failovers: HashMap::new(),
            access_log: Arc::new(crate::observability::access_log::AccessLog::new()),
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(start_entrypoints(&config, state));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid address"));
    }
}
