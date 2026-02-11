//! Entrypoint — network listeners for HTTP/HTTPS/TCP
//!
//! Manages the lifecycle of network listeners that accept incoming
//! connections and dispatch them to the router.

use crate::config::{GatewayConfig, Protocol};
use crate::error::{GatewayError, Result};
use crate::middleware::{Pipeline, RequestContext};
use crate::proxy::tcp;
use crate::proxy::HttpProxy;
use crate::router::RouterTable;
use crate::service::ServiceRegistry;
use bytes::Bytes;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Shared state for request handling
pub struct GatewayState {
    pub router_table: Arc<RouterTable>,
    pub service_registry: Arc<ServiceRegistry>,
    pub middleware_configs: Arc<HashMap<String, crate::config::MiddlewareConfig>>,
    pub http_proxy: Arc<HttpProxy>,
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
                    state.clone(),
                )
                .await?;
                handles.push(handle);
            }
            Protocol::Udp => {
                tracing::warn!(entrypoint = name, "UDP entrypoints not yet implemented");
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
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        GatewayError::Other(format!("Failed to bind {}: {}", addr, e))
    })?;

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
    state: Arc<GatewayState>,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = TcpListener::bind(addr).await.map_err(|e| {
        GatewayError::Other(format!("Failed to bind TCP {}: {}", addr, e))
    })?;

    tracing::info!(entrypoint = name, address = %addr, "TCP entrypoint listening");

    let handle = tokio::spawn(async move {
        loop {
            let (client_stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to accept TCP connection");
                    continue;
                }
            };

            let state = state.clone();
            let ep_name = name.clone();

            tokio::spawn(async move {
                // For TCP, use the first router that matches this entrypoint
                let headers = HashMap::new();
                if let Some(route) = state.router_table.match_request(
                    None, "/", "TCP", &headers, &ep_name,
                ) {
                    if let Some(lb) = state.service_registry.get(&route.service_name) {
                        if let Some(backend) = lb.next_backend() {
                            let address = tcp::extract_address(&backend.url);
                            match tcp::connect_upstream(address).await {
                                Ok(upstream_stream) => {
                                    backend.inc_connections();
                                    let result = tcp::relay_tcp(
                                        client_stream,
                                        upstream_stream,
                                    )
                                    .await;
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
    let pipeline = match Pipeline::from_config(
        &route.middlewares,
        &state.middleware_configs,
    ) {
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

    // Select backend
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

    let backend = match lb.next_backend() {
        Some(b) => b,
        None => {
            return Ok(hyper::Response::builder()
                .status(503)
                .body(http_body_util::Full::new(Bytes::from(
                    r#"{"error":"No healthy backends"}"#,
                )))
                .unwrap());
        }
    };

    // Forward to backend
    match state
        .http_proxy
        .forward(&backend, &req_parts.method, &req_parts.uri, &req_parts.headers, body_bytes)
        .await
    {
        Ok(proxy_resp) => {
            let mut builder = hyper::Response::builder().status(proxy_resp.status.as_u16());
            for (key, value) in proxy_resp.headers.iter() {
                builder = builder.header(key, value);
            }
            Ok(builder
                .body(http_body_util::Full::new(proxy_resp.body))
                .unwrap())
        }
        Err(e) => {
            tracing::error!(error = %e, backend = backend.url, "Proxy error");
            Ok(hyper::Response::builder()
                .status(502)
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
    use crate::config::EntrypointConfig;
    use super::*;

    #[test]
    fn test_invalid_address() {
        let config = GatewayConfig {
            entrypoints: {
                let mut m = HashMap::new();
                m.insert("bad".to_string(), EntrypointConfig {
                    address: "not-an-address".to_string(),
                    protocol: Protocol::Http,
                    tls: None,
                });
                m
            },
            ..GatewayConfig::default()
        };

        let state = Arc::new(GatewayState {
            router_table: Arc::new(RouterTable::from_config(&HashMap::new()).unwrap()),
            service_registry: Arc::new(ServiceRegistry::from_config(&HashMap::new()).unwrap()),
            middleware_configs: Arc::new(HashMap::new()),
            http_proxy: Arc::new(HttpProxy::new()),
        });

        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(start_entrypoints(&config, state));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid address"));
    }
}
