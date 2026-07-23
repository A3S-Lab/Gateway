//! Entrypoint listener lifecycle and in-place transport reconfiguration.

use super::{handle_http_request, udp_listener, GatewayRuntime};
use crate::config::{EntrypointConfig, GatewayConfig, Protocol};
use crate::error::{GatewayError, Result};
use crate::middleware::TcpFilter;
use crate::proxy::tcp;
use crate::proxy::ForwardedProto;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

pub(crate) type EntryPointHandles = HashMap<String, EntryPointHandle>;

pub(crate) struct EntryPointHandle {
    task: tokio::task::JoinHandle<()>,
    control: EntrypointControl,
}

enum EntrypointControl {
    Http(Arc<RwLock<Option<TlsAcceptor>>>),
    Tcp(Arc<RwLock<Arc<TcpFilter>>>),
    Udp(udp_listener::UdpEntrypointControl),
}

/// A fully validated listener-policy update that cannot fail during commit.
pub(crate) enum PreparedEntrypointReconfigure {
    Http {
        target: Arc<RwLock<Option<TlsAcceptor>>>,
        next: Option<TlsAcceptor>,
    },
    Tcp {
        target: Arc<RwLock<Arc<TcpFilter>>>,
        next: Arc<TcpFilter>,
    },
    Udp(udp_listener::PreparedUdpReconfigure),
}

impl PreparedEntrypointReconfigure {
    pub(crate) fn commit(self) {
        match self {
            Self::Http { target, next } => {
                *target
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = next;
            }
            Self::Tcp { target, next } => {
                *target
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = next;
            }
            Self::Udp(prepared) => prepared.commit(),
        }
    }
}

impl EntryPointHandle {
    pub(crate) fn abort(&self) {
        self.task.abort();
    }

    pub(crate) fn into_task(self) -> tokio::task::JoinHandle<()> {
        self.task
    }

    pub(crate) fn prepare_reconfigure(
        &self,
        config: &EntrypointConfig,
    ) -> Result<PreparedEntrypointReconfigure> {
        match (&self.control, &config.protocol) {
            (EntrypointControl::Http(current), Protocol::Http) => {
                let acceptor = config
                    .tls
                    .as_ref()
                    .map(crate::proxy::tls::build_tls_acceptor)
                    .transpose()?;
                Ok(PreparedEntrypointReconfigure::Http {
                    target: current.clone(),
                    next: acceptor,
                })
            }
            (EntrypointControl::Tcp(target), Protocol::Tcp) => {
                let current = target
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let filter =
                    current.reconfigured(config.max_connections, &config.tcp_allowed_ips)?;
                Ok(PreparedEntrypointReconfigure::Tcp {
                    target: target.clone(),
                    next: Arc::new(filter),
                })
            }
            (EntrypointControl::Udp(target), Protocol::Udp) => Ok(
                PreparedEntrypointReconfigure::Udp(target.prepare_reconfigure(config)?),
            ),
            _ => Err(GatewayError::Config(
                "Entrypoint protocol cannot be changed in place".to_string(),
            )),
        }
    }
}

/// Start all entrypoints defined in the configuration.
pub(crate) async fn start_entrypoints(
    config: &GatewayConfig,
    runtime: GatewayRuntime,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<EntryPointHandles> {
    let mut handles = HashMap::new();

    for (name, ep_config) in &config.entrypoints {
        let addr: SocketAddr = ep_config.address.parse().map_err(|error| {
            GatewayError::Config(format!(
                "Invalid address '{}' for entrypoint '{}': {}",
                ep_config.address, name, error
            ))
        })?;

        let handle_result = match ep_config.protocol {
            Protocol::Http => {
                start_http_entrypoint(
                    name.clone(),
                    addr,
                    ep_config.tls.as_ref(),
                    runtime.clone(),
                    shutdown_rx.clone(),
                )
                .await
            }
            Protocol::Tcp => {
                start_tcp_entrypoint(
                    name.clone(),
                    addr,
                    ep_config.max_connections,
                    &ep_config.tcp_allowed_ips,
                    runtime.clone(),
                )
                .await
            }
            Protocol::Udp => udp_listener::start(name.clone(), addr, ep_config, runtime.clone())
                .await
                .map(|(task, control)| EntryPointHandle {
                    task,
                    control: EntrypointControl::Udp(control),
                }),
        };

        match handle_result {
            Ok(handle) => {
                handles.insert(name.clone(), handle);
            }
            Err(error) => {
                for handle in handles.values() {
                    handle.abort();
                }
                return Err(error);
            }
        }
    }

    Ok(handles)
}

/// Validate entrypoint settings that are only checked when listeners start.
pub(crate) fn validate_entrypoints(config: &GatewayConfig) -> Result<()> {
    for (name, ep_config) in &config.entrypoints {
        ep_config.address.parse::<SocketAddr>().map_err(|error| {
            GatewayError::Config(format!(
                "Invalid address '{}' for entrypoint '{}': {}",
                ep_config.address, name, error
            ))
        })?;

        match ep_config.protocol {
            Protocol::Http => {
                if let Some(tls) = &ep_config.tls {
                    crate::proxy::tls::build_tls_acceptor(tls)?;
                }
            }
            Protocol::Tcp => {
                TcpFilter::new(ep_config.max_connections, &ep_config.tcp_allowed_ips)?;
            }
            Protocol::Udp => {
                udp_listener::validate_entrypoint(ep_config)?;
            }
        }
    }

    Ok(())
}

/// Start an HTTP/HTTPS entrypoint.
pub(super) async fn start_http_entrypoint(
    name: String,
    addr: SocketAddr,
    tls_config: Option<&crate::config::TlsConfig>,
    runtime: GatewayRuntime,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<EntryPointHandle> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|error| GatewayError::Other(format!("Failed to bind {}: {}", addr, error)))?;

    let initial_acceptor = tls_config
        .map(crate::proxy::tls::build_tls_acceptor)
        .transpose()?;
    let tls_acceptor = Arc::new(RwLock::new(initial_acceptor));

    tracing::info!(
        entrypoint = name,
        address = %addr,
        tls = tls_acceptor
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some(),
        "HTTP entrypoint listening"
    );

    let ep_name = name.clone();
    let active_tls_acceptor = tls_acceptor.clone();
    let task = tokio::spawn(async move {
        let mut connection_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();

        loop {
            connection_handles.retain(|handle| !handle.is_finished());

            tokio::select! {
                result = listener.accept() => {
                    let (stream, remote_addr) = match result {
                        Ok(connection) => connection,
                        Err(error) => {
                            tracing::error!(error = %error, "Failed to accept connection");
                            continue;
                        }
                    };

                    let runtime = runtime.clone();
                    let ep_name = ep_name.clone();
                    let tls_acceptor = active_tls_acceptor
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();

                    let connection_handle = tokio::spawn(async move {
                        let metrics = runtime.load().metrics.clone();
                        metrics.inc_connections();
                        if let Some(acceptor) = tls_acceptor {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let io = TokioIo::new(tls_stream);
                                    let _ = auto::Builder::new(TokioExecutor::new())
                                        .serve_connection_with_upgrades(
                                            io,
                                            service_fn(|request| {
                                                let state = runtime.load();
                                                handle_http_request(
                                                    request,
                                                    remote_addr,
                                                    ep_name.clone(),
                                                    ForwardedProto::Https,
                                                    state,
                                                )
                                            }),
                                        )
                                        .await;
                                }
                                Err(error) => {
                                    tracing::debug!(error = %error, "TLS handshake failed");
                                }
                            }
                        } else {
                            let io = TokioIo::new(stream);
                            let _ = auto::Builder::new(TokioExecutor::new())
                                .serve_connection_with_upgrades(
                                    io,
                                    service_fn(|request| {
                                        let state = runtime.load();
                                        handle_http_request(
                                            request,
                                            remote_addr,
                                            ep_name.clone(),
                                            ForwardedProto::Http,
                                            state,
                                        )
                                    }),
                                )
                                .await;
                        }
                        metrics.dec_connections();
                    });
                    connection_handles.push(connection_handle);
                }
                _ = shutdown_rx.changed() => {
                    tracing::info!(
                        entrypoint = ep_name,
                        "Shutdown signal received, draining connections"
                    );
                    break;
                }
            }
        }

        let drain_timeout = Duration::from_secs(30);
        let drain_deadline = tokio::time::Instant::now() + drain_timeout;
        for mut handle in connection_handles {
            let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                handle.abort();
            } else {
                tokio::select! {
                    _ = &mut handle => {}
                    _ = tokio::time::sleep(remaining) => {
                        handle.abort();
                        tracing::warn!(
                            entrypoint = ep_name,
                            "Connection drain timeout, aborting remaining"
                        );
                        break;
                    }
                }
            }
        }
    });

    Ok(EntryPointHandle {
        task,
        control: EntrypointControl::Http(tls_acceptor),
    })
}

/// Start a TCP entrypoint.
async fn start_tcp_entrypoint(
    name: String,
    addr: SocketAddr,
    max_connections: Option<u32>,
    tcp_allowed_ips: &[String],
    runtime: GatewayRuntime,
) -> Result<EntryPointHandle> {
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|error| GatewayError::Other(format!("Failed to bind TCP {}: {}", addr, error)))?;

    let tcp_filter = Arc::new(RwLock::new(Arc::new(TcpFilter::new(
        max_connections,
        tcp_allowed_ips,
    )?)));

    tracing::info!(
        entrypoint = name,
        address = %addr,
        max_connections = ?max_connections,
        ip_filter = !tcp_allowed_ips.is_empty(),
        "TCP entrypoint listening"
    );

    let active_tcp_filter = tcp_filter.clone();
    let task = tokio::spawn(async move {
        loop {
            let (client_stream, remote_addr) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::error!(error = %error, "Failed to accept TCP connection");
                    continue;
                }
            };

            let tcp_filter = active_tcp_filter
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let permit = match tcp_filter.check_connection(&remote_addr.ip().to_string()) {
                Ok(permit) => permit,
                Err(error) => {
                    tracing::debug!(
                        error = %error,
                        remote = %remote_addr,
                        "TCP connection rejected by filter"
                    );
                    continue;
                }
            };

            let runtime = runtime.clone();
            let ep_name = name.clone();

            tokio::spawn(async move {
                let _permit = permit;
                let state = runtime.load();

                let headers = http::HeaderMap::new();
                if let Some(route) = state
                    .router_table
                    .match_request(None, "/", "TCP", &headers, &ep_name)
                {
                    if let Some(load_balancer) = state.service_registry.get(&route.service_name) {
                        if let Some(backend) = load_balancer.next_backend() {
                            let address = tcp::extract_address(&backend.url);
                            match tcp::connect_upstream(address).await {
                                Ok(upstream_stream) => {
                                    backend.inc_connections();
                                    let result =
                                        tcp::relay_tcp(client_stream, upstream_stream).await;
                                    backend.dec_connections();

                                    if let Err(error) = result {
                                        tracing::debug!(
                                            error = %error,
                                            remote = %remote_addr,
                                            "TCP relay ended"
                                        );
                                    }
                                }
                                Err(error) => {
                                    tracing::warn!(
                                        error = %error,
                                        backend = backend.url,
                                        "TCP upstream connection failed"
                                    );
                                }
                            }
                        }
                    }
                } else {
                    tracing::debug!(remote = %remote_addr, "No TCP route matched");
                }
            });
        }
    });

    Ok(EntryPointHandle {
        task,
        control: EntrypointControl::Tcp(tcp_filter),
    })
}
