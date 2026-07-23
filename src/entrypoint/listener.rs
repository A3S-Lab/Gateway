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
use hyper_util::server::graceful::GracefulShutdown;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinSet;
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
                    shutdown_rx.clone(),
                )
                .await
            }
            Protocol::Udp => udp_listener::start(
                name.clone(),
                addr,
                ep_config,
                runtime.clone(),
                shutdown_rx.clone(),
            )
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
                for (_, handle) in handles.drain() {
                    let task = handle.into_task();
                    task.abort();
                    let _ = task.await;
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
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
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
        let graceful = GracefulShutdown::new();
        let (upgraded_tx, mut upgraded_rx) =
            tokio::sync::mpsc::unbounded_channel::<super::UpgradedSession>();
        let mut connections = JoinSet::new();
        let mut upgraded_sessions = JoinSet::new();
        let shutdown = shutdown_signal(shutdown_rx);
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    break;
                }
                Some(session) = upgraded_rx.recv() => {
                    upgraded_sessions.spawn(session);
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    log_task_result(result, &ep_name, "HTTP connection");
                }
                Some(result) = upgraded_sessions.join_next(), if !upgraded_sessions.is_empty() => {
                    log_task_result(result, &ep_name, "upgraded session");
                }
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
                    let upgraded_tx = upgraded_tx.clone();
                    let graceful_watcher = graceful.watcher();
                    let tls_acceptor = active_tls_acceptor
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();

                    connections.spawn(async move {
                        let metrics = runtime.load().metrics.clone();
                        let _connection = metrics.track_connection();
                        if let Some(acceptor) = tls_acceptor {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    let io = TokioIo::new(tls_stream);
                                    let builder = auto::Builder::new(TokioExecutor::new());
                                    let connection = builder.serve_connection_with_upgrades(
                                        io,
                                        service_fn(move |request| {
                                            let state = runtime.load();
                                            handle_http_request(
                                                request,
                                                remote_addr,
                                                ep_name.clone(),
                                                ForwardedProto::Https,
                                                state,
                                                upgraded_tx.clone(),
                                            )
                                        }),
                                    );
                                    if let Err(error) = graceful_watcher.watch(connection).await {
                                        tracing::debug!(
                                            error = %error,
                                            remote = %remote_addr,
                                            "HTTPS connection ended"
                                        );
                                    }
                                }
                                Err(error) => {
                                    tracing::debug!(error = %error, "TLS handshake failed");
                                }
                            }
                        } else {
                            let io = TokioIo::new(stream);
                            let builder = auto::Builder::new(TokioExecutor::new());
                            let connection = builder.serve_connection_with_upgrades(
                                io,
                                service_fn(move |request| {
                                    let state = runtime.load();
                                    handle_http_request(
                                        request,
                                        remote_addr,
                                        ep_name.clone(),
                                        ForwardedProto::Http,
                                        state,
                                        upgraded_tx.clone(),
                                    )
                                }),
                            );
                            if let Err(error) = graceful_watcher.watch(connection).await {
                                tracing::debug!(
                                    error = %error,
                                    remote = %remote_addr,
                                    "HTTP connection ended"
                                );
                            }
                        }
                    });
                }
            }
        }

        drop(listener);
        drop(upgraded_tx);
        let drain_timeout = runtime.load().shutdown_timeout;
        tracing::info!(
            entrypoint = ep_name,
            timeout_secs = drain_timeout.as_secs(),
            "Shutdown signal received, draining connections"
        );

        let drain_deadline = tokio::time::Instant::now() + drain_timeout;
        let drain = async {
            let graceful_shutdown = graceful.shutdown();
            tokio::pin!(graceful_shutdown);
            let mut http_drained = false;
            let mut upgraded_channel_closed = false;

            while !(http_drained
                && upgraded_channel_closed
                && connections.is_empty()
                && upgraded_sessions.is_empty())
            {
                tokio::select! {
                    _ = &mut graceful_shutdown, if !http_drained => {
                        http_drained = true;
                    }
                    session = upgraded_rx.recv(), if !upgraded_channel_closed => {
                        match session {
                            Some(session) => {
                                upgraded_sessions.spawn(session);
                            }
                            None => {
                                upgraded_channel_closed = true;
                            }
                        }
                    }
                    Some(result) = connections.join_next(), if !connections.is_empty() => {
                        log_task_result(result, &ep_name, "HTTP connection");
                    }
                    Some(result) = upgraded_sessions.join_next(), if !upgraded_sessions.is_empty() => {
                        log_task_result(result, &ep_name, "upgraded session");
                    }
                }
            }
        };

        if tokio::time::timeout_at(drain_deadline, drain)
            .await
            .is_err()
        {
            tracing::warn!(
                entrypoint = ep_name,
                timeout_secs = drain_timeout.as_secs(),
                "Connection drain timeout, cancelling remaining work"
            );
            upgraded_rx.close();
            while upgraded_rx.try_recv().is_ok() {}
            connections.abort_all();
            upgraded_sessions.abort_all();
            join_cancelled_tasks(&mut connections, &ep_name, "HTTP connection").await;
            join_cancelled_tasks(&mut upgraded_sessions, &ep_name, "upgraded session").await;
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
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
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
        let mut relays = JoinSet::new();
        let shutdown = shutdown_signal(shutdown_rx);
        tokio::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => {
                    break;
                }
                Some(result) = relays.join_next(), if !relays.is_empty() => {
                    log_task_result(result, &name, "TCP relay");
                }
                result = listener.accept() => {
                    let (client_stream, remote_addr) = match result {
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

                    relays.spawn(async move {
                        let _permit = permit;
                        let state = runtime.load();

                        let headers = http::HeaderMap::new();
                        if let Some(route) = state
                            .router_table
                            .match_request(None, "/", "TCP", &headers, &ep_name)
                        {
                            if let Some(load_balancer) =
                                state.service_registry.get(&route.service_name)
                            {
                                if let Some(backend) = load_balancer.next_backend() {
                                    let address = tcp::extract_address(&backend.url);
                                    match tcp::connect_upstream(address).await {
                                        Ok(upstream_stream) => {
                                            let _connection = backend.track_connection();
                                            let result =
                                                tcp::relay_tcp(client_stream, upstream_stream).await;

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
            }
        }

        drop(listener);
        let drain_timeout = runtime.load().shutdown_timeout;
        tracing::info!(
            entrypoint = name,
            timeout_secs = drain_timeout.as_secs(),
            "Shutdown signal received, draining TCP relays"
        );
        drain_task_set(&mut relays, drain_timeout, &name, "TCP relay").await;
    });

    Ok(EntryPointHandle {
        task,
        control: EntrypointControl::Tcp(tcp_filter),
    })
}

pub(super) async fn shutdown_signal(mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

fn log_task_result(
    result: std::result::Result<(), tokio::task::JoinError>,
    entrypoint: &str,
    task_kind: &str,
) {
    if let Err(error) = result {
        if !error.is_cancelled() {
            tracing::warn!(
                entrypoint,
                task_kind,
                error = %error,
                "Entrypoint task failed"
            );
        }
    }
}

async fn join_cancelled_tasks(tasks: &mut JoinSet<()>, entrypoint: &str, task_kind: &str) {
    while let Some(result) = tasks.join_next().await {
        log_task_result(result, entrypoint, task_kind);
    }
}

async fn drain_task_set(
    tasks: &mut JoinSet<()>,
    drain_timeout: Duration,
    entrypoint: &str,
    task_kind: &str,
) {
    let drain_deadline = tokio::time::Instant::now() + drain_timeout;
    let drain = async {
        while let Some(result) = tasks.join_next().await {
            log_task_result(result, entrypoint, task_kind);
        }
    };

    if tokio::time::timeout_at(drain_deadline, drain)
        .await
        .is_err()
    {
        tracing::warn!(
            entrypoint,
            task_kind,
            timeout_secs = drain_timeout.as_secs(),
            "Entrypoint drain timeout, cancelling remaining work"
        );
        tasks.abort_all();
        join_cancelled_tasks(tasks, entrypoint, task_kind).await;
    }
}
