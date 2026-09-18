//! UDP entrypoint lifecycle, routing, and in-place session-policy replacement.

use super::GatewayRuntime;
use crate::config::EntrypointConfig;
use crate::error::{GatewayError, Result};
use crate::proxy::udp::{self, UdpProxyConfig};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;

pub(crate) struct UdpEntrypointControl {
    current: Arc<RwLock<Arc<udp::UdpProxy>>>,
}

pub(crate) struct PreparedUdpReconfigure {
    target: Arc<RwLock<Arc<udp::UdpProxy>>>,
    next: Arc<udp::UdpProxy>,
}

impl PreparedUdpReconfigure {
    pub(crate) fn commit(self) {
        let previous = {
            let mut current = self
                .target
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if Arc::ptr_eq(&*current, &self.next) {
                // Same session policy: keep sticky sessions so exact-generation
                // retirement can drain established UDP clients.
                return;
            }
            std::mem::replace(&mut *current, self.next)
        };
        previous.deactivate();
    }
}

impl UdpEntrypointControl {
    pub(crate) fn prepare_reconfigure(
        &self,
        config: &EntrypointConfig,
    ) -> Result<PreparedUdpReconfigure> {
        let next_config = proxy_config(config)?;
        let current = self
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let next = if current.matches_session_policy(&next_config) {
            current
        } else {
            Arc::new(udp::UdpProxy::new(next_config))
        };
        Ok(PreparedUdpReconfigure {
            target: self.current.clone(),
            next,
        })
    }
}

pub(crate) async fn start(
    name: String,
    address: SocketAddr,
    config: &EntrypointConfig,
    runtime: GatewayRuntime,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(tokio::task::JoinHandle<()>, UdpEntrypointControl)> {
    let proxy_config = proxy_config(config)?;
    let timeout = proxy_config.session_timeout;
    let max_sessions = proxy_config.max_sessions;
    let socket = Arc::new(UdpSocket::bind(address).await.map_err(|error| {
        GatewayError::Other(format!("Failed to bind UDP socket on {address}: {error}"))
    })?);
    let current = Arc::new(RwLock::new(Arc::new(udp::UdpProxy::new(proxy_config))));

    tracing::info!(
        entrypoint = name,
        address = %address,
        session_timeout_secs = timeout.as_secs(),
        max_sessions,
        "UDP entrypoint listening"
    );

    let active_proxy = current.clone();
    let task = tokio::spawn(async move {
        let mut buffer = vec![0_u8; udp::MAX_DATAGRAM_SIZE];
        let shutdown = super::listener::shutdown_signal(shutdown_rx);
        tokio::pin!(shutdown);
        loop {
            let (length, client_addr) = tokio::select! {
                biased;
                _ = &mut shutdown => {
                    break;
                }
                result = socket.recv_from(&mut buffer) => {
                    match result {
                        Ok(datagram) => datagram,
                        Err(error) => {
                            tracing::error!(error = %error, "UDP receive error");
                            continue;
                        }
                    }
                }
            };
            if !runtime.allows_traffic() {
                let proxy = active_proxy
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone();
                proxy.remove_session(client_addr);
                tracing::debug!(client = %client_addr, "UDP datagram rejected because managed snapshot expired");
                continue;
            }
            let proxy = active_proxy
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let state = runtime.load();
            let headers = http::HeaderMap::new();
            let Some(route) = state
                .router_table
                .match_request(None, "/", "UDP", &headers, &name)
            else {
                proxy.remove_session(client_addr);
                tracing::debug!(
                    entrypoint = name,
                    client = %client_addr,
                    "No UDP route or service matched"
                );
                continue;
            };
            let service_name = route.service_name.clone();
            if state.service_registry.get(&service_name).is_none() {
                proxy.remove_session(client_addr);
                tracing::debug!(
                    entrypoint = name,
                    client = %client_addr,
                    service = %service_name,
                    "UDP route references an unknown service"
                );
                continue;
            }

            let current_upstream = proxy.session_upstream(client_addr);
            let candidates = super::backend_candidates_for_service(&state, &service_name);
            let sticky_upstream = current_upstream.filter(|current| {
                let matching: Vec<_> = candidates
                    .iter()
                    .filter(|backend| {
                        crate::proxy::tcp::extract_address(&backend.url) == current.as_str()
                    })
                    .collect();
                if matching.is_empty() {
                    // Exact generation left the live registry: keep the
                    // established session pinned until timeout so drain can
                    // finish. New clients still select admitting backends.
                    true
                } else {
                    matching.iter().any(|backend| backend.is_healthy())
                }
            });
            let selected = if let Some(upstream_address) = sticky_upstream {
                Some((upstream_address, None, None))
            } else {
                super::select_backend_for_service(&state, &service_name).and_then(|backend| {
                    let connection = backend.try_track_connection_on(0)?;
                    Some((
                        crate::proxy::tcp::extract_address(&backend.url).to_string(),
                        Some(connection),
                        Some(backend),
                    ))
                })
            };
            let Some((upstream_address, connection, dial_backend)) = selected else {
                proxy.remove_session(client_addr);
                tracing::debug!(
                    entrypoint = name,
                    client = %client_addr,
                    "No healthy UDP backend available"
                );
                continue;
            };

            if let Err(error) = proxy
                .forward_to(
                    client_addr,
                    &upstream_address,
                    &buffer[..length],
                    &socket,
                    connection,
                )
                .await
            {
                tracing::debug!(
                    error = %error,
                    entrypoint = name,
                    client = %client_addr,
                    "UDP forward failed"
                );
                let backend = dial_backend.or_else(|| {
                    candidates
                        .iter()
                        .find(|backend| {
                            crate::proxy::tcp::extract_address(&backend.url) == upstream_address
                        })
                        .cloned()
                });
                if let Some(backend) = backend {
                    super::protocol::record_upstream_dial_failure(
                        state.passive_health.get(&service_name).map(Arc::as_ref),
                        &backend,
                        &error,
                    );
                }
            }
        }

        let proxy = active_proxy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        proxy.deactivate();
        proxy.wait_inactive().await;
        tracing::info!(entrypoint = name, "UDP entrypoint stopped");
    });

    Ok((task, UdpEntrypointControl { current }))
}

fn proxy_config(config: &EntrypointConfig) -> Result<UdpProxyConfig> {
    let proxy_config = UdpProxyConfig {
        session_timeout: Duration::from_secs(config.udp_session_timeout_secs.unwrap_or(30)),
        max_sessions: config.udp_max_sessions.unwrap_or(10_000),
    };
    proxy_config.validate()?;
    Ok(proxy_config)
}
