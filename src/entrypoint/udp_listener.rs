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
        let next = Arc::new(udp::UdpProxy::new(proxy_config(config)?));
        Ok(PreparedUdpReconfigure {
            target: self.current.clone(),
            next,
        })
    }
}

pub(crate) fn validate_entrypoint(config: &EntrypointConfig) -> Result<()> {
    proxy_config(config).map(|_| ())
}

pub(crate) async fn start(
    name: String,
    address: SocketAddr,
    config: &EntrypointConfig,
    runtime: GatewayRuntime,
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
        loop {
            let (length, client_addr) = match socket.recv_from(&mut buffer).await {
                Ok(datagram) => datagram,
                Err(error) => {
                    tracing::error!(error = %error, "UDP receive error");
                    continue;
                }
            };
            let proxy = active_proxy
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let state = runtime.load();
            let headers = http::HeaderMap::new();
            let load_balancer = state
                .router_table
                .match_request(None, "/", "UDP", &headers, &name)
                .and_then(|route| state.service_registry.get(&route.service_name));
            let Some(load_balancer) = load_balancer else {
                proxy.remove_session(client_addr);
                tracing::debug!(
                    entrypoint = name,
                    client = %client_addr,
                    "No UDP route or service matched"
                );
                continue;
            };

            let current_upstream = proxy.session_upstream(client_addr);
            let upstream_address = current_upstream
                .filter(|current| {
                    load_balancer.backends().iter().any(|backend| {
                        backend.is_healthy()
                            && crate::proxy::tcp::extract_address(&backend.url) == current
                    })
                })
                .or_else(|| {
                    load_balancer
                        .next_backend()
                        .map(|backend| crate::proxy::tcp::extract_address(&backend.url).to_string())
                });
            let Some(upstream_address) = upstream_address else {
                proxy.remove_session(client_addr);
                tracing::debug!(
                    entrypoint = name,
                    client = %client_addr,
                    "No healthy UDP backend available"
                );
                continue;
            };

            if let Err(error) = proxy
                .forward_to(client_addr, &upstream_address, &buffer[..length], &socket)
                .await
            {
                tracing::debug!(
                    error = %error,
                    entrypoint = name,
                    client = %client_addr,
                    "UDP forward failed"
                );
            }
        }
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
