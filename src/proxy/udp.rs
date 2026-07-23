//! UDP proxy — bidirectional datagram relay
//!
//! Handles UDP proxying by receiving datagrams from clients and forwarding
//! them to upstream backends, then relaying responses back.

use crate::error::{GatewayError, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Default session timeout for UDP "connections"
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum datagram size
pub(crate) const MAX_DATAGRAM_SIZE: usize = 65535;

/// UDP proxy configuration
#[derive(Debug, Clone)]
pub struct UdpProxyConfig {
    /// Session timeout — how long to keep a client→upstream mapping alive
    pub session_timeout: Duration,
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
}

impl Default for UdpProxyConfig {
    fn default() -> Self {
        Self {
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            max_sessions: 10000,
        }
    }
}

impl UdpProxyConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.session_timeout.is_zero() {
            return Err(GatewayError::Config(
                "udp_session_timeout_secs must be greater than zero".to_string(),
            ));
        }
        if self.max_sessions == 0 {
            return Err(GatewayError::Config(
                "udp_max_sessions must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }
}

/// A UDP session — maps a client address to an upstream socket
struct UdpSession {
    /// Socket used to communicate with the upstream
    upstream_socket: Arc<UdpSocket>,
    /// Exact upstream selected when the session was established.
    upstream_addr: String,
    /// Last activity timestamp
    last_active: Instant,
    /// Monotonic identity used to prevent an expired response task from
    /// removing a replacement session for the same client.
    id: u64,
    /// Response relay task for immediate cancellation on target replacement.
    response_task: tokio::task::AbortHandle,
}

/// UDP proxy — relays datagrams between clients and upstream
pub struct UdpProxy {
    config: UdpProxyConfig,
    /// Active sessions: client_addr → session
    sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>>,
    next_session_id: AtomicU64,
    /// A replaced policy rejects new work and drops late responses.
    active: Arc<AtomicBool>,
}

impl UdpProxy {
    /// Create a new UDP proxy
    pub fn new(config: UdpProxyConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_session_id: AtomicU64::new(1),
            active: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Get the configuration
    #[cfg(test)]
    pub fn config(&self) -> &UdpProxyConfig {
        &self.config
    }

    /// Get the number of active sessions
    #[cfg(test)]
    pub fn session_count(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Stop this policy from accepting work or returning late responses.
    pub(crate) fn deactivate(&self) {
        if self.active.swap(false, Ordering::AcqRel) {
            let sessions = {
                let mut active_sessions = self
                    .sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::mem::take(&mut *active_sessions)
            };
            for session in sessions.into_values() {
                session.response_task.abort();
            }
        }
    }

    /// Return the upstream currently pinned to a client session.
    pub(crate) fn session_upstream(&self, client_addr: SocketAddr) -> Option<String> {
        self.sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&client_addr)
            .map(|session| session.upstream_addr.clone())
    }

    /// Remove one client session and stop its response relay.
    pub(crate) fn remove_session(&self, client_addr: SocketAddr) {
        if let Some(session) = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&client_addr)
        {
            session.response_task.abort();
        }
    }

    /// Forward a datagram to an explicitly selected upstream.
    ///
    /// A session is reused while its selected upstream remains unchanged. If
    /// routing or health chooses another target, the old response relay is
    /// cancelled before the replacement session becomes active.
    pub(crate) async fn forward_to(
        &self,
        client_addr: SocketAddr,
        upstream_addr: &str,
        data: &[u8],
        listener: &Arc<UdpSocket>,
    ) -> Result<usize> {
        if !self.active.load(Ordering::Acquire) {
            return Err(GatewayError::Other(
                "UDP listener policy has been replaced".to_string(),
            ));
        }

        let existing_session = {
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(session) = sessions.get_mut(&client_addr) {
                if session.upstream_addr == upstream_addr {
                    session.last_active = Instant::now();
                    Some((session.upstream_socket.clone(), session.id))
                } else {
                    if let Some(stale) = sessions.remove(&client_addr) {
                        stale.response_task.abort();
                    }
                    None
                }
            } else {
                None
            }
        };
        if let Some((socket, session_id)) = existing_session {
            if !self.active.load(Ordering::Acquire) {
                return Err(GatewayError::Other(
                    "UDP listener policy has been replaced".to_string(),
                ));
            }
            return match socket.send(data).await {
                Ok(bytes_sent) => Ok(bytes_sent),
                Err(error) => {
                    let mut sessions = self
                        .sessions
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if sessions
                        .get(&client_addr)
                        .is_some_and(|session| session.id == session_id)
                    {
                        if let Some(session) = sessions.remove(&client_addr) {
                            session.response_task.abort();
                        }
                    }
                    Err(GatewayError::Other(format!(
                        "UDP send to upstream failed: {error}"
                    )))
                }
            };
        }

        {
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if sessions.len() >= self.config.max_sessions {
                let now = Instant::now();
                sessions.retain(|_, session| {
                    let keep =
                        now.duration_since(session.last_active) < self.config.session_timeout;
                    if !keep {
                        session.response_task.abort();
                    }
                    keep
                });
            }
            if sessions.len() >= self.config.max_sessions {
                return Err(GatewayError::Other("UDP session limit reached".to_string()));
            }
        }

        let upstream_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|error| {
            GatewayError::Other(format!("Failed to bind UDP upstream socket: {error}"))
        })?;
        upstream_socket
            .connect(upstream_addr)
            .await
            .map_err(|error| {
                GatewayError::ServiceUnavailable(format!(
                    "UDP upstream {upstream_addr} unreachable: {error}"
                ))
            })?;
        let upstream_socket = Arc::new(upstream_socket);
        let session_id = self.next_session_id.fetch_add(1, Ordering::Relaxed);

        let response_socket = upstream_socket.clone();
        let response_listener = listener.clone();
        let sessions_ref = self.sessions.clone();
        let active = self.active.clone();
        let timeout = self.config.session_timeout;
        let response_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            loop {
                if !active.load(Ordering::Acquire) {
                    break;
                }
                match tokio::time::timeout(timeout, response_socket.recv(&mut buf)).await {
                    Ok(Ok(length)) => {
                        if !active.load(Ordering::Acquire) {
                            break;
                        }
                        let is_current = sessions_ref
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .get(&client_addr)
                            .is_some_and(|session| session.id == session_id);
                        if !is_current {
                            break;
                        }
                        if response_listener
                            .send_to(&buf[..length], client_addr)
                            .await
                            .is_err()
                        {
                            break;
                        }
                        if let Some(session) = sessions_ref
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .get_mut(&client_addr)
                            .filter(|session| session.id == session_id)
                        {
                            session.last_active = Instant::now();
                        } else {
                            break;
                        }
                    }
                    Ok(Err(_)) | Err(_) => break,
                }
            }

            let mut sessions = sessions_ref
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if sessions
                .get(&client_addr)
                .is_some_and(|session| session.id == session_id)
            {
                sessions.remove(&client_addr);
            }
        });
        let response_abort = response_task.abort_handle();
        drop(response_task);

        if !self.active.load(Ordering::Acquire) {
            response_abort.abort();
            return Err(GatewayError::Other(
                "UDP listener policy has been replaced".to_string(),
            ));
        }

        {
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !self.active.load(Ordering::Acquire) {
                response_abort.abort();
                return Err(GatewayError::Other(
                    "UDP listener policy has been replaced".to_string(),
                ));
            }
            if let Some(stale) = sessions.remove(&client_addr) {
                stale.response_task.abort();
            }
            sessions.insert(
                client_addr,
                UdpSession {
                    upstream_socket: upstream_socket.clone(),
                    upstream_addr: upstream_addr.to_string(),
                    last_active: Instant::now(),
                    id: session_id,
                    response_task: response_abort.clone(),
                },
            );
        }

        match upstream_socket.send(data).await {
            Ok(bytes_sent) => Ok(bytes_sent),
            Err(error) => {
                let mut sessions = self
                    .sessions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if sessions
                    .get(&client_addr)
                    .is_some_and(|session| session.id == session_id)
                {
                    if let Some(session) = sessions.remove(&client_addr) {
                        session.response_task.abort();
                    }
                }
                Err(GatewayError::Other(format!(
                    "UDP send to upstream failed: {error}"
                )))
            }
        }
    }

    /// Evict expired sessions
    #[cfg(test)]
    pub fn evict_expired(&self) -> usize {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = sessions.len();
        let now = Instant::now();
        sessions.retain(|_, session| {
            let keep = now.duration_since(session.last_active) < self.config.session_timeout;
            if !keep {
                session.response_task.abort();
            }
            keep
        });
        before - sessions.len()
    }
}

impl Drop for UdpProxy {
    fn drop(&mut self) {
        self.deactivate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- UdpProxyConfig ---

    #[test]
    fn test_config_default() {
        let config = UdpProxyConfig::default();
        assert_eq!(config.session_timeout, Duration::from_secs(30));
        assert_eq!(config.max_sessions, 10000);
    }

    #[test]
    fn test_config_custom() {
        let config = UdpProxyConfig {
            session_timeout: Duration::from_secs(60),
            max_sessions: 5000,
        };
        assert_eq!(config.session_timeout, Duration::from_secs(60));
        assert_eq!(config.max_sessions, 5000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_rejects_zero_limits() {
        let zero_timeout = UdpProxyConfig {
            session_timeout: Duration::ZERO,
            ..Default::default()
        };
        assert!(zero_timeout.validate().is_err());

        let zero_sessions = UdpProxyConfig {
            max_sessions: 0,
            ..Default::default()
        };
        assert!(zero_sessions.validate().is_err());
    }

    // --- UdpProxy construction ---

    #[test]
    fn test_proxy_new() {
        let proxy = UdpProxy::new(UdpProxyConfig::default());
        assert_eq!(proxy.config().max_sessions, 10000);
    }

    #[test]
    fn test_proxy_initial_session_count() {
        let proxy = UdpProxy::new(UdpProxyConfig::default());
        assert_eq!(proxy.session_count(), 0);
    }

    // --- Session eviction ---

    #[test]
    fn test_evict_expired_empty() {
        let proxy = UdpProxy::new(UdpProxyConfig::default());
        let evicted = proxy.evict_expired();
        assert_eq!(evicted, 0);
    }

    #[tokio::test]
    async fn test_session_limit_rejects_a_new_client() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_address = upstream.local_addr().unwrap().to_string();
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy = UdpProxy::new(UdpProxyConfig {
            max_sessions: 1,
            ..Default::default()
        });
        let first_client = SocketAddr::from(([127, 0, 0, 1], 10_001));
        let second_client = SocketAddr::from(([127, 0, 0, 1], 10_002));

        proxy
            .forward_to(first_client, &upstream_address, b"first", &listener)
            .await
            .unwrap();
        let error = proxy
            .forward_to(second_client, &upstream_address, b"second", &listener)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("session limit"));
        assert_eq!(proxy.session_count(), 1);
        proxy.deactivate();
        assert_eq!(proxy.session_count(), 0);
    }

    #[tokio::test]
    async fn test_deactivated_policy_rejects_new_datagrams() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy = UdpProxy::new(UdpProxyConfig::default());
        proxy.deactivate();

        let error = proxy
            .forward_to(
                SocketAddr::from(([127, 0, 0, 1], 10_001)),
                &upstream.local_addr().unwrap().to_string(),
                b"rejected",
                &listener,
            )
            .await
            .unwrap_err();

        assert!(error.to_string().contains("replaced"));
        assert_eq!(proxy.session_count(), 0);
    }

    // --- UDP relay integration test ---

    #[tokio::test]
    async fn test_udp_echo_relay() {
        // Start an echo UDP server
        let echo_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_server.local_addr().unwrap();

        let echo_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            while let Ok((n, addr)) = echo_server.recv_from(&mut buf).await {
                let _ = echo_server.send_to(&buf[..n], addr).await;
            }
        });

        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy = UdpProxy::new(UdpProxyConfig {
            session_timeout: Duration::from_secs(5),
            ..Default::default()
        });
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        proxy
            .forward_to(
                client.local_addr().unwrap(),
                &echo_addr.to_string(),
                b"hello",
                &listener,
            )
            .await
            .unwrap();

        let mut buf = vec![0u8; 1024];
        let (length, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("UDP echo response timed out")
            .unwrap();
        assert_eq!(&buf[..length], b"hello");
        echo_task.abort();
    }

    // --- Constants ---

    #[test]
    fn test_max_datagram_size() {
        assert_eq!(MAX_DATAGRAM_SIZE, 65535);
    }

    #[test]
    fn test_default_session_timeout() {
        assert_eq!(DEFAULT_SESSION_TIMEOUT, Duration::from_secs(30));
    }
}
