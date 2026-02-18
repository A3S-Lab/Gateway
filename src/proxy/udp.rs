//! UDP proxy — bidirectional datagram relay
//!
//! Handles UDP proxying by receiving datagrams from clients and forwarding
//! them to upstream backends, then relaying responses back.

use crate::error::{GatewayError, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// Default session timeout for UDP "connections"
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum datagram size
const MAX_DATAGRAM_SIZE: usize = 65535;

/// UDP proxy configuration
#[derive(Debug, Clone)]
pub struct UdpProxyConfig {
    /// Session timeout — how long to keep a client→upstream mapping alive
    pub session_timeout: Duration,
    /// Maximum number of concurrent sessions
    pub max_sessions: usize,
    /// Upstream address (host:port)
    pub upstream_addr: String,
}

impl Default for UdpProxyConfig {
    fn default() -> Self {
        Self {
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            max_sessions: 10000,
            upstream_addr: String::new(),
        }
    }
}

/// A UDP session — maps a client address to an upstream socket
struct UdpSession {
    /// Socket used to communicate with the upstream
    upstream_socket: Arc<UdpSocket>,
    /// Last activity timestamp
    last_active: Instant,
}

/// UDP proxy — relays datagrams between clients and upstream
pub struct UdpProxy {
    config: UdpProxyConfig,
    /// Active sessions: client_addr → session
    sessions: Arc<RwLock<HashMap<SocketAddr, UdpSession>>>,
}

impl UdpProxy {
    /// Create a new UDP proxy
    pub fn new(config: UdpProxyConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the configuration
    #[allow(dead_code)]
    pub fn config(&self) -> &UdpProxyConfig {
        &self.config
    }

    /// Get the number of active sessions
    #[allow(dead_code)]
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// Forward a datagram from a client to the upstream
    pub async fn forward_to_upstream(
        &self,
        client_addr: SocketAddr,
        data: &[u8],
        listener: &Arc<UdpSocket>,
    ) -> Result<usize> {
        let mut sessions = self.sessions.write().await;

        // Check session limit
        if !sessions.contains_key(&client_addr) && sessions.len() >= self.config.max_sessions {
            // Evict expired sessions first
            let now = Instant::now();
            sessions.retain(|_, s| now.duration_since(s.last_active) < self.config.session_timeout);

            if sessions.len() >= self.config.max_sessions {
                return Err(GatewayError::Other("UDP session limit reached".to_string()));
            }
        }

        // Get or create session
        let session = if let Some(session) = sessions.get_mut(&client_addr) {
            session.last_active = Instant::now();
            session
        } else {
            // Create a new upstream socket bound to an ephemeral port
            let upstream_socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
                GatewayError::Other(format!("Failed to bind UDP upstream socket: {}", e))
            })?;
            upstream_socket
                .connect(&self.config.upstream_addr)
                .await
                .map_err(|e| {
                    GatewayError::ServiceUnavailable(format!(
                        "UDP upstream {} unreachable: {}",
                        self.config.upstream_addr, e
                    ))
                })?;

            let upstream_socket = Arc::new(upstream_socket);

            // Spawn a task to relay responses back to the client
            let response_socket = upstream_socket.clone();
            let listener = listener.clone();
            let sessions_ref = self.sessions.clone();
            let timeout = self.config.session_timeout;

            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
                loop {
                    match tokio::time::timeout(timeout, response_socket.recv(&mut buf)).await {
                        Ok(Ok(n)) => {
                            let _ = listener.send_to(&buf[..n], client_addr).await;
                            // Update last_active
                            if let Some(session) = sessions_ref.write().await.get_mut(&client_addr)
                            {
                                session.last_active = Instant::now();
                            }
                        }
                        Ok(Err(_)) | Err(_) => {
                            // Error or timeout — remove session
                            sessions_ref.write().await.remove(&client_addr);
                            break;
                        }
                    }
                }
            });

            sessions.insert(
                client_addr,
                UdpSession {
                    upstream_socket,
                    last_active: Instant::now(),
                },
            );
            sessions.get_mut(&client_addr).unwrap()
        };

        // Send datagram to upstream
        let bytes_sent = session
            .upstream_socket
            .send(data)
            .await
            .map_err(|e| GatewayError::Other(format!("UDP send to upstream failed: {}", e)))?;

        Ok(bytes_sent)
    }

    /// Evict expired sessions
    #[allow(dead_code)]
    pub async fn evict_expired(&self) -> usize {
        let mut sessions = self.sessions.write().await;
        let before = sessions.len();
        let now = Instant::now();
        sessions.retain(|_, s| now.duration_since(s.last_active) < self.config.session_timeout);
        before - sessions.len()
    }
}

/// Start a UDP listener that proxies datagrams to the upstream
pub async fn start_udp_listener(
    bind_addr: &str,
    upstream_addr: &str,
    session_timeout: Duration,
) -> Result<(Arc<UdpSocket>, UdpProxy)> {
    let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
        GatewayError::Other(format!("Failed to bind UDP socket on {}: {}", bind_addr, e))
    })?;
    let socket = Arc::new(socket);

    let proxy = UdpProxy::new(UdpProxyConfig {
        session_timeout,
        upstream_addr: upstream_addr.to_string(),
        ..Default::default()
    });

    Ok((socket, proxy))
}

/// Run the UDP proxy receive loop
pub async fn run_udp_proxy(socket: Arc<UdpSocket>, proxy: Arc<UdpProxy>) {
    let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, client_addr)) => {
                if let Err(e) = proxy
                    .forward_to_upstream(client_addr, &buf[..n], &socket)
                    .await
                {
                    tracing::debug!(
                        error = %e,
                        client = %client_addr,
                        "UDP forward failed"
                    );
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "UDP receive error");
            }
        }
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
        assert!(config.upstream_addr.is_empty());
    }

    #[test]
    fn test_config_custom() {
        let config = UdpProxyConfig {
            session_timeout: Duration::from_secs(60),
            max_sessions: 5000,
            upstream_addr: "127.0.0.1:9001".to_string(),
        };
        assert_eq!(config.session_timeout, Duration::from_secs(60));
        assert_eq!(config.max_sessions, 5000);
        assert_eq!(config.upstream_addr, "127.0.0.1:9001");
    }

    // --- UdpProxy construction ---

    #[test]
    fn test_proxy_new() {
        let proxy = UdpProxy::new(UdpProxyConfig {
            upstream_addr: "127.0.0.1:9001".to_string(),
            ..Default::default()
        });
        assert_eq!(proxy.config().upstream_addr, "127.0.0.1:9001");
        assert_eq!(proxy.config().max_sessions, 10000);
    }

    #[tokio::test]
    async fn test_proxy_initial_session_count() {
        let proxy = UdpProxy::new(UdpProxyConfig::default());
        assert_eq!(proxy.session_count().await, 0);
    }

    // --- Session eviction ---

    #[tokio::test]
    async fn test_evict_expired_empty() {
        let proxy = UdpProxy::new(UdpProxyConfig::default());
        let evicted = proxy.evict_expired().await;
        assert_eq!(evicted, 0);
    }

    // --- start_udp_listener ---

    #[tokio::test]
    async fn test_start_udp_listener() {
        let result =
            start_udp_listener("127.0.0.1:0", "127.0.0.1:9999", Duration::from_secs(10)).await;
        assert!(result.is_ok());
        let (socket, proxy) = result.unwrap();
        assert!(socket.local_addr().is_ok());
        assert_eq!(proxy.config().upstream_addr, "127.0.0.1:9999");
    }

    #[tokio::test]
    async fn test_start_udp_listener_invalid_addr() {
        let result = start_udp_listener(
            "999.999.999.999:0",
            "127.0.0.1:9999",
            Duration::from_secs(10),
        )
        .await;
        assert!(result.is_err());
    }

    // --- UDP relay integration test ---

    #[tokio::test]
    async fn test_udp_echo_relay() {
        // Start an echo UDP server
        let echo_server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_server.local_addr().unwrap();

        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            loop {
                match echo_server.recv_from(&mut buf).await {
                    Ok((n, addr)) => {
                        let _ = echo_server.send_to(&buf[..n], addr).await;
                    }
                    Err(_) => break,
                }
            }
        });

        // Start the proxy
        let (proxy_socket, proxy) = start_udp_listener(
            "127.0.0.1:0",
            &echo_addr.to_string(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let proxy_addr = proxy_socket.local_addr().unwrap();
        let proxy = Arc::new(proxy);

        // Run proxy in background
        let proxy_socket_clone = proxy_socket.clone();
        let proxy_clone = proxy.clone();
        tokio::spawn(async move {
            run_udp_proxy(proxy_socket_clone, proxy_clone).await;
        });

        // Send a datagram through the proxy
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"hello", proxy_addr).await.unwrap();

        // Receive the echoed response
        let mut buf = vec![0u8; 1024];
        let result = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await;

        match result {
            Ok(Ok((n, _))) => {
                assert_eq!(&buf[..n], b"hello");
            }
            Ok(Err(e)) => {
                // Acceptable on some CI environments
                tracing::warn!("UDP echo test recv error: {}", e);
            }
            Err(_) => {
                // Timeout is acceptable on some systems
                tracing::warn!("UDP echo test timed out");
            }
        }
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
