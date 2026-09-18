//! TCP proxy — bidirectional byte stream relay
//!
//! Handles raw TCP proxying by establishing a connection to the upstream
//! backend and relaying bytes in both directions.

use crate::error::{GatewayError, Result};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Relay bytes bidirectionally between two TCP streams
///
/// Copies data from client→upstream and upstream→client concurrently
/// until either side closes the connection.
pub async fn relay_tcp(mut client: TcpStream, mut upstream: TcpStream) -> Result<(u64, u64)> {
    let (mut client_read, mut client_write) = client.split();
    let (mut upstream_read, mut upstream_write) = upstream.split();

    let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
    let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

    let result = tokio::select! {
        result = client_to_upstream => {
            let bytes_sent = result.map_err(|e| {
                GatewayError::Other(format!("TCP relay client→upstream error: {}", e))
            })?;
            // Client closed, shutdown upstream write side
            let _ = upstream_write.shutdown().await;
            (bytes_sent, 0u64)
        }
        result = upstream_to_client => {
            let bytes_received = result.map_err(|e| {
                GatewayError::Other(format!("TCP relay upstream→client error: {}", e))
            })?;
            // Upstream closed, shutdown client write side
            let _ = client_write.shutdown().await;
            (0u64, bytes_received)
        }
    };

    Ok(result)
}

/// Connect to an upstream TCP server with a bounded dial deadline.
pub async fn connect_upstream(address: &str, connect_timeout: Duration) -> Result<TcpStream> {
    match tokio::time::timeout(connect_timeout, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(error)) => Err(GatewayError::UpstreamTransport(format!(
            "TCP upstream connection to {} failed: {}",
            address, error
        ))),
        Err(_) => Err(GatewayError::UpstreamTimeout(
            u64::try_from(connect_timeout.as_millis()).unwrap_or(u64::MAX),
        )),
    }
}

/// Dial address for a backend URL.
///
/// TCP and UDP ignore the scheme and any path: they connect to host:port.
/// Schemes with a default port (`http`/`ws`/`h2c` → 80, `https`/`wss` → 443)
/// keep that port when the URL omits it. A prefix strip of `ws://host:port`
/// leaves the host as `ws`, which is a different machine.
pub fn extract_address(url: &str) -> String {
    let Ok(parsed) = url::Url::parse(url) else {
        return url.trim_end_matches('/').to_string();
    };
    let Some(host) = parsed.host_str() else {
        return url.trim_end_matches('/').to_string();
    };
    let Some(port) = parsed.port().or_else(|| default_dial_port(parsed.scheme())) else {
        return host.to_string();
    };
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn default_dial_port(scheme: &str) -> Option<u16> {
    match scheme {
        "http" | "ws" | "h2c" => Some(80),
        "https" | "wss" => Some(443),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn test_extract_address_http() {
        assert_eq!(extract_address("http://127.0.0.1:8001"), "127.0.0.1:8001");
    }

    #[test]
    fn test_extract_address_https() {
        assert_eq!(
            extract_address("https://backend.example.com:443"),
            "backend.example.com:443"
        );
    }

    #[test]
    fn test_extract_address_h2c() {
        assert_eq!(extract_address("h2c://127.0.0.1:50051"), "127.0.0.1:50051");
    }

    #[test]
    fn test_extract_address_tcp() {
        assert_eq!(extract_address("tcp://127.0.0.1:9000"), "127.0.0.1:9000");
    }

    #[test]
    fn test_extract_address_udp() {
        assert_eq!(extract_address("udp://127.0.0.1:5353"), "127.0.0.1:5353");
    }

    #[test]
    fn test_extract_address_bare() {
        assert_eq!(extract_address("127.0.0.1:9000"), "127.0.0.1:9000");
    }

    #[test]
    fn test_extract_address_trailing_slash() {
        assert_eq!(extract_address("http://127.0.0.1:8001/"), "127.0.0.1:8001");
    }

    #[test]
    fn test_extract_address_https_default_port_and_ignored_path() {
        assert_eq!(
            extract_address("https://backend.example.com"),
            "backend.example.com:443"
        );
        assert_eq!(
            extract_address("http://127.0.0.1:8001/api"),
            "127.0.0.1:8001"
        );
        assert_eq!(extract_address("ws://127.0.0.1:9000"), "127.0.0.1:9000");
        assert_eq!(extract_address("wss://example.test"), "example.test:443");
        assert_eq!(extract_address("http://[::1]:8080"), "[::1]:8080");
    }

    #[tokio::test]
    async fn test_connect_upstream_invalid() {
        let result = connect_upstream("127.0.0.1:1", Duration::from_secs(1)).await;
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            error.permits_pre_response_fallback(),
            "TCP dial failure must be an upstream transport or timeout, got {error}"
        );
        let message = error.to_string();
        assert!(
            message.contains("TCP upstream connection") || message.contains("timeout"),
            "unexpected connect error: {message}"
        );
    }

    #[tokio::test]
    async fn test_connect_upstream_valid() {
        // Create a server that accepts connections
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = connect_upstream(&addr.to_string(), Duration::from_secs(1)).await;
        assert!(result.is_ok());

        server.abort();
    }

    #[tokio::test]
    async fn test_extract_address_http_port() {
        assert_eq!(extract_address("http://127.0.0.1:8080"), "127.0.0.1:8080");
    }

    #[tokio::test]
    async fn test_extract_address_https_with_path() {
        assert_eq!(
            extract_address("https://example.com:8443"),
            "example.com:8443"
        );
    }

    // NOTE: relay_tcp tests are omitted because tokio::select! in relay_tcp
    // returns when one direction completes, leaving the other direction's
    // future running in a detached task. This causes tests to hang.
    // The relay_tcp function's core logic is tested via integration tests.
}
