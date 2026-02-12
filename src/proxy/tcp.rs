//! TCP proxy — bidirectional byte stream relay
//!
//! Handles raw TCP proxying by establishing a connection to the upstream
//! backend and relaying bytes in both directions.

use crate::error::{GatewayError, Result};
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

/// Connect to an upstream TCP server
pub async fn connect_upstream(address: &str) -> Result<TcpStream> {
    TcpStream::connect(address).await.map_err(|e| {
        GatewayError::ServiceUnavailable(format!(
            "TCP upstream connection to {} failed: {}",
            address, e
        ))
    })
}

/// Extract the host:port from a backend URL
///
/// Strips the protocol prefix if present:
/// - "http://127.0.0.1:8001" → "127.0.0.1:8001"
/// - "h2c://127.0.0.1:50051" → "127.0.0.1:50051"
/// - "127.0.0.1:9000" → "127.0.0.1:9000"
pub fn extract_address(url: &str) -> &str {
    if let Some(rest) = url.strip_prefix("http://") {
        rest.trim_end_matches('/')
    } else if let Some(rest) = url.strip_prefix("https://") {
        rest.trim_end_matches('/')
    } else if let Some(rest) = url.strip_prefix("h2c://") {
        rest.trim_end_matches('/')
    } else if let Some(rest) = url.strip_prefix("tcp://") {
        rest.trim_end_matches('/')
    } else {
        url.trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_extract_address_bare() {
        assert_eq!(extract_address("127.0.0.1:9000"), "127.0.0.1:9000");
    }

    #[test]
    fn test_extract_address_trailing_slash() {
        assert_eq!(extract_address("http://127.0.0.1:8001/"), "127.0.0.1:8001");
    }

    #[tokio::test]
    async fn test_connect_upstream_invalid() {
        let result = connect_upstream("127.0.0.1:1").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("TCP upstream connection"));
    }
}
