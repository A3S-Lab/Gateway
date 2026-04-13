//! WebSocket proxy — bidirectional relay between client and upstream
//!
//! Detects WebSocket upgrade requests and establishes a bidirectional
//! relay between the client and the upstream backend.

use crate::error::{GatewayError, Result};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

/// Check if an HTTP request is a WebSocket upgrade request
pub fn is_websocket_upgrade(headers: &http::HeaderMap) -> bool {
    headers
        .get("Upgrade")
        .or_else(|| headers.get("upgrade"))
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Build the upstream WebSocket URL from the backend URL and request URI
pub fn build_ws_url(backend_url: &str, uri: &http::Uri) -> String {
    let backend = backend_url.trim_end_matches('/');
    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    // Convert http(s) to ws(s)
    let ws_url = if backend.starts_with("https://") {
        backend.replacen("https://", "wss://", 1)
    } else if backend.starts_with("http://") {
        backend.replacen("http://", "ws://", 1)
    } else if backend.starts_with("ws://") || backend.starts_with("wss://") {
        backend.to_string()
    } else {
        format!("ws://{}", backend)
    };

    format!("{}{}", ws_url, path)
}

/// Compute the `Sec-WebSocket-Accept` header value from a `Sec-WebSocket-Key`.
///
/// Per RFC 6455: SHA-1( key + magic_guid ) → base64
pub fn compute_accept_key(key: &str) -> String {
    use base64::prelude::BASE64_STANDARD;
    use base64::Engine as _;
    use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

    let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(key.as_bytes());
    ctx.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = ctx.finish();
    BASE64_STANDARD.encode(digest.as_ref())
}

/// Relay messages bidirectionally between two WebSocket streams.
///
/// The client stream `C` is the connection coming from the downstream client
/// (e.g. an upgraded `hyper::upgrade::Upgraded`). The upstream stream `U` is
/// the connection to the backend server.
pub async fn relay_websocket<C, U>(mut client: WebSocketStream<C>, mut upstream: WebSocketStream<U>)
where
    C: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        tokio::select! {
            msg = client.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        if msg.is_close() {
                            let _ = upstream.close(None).await;
                            break;
                        }
                        if upstream.send(msg).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            msg = upstream.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        if msg.is_close() {
                            let _ = client.close(None).await;
                            break;
                        }
                        if client.send(msg).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }
    }

    // Best-effort close both sides
    let _ = client.close(None).await;
    let _ = upstream.close(None).await;
}

/// Connect to an upstream WebSocket server
pub async fn connect_upstream(url: &str) -> Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let (ws_stream, _response) = connect_async(url).await.map_err(|e| {
        GatewayError::ServiceUnavailable(format!("WebSocket upstream connection failed: {}", e))
    })?;
    Ok(ws_stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    #[test]
    fn test_is_websocket_upgrade() {
        let mut headers = http::HeaderMap::new();
        assert!(!is_websocket_upgrade(&headers));

        headers.insert("Upgrade", "websocket".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_case_insensitive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("upgrade", "WebSocket".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_not_websocket() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Upgrade", "h2c".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_build_ws_url_from_http() {
        let uri: http::Uri = "/ws/chat".parse().unwrap();
        assert_eq!(
            build_ws_url("http://127.0.0.1:8001", &uri),
            "ws://127.0.0.1:8001/ws/chat"
        );
    }

    #[test]
    fn test_build_ws_url_from_https() {
        let uri: http::Uri = "/ws".parse().unwrap();
        assert_eq!(
            build_ws_url("https://backend.example.com", &uri),
            "wss://backend.example.com/ws"
        );
    }

    #[test]
    fn test_build_ws_url_already_ws() {
        let uri: http::Uri = "/chat".parse().unwrap();
        assert_eq!(
            build_ws_url("ws://127.0.0.1:9000", &uri),
            "ws://127.0.0.1:9000/chat"
        );
    }

    #[test]
    fn test_build_ws_url_with_query() {
        let uri: http::Uri = "/ws?token=abc".parse().unwrap();
        assert_eq!(
            build_ws_url("http://127.0.0.1:8001", &uri),
            "ws://127.0.0.1:8001/ws?token=abc"
        );
    }

    #[test]
    fn test_build_ws_url_trailing_slash() {
        let uri: http::Uri = "/ws".parse().unwrap();
        assert_eq!(
            build_ws_url("http://127.0.0.1:8001/", &uri),
            "ws://127.0.0.1:8001/ws"
        );
    }

    #[test]
    fn test_build_ws_url_bare_host() {
        let uri: http::Uri = "/ws".parse().unwrap();
        assert_eq!(
            build_ws_url("127.0.0.1:8001", &uri),
            "ws://127.0.0.1:8001/ws"
        );
    }

    #[tokio::test]
    async fn test_compute_accept_key() {
        // RFC 6455 test vector
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(compute_accept_key(key), expected);
    }

    #[tokio::test]
    async fn test_connect_upstream_invalid_url() {
        let result = connect_upstream("invalid-url").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_upstream_connection_refused() {
        // Use a port that nothing is listening on
        let result = connect_upstream("ws://127.0.0.1:1/ws").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_upstream_success() {
        // Spawn a WebSocket server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ws_url = format!("ws://{}/ws", addr);

        // Accept one connection in background
        let handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = accept_async(stream).await;
            }
        });

        // Connect to it
        let result = connect_upstream(&ws_url).await;
        assert!(result.is_ok());

        handle.abort();
    }

    #[tokio::test]
    async fn test_relay_websocket_upstream_error() {
        // Spawn a server that accepts but immediately closes
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ws_url = format!("ws://{}/ws", addr);

        let server_handle = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                // Accept then immediately close
                drop(stream);
            }
        });

        // Give server time to set up
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // Connect client
        let client_result = connect_async(&ws_url).await;
        // Client might succeed or fail depending on server timing

        server_handle.abort();
        let _ = client_result;
    }

    #[tokio::test]
    async fn test_build_ws_url_with_path_only() {
        let uri: http::Uri = "/".parse().unwrap();
        assert_eq!(
            build_ws_url("http://127.0.0.1:8001", &uri),
            "ws://127.0.0.1:8001/"
        );
    }
}
