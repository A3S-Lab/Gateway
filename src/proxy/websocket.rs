//! WebSocket proxy — bidirectional relay between client and upstream
//!
//! Detects WebSocket upgrade requests and establishes a bidirectional
//! relay between the client and the upstream backend.

use crate::error::{GatewayError, Result};
use crate::proxy::http_proxy::{
    apply_forwarded_headers, is_forwarded_header, is_hop_by_hop_header,
};
use crate::proxy::ForwardedContext;
use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use futures_util::{SinkExt, StreamExt};
use http::header::{HOST, SEC_WEBSOCKET_PROTOCOL};
use http::{HeaderMap, HeaderValue, Method, Version};
use std::future::poll_fn;
use std::task::Poll;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Error as TungsteniteError;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

/// A malformed downstream RFC 6455 opening handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WebSocketHandshakeError {
    /// RFC 6455 opening handshakes must use GET.
    #[error("WebSocket opening handshake must use GET")]
    InvalidMethod,
    /// This listener implements the HTTP/1.1 Upgrade form, not extended CONNECT.
    #[error("WebSocket opening handshake must use HTTP/1.1")]
    UnsupportedHttpVersion,
    /// The Upgrade header did not request WebSocket.
    #[error("WebSocket opening handshake is missing Upgrade: websocket")]
    MissingUpgrade,
    /// The Connection header did not nominate Upgrade.
    #[error("WebSocket opening handshake is missing Connection: upgrade")]
    MissingConnectionUpgrade,
    /// The request did not contain one supported WebSocket version header.
    #[error("WebSocket opening handshake requires Sec-WebSocket-Version: 13")]
    InvalidVersion,
    /// The request did not contain exactly one valid 16-byte nonce.
    #[error("WebSocket opening handshake contains an invalid Sec-WebSocket-Key")]
    InvalidKey,
}

/// Validated values needed to complete a downstream WebSocket handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWebSocketHandshake {
    accept: HeaderValue,
}

impl ValidatedWebSocketHandshake {
    /// RFC 6455 response value for `Sec-WebSocket-Accept`.
    pub fn accept_header(&self) -> &HeaderValue {
        &self.accept
    }
}

/// An upstream WebSocket whose opening handshake has already succeeded.
pub struct PreparedWebSocket {
    pub(crate) stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
    pub(crate) selected_protocol: Option<HeaderValue>,
}

/// HTTP outcome from the selected WebSocket upstream.
///
/// `Ok` contains an accepted upgrade ready to relay. `Err` is a normal
/// non-`101` HTTP rejection; transport and timeout failures remain the outer
/// [`crate::error::Result`] returned by [`prepare_upstream`].
pub type UpstreamWebSocketHandshake =
    std::result::Result<PreparedWebSocket, RejectedWebSocketHandshake>;

/// Safe downstream projection of an upstream non-101 handshake response.
pub struct RejectedWebSocketHandshake {
    status: http::StatusCode,
    headers: HeaderMap,
}

impl RejectedWebSocketHandshake {
    /// HTTP status returned by the upstream.
    pub fn status(&self) -> http::StatusCode {
        self.status
    }

    /// End-to-end headers safe to attach to the Gateway-generated body.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
}

/// Check whether an HTTP request declares a WebSocket upgrade candidate.
///
/// Full RFC 6455 validation is deliberately separate so managed inference can
/// reject the entire WebSocket surface before exposing parser details.
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    header_contains_token(headers, http::header::UPGRADE, "websocket")
}

/// Validate the downstream HTTP/1.1 WebSocket opening handshake.
pub fn validate_handshake(
    method: &Method,
    version: Version,
    headers: &HeaderMap,
) -> std::result::Result<ValidatedWebSocketHandshake, WebSocketHandshakeError> {
    if method != Method::GET {
        return Err(WebSocketHandshakeError::InvalidMethod);
    }
    if version != Version::HTTP_11 {
        return Err(WebSocketHandshakeError::UnsupportedHttpVersion);
    }
    if !is_websocket_upgrade(headers) {
        return Err(WebSocketHandshakeError::MissingUpgrade);
    }
    if !header_contains_token(headers, http::header::CONNECTION, "upgrade") {
        return Err(WebSocketHandshakeError::MissingConnectionUpgrade);
    }

    let version = single_header(headers, http::header::SEC_WEBSOCKET_VERSION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim);
    if version != Some("13") {
        return Err(WebSocketHandshakeError::InvalidVersion);
    }

    let key = single_header(headers, http::header::SEC_WEBSOCKET_KEY)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .ok_or(WebSocketHandshakeError::InvalidKey)?;
    let decoded = BASE64_STANDARD
        .decode(key)
        .map_err(|_| WebSocketHandshakeError::InvalidKey)?;
    if decoded.len() != 16 {
        return Err(WebSocketHandshakeError::InvalidKey);
    }

    let accept = HeaderValue::from_str(&compute_accept_key(key))
        .map_err(|_| WebSocketHandshakeError::InvalidKey)?;
    Ok(ValidatedWebSocketHandshake { accept })
}

fn header_contains_token(
    headers: &HeaderMap,
    name: http::header::HeaderName,
    expected: &str,
) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case(expected))
        })
    })
}

fn single_header(headers: &HeaderMap, name: http::header::HeaderName) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    values.next().is_none().then_some(value)
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
    use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY};

    let mut ctx = Context::new(&SHA1_FOR_LEGACY_USE_ONLY);
    ctx.update(key.as_bytes());
    ctx.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = ctx.finish();
    BASE64_STANDARD.encode(digest.as_ref())
}

/// Complete a bounded upstream opening handshake using trusted proxy headers.
pub async fn prepare_upstream(
    url: &str,
    downstream_headers: &HeaderMap,
    forwarded: ForwardedContext,
    timeout: Duration,
) -> Result<UpstreamWebSocketHandshake> {
    let request = build_upstream_request(url, downstream_headers, forwarded)?;
    let requested_protocols = requested_subprotocols(downstream_headers)?;
    let handshake = tokio::time::timeout(timeout, connect_async(request))
        .await
        .map_err(|_| GatewayError::UpstreamTimeout(timeout.as_millis() as u64))?;
    let (stream, response) = match handshake {
        Ok(connected) => connected,
        Err(TungsteniteError::Http(response)) => {
            return Ok(Err(rejected_handshake(response)));
        }
        Err(error) => return Err(upstream_handshake_error(error)),
    };
    let selected_protocol = selected_subprotocol(response.headers(), &requested_protocols)?;

    Ok(Ok(PreparedWebSocket {
        stream,
        selected_protocol,
    }))
}

fn rejected_handshake(response: http::Response<Option<Vec<u8>>>) -> RejectedWebSocketHandshake {
    let (parts, _buffered_tail) = response.into_parts();
    let mut headers = HeaderMap::new();
    for (name, value) in &parts.headers {
        if is_rejection_header_safe(&parts.headers, name) {
            headers.append(name.clone(), value.clone());
        }
    }
    RejectedWebSocketHandshake {
        status: parts.status,
        headers,
    }
}

fn is_rejection_header_safe(headers: &HeaderMap, name: &http::header::HeaderName) -> bool {
    let name_str = name.as_str();
    !is_hop_by_hop_header(headers, name)
        && !name_str.starts_with("sec-websocket-")
        && !name_str.starts_with("content-")
        && !name_str.eq_ignore_ascii_case("etag")
        && !name_str.eq_ignore_ascii_case("digest")
        && !name_str.eq_ignore_ascii_case("last-modified")
        && !name_str.eq_ignore_ascii_case("accept-ranges")
}

fn build_upstream_request(
    url: &str,
    downstream_headers: &HeaderMap,
    forwarded: ForwardedContext,
) -> Result<http::Request<()>> {
    let generated = url
        .into_client_request()
        .map_err(upstream_handshake_error)?;
    let (parts, ()) = generated.into_parts();
    let mut builder = http::Request::builder()
        .method(parts.method)
        .uri(parts.uri)
        .version(parts.version);

    for (name, value) in &parts.headers {
        builder = builder.header(name, value);
    }
    for (name, value) in downstream_headers {
        if name != HOST
            && !is_hop_by_hop_header(downstream_headers, name)
            && !is_forwarded_header(name.as_str())
            && !is_gateway_websocket_header(name.as_str())
        {
            builder = builder.header(name, value);
        }
    }
    builder = apply_forwarded_headers(builder, downstream_headers, forwarded);
    builder.body(()).map_err(|error| {
        GatewayError::UpstreamTransport(format!(
            "Failed to build WebSocket upstream handshake: {error}"
        ))
    })
}

fn is_gateway_websocket_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("sec-websocket-key")
        || name.eq_ignore_ascii_case("sec-websocket-version")
        || name.eq_ignore_ascii_case("sec-websocket-extensions")
        || name.eq_ignore_ascii_case("sec-websocket-accept")
}

fn requested_subprotocols(headers: &HeaderMap) -> Result<Vec<String>> {
    let mut protocols = Vec::new();
    for value in headers.get_all(SEC_WEBSOCKET_PROTOCOL) {
        let value = value.to_str().map_err(|_| {
            GatewayError::UpstreamTransport(
                "Invalid downstream WebSocket subprotocol header".to_string(),
            )
        })?;
        protocols.extend(
            value
                .split(',')
                .map(str::trim)
                .filter(|protocol| !protocol.is_empty())
                .map(str::to_string),
        );
    }
    Ok(protocols)
}

fn selected_subprotocol(headers: &HeaderMap, requested: &[String]) -> Result<Option<HeaderValue>> {
    let mut values = headers.get_all(SEC_WEBSOCKET_PROTOCOL).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(GatewayError::UpstreamTransport(
            "Upstream selected multiple WebSocket subprotocols".to_string(),
        ));
    }
    let selected = value.to_str().map_err(|_| {
        GatewayError::UpstreamTransport(
            "Upstream selected an invalid WebSocket subprotocol".to_string(),
        )
    })?;
    if selected.is_empty()
        || selected.contains(',')
        || !requested.iter().any(|protocol| protocol == selected)
    {
        return Err(GatewayError::UpstreamTransport(
            "Upstream selected an unrequested WebSocket subprotocol".to_string(),
        ));
    }
    Ok(Some(value.clone()))
}

fn upstream_handshake_error(error: TungsteniteError) -> GatewayError {
    GatewayError::UpstreamTransport(format!("WebSocket upstream handshake failed: {error}"))
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
    let mut client_first = true;
    loop {
        // Poll deterministically and prefer the opposite peer after every
        // event. This preserves fairness without select's per-message RNG.
        let (from_client, msg) = poll_fn(|context| {
            if client_first {
                if let Poll::Ready(msg) = client.poll_next_unpin(context) {
                    return Poll::Ready((true, msg));
                }
                upstream.poll_next_unpin(context).map(|msg| (false, msg))
            } else {
                if let Poll::Ready(msg) = upstream.poll_next_unpin(context) {
                    return Poll::Ready((false, msg));
                }
                client.poll_next_unpin(context).map(|msg| (true, msg))
            }
        })
        .await;
        client_first = !from_client;

        if from_client {
            match msg {
                Some(Ok(msg)) => {
                    if msg.is_close() {
                        let _ = upstream.close(None).await;
                        break;
                    }
                    if upstream.send(msg).await.is_err() {
                        tracing::debug!("WebSocket upstream write failed");
                        break;
                    }
                }
                Some(Err(error)) => {
                    tracing::debug!(error = %error, "WebSocket downstream read failed");
                    break;
                }
                None => break,
            }
        } else {
            match msg {
                Some(Ok(msg)) => {
                    if msg.is_close() {
                        let _ = client.close(None).await;
                        break;
                    }
                    if client.send(msg).await.is_err() {
                        tracing::debug!("WebSocket downstream write failed");
                        break;
                    }
                }
                Some(Err(error)) => {
                    tracing::debug!(error = %error, "WebSocket upstream read failed");
                    break;
                }
                None => break,
            }
        }
    }

    // Best-effort close both sides
    let _ = client.close(None).await;
    let _ = upstream.close(None).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn valid_handshake() -> http::Request<()> {
        http::Request::builder()
            .method(http::Method::GET)
            .version(http::Version::HTTP_11)
            .header("Host", "gateway.example.test")
            .header("Upgrade", "websocket")
            .header("Connection", "keep-alive, Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .body(())
            .unwrap()
    }

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
        headers.insert("upgrade", "h2c, WebSocket".parse().unwrap());
        assert!(is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_is_websocket_upgrade_not_websocket() {
        let mut headers = http::HeaderMap::new();
        headers.insert("Upgrade", "h2c".parse().unwrap());
        assert!(!is_websocket_upgrade(&headers));
    }

    #[test]
    fn test_validate_handshake_accepts_rfc_6455_example() {
        let request = valid_handshake();
        let validated =
            validate_handshake(request.method(), request.version(), request.headers()).unwrap();
        assert_eq!(
            validated.accept_header(),
            &HeaderValue::from_static("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
        );
    }

    #[test]
    fn test_validate_handshake_rejects_wrong_method_and_http_version() {
        let mut request = valid_handshake();
        *request.method_mut() = Method::POST;
        assert_eq!(
            validate_handshake(request.method(), request.version(), request.headers()),
            Err(WebSocketHandshakeError::InvalidMethod)
        );

        *request.method_mut() = Method::GET;
        *request.version_mut() = Version::HTTP_10;
        assert_eq!(
            validate_handshake(request.method(), request.version(), request.headers()),
            Err(WebSocketHandshakeError::UnsupportedHttpVersion)
        );
    }

    #[test]
    fn test_validate_handshake_requires_connection_upgrade_and_version_13() {
        let mut request = valid_handshake();
        request.headers_mut().remove(http::header::CONNECTION);
        assert_eq!(
            validate_handshake(request.method(), request.version(), request.headers()),
            Err(WebSocketHandshakeError::MissingConnectionUpgrade)
        );

        request.headers_mut().insert(
            http::header::CONNECTION,
            HeaderValue::from_static("Upgrade"),
        );
        request.headers_mut().insert(
            http::header::SEC_WEBSOCKET_VERSION,
            HeaderValue::from_static("8"),
        );
        assert_eq!(
            validate_handshake(request.method(), request.version(), request.headers()),
            Err(WebSocketHandshakeError::InvalidVersion)
        );
    }

    #[test]
    fn test_validate_handshake_rejects_invalid_or_duplicate_key() {
        let mut request = valid_handshake();
        request.headers_mut().insert(
            http::header::SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("not-base64"),
        );
        assert_eq!(
            validate_handshake(request.method(), request.version(), request.headers()),
            Err(WebSocketHandshakeError::InvalidKey)
        );

        request.headers_mut().insert(
            http::header::SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("dGhlIHNhbXBsZSBub25jZQ=="),
        );
        request.headers_mut().append(
            http::header::SEC_WEBSOCKET_KEY,
            HeaderValue::from_static("MDEyMzQ1Njc4OWFiY2RlZg=="),
        );
        assert_eq!(
            validate_handshake(request.method(), request.version(), request.headers()),
            Err(WebSocketHandshakeError::InvalidKey)
        );
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
