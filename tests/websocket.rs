//! End-to-end WebSocket handshake and forwarding coverage.

use a3s_gateway::config::{
    EntrypointConfig, GatewayConfig, LoadBalancerConfig, MiddlewareConfig, Protocol, RouterConfig,
    ServerConfig, ServiceConfig, Strategy,
};
use a3s_gateway::Gateway;
use futures_util::{SinkExt, StreamExt};
use http::header::{AUTHORIZATION, COOKIE, ORIGIN, SEC_WEBSOCKET_PROTOCOL};
use http::HeaderValue;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;

#[derive(Debug)]
struct CapturedHandshake {
    authorization: Option<String>,
    cookie: Option<String>,
    origin: Option<String>,
    custom: Option<String>,
    middleware: Option<String>,
    forwarded_for: Option<String>,
    forwarded_host: Option<String>,
    forwarded_proto: Option<String>,
    forwarded_port: Option<String>,
    subprotocols: Option<String>,
}

async fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

fn gateway_config(
    gateway_address: SocketAddr,
    backend_address: SocketAddr,
    request_timeout: &str,
) -> GatewayConfig {
    let mut entrypoints = HashMap::new();
    entrypoints.insert(
        "web".to_string(),
        EntrypointConfig {
            address: gateway_address.to_string(),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: Vec::new(),
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let mut routers = HashMap::new();
    routers.insert(
        "websocket".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/`)".to_string(),
            service: "backend".to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: vec!["websocket-headers".to_string()],
            priority: 0,
        },
    );

    let mut services = HashMap::new();
    services.insert(
        "backend".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: request_timeout.to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers: vec![ServerConfig {
                    url: format!("http://{backend_address}"),
                    weight: 1,
                }],
                health_check: None,
                sticky: None,
            },
            scaling: None,
            revisions: Vec::new(),
            rollout: None,
            mirror: None,
            failover: None,
        },
    );

    let mut middlewares = HashMap::new();
    middlewares.insert(
        "websocket-headers".to_string(),
        MiddlewareConfig {
            middleware_type: "headers".to_string(),
            request_headers: HashMap::from([(
                "x-from-middleware".to_string(),
                "applied".to_string(),
            )]),
            ..Default::default()
        },
    );

    GatewayConfig {
        mode: Default::default(),
        managed: Default::default(),
        inference: None,
        entrypoints,
        routers,
        services,
        middlewares,
        providers: Default::default(),
        management: Default::default(),
        observability: Default::default(),
        shutdown_timeout_secs: 0,
    }
}

async fn start_gateway(
    backend_address: SocketAddr,
    request_timeout: &str,
) -> (Arc<Gateway>, SocketAddr) {
    let gateway_address = free_address().await;
    let gateway = Arc::new(
        Gateway::new(gateway_config(
            gateway_address,
            backend_address,
            request_timeout,
        ))
        .unwrap(),
    );
    gateway.start().await.unwrap();

    for _ in 0..50 {
        if TcpStream::connect(gateway_address).await.is_ok() {
            return (gateway, gateway_address);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("Gateway did not become ready at {gateway_address}");
}

async fn read_response_headers(stream: &mut TcpStream) -> String {
    let mut response = Vec::new();
    let mut buffer = [0_u8; 1024];
    tokio::time::timeout(Duration::from_secs(2), async {
        while !response.windows(4).any(|window| window == b"\r\n\r\n") {
            let length = stream.read(&mut buffer).await.unwrap();
            assert!(
                length > 0,
                "gateway closed before returning response headers"
            );
            response.extend_from_slice(&buffer[..length]);
        }
    })
    .await
    .expect("gateway response headers timed out");
    String::from_utf8(response).unwrap()
}

async fn send_raw_handshake(gateway_address: SocketAddr, request: &str) -> String {
    let mut stream = TcpStream::connect(gateway_address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    read_response_headers(&mut stream).await
}

fn status_code(response: &str) -> u16 {
    response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse().ok())
        .unwrap()
}

fn header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

#[tokio::test]
async fn malformed_websocket_handshake_is_rejected_before_backend_contact() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (gateway, gateway_address) = start_gateway(backend_address, "30s").await;

    let response = send_raw_handshake(
        gateway_address,
        &format!(
            "GET /socket HTTP/1.1\r\nHost: {gateway_address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ),
    )
    .await;

    assert_eq!(status_code(&response), 400, "{response}");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backend.accept())
            .await
            .is_err(),
        "an invalid downstream handshake reached the backend"
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn upstream_handshake_failure_returns_503_before_downstream_upgrade() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = backend.accept().await.unwrap();
        drop(stream);
    });
    let (gateway, gateway_address) = start_gateway(backend_address, "1s").await;

    let response = send_raw_handshake(
        gateway_address,
        &format!(
            "GET /socket HTTP/1.1\r\nHost: {gateway_address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        ),
    )
    .await;

    assert_eq!(status_code(&response), 503, "{response}");
    gateway.shutdown().await;
}

#[tokio::test]
async fn upstream_handshake_obeys_service_request_timeout() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        let _ = accepted_tx.send(());
        let mut buffer = [0_u8; 1024];
        while stream.read(&mut buffer).await.unwrap_or(0) > 0 {}
    });
    let (gateway, gateway_address) = start_gateway(backend_address, "50ms").await;

    let started = Instant::now();
    let response = send_raw_handshake(
        gateway_address,
        &format!(
            "GET /socket HTTP/1.1\r\nHost: {gateway_address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
        ),
    )
    .await;

    accepted_rx.await.unwrap();
    assert_eq!(status_code(&response), 504, "{response}");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "WebSocket handshake ignored its service timeout"
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn websocket_forwards_headers_and_negotiated_subprotocol() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (captured_tx, captured_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = backend.accept().await.unwrap();
        // Tungstenite's callback contract fixes the rejection type to a full
        // HTTP response, so this test closure cannot reduce the error size.
        #[allow(clippy::result_large_err)]
        let callback = move |request: &Request, mut response: Response| {
            let captured = CapturedHandshake {
                authorization: header_value(request.headers(), "authorization"),
                cookie: header_value(request.headers(), "cookie"),
                origin: header_value(request.headers(), "origin"),
                custom: header_value(request.headers(), "x-a3s-test"),
                middleware: header_value(request.headers(), "x-from-middleware"),
                forwarded_for: header_value(request.headers(), "x-forwarded-for"),
                forwarded_host: header_value(request.headers(), "x-forwarded-host"),
                forwarded_proto: header_value(request.headers(), "x-forwarded-proto"),
                forwarded_port: header_value(request.headers(), "x-forwarded-port"),
                subprotocols: header_value(request.headers(), "sec-websocket-protocol"),
            };
            let _ = captured_tx.send(captured);
            response.headers_mut().insert(
                SEC_WEBSOCKET_PROTOCOL,
                HeaderValue::from_static("superchat"),
            );
            Ok(response)
        };
        let mut websocket = tokio_tungstenite::accept_hdr_async(stream, callback)
            .await
            .unwrap();
        while let Some(Ok(message)) = websocket.next().await {
            if message.is_close() || websocket.send(message).await.is_err() {
                return;
            }
        }
    });

    let (gateway, gateway_address) = start_gateway(backend_address, "1s").await;
    let mut request = format!("ws://{gateway_address}/socket?room=blue")
        .into_client_request()
        .unwrap();
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_static("Bearer gateway-test"),
    );
    request
        .headers_mut()
        .insert(COOKIE, HeaderValue::from_static("session=abc"));
    request.headers_mut().insert(
        ORIGIN,
        HeaderValue::from_static("https://client.example.test"),
    );
    request
        .headers_mut()
        .insert("x-a3s-test", HeaderValue::from_static("forward-me"));
    request.headers_mut().insert(
        SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static("chat,superchat"),
    );

    let (mut websocket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::SWITCHING_PROTOCOLS);
    assert_eq!(
        response
            .headers()
            .get(SEC_WEBSOCKET_PROTOCOL)
            .and_then(|value| value.to_str().ok()),
        Some("superchat")
    );

    let captured = captured_rx.await.unwrap();
    assert_eq!(
        captured.authorization.as_deref(),
        Some("Bearer gateway-test")
    );
    assert_eq!(captured.cookie.as_deref(), Some("session=abc"));
    assert_eq!(
        captured.origin.as_deref(),
        Some("https://client.example.test")
    );
    assert_eq!(captured.custom.as_deref(), Some("forward-me"));
    assert_eq!(captured.middleware.as_deref(), Some("applied"));
    assert_eq!(captured.forwarded_for.as_deref(), Some("127.0.0.1"));
    let expected_host = gateway_address.to_string();
    assert_eq!(
        captured.forwarded_host.as_deref(),
        Some(expected_host.as_str())
    );
    assert_eq!(captured.forwarded_proto.as_deref(), Some("http"));
    let expected_port = gateway_address.port().to_string();
    assert_eq!(
        captured.forwarded_port.as_deref(),
        Some(expected_port.as_str())
    );
    assert_eq!(captured.subprotocols.as_deref(), Some("chat,superchat"));

    websocket
        .send(Message::Text("opaque-message".into()))
        .await
        .unwrap();
    assert_eq!(
        websocket.next().await.unwrap().unwrap(),
        Message::Text("opaque-message".into())
    );
    websocket.close(None).await.unwrap();
    gateway.shutdown().await;
}
