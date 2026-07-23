//! End-to-end graceful-drain and forced-cancellation evidence.

use a3s_gateway::config::{
    EntrypointConfig, GatewayConfig, LoadBalancerConfig, Protocol, RouterConfig, ServerConfig,
    ServiceConfig, Strategy,
};
use a3s_gateway::{Gateway, GatewayState};
use futures_util::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

async fn free_tcp_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn free_udp_address() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.local_addr().unwrap()
}

fn gateway_config(
    protocol: Protocol,
    gateway_address: SocketAddr,
    backend_url: String,
    shutdown_timeout_secs: u64,
) -> GatewayConfig {
    let is_udp = protocol == Protocol::Udp;
    let mut entrypoints = HashMap::new();
    entrypoints.insert(
        "traffic".to_string(),
        EntrypointConfig {
            address: gateway_address.to_string(),
            protocol,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: Vec::new(),
            udp_session_timeout_secs: is_udp.then_some(30),
            udp_max_sessions: is_udp.then_some(100),
        },
    );

    let mut routers = HashMap::new();
    routers.insert(
        "traffic".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/`)".to_string(),
            service: "backend".to_string(),
            entrypoints: vec!["traffic".to_string()],
            middlewares: Vec::new(),
            priority: 0,
        },
    );

    let mut services = HashMap::new();
    services.insert(
        "backend".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                servers: vec![ServerConfig {
                    url: backend_url,
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

    GatewayConfig {
        mode: Default::default(),
        managed: Default::default(),
        inference: None,
        entrypoints,
        routers,
        services,
        middlewares: HashMap::new(),
        providers: Default::default(),
        management: Default::default(),
        observability: Default::default(),
        shutdown_timeout_secs,
    }
}

async fn read_request(stream: &mut TcpStream) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let length = stream.read(&mut buffer).await.unwrap();
        assert!(length > 0, "client disconnected before sending headers");
        request.extend_from_slice(&buffer[..length]);
    }
}

async fn write_chunk(stream: &mut TcpStream, body: &[u8]) {
    stream
        .write_all(format!("{:X}\r\n", body.len()).as_bytes())
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
}

async fn spawn_completable_sse_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .unwrap();
        write_chunk(&mut stream, b"data: first\n\n").await;
        let _ = started_tx.send(());

        let _ = finish_rx.await;
        write_chunk(&mut stream, b"data: [DONE]\n\n").await;
        stream.write_all(b"0\r\n\r\n").await.unwrap();
        let _ = stream.shutdown().await;
    });

    (address, started_rx, finish_tx)
}

async fn spawn_hanging_sse_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (disconnected_tx, disconnected_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .unwrap();
        write_chunk(&mut stream, b"data: first\n\n").await;
        let _ = started_tx.send(());

        let mut buffer = [0_u8; 1];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = disconnected_tx.send(());
    });

    (address, started_rx, disconnected_rx)
}

async fn spawn_hanging_websocket_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Receiver<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (disconnected_tx, disconnected_rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
        let _ = started_tx.send(());
        while websocket.next().await.is_some() {}
        let _ = disconnected_tx.send(());
    });

    (address, started_rx, disconnected_rx)
}

#[tokio::test]
async fn active_sse_completes_within_graceful_drain_deadline() {
    let gateway_address = free_tcp_address().await;
    let (backend_address, started, finish) = spawn_completable_sse_backend().await;
    let config = gateway_config(
        Protocol::Http,
        gateway_address,
        format!("http://{backend_address}"),
        2,
    );
    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://{gateway_address}/v1/chat/completions"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    started.await.unwrap();

    let shutdown_gateway = gateway.clone();
    let shutdown = tokio::spawn(async move {
        shutdown_gateway.shutdown().await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(gateway.state(), GatewayState::Stopping);
    assert!(
        !shutdown.is_finished(),
        "shutdown must wait for an active response within the drain deadline"
    );
    assert!(
        TcpStream::connect(gateway_address).await.is_err(),
        "the listener must stop accepting before active responses drain"
    );

    finish.send(()).unwrap();
    let body = tokio::time::timeout(Duration::from_secs(2), response.bytes())
        .await
        .expect("SSE body timed out")
        .unwrap();
    assert_eq!(
        body.as_ref(),
        b"data: first\n\ndata: [DONE]\n\n",
        "graceful drain must preserve the complete SSE response"
    );

    tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("gateway did not finish graceful drain")
        .unwrap();
    assert_eq!(gateway.state(), GatewayState::Stopped);
    assert_eq!(gateway.health().active_connections, 0);
}

#[tokio::test]
async fn reloaded_graceful_deadline_applies_without_rebinding_listener() {
    let gateway_address = free_tcp_address().await;
    let (backend_address, started, finish) = spawn_completable_sse_backend().await;
    let config = gateway_config(
        Protocol::Http,
        gateway_address,
        format!("http://{backend_address}"),
        0,
    );
    let gateway = Arc::new(Gateway::new(config.clone()).unwrap());
    gateway.start().await.unwrap();

    let mut reloaded = config;
    reloaded.shutdown_timeout_secs = 2;
    gateway.reload(reloaded).await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://{gateway_address}/events"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    started.await.unwrap();

    let shutdown_gateway = gateway.clone();
    let shutdown = tokio::spawn(async move {
        shutdown_gateway.shutdown().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !shutdown.is_finished(),
        "the hot-reloaded deadline must apply to a preserved listener"
    );

    finish.send(()).unwrap();
    let body = tokio::time::timeout(Duration::from_secs(2), response.bytes())
        .await
        .expect("reloaded-deadline SSE body timed out")
        .unwrap();
    assert!(body.ends_with(b"data: [DONE]\n\n"));
    tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("gateway did not honor the reloaded drain deadline")
        .unwrap();
}

#[tokio::test]
async fn zero_deadline_cancels_hanging_sse_and_releases_accounting() {
    let gateway_address = free_tcp_address().await;
    let (backend_address, started, disconnected) = spawn_hanging_sse_backend().await;
    let config = gateway_config(
        Protocol::Http,
        gateway_address,
        format!("http://{backend_address}"),
        0,
    );
    let gateway = Gateway::new(config).unwrap();
    gateway.start().await.unwrap();

    let response = reqwest::Client::new()
        .get(format!("http://{gateway_address}/v1/chat/completions"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    started.await.unwrap();

    tokio::time::timeout(Duration::from_secs(2), gateway.shutdown())
        .await
        .expect("forced shutdown timed out");
    assert_eq!(gateway.state(), GatewayState::Stopped);
    assert_eq!(gateway.health().active_connections, 0);
    tokio::time::timeout(Duration::from_secs(2), disconnected)
        .await
        .expect("upstream SSE connection remained attached")
        .unwrap();
    drop(response);

    TcpListener::bind(gateway_address)
        .await
        .expect("HTTP listener address was not released after shutdown");
}

#[tokio::test]
async fn zero_deadline_cancels_upgraded_websocket_session() {
    let gateway_address = free_tcp_address().await;
    let (backend_address, started, disconnected) = spawn_hanging_websocket_backend().await;
    let config = gateway_config(
        Protocol::Http,
        gateway_address,
        format!("http://{backend_address}"),
        0,
    );
    let gateway = Gateway::new(config).unwrap();
    gateway.start().await.unwrap();

    let (websocket, response) =
        tokio_tungstenite::connect_async(format!("ws://{gateway_address}/socket"))
            .await
            .unwrap();
    assert_eq!(response.status(), 101);
    started.await.unwrap();

    tokio::time::timeout(Duration::from_secs(2), gateway.shutdown())
        .await
        .expect("forced WebSocket shutdown timed out");
    tokio::time::timeout(Duration::from_secs(2), disconnected)
        .await
        .expect("upstream WebSocket session remained attached")
        .unwrap();
    assert_eq!(gateway.health().active_connections, 0);
    drop(websocket);

    TcpListener::bind(gateway_address)
        .await
        .expect("WebSocket listener address was not released after shutdown");
}

#[tokio::test]
async fn zero_deadline_cancels_tcp_relay() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend_listener.local_addr().unwrap();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let (disconnected_tx, disconnected_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = backend_listener.accept().await.unwrap();
        let _ = accepted_tx.send(());
        let mut buffer = [0_u8; 1];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
        let _ = disconnected_tx.send(());
    });

    let gateway_address = free_tcp_address().await;
    let config = gateway_config(
        Protocol::Tcp,
        gateway_address,
        format!("tcp://{backend_address}"),
        0,
    );
    let gateway = Gateway::new(config).unwrap();
    gateway.start().await.unwrap();

    let mut client = TcpStream::connect(gateway_address).await.unwrap();
    client.write_all(b"x").await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), accepted_rx)
        .await
        .expect("TCP backend was not selected")
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), gateway.shutdown())
        .await
        .expect("forced TCP shutdown timed out");
    tokio::time::timeout(Duration::from_secs(2), disconnected_rx)
        .await
        .expect("TCP upstream relay remained attached")
        .unwrap();
    TcpListener::bind(gateway_address)
        .await
        .expect("TCP listener address was not released after shutdown");
}

#[tokio::test]
async fn shutdown_cancels_udp_sessions_and_releases_listener() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let (forwarded_tx, forwarded_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut buffer = [0_u8; 16];
        let (_, gateway_upstream) = backend.recv_from(&mut buffer).await.unwrap();
        let _ = forwarded_tx.send(gateway_upstream);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = backend.send_to(b"late", gateway_upstream).await;
    });

    let gateway_address = free_udp_address().await;
    let config = gateway_config(
        Protocol::Udp,
        gateway_address,
        format!("udp://{backend_address}"),
        0,
    );
    let gateway = Gateway::new(config).unwrap();
    gateway.start().await.unwrap();

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(b"request", gateway_address).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), forwarded_rx)
        .await
        .expect("UDP datagram was not forwarded")
        .unwrap();

    tokio::time::timeout(Duration::from_secs(2), gateway.shutdown())
        .await
        .expect("forced UDP shutdown timed out");
    let _replacement = UdpSocket::bind(gateway_address)
        .await
        .expect("UDP session task kept the listener address bound");

    let mut response = [0_u8; 16];
    assert!(
        tokio::time::timeout(Duration::from_millis(250), client.recv(&mut response))
            .await
            .is_err(),
        "a cancelled UDP session returned a late response"
    );
}
