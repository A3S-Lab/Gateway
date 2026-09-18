//! Real-listener evidence: TCP entrypoints route by ClientHello SNI via
//! pure `HostSNI(...)` rules compiled into `TcpRouterTable`.

use a3s_gateway::config::{
    EntrypointConfig, GatewayConfig, LoadBalancerConfig, Protocol, RouterConfig, ServerConfig,
    ServiceConfig, Strategy,
};
use a3s_gateway::Gateway;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn free_tcp_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

fn client_hello_with_sni(hostname: &str) -> Vec<u8> {
    let sni_hostname = hostname.as_bytes();
    let sni_hostname_len = sni_hostname.len();

    let mut sni_ext = Vec::new();
    let name_entry_len = 3 + sni_hostname_len;
    sni_ext.push(((name_entry_len >> 8) & 0xff) as u8);
    sni_ext.push((name_entry_len & 0xff) as u8);
    sni_ext.push(0x00);
    sni_ext.push(((sni_hostname_len >> 8) & 0xff) as u8);
    sni_ext.push((sni_hostname_len & 0xff) as u8);
    sni_ext.extend_from_slice(sni_hostname);

    let mut extensions = vec![
        0x00_u8,
        0x00,
        ((sni_ext.len() >> 8) & 0xff) as u8,
        (sni_ext.len() & 0xff) as u8,
    ];
    extensions.extend_from_slice(&sni_ext);

    let mut client_hello = Vec::new();
    client_hello.push(0x03);
    client_hello.push(0x03);
    client_hello.extend_from_slice(&[0u8; 32]);
    client_hello.push(0x00);
    client_hello.push(0x00);
    client_hello.push(0x02);
    client_hello.push(0x00);
    client_hello.push(0x2f);
    client_hello.push(0x01);
    client_hello.push(0x00);
    client_hello.push(((extensions.len() >> 8) & 0xff) as u8);
    client_hello.push((extensions.len() & 0xff) as u8);
    client_hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01);
    let ch_len = client_hello.len();
    handshake.push(((ch_len >> 16) & 0xff) as u8);
    handshake.push(((ch_len >> 8) & 0xff) as u8);
    handshake.push((ch_len & 0xff) as u8);
    handshake.extend_from_slice(&client_hello);

    let mut record = Vec::new();
    record.push(0x16);
    record.push(0x03);
    record.push(0x01);
    let hs_len = handshake.len();
    record.push(((hs_len >> 8) & 0xff) as u8);
    record.push((hs_len & 0xff) as u8);
    record.extend_from_slice(&handshake);
    record
}

async fn spawn_labeled_tcp_backend(label: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut buf = [0_u8; 8192];
            let Ok(n) = stream.read(&mut buf).await else {
                continue;
            };
            if n == 0 || buf[0] != 0x16 {
                continue;
            }
            let _ = stream.write_all(label).await;
            let _ = stream.shutdown().await;
        }
    });
    address
}

fn hostsni_gateway_config(
    gateway_address: SocketAddr,
    api_backend: SocketAddr,
    other_backend: SocketAddr,
) -> GatewayConfig {
    let mut entrypoints = HashMap::new();
    entrypoints.insert(
        "tcp".to_string(),
        EntrypointConfig {
            address: gateway_address.to_string(),
            protocol: Protocol::Tcp,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: Vec::new(),
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
            trust_forwarded_headers: false,
        },
    );

    let mut routers = HashMap::new();
    routers.insert(
        "api".to_string(),
        RouterConfig {
            rule: "HostSNI(`api.example.com`)".to_string(),
            service: "api".to_string(),
            entrypoints: vec!["tcp".to_string()],
            middlewares: Vec::new(),
            priority: 10,
        },
    );
    routers.insert(
        "other".to_string(),
        RouterConfig {
            rule: "HostSNI(`other.example.com`)".to_string(),
            service: "other".to_string(),
            entrypoints: vec!["tcp".to_string()],
            middlewares: Vec::new(),
            priority: 10,
        },
    );

    let mut services = HashMap::new();
    for (name, backend) in [("api", api_backend), ("other", other_backend)] {
        services.insert(
            name.to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: format!("tcp://{backend}"),
                        weight: 1,
                        target: None,
                    }],
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
                },
                scaling: None,
                revisions: Vec::new(),
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
    }

    GatewayConfig {
        mode: Default::default(),
        managed: Default::default(),
        inference: None,
        entrypoints,
        routers,
        services,
        static_bundles: HashMap::new(),
        middlewares: HashMap::new(),
        providers: Default::default(),
        management: Default::default(),
        observability: Default::default(),
        shutdown_timeout_secs: 0,
    }
}

async fn connect_and_read_label(gateway: SocketAddr, sni: &str) -> Vec<u8> {
    let hello = client_hello_with_sni(sni);
    let mut client = TcpStream::connect(gateway).await.unwrap();
    client.write_all(&hello).await.unwrap();
    let mut label = Vec::new();
    let mut buf = [0_u8; 64];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("timed out waiting for HostSNI-routed backend label")
            .unwrap();
        if n == 0 {
            break;
        }
        label.extend_from_slice(&buf[..n]);
        if label.len() >= 3 {
            break;
        }
    }
    label
}

#[tokio::test]
async fn tcp_entrypoint_routes_by_hostsni_from_client_hello() {
    let api_backend = spawn_labeled_tcp_backend(b"api").await;
    let other_backend = spawn_labeled_tcp_backend(b"oth").await;
    let gateway_address = free_tcp_address().await;
    let gateway = Arc::new(
        Gateway::new(hostsni_gateway_config(
            gateway_address,
            api_backend,
            other_backend,
        ))
        .unwrap(),
    );
    gateway.start().await.unwrap();

    assert_eq!(
        connect_and_read_label(gateway_address, "api.example.com").await,
        b"api"
    );
    assert_eq!(
        connect_and_read_label(gateway_address, "other.example.com").await,
        b"oth"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn tcp_hostsni_miss_does_not_select_a_backend() {
    let api_backend = spawn_labeled_tcp_backend(b"api").await;
    let other_backend = spawn_labeled_tcp_backend(b"oth").await;
    let gateway_address = free_tcp_address().await;
    let gateway = Arc::new(
        Gateway::new(hostsni_gateway_config(
            gateway_address,
            api_backend,
            other_backend,
        ))
        .unwrap(),
    );
    gateway.start().await.unwrap();

    let hello = client_hello_with_sni("unknown.example.com");
    let mut client = TcpStream::connect(gateway_address).await.unwrap();
    client.write_all(&hello).await.unwrap();
    let mut buf = [0_u8; 16];
    let n = tokio::time::timeout(Duration::from_millis(400), client.read(&mut buf))
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);
    assert_eq!(n, 0, "unmatched HostSNI must not relay a backend payload");

    gateway.shutdown().await;
}

async fn spawn_server_first_tcp_backend(label: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            // Push first: never wait for client bytes. A HostSNI peek on an
            // empty SNI table would stall this path for the peek timeout.
            let _ = stream.write_all(label).await;
            let _ = stream.shutdown().await;
        }
    });
    address
}

fn pathprefix_tcp_gateway_config(
    gateway_address: SocketAddr,
    backend: SocketAddr,
) -> GatewayConfig {
    let mut entrypoints = HashMap::new();
    entrypoints.insert(
        "tcp".to_string(),
        EntrypointConfig {
            address: gateway_address.to_string(),
            protocol: Protocol::Tcp,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: Vec::new(),
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
            trust_forwarded_headers: false,
        },
    );

    let mut routers = HashMap::new();
    routers.insert(
        "plain".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/`)".to_string(),
            service: "plain".to_string(),
            entrypoints: vec!["tcp".to_string()],
            middlewares: Vec::new(),
            priority: 10,
        },
    );

    let mut services = HashMap::new();
    services.insert(
        "plain".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: vec![ServerConfig {
                    url: format!("tcp://{backend}"),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
                tls_ca_file: None,
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
        static_bundles: HashMap::new(),
        middlewares: HashMap::new(),
        providers: Default::default(),
        management: Default::default(),
        observability: Default::default(),
        shutdown_timeout_secs: 0,
    }
}

#[tokio::test]
async fn tcp_pathprefix_only_relays_server_first_without_clienthello_peek_wait() {
    let backend = spawn_server_first_tcp_backend(b"sf1").await;
    let gateway_address = free_tcp_address().await;
    let gateway =
        Arc::new(Gateway::new(pathprefix_tcp_gateway_config(gateway_address, backend)).unwrap());
    gateway.start().await.unwrap();

    let mut client = TcpStream::connect(gateway_address).await.unwrap();
    // Client never writes. If Gateway peeked for ClientHello on an empty SNI
    // table, relay would wait ~200ms for bytes that never arrive.
    let started = std::time::Instant::now();
    let mut label = Vec::new();
    let mut buf = [0_u8; 16];
    loop {
        let n = tokio::time::timeout(Duration::from_millis(100), client.read(&mut buf))
            .await
            .expect(
                "PathPrefix-only TCP must relay server-first bytes without ClientHello peek wait",
            )
            .unwrap();
        if n == 0 {
            break;
        }
        label.extend_from_slice(&buf[..n]);
        if label.len() >= 3 {
            break;
        }
    }
    assert_eq!(label, b"sf1");
    assert!(
        started.elapsed() < Duration::from_millis(150),
        "server-first PathPrefix TCP took {:?}; empty-SNI peek wait would stall ~200ms",
        started.elapsed()
    );

    gateway.shutdown().await;
}
