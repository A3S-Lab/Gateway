//! Management-endpoint evidence for topology-bounded service telemetry.

use a3s_gateway::config::{
    EntrypointConfig, GatewayConfig, LoadBalancerConfig, ObservabilityConfig, RouterConfig,
    ServerConfig, ServiceConfig, Strategy,
};
use a3s_gateway::Gateway;
use futures_util::StreamExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn free_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn streaming_backend() -> (
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
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await.unwrap();
            if read == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..read]);
        }

        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nd\r\ndata: hello\n\n\r\n";
        stream.write_all(response.as_bytes()).await.unwrap();
        stream.flush().await.unwrap();
        let _ = started_tx.send(());

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

fn config(
    traffic_address: SocketAddr,
    management_address: SocketAddr,
    backend_address: SocketAddr,
) -> GatewayConfig {
    let management = a3s_gateway::config::ManagementConfig {
        enabled: true,
        address: management_address.to_string(),
        auth_token_env: None,
        ..a3s_gateway::config::ManagementConfig::default()
    };

    GatewayConfig {
        entrypoints: HashMap::from([(
            "traffic".to_string(),
            EntrypointConfig::new(traffic_address.to_string()),
        )]),
        routers: HashMap::from([(
            "inference".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/`)".to_string(),
                service: "model".to_string(),
                entrypoints: vec!["traffic".to_string()],
                middlewares: Vec::new(),
                priority: 0,
            },
        )]),
        services: HashMap::from([(
            "model".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "1s".to_string(),
                    stream_idle_timeout: "30s".to_string(),
                    stream_total_timeout: "60s".to_string(),
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
        )]),
        management,
        observability: ObservabilityConfig {
            metrics_enabled: true,
            access_log_enabled: false,
            tracing_enabled: false,
        },
        ..GatewayConfig::default()
    }
}

async fn metrics(client: &reqwest::Client, address: SocketAddr) -> String {
    client
        .get(format!("http://{address}/api/gateway/metrics"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap()
}

#[tokio::test]
async fn management_metrics_track_stream_ttft_pressure_and_drop_cleanup() {
    let (backend, stream_started, upstream_disconnected) = streaming_backend().await;
    let traffic = free_address().await;
    let management = free_address().await;
    let gateway = Arc::new(Gateway::new(config(traffic, management, backend)).unwrap());
    gateway.start().await.unwrap();

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://{traffic}/v1/chat/completions"))
        .header("accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    tokio::time::timeout(Duration::from_secs(2), stream_started)
        .await
        .unwrap()
        .unwrap();

    let mut body = response.bytes_stream();
    let first = tokio::time::timeout(Duration::from_secs(2), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(first.starts_with(b"data:"));

    let during = metrics(&client, management).await;
    assert!(during.contains("gateway_service_active_requests{service=\"model\"} 1"));
    assert!(during.contains("gateway_service_ttft_seconds_count{service=\"model\"} 1"));
    assert!(during.contains(
        "gateway_service_telemetry_observation_timestamp_seconds{service=\"model\",signal=\"ttft\"}"
    ));
    assert!(during.contains("gateway_backend_active_requests{service=\"model\",backend_id=\"b_"));
    assert!(during.contains("gateway_backend_healthy{service=\"model\",backend_id=\"b_"));
    assert!(!during.contains(&backend.to_string()));

    drop(body);
    tokio::time::timeout(Duration::from_secs(2), upstream_disconnected)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let output = metrics(&client, management).await;
            if output.contains("gateway_service_active_requests{service=\"model\"} 0")
                && output
                    .contains("gateway_service_request_duration_seconds_count{service=\"model\"} 1")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    gateway.shutdown().await;
}
