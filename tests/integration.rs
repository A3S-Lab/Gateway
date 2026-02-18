//! Integration tests for A3S Gateway
//!
//! These tests spin up real TCP listeners and HTTP backends to verify
//! end-to-end request flow through the gateway.

use a3s_gateway::config::{
    EntrypointConfig, GatewayConfig, LoadBalancerConfig, Protocol, RouterConfig, ServerConfig,
    ServiceConfig, Strategy,
};
use a3s_gateway::Gateway;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find a free port on localhost
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Spawn a minimal HTTP backend that returns a fixed body for any request.
/// Returns the address it's listening on.
async fn spawn_backend(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let body = body.to_string();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    addr
}

/// Build a minimal gateway config with one entrypoint, one router, one service.
async fn build_config(
    gateway_port: u16,
    backend_addr: SocketAddr,
    rule: &str,
) -> GatewayConfig {
    let mut entrypoints = HashMap::new();
    entrypoints.insert(
        "web".to_string(),
        EntrypointConfig {
            address: format!("127.0.0.1:{}", gateway_port),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let mut routers = HashMap::new();
    routers.insert(
        "test-router".to_string(),
        RouterConfig {
            rule: rule.to_string(),
            service: "test-svc".to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: vec![],
            priority: 0,
        },
    );

    let mut services = HashMap::new();
    services.insert(
        "test-svc".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                servers: vec![ServerConfig {
                    url: format!("http://{}", backend_addr),
                    weight: 1,
                }],
                health_check: None,
                sticky: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        },
    );

    GatewayConfig {
        entrypoints,
        routers,
        services,
        middlewares: HashMap::new(),
        providers: Default::default(),
        shutdown_timeout_secs: 5,
    }
}

/// Wait briefly for the gateway to be ready to accept connections.
async fn wait_ready(port: u16) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("Gateway did not become ready on port {}", port);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_gateway_lifecycle() {
    let port = free_port().await;
    let backend = spawn_backend("ok").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    assert!(gw.is_running());

    wait_ready(port).await;

    // Health check
    let health = gw.health();
    assert_eq!(health.state, a3s_gateway::GatewayState::Running);

    gw.shutdown().await;
    assert!(gw.is_shutdown());
}

#[tokio::test]
async fn test_http_proxy_round_trip() {
    let port = free_port().await;
    let backend = spawn_backend("hello from backend").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // Send a real HTTP request through the gateway
    let resp = reqwest::get(format!("http://127.0.0.1:{}/anything", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello from backend");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_path_prefix_routing() {
    let port = free_port().await;
    let backend_api = spawn_backend("api-response").await;
    let backend_web = spawn_backend("web-response").await;

    let mut config = build_config(port, backend_api, "PathPrefix(`/api`)").await;
    config.routers.insert(
        "web-router".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/web`)".to_string(),
            service: "web-svc".to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: vec![],
            priority: 0,
        },
    );
    config.services.insert(
        "web-svc".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                servers: vec![ServerConfig {
                    url: format!("http://{}", backend_web),
                    weight: 1,
                }],
                health_check: None,
                sticky: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        },
    );

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // /api → api backend
    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/test", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "api-response");

    // /web → web backend
    let resp = reqwest::get(format!("http://127.0.0.1:{}/web/page", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "web-response");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_no_route_returns_404() {
    let port = free_port().await;
    let backend = spawn_backend("ok").await;
    // Only match /api prefix
    let config = build_config(port, backend, "PathPrefix(`/api`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // /unknown should get 404
    let resp = reqwest::get(format!("http://127.0.0.1:{}/unknown", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_backend_down_returns_503() {
    let port = free_port().await;
    // Point to a port that nothing is listening on
    let dead_port = free_port().await;
    let dead_addr: SocketAddr = format!("127.0.0.1:{}", dead_port).parse().unwrap();
    let config = build_config(port, dead_addr, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/test", port))
        .await
        .unwrap();
    // Should get 502 or 503 when backend is unreachable
    assert!(resp.status().as_u16() >= 500);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_reload_switches_backend() {
    let port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let config = build_config(port, backend_v1, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // Verify v1
    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "v1");

    // Reload with v2 backend (same port — reload stops old listeners first)
    let new_config = build_config(port, backend_v2, "PathPrefix(`/`)").await;
    gw.reload(new_config).await.unwrap();

    // Wait for new listener to bind
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "v2");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_invalid_config_rejected() {
    // Router references nonexistent service
    let mut config = GatewayConfig::default();
    config.routers.insert(
        "bad".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/`)".to_string(),
            service: "nonexistent".to_string(),
            entrypoints: vec![],
            middlewares: vec![],
            priority: 0,
        },
    );
    assert!(Gateway::new(config).is_err());
}

#[tokio::test]
async fn test_multiple_entrypoints() {
    let port1 = free_port().await;
    let port2 = free_port().await;
    let backend = spawn_backend("multi-ep").await;

    let mut config = build_config(port1, backend, "PathPrefix(`/`)").await;
    // Router must list both entrypoints to accept traffic on both
    config.routers.get_mut("test-router").unwrap().entrypoints =
        vec!["web".to_string(), "web2".to_string()];
    config.entrypoints.insert(
        "web2".to_string(),
        EntrypointConfig {
            address: format!("127.0.0.1:{}", port2),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port1).await;
    wait_ready(port2).await;

    // Both entrypoints should proxy to the same backend
    let r1 = reqwest::get(format!("http://127.0.0.1:{}/", port1))
        .await
        .unwrap();
    assert_eq!(r1.text().await.unwrap(), "multi-ep");

    let r2 = reqwest::get(format!("http://127.0.0.1:{}/", port2))
        .await
        .unwrap();
    assert_eq!(r2.text().await.unwrap(), "multi-ep");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_dashboard_api_via_http() {
    let port = free_port().await;
    let backend = spawn_backend("ok").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // The dashboard API is not wired into the entrypoint HTTP handler,
    // but we can test it programmatically
    let dashboard = a3s_gateway::dashboard::DashboardApi::new("/api/gateway");
    let resp = dashboard.handle("/api/gateway/health", &gw).unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("Running"));

    let resp = dashboard.handle("/api/gateway/routes", &gw).unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("test-router"));

    let resp = dashboard.handle("/api/gateway/services", &gw).unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("test-svc"));

    let resp = dashboard.handle("/api/gateway/version", &gw).unwrap();
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("a3s-gateway"));

    gw.shutdown().await;
}

#[tokio::test]
async fn test_concurrent_requests() {
    let port = free_port().await;
    let backend = spawn_backend("concurrent-ok").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // Fire 20 concurrent requests
    let mut handles = Vec::new();
    for _ in 0..20 {
        let url = format!("http://127.0.0.1:{}/", port);
        handles.push(tokio::spawn(async move {
            reqwest::get(&url).await.unwrap().text().await.unwrap()
        }));
    }

    for h in handles {
        let body = h.await.unwrap();
        assert_eq!(body, "concurrent-ok");
    }

    // Verify metrics recorded requests
    let snapshot = gw.metrics().snapshot();
    assert!(snapshot.total_requests >= 20);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_graceful_shutdown_completes() {
    let port = free_port().await;
    let backend = spawn_backend("shutdown-test").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // Verify it's working
    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Shutdown should complete without hanging
    let gw_clone = gw.clone();
    let shutdown = tokio::spawn(async move {
        gw_clone.shutdown().await;
    });

    tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
        .await
        .expect("Shutdown should complete within 5 seconds")
        .unwrap();

    assert_eq!(gw.state(), a3s_gateway::GatewayState::Stopped);
}
