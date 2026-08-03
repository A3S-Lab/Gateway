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
async fn test_http_proxy_forwards_client_context_headers() {
    let port = free_port().await;
    let (backend, captured) = spawn_capture_backend().await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/headers?trace=1", port))
        .header("Host", "public.example.test:8080")
        .header("X-Forwarded-For", "198.51.100.10")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "captured");

    let request = tokio::time::timeout(Duration::from_secs(2), captured)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        captured_header(&request, "x-forwarded-for").as_deref(),
        Some("198.51.100.10, 127.0.0.1")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-host").as_deref(),
        Some("public.example.test:8080")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-proto").as_deref(),
        Some("http")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-port").as_deref(),
        Some("8080")
    );

    gw.shutdown().await;
}

#[tokio::test]
async fn test_http_proxy_forwards_large_request_body() {
    let port = free_port().await;
    let backend = spawn_body_length_backend().await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let body = vec![b'a'; 1024 * 1024];
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/upload", port))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), (1024 * 1024).to_string());

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
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
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

    // /api routes to the API backend.
    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/test", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "api-response");

    // /web routes to the web backend.
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
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_http_proxy_respects_service_request_timeout() {
    let port = free_port().await;
    let backend = spawn_delayed_backend("too slow", Duration::from_millis(250)).await;
    let mut config = build_config(port, backend, "PathPrefix(`/`)").await;
    config
        .services
        .get_mut("test-svc")
        .unwrap()
        .load_balancer
        .request_timeout = "50ms".to_string();

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/slow", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);

    gw.shutdown().await;
}
