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
async fn test_http_proxy_relays_first_chunk_before_upstream_completion() {
    let port = free_port().await;
    let (backend, first_chunk_sent, release_second_chunk) =
        spawn_controlled_streaming_backend().await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();
    wait_ready(port).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    client
        .write_all(b"GET /stream HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), first_chunk_sent)
        .await
        .expect("backend should write its first response chunk")
        .unwrap();

    let mut before_completion = Vec::new();
    tokio::time::timeout(Duration::from_millis(500), async {
        let mut buf = [0_u8; 1024];
        while !before_completion
            .windows(b"first".len())
            .any(|window| window == b"first")
        {
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "downstream closed before the first response chunk");
            before_completion.extend_from_slice(&buf[..n]);
        }
    })
    .await
    .expect("Gateway must relay the first chunk before the upstream response completes");

    release_second_chunk.send(()).unwrap();
    let mut after_completion = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut after_completion))
        .await
        .expect("Gateway should finish the downstream response")
        .unwrap();
    before_completion.extend_from_slice(&after_completion);
    assert!(before_completion
        .windows(b"second".len())
        .any(|window| window == b"second"));

    gateway.shutdown().await;
}

#[tokio::test]
async fn test_http_proxy_enforces_response_idle_timeout_after_headers() {
    let port = free_port().await;
    let (backend, first_chunk_sent, release_second_chunk) =
        spawn_controlled_streaming_backend().await;
    let mut config = build_config(port, backend, "PathPrefix(`/`)").await;
    config
        .services
        .get_mut("test-svc")
        .unwrap()
        .load_balancer
        .stream_idle_timeout = "50ms".to_string();

    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();
    wait_ready(port).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    client
        .write_all(b"GET /idle HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), first_chunk_sent)
        .await
        .expect("backend should write its first response chunk")
        .unwrap();

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(1), client.read_to_end(&mut response))
        .await
        .expect("Gateway should terminate an idle ordinary HTTP response")
        .unwrap();
    assert!(response
        .windows(b"first".len())
        .any(|window| window == b"first"));
    assert!(!response
        .windows(b"second".len())
        .any(|window| window == b"second"));

    let _ = release_second_chunk.send(());
    gateway.shutdown().await;
}

#[tokio::test]
async fn test_compress_middleware_encodes_eligible_http_response() {
    use std::io::Read as _;

    let port = free_port().await;
    let original = "compressible gateway response ".repeat(256);
    let backend = spawn_backend(original.clone()).await;
    let mut config = build_config(port, backend, "PathPrefix(`/`)").await;
    config.middlewares.insert(
        "compress".to_string(),
        MiddlewareConfig {
            middleware_type: "compress".to_string(),
            ..MiddlewareConfig::default()
        },
    );
    config
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("compress".to_string());

    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();
    wait_ready(port).await;

    let client = reqwest::Client::new();
    let response = client
        .get(format!("http://127.0.0.1:{port}/compressed"))
        .header(http::header::ACCEPT_ENCODING, "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()[http::header::CONTENT_ENCODING], "gzip");
    assert!(response
        .headers()
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("accept-encoding")));
    assert!(!response.headers().contains_key("x-gateway-compress"));
    let encoded = response.bytes().await.unwrap();
    assert!(encoded.len() < original.len());
    let mut decoder = flate2::read::GzDecoder::new(encoded.as_ref());
    let mut decoded = String::new();
    decoder.read_to_string(&mut decoded).unwrap();
    assert_eq!(decoded, original);

    let response = client
        .get(format!("http://127.0.0.1:{port}/identity"))
        .header(http::header::ACCEPT_ENCODING, "gzip;q=0")
        .send()
        .await
        .unwrap();
    assert!(!response
        .headers()
        .contains_key(http::header::CONTENT_ENCODING));
    assert_eq!(response.text().await.unwrap(), original);

    gateway.shutdown().await;
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

async fn assert_connection_nominated_headers_are_stripped(accept: Option<&str>) {
    let port = free_port().await;
    let (backend, captured) = spawn_connection_header_backend().await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let client = reqwest::Client::new();
    let mut request = client
        .get(format!("http://127.0.0.1:{port}/connection-options"))
        .header("Connection", "keep-alive, X-Client-Connection")
        .header("X-Client-Connection", "must-not-reach-upstream")
        .header("X-End-To-End-Request", "preserved");
    if let Some(accept) = accept {
        request = request.header(http::header::ACCEPT, accept);
    }
    let response = request.send().await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let end_to_end_response = response
        .headers()
        .get("x-end-to-end-response")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let leaked_backend_header = response.headers().contains_key("x-backend-connection");
    let body = response.text().await.unwrap();

    let request = tokio::time::timeout(Duration::from_secs(2), captured)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(captured_header(&request, "x-client-connection"), None);
    assert_eq!(
        captured_header(&request, "x-end-to-end-request").as_deref(),
        Some("preserved")
    );
    assert_eq!(end_to_end_response.as_deref(), Some("preserved"));
    assert!(!leaked_backend_header);
    assert_eq!(body, "ok");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_http_proxy_strips_connection_nominated_headers() {
    assert_connection_nominated_headers_are_stripped(None).await;
}

#[tokio::test]
async fn test_sse_proxy_strips_connection_nominated_headers() {
    assert_connection_nominated_headers_are_stripped(Some("text/event-stream")).await;
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
