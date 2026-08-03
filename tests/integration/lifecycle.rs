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

#[tokio::test]
async fn test_failed_start_never_starts_candidate_health_checks() {
    let blocked_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let blocked_port = blocked_listener.local_addr().unwrap().port();
    let (backend, mut candidate_probes) = spawn_health_probe_backend().await;
    let mut config = build_config(blocked_port, backend, "PathPrefix(`/`)").await;
    enable_fast_health_checks(&mut config);

    let gateway = Gateway::new(config).unwrap();
    assert!(gateway.start().await.is_err());
    let candidate_checker_never_started =
        tokio::time::timeout(Duration::from_millis(150), candidate_probes.recv())
            .await
            .is_err();

    gateway.shutdown().await;
    drop(blocked_listener);

    assert!(
        candidate_checker_never_started,
        "a failed startup candidate started probing its backend"
    );
}

#[tokio::test]
async fn test_reload_waits_for_shutdown_and_cannot_restart_background_work() {
    let port = free_port().await;
    let (stream_backend, first_chunk, release_response) =
        spawn_controlled_streaming_backend().await;
    let mut config = build_config(port, stream_backend, "PathPrefix(`/`)").await;
    config.shutdown_timeout_secs = 2;

    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();

    let request = tokio::spawn(async move {
        reqwest::get(format!("http://127.0.0.1:{port}/"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    first_chunk.await.unwrap();

    let shutdown_gateway = gateway.clone();
    let shutdown = tokio::spawn(async move {
        shutdown_gateway.shutdown().await;
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while gateway.state() != a3s_gateway::GatewayState::Stopping {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("gateway did not begin shutdown");

    let (candidate_backend, mut candidate_probes) = spawn_health_probe_backend().await;
    let mut candidate = build_config(port, candidate_backend, "PathPrefix(`/`)").await;
    enable_fast_health_checks(&mut candidate);
    let reload_gateway = gateway.clone();
    let mut reload = tokio::spawn(async move { reload_gateway.reload(candidate).await });

    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut reload)
            .await
            .is_err(),
        "reload completed while shutdown still owned the runtime lifecycle"
    );

    let concurrent_shutdown_gateway = gateway.clone();
    let mut concurrent_shutdown =
        tokio::spawn(async move { concurrent_shutdown_gateway.shutdown().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut concurrent_shutdown)
            .await
            .is_err(),
        "a concurrent shutdown returned before the gateway reached Stopped"
    );

    release_response.send(()).unwrap();
    assert_eq!(request.await.unwrap(), "firstsecond");
    tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .expect("shutdown did not complete after the active response")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), concurrent_shutdown)
        .await
        .expect("concurrent shutdown remained blocked after cleanup")
        .unwrap();

    let reload_error = tokio::time::timeout(Duration::from_secs(2), reload)
        .await
        .expect("reload remained blocked after shutdown")
        .unwrap()
        .unwrap_err();
    assert!(reload_error.to_string().contains("cannot reload"));

    let candidate_checker_never_started =
        tokio::time::timeout(Duration::from_millis(150), candidate_probes.recv())
            .await
            .is_err();
    assert!(candidate_checker_never_started);
    assert_eq!(gateway.state(), a3s_gateway::GatewayState::Stopped);
}
