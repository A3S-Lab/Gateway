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
