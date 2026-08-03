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

    // Reload with v2 backend on the same entrypoint. This should hot-swap the
    // runtime state without dropping or rebinding the traffic listener.
    let new_config = build_config(port, backend_v2, "PathPrefix(`/`)").await;
    gw.reload(new_config).await.unwrap();

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "v2");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_reload_rejects_invalid_middleware_pipeline_and_preserves_live_traffic() {
    let port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let config = build_config(port, backend_v1, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let mut invalid = build_config(port, backend_v2, "PathPrefix(`/`)").await;
    invalid.middlewares.insert(
        "broken".to_string(),
        MiddlewareConfig {
            middleware_type: "unknown-type".to_string(),
            ..MiddlewareConfig::default()
        },
    );
    invalid
        .routers
        .get_mut("test-router")
        .unwrap()
        .middlewares
        .push("broken".to_string());

    let error = gw.reload(invalid).await.unwrap_err();
    assert!(error.to_string().contains("Middleware 'broken'"));
    assert!(error.to_string().contains("Unknown middleware type"));

    let response = reqwest::get(format!("http://127.0.0.1:{port}/"))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "v1");
    assert!(gw.is_running());

    gw.shutdown().await;
}

#[tokio::test]
async fn test_file_provider_reload_updates_live_traffic() {
    let port = free_port().await;
    let backend_v1 = spawn_backend("file-v1").await;
    let backend_v2 = spawn_backend("file-v2").await;
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.acl");

    write_file(&config_path, gateway_acl(port, backend_v1, true)).await;
    let watcher = FileWatcher::new(&config_path);
    let config = watcher.load_config().unwrap();

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "file-v1");

    let rx = watcher.watch().unwrap();
    tokio::time::sleep(Duration::from_millis(650)).await;
    write_file(&config_path, gateway_acl(port, backend_v2, true)).await;

    let event = wait_for_file_reload(rx).await;
    let new_config = event.config.unwrap();
    gw.reload(new_config).await.unwrap();

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "file-v2");
    assert!(watcher.reload_count() >= 1);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_discovery_provider_reload_updates_live_traffic() {
    let gateway_port = free_port().await;
    let seed = spawn_discovery_seed("discovered-ok").await;

    let mut config = GatewayConfig::default();
    config.entrypoints.clear();
    config.entrypoints.insert(
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
    config.routers.clear();
    config.services.clear();
    config.providers.discovery = Some(DiscoveryConfig {
        seeds: vec![DiscoverySeedConfig {
            url: format!("http://{}", seed),
        }],
        poll_interval_secs: 1,
        timeout_secs: 1,
    });

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(gateway_port).await;

    let url = format!("http://127.0.0.1:{}/discovered", gateway_port);
    for _ in 0..50 {
        if let Ok(resp) = reqwest::get(&url).await {
            if resp.status() == 200 && resp.text().await.unwrap_or_default() == "discovered-ok" {
                gw.shutdown().await;
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    gw.shutdown().await;
    panic!("discovery provider did not update live traffic");
}

#[tokio::test]
async fn test_revision_only_service_routes_to_revision_backend() {
    let port = free_port().await;
    let backend = spawn_backend("revision-v1").await;
    let mut config = build_config(port, backend, "PathPrefix(`/`)").await;

    let service = config.services.get_mut("test-svc").unwrap();
    service.load_balancer.servers.clear();
    service.revisions = vec![RevisionConfig {
        name: "v1".to_string(),
        traffic_percent: 100,
        servers: vec![ServerConfig {
            url: format!("http://{}", backend),
            weight: 1,
        }],
        strategy: Strategy::RoundRobin,
    }];

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "revision-v1");

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
