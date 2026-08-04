#[tokio::test]
async fn test_api_gateway_path_is_regular_traffic() {
    let port = free_port().await;
    let backend = spawn_backend("regular-traffic").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/gateway/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "regular-traffic");

    gw.shutdown().await;
}
#[tokio::test]
async fn test_node_api_uses_dedicated_listener() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let mut config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;
    config.mode = OperatingMode::CloudManaged;
    let token_env = format!("A3S_TEST_GATEWAY_ADMIN_TOKEN_{}", management_port);
    std::env::set_var(&token_env, "secret-token");
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;

    let client = reqwest::Client::new();
    let management_url = format!("http://127.0.0.1:{}/api/gateway/health", management_port);
    let unauthorized = client.get(&management_url).send().await.unwrap();
    assert_eq!(unauthorized.status(), 401);

    let management_resp = client
        .get(&management_url)
        .bearer_auth("secret-token")
        .send()
        .await
        .unwrap();
    assert_eq!(management_resp.status(), 200);
    let management_health: serde_json::Value = management_resp.json().await.unwrap();
    assert_eq!(management_health["state"], "Running");
    assert_eq!(management_health["mode"], "cloud-managed");

    let traffic_resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/gateway/health",
        traffic_port
    ))
    .await
    .unwrap();
    assert_eq!(traffic_resp.status(), 200);
    assert_eq!(traffic_resp.text().await.unwrap(), "traffic-ok");

    gw.shutdown().await;
    std::env::remove_var(token_env);
}

#[tokio::test]
async fn test_node_api_exposes_only_the_machine_contract() {
    let traffic_port = free_port().await;
    let node_api_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let mut config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{node_api_port}"),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: None,
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(node_api_port).await;

    let client = reqwest::Client::new();
    let base_url = format!("http://127.0.0.1:{node_api_port}/api/gateway");
    let mut machine_statuses = Vec::new();
    for path in ["health", "metrics", "version"] {
        let status = client
            .get(format!("{base_url}/{path}"))
            .send()
            .await
            .unwrap()
            .status();
        machine_statuses.push((path, status));
    }

    let mut removed_statuses = Vec::new();
    for path in [
        "config",
        "routes",
        "routes/example",
        "services",
        "services/example",
        "backends",
        "events",
    ] {
        let status = client
            .get(format!("{base_url}/{path}"))
            .send()
            .await
            .unwrap()
            .status();
        removed_statuses.push((path, status));
    }
    for path in ["config/validate", "config/reload"] {
        let status = client
            .post(format!("{base_url}/{path}"))
            .body("invalid operator payload")
            .send()
            .await
            .unwrap()
            .status();
        removed_statuses.push((path, status));
    }

    let traffic = reqwest::get(format!("http://127.0.0.1:{traffic_port}/"))
        .await
        .unwrap();
    let traffic_status = traffic.status();
    let traffic_body = traffic.text().await.unwrap();
    gateway.shutdown().await;

    assert!(machine_statuses
        .iter()
        .all(|(_, status)| *status == reqwest::StatusCode::OK));
    assert!(
        removed_statuses
            .iter()
            .all(|(_, status)| *status == reqwest::StatusCode::NOT_FOUND),
        "operator endpoints remain exposed: {removed_statuses:?}"
    );
    assert_eq!(traffic_status, reqwest::StatusCode::OK);
    assert_eq!(traffic_body, "traffic-ok");
}

#[tokio::test]
async fn test_node_api_rejects_disallowed_ip() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let mut config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: None,
        allowed_ips: vec!["10.0.0.1".to_string()],
        tls: None,
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(management_port).await;

    let management_url = format!("http://127.0.0.1:{}/api/gateway/health", management_port);
    let resp = reqwest::get(management_url).await.unwrap();
    assert_eq!(resp.status(), 403);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_node_api_requires_valid_client_certificate() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let fixture = management_mtls_fixture();
    let mut config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: None,
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: Some(ManagementTlsConfig {
            cert_file: fixture.server_cert_file.clone(),
            key_file: fixture.server_key_file.clone(),
            client_ca_file: Some(fixture.client_ca_file.clone()),
            require_client_cert: true,
            min_version: "1.2".to_string(),
        }),
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(management_port).await;

    let ca_cert = reqwest::Certificate::from_pem(fixture.client_ca_pem.as_bytes()).unwrap();
    let no_cert_client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .build()
        .unwrap();
    let management_url = format!("https://127.0.0.1:{}/api/gateway/health", management_port);
    let no_cert_result = no_cert_client.get(&management_url).send().await;
    assert!(no_cert_result.is_err());

    let ca_cert = reqwest::Certificate::from_pem(fixture.client_ca_pem.as_bytes()).unwrap();
    let identity = reqwest::Identity::from_pem(&fixture.client_identity_pem).unwrap();
    let mtls_client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .build()
        .unwrap();
    let resp = mtls_client.get(management_url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("Running"));

    gw.shutdown().await;
}

#[tokio::test]
async fn test_reload_enables_node_api_on_dedicated_listener() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config.clone()).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;

    let token_env = format!("A3S_TEST_GATEWAY_RELOAD_ADMIN_TOKEN_{}", management_port);
    std::env::set_var(&token_env, "reload-secret");
    let mut new_config = config;
    new_config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    gw.reload(new_config).await.unwrap();
    wait_ready(management_port).await;

    let management_url = format!("http://127.0.0.1:{}/api/gateway/health", management_port);
    let resp = reqwest::Client::new()
        .get(management_url)
        .bearer_auth("reload-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let traffic_resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/gateway/health",
        traffic_port
    ))
    .await
    .unwrap();
    assert_eq!(traffic_resp.status(), 200);
    assert_eq!(traffic_resp.text().await.unwrap(), "traffic-ok");

    gw.shutdown().await;
    std::env::remove_var(token_env);
}

#[tokio::test]
async fn test_failed_node_api_reload_keeps_old_runtime_and_listener() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let mut config = build_config(traffic_port, backend_v1, "PathPrefix(`/`)").await;

    let token_env = format!("A3S_TEST_GATEWAY_OLD_ADMIN_TOKEN_{}", management_port);
    let missing_token_env = format!("A3S_TEST_GATEWAY_MISSING_ADMIN_TOKEN_{}", management_port);
    std::env::set_var(&token_env, "old-secret");
    std::env::remove_var(&missing_token_env);
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;

    let mut new_config = build_config(traffic_port, backend_v2, "PathPrefix(`/`)").await;
    new_config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(missing_token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let err = gw.reload(new_config).await.unwrap_err();
    assert!(err.to_string().contains(&missing_token_env));

    let traffic_resp = reqwest::get(format!("http://127.0.0.1:{}/", traffic_port))
        .await
        .unwrap();
    assert_eq!(traffic_resp.status(), 200);
    assert_eq!(traffic_resp.text().await.unwrap(), "v1");

    let management_url = format!("http://127.0.0.1:{}/api/gateway/health", management_port);
    let management_resp = reqwest::Client::new()
        .get(management_url)
        .bearer_auth("old-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(management_resp.status(), 200);

    gw.shutdown().await;
    std::env::remove_var(token_env);
    std::env::remove_var(missing_token_env);
}

#[tokio::test]
async fn test_failed_entrypoint_reload_keeps_old_listener_and_runtime() {
    let port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let config = build_config(port, backend_v1, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let mut new_config = build_config(port, backend_v2, "PathPrefix(`/`)").await;
    new_config.entrypoints.insert(
        "admin".to_string(),
        EntrypointConfig {
            address: format!("127.0.0.1:{}", port),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let err = gw.reload(new_config).await.unwrap_err();
    assert!(err.to_string().contains("Failed to bind"));

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "v1");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_failed_entrypoint_reload_does_not_switch_node_api_listener() {
    let traffic_port = free_port().await;
    let old_management_port = free_port().await;
    let new_management_port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let mut config = build_config(traffic_port, backend_v1, "PathPrefix(`/`)").await;

    let old_token_env = format!("A3S_TEST_GATEWAY_OLD_MGMT_TOKEN_{}", old_management_port);
    let new_token_env = format!("A3S_TEST_GATEWAY_NEW_MGMT_TOKEN_{}", new_management_port);
    std::env::set_var(&old_token_env, "old-token");
    std::env::set_var(&new_token_env, "new-token");
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", old_management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(old_token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(old_management_port).await;

    let mut new_config = build_config(traffic_port, backend_v2, "PathPrefix(`/`)").await;
    new_config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", new_management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(new_token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };
    new_config.entrypoints.insert(
        "admin".to_string(),
        EntrypointConfig {
            address: format!("127.0.0.1:{}", traffic_port),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let err = gw.reload(new_config).await.unwrap_err();
    assert!(err.to_string().contains("Failed to bind"));

    let old_management_url = format!(
        "http://127.0.0.1:{}/api/gateway/health",
        old_management_port
    );
    let old_management_resp = reqwest::Client::new()
        .get(old_management_url)
        .bearer_auth("old-token")
        .send()
        .await
        .unwrap();
    assert_eq!(old_management_resp.status(), 200);

    let new_management_connect = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", new_management_port)),
    )
    .await;
    assert!(!matches!(new_management_connect, Ok(Ok(_))));

    let traffic_resp = reqwest::get(format!("http://127.0.0.1:{}/", traffic_port))
        .await
        .unwrap();
    assert_eq!(traffic_resp.status(), 200);
    assert_eq!(traffic_resp.text().await.unwrap(), "v1");

    gw.shutdown().await;
    std::env::remove_var(old_token_env);
    std::env::remove_var(new_token_env);
}

#[tokio::test]
async fn test_entrypoint_address_change_restarts_only_changed_listener() {
    let old_port = free_port().await;
    let new_port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let config = build_config(old_port, backend_v1, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(old_port).await;

    let mut new_config = build_config(new_port, backend_v2, "PathPrefix(`/`)").await;
    new_config
        .routers
        .get_mut("test-router")
        .unwrap()
        .entrypoints = vec!["web".to_string()];

    gw.reload(new_config).await.unwrap();
    wait_ready(new_port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", new_port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "v2");

    gw.shutdown().await;
}
