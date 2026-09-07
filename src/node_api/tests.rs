use super::*;

fn state_fixture() -> NodeApiState {
    NodeApiState {
        config: Arc::new(RwLock::new(GatewayConfig::default())),
        lifecycle_state: Arc::new(RwLock::new(GatewayState::Running)),
        start_time: Instant::now(),
        metrics: Arc::new(GatewayMetrics::new()),
        reload_managed_snapshot: None,
        managed_snapshots: Arc::new(ManagedSnapshotStore::new(None, None)),
        usage_spool: Arc::new(RwLock::new(None)),
    }
}

#[test]
fn node_api_matches_only_the_configured_path_boundary() {
    let api = NodeApi::new("/api/gateway", None);

    assert!(api.matches("/api/gateway"));
    assert!(api.matches("/api/gateway/health"));
    assert!(!api.matches("/api/gatewayfoo"));
    assert!(api.matches_subpath("/api/gateway/snapshots/apply", "/snapshots/apply"));
    assert!(api.matches_subpath("/api/gateway/snapshots/apply/", "/snapshots/apply"));
    assert!(!api.matches_subpath("/api/gateway/nested/snapshots/apply", "/snapshots/apply"));
}

#[test]
fn node_api_root_prefix_routes_management_subpaths() {
    let api = NodeApi::new("/", None);

    assert!(api.matches("/health"));
    assert!(api.matches_subpath("/snapshots/apply", "/snapshots/apply"));
    assert!(api.matches_subpath("/snapshots/status/", "/snapshots/status"));
    assert!(!api.matches_subpath("/other/snapshots/apply", "/snapshots/apply"));
}

#[test]
fn node_api_exposes_version() {
    let api = NodeApi::new("/api/gateway", None);
    let state = state_fixture();
    let response = api.handle(&Method::GET, "/api/gateway/version", &state);

    assert_eq!(response.status, 200);
    assert!(response.body.contains("a3s-gateway"));
}

#[test]
fn node_api_rejects_operator_endpoints() {
    let api = NodeApi::new("/api/gateway", None);
    let state = state_fixture();

    for path in [
        "/config",
        "/routes",
        "/routes/example",
        "/services",
        "/services/example",
        "/backends",
        "/events",
    ] {
        let response = api.handle(&Method::GET, &format!("/api/gateway{path}"), &state);
        assert_eq!(response.status, 404, "operator endpoint remained: {path}");
    }

    for path in ["/config/validate", "/config/reload"] {
        let response = api.handle(&Method::POST, &format!("/api/gateway{path}"), &state);
        assert_eq!(response.status, 404, "operator endpoint remained: {path}");
    }
}

#[tokio::test]
async fn node_api_health_exposes_the_durable_usage_spool() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = uuid::Uuid::new_v4();
    let spool = crate::usage::UsageSpool::open(crate::usage::UsageSpoolOptions {
        directory: directory.path().join("usage"),
        gateway_id,
        max_bytes: crate::config::MIN_USAGE_SPOOL_MAX_BYTES,
    })
    .await
    .unwrap();
    let acknowledged = spool
        .append(uuid::Uuid::new_v4(), b"acknowledged")
        .await
        .unwrap();
    spool.acknowledge(acknowledged).await.unwrap();
    let retained = spool
        .append(uuid::Uuid::new_v4(), b"retained")
        .await
        .unwrap();
    let mut state = state_fixture();
    state.usage_spool = Arc::new(RwLock::new(Some(Arc::new(spool))));

    let response =
        NodeApi::new("/api/gateway", None).handle(&Method::GET, "/api/gateway/health", &state);
    let health: HealthStatus = serde_json::from_str(&response.body).unwrap();

    assert_eq!(response.status, 200);
    let status = health.usage_spool.unwrap();
    assert_eq!(status.gateway_id, gateway_id);
    assert!(status.writable);
    assert_eq!(status.next_sequence, 3);
    assert_eq!(status.acknowledged_through, Some(acknowledged));
    assert_eq!(status.oldest_retained_cursor, Some(retained));
}

#[test]
fn version_info_identifies_the_machine_contract() {
    let version = VersionInfo::current();

    assert_eq!(version.name, "a3s-gateway");
    assert!(!version.version.is_empty());
    assert_eq!(version.api_version, "v1");
}

#[test]
fn node_api_policy_reconfiguration_is_prepared_and_published_atomically() {
    let token_env = "A3S_TEST_NODE_API_POLICY_TOKEN";
    std::env::set_var(token_env, "old-token");
    let config = ManagementConfig {
        enabled: true,
        address: "127.0.0.1:9090".to_string(),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(token_env.to_string()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };
    let control = NodeApiListenerControl {
        policy: Arc::new(RwLock::new(Arc::new(build_policy(&config).unwrap()))),
    };

    std::env::set_var(token_env, "new-token");
    let mut next = config.clone();
    next.path_prefix = "/api/node".to_string();
    let prepared = control.prepare_reconfigure(&next).unwrap();
    control.commit(prepared);

    let policy = control.snapshot();
    assert_eq!(policy.api.path_prefix, "/api/node");
    assert_eq!(policy.api.auth_token.as_deref(), Some("new-token"));
    assert_eq!(policy.transport_generation, 0);
    std::env::remove_var(token_env);
}

#[test]
fn disabled_node_api_policy_cannot_be_prepared() {
    let control = NodeApiListenerControl {
        policy: Arc::new(RwLock::new(Arc::new(NodeApiPolicy {
            api: Arc::new(NodeApi::new("/api/gateway", None)),
            tls_acceptor: None,
            auth_enabled: false,
            client_cert_required: false,
            tls_identity: None,
            transport_generation: 0,
        }))),
    };
    match control.prepare_reconfigure(&ManagementConfig::default()) {
        Err(error) => assert!(error.to_string().contains("disabled listener")),
        Ok(_) => panic!("a disabled node API policy was prepared"),
    }
}
