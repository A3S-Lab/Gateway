use super::*;

fn minimal_config() -> GatewayConfig {
    let mut config = GatewayConfig::default();
    config.routers.clear();
    config.services.clear();
    config.middlewares.clear();
    config
}

#[test]
fn test_gateway_new() {
    let gw = Gateway::new(minimal_config()).unwrap();
    assert_eq!(gw.state(), GatewayState::Created);
    assert!(!gw.is_running());
    assert!(!gw.is_shutdown());
}

#[test]
fn test_gateway_new_invalid_config() {
    use crate::config::RouterConfig;
    let mut config = minimal_config();
    config.routers.insert(
        "bad".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/api`)".to_string(),
            service: "nonexistent".to_string(),
            entrypoints: vec![],
            middlewares: vec![],
            priority: 0,
        },
    );
    let result = Gateway::new(config);
    assert!(result.is_err());
}

#[test]
fn test_gateway_health() {
    let gw = Gateway::new(minimal_config()).unwrap();
    let health = gw.health();
    assert_eq!(health.state, GatewayState::Created);
    assert_eq!(health.total_requests, 0);
}

#[test]
fn test_gateway_config() {
    let config = minimal_config();
    let gw = Gateway::new(config.clone()).unwrap();
    let retrieved = gw.config();
    assert_eq!(retrieved.entrypoints.len(), config.entrypoints.len());
}

#[test]
fn test_entrypoints_support_hot_swap_for_unchanged_http_entrypoints() {
    use crate::config::{EntrypointConfig, Protocol};

    let mut old_config = minimal_config();
    old_config.entrypoints.insert(
        "web".to_string(),
        EntrypointConfig {
            address: "127.0.0.1:8080".to_string(),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );
    let new_config = old_config.clone();

    assert!(entrypoints_support_hot_swap(&old_config, &new_config));
}

#[test]
fn test_entrypoints_do_not_hot_swap_udp_entrypoints() {
    use crate::config::{EntrypointConfig, Protocol};

    let mut old_config = minimal_config();
    old_config.entrypoints.insert(
        "dns".to_string(),
        EntrypointConfig {
            address: "127.0.0.1:5353".to_string(),
            protocol: Protocol::Udp,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );
    let new_config = old_config.clone();

    assert!(!entrypoints_support_hot_swap(&old_config, &new_config));
}

#[test]
fn test_gateway_metrics() {
    let gw = Gateway::new(minimal_config()).unwrap();
    let metrics = gw.metrics();
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.total_requests, 0);
}

#[test]
fn test_state_transitions() {
    let gw = Gateway::new(minimal_config()).unwrap();
    assert_eq!(gw.state(), GatewayState::Created);

    gw.set_state(GatewayState::Starting);
    assert_eq!(gw.state(), GatewayState::Starting);

    gw.set_state(GatewayState::Running);
    assert!(gw.is_running());

    gw.set_state(GatewayState::Stopping);
    assert!(!gw.is_running());

    gw.set_state(GatewayState::Stopped);
    assert_eq!(gw.state(), GatewayState::Stopped);
}

#[tokio::test]
async fn test_gateway_shutdown() {
    let gw = Gateway::new(minimal_config()).unwrap();
    assert!(!gw.is_shutdown());
    gw.shutdown().await;
    assert!(gw.is_shutdown());
    assert_eq!(gw.state(), GatewayState::Stopped);
}

#[tokio::test]
async fn test_gateway_double_shutdown() {
    let gw = Gateway::new(minimal_config()).unwrap();
    gw.shutdown().await;
    gw.shutdown().await;
    assert_eq!(gw.state(), GatewayState::Stopped);
}

#[test]
fn test_gateway_discovery_handle_initially_none() {
    let gw = Gateway::new(minimal_config()).unwrap();
    let handle = gw.discovery_handle.read().unwrap();
    assert!(handle.is_none());
    assert!(gw.provider_handles.read().unwrap().is_empty());
}

#[tokio::test]
async fn test_gateway_shutdown_with_no_discovery() {
    let gw = Gateway::new(minimal_config()).unwrap();
    gw.shutdown().await;
    assert_eq!(gw.state(), GatewayState::Stopped);
    let handle = gw.discovery_handle.read().unwrap();
    assert!(handle.is_none());
    assert!(gw.provider_handles.read().unwrap().is_empty());
}

#[test]
fn test_gateway_config_with_discovery() {
    use crate::config::{DiscoveryConfig, DiscoverySeedConfig};
    let mut config = minimal_config();
    config.providers.discovery = Some(DiscoveryConfig {
        seeds: vec![DiscoverySeedConfig {
            url: "http://10.0.0.1:8080".to_string(),
        }],
        poll_interval_secs: 30,
        timeout_secs: 5,
    });
    let gw = Gateway::new(config).unwrap();
    let retrieved = gw.config();
    assert!(retrieved.providers.discovery.is_some());
}

#[tokio::test]
async fn test_gateway_start_tracks_docker_provider_handles() {
    use crate::config::DockerProviderConfig;

    let mut config = minimal_config();
    config.entrypoints.clear();
    config.providers.docker = Some(DockerProviderConfig {
        poll_interval_secs: 60,
        ..DockerProviderConfig::default()
    });

    let gw = Gateway::new(config).unwrap();
    gw.start().await.unwrap();
    assert!(gw.provider_handles.read().unwrap().len() >= 2);

    gw.shutdown().await;
    assert!(gw.provider_handles.read().unwrap().is_empty());
}

#[tokio::test]
async fn test_reload_handle_updates_live_components() {
    use crate::config::{LoadBalancerConfig, ServerConfig, ServiceConfig, Strategy};

    let mut initial = minimal_config();
    initial.entrypoints.clear();
    let gw = Gateway::new(initial).unwrap();
    let mut config = minimal_config();
    config.entrypoints.clear();
    config.services.insert(
        "api".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                servers: vec![ServerConfig {
                    url: "http://127.0.0.1:8080".to_string(),
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

    gw.reload_handle().reload(config, "test").await.unwrap();

    assert!(gw.is_running());
    assert!(gw.config().services.contains_key("api"));
}

fn managed_usage_config(gateway_id: uuid::Uuid, directory: std::path::PathBuf) -> GatewayConfig {
    let mut config = minimal_config();
    config.entrypoints.clear();
    config.mode = crate::config::OperatingMode::CloudManaged;
    config.managed.gateway_id = Some(gateway_id);
    config.managed.usage_spool = Some(crate::config::UsageSpoolConfig {
        directory,
        max_bytes: crate::config::MIN_USAGE_SPOOL_MAX_BYTES,
    });
    config
}

#[tokio::test]
async fn gateway_start_opens_and_recovers_the_configured_usage_spool() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let gateway_id = uuid::Uuid::new_v4();
    let event_id = uuid::Uuid::new_v4();
    let first_epoch = {
        let gateway =
            Gateway::new(managed_usage_config(gateway_id, spool_directory.clone())).unwrap();
        assert_eq!(gateway.health().usage_spool, None);
        gateway.start().await.unwrap();
        let status = gateway.health().usage_spool.unwrap();
        assert!(status.writable);
        assert_eq!(status.gateway_id, gateway_id);
        assert_eq!(status.retained_records, 0);
        let spool = gateway
            .usage_spool
            .read()
            .unwrap()
            .as_ref()
            .unwrap()
            .clone();
        spool.append(event_id, b"durable").await.unwrap();
        gateway.shutdown().await;
        status.boot_epoch
    };

    let gateway = Gateway::new(managed_usage_config(gateway_id, spool_directory)).unwrap();
    gateway.start().await.unwrap();
    let status = gateway.health().usage_spool.unwrap();
    assert_ne!(status.boot_epoch, first_epoch);
    assert_eq!(status.retained_records, 1);
    let spool = gateway
        .usage_spool
        .read()
        .unwrap()
        .as_ref()
        .unwrap()
        .clone();
    let records = spool.read_batch(None, 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event_id, event_id);
    assert_eq!(records[0].payload, b"durable");
    gateway.shutdown().await;
}

#[tokio::test]
async fn gateway_start_fails_closed_on_a_usage_spool_identity_mismatch() {
    let directory = tempfile::tempdir().unwrap();
    let spool_directory = directory.path().join("usage");
    let first_gateway_id = uuid::Uuid::new_v4();
    {
        let gateway = Gateway::new(managed_usage_config(
            first_gateway_id,
            spool_directory.clone(),
        ))
        .unwrap();
        gateway.start().await.unwrap();
        gateway.shutdown().await;
    }

    let gateway =
        Gateway::new(managed_usage_config(uuid::Uuid::new_v4(), spool_directory)).unwrap();
    let error = gateway.start().await.unwrap_err();
    assert!(error.to_string().contains("belongs to Gateway"));
    assert_eq!(gateway.state(), GatewayState::Created);
    assert!(gateway.runtime.read().unwrap().is_none());
    assert!(gateway.handles.read().unwrap().is_empty());
}
