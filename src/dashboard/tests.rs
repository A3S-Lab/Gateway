use super::*;
use crate::config::{LoadBalancerConfig, RouterConfig, ServerConfig, ServiceConfig, Strategy};

fn state_fixture() -> DashboardState {
    let mut config = GatewayConfig::default();
    config.routers.insert(
        "api".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/api`)".to_string(),
            service: "backend".to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: vec![],
            priority: 0,
        },
    );
    config.services.insert(
        "backend".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                servers: vec![ServerConfig {
                    url: "http://127.0.0.1:8001".to_string(),
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

    let registry = ServiceRegistry::from_config(&config.services).unwrap();
    DashboardState {
        config: Arc::new(RwLock::new(config)),
        lifecycle_state: Arc::new(RwLock::new(GatewayState::Running)),
        start_time: Instant::now(),
        metrics: Arc::new(GatewayMetrics::new()),
        service_registry: Arc::new(RwLock::new(Some(Arc::new(registry)))),
        audit_log: Arc::new(ManagementAuditLog::default()),
        reload_config: None,
        reload_managed_snapshot: None,
        managed_snapshots: Arc::new(ManagedSnapshotStore::new(None, None)),
        usage_spool: Arc::new(RwLock::new(None)),
    }
}

#[test]
fn test_dashboard_matches_path_boundary() {
    let api = DashboardApi::new("/api/gateway", None);
    assert!(api.matches("/api/gateway"));
    assert!(api.matches("/api/gateway/health"));
    assert!(!api.matches("/api/gatewayfoo"));
    assert!(api.matches_subpath("/api/gateway/snapshots/apply", "/snapshots/apply"));
    assert!(api.matches_subpath("/api/gateway/snapshots/apply/", "/snapshots/apply"));
    assert!(!api.matches_subpath("/api/gateway/nested/snapshots/apply", "/snapshots/apply"));
}

#[test]
fn test_dashboard_routes_snapshot() {
    let state = state_fixture();
    let routes = routes_snapshot(&state);
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].name, "api");
}

#[test]
fn test_dashboard_services_snapshot() {
    let state = state_fixture();
    let services = services_snapshot(&state);
    assert_eq!(services.len(), 1);
    assert_eq!(services[0].name, "backend");
    assert_eq!(services[0].backends_total, 1);
}

#[test]
fn test_dashboard_handle_version() {
    let api = DashboardApi::new("/api/gateway", None);
    let state = state_fixture();
    let resp = api.handle("/api/gateway/version", None, &state);
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("a3s-gateway"));
}

#[tokio::test]
async fn test_dashboard_health_exposes_the_durable_usage_spool() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = uuid::Uuid::new_v4();
    let spool = crate::usage::UsageSpool::open(crate::usage::UsageSpoolOptions {
        directory: directory.path().join("usage"),
        gateway_id,
        max_bytes: crate::config::MIN_USAGE_SPOOL_MAX_BYTES,
    })
    .await
    .unwrap();
    let mut state = state_fixture();
    state.usage_spool = Arc::new(RwLock::new(Some(Arc::new(spool))));

    let response =
        DashboardApi::new("/api/gateway", None).handle("/api/gateway/health", None, &state);
    let health: HealthStatus = serde_json::from_str(&response.body).unwrap();

    assert_eq!(response.status, 200);
    let status = health.usage_spool.unwrap();
    assert_eq!(status.gateway_id, gateway_id);
    assert!(status.writable);
    assert_eq!(status.next_sequence, 1);
}

#[test]
fn test_dashboard_handle_events() {
    let api = DashboardApi::new("/api/gateway", None);
    let state = state_fixture();
    state.audit_log.record_event(
        ManagementAuditEventKind::AuthRejected,
        None,
        Some("/api/gateway/health".to_string()),
        Some(401),
        "Bearer token is missing or invalid",
    );

    let resp = api.handle("/api/gateway/events", Some("limit=1"), &state);
    assert_eq!(resp.status, 200);
    assert!(resp.body.contains("auth-rejected"));
}

#[test]
fn test_audit_log_keeps_recent_events() {
    let log = ManagementAuditLog::new(2);
    for index in 0..3 {
        log.record_event(
            ManagementAuditEventKind::NotFound,
            None,
            Some(format!("/missing-{index}")),
            Some(404),
            "missing",
        );
    }

    let events = log.snapshot(10);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sequence, 2);
    assert_eq!(events[1].sequence, 3);
}

#[test]
fn test_audit_event_limit_from_query() {
    assert_eq!(audit_event_limit_from_query(Some("limit=2")), 2);
    assert_eq!(
        audit_event_limit_from_query(Some("limit=99999")),
        MAX_AUDIT_EVENT_LIMIT
    );
    assert_eq!(
        audit_event_limit_from_query(Some("limit=0")),
        DEFAULT_AUDIT_EVENT_LIMIT
    );
}

#[test]
fn test_version_info() {
    let version = VersionInfo::current();
    assert_eq!(version.name, "a3s-gateway");
    assert!(!version.version.is_empty());
}

#[test]
fn test_empty_backends_without_registry() {
    let state = DashboardState {
        config: Arc::new(RwLock::new(GatewayConfig::default())),
        lifecycle_state: Arc::new(RwLock::new(GatewayState::Running)),
        start_time: Instant::now(),
        metrics: Arc::new(GatewayMetrics::new()),
        service_registry: Arc::new(RwLock::new(None)),
        audit_log: Arc::new(ManagementAuditLog::default()),
        reload_config: None,
        reload_managed_snapshot: None,
        managed_snapshots: Arc::new(ManagedSnapshotStore::new(None, None)),
        usage_spool: Arc::new(RwLock::new(None)),
    };
    assert!(backends_snapshot(&state).is_empty());
}
