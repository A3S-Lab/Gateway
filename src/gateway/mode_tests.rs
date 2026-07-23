use super::*;
use crate::config::OperatingMode;

fn minimal_config(mode: OperatingMode) -> GatewayConfig {
    let mut config = GatewayConfig {
        mode,
        ..GatewayConfig::default()
    };
    config.entrypoints.clear();
    config.routers.clear();
    config.services.clear();
    config.middlewares.clear();
    config
}

#[test]
fn health_exposes_cloud_managed_mode() {
    let gateway = Gateway::new(minimal_config(OperatingMode::CloudManaged)).unwrap();

    assert_eq!(gateway.health().mode, OperatingMode::CloudManaged);
}

async fn assert_mode_reload_is_rejected(
    initial_mode: OperatingMode,
    candidate_mode: OperatingMode,
) {
    let gateway = Gateway::new(minimal_config(initial_mode)).unwrap();
    gateway.set_state(GatewayState::Running);

    let err = gateway
        .reload(minimal_config(candidate_mode))
        .await
        .unwrap_err();

    assert!(err.to_string().contains("cannot be changed by hot reload"));
    assert_eq!(gateway.config().mode, initial_mode);
    assert_eq!(gateway.state(), GatewayState::Running);
}

#[tokio::test]
async fn reload_rejects_standalone_to_cloud_managed_transition() {
    assert_mode_reload_is_rejected(OperatingMode::Standalone, OperatingMode::CloudManaged).await;
}

#[tokio::test]
async fn reload_rejects_cloud_managed_to_standalone_transition() {
    assert_mode_reload_is_rejected(OperatingMode::CloudManaged, OperatingMode::Standalone).await;
}

#[tokio::test]
async fn cloud_managed_reload_accepts_static_traffic_changes() {
    let gateway = Gateway::new(minimal_config(OperatingMode::CloudManaged)).unwrap();
    gateway.set_state(GatewayState::Running);
    let candidate = GatewayConfig::from_acl(
        r#"
        mode { kind = "cloud-managed" }
        services "api" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8080" }]
            }
        }
        "#,
    )
    .unwrap();

    gateway.reload(candidate).await.unwrap();

    assert_eq!(gateway.config().mode, OperatingMode::CloudManaged);
    assert!(gateway.config().services.contains_key("api"));
    assert_eq!(gateway.state(), GatewayState::Running);
}
