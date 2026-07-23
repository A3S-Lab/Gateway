//! Gateway operating-mode contract.

use serde::{Deserialize, Serialize};

use super::GatewayConfig;
use crate::error::{GatewayError, Result};

/// Process-level operating mode for A3S Gateway.
///
/// The mode selects the desired-state authority and cannot be changed by hot
/// reload. Restart the process to cross this boundary.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum OperatingMode {
    /// Operator-owned ACL configuration and optional local providers.
    #[default]
    Standalone,
    /// A3S Cloud owns desired state; Gateway applies static traffic snapshots.
    CloudManaged,
}

impl OperatingMode {
    /// Stable ACL and API representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::CloudManaged => "cloud-managed",
        }
    }
}

impl std::fmt::Display for OperatingMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for OperatingMode {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim() {
            "standalone" => Ok(Self::Standalone),
            "cloud-managed" => Ok(Self::CloudManaged),
            other => Err(format!(
                "unknown gateway operating mode '{}'; expected 'standalone' or 'cloud-managed'",
                other
            )),
        }
    }
}

impl GatewayConfig {
    pub(crate) fn validate_managed_bootstrap(&self) -> Result<()> {
        if self.mode != OperatingMode::CloudManaged || self.managed.gateway_id.is_none() {
            return Ok(());
        }
        if !self.routers.is_empty() || !self.services.is_empty() || !self.middlewares.is_empty() {
            return Err(GatewayError::Config(
                "A cloud-managed bootstrap ACL with managed.gateway_id cannot define traffic routers, services, or middlewares; deliver them as a managed snapshot"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_reload_from(&self, current: &Self) -> Result<()> {
        self.validate()?;
        if self.mode != current.mode {
            return Err(GatewayError::Config(format!(
                "Gateway operating mode cannot be changed by hot reload ({} -> {}); restart the process",
                current.mode, self.mode
            )));
        }
        if self.managed != current.managed {
            return Err(GatewayError::Config(
                "Managed Gateway identity cannot be changed by hot reload; restart the process"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_managed_snapshot_reload_from(&self, current: &Self) -> Result<()> {
        if current.mode != OperatingMode::CloudManaged || current.managed.gateway_id.is_none() {
            return Err(GatewayError::Config(
                "Managed snapshot apply requires a cloud-managed bootstrap ACL with managed.gateway_id"
                    .to_string(),
            ));
        }
        if self.management != current.management {
            return Err(GatewayError::Config(
                "Managed snapshots cannot change the bootstrap management listener".to_string(),
            ));
        }
        for (name, entrypoint) in &self.entrypoints {
            if current.entrypoints.get(name) == Some(entrypoint) {
                continue;
            }
            if current
                .entrypoints
                .get(name)
                .is_some_and(|active| entrypoint.can_reconfigure_in_place_from(active))
            {
                continue;
            }
            if current
                .entrypoints
                .values()
                .any(|current| current.address == entrypoint.address)
            {
                return Err(GatewayError::Config(format!(
                    "Managed snapshot cannot reconfigure entrypoint '{}' on an address already bound by the current snapshot",
                    name
                )));
            }
        }

        Ok(())
    }

    pub(super) fn validate_mode_constraints(&self) -> Result<()> {
        if self.mode != OperatingMode::CloudManaged {
            if self.managed.gateway_id.is_some() {
                return Err(GatewayError::Config(
                    "managed.gateway_id requires operating mode 'cloud-managed'".to_string(),
                ));
            }
            if self.managed.state_file.is_some() {
                return Err(GatewayError::Config(
                    "managed.state_file requires operating mode 'cloud-managed'".to_string(),
                ));
            }
            return Ok(());
        }

        if self
            .managed
            .gateway_id
            .is_some_and(|gateway_id| gateway_id.is_nil())
        {
            return Err(GatewayError::Config(
                "managed.gateway_id must not be the nil UUID".to_string(),
            ));
        }
        if self.managed.state_file.is_some() && self.managed.gateway_id.is_none() {
            return Err(GatewayError::Config(
                "managed.state_file requires managed.gateway_id".to_string(),
            ));
        }
        if let Some(path) = &self.managed.state_file {
            if !path.is_absolute() {
                return Err(GatewayError::Config(
                    "managed.state_file must be an absolute path".to_string(),
                ));
            }
            if path.file_name().is_none() {
                return Err(GatewayError::Config(
                    "managed.state_file must identify a file".to_string(),
                ));
            }
        }

        for (configured, path) in [
            (self.providers.file.is_some(), "providers.file"),
            (self.providers.discovery.is_some(), "providers.discovery"),
            (self.providers.kubernetes.is_some(), "providers.kubernetes"),
            (self.providers.docker.is_some(), "providers.docker"),
        ] {
            if configured {
                return Err(GatewayError::Config(format!(
                    "Operating mode 'cloud-managed' does not allow '{}'; A3S Cloud is the desired-state authority",
                    path
                )));
            }
        }

        for (name, service) in &self.services {
            if service.scaling.is_some() {
                return Err(GatewayError::Config(format!(
                    "Operating mode 'cloud-managed' does not allow 'services.{}.scaling'; A3S Cloud owns production autoscaling",
                    name
                )));
            }
            if service.rollout.is_some() {
                return Err(GatewayError::Config(format!(
                    "Operating mode 'cloud-managed' does not allow 'services.{}.rollout'; A3S Cloud owns production rollout",
                    name
                )));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_acl_defaults_to_standalone_mode() {
        let config = GatewayConfig::from_acl("").unwrap();
        assert_eq!(config.mode, OperatingMode::Standalone);
    }

    #[test]
    fn parses_both_operating_modes() {
        for (kind, expected) in [
            ("standalone", OperatingMode::Standalone),
            ("cloud-managed", OperatingMode::CloudManaged),
        ] {
            let config =
                GatewayConfig::from_acl(&format!(r#"mode {{ kind = "{kind}" }}"#)).unwrap();
            assert_eq!(config.mode, expected);
        }
    }

    #[test]
    fn parses_stable_managed_gateway_identity() {
        let gateway_id = uuid::Uuid::new_v4();
        let config = GatewayConfig::from_acl(&format!(
            r#"
            mode {{ kind = "cloud-managed" }}
            managed {{
              gateway_id = "{gateway_id}"
              state_file = "/var/lib/a3s-gateway/managed-snapshot.json"
            }}
            "#
        ))
        .unwrap();

        assert_eq!(config.managed.gateway_id, Some(gateway_id));
        assert_eq!(
            config.managed.state_file.as_deref(),
            Some(std::path::Path::new(
                "/var/lib/a3s-gateway/managed-snapshot.json"
            ))
        );
        assert!(config.validate().is_ok());

        let json = serde_json::to_string(&config).unwrap();
        let decoded: GatewayConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.managed, config.managed);
    }

    #[test]
    fn managed_gateway_identity_requires_cloud_managed_mode() {
        let gateway_id = uuid::Uuid::new_v4();
        let config =
            GatewayConfig::from_acl(&format!(r#"managed {{ gateway_id = "{gateway_id}" }}"#))
                .unwrap();
        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("cloud-managed"));
    }

    #[test]
    fn rejects_nil_managed_gateway_identity() {
        let config = GatewayConfig::from_acl(
            r#"
            mode { kind = "cloud-managed" }
            managed { gateway_id = "00000000-0000-0000-0000-000000000000" }
            "#,
        )
        .unwrap();
        let error = config.validate().unwrap_err();

        assert!(error.to_string().contains("nil UUID"));
    }

    #[test]
    fn managed_state_file_requires_identity_and_absolute_file_path() {
        let without_identity = GatewayConfig::from_acl(
            r#"
            mode { kind = "cloud-managed" }
            managed { state_file = "/var/lib/a3s-gateway/snapshot.json" }
            "#,
        )
        .unwrap();
        assert!(without_identity
            .validate()
            .unwrap_err()
            .to_string()
            .contains("requires managed.gateway_id"));

        let gateway_id = uuid::Uuid::new_v4();
        let relative = GatewayConfig::from_acl(&format!(
            r#"
            mode {{ kind = "cloud-managed" }}
            managed {{
              gateway_id = "{gateway_id}"
              state_file = "snapshot.json"
            }}
            "#
        ))
        .unwrap();
        assert!(relative
            .validate()
            .unwrap_err()
            .to_string()
            .contains("absolute path"));
    }

    #[test]
    fn managed_snapshot_reload_accepts_safe_in_place_listener_updates() {
        let mut current = GatewayConfig {
            mode: OperatingMode::CloudManaged,
            ..GatewayConfig::default()
        };
        current.managed.gateway_id = Some(uuid::Uuid::new_v4());

        let mut same_address_change = current.clone();
        same_address_change
            .entrypoints
            .get_mut("web")
            .unwrap()
            .max_connections = Some(10);
        assert!(same_address_change
            .validate_managed_snapshot_reload_from(&current)
            .is_ok());

        let mut same_address_protocol_change = current.clone();
        same_address_protocol_change
            .entrypoints
            .get_mut("web")
            .unwrap()
            .protocol = crate::config::Protocol::Tcp;
        assert!(same_address_protocol_change
            .validate_managed_snapshot_reload_from(&current)
            .unwrap_err()
            .to_string()
            .contains("already bound"));

        let mut new_address_change = current.clone();
        new_address_change
            .entrypoints
            .get_mut("web")
            .unwrap()
            .address = "127.0.0.1:8080".to_string();
        assert!(new_address_change
            .validate_managed_snapshot_reload_from(&current)
            .is_ok());

        let mut management_change = current.clone();
        management_change.management.address = "127.0.0.1:9191".to_string();
        assert!(management_change
            .validate_managed_snapshot_reload_from(&current)
            .unwrap_err()
            .to_string()
            .contains("management listener"));

        current.entrypoints.get_mut("web").unwrap().protocol = crate::config::Protocol::Udp;
        let mut udp_policy_change = current.clone();
        udp_policy_change
            .entrypoints
            .get_mut("web")
            .unwrap()
            .udp_max_sessions = Some(2_000);
        assert!(udp_policy_change
            .validate_managed_snapshot_reload_from(&current)
            .is_ok());
    }

    #[test]
    fn rejects_invalid_operating_mode() {
        let err = GatewayConfig::from_acl(r#"mode { kind = "hybrid" }"#).unwrap_err();
        assert!(err.to_string().contains("hybrid"));
        assert!(err.to_string().contains("operating mode"));
    }

    #[test]
    fn config_serialization_exposes_operating_mode() {
        let config = GatewayConfig {
            mode: OperatingMode::CloudManaged,
            ..GatewayConfig::default()
        };

        let json = serde_json::to_value(config).unwrap();
        assert_eq!(json["mode"], "cloud-managed");
    }

    #[test]
    fn standalone_accepts_local_control_features() {
        let acl = r#"
            mode { kind = "standalone" }

            providers {
                file {}
                discovery { seeds = [] }
                kubernetes {}
                docker {}
            }

            services "backend" {
                scaling {
                    min_replicas = 0
                    max_replicas = 2
                }
                revisions "v1" {
                    traffic_percent = 50
                    servers = [{ url = "http://127.0.0.1:8001" }]
                }
                revisions "v2" {
                    traffic_percent = 50
                    servers = [{ url = "http://127.0.0.1:8002" }]
                }
                rollout {
                    from = "v1"
                    to   = "v2"
                }
            }
        "#;

        let config = GatewayConfig::from_acl(acl).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn cloud_managed_accepts_static_traffic_configuration() {
        let acl = r#"
            mode { kind = "cloud-managed" }

            entrypoints "web" {
                address = "127.0.0.1:8080"
            }
            routers "api" {
                rule        = "PathPrefix(`/api`)"
                service     = "backend"
                entrypoints = ["web"]
            }
            services "backend" {
                load_balancer {
                    health_check { path = "/health" }
                }
                revisions "v1" {
                    traffic_percent = 90
                    servers = [{ url = "http://127.0.0.1:8001" }]
                }
                revisions "v2" {
                    traffic_percent = 10
                    servers = [{ url = "http://127.0.0.1:8002" }]
                }
            }
        "#;

        let config = GatewayConfig::from_acl(acl).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn cloud_managed_rejects_dynamic_providers() {
        for (provider, block) in [
            ("providers.file", "file {}"),
            ("providers.discovery", "discovery { seeds = [] }"),
            ("providers.kubernetes", "kubernetes {}"),
            ("providers.docker", "docker {}"),
        ] {
            let acl = format!(
                r#"
                mode {{ kind = "cloud-managed" }}
                providers {{ {block} }}
                "#
            );
            let config = GatewayConfig::from_acl(&acl).unwrap();
            let err = config.validate().unwrap_err();
            assert!(
                err.to_string().contains(provider),
                "expected error for {provider}, got: {err}"
            );
        }
    }

    #[test]
    fn cloud_managed_rejects_service_scaling() {
        let config = GatewayConfig::from_acl(
            r#"
            mode { kind = "cloud-managed" }
            services "backend" {
                load_balancer {
                    servers = [{ url = "http://127.0.0.1:8001" }]
                }
                scaling {}
            }
            "#,
        )
        .unwrap();

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("services.backend.scaling"));
    }

    #[test]
    fn cloud_managed_rejects_service_rollout() {
        let config = GatewayConfig::from_acl(
            r#"
            mode { kind = "cloud-managed" }
            services "backend" {
                revisions "v1" {
                    traffic_percent = 50
                    servers = [{ url = "http://127.0.0.1:8001" }]
                }
                revisions "v2" {
                    traffic_percent = 50
                    servers = [{ url = "http://127.0.0.1:8002" }]
                }
                rollout {
                    from = "v1"
                    to   = "v2"
                }
            }
            "#,
        )
        .unwrap();

        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("services.backend.rollout"));
    }
}
