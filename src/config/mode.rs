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
    pub(crate) fn validate_reload_from(&self, current: &Self) -> Result<()> {
        self.validate()?;
        if self.mode != current.mode {
            return Err(GatewayError::Config(format!(
                "Gateway operating mode cannot be changed by hot reload ({} -> {}); restart the process",
                current.mode, self.mode
            )));
        }
        Ok(())
    }

    pub(super) fn validate_mode_constraints(&self) -> Result<()> {
        if self.mode != OperatingMode::CloudManaged {
            return Ok(());
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
