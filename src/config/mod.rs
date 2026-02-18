//! Configuration types for A3S Gateway
//!
//! Defines the configuration model following Traefik's
//! entrypoint → router → middleware → service architecture.
//! Supports TOML and HCL configuration file formats.

mod entrypoint;
mod middleware;
mod router;
pub mod scaling;
mod service;

pub use entrypoint::{EntrypointConfig, Protocol, TlsConfig};
pub use middleware::MiddlewareConfig;
pub use router::RouterConfig;
pub use scaling::{RevisionConfig, RolloutConfig, ScalingConfig};
pub use service::{FailoverConfig, HealthCheckConfig, LoadBalancerConfig, MirrorConfig, ServerConfig, ServiceConfig, Strategy};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::{GatewayError, Result};

/// Top-level gateway configuration
///
/// Supports both TOML and HCL file formats. The format is auto-detected
/// by file extension when using `from_file()`.
///
/// # TOML Example
///
/// ```toml
/// [entrypoints.web]
/// address = "0.0.0.0:80"
///
/// [routers.api]
/// rule = "PathPrefix(`/api`)"
/// service = "backend"
///
/// [services.backend.load_balancer]
/// strategy = "round-robin"
/// ```
///
/// # HCL Example
///
/// ```hcl
/// entrypoints "web" {
///   address = "0.0.0.0:80"
/// }
///
/// routers "api" {
///   rule    = "PathPrefix(`/api`)"
///   service = "backend"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Entrypoints: named listeners (e.g., "web" → 0.0.0.0:80)
    #[serde(default)]
    pub entrypoints: HashMap<String, EntrypointConfig>,

    /// Routers: named routing rules
    #[serde(default)]
    pub routers: HashMap<String, RouterConfig>,

    /// Services: named upstream backends
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,

    /// Middlewares: named middleware configurations
    #[serde(default)]
    pub middlewares: HashMap<String, MiddlewareConfig>,

    /// Provider configuration
    #[serde(default)]
    pub providers: ProviderConfig,
}

impl GatewayConfig {
    /// Load configuration from a file, auto-detecting format by extension.
    ///
    /// Supported formats:
    /// - `.toml` — TOML format (default)
    /// - `.hcl` — HCL (HashiCorp Configuration Language) format
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = tokio::fs::read_to_string(path).await.map_err(|e| {
            GatewayError::Config(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("hcl") => Self::from_hcl(&content),
            _ => Self::from_toml(&content),
        }
    }

    /// Parse configuration from a TOML string
    pub fn from_toml(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| GatewayError::Config(format!("Failed to parse TOML config: {}", e)))
    }

    /// Parse configuration from an HCL string
    pub fn from_hcl(content: &str) -> Result<Self> {
        hcl::from_str(content)
            .map_err(|e| GatewayError::Config(format!("Failed to parse HCL config: {}", e)))
    }

    /// Validate the configuration for consistency
    pub fn validate(&self) -> Result<()> {
        // Every router must reference an existing service
        for (name, router) in &self.routers {
            if !self.services.contains_key(&router.service) {
                return Err(GatewayError::Config(format!(
                    "Router '{}' references unknown service '{}'",
                    name, router.service
                )));
            }
            // Every middleware reference must exist
            for mw in &router.middlewares {
                if !self.middlewares.contains_key(mw) {
                    return Err(GatewayError::Config(format!(
                        "Router '{}' references unknown middleware '{}'",
                        name, mw
                    )));
                }
            }
            // Every entrypoint reference must exist
            for ep in &router.entrypoints {
                if !self.entrypoints.contains_key(ep) {
                    return Err(GatewayError::Config(format!(
                        "Router '{}' references unknown entrypoint '{}'",
                        name, ep
                    )));
                }
            }
        }

        // Every service must have at least one server (unless revisions provide them)
        for (name, svc) in &self.services {
            if svc.load_balancer.servers.is_empty() && svc.revisions.is_empty() {
                return Err(GatewayError::Config(format!(
                    "Service '{}' has no servers configured",
                    name
                )));
            }

            // Validate scaling configuration
            scaling::validate_scaling(
                name,
                svc.scaling.as_ref(),
                &svc.revisions,
                svc.rollout.as_ref(),
            )?;
        }

        Ok(())
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        let mut entrypoints = HashMap::new();
        entrypoints.insert(
            "web".to_string(),
            EntrypointConfig {
                address: "0.0.0.0:80".to_string(),
                protocol: Protocol::Http,
                tls: None,
                max_connections: None,
                tcp_allowed_ips: vec![],
                udp_session_timeout_secs: None,
                udp_max_sessions: None,
            },
        );

        Self {
            entrypoints,
            routers: HashMap::new(),
            services: HashMap::new(),
            middlewares: HashMap::new(),
            providers: ProviderConfig::default(),
        }
    }
}

/// Configuration provider settings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    /// File provider configuration
    #[serde(default)]
    pub file: Option<FileProviderConfig>,

    /// Discovery provider configuration
    #[serde(default)]
    pub discovery: Option<DiscoveryConfig>,

    /// Kubernetes provider configuration (requires `kube` feature)
    #[serde(default)]
    pub kubernetes: Option<KubernetesProviderConfig>,
}

/// Kubernetes provider configuration
///
/// Watches K8s Ingress and IngressRoute CRD resources to auto-generate
/// gateway routing configuration.
///
/// # Example
///
/// ```toml
/// [providers.kubernetes]
/// namespace = "default"
/// label_selector = "app=my-service"
/// watch_interval_secs = 30
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesProviderConfig {
    /// Namespace to watch (empty = all namespaces)
    #[serde(default)]
    pub namespace: String,

    /// Label selector to filter resources (e.g., "app=my-service")
    #[serde(default)]
    pub label_selector: String,

    /// Watch/poll interval in seconds (default: 30)
    #[serde(default = "default_k8s_watch_interval")]
    pub watch_interval_secs: u64,

    /// Whether to watch IngressRoute CRDs in addition to standard Ingress
    #[serde(default)]
    pub ingress_route_crd: bool,
}

fn default_k8s_watch_interval() -> u64 {
    30
}

impl Default for KubernetesProviderConfig {
    fn default() -> Self {
        Self {
            namespace: String::new(),
            label_selector: String::new(),
            watch_interval_secs: default_k8s_watch_interval(),
            ingress_route_crd: false,
        }
    }
}

/// Health-based service discovery configuration
///
/// Polls backend seed URLs for `/.well-known/a3s-service.json` metadata
/// and health endpoints to auto-register services.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Seed URLs to probe for service metadata
    pub seeds: Vec<DiscoverySeedConfig>,

    /// Polling interval in seconds (default: 30)
    #[serde(default = "default_poll_interval")]
    pub poll_interval_secs: u64,

    /// HTTP timeout per probe in seconds (default: 5)
    #[serde(default = "default_discovery_timeout")]
    pub timeout_secs: u64,
}

/// A single discovery seed — a backend URL to probe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoverySeedConfig {
    /// Base URL of the backend (e.g., "http://10.0.0.5:8080")
    pub url: String,
}

fn default_poll_interval() -> u64 {
    30
}

fn default_discovery_timeout() -> u64 {
    5
}

/// File-based configuration provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProviderConfig {
    /// Watch for file changes and hot-reload
    #[serde(default = "default_true")]
    pub watch: bool,

    /// Directory to watch for additional config files
    pub directory: Option<String>,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GatewayConfig::default();
        assert_eq!(config.entrypoints.len(), 1);
        assert!(config.entrypoints.contains_key("web"));
        assert_eq!(config.entrypoints["web"].address, "0.0.0.0:80");
        assert!(config.routers.is_empty());
        assert!(config.services.is_empty());
        assert!(config.middlewares.is_empty());
    }

    #[test]
    fn test_parse_minimal_config() {
        let toml = r#"
            [entrypoints.web]
            address = "0.0.0.0:8080"
        "#;
        let config = GatewayConfig::from_toml(toml).unwrap();
        assert_eq!(config.entrypoints["web"].address, "0.0.0.0:8080");
    }

    #[test]
    fn test_parse_full_config() {
        let toml = r#"
            [entrypoints.web]
            address = "0.0.0.0:80"

            [entrypoints.websecure]
            address = "0.0.0.0:443"
            [entrypoints.websecure.tls]
            cert_file = "/etc/certs/cert.pem"
            key_file = "/etc/certs/key.pem"

            [routers.api]
            rule = "PathPrefix(`/api`)"
            service = "backend"
            entrypoints = ["web"]
            middlewares = ["rate-limit"]

            [services.backend.load_balancer]
            strategy = "round-robin"
            [[services.backend.load_balancer.servers]]
            url = "http://127.0.0.1:8001"

            [middlewares.rate-limit]
            type = "rate-limit"
            rate = 100
            burst = 50
        "#;
        let config = GatewayConfig::from_toml(toml).unwrap();
        assert_eq!(config.entrypoints.len(), 2);
        assert_eq!(config.routers.len(), 1);
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.middlewares.len(), 1);
    }

    #[test]
    fn test_validate_valid_config() {
        let toml = r#"
            [entrypoints.web]
            address = "0.0.0.0:80"

            [routers.api]
            rule = "PathPrefix(`/api`)"
            service = "backend"
            entrypoints = ["web"]

            [services.backend.load_balancer]
            strategy = "round-robin"
            [[services.backend.load_balancer.servers]]
            url = "http://127.0.0.1:8001"
        "#;
        let config = GatewayConfig::from_toml(toml).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_unknown_service() {
        let toml = r#"
            [entrypoints.web]
            address = "0.0.0.0:80"

            [routers.api]
            rule = "PathPrefix(`/api`)"
            service = "nonexistent"
            entrypoints = ["web"]

            [services.backend.load_balancer]
            strategy = "round-robin"
            [[services.backend.load_balancer.servers]]
            url = "http://127.0.0.1:8001"
        "#;
        let config = GatewayConfig::from_toml(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unknown service"));
    }

    #[test]
    fn test_validate_unknown_middleware() {
        let toml = r#"
            [entrypoints.web]
            address = "0.0.0.0:80"

            [routers.api]
            rule = "PathPrefix(`/api`)"
            service = "backend"
            entrypoints = ["web"]
            middlewares = ["nonexistent"]

            [services.backend.load_balancer]
            strategy = "round-robin"
            [[services.backend.load_balancer.servers]]
            url = "http://127.0.0.1:8001"
        "#;
        let config = GatewayConfig::from_toml(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unknown middleware"));
    }

    #[test]
    fn test_validate_unknown_entrypoint() {
        let toml = r#"
            [entrypoints.web]
            address = "0.0.0.0:80"

            [routers.api]
            rule = "PathPrefix(`/api`)"
            service = "backend"
            entrypoints = ["nonexistent"]

            [services.backend.load_balancer]
            strategy = "round-robin"
            [[services.backend.load_balancer.servers]]
            url = "http://127.0.0.1:8001"
        "#;
        let config = GatewayConfig::from_toml(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unknown entrypoint"));
    }

    #[test]
    fn test_validate_empty_servers() {
        let toml = r#"
            [entrypoints.web]
            address = "0.0.0.0:80"

            [routers.api]
            rule = "PathPrefix(`/api`)"
            service = "backend"
            entrypoints = ["web"]

            [services.backend.load_balancer]
            strategy = "round-robin"
        "#;
        let config = GatewayConfig::from_toml(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("no servers"));
    }

    #[test]
    fn test_parse_invalid_toml() {
        let result = GatewayConfig::from_toml("= invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hcl_minimal() {
        let hcl = r#"
            entrypoints "web" {
                address = "0.0.0.0:8080"
            }
        "#;
        let config = GatewayConfig::from_hcl(hcl).unwrap();
        assert_eq!(config.entrypoints["web"].address, "0.0.0.0:8080");
    }

    #[test]
    fn test_parse_hcl_full() {
        let hcl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }

            routers "api" {
                rule        = "PathPrefix(`/api`)"
                service     = "backend"
                entrypoints = ["web"]
                middlewares  = ["rate-limit"]
            }

            services "backend" {
                load_balancer {
                    strategy = "round-robin"
                    servers = [{url = "http://127.0.0.1:8001"}]
                }
            }

            middlewares "rate-limit" {
                type  = "rate-limit"
                rate  = 100
                burst = 50
            }
        "#;
        let config = GatewayConfig::from_hcl(hcl).unwrap();
        assert_eq!(config.entrypoints.len(), 1);
        assert_eq!(config.routers.len(), 1);
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.middlewares.len(), 1);
    }

    #[test]
    fn test_parse_invalid_hcl() {
        let result = GatewayConfig::from_hcl("{{{{ invalid");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_from_file_detects_hcl() {
        let dir = tempfile::tempdir().unwrap();
        let hcl_path = dir.path().join("gateway.hcl");
        std::fs::write(
            &hcl_path,
            r#"
            entrypoints "web" {
                address = "0.0.0.0:9090"
            }
            "#,
        )
        .unwrap();
        let config = GatewayConfig::from_file(&hcl_path).await.unwrap();
        assert_eq!(config.entrypoints["web"].address, "0.0.0.0:9090");
    }

    #[tokio::test]
    async fn test_from_file_detects_toml() {
        let dir = tempfile::tempdir().unwrap();
        let toml_path = dir.path().join("gateway.toml");
        std::fs::write(
            &toml_path,
            r#"
            [entrypoints.web]
            address = "0.0.0.0:9090"
            "#,
        )
        .unwrap();
        let config = GatewayConfig::from_file(&toml_path).await.unwrap();
        assert_eq!(config.entrypoints["web"].address, "0.0.0.0:9090");
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = GatewayConfig::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed = GatewayConfig::from_toml(&toml_str).unwrap();
        assert_eq!(parsed.entrypoints.len(), config.entrypoints.len());
    }

    #[test]
    fn test_provider_config_default() {
        let provider = ProviderConfig::default();
        assert!(provider.file.is_none());
    }

    #[test]
    fn test_file_provider_config() {
        let toml = r#"
            [providers.file]
            watch = true
            directory = "/etc/gateway/conf.d"
        "#;
        let config: GatewayConfig = toml::from_str(toml).unwrap();
        let file = config.providers.file.unwrap();
        assert!(file.watch);
        assert_eq!(file.directory.unwrap(), "/etc/gateway/conf.d");
    }

    #[test]
    fn test_discovery_config_toml_parsing() {
        let toml = r#"
            [providers.discovery]
            poll_interval_secs = 15
            timeout_secs = 3

            [[providers.discovery.seeds]]
            url = "http://10.0.0.5:8080"

            [[providers.discovery.seeds]]
            url = "http://10.0.0.6:8080"
        "#;
        let config: GatewayConfig = toml::from_str(toml).unwrap();
        let disc = config.providers.discovery.unwrap();
        assert_eq!(disc.seeds.len(), 2);
        assert_eq!(disc.seeds[0].url, "http://10.0.0.5:8080");
        assert_eq!(disc.seeds[1].url, "http://10.0.0.6:8080");
        assert_eq!(disc.poll_interval_secs, 15);
        assert_eq!(disc.timeout_secs, 3);
    }

    #[test]
    fn test_discovery_config_hcl_parsing() {
        let hcl = r#"
            providers {
                discovery {
                    poll_interval_secs = 10
                    timeout_secs = 2
                    seeds = [
                        { url = "http://backend-1:3000" }
                    ]
                }
            }
        "#;
        let config = GatewayConfig::from_hcl(hcl).unwrap();
        let disc = config.providers.discovery.unwrap();
        assert_eq!(disc.seeds.len(), 1);
        assert_eq!(disc.seeds[0].url, "http://backend-1:3000");
        assert_eq!(disc.poll_interval_secs, 10);
    }

    #[test]
    fn test_discovery_config_defaults() {
        let toml = r#"
            [providers.discovery]
            [[providers.discovery.seeds]]
            url = "http://localhost:9000"
        "#;
        let config: GatewayConfig = toml::from_str(toml).unwrap();
        let disc = config.providers.discovery.unwrap();
        assert_eq!(disc.poll_interval_secs, 30);
        assert_eq!(disc.timeout_secs, 5);
    }

    #[test]
    fn test_discovery_config_serialization_roundtrip() {
        let config = DiscoveryConfig {
            seeds: vec![
                DiscoverySeedConfig {
                    url: "http://10.0.0.1:8080".to_string(),
                },
            ],
            poll_interval_secs: 20,
            timeout_secs: 3,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DiscoveryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.seeds.len(), 1);
        assert_eq!(parsed.seeds[0].url, "http://10.0.0.1:8080");
        assert_eq!(parsed.poll_interval_secs, 20);
        assert_eq!(parsed.timeout_secs, 3);
    }

    // --- KubernetesProviderConfig ---

    #[test]
    fn test_kubernetes_config_default() {
        let config = KubernetesProviderConfig::default();
        assert!(config.namespace.is_empty());
        assert!(config.label_selector.is_empty());
        assert_eq!(config.watch_interval_secs, 30);
        assert!(!config.ingress_route_crd);
    }

    #[test]
    fn test_kubernetes_config_toml_parsing() {
        let toml = r#"
            [providers.kubernetes]
            namespace = "production"
            label_selector = "app=web"
            watch_interval_secs = 15
            ingress_route_crd = true
        "#;
        let config: GatewayConfig = toml::from_str(toml).unwrap();
        let k8s = config.providers.kubernetes.unwrap();
        assert_eq!(k8s.namespace, "production");
        assert_eq!(k8s.label_selector, "app=web");
        assert_eq!(k8s.watch_interval_secs, 15);
        assert!(k8s.ingress_route_crd);
    }

    #[test]
    fn test_kubernetes_config_defaults_in_toml() {
        let toml = r#"
            [providers.kubernetes]
        "#;
        let config: GatewayConfig = toml::from_str(toml).unwrap();
        let k8s = config.providers.kubernetes.unwrap();
        assert!(k8s.namespace.is_empty());
        assert_eq!(k8s.watch_interval_secs, 30);
    }

    #[test]
    fn test_kubernetes_config_serialization_roundtrip() {
        let config = KubernetesProviderConfig {
            namespace: "staging".to_string(),
            label_selector: "tier=frontend".to_string(),
            watch_interval_secs: 60,
            ingress_route_crd: true,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: KubernetesProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.namespace, "staging");
        assert_eq!(parsed.label_selector, "tier=frontend");
        assert_eq!(parsed.watch_interval_secs, 60);
        assert!(parsed.ingress_route_crd);
    }

    #[test]
    fn test_provider_config_with_kubernetes() {
        let provider = ProviderConfig {
            file: None,
            discovery: None,
            kubernetes: Some(KubernetesProviderConfig::default()),
        };
        assert!(provider.kubernetes.is_some());
    }
}
