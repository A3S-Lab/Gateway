//! Configuration types for A3S Gateway
//!
//! Defines the configuration model following Traefik's
//! entrypoint → router → middleware → service architecture.
//! Uses ACL (Agent Configuration Language) as the configuration format.

pub(crate) mod acl;
mod entrypoint;
mod middleware;
mod mode;
mod router;
pub mod scaling;
mod service;

pub use entrypoint::{EntrypointConfig, Protocol, TlsConfig};
pub use middleware::MiddlewareConfig;
pub use mode::OperatingMode;
pub use router::RouterConfig;
pub use scaling::{RevisionConfig, RolloutConfig, ScalingConfig};
pub(crate) use service::parse_duration as parse_service_duration;
pub use service::{
    FailoverConfig, HealthCheckConfig, LoadBalancerConfig, MirrorConfig, ServerConfig,
    ServiceConfig, StickyConfig, Strategy,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::error::{GatewayError, Result};

/// Top-level gateway configuration
///
/// Uses ACL (Agent Configuration Language) format.
///
/// # ACL Example
///
/// ```acl
/// entrypoints "web" {
///   address = "0.0.0.0:80"
/// }
///
/// routers "api" {
///   rule    = "PathPrefix(`/api`)"
///   service = "backend"
/// }
///
/// services "backend" {
///   load_balancer {
///     strategy = "round-robin"
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Desired-state authority and process-level behavior boundary.
    #[serde(default)]
    pub mode: OperatingMode,

    /// Stable identity and delivery boundary for Cloud-managed snapshots.
    #[serde(default)]
    pub managed: ManagedConfig,

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

    /// Optional dedicated management API listener.
    #[serde(default)]
    pub management: ManagementConfig,

    /// Observability configuration (metrics, access log, tracing)
    #[serde(default)]
    pub observability: ObservabilityConfig,

    /// Graceful shutdown timeout in seconds (default: 30)
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout_secs: u64,
}

fn default_shutdown_timeout() -> u64 {
    30
}

/// Observability configuration — controls metrics, access logging, and tracing overhead.
///
/// All features are enabled by default. Disable individual features to reduce
/// per-request overhead in high-throughput scenarios.
///
/// # Example
///
/// ```acl
/// observability {
///   metrics_enabled     = true
///   access_log_enabled  = false
///   tracing_enabled     = false
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityConfig {
    /// Enable Prometheus metrics collection (per-router, per-service, per-backend counters).
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,

    /// Enable structured access log entries for every request.
    #[serde(default = "default_true")]
    pub access_log_enabled: bool,

    /// Enable W3C Trace Context propagation and span injection.
    #[serde(default = "default_true")]
    pub tracing_enabled: bool,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: true,
            access_log_enabled: true,
            tracing_enabled: true,
        }
    }
}

impl GatewayConfig {
    /// Load configuration from an ACL file.
    ///
    /// The file must use the `.acl` extension.
    pub async fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        acl::ensure_acl_path(path)?;
        let content = tokio::fs::read_to_string(path).await.map_err(|e| {
            GatewayError::Config(format!(
                "Failed to read config file {}: {}",
                path.display(),
                e
            ))
        })?;
        Self::from_acl(&content)
    }

    /// Parse configuration from an ACL string.
    pub fn from_acl(content: &str) -> Result<Self> {
        acl::parse_gateway_config(content)
    }

    /// Validate the configuration for consistency
    pub fn validate(&self) -> Result<()> {
        self.validate_mode_constraints()?;

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
            service::parse_duration(&svc.load_balancer.request_timeout).map_err(|e| {
                GatewayError::Config(format!(
                    "Invalid request_timeout for service '{}': {}",
                    name, e
                ))
            })?;

            // Validate scaling configuration
            scaling::validate_scaling(
                name,
                svc.scaling.as_ref(),
                &svc.revisions,
                svc.rollout.as_ref(),
            )?;
        }

        if self.management.enabled {
            self.management
                .address
                .parse::<std::net::SocketAddr>()
                .map_err(|e| {
                    GatewayError::Config(format!(
                        "Invalid management address '{}': {}",
                        self.management.address, e
                    ))
                })?;
            if !self.management.path_prefix.starts_with('/') {
                return Err(GatewayError::Config(
                    "Management path_prefix must start with '/'".to_string(),
                ));
            }
            crate::middleware::ip_matcher::IpMatcher::new(&self.management.allowed_ips)?;
            if let Some(tls) = &self.management.tls {
                tls.validate()?;
            }
        }

        Ok(())
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        let mut entrypoints = HashMap::new();
        entrypoints.insert("web".to_string(), EntrypointConfig::new("0.0.0.0:80"));

        Self {
            mode: OperatingMode::default(),
            managed: ManagedConfig::default(),
            entrypoints,
            routers: HashMap::new(),
            services: HashMap::new(),
            middlewares: HashMap::new(),
            providers: ProviderConfig::default(),
            management: ManagementConfig::default(),
            observability: ObservabilityConfig::default(),
            shutdown_timeout_secs: default_shutdown_timeout(),
        }
    }
}

/// Process-stable identity used by the managed snapshot protocol.
///
/// The field is optional so existing standalone and pre-H0.2 Cloud
/// configurations remain valid. The managed snapshot endpoint requires it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedConfig {
    /// Logical Gateway identity assigned by A3S Cloud.
    #[serde(default)]
    pub gateway_id: Option<uuid::Uuid>,
}

/// Dedicated management API listener configuration.
///
/// Management is disabled by default. When enabled, it runs on its own
/// listener and never intercepts user traffic entrypoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementConfig {
    /// Enable the management HTTP API.
    #[serde(default)]
    pub enabled: bool,

    /// Management listener address.
    #[serde(default = "default_management_address")]
    pub address: String,

    /// API path prefix.
    #[serde(default = "default_management_path_prefix")]
    pub path_prefix: String,

    /// Optional environment variable containing the bearer token.
    #[serde(default = "default_management_auth_token_env")]
    pub auth_token_env: Option<String>,

    /// Allowed client IPs or CIDR ranges for the management listener.
    #[serde(default = "default_management_allowed_ips")]
    pub allowed_ips: Vec<String>,

    /// Optional TLS/mTLS configuration for the management listener.
    #[serde(default)]
    pub tls: Option<ManagementTlsConfig>,
}

/// TLS and client certificate validation for the management listener.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementTlsConfig {
    /// Path to the server certificate PEM file.
    pub cert_file: String,

    /// Path to the server private key PEM file.
    pub key_file: String,

    /// Optional CA bundle used to validate client certificates.
    #[serde(default)]
    pub client_ca_file: Option<String>,

    /// Require a valid client certificate signed by `client_ca_file`.
    #[serde(default)]
    pub require_client_cert: bool,

    /// Minimum TLS version (default: 1.2).
    #[serde(default = "default_management_tls_min_version")]
    pub min_version: String,
}

impl ManagementTlsConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.cert_file.trim().is_empty() {
            return Err(GatewayError::Config(
                "Management TLS cert_file is required".to_string(),
            ));
        }
        if self.key_file.trim().is_empty() {
            return Err(GatewayError::Config(
                "Management TLS key_file is required".to_string(),
            ));
        }
        if !matches!(self.min_version.as_str(), "1.2" | "1.3") {
            return Err(GatewayError::Config(format!(
                "Management TLS min_version must be '1.2' or '1.3', got '{}'",
                self.min_version
            )));
        }

        match self.client_ca_file.as_deref() {
            Some(path) if path.trim().is_empty() => {
                return Err(GatewayError::Config(
                    "Management TLS client_ca_file must not be empty".to_string(),
                ));
            }
            Some(_) => {}
            None if self.require_client_cert => {
                return Err(GatewayError::Config(
                    "Management TLS require_client_cert requires client_ca_file".to_string(),
                ));
            }
            None => {}
        }

        Ok(())
    }
}

fn default_management_address() -> String {
    "127.0.0.1:9090".to_string()
}

fn default_management_path_prefix() -> String {
    "/api/gateway".to_string()
}

fn default_management_auth_token_env() -> Option<String> {
    Some("A3S_GATEWAY_ADMIN_TOKEN".to_string())
}

fn default_management_allowed_ips() -> Vec<String> {
    vec!["127.0.0.1".to_string(), "::1".to_string()]
}

fn default_management_tls_min_version() -> String {
    "1.2".to_string()
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            address: default_management_address(),
            path_prefix: default_management_path_prefix(),
            auth_token_env: default_management_auth_token_env(),
            allowed_ips: default_management_allowed_ips(),
            tls: None,
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

    /// Docker provider configuration — auto-discover services from container labels
    #[serde(default)]
    pub docker: Option<DockerProviderConfig>,
}

/// Docker provider configuration
///
/// Polls the Docker daemon for running containers and translates their labels
/// into gateway routing configuration. Supports both Unix socket and TCP connections.
///
/// # Label Format
///
/// ```text
/// a3s.enable=true
/// a3s.router.rule=PathPrefix(`/api`)
/// a3s.router.entrypoints=web
/// a3s.router.middlewares=rate-limit
/// a3s.router.priority=10
/// a3s.service.port=8080
/// a3s.service.strategy=round-robin
/// a3s.service.weight=1
/// ```
///
/// # Example
///
/// ```acl
/// providers {
///   docker {
///     host               = "/var/run/docker.sock"
///     poll_interval_secs = 10
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DockerProviderConfig {
    /// Docker daemon host — Unix socket path or TCP URL.
    /// - Unix: `/var/run/docker.sock` (default on Linux/macOS)
    /// - TCP:  `tcp://localhost:2375`
    #[serde(default = "default_docker_host")]
    pub host: String,

    /// Label prefix used to identify A3S routing labels (default: `a3s`)
    #[serde(default = "default_label_prefix")]
    pub label_prefix: String,

    /// Poll interval in seconds (default: 10)
    #[serde(default = "default_docker_poll")]
    pub poll_interval_secs: u64,
}

fn default_docker_host() -> String {
    "/var/run/docker.sock".to_string()
}

fn default_label_prefix() -> String {
    "a3s".to_string()
}

fn default_docker_poll() -> u64 {
    10
}

impl Default for DockerProviderConfig {
    fn default() -> Self {
        Self {
            host: default_docker_host(),
            label_prefix: default_label_prefix(),
            poll_interval_secs: default_docker_poll(),
        }
    }
}

/// Kubernetes provider configuration
///
/// Watches K8s Ingress and IngressRoute CRD resources to auto-generate
/// gateway routing configuration.
///
/// # Example
///
/// ```acl
/// providers {
///   kubernetes {
///     namespace          = "default"
///     label_selector     = "app=my-service"
///     watch_interval_secs = 30
///   }
/// }
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
        assert_eq!(config.mode, OperatingMode::Standalone);
        assert_eq!(config.entrypoints.len(), 1);
        assert!(config.entrypoints.contains_key("web"));
        assert_eq!(config.entrypoints["web"].address, "0.0.0.0:80");
        assert!(config.routers.is_empty());
        assert!(config.services.is_empty());
        assert!(config.middlewares.is_empty());
    }

    #[test]
    fn test_parse_minimal_config() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:8080"
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        assert_eq!(config.entrypoints["web"].address, "0.0.0.0:8080");
    }

    #[test]
    fn test_parse_full_config() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }
            entrypoints "websecure" {
                address = "0.0.0.0:443"
                tls {
                    cert_file = "/etc/certs/cert.pem"
                    key_file  = "/etc/certs/key.pem"
                }
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
                    servers = [
                        { url = "http://127.0.0.1:8001" }
                    ]
                }
            }
            middlewares "rate-limit" {
                type  = "rate-limit"
                rate  = 100
                burst = 50
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        assert_eq!(config.entrypoints.len(), 2);
        assert_eq!(config.routers.len(), 1);
        assert_eq!(config.services.len(), 1);
        assert_eq!(config.middlewares.len(), 1);
    }

    #[test]
    fn test_validate_valid_config() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }
            routers "api" {
                rule        = "PathPrefix(`/api`)"
                service     = "backend"
                entrypoints = ["web"]
            }
            services "backend" {
                load_balancer {
                    strategy = "round-robin"
                    servers = [
                        { url = "http://127.0.0.1:8001" }
                    ]
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_unknown_service() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }
            routers "api" {
                rule        = "PathPrefix(`/api`)"
                service     = "nonexistent"
                entrypoints = ["web"]
            }
            services "backend" {
                load_balancer {
                    strategy = "round-robin"
                    servers = [
                        { url = "http://127.0.0.1:8001" }
                    ]
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unknown service"));
    }

    #[test]
    fn test_validate_unknown_middleware() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }
            routers "api" {
                rule        = "PathPrefix(`/api`)"
                service     = "backend"
                entrypoints = ["web"]
                middlewares  = ["nonexistent"]
            }
            services "backend" {
                load_balancer {
                    strategy = "round-robin"
                    servers = [
                        { url = "http://127.0.0.1:8001" }
                    ]
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unknown middleware"));
    }

    #[test]
    fn test_validate_unknown_entrypoint() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }
            routers "api" {
                rule        = "PathPrefix(`/api`)"
                service     = "backend"
                entrypoints = ["nonexistent"]
            }
            services "backend" {
                load_balancer {
                    strategy = "round-robin"
                    servers = [
                        { url = "http://127.0.0.1:8001" }
                    ]
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("unknown entrypoint"));
    }

    #[test]
    fn test_validate_empty_servers() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }
            routers "api" {
                rule        = "PathPrefix(`/api`)"
                service     = "backend"
                entrypoints = ["web"]
            }
            services "backend" {
                load_balancer {
                    strategy = "round-robin"
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("no servers"));
    }

    #[test]
    fn test_validate_invalid_request_timeout() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }
            routers "api" {
                rule        = "PathPrefix(`/api`)"
                service     = "backend"
                entrypoints = ["web"]
            }
            services "backend" {
                load_balancer {
                    request_timeout = "never"
                    servers = [
                        { url = "http://127.0.0.1:8001" }
                    ]
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid request_timeout"));
    }

    #[test]
    fn test_parse_invalid_acl() {
        let result = GatewayConfig::from_acl("{{{{ invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_file_rejects_non_acl_extension() {
        let err = tokio_test::block_on(GatewayConfig::from_file("gateway.txt")).unwrap_err();
        assert!(err.to_string().contains(".acl extension"));
    }

    #[test]
    fn test_management_config_acl_parsing() {
        let acl = r#"
            management {
                enabled        = true
                address        = "127.0.0.1:19090"
                path_prefix    = "/admin"
                auth_token_env = "ADMIN_TOKEN"
                allowed_ips    = ["127.0.0.1", "10.0.0.0/8"]
                tls {
                    cert_file           = "/etc/a3s/admin.crt"
                    key_file            = "/etc/a3s/admin.key"
                    client_ca_file      = "/etc/a3s/admin-client-ca.crt"
                    require_client_cert = true
                    min_version         = "1.3"
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        assert!(config.management.enabled);
        assert_eq!(config.management.address, "127.0.0.1:19090");
        assert_eq!(config.management.path_prefix, "/admin");
        assert_eq!(
            config.management.auth_token_env.as_deref(),
            Some("ADMIN_TOKEN")
        );
        assert_eq!(config.management.allowed_ips.len(), 2);
        assert_eq!(config.management.allowed_ips[1], "10.0.0.0/8");
        let tls = config.management.tls.unwrap();
        assert_eq!(tls.cert_file, "/etc/a3s/admin.crt");
        assert_eq!(tls.key_file, "/etc/a3s/admin.key");
        assert_eq!(
            tls.client_ca_file.as_deref(),
            Some("/etc/a3s/admin-client-ca.crt")
        );
        assert!(tls.require_client_cert);
        assert_eq!(tls.min_version, "1.3");
    }

    #[test]
    fn test_management_config_defaults_to_local_allowlist() {
        let config = GatewayConfig::from_acl(
            r#"
            management {
                enabled = true
            }
        "#,
        )
        .unwrap();
        assert_eq!(config.management.allowed_ips, vec!["127.0.0.1", "::1"]);
    }

    #[test]
    fn test_management_config_validate_path_prefix() {
        let acl = r#"
            management {
                enabled     = true
                path_prefix = "admin"
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("path_prefix"));
    }

    #[test]
    fn test_management_config_validate_allowed_ips() {
        let acl = r#"
            management {
                enabled     = true
                allowed_ips = ["not-an-ip"]
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid IP address"));
    }

    #[test]
    fn test_management_config_validate_mtls_requires_client_ca() {
        let acl = r#"
            management {
                enabled = true
                tls {
                    cert_file           = "/etc/a3s/admin.crt"
                    key_file            = "/etc/a3s/admin.key"
                    require_client_cert = true
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("client_ca_file"));
    }

    #[test]
    fn test_management_config_validate_tls_min_version() {
        let acl = r#"
            management {
                enabled = true
                tls {
                    cert_file   = "/etc/a3s/admin.crt"
                    key_file    = "/etc/a3s/admin.key"
                    min_version = "1.1"
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("min_version"));
    }

    #[test]
    fn test_provider_config_default() {
        let provider = ProviderConfig::default();
        assert!(provider.file.is_none());
    }

    #[test]
    fn test_file_provider_config() {
        let acl = r#"
            providers {
                file {
                    watch     = true
                    directory = "/etc/gateway/conf.d"
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let file = config.providers.file.unwrap();
        assert!(file.watch);
        assert_eq!(file.directory.unwrap(), "/etc/gateway/conf.d");
    }

    #[test]
    fn test_discovery_config_acl_parsing() {
        let acl = r#"
            providers {
                discovery {
                    poll_interval_secs = 15
                    timeout_secs       = 3
                    seeds = [
                        { url = "http://10.0.0.5:8080" },
                        { url = "http://10.0.0.6:8080" }
                    ]
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let disc = config.providers.discovery.unwrap();
        assert_eq!(disc.seeds.len(), 2);
        assert_eq!(disc.seeds[0].url, "http://10.0.0.5:8080");
        assert_eq!(disc.seeds[1].url, "http://10.0.0.6:8080");
        assert_eq!(disc.poll_interval_secs, 15);
        assert_eq!(disc.timeout_secs, 3);
    }

    #[test]
    fn test_discovery_config_defaults() {
        let acl = r#"
            providers {
                discovery {
                    seeds = [
                        { url = "http://localhost:9000" }
                    ]
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let disc = config.providers.discovery.unwrap();
        assert_eq!(disc.poll_interval_secs, 30);
        assert_eq!(disc.timeout_secs, 5);
    }

    #[test]
    fn test_discovery_config_serialization_roundtrip() {
        let config = DiscoveryConfig {
            seeds: vec![DiscoverySeedConfig {
                url: "http://10.0.0.1:8080".to_string(),
            }],
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
    fn test_kubernetes_config_acl_parsing() {
        let acl = r#"
            providers {
                kubernetes {
                    namespace           = "production"
                    label_selector      = "app=web"
                    watch_interval_secs = 15
                    ingress_route_crd   = true
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let k8s = config.providers.kubernetes.unwrap();
        assert_eq!(k8s.namespace, "production");
        assert_eq!(k8s.label_selector, "app=web");
        assert_eq!(k8s.watch_interval_secs, 15);
        assert!(k8s.ingress_route_crd);
    }

    #[test]
    fn test_kubernetes_config_defaults_in_acl() {
        let acl = r#"
            providers {
                kubernetes {}
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
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
            docker: None,
        };
        assert!(provider.kubernetes.is_some());
    }

    // --- DockerProviderConfig ---

    #[test]
    fn test_docker_config_default() {
        let config = DockerProviderConfig::default();
        assert_eq!(config.host, "/var/run/docker.sock");
        assert_eq!(config.label_prefix, "a3s");
        assert_eq!(config.poll_interval_secs, 10);
    }

    #[test]
    fn test_docker_config_acl_parsing() {
        let acl = r#"
            providers {
                docker {
                    host                = "tcp://localhost:2375"
                    label_prefix        = "myapp"
                    poll_interval_secs  = 30
                }
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let docker = config.providers.docker.unwrap();
        assert_eq!(docker.host, "tcp://localhost:2375");
        assert_eq!(docker.label_prefix, "myapp");
        assert_eq!(docker.poll_interval_secs, 30);
    }

    #[test]
    fn test_docker_config_defaults_in_acl() {
        let acl = r#"
            providers {
                docker {}
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        let docker = config.providers.docker.unwrap();
        assert_eq!(docker.host, "/var/run/docker.sock");
        assert_eq!(docker.label_prefix, "a3s");
        assert_eq!(docker.poll_interval_secs, 10);
    }

    #[test]
    fn test_docker_config_absent_when_not_configured() {
        let acl = r#"
            entrypoints "web" {
                address = "0.0.0.0:80"
            }
        "#;
        let config = GatewayConfig::from_acl(acl).unwrap();
        assert!(config.providers.docker.is_none());
    }

    #[test]
    fn test_docker_config_serialization_roundtrip() {
        let config = DockerProviderConfig {
            host: "tcp://docker-host:2375".to_string(),
            label_prefix: "traefik".to_string(),
            poll_interval_secs: 5,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DockerProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.host, "tcp://docker-host:2375");
        assert_eq!(parsed.label_prefix, "traefik");
        assert_eq!(parsed.poll_interval_secs, 5);
    }
}
