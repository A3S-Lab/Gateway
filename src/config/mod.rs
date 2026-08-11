//! Configuration types for A3S Gateway
//!
//! Defines the configuration model following Traefik's
//! entrypoint → router → middleware → service architecture.
//! Uses ACL (Agent Configuration Language) as the configuration format.

pub(crate) mod acl;
mod entrypoint;
mod inference;
mod middleware;
mod mode;
mod router;
pub mod scaling;
mod service;
mod usage;

pub use entrypoint::{EntrypointConfig, Protocol, TlsConfig};
pub use inference::{
    InferenceConfig, InferenceCredentialConfig, InferenceEndpoint, InferenceGrantConfig,
    InferenceLimitsConfig, InferenceModelConfig, InferenceRouteConfig, InferenceTargetConfig,
    INFERENCE_CREDENTIAL_AUDIENCE,
};
pub use middleware::MiddlewareConfig;
pub use mode::OperatingMode;
pub use router::RouterConfig;
pub use scaling::{RevisionConfig, RolloutConfig, ScalingConfig};
pub(crate) use service::parse_duration as parse_service_duration;
pub use service::{
    FailoverConfig, HealthCheckConfig, LoadBalancerConfig, ManagedTargetConfig, MirrorConfig,
    ServerConfig, ServiceConfig, StickyConfig, Strategy,
};
pub use usage::UsageSpoolConfig;
#[cfg(test)]
pub(crate) use usage::MIN_USAGE_SPOOL_MAX_BYTES;

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

    /// Optional Cloud-projected native inference policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inference: Option<InferenceConfig>,

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

    /// Optional dedicated node API listener (`management` in ACL for compatibility).
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
        self.validate_with_custom_middlewares(&std::collections::HashSet::new())
    }

    pub(crate) fn validate_with_custom_middlewares(
        &self,
        custom_middlewares: &std::collections::HashSet<String>,
    ) -> Result<()> {
        self.validate_mode_constraints()?;
        if let Some(inference) = &self.inference {
            inference.validate(self, chrono::Utc::now())?;
        }

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
                if !self.middlewares.contains_key(mw) && !custom_middlewares.contains(mw) {
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

        if let Some(name) = custom_middlewares
            .iter()
            .filter(|name| self.middlewares.contains_key(*name))
            .min()
        {
            return Err(GatewayError::Config(format!(
                "Custom middleware '{name}' conflicts with an ACL middleware definition"
            )));
        }

        // Compile every definition through the production constructor so CLI,
        // startup, and reload validation share one semantic boundary for
        // middleware-specific settings and feature requirements.
        let mut middleware_names = self.middlewares.keys().collect::<Vec<_>>();
        middleware_names.sort();
        for name in middleware_names {
            crate::middleware::Pipeline::from_config(std::slice::from_ref(name), &self.middlewares)
                .map_err(|error| {
                    let detail = match error {
                        GatewayError::Config(detail) => detail,
                        other => other.to_string(),
                    };
                    GatewayError::Config(format!("Middleware '{name}' is invalid: {detail}"))
                })?;
        }

        // Every service must have a configured or executor-owned upstream source.
        for (name, svc) in &self.services {
            if svc.load_balancer.servers.is_empty()
                && svc.revisions.is_empty()
                && !svc.uses_box_endpoint_discovery()
            {
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
            service::parse_duration(&svc.load_balancer.stream_idle_timeout).map_err(|e| {
                GatewayError::Config(format!(
                    "Invalid stream_idle_timeout for service '{}': {}",
                    name, e
                ))
            })?;
            service::parse_duration(&svc.load_balancer.stream_total_timeout).map_err(|e| {
                GatewayError::Config(format!(
                    "Invalid stream_total_timeout for service '{}': {}",
                    name, e
                ))
            })?;
            if let Some(health_check) = &svc.load_balancer.health_check {
                health_check
                    .validate_and_parse_durations()
                    .map_err(|error| {
                        GatewayError::Config(format!(
                            "Invalid health_check for service '{}': {}",
                            name, error
                        ))
                    })?;
            }

            // Validate scaling configuration
            scaling::validate_scaling(
                name,
                svc.scaling.as_ref(),
                &svc.revisions,
                svc.rollout.as_ref(),
            )?;
        }

        let autoscaling_executors: std::collections::BTreeSet<_> = self
            .services
            .values()
            .filter_map(|service| {
                service
                    .scaling
                    .as_ref()
                    .filter(|scaling| scaling.container_concurrency > 0)
                    .map(|scaling| scaling.executor.as_str())
            })
            .collect();
        if autoscaling_executors.len() > 1 {
            return Err(GatewayError::Config(format!(
                "Standalone autoscaling requires one executor across all active services, got: {}",
                autoscaling_executors
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }

        let box_executor_endpoints: std::collections::BTreeSet<_> = self
            .services
            .values()
            .filter_map(|service| {
                service
                    .scaling
                    .as_ref()
                    .filter(|scaling| {
                        scaling.container_concurrency > 0 && scaling.executor == "box"
                    })
                    .map(|scaling| scaling.executor_endpoint.as_str())
            })
            .collect();
        if box_executor_endpoints.len() > 1 {
            return Err(GatewayError::Config(format!(
                "Standalone Box autoscaling requires one executor_endpoint across all active services, got: {}",
                box_executor_endpoints
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
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
            inference: None,
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

    /// Optional absolute path for the durable managed-snapshot journal.
    #[serde(default)]
    pub state_file: Option<std::path::PathBuf>,

    /// Optional node-local durable usage spool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_spool: Option<UsageSpoolConfig>,
}

/// Dedicated node API listener configuration.
///
/// The historical `management` ACL block is retained for Cloud compatibility.
/// The listener is disabled by default and never intercepts user traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementConfig {
    /// Enable the node HTTP API.
    #[serde(default)]
    pub enabled: bool,

    /// Node API listener address.
    #[serde(default = "default_management_address")]
    pub address: String,

    /// API path prefix.
    #[serde(default = "default_management_path_prefix")]
    pub path_prefix: String,

    /// Optional environment variable containing the bearer token.
    #[serde(default = "default_management_auth_token_env")]
    pub auth_token_env: Option<String>,

    /// Allowed client IPs or CIDR ranges for the node API listener.
    #[serde(default = "default_management_allowed_ips")]
    pub allowed_ips: Vec<String>,

    /// Optional TLS/mTLS configuration for the node API listener.
    #[serde(default)]
    pub tls: Option<ManagementTlsConfig>,
}

/// TLS and client certificate validation for the node API listener.
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
                "Node API TLS cert_file is required".to_string(),
            ));
        }
        if self.key_file.trim().is_empty() {
            return Err(GatewayError::Config(
                "Node API TLS key_file is required".to_string(),
            ));
        }
        if !matches!(self.min_version.as_str(), "1.2" | "1.3") {
            return Err(GatewayError::Config(format!(
                "Node API TLS min_version must be '1.2' or '1.3', got '{}'",
                self.min_version
            )));
        }

        match self.client_ca_file.as_deref() {
            Some(path) if path.trim().is_empty() => {
                return Err(GatewayError::Config(
                    "Node API TLS client_ca_file must not be empty".to_string(),
                ));
            }
            Some(_) => {}
            None if self.require_client_cert => {
                return Err(GatewayError::Config(
                    "Node API TLS require_client_cert requires client_ca_file".to_string(),
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
#[path = "config_tests.rs"]
mod tests;
