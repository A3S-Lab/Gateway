#![allow(clippy::items_after_test_module)]
//! # A3S Gateway
//!
//! An AI Native Traffic Layer for standalone and A3S Cloud-managed deployments.
//!
//! ## Architecture
//!
//! ```text
//! Agent Profile → Skill Catalog → Native CLI
//! Entrypoint    → Router        → Middleware → Service → Backend
//! ```
//!
//! ## Core Features
//!
//! - **Multi-protocol**: HTTP/HTTPS, WebSocket, SSE/Streaming, TCP
//! - **Coding agents**: Native CLI profiles, exact argument passthrough, standard Skills
//! - **Dynamic Routing**: Traefik-style rule engine (`Host()`, `PathPrefix()`, `Headers()`)
//! - **Load Balancing**: Round-robin, weighted, least-connections
//! - **Middleware Pipeline**: Built-in ACL policies plus typed Rust extensions
//! - **Health Checks**: Active HTTP probes with automatic backend removal
//! - **Hot Reload**: File-watch based ACL configuration reload without restart
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use a3s_gateway::{Gateway, config::GatewayConfig};
//!
//! #[tokio::main]
//! async fn main() -> a3s_gateway::Result<()> {
//!     let config = GatewayConfig::from_file("gateway.acl").await?;
//!     let gateway = Gateway::new(config)?;
//!     gateway.start().await?;
//!     gateway.wait_for_shutdown().await;
//!     Ok(())
//! }
//! ```

pub mod agent;
pub mod config;
pub(crate) mod entrypoint;
pub mod error;
pub mod gateway;
pub(crate) mod inference;
pub mod managed_service;
pub mod managed_snapshot;
pub mod middleware;
mod node_api;
pub(crate) mod observability;
pub mod provider;
pub(crate) mod proxy;
pub(crate) mod response_body;
#[doc(hidden)]
pub mod router;
pub(crate) mod scaling;
pub(crate) mod service;
pub(crate) mod static_object;
pub(crate) mod usage;
#[cfg(feature = "wire")]
pub mod wire;

// Re-export main types
pub use error::{GatewayError, Result};
pub use gateway::Gateway;
pub use middleware::{Middleware, MiddlewareRegistry, RequestContext};
pub use provider::discovery::{DiscoveredService, DiscoveryProvider, ServiceMetadata};
pub use usage::{UsageSpoolCursor, UsageSpoolStatus};

use crate::config::GatewayConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// True when cold start / reload will construct a Kubernetes API client —
/// either for `providers.kubernetes` watchers or standalone `scaling.executor = "k8s"`.
#[cfg(feature = "kube")]
fn config_needs_kubernetes_client(config: &GatewayConfig) -> bool {
    if config.providers.kubernetes.is_some() {
        return true;
    }
    config.services.values().any(|service| {
        service
            .scaling
            .as_ref()
            .is_some_and(|scaling| scaling.container_concurrency > 0 && scaling.executor == "k8s")
    })
}

/// True when cold start / reload will construct a standalone Box scale HTTP client.
fn config_needs_box_scale_client(config: &GatewayConfig) -> bool {
    config
        .services
        .values()
        .any(|service| service.uses_box_endpoint_discovery())
}

/// True when cold start will reconcile standalone k8s Scale subresources.
#[cfg(feature = "kube")]
fn config_needs_k8s_scale_probe(config: &GatewayConfig) -> bool {
    config.services.values().any(|service| {
        service
            .scaling
            .as_ref()
            .is_some_and(|scaling| scaling.container_concurrency > 0 && scaling.executor == "k8s")
    })
}

/// Probe Box scale GET `/v1/scale/{service}` for every active Box-discovered service.
fn validate_box_scale_activation(config: &GatewayConfig) -> Result<()> {
    crate::scaling::executor::validate_box_scale_services(&config.services)
}

/// Probe k8s `get_scale` for every standalone k8s autoscaler service.
#[cfg(feature = "kube")]
fn validate_k8s_scale_activation(config: &GatewayConfig) -> Result<()> {
    let namespace = config
        .providers
        .kubernetes
        .as_ref()
        .map(|provider| provider.namespace.as_str())
        .filter(|namespace| !namespace.is_empty())
        .unwrap_or("default");
    crate::scaling::kubernetes_executor::validate_k8s_scale_services(&config.services, namespace)
}

/// Probe the same health-check construction as cold start (`prepare_health_checks`).
///
/// Builds the service registry and revision routers so validate activates both
/// service-level and revision-pool checkers — not only a bare HTTP client.
fn validate_health_check_client_activation(config: &GatewayConfig) -> Result<()> {
    let registry = crate::service::ServiceRegistry::from_config(&config.services)?;
    let scaling_state = crate::gateway::builders::build_scaling_state(config);
    let _ = registry.prepare_health_checks(
        &config.services,
        scaling_state.as_ref().map(|state| &state.revision_routers),
    )?;
    Ok(())
}

/// Structural + activation checks shared by CLI validate, cold start, and
/// `Gateway::new` so missing TLS PEMs / node API secrets / managed bootstrap
/// traffic / usage Cloud ingest fail before bind.
pub fn validate_activation(config: &GatewayConfig) -> Result<()> {
    validate_activation_with_custom_middlewares(config, &HashSet::new())
}

/// Same as [`validate_activation`], then attach the root ACL parent path to the
/// same notify watcher surface as CLI hot reload.
///
/// Prefer this, [`validate_activation_with_custom_middlewares_at_path`],
/// [`Gateway::new_at_path`], or [`provider::load_merged_gateway_config`] when
/// `providers.file.watch` is enabled so validate ≡ activate includes the
/// config-file watch path, not only notify backend + optional conf.d directory.
pub fn validate_activation_at_path(
    config: &GatewayConfig,
    config_path: &std::path::Path,
) -> Result<()> {
    validate_activation_with_custom_middlewares_at_path(config, &HashSet::new(), config_path)
}

/// Same as [`validate_activation`], allowing programmatic middleware names.
pub fn validate_activation_with_custom_middlewares(
    config: &GatewayConfig,
    custom_middlewares: &HashSet<String>,
) -> Result<()> {
    config.validate_managed_bootstrap()?;
    // Raw operator ACL only — composed overlays inject reserved names later.
    config.validate_reserved_managed_service_acl_names()?;
    // Cold-start validate probes usage-spool exclusive lock contention.
    validate_runtime_activation_inner(config, custom_middlewares, true, None)
}

/// Same as [`validate_activation_with_custom_middlewares`], then attach the
/// root ACL parent path to the same notify watcher surface as
/// [`provider::FileWatcher::watch`] / CLI hot reload.
pub fn validate_activation_with_custom_middlewares_at_path(
    config: &GatewayConfig,
    custom_middlewares: &HashSet<String>,
    config_path: &std::path::Path,
) -> Result<()> {
    config.validate_managed_bootstrap()?;
    config.validate_reserved_managed_service_acl_names()?;
    validate_runtime_activation_inner(config, custom_middlewares, true, Some(config_path))
}

/// Activation checks for a config that may already carry traffic (managed
/// snapshot recovery or Managed Service overlay). Skips bootstrap-empty-traffic
/// rules that would reject a legitimate composed runtime ACL.
///
/// Does **not** probe usage-spool exclusive lock contention — callers such as
/// [`Gateway::start`] already hold `.lock` before this second activation pass.
pub(crate) fn validate_runtime_activation_with_custom_middlewares(
    config: &GatewayConfig,
    custom_middlewares: &HashSet<String>,
) -> Result<()> {
    validate_runtime_activation_inner(config, custom_middlewares, false, None)
}

fn validate_runtime_activation_inner(
    config: &GatewayConfig,
    custom_middlewares: &HashSet<String>,
    probe_usage_spool_lock: bool,
    config_path: Option<&std::path::Path>,
) -> Result<()> {
    config.validate_with_custom_middlewares(custom_middlewares)?;
    entrypoint::validate_entrypoints(config)?;
    if config.management.enabled {
        node_api::validate_node_api_listener_config(&config.management)?;
    }
    if let Some(spool) = &config.managed.usage_spool {
        usage::validate_usage_cloud_ingest_activation(spool)?;
        let gateway_id = config.managed.gateway_id.ok_or_else(|| {
            GatewayError::Config("managed.usage_spool requires managed.gateway_id".to_string())
        })?;
        usage::validate_usage_spool_activation(spool, gateway_id, probe_usage_spool_lock)?;
    }
    if let Some(discovery) = &config.providers.discovery {
        // Same client build as spawn_discovery_loop — fail closed here so CLI
        // validate matches cold start instead of soft-opening until providers start.
        let _ = provider::discovery::DiscoveryProvider::new(discovery.clone())?;
    }
    if let Some(docker) = &config.providers.docker {
        // Same `/_ping` transport as the poll loop — path/URL existence alone
        // cannot soft-open a forever-warn Docker poller.
        provider::docker::validate_docker_activation(docker)?;
    }
    #[cfg(feature = "kube")]
    if config_needs_kubernetes_client(config) {
        // Same Client::try_default surface as prepare_kubernetes_client / K8sScaleExecutor
        // (not kubeconfig YAML parse alone). Covers providers.kubernetes and
        // standalone scaling.executor = "k8s".
        provider::kubernetes::validate_kubernetes_activation()?;
    }
    #[cfg(feature = "kube")]
    if let Some(kubernetes) = &config.providers.kubernetes {
        // Same Ingress (and optional CRD) list surface as the first watcher poll —
        // client construction alone cannot soft-open a forever-warn provider.
        provider::kubernetes::validate_kubernetes_provider_activation(kubernetes)?;
    }
    #[cfg(feature = "kube")]
    if config_needs_k8s_scale_probe(config) {
        // Same get_scale surface as the first autoscaler reconcile — client
        // construction alone cannot soft-open a Running k8s autoscaler that only
        // errors on the first tick.
        validate_k8s_scale_activation(config)?;
    }
    if config_needs_box_scale_client(config) {
        // Same GET /v1/scale/{service} surface as the first autoscaler reconcile —
        // client construction alone cannot soft-open a Running autoscaler that
        // only errors on the first tick.
        validate_box_scale_activation(config)?;
    }
    // Default upstream TLS pools — same construction as build_runtime, so a missing
    // system CA store cannot soft-open Running and only fail on the first forward.
    crate::proxy::HttpProxy::try_with_timeouts(
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(10),
    )
    .map_err(|error| {
        GatewayError::Tls(format!("Failed to initialize upstream TLS client: {error}"))
    })?;
    crate::proxy::grpc::GrpcProxy::try_new().map_err(|error| {
        GatewayError::Tls(format!("Failed to initialize gRPC TLS client: {error}"))
    })?;
    // Per-service private CA proxies — same construction as build_runtime's
    // build_service_http_proxies / build_service_grpc_proxies /
    // build_service_ws_tls_configs (PEM-only validate is not enough).
    let _ = crate::gateway::builders::build_service_http_proxies(
        config,
        std::time::Duration::from_secs(30),
    )?;
    let _ = crate::gateway::builders::build_service_grpc_proxies(config)?;
    let _ = crate::gateway::builders::build_service_ws_tls_configs(config)?;
    validate_health_check_client_activation(config)?;
    managed_snapshot::validate_managed_snapshot_activation(config)?;
    if config.inference.is_some() {
        // Same Power credential resolution as build_runtime / snapshot apply.
        crate::inference::PowerDistributedClient::validate_credentials_from_policy(
            config.inference.as_ref(),
        )
        .map_err(|error| GatewayError::Config(error.to_string()))?;
    }
    proxy::acme_manager::AcmeManager::validate_activation(config)?;
    // Same HTTP connect surface as the first forward-auth request — URL shape
    // alone cannot soft-open Running and only 502 on traffic.
    middleware::validate_forward_auth_activation(&config.middlewares)?;
    #[cfg(feature = "redis")]
    {
        // Same multiplexed connect + PING as the first rate-limit request — URL
        // presence alone cannot soft-open Running and only 503 on traffic when
        // redis_fail_open = false.
        middleware::validate_redis_rate_limit_activation(&config.middlewares)?;
    }
    if config
        .providers
        .file
        .as_ref()
        .is_some_and(|file| file.watch)
    {
        // Same notify Watcher::new (+ optional conf.d / root ACL parent attach)
        // as hot reload — watch=true (the ACL default) cannot soft-open
        // validate while FileWatcher::watch / CLI run later aborts. Path-aware
        // callers (validate_activation_at_path / Gateway::new_at_path /
        // load_merged) probe the full FileWatcher::watch surface; path-less
        // embedders probe notify backend + optional conf.d only.
        let directory = config
            .providers
            .file
            .as_ref()
            .and_then(|file| file.directory.as_deref())
            .map(std::path::Path::new);
        match config_path {
            Some(path) => {
                provider::file_watcher::probe_file_watch_activation(path, directory)?;
            }
            None => {
                provider::file_watcher::probe_file_watch_notify_activation(directory)?;
            }
        }
    }
    Ok(())
}

/// Gateway runtime state
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GatewayState {
    /// Gateway has been created but not yet started
    #[default]
    Created,
    /// Gateway is initializing listeners and loading configuration
    Starting,
    /// Gateway is actively accepting and proxying requests
    Running,
    /// Gateway is reloading configuration without downtime
    Reloading,
    /// Gateway is draining connections and shutting down
    Stopping,
    /// Gateway has fully stopped
    Stopped,
}

impl std::fmt::Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Reloading => write!(f, "reloading"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped => write!(f, "stopped"),
        }
    }
}

/// Gateway health status snapshot
#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Current gateway state
    pub state: GatewayState,
    /// Process-level desired-state authority.
    #[serde(default)]
    pub mode: config::OperatingMode,
    /// Stable logical identity when the managed snapshot protocol is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<uuid::Uuid>,
    /// Uptime in seconds since gateway started
    pub uptime_secs: u64,
    /// Number of active connections
    pub active_connections: usize,
    /// Total requests handled since start
    pub total_requests: u64,
    /// Node-local durable usage spool state when explicitly configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_spool: Option<UsageSpoolStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_state_default() {
        let state = GatewayState::default();
        assert_eq!(state, GatewayState::Created);
    }

    #[test]
    fn test_gateway_state_display() {
        assert_eq!(GatewayState::Created.to_string(), "created");
        assert_eq!(GatewayState::Starting.to_string(), "starting");
        assert_eq!(GatewayState::Running.to_string(), "running");
        assert_eq!(GatewayState::Reloading.to_string(), "reloading");
        assert_eq!(GatewayState::Stopping.to_string(), "stopping");
        assert_eq!(GatewayState::Stopped.to_string(), "stopped");
    }

    #[test]
    fn test_gateway_state_equality() {
        assert_eq!(GatewayState::Running, GatewayState::Running);
        assert_ne!(GatewayState::Running, GatewayState::Stopped);
    }

    #[test]
    fn test_gateway_state_serialization() {
        let state = GatewayState::Running;
        let json = serde_json::to_string(&state).unwrap();
        let parsed: GatewayState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, GatewayState::Running);
    }

    #[test]
    fn test_health_status_default() {
        let health = HealthStatus::default();
        assert_eq!(health.state, GatewayState::Created);
        assert_eq!(health.mode, config::OperatingMode::Standalone);
        assert_eq!(health.gateway_id, None);
        assert_eq!(health.uptime_secs, 0);
        assert_eq!(health.active_connections, 0);
        assert_eq!(health.total_requests, 0);
        assert_eq!(health.usage_spool, None);
    }

    #[test]
    fn test_health_status_serialization() {
        let gateway_id = uuid::Uuid::new_v4();
        let health = HealthStatus {
            state: GatewayState::Running,
            mode: config::OperatingMode::CloudManaged,
            gateway_id: Some(gateway_id),
            uptime_secs: 3600,
            active_connections: 42,
            total_requests: 10000,
            usage_spool: None,
        };
        let json = serde_json::to_string(&health).unwrap();
        let parsed: HealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.state, GatewayState::Running);
        assert_eq!(parsed.mode, config::OperatingMode::CloudManaged);
        assert_eq!(parsed.gateway_id, Some(gateway_id));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).unwrap()["mode"],
            "cloud-managed"
        );
        assert_eq!(parsed.uptime_secs, 3600);
        assert_eq!(parsed.active_connections, 42);
        assert_eq!(parsed.total_requests, 10000);
    }

    #[test]
    fn test_health_status_clone() {
        let health = HealthStatus {
            state: GatewayState::Running,
            mode: config::OperatingMode::Standalone,
            gateway_id: None,
            uptime_secs: 100,
            active_connections: 5,
            total_requests: 500,
            usage_spool: None,
        };
        let cloned = health.clone();
        assert_eq!(cloned.state, health.state);
        assert_eq!(cloned.uptime_secs, health.uptime_secs);
    }
}
