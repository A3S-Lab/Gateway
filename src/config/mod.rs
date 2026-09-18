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
mod static_bundle;
mod usage;

pub use entrypoint::{EntrypointConfig, Protocol, TlsConfig};
pub use inference::{
    InferenceConfig, InferenceCredentialConfig, InferenceDistributedServingConfig,
    InferenceEndpoint, InferenceGrantConfig, InferenceLimitsConfig, InferenceModelConfig,
    InferencePhaseRole, InferenceRouteConfig, InferenceSchedulingConfig, InferenceTargetConfig,
    InferenceTransferHealth, InferenceWorkerConfig, INFERENCE_CREDENTIAL_AUDIENCE,
    INFERENCE_TOKENIZER_REVISION, POWER_WORKER_OBSERVATION_SCHEMA,
};
pub use middleware::MiddlewareConfig;
pub use mode::OperatingMode;
pub use router::RouterConfig;
pub use scaling::{RevisionConfig, RolloutConfig, ScalingConfig};
pub(crate) use service::{
    default_request_timeout, default_stream_idle_timeout, default_stream_total_timeout,
    parse_duration as parse_service_duration, server_supports_active_http_health_probe,
    server_supports_sticky_affinity, validate_server_url, validate_server_weight,
    validate_sticky_cookie_name,
};
pub use service::{
    parse_declared_priority, parse_declared_request_timeout, parse_declared_strategy,
    FailoverConfig, HealthCheckConfig, LoadBalancerConfig, ManagedTargetConfig, MirrorConfig,
    ServerConfig, ServiceConfig, StickyConfig, Strategy,
};
pub use static_bundle::{StaticBundleConfig, StaticBundleManifestConfig};
pub use usage::UsageSpoolConfig;
pub(crate) use usage::DEFAULT_USAGE_CLOUD_INGEST_BATCH_LIMIT;
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

    /// Static bundles: read-only immutable Web releases (`WEB0.4`)
    #[serde(default)]
    pub static_bundles: HashMap<String, StaticBundleConfig>,

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
        // Compile every route during configuration validation. This keeps
        // malformed matcher syntax out of startup/reload side effects and
        // makes `config validate` equivalent to the runtime route compiler.
        crate::router::RouterTable::from_config(&self.routers)?;
        crate::router::TcpRouterTable::from_config(&self.routers)
            .map_err(|error| GatewayError::Config(format!("TCP/SNI router table: {error}")))?;
        self.validate_listener_addresses()?;
        self.validate_entrypoint_listener_policy()?;
        self.validate_acme_policy()?;
        if let Some(docker) = &self.providers.docker {
            if docker.poll_interval_secs == 0 {
                return Err(GatewayError::Config(
                    "Docker poll_interval_secs must be greater than zero".to_string(),
                ));
            }
            if docker.label_prefix.trim().is_empty()
                || docker.label_prefix.len() > 128
                || docker.label_prefix.chars().any(char::is_control)
                || docker.label_prefix.chars().any(char::is_whitespace)
            {
                return Err(GatewayError::Config(
                    "Docker label_prefix must be non-empty, at most 128 bytes, and contain no whitespace or control characters".to_string(),
                ));
            }
            if docker.host.starts_with('/') {
                if docker.host.chars().any(char::is_control) {
                    return Err(GatewayError::Config(
                        "Docker Unix socket host must not contain control characters".to_string(),
                    ));
                }
                #[cfg(not(unix))]
                {
                    return Err(GatewayError::Config(
                        "Docker Unix socket connections are not supported on this platform. \
                         Set providers.docker.host to a TCP URL (e.g. tcp://localhost:2375)."
                            .to_string(),
                    ));
                }
                #[cfg(unix)]
                {
                    // Same class as providers.file.directory: a configured Unix
                    // socket that is missing soft-opens as a forever-failing poller.
                    if !std::path::Path::new(&docker.host).exists() {
                        return Err(GatewayError::Config(format!(
                            "Docker Unix socket host '{}' does not exist",
                            docker.host
                        )));
                    }
                }
            } else {
                let parsed = url::Url::parse(&docker.host).map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid Docker host '{}': {}",
                        docker.host, error
                    ))
                })?;
                if !matches!(parsed.scheme(), "tcp" | "http") || parsed.host_str().is_none() {
                    return Err(GatewayError::Config(
                        "Docker host must be an absolute tcp:// or http:// URL, or an absolute Unix socket path".to_string(),
                    ));
                }
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Err(GatewayError::Config(
                        "Docker host must not contain embedded credentials".to_string(),
                    ));
                }
                if parsed.query().is_some() || parsed.fragment().is_some() {
                    return Err(GatewayError::Config(
                        "Docker host must not contain a query or fragment".to_string(),
                    ));
                }
                if !parsed.path().is_empty() && parsed.path() != "/" {
                    return Err(GatewayError::Config(
                        "Docker host must not contain a path".to_string(),
                    ));
                }
            }
        }
        if let Some(kubernetes) = &self.providers.kubernetes {
            #[cfg(not(feature = "kube"))]
            {
                let _ = kubernetes;
                return Err(GatewayError::Config(
                    "providers.kubernetes requires the 'kube' feature flag: cargo build --features kube"
                        .to_string(),
                ));
            }
            #[cfg(feature = "kube")]
            if kubernetes.watch_interval_secs == 0 {
                return Err(GatewayError::Config(
                    "Kubernetes watch_interval_secs must be greater than zero".to_string(),
                ));
            }
        }
        if let Some(discovery) = &self.providers.discovery {
            if discovery.seeds.is_empty() {
                return Err(GatewayError::Config(
                    "providers.discovery requires at least one seed URL; empty seeds soft-open as a no-op provider".to_string(),
                ));
            }
            if discovery.poll_interval_secs == 0 {
                return Err(GatewayError::Config(
                    "Discovery poll_interval_secs must be greater than zero".to_string(),
                ));
            }
            if discovery.timeout_secs == 0 {
                return Err(GatewayError::Config(
                    "Discovery timeout_secs must be greater than zero".to_string(),
                ));
            }
            let mut discovery_seed_urls = std::collections::HashSet::new();
            for (index, seed) in discovery.seeds.iter().enumerate() {
                if !discovery_seed_urls.insert(seed.url.as_str()) {
                    return Err(GatewayError::Config(format!(
                        "Discovery seed URL '{}' is duplicated",
                        seed.url
                    )));
                }
                let parsed = url::Url::parse(&seed.url).map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid discovery seed URL at index {index}: {error}"
                    ))
                })?;
                if !matches!(parsed.scheme(), "http" | "https") || parsed.host().is_none() {
                    return Err(GatewayError::Config(format!(
                        "Discovery seed URL at index {index} must use http or https and include a host"
                    )));
                }
                if parsed.username() != "" || parsed.password().is_some() {
                    return Err(GatewayError::Config(format!(
                        "Discovery seed URL at index {index} must not contain credentials"
                    )));
                }
                if parsed.query().is_some() || parsed.fragment().is_some() {
                    return Err(GatewayError::Config(format!(
                        "Discovery seed URL at index {index} must not contain a query or fragment"
                    )));
                }
            }
        }
        if let Some(inference) = &self.inference {
            inference.validate(self, chrono::Utc::now())?;
        }

        // Every router must reference an existing service or static bundle.
        for (name, router) in &self.routers {
            let has_service = self.services.contains_key(&router.service);
            let has_static = self.static_bundles.contains_key(&router.service);
            if has_service == has_static {
                return Err(GatewayError::Config(format!(
                    "Router '{}' references unknown or ambiguous target '{}'; name exactly one service or static_bundle",
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
            let retry_count = router
                .middlewares
                .iter()
                .filter(|middleware| {
                    self.middlewares
                        .get(*middleware)
                        .is_some_and(|config| config.middleware_type == "retry")
                })
                .count();
            if retry_count > 1 {
                return Err(GatewayError::Config(format!(
                    "Router '{}' references retry middleware more than once",
                    name
                )));
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
            // Router middleware, static bundles, and inference run on the HTTP
            // request path only. An explicit TCP/UDP binding, or an omitted
            // list when every configured listener is TCP or UDP, never reaches
            // that path. No listeners yet is a partial config, not a mismatch.
            if let Some((entrypoint_name, protocol)) =
                router_non_http_binding(&self.entrypoints, router)
            {
                let protocol = listener_protocol_name(protocol);
                if !router.middlewares.is_empty() {
                    let middleware = &router.middlewares[0];
                    return Err(GatewayError::Config(format!(
                        "Router '{name}' sets middleware '{middleware}', which applies only to protocol http (entrypoint '{entrypoint_name}' is {protocol})"
                    )));
                }
                if self.static_bundles.contains_key(&router.service) {
                    return Err(GatewayError::Config(format!(
                        "Router '{name}' targets static bundle '{}', which applies only to protocol http (entrypoint '{entrypoint_name}' is {protocol})",
                        router.service
                    )));
                }
            }
        }

        for name in self.static_bundles.keys() {
            if self.services.contains_key(name) {
                return Err(GatewayError::Config(format!(
                    "static_bundles '{name}' conflicts with a service of the same name"
                )));
            }
        }
        let mut static_names = self.static_bundles.keys().collect::<Vec<_>>();
        static_names.sort();
        for name in static_names {
            self.static_bundles[name].validate(name)?;
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
            service::parse_duration(&svc.load_balancer.connect_timeout).map_err(|e| {
                GatewayError::Config(format!(
                    "Invalid connect_timeout for service '{}': {}",
                    name, e
                ))
            })?;
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
                // Declared active health must apply to every configured backend.
                // Skipping non-HTTP members leaves them default-healthy forever
                // (validate ≡ activate: no soft-open mixed pools).
                let mut probe_urls: Vec<&str> = svc
                    .load_balancer
                    .servers
                    .iter()
                    .map(|server| server.url.as_str())
                    .collect();
                for revision in &svc.revisions {
                    for server in &revision.servers {
                        probe_urls.push(server.url.as_str());
                    }
                }
                if probe_urls.is_empty() {
                    return Err(GatewayError::Config(format!(
                        "Service '{name}' sets health_check but has no http:// or https:// servers"
                    )));
                }
                for url in &probe_urls {
                    if !server_supports_active_http_health_probe(url) {
                        return Err(GatewayError::Config(format!(
                            "Service '{name}' sets health_check but server '{url}' is not http:// or https://; active health cannot probe non-HTTP backends"
                        )));
                    }
                }
            }

            for (index, server) in svc.load_balancer.servers.iter().enumerate() {
                validate_server_weight(server.weight).map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid server weight for service '{}' at index {}: {}",
                        name, index, error
                    ))
                })?;
                validate_server_url(&server.url).map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid server URL for service '{}' at index {}: {}",
                        name, index, error
                    ))
                })?;
            }

            if let Some(sticky) = &svc.load_balancer.sticky {
                validate_sticky_cookie_name(&sticky.cookie).map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid sticky cookie for service '{name}': {error}"
                    ))
                })?;
                // Cookie affinity is only enforced by HTTP, gRPC, and WebSocket
                // handlers. A tcp/udp pool still validates today and then ignores
                // the cookie, so the ACL claims a control the listener never reads.
                let affinity_urls: Vec<&str> = svc
                    .load_balancer
                    .servers
                    .iter()
                    .map(|server| server.url.as_str())
                    .chain(svc.revisions.iter().flat_map(|revision| {
                        revision.servers.iter().map(|server| server.url.as_str())
                    }))
                    .collect();
                if !affinity_urls.is_empty()
                    && affinity_urls
                        .iter()
                        .all(|url| !server_supports_sticky_affinity(url))
                {
                    let server = affinity_urls[0];
                    return Err(GatewayError::Config(format!(
                        "Service '{name}' sets sticky, which applies only to http, https, h2c, ws, or wss backends (server '{server}' is not)"
                    )));
                }
            }

            if let Some(ca_file) = svc.load_balancer.tls_ca_file.as_deref() {
                if ca_file.trim().is_empty() {
                    return Err(GatewayError::Config(format!(
                        "Service '{name}' tls_ca_file must not be empty"
                    )));
                }
                // Same server union as health_check: revision HTTPS backends
                // need the declared CA (validate ≡ activate).
                let has_https = svc
                    .load_balancer
                    .servers
                    .iter()
                    .map(|server| server.url.as_str())
                    .chain(svc.revisions.iter().flat_map(|revision| {
                        revision.servers.iter().map(|server| server.url.as_str())
                    }))
                    .any(|url| {
                        url::Url::parse(url)
                            .ok()
                            .is_some_and(|parsed| parsed.scheme() == "https")
                    });
                if !has_https {
                    return Err(GatewayError::Config(format!(
                        "Service '{name}' sets tls_ca_file but has no https:// servers"
                    )));
                }
                crate::proxy::http_proxy::validate_tls_ca_file(ca_file).map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid tls_ca_file for service '{name}': {error}"
                    ))
                })?;
            }

            if let Some(mirror) = &svc.mirror {
                if !self.services.contains_key(&mirror.service) {
                    return Err(GatewayError::Config(format!(
                        "Service '{}' mirror references unknown service '{}'",
                        name, mirror.service
                    )));
                }
                if mirror.percentage > 100 {
                    return Err(GatewayError::Config(format!(
                        "Service '{}' mirror percentage ({}) must be at most 100",
                        name, mirror.percentage
                    )));
                }
            }
            if let Some(failover) = &svc.failover {
                if !self.services.contains_key(&failover.service) {
                    return Err(GatewayError::Config(format!(
                        "Service '{}' failover references unknown service '{}'",
                        name, failover.service
                    )));
                }
                if failover.service == *name {
                    return Err(GatewayError::Config(format!(
                        "Service '{}' failover must reference a different service",
                        name
                    )));
                }
            }

            // Validate scaling configuration
            scaling::validate_scaling(
                name,
                svc.scaling.as_ref(),
                &svc.revisions,
                svc.rollout.as_ref(),
            )?;
        }

        // Mirror copies use the HTTP proxy. A shadow pool that cannot speak
        // http(s) still validates, then every copy fails and is discarded.
        let mirror_targets: Vec<(String, String, u8)> = self
            .services
            .iter()
            .filter_map(|(name, svc)| {
                svc.mirror
                    .as_ref()
                    .map(|mirror| (name.clone(), mirror.service.clone(), mirror.percentage))
            })
            .collect();
        for (name, shadow_name, percentage) in mirror_targets {
            if percentage == 0 {
                continue;
            }
            let Some(shadow) = self.services.get(&shadow_name) else {
                continue;
            };
            let shadow_urls: Vec<&str> =
                shadow
                    .load_balancer
                    .servers
                    .iter()
                    .map(|server| server.url.as_str())
                    .chain(shadow.revisions.iter().flat_map(|revision| {
                        revision.servers.iter().map(|server| server.url.as_str())
                    }))
                    .collect();
            if shadow_urls.is_empty()
                || shadow_urls
                    .iter()
                    .any(|url| server_supports_active_http_health_probe(url))
            {
                continue;
            }
            let server = shadow_urls[0];
            return Err(GatewayError::Config(format!(
                "Service '{name}' mirror target '{shadow_name}' cannot receive an HTTP copy (server '{server}' is not http:// or https://)"
            )));
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
            if !self.management.path_prefix.starts_with('/') {
                return Err(GatewayError::Config(
                    "Management path_prefix must start with '/'".to_string(),
                ));
            }
            match self.management.auth_token_env.as_deref() {
                Some(name) if !name.trim().is_empty() => {}
                _ => {
                    return Err(GatewayError::Config(
                        "management.enabled requires a non-empty auth_token_env; empty auth soft-opens the node API without bearer protection".to_string(),
                    ));
                }
            }
            if self.management.allowed_ips.is_empty() {
                return Err(GatewayError::Config(
                    "management.enabled requires at least one allowed_ips entry; an empty list soft-opens the node API to any client IP".to_string(),
                ));
            }
            crate::middleware::ip_matcher::IpMatcher::new(&self.management.allowed_ips)?;
            if let Some(tls) = &self.management.tls {
                tls.validate()?;
            }
        }

        Ok(())
    }

    fn validate_entrypoint_listener_policy(&self) -> Result<()> {
        let mut names = self.entrypoints.keys().cloned().collect::<Vec<_>>();
        names.sort();
        for name in names {
            self.entrypoints[&name].validate_listener_policy(&name)?;
        }
        Ok(())
    }

    fn validate_acme_policy(&self) -> Result<()> {
        let mut names = self.entrypoints.keys().cloned().collect::<Vec<_>>();
        names.sort();
        for name in names {
            let Some(tls) = self.entrypoints[&name].tls.as_ref().filter(|tls| tls.acme) else {
                continue;
            };
            let domains = resolve_acme_domains(tls, &self.routers);
            if domains.is_empty() {
                return Err(GatewayError::Config(format!(
                    "Entrypoint '{name}' TLS acme requires acme_domains or at least one Host(`...`) router"
                )));
            }
            for domain in &domains {
                if domain.trim().is_empty() || domain.contains(' ') {
                    return Err(GatewayError::Config(format!(
                        "Entrypoint '{name}' TLS acme has invalid domain '{domain}'"
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_listener_addresses(&self) -> Result<()> {
        let mut addresses = std::collections::HashMap::<std::net::SocketAddr, String>::new();
        for (name, entrypoint) in &self.entrypoints {
            let address = entrypoint
                .address
                .parse::<std::net::SocketAddr>()
                .map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid address '{}' for entrypoint '{}': {}",
                        entrypoint.address, name, error
                    ))
                })?;
            if let Some(previous) = addresses.insert(address, name.clone()) {
                return Err(GatewayError::Config(format!(
                    "Entrypoints '{}' and '{}' use the same listen address {}",
                    previous, name, address
                )));
            }
        }

        if self.management.enabled {
            let management_address = self
                .management
                .address
                .parse::<std::net::SocketAddr>()
                .map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid management address '{}': {}",
                        self.management.address, error
                    ))
                })?;
            if let Some((name, entrypoint_address)) = addresses
                .iter()
                .find(|(address, _)| listener_addresses_conflict(management_address, **address))
            {
                return Err(GatewayError::Config(format!(
                    "Management listener address {} conflicts with entrypoint '{}' at {}",
                    management_address, name, entrypoint_address
                )));
            }
        }
        Ok(())
    }
}

/// Stable listener protocol name for validate errors.
fn listener_protocol_name(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::Http => "http",
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    }
}

/// `Some` when this router is bound only to TCP or UDP listeners.
///
/// An empty router entrypoint list means every configured listener. An empty
/// gateway entrypoint map is a partial config and returns `None`.
fn router_non_http_binding<'a>(
    entrypoints: &'a HashMap<String, EntrypointConfig>,
    router: &'a RouterConfig,
) -> Option<(&'a str, &'a Protocol)> {
    let mut bound: Vec<&str> = if router.entrypoints.is_empty() {
        entrypoints.keys().map(String::as_str).collect()
    } else {
        router.entrypoints.iter().map(String::as_str).collect()
    };
    bound.sort_unstable();
    if bound.is_empty()
        || bound.iter().any(|name| {
            entrypoints
                .get(*name)
                .is_some_and(|entrypoint| entrypoint.protocol == Protocol::Http)
        })
    {
        return None;
    }
    let name = bound[0];
    Some((name, &entrypoints[name].protocol))
}

/// Resolve ACME certificate domains from explicit `acme_domains` or Host routers.
pub(crate) fn resolve_acme_domains(
    tls: &TlsConfig,
    routers: &std::collections::HashMap<String, RouterConfig>,
) -> Vec<String> {
    if !tls.acme_domains.is_empty() {
        return tls.acme_domains.clone();
    }
    let mut domains = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut names = routers.keys().cloned().collect::<Vec<_>>();
    names.sort();
    for name in names {
        let rule = &routers[&name].rule;
        let Ok(parsed) = crate::router::Rule::parse(rule) else {
            continue;
        };
        if let Some(host) = parsed.host_hint() {
            let host = host.trim();
            if host.is_empty() || !seen.insert(host.to_string()) {
                continue;
            }
            domains.push(host.to_string());
        }
    }
    domains
}

/// Whether two local listeners can be bound simultaneously without an
/// explicit socket-reuse policy. Wildcard addresses conflict with every
/// address in the same address family and port, so reject those combinations
/// during validation instead of discovering the collision halfway through
/// startup.
fn listener_addresses_conflict(left: std::net::SocketAddr, right: std::net::SocketAddr) -> bool {
    if left.port() != right.port() {
        return false;
    }
    if left.ip() == right.ip() {
        return true;
    }
    match (left.ip(), right.ip()) {
        (std::net::IpAddr::V4(left), std::net::IpAddr::V4(right)) => {
            left.is_unspecified() || right.is_unspecified()
        }
        (std::net::IpAddr::V6(left), std::net::IpAddr::V6(right)) => {
            left.is_unspecified() || right.is_unspecified()
        }
        // Tokio's default IPv6 listener may also accept IPv4 traffic on
        // platforms with dual-stack sockets. A wildcard on either side is
        // therefore ambiguous; two specific addresses remain independent.
        (std::net::IpAddr::V4(left), std::net::IpAddr::V6(right))
        | (std::net::IpAddr::V6(right), std::net::IpAddr::V4(left)) => {
            left.is_unspecified() || right.is_unspecified()
        }
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
            static_bundles: HashMap::new(),
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
            Some(_) if !self.require_client_cert => {
                return Err(GatewayError::Config(
                    "Node API TLS client_ca_file requires require_client_cert = true; optional client auth soft-opens mTLS".to_string(),
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
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
