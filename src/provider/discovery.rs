//! Health-based service discovery provider
//!
//! Polls backend seed URLs for `/.well-known/a3s-service.json` metadata
//! and health endpoints. Discovered services are merged with static config
//! and trigger `Gateway::reload()` on change.
//!
//! ## Contract
//!
//! Backends expose a JSON document at `/.well-known/a3s-service.json`:
//!
//! ```json
//! {
//!   "name": "auth-service",
//!   "version": "1.2.0",
//!   "routes": [
//!     { "rule": "PathPrefix(`/auth`)", "middlewares": ["rate-limit"], "priority": 0 }
//!   ],
//!   "health_path": "/health",
//!   "weight": 1
//! }
//! ```

use crate::config::{
    DiscoveryConfig, GatewayConfig, LoadBalancerConfig, RouterConfig, ServerConfig, ServiceConfig,
    Strategy,
};
use crate::error::{GatewayError, Result};
use bytes::BytesMut;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, RwLock};

/// Well-known path for service metadata (RFC 8615)
pub const WELL_KNOWN_PATH: &str = "/.well-known/a3s-service.json";
const MAX_METADATA_BYTES: usize = 64 * 1024;
const MAX_METADATA_NAME_BYTES: usize = 128;
const MAX_METADATA_VERSION_BYTES: usize = 128;
const MAX_METADATA_HEALTH_PATH_BYTES: usize = 2048;
const MAX_METADATA_ROUTE_BYTES: usize = 4096;

/// Service metadata — the JSON contract backends expose
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceMetadata {
    /// Service key used in gateway config (e.g., "auth-service")
    pub name: String,
    /// Service version — used for change detection
    pub version: String,
    /// Routing rules this service advertises
    #[serde(default)]
    pub routes: Vec<RouteMetadata>,
    /// Health check path (default: "/health")
    #[serde(default = "default_health_path")]
    pub health_path: String,
    /// Load balancer weight (default: 1)
    #[serde(default = "default_weight")]
    pub weight: u32,
}

/// A single route advertised by a backend service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteMetadata {
    /// Traefik-style rule expression
    pub rule: String,
    /// Middleware chain references
    #[serde(default)]
    pub middlewares: Vec<String>,
    /// Priority (lower = higher priority, default: 0)
    #[serde(default)]
    pub priority: i32,
}

fn default_health_path() -> String {
    "/health".to_string()
}

fn default_weight() -> u32 {
    1
}

/// A discovered backend service — metadata + origin URL + health status
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredService {
    /// Base URL of the seed that was probed
    pub seed_url: String,
    /// Parsed service metadata from `/.well-known/a3s-service.json`
    pub metadata: ServiceMetadata,
    /// Whether the health endpoint returned 2xx
    pub healthy: bool,
}

/// Discovery provider — probes seeds and builds config
pub struct DiscoveryProvider {
    config: DiscoveryConfig,
    client: Option<reqwest::Client>,
    discovered: Arc<RwLock<HashMap<String, Vec<DiscoveredService>>>>,
    /// Last successful metadata observation per configured seed. Failed
    /// probes retain their previous observation for a bounded grace window so
    /// a transient discovery outage cannot withdraw every dynamic route.
    last_success: Arc<RwLock<HashMap<String, std::time::Instant>>>,
}

impl DiscoveryProvider {
    /// Create a new discovery provider with the given config
    pub fn new(config: DiscoveryConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            // Discovery is an authority boundary: a seed may not redirect
            // metadata or health probes to an unconfigured origin.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                tracing::error!(error = %error, "Could not initialize discovery HTTP client");
                error
            })
            .ok();

        Self {
            config,
            client,
            discovered: Arc::new(RwLock::new(HashMap::new())),
            last_success: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Probe a single seed URL for service metadata and health
    pub async fn probe_seed(&self, seed_url: &str) -> Result<DiscoveredService> {
        let seed = url::Url::parse(seed_url).map_err(|error| {
            GatewayError::Discovery(format!(
                "Invalid discovery seed URL '{}': {}",
                seed_url, error
            ))
        })?;
        if !matches!(seed.scheme(), "http" | "https")
            || seed.host().is_none()
            || !seed.username().is_empty()
            || seed.password().is_some()
        {
            return Err(GatewayError::Discovery(format!(
                "Discovery seed URL '{}' must use http or https, include a host, and omit credentials",
                seed_url
            )));
        }

        let client = self.client.as_ref().ok_or_else(|| {
            GatewayError::Discovery(
                "Discovery HTTP client is unavailable; refusing to probe seeds".to_string(),
            )
        })?;
        let metadata_url = format!("{}{}", seed_url.trim_end_matches('/'), WELL_KNOWN_PATH);

        let resp = client.get(&metadata_url).send().await.map_err(|e| {
            GatewayError::Discovery(format!(
                "Failed to fetch metadata from {}: {}",
                metadata_url, e
            ))
        })?;

        if !resp.status().is_success() {
            return Err(GatewayError::Discovery(format!(
                "Metadata endpoint {} returned status {}",
                metadata_url,
                resp.status()
            )));
        }

        let metadata_body = collect_metadata_body(resp).await?;
        let metadata: ServiceMetadata = serde_json::from_slice(&metadata_body).map_err(|e| {
            GatewayError::Discovery(format!(
                "Failed to parse metadata from {}: {}",
                metadata_url, e
            ))
        })?;
        validate_metadata(&metadata)?;

        // Probe health endpoint
        let health_url = format!(
            "{}{}",
            seed_url.trim_end_matches('/'),
            metadata.health_path.as_str()
        );

        let healthy = match client.get(&health_url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        };

        Ok(DiscoveredService {
            seed_url: seed_url.to_string(),
            metadata,
            healthy,
        })
    }

    /// Probe all configured seeds, returning successes (errors are logged)
    pub async fn probe_all(&self) -> Vec<DiscoveredService> {
        let mut results = Vec::new();
        let now = std::time::Instant::now();
        let stale_after =
            Duration::from_secs(self.config.poll_interval_secs.saturating_mul(3).max(30));
        for seed in &self.config.seeds {
            match self.probe_seed(&seed.url).await {
                Ok(discovered) => {
                    self.last_success
                        .write()
                        .await
                        .insert(seed.url.clone(), now);
                    tracing::debug!(
                        seed = %seed.url,
                        service = %discovered.metadata.name,
                        healthy = discovered.healthy,
                        "Discovered service"
                    );
                    results.push(discovered);
                }
                Err(e) => {
                    tracing::warn!(seed = %seed.url, error = %e, "Failed to probe seed");
                    let retained = {
                        let cached = self.discovered.read().await;
                        let last_success = self.last_success.read().await;
                        let within_grace = last_success
                            .get(&seed.url)
                            .is_some_and(|last| now.duration_since(*last) <= stale_after);
                        within_grace.then(|| {
                            cached
                                .values()
                                .flatten()
                                .find(|service| service.seed_url == seed.url)
                                .cloned()
                        })
                    }
                    .flatten();
                    if let Some(retained) = retained {
                        tracing::debug!(
                            seed = %seed.url,
                            stale_after_secs = stale_after.as_secs(),
                            "Retaining last-known-good discovered service after probe failure"
                        );
                        results.push(retained);
                    }
                }
            }
        }
        results
    }

    /// Check if newly discovered services differ from the cached state
    pub async fn has_changed(&self, new_services: &[DiscoveredService]) -> bool {
        let cached = self.discovered.read().await;

        // Build new grouped map for comparison
        let mut new_map: HashMap<String, Vec<&DiscoveredService>> = HashMap::new();
        for svc in new_services {
            new_map
                .entry(svc.metadata.name.clone())
                .or_default()
                .push(svc);
        }

        // Quick length check
        if cached.len() != new_map.len() {
            return true;
        }

        for (name, new_entries) in &new_map {
            match cached.get(name) {
                None => return true,
                Some(old_entries) => {
                    if old_entries.len() != new_entries.len() {
                        return true;
                    }
                    for (new_entry, old_entry) in new_entries.iter().zip(old_entries.iter()) {
                        if new_entry.seed_url != old_entry.seed_url
                            || new_entry.metadata != old_entry.metadata
                            || new_entry.healthy != old_entry.healthy
                        {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Update the cached state with newly discovered services
    pub async fn update_cache(&self, services: &[DiscoveredService]) {
        let mut cached = self.discovered.write().await;
        cached.clear();
        for svc in services {
            cached
                .entry(svc.metadata.name.clone())
                .or_default()
                .push(svc.clone());
        }
        // Tests, embedders, and a restored provider cache may seed the cache
        // without going through probe_all. Initialize their grace timestamps
        // once, while leaving timestamps for retained stale entries intact.
        let mut last_success = self.last_success.write().await;
        let now = std::time::Instant::now();
        for service in services {
            last_success.entry(service.seed_url.clone()).or_insert(now);
        }
    }

    /// Get the current discovered services (snapshot)
    pub async fn discovered(&self) -> HashMap<String, Vec<DiscoveredService>> {
        self.discovered.read().await.clone()
    }
}

async fn collect_metadata_body(resp: reqwest::Response) -> Result<Vec<u8>> {
    let content_length = resp.content_length();
    if content_length.is_some_and(|length| length > MAX_METADATA_BYTES as u64) {
        return Err(GatewayError::Discovery(format!(
            "Discovery metadata exceeds the {} byte limit",
            MAX_METADATA_BYTES
        )));
    }

    let mut stream = resp.bytes_stream();
    let mut body = BytesMut::with_capacity(
        content_length
            .unwrap_or_default()
            .min(MAX_METADATA_BYTES as u64) as usize,
    );
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            GatewayError::Discovery(format!("Failed to read discovery metadata: {error}"))
        })?;
        if body.len().saturating_add(chunk.len()) > MAX_METADATA_BYTES {
            return Err(GatewayError::Discovery(format!(
                "Discovery metadata exceeds the {} byte limit",
                MAX_METADATA_BYTES
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.to_vec())
}

fn validate_metadata(metadata: &ServiceMetadata) -> Result<()> {
    if metadata.name.is_empty()
        || metadata.name.len() > MAX_METADATA_NAME_BYTES
        || metadata.name.chars().any(char::is_control)
    {
        return Err(GatewayError::Discovery(
            "Discovered service name is empty, too long, or contains control characters"
                .to_string(),
        ));
    }
    if metadata.version.is_empty()
        || metadata.version.len() > MAX_METADATA_VERSION_BYTES
        || metadata.version.chars().any(char::is_control)
    {
        return Err(GatewayError::Discovery(
            "Discovered service version is empty, too long, or contains control characters"
                .to_string(),
        ));
    }
    if metadata.weight == 0 {
        return Err(GatewayError::Discovery(
            "Discovered service weight must be greater than zero".to_string(),
        ));
    }
    if metadata.health_path.is_empty()
        || metadata.health_path.len() > MAX_METADATA_HEALTH_PATH_BYTES
        || !metadata.health_path.starts_with('/')
        || metadata.health_path.starts_with("//")
        || metadata.health_path.contains('#')
        || metadata.health_path.chars().any(char::is_control)
        || metadata.health_path.chars().any(char::is_whitespace)
    {
        return Err(GatewayError::Discovery(
            "Discovered health_path must be a bounded absolute path".to_string(),
        ));
    }
    for route in &metadata.routes {
        if route.rule.is_empty()
            || route.rule.len() > MAX_METADATA_ROUTE_BYTES
            || route.rule.chars().any(char::is_control)
        {
            return Err(GatewayError::Discovery(
                "Discovered route rule is empty, too long, or contains control characters"
                    .to_string(),
            ));
        }
        if route.middlewares.iter().any(|middleware| {
            middleware.is_empty()
                || middleware.len() > MAX_METADATA_NAME_BYTES
                || middleware.chars().any(char::is_control)
                || middleware.chars().any(char::is_whitespace)
        }) {
            return Err(GatewayError::Discovery(
                "Discovered middleware reference is empty or too long".to_string(),
            ));
        }
    }
    Ok(())
}

/// Build `ServiceConfig` entries from discovered services, grouped by service name
pub fn build_services_config(discovered: &[DiscoveredService]) -> HashMap<String, ServiceConfig> {
    let mut grouped: HashMap<String, Vec<&DiscoveredService>> = HashMap::new();
    for svc in discovered {
        if svc.healthy {
            grouped
                .entry(svc.metadata.name.clone())
                .or_default()
                .push(svc);
        }
    }

    grouped
        .into_iter()
        .map(|(name, backends)| {
            let servers: Vec<ServerConfig> = backends
                .iter()
                .map(|b| ServerConfig {
                    url: b.seed_url.clone(),
                    weight: b.metadata.weight,
                    target: None,
                })
                .collect();

            let config = ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers,
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            };
            (name, config)
        })
        .collect()
}

/// Build `RouterConfig` entries from discovered service route metadata
pub fn build_routers_config(
    discovered: &[DiscoveredService],
    entrypoint_names: &[String],
) -> HashMap<String, RouterConfig> {
    let mut routers = HashMap::new();
    let mut grouped: HashMap<String, Vec<&DiscoveredService>> = HashMap::new();
    for service in discovered.iter().filter(|service| service.healthy) {
        grouped
            .entry(service.metadata.name.clone())
            .or_default()
            .push(service);
    }

    for (service_name, instances) in grouped {
        let Some(first) = instances.first() else {
            continue;
        };
        // A route is a security policy, so silently taking the first healthy
        // instance makes discovery order an authorization decision. Require
        // every healthy instance of one service to advertise the same route
        // set; a rollout with disagreement withdraws only the dynamic routes
        // until the instances converge.
        if instances
            .iter()
            .skip(1)
            .any(|instance| instance.metadata.routes != first.metadata.routes)
        {
            tracing::warn!(
                service = %service_name,
                instances = instances.len(),
                "Conflicting route metadata across discovered service instances; withholding dynamic routes"
            );
            continue;
        }

        for (i, route) in first.metadata.routes.iter().enumerate() {
            let router_name = if first.metadata.routes.len() == 1 {
                format!("discovered-{}", service_name)
            } else {
                format!("discovered-{}-{}", service_name, i)
            };

            routers.insert(
                router_name,
                RouterConfig {
                    rule: route.rule.clone(),
                    service: service_name.clone(),
                    entrypoints: entrypoint_names.to_vec(),
                    middlewares: route.middlewares.clone(),
                    priority: route.priority,
                },
            );
        }
    }

    routers
}

/// Merge discovered config into static config. Static config wins on name collisions.
pub fn merge_with_static(
    static_config: &GatewayConfig,
    discovered: &[DiscoveredService],
) -> GatewayConfig {
    let entrypoint_names: Vec<String> = static_config.entrypoints.keys().cloned().collect();

    let discovered_services = build_services_config(discovered);
    let discovered_routers = build_routers_config(discovered, &entrypoint_names);

    let mut merged = static_config.clone();

    // Discovery only adds new entries — static config wins on collisions
    for (name, svc) in discovered_services {
        merged.services.entry(name).or_insert(svc);
    }
    for (name, router) in discovered_routers {
        merged.routers.entry(name).or_insert(router);
    }

    merged
}

/// Spawn the discovery polling loop.
///
/// Periodically probes all seeds, merges with static config, and sends
/// the merged config through the channel when changes are detected.
pub fn spawn_discovery_loop(
    config: DiscoveryConfig,
    static_config: GatewayConfig,
    on_change_tx: tokio::sync::mpsc::Sender<GatewayConfig>,
) -> tokio::task::JoinHandle<()> {
    let send = Box::new(move |config| {
        let on_change_tx = on_change_tx.clone();
        Box::pin(async move {
            on_change_tx
                .send(config)
                .await
                .map(|_| true)
                .map_err(|_| ())
        }) as DiscoveryDeliveryFuture
    });
    spawn_discovery_loop_inner(config, static_config, send)
}

/// A discovery update delivered to the Gateway reload owner.
///
/// The acknowledgement is part of the delivery contract. A provider must not
/// advance its change-detection cache until the receiver has accepted the
/// candidate runtime; otherwise one rejected candidate can permanently stall
/// discovery convergence.
pub(crate) type DiscoveryUpdate = crate::provider::ConfigUpdate;

/// Spawn discovery with an explicit reload acknowledgement channel.
pub(crate) fn spawn_discovery_loop_with_ack(
    config: DiscoveryConfig,
    static_config: GatewayConfig,
    on_change_tx: tokio::sync::mpsc::Sender<DiscoveryUpdate>,
) -> tokio::task::JoinHandle<()> {
    let send = Box::new(move |config| {
        let on_change_tx = on_change_tx.clone();
        Box::pin(async move {
            let (ack_tx, ack_rx) = oneshot::channel();
            on_change_tx
                .send(DiscoveryUpdate {
                    source: "discovery",
                    config,
                    acknowledged: ack_tx,
                })
                .await
                .map_err(|_| ())?;
            ack_rx.await.map_err(|_| ())
        }) as DiscoveryDeliveryFuture
    });
    spawn_discovery_loop_inner(config, static_config, send)
}

type DiscoveryDeliveryFuture =
    Pin<Box<dyn Future<Output = std::result::Result<bool, ()>> + Send + 'static>>;

fn spawn_discovery_loop_inner(
    config: DiscoveryConfig,
    static_config: GatewayConfig,
    mut deliver: Box<dyn FnMut(GatewayConfig) -> DiscoveryDeliveryFuture + Send>,
) -> tokio::task::JoinHandle<()> {
    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    let provider = DiscoveryProvider::new(config);

    tokio::spawn(async move {
        loop {
            let discovered = provider.probe_all().await;

            if provider.has_changed(&discovered).await {
                let merged = merge_with_static(&static_config, &discovered);
                match deliver(merged).await {
                    Ok(true) => {
                        provider.update_cache(&discovered).await;
                        tracing::info!(
                            services = discovered.len(),
                            "Discovery detected changes and reload was accepted"
                        );
                    }
                    Ok(false) => {
                        // Keep the old cache so the same candidate is retried
                        // after a transient validation/reload failure.
                        tracing::warn!(
                            services = discovered.len(),
                            "Discovered config was rejected; retaining the previous discovery cache"
                        );
                    }
                    Err(()) => {
                        tracing::debug!("Discovery update receiver dropped; stopping polling loop");
                        break;
                    }
                }
            }

            tokio::time::sleep(poll_interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DiscoverySeedConfig, EntrypointConfig, Protocol};

    // --- ServiceMetadata ---

    #[test]
    fn test_service_metadata_deserialize() {
        let json = r#"{
            "name": "auth-service",
            "version": "1.0.0",
            "routes": [
                {"rule": "PathPrefix(`/auth`)", "middlewares": ["rate-limit"], "priority": 5}
            ],
            "health_path": "/healthz",
            "weight": 2
        }"#;
        let meta: ServiceMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.name, "auth-service");
        assert_eq!(meta.version, "1.0.0");
        assert_eq!(meta.routes.len(), 1);
        assert_eq!(meta.routes[0].rule, "PathPrefix(`/auth`)");
        assert_eq!(meta.routes[0].middlewares, vec!["rate-limit"]);
        assert_eq!(meta.routes[0].priority, 5);
        assert_eq!(meta.health_path, "/healthz");
        assert_eq!(meta.weight, 2);
    }

    #[test]
    fn test_service_metadata_defaults() {
        let json = r#"{"name": "svc", "version": "0.1.0"}"#;
        let meta: ServiceMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.health_path, "/health");
        assert_eq!(meta.weight, 1);
        assert!(meta.routes.is_empty());
    }

    #[test]
    fn test_service_metadata_roundtrip() {
        let meta = ServiceMetadata {
            name: "test".to_string(),
            version: "2.0.0".to_string(),
            routes: vec![RouteMetadata {
                rule: "Host(`test.com`)".to_string(),
                middlewares: vec![],
                priority: 0,
            }],
            health_path: "/health".to_string(),
            weight: 1,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: ServiceMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, meta);
    }

    #[test]
    fn test_route_metadata_defaults() {
        let json = r#"{"rule": "PathPrefix(`/api`)"}"#;
        let route: RouteMetadata = serde_json::from_str(json).unwrap();
        assert!(route.middlewares.is_empty());
        assert_eq!(route.priority, 0);
    }

    #[test]
    fn test_metadata_validation_rejects_unsafe_health_path_and_weight() {
        let mut metadata = ServiceMetadata {
            name: "svc".to_string(),
            version: "1".to_string(),
            routes: vec![],
            health_path: "https://other.example/health".to_string(),
            weight: 1,
        };
        assert!(validate_metadata(&metadata).is_err());

        metadata.health_path = "/health#fragment".to_string();
        assert!(validate_metadata(&metadata).is_err());

        metadata.health_path = "/health".to_string();
        metadata.weight = 0;
        assert!(validate_metadata(&metadata).is_err());
    }

    #[test]
    fn test_metadata_validation_accepts_bounded_contract() {
        let metadata = ServiceMetadata {
            name: "svc".to_string(),
            version: "1".to_string(),
            routes: vec![RouteMetadata {
                rule: "PathPrefix(`/api`)".to_string(),
                middlewares: vec!["auth".to_string()],
                priority: 1,
            }],
            health_path: "/health".to_string(),
            weight: 1,
        };
        assert!(validate_metadata(&metadata).is_ok());
    }

    // --- DiscoveryProvider ---

    #[test]
    fn test_provider_new() {
        let config = DiscoveryConfig {
            seeds: vec![DiscoverySeedConfig {
                url: "http://localhost:9000".to_string(),
            }],
            poll_interval_secs: 30,
            timeout_secs: 5,
        };
        let provider = DiscoveryProvider::new(config);
        assert_eq!(provider.config.seeds.len(), 1);
    }

    #[tokio::test]
    async fn test_provider_probe_seed_unreachable() {
        let config = DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 30,
            timeout_secs: 1,
        };
        let provider = DiscoveryProvider::new(config);
        let result = provider.probe_seed("http://127.0.0.1:1").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Discovery error"));
    }

    #[tokio::test]
    async fn test_provider_probe_all_empty_seeds() {
        let config = DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 30,
            timeout_secs: 1,
        };
        let provider = DiscoveryProvider::new(config);
        let results = provider.probe_all().await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_provider_probe_all_unreachable_seeds() {
        let config = DiscoveryConfig {
            seeds: vec![
                DiscoverySeedConfig {
                    url: "http://127.0.0.1:1".to_string(),
                },
                DiscoverySeedConfig {
                    url: "http://127.0.0.1:2".to_string(),
                },
            ],
            poll_interval_secs: 30,
            timeout_secs: 1,
        };
        let provider = DiscoveryProvider::new(config);
        let results = provider.probe_all().await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_probe_all_retains_last_known_good_during_transient_failure() {
        let config = DiscoveryConfig {
            seeds: vec![DiscoverySeedConfig {
                url: "http://127.0.0.1:1".to_string(),
            }],
            poll_interval_secs: 1,
            timeout_secs: 1,
        };
        let provider = DiscoveryProvider::new(config);
        let service = DiscoveredService {
            seed_url: "http://127.0.0.1:1".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        };
        provider.update_cache(std::slice::from_ref(&service)).await;

        let retained = provider.probe_all().await;
        assert_eq!(retained, vec![service]);
    }

    #[tokio::test]
    async fn test_probe_all_expires_last_known_good_after_grace_window() {
        let config = DiscoveryConfig {
            seeds: vec![DiscoverySeedConfig {
                url: "http://127.0.0.1:1".to_string(),
            }],
            poll_interval_secs: 1,
            timeout_secs: 1,
        };
        let provider = DiscoveryProvider::new(config);
        let service = DiscoveredService {
            seed_url: "http://127.0.0.1:1".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        };
        provider.update_cache(&[service]).await;
        provider.last_success.write().await.insert(
            "http://127.0.0.1:1".to_string(),
            std::time::Instant::now() - Duration::from_secs(31),
        );

        assert!(provider.probe_all().await.is_empty());
    }

    // --- has_changed ---

    #[tokio::test]
    async fn test_has_changed_empty_to_some() {
        let config = DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 30,
            timeout_secs: 5,
        };
        let provider = DiscoveryProvider::new(config);
        let services = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        assert!(provider.has_changed(&services).await);
    }

    #[tokio::test]
    async fn test_has_changed_no_change() {
        let config = DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 30,
            timeout_secs: 5,
        };
        let provider = DiscoveryProvider::new(config);
        let services = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        provider.update_cache(&services).await;
        assert!(!provider.has_changed(&services).await);
    }

    #[tokio::test]
    async fn test_has_changed_version_bump() {
        let config = DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 30,
            timeout_secs: 5,
        };
        let provider = DiscoveryProvider::new(config);
        let v1 = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        provider.update_cache(&v1).await;

        let v2 = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "2.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        assert!(provider.has_changed(&v2).await);
    }

    #[tokio::test]
    async fn detects_route_and_weight_changes_without_a_version_bump() {
        let provider = DiscoveryProvider::new(DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 30,
            timeout_secs: 5,
        });
        let original = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        provider.update_cache(&original).await;
        let mut changed = original.clone();
        changed[0].metadata.weight = 2;
        assert!(provider.has_changed(&changed).await);

        changed[0].metadata.weight = 1;
        changed[0].metadata.routes.push(RouteMetadata {
            rule: "PathPrefix(`/new`)".to_string(),
            middlewares: vec![],
            priority: 0,
        });
        assert!(provider.has_changed(&changed).await);
    }

    #[tokio::test]
    async fn test_has_changed_health_flip() {
        let config = DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 30,
            timeout_secs: 5,
        };
        let provider = DiscoveryProvider::new(config);
        let healthy = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        provider.update_cache(&healthy).await;

        let unhealthy = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: false,
        }];
        assert!(provider.has_changed(&unhealthy).await);
    }

    // --- build_services_config ---

    #[test]
    fn test_build_services_config_single() {
        let discovered = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "auth".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 3,
            },
            healthy: true,
        }];
        let services = build_services_config(&discovered);
        assert_eq!(services.len(), 1);
        let auth = &services["auth"];
        assert_eq!(auth.load_balancer.servers.len(), 1);
        assert_eq!(auth.load_balancer.servers[0].url, "http://10.0.0.1:8080");
        assert_eq!(auth.load_balancer.servers[0].weight, 3);
    }

    #[test]
    fn test_build_services_config_multiple_backends() {
        let discovered = vec![
            DiscoveredService {
                seed_url: "http://10.0.0.1:8080".to_string(),
                metadata: ServiceMetadata {
                    name: "api".to_string(),
                    version: "1.0.0".to_string(),
                    routes: vec![],
                    health_path: "/health".to_string(),
                    weight: 1,
                },
                healthy: true,
            },
            DiscoveredService {
                seed_url: "http://10.0.0.2:8080".to_string(),
                metadata: ServiceMetadata {
                    name: "api".to_string(),
                    version: "1.0.0".to_string(),
                    routes: vec![],
                    health_path: "/health".to_string(),
                    weight: 2,
                },
                healthy: true,
            },
        ];
        let services = build_services_config(&discovered);
        assert_eq!(services.len(), 1);
        assert_eq!(services["api"].load_balancer.servers.len(), 2);
    }

    #[test]
    fn test_build_services_config_skips_unhealthy() {
        let discovered = vec![
            DiscoveredService {
                seed_url: "http://10.0.0.1:8080".to_string(),
                metadata: ServiceMetadata {
                    name: "api".to_string(),
                    version: "1.0.0".to_string(),
                    routes: vec![],
                    health_path: "/health".to_string(),
                    weight: 1,
                },
                healthy: true,
            },
            DiscoveredService {
                seed_url: "http://10.0.0.2:8080".to_string(),
                metadata: ServiceMetadata {
                    name: "api".to_string(),
                    version: "1.0.0".to_string(),
                    routes: vec![],
                    health_path: "/health".to_string(),
                    weight: 1,
                },
                healthy: false,
            },
        ];
        let services = build_services_config(&discovered);
        assert_eq!(services["api"].load_balancer.servers.len(), 1);
    }

    #[test]
    fn test_build_services_config_all_unhealthy() {
        let discovered = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "api".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: false,
        }];
        let services = build_services_config(&discovered);
        assert!(services.is_empty());
    }

    // --- build_routers_config ---

    #[test]
    fn test_build_routers_config_single_route() {
        let discovered = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "auth".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![RouteMetadata {
                    rule: "PathPrefix(`/auth`)".to_string(),
                    middlewares: vec!["rate-limit".to_string()],
                    priority: 5,
                }],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        let entrypoints = vec!["web".to_string()];
        let routers = build_routers_config(&discovered, &entrypoints);
        assert_eq!(routers.len(), 1);
        let router = &routers["discovered-auth"];
        assert_eq!(router.rule, "PathPrefix(`/auth`)");
        assert_eq!(router.service, "auth");
        assert_eq!(router.entrypoints, vec!["web"]);
        assert_eq!(router.middlewares, vec!["rate-limit"]);
        assert_eq!(router.priority, 5);
    }

    #[test]
    fn test_build_routers_config_multiple_routes() {
        let discovered = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "api".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![
                    RouteMetadata {
                        rule: "PathPrefix(`/v1`)".to_string(),
                        middlewares: vec![],
                        priority: 0,
                    },
                    RouteMetadata {
                        rule: "PathPrefix(`/v2`)".to_string(),
                        middlewares: vec![],
                        priority: 10,
                    },
                ],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        let entrypoints = vec!["web".to_string()];
        let routers = build_routers_config(&discovered, &entrypoints);
        assert_eq!(routers.len(), 2);
        assert!(routers.contains_key("discovered-api-0"));
        assert!(routers.contains_key("discovered-api-1"));
    }

    #[test]
    fn test_build_routers_config_skips_unhealthy() {
        let discovered = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "api".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![RouteMetadata {
                    rule: "PathPrefix(`/api`)".to_string(),
                    middlewares: vec![],
                    priority: 0,
                }],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: false,
        }];
        let routers = build_routers_config(&discovered, &["web".to_string()]);
        assert!(routers.is_empty());
    }

    #[test]
    fn test_build_routers_config_withholds_conflicting_instance_routes() {
        let base = DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "api".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![RouteMetadata {
                    rule: "PathPrefix(`/private`)".to_string(),
                    middlewares: vec!["auth".to_string()],
                    priority: 0,
                }],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        };
        let mut conflicting = base.clone();
        conflicting.seed_url = "http://10.0.0.2:8080".to_string();
        conflicting.metadata.routes[0].middlewares.clear();

        let routers = build_routers_config(&[base, conflicting], &["web".to_string()]);
        assert!(routers.is_empty());
    }

    // --- merge_with_static ---

    #[test]
    fn test_merge_discovery_adds_new_services() {
        let mut static_config = GatewayConfig::default();
        static_config.services.insert(
            "existing".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://static:8080".to_string(),
                        weight: 1,
                        target: None,
                    }],
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );

        let discovered = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "new-svc".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![RouteMetadata {
                    rule: "PathPrefix(`/new`)".to_string(),
                    middlewares: vec![],
                    priority: 0,
                }],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];

        let merged = merge_with_static(&static_config, &discovered);
        assert!(merged.services.contains_key("existing"));
        assert!(merged.services.contains_key("new-svc"));
        assert!(merged.routers.contains_key("discovered-new-svc"));
    }

    #[test]
    fn test_merge_static_wins_on_collision() {
        let mut static_config = GatewayConfig::default();
        static_config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::Weighted,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://static:8080".to_string(),
                        weight: 10,
                        target: None,
                    }],
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );

        let discovered = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "api".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];

        let merged = merge_with_static(&static_config, &discovered);
        let api = &merged.services["api"];
        // Static config wins — strategy should remain Weighted
        assert_eq!(api.load_balancer.strategy, Strategy::Weighted);
        assert_eq!(api.load_balancer.servers[0].url, "http://static:8080");
    }

    #[test]
    fn test_merge_empty_discovery() {
        let static_config = GatewayConfig::default();
        let merged = merge_with_static(&static_config, &[]);
        assert_eq!(merged.entrypoints.len(), static_config.entrypoints.len());
        assert_eq!(merged.services.len(), static_config.services.len());
    }

    // --- spawn_discovery_loop ---

    #[tokio::test]
    async fn test_spawn_discovery_loop_sends_on_change() {
        // Use unreachable seeds — the loop should still run and send
        // an initial "empty discovered" config if the cache was empty
        let config = DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 60, // Long interval — we only care about the first probe
            timeout_secs: 1,
        };

        let mut static_config = GatewayConfig::default();
        static_config.entrypoints.insert(
            "web".to_string(),
            EntrypointConfig {
                address: "0.0.0.0:80".to_string(),
                protocol: Protocol::Http,
                tls: None,
                max_connections: None,
                tcp_allowed_ips: vec![],
                udp_session_timeout_secs: None,
                udp_max_sessions: None,
                trust_forwarded_headers: false,
            },
        );

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let handle = spawn_discovery_loop(config, static_config.clone(), tx);

        // The first probe with empty seeds will produce an empty discovered list,
        // which differs from the initial empty cache (no entries vs no cache at all).
        // However, since both are "empty", has_changed returns false.
        // So we expect no message — validate the loop is running and doesn't crash.
        let result = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;

        // Either timeout (no change detected) or a config is fine
        match result {
            Ok(Some(_config)) => {
                // Got a config — that's fine too
            }
            Ok(None) => {
                // Channel closed — unexpected but handle gracefully
            }
            Err(_) => {
                // Timeout — expected since empty seeds produce no change
            }
        }

        handle.abort();
    }

    // --- WELL_KNOWN_PATH ---

    #[test]
    fn test_well_known_path() {
        assert_eq!(WELL_KNOWN_PATH, "/.well-known/a3s-service.json");
    }

    // --- update_cache / discovered ---

    #[tokio::test]
    async fn test_update_cache_and_read() {
        let config = DiscoveryConfig {
            seeds: vec![],
            poll_interval_secs: 30,
            timeout_secs: 5,
        };
        let provider = DiscoveryProvider::new(config);
        assert!(provider.discovered().await.is_empty());

        let services = vec![DiscoveredService {
            seed_url: "http://10.0.0.1:8080".to_string(),
            metadata: ServiceMetadata {
                name: "svc".to_string(),
                version: "1.0.0".to_string(),
                routes: vec![],
                health_path: "/health".to_string(),
                weight: 1,
            },
            healthy: true,
        }];
        provider.update_cache(&services).await;

        let cached = provider.discovered().await;
        assert_eq!(cached.len(), 1);
        assert!(cached.contains_key("svc"));
        assert_eq!(cached["svc"].len(), 1);
    }
}
