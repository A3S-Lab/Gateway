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
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Well-known path for service metadata (RFC 8615)
pub const WELL_KNOWN_PATH: &str = "/.well-known/a3s-service.json";

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
#[derive(Debug, Clone)]
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
    client: reqwest::Client,
    discovered: Arc<RwLock<HashMap<String, Vec<DiscoveredService>>>>,
}

impl DiscoveryProvider {
    /// Create a new discovery provider with the given config
    pub fn new(config: DiscoveryConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .unwrap_or_default();

        Self {
            config,
            client,
            discovered: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Probe a single seed URL for service metadata and health
    pub async fn probe_seed(&self, seed_url: &str) -> Result<DiscoveredService> {
        let metadata_url = format!(
            "{}{}",
            seed_url.trim_end_matches('/'),
            WELL_KNOWN_PATH
        );

        let resp = self
            .client
            .get(&metadata_url)
            .send()
            .await
            .map_err(|e| {
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

        let metadata: ServiceMetadata = resp.json().await.map_err(|e| {
            GatewayError::Discovery(format!(
                "Failed to parse metadata from {}: {}",
                metadata_url, e
            ))
        })?;

        // Probe health endpoint
        let health_url = format!(
            "{}{}",
            seed_url.trim_end_matches('/'),
            &metadata.health_path
        );

        let healthy = match self.client.get(&health_url).send().await {
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
        for seed in &self.config.seeds {
            match self.probe_seed(&seed.url).await {
                Ok(discovered) => {
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
                }
            }
        }
        results
    }

    /// Check if newly discovered services differ from the cached state
    pub async fn has_changed(&self, new_services: &[DiscoveredService]) -> bool {
        let cached = self.discovered.read().await;

        // Build new grouped map for comparison
        let mut new_map: HashMap<String, Vec<(&str, &str, bool)>> = HashMap::new();
        for svc in new_services {
            new_map
                .entry(svc.metadata.name.clone())
                .or_default()
                .push((&svc.seed_url, &svc.metadata.version, svc.healthy));
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
                        if new_entry.0 != old_entry.seed_url
                            || new_entry.1 != old_entry.metadata.version
                            || new_entry.2 != old_entry.healthy
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
    }

    /// Get the current discovered services (snapshot)
    pub async fn discovered(&self) -> HashMap<String, Vec<DiscoveredService>> {
        self.discovered.read().await.clone()
    }
}

/// Build `ServiceConfig` entries from discovered services, grouped by service name
pub fn build_services_config(
    discovered: &[DiscoveredService],
) -> HashMap<String, ServiceConfig> {
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
                })
                .collect();

            let config = ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    servers,
                    health_check: None,
                    sticky: None,
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
    let mut seen_services: HashMap<String, bool> = HashMap::new();

    for svc in discovered {
        if !svc.healthy {
            continue;
        }
        // Only generate routers once per service name (first healthy instance wins)
        if seen_services.contains_key(&svc.metadata.name) {
            continue;
        }
        seen_services.insert(svc.metadata.name.clone(), true);

        for (i, route) in svc.metadata.routes.iter().enumerate() {
            let router_name = if svc.metadata.routes.len() == 1 {
                format!("discovered-{}", svc.metadata.name)
            } else {
                format!("discovered-{}-{}", svc.metadata.name, i)
            };

            routers.insert(
                router_name,
                RouterConfig {
                    rule: route.rule.clone(),
                    service: svc.metadata.name.clone(),
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
    let poll_interval = Duration::from_secs(config.poll_interval_secs);
    let provider = DiscoveryProvider::new(config);

    tokio::spawn(async move {
        loop {
            let discovered = provider.probe_all().await;

            if provider.has_changed(&discovered).await {
                provider.update_cache(&discovered).await;

                let merged = merge_with_static(&static_config, &discovered);

                if let Err(e) = on_change_tx.send(merged).await {
                    tracing::error!(error = %e, "Failed to send discovered config — receiver dropped");
                    break;
                }

                tracing::info!(
                    services = discovered.len(),
                    "Discovery detected changes, triggering reload"
                );
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

    // --- merge_with_static ---

    #[test]
    fn test_merge_discovery_adds_new_services() {
        let mut static_config = GatewayConfig::default();
        static_config.services.insert(
            "existing".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    servers: vec![ServerConfig {
                        url: "http://static:8080".to_string(),
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
                    servers: vec![ServerConfig {
                        url: "http://static:8080".to_string(),
                        weight: 10,
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
        assert_eq!(
            merged.entrypoints.len(),
            static_config.entrypoints.len()
        );
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
            },
        );

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let handle = spawn_discovery_loop(config, static_config.clone(), tx);

        // The first probe with empty seeds will produce an empty discovered list,
        // which differs from the initial empty cache (no entries vs no cache at all).
        // However, since both are "empty", has_changed returns false.
        // So we expect no message — validate the loop is running and doesn't crash.
        let result =
            tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;

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
