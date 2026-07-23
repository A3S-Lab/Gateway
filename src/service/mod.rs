//! Service layer — load balancing and health checking
//!
//! Manages upstream backend pools with configurable load balancing
//! strategies and active health checking.

pub mod failover;
mod health_check;
mod load_balancer;
pub mod mirror;
pub mod passive_health;
pub mod sticky;

pub use failover::FailoverSelector;
pub use health_check::HealthChecker;
pub(crate) use load_balancer::BackendConnectionGuard;
pub use load_balancer::{Backend, LoadBalancer, ServiceTimeouts};
pub use mirror::TrafficMirror;

use crate::config::ServiceConfig;
use crate::error::{GatewayError, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// Service registry — holds all configured upstream services
pub struct ServiceRegistry {
    services: HashMap<String, Arc<LoadBalancer>>,
}

impl ServiceRegistry {
    /// Build a service registry from configuration
    pub fn from_config(configs: &HashMap<String, ServiceConfig>) -> Result<Self> {
        let mut services = HashMap::new();

        for (name, config) in configs {
            if config.load_balancer.servers.is_empty() && config.revisions.is_empty() {
                return Err(GatewayError::Config(format!(
                    "Service '{}' has no servers",
                    name
                )));
            }

            let request_timeout =
                crate::config::parse_service_duration(&config.load_balancer.request_timeout)
                    .map_err(|e| {
                        GatewayError::Config(format!(
                            "Invalid request_timeout for service '{}': {}",
                            name, e
                        ))
                    })?;
            let stream_idle_timeout =
                crate::config::parse_service_duration(&config.load_balancer.stream_idle_timeout)
                    .map_err(|e| {
                        GatewayError::Config(format!(
                            "Invalid stream_idle_timeout for service '{}': {}",
                            name, e
                        ))
                    })?;
            let stream_total_timeout =
                crate::config::parse_service_duration(&config.load_balancer.stream_total_timeout)
                    .map_err(|e| {
                    GatewayError::Config(format!(
                        "Invalid stream_total_timeout for service '{}': {}",
                        name, e
                    ))
                })?;

            let lb = LoadBalancer::with_timeouts(
                name.clone(),
                config.load_balancer.strategy.clone(),
                &config.load_balancer.servers,
                config
                    .load_balancer
                    .sticky
                    .as_ref()
                    .map(|s| s.cookie.clone()),
                request_timeout,
                stream_idle_timeout,
                stream_total_timeout,
            );

            services.insert(name.clone(), Arc::new(lb));
        }

        Ok(Self { services })
    }

    /// Get a service by name
    pub fn get(&self, name: &str) -> Option<Arc<LoadBalancer>> {
        self.services.get(name).cloned()
    }

    /// Number of registered services
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether the registry is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Iterate over all services (name → load balancer)
    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Arc<LoadBalancer>)> {
        self.services.iter()
    }

    /// Start health checkers for all services that have health check config
    pub async fn start_health_checks(&self, configs: &HashMap<String, ServiceConfig>) {
        for (name, config) in configs {
            if let Some(hc_config) = &config.load_balancer.health_check {
                if let Some(lb) = self.services.get(name) {
                    let checker = HealthChecker::new(
                        lb.clone(),
                        hc_config.path.clone(),
                        &hc_config.interval,
                        &hc_config.timeout,
                        hc_config.unhealthy_threshold,
                        hc_config.healthy_threshold,
                    );
                    tokio::spawn(async move {
                        checker.run().await;
                    });
                    tracing::info!(service = name, "Started health checker");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LoadBalancerConfig, RevisionConfig, ServerConfig, Strategy};

    fn make_service_config(urls: Vec<&str>) -> ServiceConfig {
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers: urls
                    .into_iter()
                    .map(|url| ServerConfig {
                        url: url.to_string(),
                        weight: 1,
                    })
                    .collect(),
                health_check: None,
                sticky: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        }
    }

    #[test]
    fn test_registry_from_config() {
        let mut configs = HashMap::new();
        configs.insert(
            "backend".to_string(),
            make_service_config(vec!["http://127.0.0.1:8001"]),
        );
        let registry = ServiceRegistry::from_config(&configs).unwrap();
        assert_eq!(registry.len(), 1);
        assert!(registry.get("backend").is_some());
        assert!(registry.get("nonexistent").is_none());
    }

    #[test]
    fn test_registry_applies_request_timeout() {
        let mut config = make_service_config(vec!["http://127.0.0.1:8001"]);
        config.load_balancer.request_timeout = "250ms".to_string();
        config.load_balancer.stream_idle_timeout = "2s".to_string();
        config.load_balancer.stream_total_timeout = "3m".to_string();
        let mut configs = HashMap::new();
        configs.insert("backend".to_string(), config);

        let registry = ServiceRegistry::from_config(&configs).unwrap();
        let lb = registry.get("backend").unwrap();
        assert_eq!(lb.request_timeout(), std::time::Duration::from_millis(250));
        assert_eq!(lb.stream_idle_timeout(), std::time::Duration::from_secs(2));
        assert_eq!(
            lb.stream_total_timeout(),
            std::time::Duration::from_secs(180)
        );
    }

    #[test]
    fn test_registry_empty_servers() {
        let mut configs = HashMap::new();
        configs.insert("bad".to_string(), make_service_config(vec![]));
        let result = ServiceRegistry::from_config(&configs);
        assert!(result.is_err());
    }

    #[test]
    fn test_registry_allows_revision_only_service() {
        let mut config = make_service_config(vec![]);
        config.revisions = vec![RevisionConfig {
            name: "v1".to_string(),
            traffic_percent: 100,
            servers: vec![ServerConfig {
                url: "http://127.0.0.1:8001".to_string(),
                weight: 1,
            }],
            strategy: Strategy::RoundRobin,
        }];

        let mut configs = HashMap::new();
        configs.insert("revision-only".to_string(), config);

        let registry = ServiceRegistry::from_config(&configs).unwrap();
        let lb = registry.get("revision-only").unwrap();
        assert_eq!(registry.len(), 1);
        assert!(lb.backends().is_empty());
    }

    #[test]
    fn test_registry_multiple_services() {
        let mut configs = HashMap::new();
        configs.insert(
            "api".to_string(),
            make_service_config(vec!["http://127.0.0.1:8001"]),
        );
        configs.insert(
            "web".to_string(),
            make_service_config(vec!["http://127.0.0.1:8002"]),
        );
        let registry = ServiceRegistry::from_config(&configs).unwrap();
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn test_registry_empty() {
        let configs = HashMap::new();
        let registry = ServiceRegistry::from_config(&configs).unwrap();
        assert!(registry.is_empty());
    }

    #[test]
    fn test_registry_iter() {
        let mut configs = HashMap::new();
        configs.insert(
            "api".to_string(),
            make_service_config(vec!["http://127.0.0.1:8001"]),
        );
        configs.insert(
            "web".to_string(),
            make_service_config(vec!["http://127.0.0.1:8002"]),
        );
        let registry = ServiceRegistry::from_config(&configs).unwrap();

        let names: Vec<&String> = registry.iter().map(|(name, _)| name).collect();
        assert!(names.contains(&&"api".to_string()));
        assert!(names.contains(&&"web".to_string()));
    }

    #[test]
    fn test_registry_len() {
        let mut configs = HashMap::new();
        configs.insert(
            "api".to_string(),
            make_service_config(vec!["http://127.0.0.1:8001"]),
        );
        let registry = ServiceRegistry::from_config(&configs).unwrap();
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_registry_get_nonexistent() {
        let mut configs = HashMap::new();
        configs.insert(
            "api".to_string(),
            make_service_config(vec!["http://127.0.0.1:8001"]),
        );
        let registry = ServiceRegistry::from_config(&configs).unwrap();
        assert!(registry.get("nonexistent").is_none());
    }
}
