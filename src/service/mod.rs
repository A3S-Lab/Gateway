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
pub use load_balancer::{Backend, LoadBalancer};
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
            if config.load_balancer.servers.is_empty() {
                return Err(GatewayError::Config(format!(
                    "Service '{}' has no servers",
                    name
                )));
            }

            let lb = LoadBalancer::new(
                name.clone(),
                config.load_balancer.strategy.clone(),
                &config.load_balancer.servers,
                config
                    .load_balancer
                    .sticky
                    .as_ref()
                    .map(|s| s.cookie.clone()),
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
    use crate::config::{LoadBalancerConfig, ServerConfig, Strategy};

    fn make_service_config(urls: Vec<&str>) -> ServiceConfig {
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
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
    fn test_registry_empty_servers() {
        let mut configs = HashMap::new();
        configs.insert("bad".to_string(), make_service_config(vec![]));
        let result = ServiceRegistry::from_config(&configs);
        assert!(result.is_err());
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
}
