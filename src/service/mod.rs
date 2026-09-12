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
pub(crate) use health_check::{HealthCheckTasks, PreparedHealthChecks};
pub(crate) use load_balancer::BackendConnectionGuard;
pub use load_balancer::{Backend, LoadBalancer, ServiceTimeouts};
pub use mirror::TrafficMirror;
pub(crate) use mirror::MAX_MIRROR_BODY_BYTES;

/// Maximum number of executor-owned backend slots retained in one live
/// service snapshot.  The bound protects routing, health, and telemetry from
/// an unexpectedly large dynamic endpoint observation.
pub(crate) const MAX_DYNAMIC_BACKENDS: usize = 4096;

use crate::config::ServiceConfig;
use crate::error::{GatewayError, Result};
use crate::scaling::revision::RevisionRouter;
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
            if config.load_balancer.servers.is_empty()
                && config.revisions.is_empty()
                && !config.uses_box_endpoint_discovery()
            {
                return Err(GatewayError::Config(format!(
                    "Service '{}' has no servers",
                    name
                )));
            }

            for (index, server) in config.load_balancer.servers.iter().enumerate() {
                crate::config::validate_server_weight(server.weight).map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid server weight for service '{}' at index {}: {}",
                        name, index, error
                    ))
                })?;
                crate::config::validate_server_url(&server.url).map_err(|error| {
                    GatewayError::Config(format!(
                        "Invalid server URL for service '{}' at index {}: {}",
                        name, index, error
                    ))
                })?;
            }

            let connect_timeout =
                crate::config::parse_service_duration(&config.load_balancer.connect_timeout)
                    .map_err(|e| {
                        GatewayError::Config(format!(
                            "Invalid connect_timeout for service '{}': {}",
                            name, e
                        ))
                    })?;
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
                connect_timeout,
                request_timeout,
                stream_idle_timeout,
                stream_total_timeout,
            );
            if let Some(scaling) = config.scaling.as_ref() {
                lb.set_concurrency_limit(scaling.container_concurrency);
            }

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

    /// Prepare health checkers without starting background work.
    pub(crate) fn prepare_health_checks(
        &self,
        configs: &HashMap<String, ServiceConfig>,
        revision_routers: Option<&HashMap<String, Arc<RevisionRouter>>>,
    ) -> Result<PreparedHealthChecks> {
        let mut checkers = Vec::new();
        for (name, config) in configs {
            let Some(health) = config.load_balancer.health_check.as_ref() else {
                continue;
            };
            let (interval, timeout) = health.validate_and_parse_durations().map_err(|error| {
                GatewayError::Config(format!(
                    "Invalid health_check for service '{}': {}",
                    name, error
                ))
            })?;
            let load_balancer = self.services.get(name).ok_or_else(|| {
                GatewayError::Config(format!(
                    "Health checker references unregistered service '{}'",
                    name
                ))
            })?;
            let checker = match config.load_balancer.tls_ca_file.as_deref() {
                Some(ca_file) => HealthChecker::try_new_with_ca(
                    load_balancer.clone(),
                    health.path.clone(),
                    interval,
                    timeout,
                    health.unhealthy_threshold,
                    health.healthy_threshold,
                    Some(ca_file),
                ),
                None => HealthChecker::try_new(
                    load_balancer.clone(),
                    health.path.clone(),
                    interval,
                    timeout,
                    health.unhealthy_threshold,
                    health.healthy_threshold,
                ),
            }
            .map_err(|error| {
                GatewayError::Other(format!(
                    "Failed to prepare health_check for service '{}': {}",
                    name, error
                ))
            })?;
            checkers.push((name.clone(), checker));

            // Revision traffic is served by the revision router's own load
            // balancers. Probe those concrete pools as well; checking only
            // the service-level pool leaves revision backends permanently
            // marked healthy and makes active health checks ineffective for
            // static traffic splitting.
            if let Some(router) = revision_routers.and_then(|routers| routers.get(name)) {
                for revision in router.revisions() {
                    let checker = match config.load_balancer.tls_ca_file.as_deref() {
                        Some(ca_file) => HealthChecker::try_new_with_ca(
                            revision.load_balancer().clone(),
                            health.path.clone(),
                            interval,
                            timeout,
                            health.unhealthy_threshold,
                            health.healthy_threshold,
                            Some(ca_file),
                        ),
                        None => HealthChecker::try_new(
                            revision.load_balancer().clone(),
                            health.path.clone(),
                            interval,
                            timeout,
                            health.unhealthy_threshold,
                            health.healthy_threshold,
                        ),
                    }
                    .map_err(|error| {
                        GatewayError::Other(format!(
                            "Failed to prepare health_check for revision '{}': {}",
                            revision.name, error
                        ))
                    })?;
                    checkers.push((format!("{name}/{}", revision.name), checker));
                }
            }
        }
        Ok(PreparedHealthChecks::new(checkers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        HealthCheckConfig, LoadBalancerConfig, RevisionConfig, ScalingConfig, ServerConfig,
        Strategy,
    };

    fn make_service_config(urls: Vec<&str>) -> ServiceConfig {
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                connect_timeout: "10s".to_string(),
                servers: urls
                    .into_iter()
                    .map(|url| ServerConfig {
                        url: url.to_string(),
                        weight: 1,
                        target: None,
                    })
                    .collect(),
                health_check: None,
                sticky: None,
                tls_ca_file: None,
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
    fn test_registry_propagates_container_concurrency_to_backend_admission() {
        let mut config = make_service_config(vec!["http://127.0.0.1:8001"]);
        config.scaling = Some(ScalingConfig {
            container_concurrency: 1,
            ..ScalingConfig::default()
        });
        let mut configs = HashMap::new();
        configs.insert("backend".to_string(), config);

        let registry = ServiceRegistry::from_config(&configs).unwrap();
        let backend = registry.get("backend").unwrap().backends()[0].clone();
        let first = backend
            .try_track_connection_on(0)
            .expect("first operation should be admitted");
        assert!(backend.try_track_connection_on(1).is_none());
        drop(first);
        assert!(backend.try_track_connection_on(2).is_some());
    }

    #[test]
    fn test_prepare_health_checks_revalidates_runtime_settings() {
        let mut config = make_service_config(vec!["http://127.0.0.1:8001"]);
        config.load_balancer.health_check = Some(HealthCheckConfig {
            path: "/health".to_string(),
            interval: "invalid".to_string(),
            timeout: "5s".to_string(),
            unhealthy_threshold: 3,
            healthy_threshold: 1,
        });
        let mut configs = HashMap::new();
        configs.insert("backend".to_string(), config);
        let registry = ServiceRegistry::from_config(&configs).unwrap();

        let error = registry
            .prepare_health_checks(&configs, None)
            .err()
            .expect("runtime preparation accepted an invalid health check");
        assert!(error
            .to_string()
            .contains("Invalid health_check for service 'backend'"));
    }

    #[test]
    fn test_prepare_health_checks_includes_revision_pools() {
        let mut config = make_service_config(vec![]);
        config.load_balancer.health_check = Some(HealthCheckConfig {
            path: "/health".to_string(),
            interval: "1s".to_string(),
            timeout: "100ms".to_string(),
            unhealthy_threshold: 2,
            healthy_threshold: 1,
        });
        config.revisions = vec![RevisionConfig {
            name: "v1".to_string(),
            traffic_percent: 100,
            servers: vec![ServerConfig {
                url: "http://127.0.0.1:8001".to_string(),
                weight: 1,
                target: None,
            }],
            strategy: Strategy::RoundRobin,
        }];
        let mut configs = HashMap::new();
        configs.insert("backend".to_string(), config);
        let registry = ServiceRegistry::from_config(&configs).unwrap();
        let router = Arc::new(RevisionRouter::from_config(
            "backend",
            &configs["backend"].revisions,
        ));
        let mut routers = HashMap::new();
        routers.insert("backend".to_string(), router);

        let prepared = registry
            .prepare_health_checks(&configs, Some(&routers))
            .unwrap();
        assert_eq!(prepared.len(), 2);
        assert!(prepared.service_names().any(|name| name == "backend/v1"));
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
                target: None,
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
    fn test_registry_allows_box_managed_scale_from_zero_service() {
        let mut config = make_service_config(vec![]);
        config.scaling = Some(ScalingConfig {
            container_concurrency: 10,
            executor: "box".to_string(),
            ..ScalingConfig::default()
        });
        let mut configs = HashMap::new();
        configs.insert("box-managed".to_string(), config);

        let registry = ServiceRegistry::from_config(&configs).unwrap();
        assert!(registry.get("box-managed").unwrap().backends().is_empty());
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
