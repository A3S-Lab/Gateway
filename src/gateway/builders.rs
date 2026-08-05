//! Builder helpers for gateway component construction
//!
//! Pure functions that translate GatewayConfig into runtime state:
//! scaling state, mirror/failover routing, sticky sessions, pipelines, etc.

use crate::config::GatewayConfig;
use crate::entrypoint;
use crate::error::{GatewayError, Result};
use crate::proxy::HttpProxy;
use crate::scaling::buffer::RequestBuffer;
use crate::scaling::concurrency::ConcurrencyLimiter;
use crate::scaling::revision::RevisionRouter;
use crate::service::passive_health::{PassiveHealthCheck, PassiveHealthConfig};
use crate::service::sticky::{StickyConfig, StickySessionManager};
use crate::service::ServiceRegistry;
use std::collections::HashMap;
use std::sync::Arc;

/// Build ScalingState from gateway config if any service has scaling configuration
pub fn build_scaling_state(config: &GatewayConfig) -> Option<Arc<entrypoint::ScalingState>> {
    let mut buffers = HashMap::new();
    let mut limiters = HashMap::new();
    let mut revision_routers = HashMap::new();
    let mut has_scaling = false;

    for (name, svc) in &config.services {
        // Build revision router if revisions are configured
        if !svc.revisions.is_empty() {
            let router = RevisionRouter::from_config(name, &svc.revisions);
            revision_routers.insert(name.clone(), Arc::new(router));
            has_scaling = true;
        }

        if let Some(ref sc) = svc.scaling {
            has_scaling = true;

            // Build concurrency limiter if container_concurrency > 0
            if sc.container_concurrency > 0 {
                let limiter = ConcurrencyLimiter::new(sc.container_concurrency);
                limiters.insert(name.clone(), Arc::new(limiter));
            }

            // Build request buffer if buffering is enabled (scale-from-zero)
            if sc.buffer_enabled {
                let buffer =
                    RequestBuffer::new(name.clone(), sc.buffer_size, sc.buffer_timeout_secs);
                buffers.insert(name.clone(), Arc::new(buffer));
            }
        }
    }

    if has_scaling {
        Some(Arc::new(entrypoint::ScalingState {
            buffers,
            limiters,
            revision_routers,
        }))
    } else {
        None
    }
}

/// Build mirror and failover state from gateway config
pub fn build_mirror_failover_state(
    config: &GatewayConfig,
    service_registry: &Arc<ServiceRegistry>,
    http_proxy: &Arc<HttpProxy>,
) -> (
    HashMap<String, Arc<crate::service::TrafficMirror>>,
    HashMap<String, Arc<crate::service::FailoverSelector>>,
) {
    let mut mirrors = HashMap::new();
    let mut failovers = HashMap::new();

    for (name, svc) in &config.services {
        // Build traffic mirror if configured
        if let Some(ref mirror_config) = svc.mirror {
            if let Some(shadow_lb) = service_registry.get(&mirror_config.service) {
                let mirror = crate::service::TrafficMirror::new(
                    shadow_lb,
                    mirror_config.percentage,
                    http_proxy.clone(),
                );
                mirrors.insert(name.clone(), Arc::new(mirror));
                tracing::info!(
                    service = name,
                    shadow = mirror_config.service,
                    percentage = mirror_config.percentage,
                    "Traffic mirroring configured"
                );
            } else {
                tracing::warn!(
                    service = name,
                    shadow = mirror_config.service,
                    "Mirror target service not found, skipping"
                );
            }
        }

        // Build failover selector if configured
        if let Some(ref failover_config) = svc.failover {
            if let (Some(primary_lb), Some(failover_lb)) = (
                service_registry.get(name),
                service_registry.get(&failover_config.service),
            ) {
                let selector = crate::service::FailoverSelector::new(primary_lb, failover_lb);
                failovers.insert(name.clone(), Arc::new(selector));
                tracing::info!(
                    service = name,
                    failover = failover_config.service,
                    "Failover configured"
                );
            } else {
                tracing::warn!(
                    service = name,
                    failover = failover_config.service,
                    "Failover target service not found, skipping"
                );
            }
        }
    }

    (mirrors, failovers)
}

/// Spawn a background task that drains the access log channel and serializes entries.
/// This keeps JSON serialization and tracing off the request hot path.
pub fn spawn_log_task(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<crate::observability::access_log::AccessLogEntry>,
    access_log: Arc<crate::observability::access_log::AccessLog>,
) {
    tokio::spawn(async move {
        while let Some(entry) = rx.recv().await {
            access_log.record(&entry);
        }
    });
}

/// Pre-compile middleware pipelines for all routers — avoids per-request Pipeline::from_config.
pub fn build_pipeline_cache(
    config: &GatewayConfig,
    middleware_configs: &HashMap<String, crate::config::MiddlewareConfig>,
    middleware_registry: &crate::middleware::MiddlewareRegistry,
) -> Result<HashMap<String, Arc<crate::middleware::Pipeline>>> {
    config
        .routers
        .iter()
        .map(|(name, router)| {
            crate::middleware::Pipeline::from_config_with_registry(
                &router.middlewares,
                middleware_configs,
                middleware_registry,
            )
            .map(|pipeline| (name.clone(), Arc::new(pipeline)))
            .map_err(|error| {
                let detail = match error {
                    GatewayError::Config(detail) => detail,
                    other => other.to_string(),
                };
                GatewayError::Config(format!(
                    "Failed to build middleware pipeline for router '{name}': {detail}"
                ))
            })
        })
        .collect()
}

/// Bind each sorted HTTP route to its middleware pipeline and load balancer.
pub fn build_route_plans(
    config: &GatewayConfig,
    router_table: &crate::router::RouterTable,
    pipeline_cache: &HashMap<String, Arc<crate::middleware::Pipeline>>,
    service_registry: &ServiceRegistry,
    passive_health: &HashMap<String, Arc<PassiveHealthCheck>>,
) -> Result<Box<[entrypoint::RoutePlan]>> {
    router_table
        .resolved_routes()
        .map(|route| {
            let pipeline = pipeline_cache
                .get(&route.router_name)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::Config(format!(
                        "Router '{}' has no compiled middleware pipeline",
                        route.router_name
                    ))
                })?;
            let load_balancer = service_registry.get(&route.service_name).ok_or_else(|| {
                GatewayError::Config(format!(
                    "Router '{}' references unknown service '{}'",
                    route.router_name, route.service_name
                ))
            })?;
            let service = config.services.get(&route.service_name).ok_or_else(|| {
                GatewayError::Config(format!(
                    "Router '{}' references missing service configuration '{}'",
                    route.router_name, route.service_name
                ))
            })?;
            let passive_health = passive_health
                .get(&route.service_name)
                .cloned()
                .ok_or_else(|| {
                    GatewayError::Config(format!(
                        "Router '{}' has no passive health binding for service '{}'",
                        route.router_name, route.service_name
                    ))
                })?;
            let direct_http_eligible = pipeline.is_empty()
                && service.scaling.is_none()
                && service.revisions.is_empty()
                && service.mirror.is_none()
                && service.failover.is_none()
                && service.load_balancer.sticky.is_none();
            Ok(entrypoint::RoutePlan {
                pipeline,
                load_balancer,
                passive_health,
                direct_http_eligible,
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Vec::into_boxed_slice)
}

/// Build sticky session managers for services that have a sticky cookie configured.
pub fn build_sticky_managers(config: &GatewayConfig) -> HashMap<String, Arc<StickySessionManager>> {
    config
        .services
        .iter()
        .filter_map(|(name, svc)| {
            svc.load_balancer.sticky.as_ref().map(|sticky_cfg| {
                let sc = StickyConfig {
                    cookie_name: sticky_cfg.cookie.clone(),
                    ..StickyConfig::default()
                };
                (name.clone(), Arc::new(StickySessionManager::new(sc)))
            })
        })
        .collect()
}

/// Build passive health checkers for every configured service (always-on, default settings).
pub fn build_passive_health(config: &GatewayConfig) -> HashMap<String, Arc<PassiveHealthCheck>> {
    config
        .services
        .keys()
        .map(|name| {
            let phc = Arc::new(PassiveHealthCheck::new(PassiveHealthConfig::default()));
            // 启动半开自愈后台任务:后端被拉黑超过 recovery_time 后主动放行试探,
            // 破"拉黑→无流量→无成功→永不恢复"的死锁(否则一次瞬时抖动 = 持续 503 直到重启)。
            phc.spawn_recovery();
            (name.clone(), phc)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        LoadBalancerConfig, MiddlewareConfig, RevisionConfig, RouterConfig, ScalingConfig,
        ServerConfig, ServiceConfig, StickyConfig, Strategy,
    };
    fn minimal_config() -> GatewayConfig {
        let mut config = GatewayConfig::default();
        config.routers.clear();
        config.services.clear();
        config.middlewares.clear();
        config
    }

    // --- build_scaling_state ---

    #[test]
    fn test_build_scaling_state_none_when_no_scaling() {
        let config = minimal_config();
        assert!(build_scaling_state(&config).is_none());
    }

    #[test]
    fn test_build_scaling_state_with_scaling_config() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: Some(ScalingConfig {
                    container_concurrency: 10,
                    buffer_enabled: true,
                    ..ScalingConfig::default()
                }),
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let state = build_scaling_state(&config).unwrap();
        assert!(state.buffers.contains_key("api"));
        assert!(state.limiters.contains_key("api"));
        assert!(!state.revision_routers.contains_key("api"));
    }

    #[test]
    fn test_build_scaling_state_with_revisions() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![],
                    health_check: None,
                    sticky: None,
                },
                scaling: None,
                revisions: vec![
                    RevisionConfig {
                        name: "v1".into(),
                        traffic_percent: 80,
                        servers: vec![ServerConfig {
                            url: "http://a:8001".into(),
                            weight: 1,
                        }],
                        strategy: Strategy::RoundRobin,
                    },
                    RevisionConfig {
                        name: "v2".into(),
                        traffic_percent: 20,
                        servers: vec![ServerConfig {
                            url: "http://b:8001".into(),
                            weight: 1,
                        }],
                        strategy: Strategy::RoundRobin,
                    },
                ],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let state = build_scaling_state(&config).unwrap();
        assert!(state.revision_routers.contains_key("api"));
    }

    #[test]
    fn test_build_scaling_state_no_buffer_when_disabled() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: Some(ScalingConfig {
                    buffer_enabled: false,
                    container_concurrency: 0,
                    ..ScalingConfig::default()
                }),
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let state = build_scaling_state(&config).unwrap();
        assert!(!state.buffers.contains_key("api"));
        assert!(!state.limiters.contains_key("api"));
    }

    #[test]
    fn test_build_scaling_state_no_limiter_when_cc_zero() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: Some(ScalingConfig {
                    buffer_enabled: true,
                    container_concurrency: 0,
                    ..ScalingConfig::default()
                }),
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let state = build_scaling_state(&config).unwrap();
        assert!(state.buffers.contains_key("api"));
        assert!(!state.limiters.contains_key("api"));
    }

    // --- build_pipeline_cache ---

    #[test]
    fn test_build_pipeline_cache_empty() {
        let config = minimal_config();
        let middlewares = std::collections::HashMap::new();
        let cache = build_pipeline_cache(
            &config,
            &middlewares,
            &crate::middleware::MiddlewareRegistry::new(),
        )
        .unwrap();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_build_pipeline_cache_with_routers() {
        let mut config = minimal_config();
        let mut mw_configs = std::collections::HashMap::new();
        mw_configs.insert(
            "cors".to_string(),
            MiddlewareConfig {
                middleware_type: "cors".to_string(),
                allowed_origins: vec!["*".to_string()],
                ..Default::default()
            },
        );
        config.routers.insert(
            "api".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/api`)".to_string(),
                service: "api".to_string(),
                entrypoints: vec![],
                middlewares: vec!["cors".to_string()],
                priority: 0,
            },
        );
        let cache = build_pipeline_cache(
            &config,
            &mw_configs,
            &crate::middleware::MiddlewareRegistry::new(),
        )
        .unwrap();
        assert_eq!(cache.len(), 1);
        assert!(cache.contains_key("api"));
    }

    #[test]
    fn test_build_pipeline_cache_rejects_invalid_middleware() {
        let mut config = minimal_config();
        let mw_configs = std::collections::HashMap::new();
        config.routers.insert(
            "api".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/api`)".to_string(),
                service: "api".to_string(),
                entrypoints: vec![],
                middlewares: vec!["nonexistent".to_string()],
                priority: 0,
            },
        );
        let error = match build_pipeline_cache(
            &config,
            &mw_configs,
            &crate::middleware::MiddlewareRegistry::new(),
        ) {
            Ok(_) => panic!("invalid middleware pipeline must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("router 'api'"));
        assert!(error.to_string().contains("Middleware 'nonexistent'"));
    }

    #[test]
    fn test_build_route_plans_bind_runtime_objects() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".to_string(),
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
        config.routers.insert(
            "api".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/api`)".to_string(),
                service: "api".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: 0,
            },
        );

        let router_table = crate::router::RouterTable::from_config(&config.routers).unwrap();
        let pipeline_cache = build_pipeline_cache(
            &config,
            &config.middlewares,
            &crate::middleware::MiddlewareRegistry::new(),
        )
        .unwrap();
        let service_registry = ServiceRegistry::from_config(&config.services).unwrap();
        let passive_health = build_passive_health(&config);
        let plans = build_route_plans(
            &config,
            &router_table,
            &pipeline_cache,
            &service_registry,
            &passive_health,
        )
        .unwrap();

        assert_eq!(plans.len(), 1);
        assert!(plans[0].pipeline.is_empty());
        assert_eq!(plans[0].load_balancer.name, "api");
        assert!(plans[0].direct_http_eligible);

        config.services.get_mut("api").unwrap().load_balancer.sticky =
            Some(crate::config::StickyConfig {
                cookie: "a3s_session".to_string(),
            });
        let plans = build_route_plans(
            &config,
            &router_table,
            &pipeline_cache,
            &service_registry,
            &passive_health,
        )
        .unwrap();
        assert!(!plans[0].direct_http_eligible);
    }

    // --- build_sticky_managers ---

    #[test]
    fn test_build_sticky_managers_empty() {
        let config = minimal_config();
        let managers = build_sticky_managers(&config);
        assert!(managers.is_empty());
    }

    #[test]
    fn test_build_sticky_managers_with_sticky_service() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: Some(StickyConfig {
                        cookie: "session_id".to_string(),
                    }),
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let managers = build_sticky_managers(&config);
        assert_eq!(managers.len(), 1);
        assert!(managers.contains_key("api"));
        assert_eq!(managers.get("api").unwrap().cookie_name(), "session_id");
    }

    #[test]
    fn test_build_sticky_managers_without_sticky() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
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
        let managers = build_sticky_managers(&config);
        assert!(managers.is_empty());
    }

    // --- build_passive_health ---

    #[test]
    fn test_build_passive_health_empty() {
        let config = minimal_config();
        let healths = build_passive_health(&config);
        assert!(healths.is_empty());
    }

    #[test]
    fn test_build_passive_health_with_services() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
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
        config.services.insert(
            "backend".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8002".into(),
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
        let healths = build_passive_health(&config);
        assert_eq!(healths.len(), 2);
        assert!(healths.contains_key("api"));
        assert!(healths.contains_key("backend"));
    }
}
