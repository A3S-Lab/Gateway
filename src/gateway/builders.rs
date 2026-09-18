//! Builder helpers for gateway component construction
//!
//! Pure functions that translate GatewayConfig into runtime state:
//! scaling state, mirror/failover routing, sticky sessions, pipelines, etc.

use crate::config::GatewayConfig;
use crate::entrypoint;
use crate::error::{GatewayError, Result};
use crate::proxy::{HttpProxy, HttpTimeouts};
use crate::scaling::buffer::RequestBuffer;
use crate::scaling::concurrency::ConcurrencyLimiter;
use crate::scaling::revision::RevisionRouter;
use crate::service::passive_health::{PassiveHealthCheck, PassiveHealthConfig};
use crate::service::sticky::{StickyConfig, StickySessionManager};
use crate::service::ServiceRegistry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// Build standalone digest-store runtimes for configured static bundles.
pub fn build_static_bundle_runtimes(
    config: &GatewayConfig,
) -> Result<HashMap<String, Arc<crate::static_object::StaticBundleRuntime>>> {
    let mut bundles = HashMap::new();
    let mut names = config.static_bundles.keys().cloned().collect::<Vec<_>>();
    names.sort();
    for name in names {
        let bundle = &config.static_bundles[&name];
        let store = bundle.local_digest_store.as_ref().ok_or_else(|| {
            GatewayError::Config(format!(
                "static_bundles '{name}' requires local_digest_store in standalone mode"
            ))
        })?;
        let port = Arc::new(crate::static_object::DirectoryObjectAuthority::new(
            store.clone(),
        ));
        let manifest = bundle.sealed_manifest();
        let manifest_digest = manifest.content_fingerprint();
        bundles.insert(
            name.clone(),
            Arc::new(crate::static_object::StaticBundleRuntime {
                name: Arc::from(name.as_str()),
                manifest,
                base_path: bundle.base_path.clone(),
                object_namespace: bundle.object_namespace.clone(),
                manifest_digest,
                port,
                cache: Arc::new(crate::static_object::AdmittedObjectCache::with_defaults()),
            }),
        );
    }
    Ok(bundles)
}

/// Build per-service HTTP proxies for private upstream CA bundles.
pub fn build_service_http_proxies(
    config: &GatewayConfig,
    request_header_timeout: Duration,
) -> Result<HashMap<String, Arc<HttpProxy>>> {
    let mut proxies = HashMap::new();
    for (name, svc) in &config.services {
        let Some(ca_file) = svc.load_balancer.tls_ca_file.as_deref() else {
            continue;
        };
        let connect_timeout =
            crate::config::parse_service_duration(&svc.load_balancer.connect_timeout).map_err(
                |error| {
                    GatewayError::Config(format!(
                        "Invalid connect_timeout for service '{name}' while building tls_ca_file proxy: {error}"
                    ))
                },
            )?;
        let proxy = HttpProxy::try_with_timeouts_and_ca_file(
            request_header_timeout,
            connect_timeout,
            ca_file,
        )
        .map_err(|error| {
            GatewayError::Config(format!(
                "Failed to build upstream TLS client for service '{name}': {error}"
            ))
        })?;
        proxies.insert(name.clone(), Arc::new(proxy));
    }
    Ok(proxies)
}

/// Build per-service gRPC proxies for private upstream CA bundles.
///
/// Mirrors [`build_service_http_proxies`] so `tls_ca_file` activates for
/// application/grpc on the same validate ≡ activate path as HTTP.
pub fn build_service_grpc_proxies(
    config: &GatewayConfig,
) -> Result<HashMap<String, Arc<crate::proxy::grpc::GrpcProxy>>> {
    let mut proxies = HashMap::new();
    for (name, svc) in &config.services {
        let Some(ca_file) = svc.load_balancer.tls_ca_file.as_deref() else {
            continue;
        };
        let proxy = crate::proxy::grpc::GrpcProxy::try_with_ca_file(ca_file).map_err(|error| {
            GatewayError::Config(format!(
                "Failed to build upstream gRPC TLS client for service '{name}': {error}"
            ))
        })?;
        proxies.insert(name.clone(), Arc::new(proxy));
    }
    Ok(proxies)
}

/// Build per-service WebSocket TLS configs that trust only `tls_ca_file`.
///
/// Default WebSocket upgrades use public webpki roots. A service with
/// `tls_ca_file` must not fall back to those roots on the upgrade path.
pub fn build_service_ws_tls_configs(
    config: &GatewayConfig,
) -> Result<HashMap<String, Arc<rustls::ClientConfig>>> {
    let mut configs = HashMap::new();
    for (name, svc) in &config.services {
        let Some(ca_file) = svc.load_balancer.tls_ca_file.as_deref() else {
            continue;
        };
        let tls = crate::proxy::websocket::private_ca_client_config(ca_file).map_err(|error| {
            GatewayError::Config(format!(
                "Failed to build upstream WebSocket TLS client for service '{name}': {error}"
            ))
        })?;
        configs.insert(name.clone(), tls);
    }
    Ok(configs)
}

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
            if let Some(scaling) = svc.scaling.as_ref() {
                router.set_concurrency_limit(scaling.container_concurrency);
            }
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

/// Build mirror and failover state from gateway config.
///
/// Missing mirror/failover targets fail closed — the same invariant as
/// `GatewayConfig::validate` — instead of soft-skipping HA policy at runtime build.
pub fn build_mirror_failover_state(
    config: &GatewayConfig,
    service_registry: &Arc<ServiceRegistry>,
    http_proxy: &Arc<HttpProxy>,
    service_http_proxies: &HashMap<String, Arc<HttpProxy>>,
) -> Result<(
    HashMap<String, Arc<crate::service::TrafficMirror>>,
    HashMap<String, Arc<crate::service::FailoverSelector>>,
)> {
    let mut mirrors = HashMap::new();
    let mut failovers = HashMap::new();

    for (name, svc) in &config.services {
        if let Some(ref mirror_config) = svc.mirror {
            let Some(shadow_lb) = service_registry.get(&mirror_config.service) else {
                return Err(GatewayError::Config(format!(
                    "Service '{name}' mirror references unknown service '{}'",
                    mirror_config.service
                )));
            };
            let shadow_proxy = service_http_proxies
                .get(&mirror_config.service)
                .unwrap_or(http_proxy);
            let mirror = crate::service::TrafficMirror::new(
                shadow_lb,
                mirror_config.percentage,
                shadow_proxy.clone(),
            );
            mirrors.insert(name.clone(), Arc::new(mirror));
            tracing::info!(
                service = name,
                shadow = mirror_config.service,
                percentage = mirror_config.percentage,
                "Traffic mirroring configured"
            );
        }

        if let Some(ref failover_config) = svc.failover {
            let Some(primary_lb) = service_registry.get(name) else {
                return Err(GatewayError::Config(format!(
                    "Service '{name}' failover requires the primary service in the registry"
                )));
            };
            let Some(failover_lb) = service_registry.get(&failover_config.service) else {
                return Err(GatewayError::Config(format!(
                    "Service '{name}' failover references unknown service '{}'",
                    failover_config.service
                )));
            };
            let selector = crate::service::FailoverSelector::new(primary_lb, failover_lb);
            failovers.insert(name.clone(), Arc::new(selector));
            tracing::info!(
                service = name,
                failover = failover_config.service,
                "Failover configured"
            );
        }
    }

    Ok((mirrors, failovers))
}

/// Spawn a background task that drains the access log channel and serializes entries.
/// This keeps JSON serialization and tracing off the request hot path.
pub fn spawn_log_task(
    mut rx: tokio::sync::mpsc::Receiver<crate::observability::access_log::AccessLogEntry>,
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

/// Bind each sorted HTTP route to its middleware pipeline and load balancer
/// or static bundle target.
pub fn build_route_plans(
    config: &GatewayConfig,
    router_table: &crate::router::RouterTable,
    pipeline_cache: &HashMap<String, Arc<crate::middleware::Pipeline>>,
    service_registry: &ServiceRegistry,
    passive_health: &HashMap<String, Arc<PassiveHealthCheck>>,
    static_bundles: &HashMap<String, Arc<crate::static_object::StaticBundleRuntime>>,
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
            if let Some(static_bundle) = static_bundles.get(&route.service_name) {
                return Ok(entrypoint::RoutePlan {
                    pipeline,
                    load_balancer: None,
                    passive_health: None,
                    direct_http_eligible: false,
                    direct_http_binding: None,
                    static_bundle: Some(Arc::clone(static_bundle)),
                });
            }
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
            let direct_http_binding = if direct_http_eligible {
                match load_balancer.backends().as_slice() {
                    [backend] => {
                        let timeouts = load_balancer.timeouts();
                        Some(entrypoint::DirectHttpBinding {
                            backend: Arc::clone(backend),
                            timeouts: HttpTimeouts::new(
                                timeouts.request_timeout(),
                                timeouts.stream_idle_timeout(),
                                timeouts.stream_total_timeout(),
                            ),
                        })
                    }
                    _ => None,
                }
            } else {
                None
            };
            Ok(entrypoint::RoutePlan {
                pipeline,
                load_balancer: Some(load_balancer),
                passive_health: Some(passive_health),
                direct_http_eligible,
                direct_http_binding,
                static_bundle: None,
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Vec::into_boxed_slice)
}

/// Build sticky session managers for services that have a sticky cookie configured.
pub fn build_sticky_managers(
    config: &GatewayConfig,
) -> Result<HashMap<String, Arc<StickySessionManager>>> {
    let mut managers = HashMap::new();
    for (name, svc) in &config.services {
        let Some(sticky_cfg) = &svc.load_balancer.sticky else {
            continue;
        };
        crate::config::validate_sticky_cookie_name(&sticky_cfg.cookie).map_err(|error| {
            GatewayError::Config(format!(
                "Invalid sticky cookie for service '{name}': {error}"
            ))
        })?;
        let sc = StickyConfig {
            cookie_name: sticky_cfg.cookie.clone(),
            ..StickyConfig::default()
        };
        managers.insert(name.clone(), Arc::new(StickySessionManager::new(sc)));
    }
    Ok(managers)
}

/// Build passive health checkers for every configured service (always-on, default settings).
pub fn build_passive_health(config: &GatewayConfig) -> HashMap<String, Arc<PassiveHealthCheck>> {
    config
        .services
        .keys()
        .map(|name| {
            let phc = Arc::new(PassiveHealthCheck::new(PassiveHealthConfig::default()));
            // Background half-open recovery: after `recovery_time` the checker
            // re-enables a blacklisted backend so traffic can probe again,
            // breaking the "no traffic → no success → never recover" deadlock.
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
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                        target: None,
                    }],
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
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
                    connect_timeout: "10s".to_string(),
                    servers: vec![],
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
                },
                scaling: None,
                revisions: vec![
                    RevisionConfig {
                        name: "v1".into(),
                        traffic_percent: 80,
                        servers: vec![ServerConfig {
                            url: "http://a:8001".into(),
                            weight: 1,
                            target: None,
                        }],
                        strategy: Strategy::RoundRobin,
                    },
                    RevisionConfig {
                        name: "v2".into(),
                        traffic_percent: 20,
                        servers: vec![ServerConfig {
                            url: "http://b:8001".into(),
                            weight: 1,
                            target: None,
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
    fn test_build_scaling_state_propagates_concurrency_to_revisions() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers: vec![],
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
                },
                scaling: Some(ScalingConfig {
                    container_concurrency: 1,
                    ..ScalingConfig::default()
                }),
                revisions: vec![RevisionConfig {
                    name: "v1".into(),
                    traffic_percent: 100,
                    servers: vec![ServerConfig {
                        url: "http://a:8001".into(),
                        weight: 1,
                        target: None,
                    }],
                    strategy: Strategy::RoundRobin,
                }],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );

        let state = build_scaling_state(&config).unwrap();
        let backend = state.revision_routers["api"].revisions()[0]
            .load_balancer()
            .backends()[0]
            .clone();
        let first = backend
            .try_track_connection_on(0)
            .expect("first revision operation should be admitted");
        assert!(backend.try_track_connection_on(1).is_none());
        drop(first);
        assert!(backend.try_track_connection_on(2).is_some());
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
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                        target: None,
                    }],
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
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
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                        target: None,
                    }],
                    health_check: None,
                    sticky: None,
                    tls_ca_file: None,
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
    fn build_pipeline_cache_rejects_acl_retry_plus_custom_retry_policy() {
        use crate::middleware::RetryPolicy;
        use async_trait::async_trait;

        struct CustomRetry;

        #[async_trait]
        impl crate::middleware::Middleware for CustomRetry {
            async fn handle_request(
                &self,
                _req: &mut http::request::Parts,
                _ctx: &crate::middleware::RequestContext,
            ) -> crate::Result<Option<http::Response<Vec<u8>>>> {
                Ok(None)
            }

            fn retry_policy(&self) -> Option<RetryPolicy> {
                Some(RetryPolicy::default())
            }

            fn name(&self) -> &str {
                "custom-retry"
            }
        }

        let mut config = minimal_config();
        config.middlewares.insert(
            "acl-retry".to_string(),
            crate::config::MiddlewareConfig {
                middleware_type: "retry".to_string(),
                max_retries: Some(2),
                ..Default::default()
            },
        );
        config.routers.insert(
            "api".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/api`)".to_string(),
                service: "api".to_string(),
                entrypoints: vec![],
                middlewares: vec!["acl-retry".to_string(), "custom-retry".to_string()],
                priority: 0,
            },
        );
        let mut registry = crate::middleware::MiddlewareRegistry::new();
        registry.register("custom-retry", CustomRetry).unwrap();

        let error = match build_pipeline_cache(&config, &config.middlewares, &registry) {
            Ok(_) => panic!("dual retry policies must fail pipeline compile"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("at most one retry policy"),
            "unexpected error: {error}"
        );
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
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".to_string(),
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
        let static_bundles = HashMap::new();
        let plans = build_route_plans(
            &config,
            &router_table,
            &pipeline_cache,
            &service_registry,
            &passive_health,
            &static_bundles,
        )
        .unwrap();

        assert_eq!(plans.len(), 1);
        assert!(plans[0].pipeline.is_empty());
        assert_eq!(plans[0].load_balancer.as_ref().unwrap().name, "api");
        assert!(plans[0].direct_http_eligible);
        let direct = plans[0].direct_http_binding.as_ref().unwrap();
        assert_eq!(direct.backend.url, "http://127.0.0.1:8001");

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
            &static_bundles,
        )
        .unwrap();
        assert!(!plans[0].direct_http_eligible);
        assert!(plans[0].direct_http_binding.is_none());
    }

    // --- build_sticky_managers ---

    #[test]
    fn test_build_sticky_managers_empty() {
        let config = minimal_config();
        let managers = build_sticky_managers(&config).unwrap();
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
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                        target: None,
                    }],
                    health_check: None,
                    sticky: Some(StickyConfig {
                        cookie: "session_id".to_string(),
                    }),
                    tls_ca_file: None,
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let managers = build_sticky_managers(&config).unwrap();
        assert_eq!(managers.len(), 1);
        assert!(managers.contains_key("api"));
        assert_eq!(managers.get("api").unwrap().cookie_name(), "session_id");
    }

    #[test]
    fn build_sticky_managers_fails_closed_on_invalid_cookie_name() {
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                        target: None,
                    }],
                    health_check: None,
                    sticky: Some(StickyConfig {
                        cookie: "bad name".to_string(),
                    }),
                    tls_ca_file: None,
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let error = match build_sticky_managers(&config) {
            Ok(_) => panic!("invalid sticky cookie must fail closed at build"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("sticky cookie") && error.contains("bad name"),
            "unexpected error: {error}"
        );
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
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
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
        let managers = build_sticky_managers(&config).unwrap();
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
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
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
        config.services.insert(
            "backend".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8002".into(),
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
        let healths = build_passive_health(&config);
        assert_eq!(healths.len(), 2);
        assert!(healths.contains_key("api"));
        assert!(healths.contains_key("backend"));
    }

    #[test]
    fn build_mirror_failover_fails_closed_when_mirror_target_missing_from_registry() {
        use crate::config::MirrorConfig;

        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
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
                mirror: Some(MirrorConfig {
                    service: "shadow".to_string(),
                    percentage: 100,
                }),
                failover: None,
            },
        );
        let registry = Arc::new(ServiceRegistry::from_config(&config.services).unwrap());
        let http_proxy = Arc::new(HttpProxy::new());
        let err =
            match build_mirror_failover_state(&config, &registry, &http_proxy, &HashMap::new()) {
                Ok(_) => panic!("missing mirror target must fail closed"),
                Err(error) => error.to_string(),
            };
        assert!(
            err.contains("mirror") && err.contains("shadow"),
            "missing mirror target must fail closed: {err}"
        );
    }

    #[test]
    fn build_mirror_failover_fails_closed_when_failover_target_missing_from_registry() {
        use crate::config::FailoverConfig;

        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    connect_timeout: "10s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
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
                failover: Some(FailoverConfig {
                    service: "backup".to_string(),
                }),
            },
        );
        let registry = Arc::new(ServiceRegistry::from_config(&config.services).unwrap());
        let http_proxy = Arc::new(HttpProxy::new());
        let err =
            match build_mirror_failover_state(&config, &registry, &http_proxy, &HashMap::new()) {
                Ok(_) => panic!("missing failover target must fail closed"),
                Err(error) => error.to_string(),
            };
        assert!(
            err.contains("failover") && err.contains("backup"),
            "missing failover target must fail closed: {err}"
        );
    }
}
