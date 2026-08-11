//! Standalone autoscaler runtime wiring.
//!
//! Cloud-managed mode rejects local scaling configuration before this module is
//! reached. The runtime here therefore observes only operator-owned standalone
//! services.

use crate::config::GatewayConfig;
use crate::entrypoint;
use crate::error::{GatewayError, Result};
use crate::scaling::autoscaler::{Autoscaler, ServiceMetricsSnapshot};
use crate::scaling::executor::{BoxScaleExecutor, ScaleDecision, ScaleEndpoint, ScaleExecutor};
#[cfg(feature = "kube")]
use crate::scaling::kubernetes_executor::K8sScaleExecutor;
use crate::service::ServiceRegistry;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

#[cfg(feature = "kube")]
const EXECUTOR_PREPARE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A fully constructed standalone autoscaler that has not started mutating an
/// external executor.
pub(super) struct PreparedAutoscaler {
    autoscaler: Autoscaler,
    scaling_state: Option<Arc<entrypoint::ScalingState>>,
    service_registry: Arc<ServiceRegistry>,
    manages_box_endpoints: bool,
}

impl PreparedAutoscaler {
    fn sync_box_endpoints(&self) {
        if !self.manages_box_endpoints {
            return;
        }
        for (service, ready_replicas, endpoints) in self.autoscaler.endpoint_observations() {
            let Some(load_balancer) = self.service_registry.get(&service) else {
                tracing::warn!(%service, "Box endpoint observation has no Gateway service");
                continue;
            };
            let endpoints = endpoints
                .into_iter()
                .map(|endpoint| (endpoint.slot, endpoint.url))
                .collect::<Vec<_>>();
            if let Err(error) = load_balancer.replace_dynamic_backends(&endpoints) {
                tracing::warn!(%service, %error, "Box endpoint update was rejected");
                continue;
            }
            if ready_replicas > 0 && load_balancer.healthy_count() == 0 {
                tracing::warn!(
                    %service,
                    ready_replicas,
                    "Box reports ready replicas without a routable endpoint"
                );
            }
            if load_balancer.healthy_count() > 0 {
                if let Some(buffer) = self
                    .scaling_state
                    .as_ref()
                    .and_then(|scaling| scaling.buffers.get(&service))
                {
                    buffer.signal_ready();
                }
            }
        }
    }

    async fn tick_once(&mut self) -> Vec<Result<()>> {
        let scaling_state = self.scaling_state.clone();
        let metrics_registry = Arc::clone(&self.service_registry);
        let results = if self.manages_box_endpoints {
            let endpoint_registry = Arc::clone(&self.service_registry);
            self.autoscaler
                .tick_with_before_execute(
                    |service_name| {
                        service_metrics_snapshot(
                            service_name,
                            scaling_state.as_deref(),
                            &metrics_registry,
                        )
                    },
                    move |decision, endpoints| {
                        withdraw_box_endpoints(&endpoint_registry, decision, endpoints)
                    },
                )
                .await
        } else {
            self.autoscaler
                .tick(|service_name| {
                    service_metrics_snapshot(
                        service_name,
                        scaling_state.as_deref(),
                        &metrics_registry,
                    )
                })
                .await
        };
        self.sync_box_endpoints();
        results
    }

    /// Start the control loop after the surrounding Gateway runtime commits.
    pub(super) fn start(mut self) -> tokio::task::JoinHandle<()> {
        tracing::info!(
            services = self.autoscaler.service_count(),
            "Standalone autoscaler loop starting"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                interval.tick().await;

                let results = self.tick_once().await;

                for result in results {
                    if let Err(error) = result {
                        tracing::warn!(error = %error, "Standalone autoscaler decision failed");
                    }
                }
            }
        })
    }
}

fn withdraw_box_endpoints(
    service_registry: &ServiceRegistry,
    decision: &ScaleDecision,
    endpoints: &[ScaleEndpoint],
) -> Result<()> {
    let load_balancer = service_registry.get(&decision.service).ok_or_else(|| {
        GatewayError::Scaling(format!(
            "Box endpoint withdrawal has no Gateway service '{}'",
            decision.service
        ))
    })?;
    let endpoints = endpoints
        .iter()
        .map(|endpoint| (endpoint.slot, endpoint.url.clone()))
        .collect::<Vec<_>>();
    load_balancer.replace_dynamic_backends(&endpoints)?;
    tracing::info!(
        service = decision.service,
        retained_endpoints = endpoints.len(),
        desired_replicas = decision.desired_replicas,
        "Withdrew surplus Box endpoints before scale-down"
    );
    Ok(())
}

/// Prepare the standalone autoscaler when at least one service has a positive
/// container-concurrency target.
pub(super) async fn prepare_autoscaler(
    config: &GatewayConfig,
    scaling_state: Option<&Arc<entrypoint::ScalingState>>,
    service_registry: &Arc<ServiceRegistry>,
) -> Result<Option<PreparedAutoscaler>> {
    let scaling_configs: HashMap<_, _> = config
        .services
        .iter()
        .filter_map(|(name, service)| {
            service
                .scaling
                .as_ref()
                .filter(|scaling| scaling.container_concurrency > 0)
                .map(|scaling| (name.clone(), scaling.clone()))
        })
        .collect();

    if scaling_configs.is_empty() {
        return Ok(None);
    }

    let executor_types: BTreeSet<_> = scaling_configs
        .values()
        .map(|scaling| scaling.executor.as_str())
        .collect();
    if executor_types.len() != 1 {
        return Err(GatewayError::Config(format!(
            "Standalone autoscaling requires one executor across all active services, got: {}",
            executor_types.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    let executor_type = executor_types
        .into_iter()
        .next()
        .unwrap_or("box")
        .to_string();

    let executor: Arc<dyn ScaleExecutor> = match executor_type.as_str() {
        "box" => {
            let endpoints: BTreeSet<_> = scaling_configs
                .values()
                .map(|scaling| scaling.executor_endpoint.as_str())
                .collect();
            if endpoints.len() != 1 {
                return Err(GatewayError::Config(format!(
                    "Standalone Box autoscaling requires one executor_endpoint across all active services, got: {}",
                    endpoints.into_iter().collect::<Vec<_>>().join(", ")
                )));
            }
            Arc::new(BoxScaleExecutor::new(
                endpoints.into_iter().next().expect("one Box endpoint"),
            ))
        }
        #[cfg(feature = "kube")]
        "k8s" => {
            let namespace = config
                .providers
                .kubernetes
                .as_ref()
                .map(|provider| provider.namespace.as_str())
                .filter(|namespace| !namespace.is_empty())
                .unwrap_or("default");
            let executor =
                tokio::time::timeout(EXECUTOR_PREPARE_TIMEOUT, K8sScaleExecutor::new(namespace))
                    .await
                    .map_err(|_| {
                        GatewayError::Scaling(format!(
                            "K8s autoscaling executor initialization timed out after {} ms",
                            EXECUTOR_PREPARE_TIMEOUT.as_millis()
                        ))
                    })??;
            Arc::new(executor)
        }
        #[cfg(not(feature = "kube"))]
        "k8s" => {
            return Err(GatewayError::Config(
                "Standalone autoscaling executor 'k8s' requires the 'kube' feature".to_string(),
            ));
        }
        other => {
            return Err(GatewayError::Config(format!(
                "Unsupported standalone autoscaling executor '{other}'"
            )));
        }
    };

    Ok(Some(PreparedAutoscaler {
        autoscaler: Autoscaler::new(executor, scaling_configs),
        scaling_state: scaling_state.cloned(),
        service_registry: service_registry.clone(),
        manages_box_endpoints: executor_type == "box",
    }))
}

fn service_metrics_snapshot(
    service_name: &str,
    scaling: Option<&entrypoint::ScalingState>,
    service_registry: &ServiceRegistry,
) -> Option<ServiceMetricsSnapshot> {
    let scaling = scaling?;
    let queue_depth = scaling
        .buffers
        .get(service_name)
        .map(|buffer| buffer.queue_depth())
        .unwrap_or(0);

    let (healthy_backends, in_flight) =
        if let Some(router) = scaling.revision_routers.get(service_name) {
            (router.healthy_backend_count(), router.total_in_flight())
        } else {
            let load_balancer = service_registry.get(service_name)?;
            (
                load_balancer.healthy_count(),
                load_balancer
                    .backends()
                    .iter()
                    .map(|backend| backend.connections())
                    .sum(),
            )
        };

    if healthy_backends > 0 {
        if let Some(buffer) = scaling.buffers.get(service_name) {
            buffer.signal_ready();
        }
    }

    Some(ServiceMetricsSnapshot {
        service: service_name.to_string(),
        healthy_backends,
        in_flight,
        queue_depth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        LoadBalancerConfig, RevisionConfig, ScalingConfig, ServerConfig, ServiceConfig, Strategy,
    };
    use crate::gateway::builders::build_scaling_state;
    use crate::scaling::executor::{
        MockScaleExecutor, ReplicaState, ScaleDecision, ScaleEndpoint, ScaleExecutor, ScaleResult,
    };
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn standalone_service(servers: Vec<ServerConfig>) -> ServiceConfig {
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers,
                health_check: None,
                sticky: None,
            },
            scaling: Some(ScalingConfig {
                container_concurrency: 10,
                buffer_enabled: true,
                ..ScalingConfig::default()
            }),
            revisions: Vec::new(),
            rollout: None,
            mirror: None,
            failover: None,
        }
    }

    #[test]
    fn snapshot_reports_real_backend_load_and_health() {
        let mut config = GatewayConfig::default();
        config.services.clear();
        config.services.insert(
            "api".to_string(),
            standalone_service(vec![
                ServerConfig {
                    url: "http://one:8000".to_string(),
                    weight: 1,
                },
                ServerConfig {
                    url: "http://two:8000".to_string(),
                    weight: 1,
                },
            ]),
        );
        let scaling = build_scaling_state(&config).unwrap();
        let registry = ServiceRegistry::from_config(&config.services).unwrap();
        let load_balancer = registry.get("api").unwrap();
        load_balancer.backends()[0].inc_connections();
        load_balancer.backends()[0].inc_connections();
        load_balancer.backends()[1].inc_connections();
        load_balancer.backends()[1].set_healthy(false);

        let snapshot = service_metrics_snapshot("api", Some(&scaling), &registry).unwrap();

        assert_eq!(snapshot.healthy_backends, 1);
        assert_eq!(snapshot.in_flight, 3);
        assert_eq!(snapshot.queue_depth, 0);
    }

    #[test]
    fn snapshot_includes_revision_backend_load() {
        let mut config = GatewayConfig::default();
        config.services.clear();
        let mut service = standalone_service(Vec::new());
        service.revisions = vec![
            RevisionConfig {
                name: "stable".to_string(),
                traffic_percent: 90,
                servers: vec![ServerConfig {
                    url: "http://stable:8000".to_string(),
                    weight: 1,
                }],
                strategy: Strategy::RoundRobin,
            },
            RevisionConfig {
                name: "candidate".to_string(),
                traffic_percent: 10,
                servers: vec![ServerConfig {
                    url: "http://candidate:8000".to_string(),
                    weight: 1,
                }],
                strategy: Strategy::RoundRobin,
            },
        ];
        config.services.insert("api".to_string(), service);
        let scaling = build_scaling_state(&config).unwrap();
        let registry = ServiceRegistry::from_config(&config.services).unwrap();
        let router = scaling.revision_routers.get("api").unwrap();
        router.revisions()[0].load_balancer().backends()[0].inc_connections();
        router.revisions()[1].load_balancer().backends()[0].inc_connections();
        router.revisions()[1].load_balancer().backends()[0].inc_connections();

        let snapshot = service_metrics_snapshot("api", Some(&scaling), &registry).unwrap();

        assert_eq!(snapshot.healthy_backends, 2);
        assert_eq!(snapshot.in_flight, 3);
    }

    #[tokio::test]
    async fn prepared_autoscaler_does_not_execute_before_start() {
        let mut config = GatewayConfig::default();
        config.services.clear();
        config.services.insert(
            "api".to_string(),
            standalone_service(vec![
                ServerConfig {
                    url: "http://one:8000".to_string(),
                    weight: 1,
                },
                ServerConfig {
                    url: "http://two:8000".to_string(),
                    weight: 1,
                },
            ]),
        );
        let scaling = build_scaling_state(&config).unwrap();
        let registry = Arc::new(ServiceRegistry::from_config(&config.services).unwrap());
        let load_balancer = registry.get("api").unwrap();
        for _ in 0..20 {
            load_balancer.backends()[0].inc_connections();
        }

        let executor = Arc::new(MockScaleExecutor::new());
        let configs = config
            .services
            .iter()
            .map(|(name, service)| (name.clone(), service.scaling.as_ref().unwrap().clone()))
            .collect();
        let prepared = PreparedAutoscaler {
            autoscaler: Autoscaler::new(executor.clone(), configs),
            scaling_state: Some(scaling),
            service_registry: registry,
            manages_box_endpoints: false,
        };

        tokio::task::yield_now().await;
        assert!(executor.decisions().is_empty());

        let handle = prepared.start();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if !executor.decisions().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        handle.abort();
        let _ = handle.await;

        assert_eq!(executor.decisions().len(), 1);
    }

    struct EndpointExecutor;

    #[async_trait]
    impl ScaleExecutor for EndpointExecutor {
        async fn execute(&self, _decision: &ScaleDecision) -> Result<ScaleResult> {
            panic!("stable endpoint observation must not scale")
        }

        async fn current_replicas(&self, _service: &str) -> Result<ReplicaState> {
            Ok(ReplicaState {
                replicas: 1,
                revision: Some("7".to_string()),
                ready_replicas: 1,
                endpoints: vec![ScaleEndpoint {
                    instance_id: "box-api-0".to_string(),
                    slot: 0,
                    url: "http://127.0.0.1:18080".to_string(),
                }],
            })
        }

        fn name(&self) -> &str {
            "box"
        }
    }

    struct RegistryAwareDownscaleExecutor {
        registry: Arc<ServiceRegistry>,
        executed: AtomicBool,
    }

    #[async_trait]
    impl ScaleExecutor for RegistryAwareDownscaleExecutor {
        async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
            assert_eq!(
                decision.direction,
                crate::scaling::executor::ScaleDirection::Down
            );
            assert!(self
                .registry
                .get("api")
                .expect("api service")
                .backends()
                .is_empty());
            self.executed.store(true, Ordering::SeqCst);
            Ok(ScaleResult {
                accepted: true,
                actual_replicas: 0,
                revision: Some("8".to_string()),
                ready_replicas: 0,
                endpoints: Vec::new(),
                message: "scaled to zero".to_string(),
            })
        }

        async fn current_replicas(&self, _service: &str) -> Result<ReplicaState> {
            Ok(ReplicaState {
                replicas: 2,
                revision: Some("7".to_string()),
                ready_replicas: 2,
                endpoints: vec![
                    ScaleEndpoint {
                        instance_id: "box-api-0".to_string(),
                        slot: 0,
                        url: "http://127.0.0.1:18080".to_string(),
                    },
                    ScaleEndpoint {
                        instance_id: "box-api-1".to_string(),
                        slot: 1,
                        url: "http://127.0.0.1:18081".to_string(),
                    },
                ],
            })
        }

        fn name(&self) -> &str {
            "box"
        }
    }

    #[tokio::test]
    async fn box_endpoint_observation_updates_the_live_backend_pool() {
        let mut config = GatewayConfig::default();
        config.services.clear();
        let mut service = standalone_service(Vec::new());
        service.scaling = Some(ScalingConfig {
            min_replicas: 1,
            container_concurrency: 10,
            ..ScalingConfig::default()
        });
        config.services.insert("api".to_string(), service);
        let scaling = build_scaling_state(&config).unwrap();
        let registry = Arc::new(ServiceRegistry::from_config(&config.services).unwrap());
        let configs = config
            .services
            .iter()
            .map(|(name, service)| (name.clone(), service.scaling.as_ref().unwrap().clone()))
            .collect();
        let mut prepared = PreparedAutoscaler {
            autoscaler: Autoscaler::new(Arc::new(EndpointExecutor), configs),
            scaling_state: Some(scaling),
            service_registry: registry.clone(),
            manages_box_endpoints: true,
        };

        assert!(registry.get("api").unwrap().backends().is_empty());
        let results = prepared
            .autoscaler
            .tick(|_| {
                Some(ServiceMetricsSnapshot {
                    service: "api".to_string(),
                    healthy_backends: 0,
                    in_flight: 0,
                    queue_depth: 0,
                })
            })
            .await;
        assert!(results.is_empty());
        prepared.sync_box_endpoints();

        let backends = registry.get("api").unwrap().backends();
        assert_eq!(backends.len(), 1);
        assert_eq!(backends[0].url, "http://127.0.0.1:18080");
    }

    #[tokio::test]
    async fn box_downscale_removes_backends_before_executor_call() {
        let mut config = GatewayConfig::default();
        config.services.clear();
        let mut service = standalone_service(Vec::new());
        service.scaling = Some(ScalingConfig {
            min_replicas: 0,
            scale_down_delay_secs: 0,
            container_concurrency: 10,
            ..ScalingConfig::default()
        });
        config.services.insert("api".to_string(), service);
        let scaling = build_scaling_state(&config).unwrap();
        let registry = Arc::new(ServiceRegistry::from_config(&config.services).unwrap());
        registry
            .get("api")
            .unwrap()
            .replace_dynamic_backends(&[
                (0, "http://127.0.0.1:18080".to_string()),
                (1, "http://127.0.0.1:18081".to_string()),
            ])
            .unwrap();
        let executor = Arc::new(RegistryAwareDownscaleExecutor {
            registry: Arc::clone(&registry),
            executed: AtomicBool::new(false),
        });
        let configs = config
            .services
            .iter()
            .map(|(name, service)| (name.clone(), service.scaling.as_ref().unwrap().clone()))
            .collect();
        let mut prepared = PreparedAutoscaler {
            autoscaler: Autoscaler::new(executor.clone(), configs),
            scaling_state: Some(scaling),
            service_registry: registry.clone(),
            manages_box_endpoints: true,
        };

        let results = prepared.tick_once().await;

        assert_eq!(results.len(), 1);
        assert!(results[0].is_ok());
        assert!(executor.executed.load(Ordering::SeqCst));
        assert!(registry.get("api").unwrap().backends().is_empty());
    }
}
