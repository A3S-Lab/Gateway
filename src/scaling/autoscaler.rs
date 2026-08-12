//! Autoscaler — periodic decision engine that monitors metrics and emits scale decisions
//!
//! Implements a Knative-style autoscaling formula:
//! `desired = ceil((in_flight + queue_depth) / (container_concurrency * target_utilization))`
//! clamped to `[min_replicas, max_replicas]`.

use crate::config::ScalingConfig;
use crate::error::Result;
use crate::scaling::executor::{
    ReplicaState, ScaleDecision, ScaleDirection, ScaleEndpoint, ScaleExecutor,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_EXECUTOR_TIMEOUT: Duration = Duration::from_secs(5);

/// A snapshot of metrics for a single service
#[derive(Debug, Clone)]
pub struct ServiceMetricsSnapshot {
    /// Service name
    pub service: String,
    /// Number of healthy backends
    #[allow(dead_code)]
    pub healthy_backends: usize,
    /// Total in-flight requests across all backends
    pub in_flight: usize,
    /// Requests waiting in the buffer (scale-from-zero)
    pub queue_depth: usize,
}

/// Per-service autoscaler state
struct ServiceScaleState {
    /// Scaling configuration
    config: ScalingConfig,
    /// Last time a request was observed for this service
    last_request_at: Instant,
    /// Last accepted or executor-observed replica count
    current_replicas: Option<u32>,
    /// Opaque executor revision paired with `current_replicas`.
    current_revision: Option<String>,
    /// Most recent successful live endpoint observation. `None` means the
    /// executor has not yet been observed; an empty vector is authoritative.
    endpoints: Option<Vec<ScaleEndpoint>>,
    ready_replicas: u32,
}

/// Autoscaler that periodically evaluates metrics and executes scaling decisions
pub struct Autoscaler {
    /// Scale executor
    executor: Arc<dyn ScaleExecutor>,
    /// Per-service state
    services: HashMap<String, ServiceScaleState>,
    /// Maximum time allowed for one executor operation
    executor_timeout: Duration,
}

impl Autoscaler {
    /// Create a new autoscaler with the given executor and service configs
    pub fn new(executor: Arc<dyn ScaleExecutor>, configs: HashMap<String, ScalingConfig>) -> Self {
        let now = Instant::now();
        let services = configs
            .into_iter()
            .map(|(name, config)| {
                let state = ServiceScaleState {
                    config,
                    last_request_at: now,
                    current_replicas: None,
                    current_revision: None,
                    endpoints: None,
                    ready_replicas: 0,
                };
                (name, state)
            })
            .collect();

        Self {
            executor,
            services,
            executor_timeout: DEFAULT_EXECUTOR_TIMEOUT,
        }
    }

    /// Compute the desired replica count using the Knative formula.
    ///
    /// `desired = ceil((in_flight + queue_depth) / (cc * utilization))`
    /// clamped to `[min, max]`.
    ///
    /// Special cases:
    /// - `cc == 0` (unlimited): returns current replicas (no autoscaling decision)
    /// - `in_flight + queue_depth == 0` and past cooldown: returns `min_replicas`
    pub fn compute_desired_replicas(
        config: &ScalingConfig,
        snapshot: &ServiceMetricsSnapshot,
    ) -> u32 {
        let cc = config.container_concurrency;
        if cc == 0 {
            // Unlimited concurrency — no autoscaling signal from concurrency
            return config.min_replicas.max(1);
        }

        let total_load = (snapshot.in_flight + snapshot.queue_depth) as f64;
        if total_load == 0.0 {
            return config.min_replicas;
        }

        let effective_capacity = cc as f64 * config.target_utilization;
        if effective_capacity <= 0.0 {
            return config.max_replicas;
        }

        let desired = (total_load / effective_capacity).ceil() as u32;
        desired.clamp(config.min_replicas, config.max_replicas)
    }

    /// Evaluate a metrics snapshot and return a scaling decision if needed.
    ///
    /// Returns `None` if no scaling action is required (desired == current,
    /// or scale-down is blocked by cooldown).
    pub fn evaluate(&mut self, snapshot: &ServiceMetricsSnapshot) -> Option<ScaleDecision> {
        let state = self.services.get_mut(&snapshot.service)?;

        // Update last_request_at if there's active load
        if snapshot.in_flight > 0 || snapshot.queue_depth > 0 {
            state.last_request_at = Instant::now();
        }

        let desired = Self::compute_desired_replicas(&state.config, snapshot);
        let current = state.current_replicas?;

        if desired == current {
            return None;
        }

        // Scale-down cooldown: only scale down if enough time has passed since last request
        if desired < current {
            let elapsed = state.last_request_at.elapsed().as_secs();
            if elapsed < state.config.scale_down_delay_secs {
                return None;
            }
        }

        let direction = if desired > current {
            ScaleDirection::Up
        } else {
            ScaleDirection::Down
        };

        let reason = format!(
            "{}: in_flight={}, queue={}, cc={}, util={:.0}%, current={}, desired={}",
            direction,
            snapshot.in_flight,
            snapshot.queue_depth,
            state.config.container_concurrency,
            state.config.target_utilization * 100.0,
            current,
            desired,
        );

        Some(ScaleDecision {
            schema_version: 1,
            operation_id: scale_operation_id(
                &snapshot.service,
                state.current_revision.as_deref(),
                current,
                desired,
            ),
            service: snapshot.service.clone(),
            expected_revision: state.current_revision.clone(),
            direction,
            current_replicas: current,
            desired_replicas: desired,
            reason,
        })
    }

    async fn reconcile_current_replicas(&mut self, service: &str) -> Result<()> {
        let observed = match tokio::time::timeout(
            self.executor_timeout,
            self.executor.current_replicas(service),
        )
        .await
        {
            Ok(Ok(observed)) => observed,
            Ok(Err(error)) => {
                return Err(crate::error::GatewayError::Scaling(format!(
                    "Autoscaler failed to query current replicas for service '{}': {}",
                    service, error
                )));
            }
            Err(_) => {
                return Err(crate::error::GatewayError::Scaling(format!(
                    "Autoscaler executor replica query timed out after {} ms for service '{}'",
                    self.executor_timeout.as_millis(),
                    service
                )));
            }
        };

        self.set_current_state(service, observed.clone());
        tracing::debug!(
            service,
            replicas = observed.replicas,
            revision = observed.revision.as_deref().unwrap_or("none"),
            executor = self.executor.name(),
            "Autoscaler reconciled current replica state"
        );
        Ok(())
    }

    /// Execute a single evaluation cycle for all services using the provided metrics function.
    pub async fn tick<F>(&mut self, metrics_fn: F) -> Vec<Result<()>>
    where
        F: Fn(&str) -> Option<ServiceMetricsSnapshot>,
    {
        self.tick_with_before_execute(metrics_fn, |_, _| Ok(()))
            .await
    }

    /// Execute one evaluation cycle and withdraw surplus live endpoints before
    /// a scale-down mutation reaches the external executor.
    ///
    /// The hook is synchronous by design: Gateway's dynamic backend swap is an
    /// in-memory atomic publication step. If the executor result is ambiguous,
    /// the reduced endpoint set remains published until the next authoritative
    /// observation either confirms the downscale or restores the old slots.
    pub(crate) async fn tick_with_before_execute<F, H>(
        &mut self,
        metrics_fn: F,
        mut before_execute: H,
    ) -> Vec<Result<()>>
    where
        F: Fn(&str) -> Option<ServiceMetricsSnapshot>,
        H: FnMut(&ScaleDecision, &[ScaleEndpoint]) -> Result<()>,
    {
        let service_names: Vec<String> = self.services.keys().cloned().collect();
        let mut results = Vec::new();

        for name in &service_names {
            if let Some(snapshot) = metrics_fn(name) {
                if let Err(error) = self.reconcile_current_replicas(name).await {
                    results.push(Err(error));
                    continue;
                }

                if let Some(decision) = self.evaluate(&snapshot) {
                    tracing::info!(
                        service = decision.service,
                        direction = %decision.direction,
                        from = decision.current_replicas,
                        to = decision.desired_replicas,
                        reason = decision.reason,
                        "Autoscaler decision"
                    );
                    let previous_endpoint_observation = if decision.direction
                        == ScaleDirection::Down
                    {
                        let Some(state) = self.services.get(&decision.service) else {
                            results.push(Err(crate::error::GatewayError::Scaling(format!(
                                "Autoscaler service '{}' disappeared before endpoint withdrawal",
                                decision.service
                            ))));
                            continue;
                        };
                        let previous = (state.ready_replicas, state.endpoints.clone());
                        let retained_endpoints = state
                            .endpoints
                            .as_deref()
                            .unwrap_or_default()
                            .iter()
                            .filter(|endpoint| endpoint.slot < decision.desired_replicas)
                            .cloned()
                            .collect::<Vec<_>>();
                        if let Err(error) = before_execute(&decision, &retained_endpoints) {
                            results.push(Err(error));
                            continue;
                        }
                        let Some(state) = self.services.get_mut(&decision.service) else {
                            results.push(Err(crate::error::GatewayError::Scaling(format!(
                                "Autoscaler service '{}' disappeared after endpoint withdrawal",
                                decision.service
                            ))));
                            continue;
                        };
                        state.ready_replicas = state.ready_replicas.min(decision.desired_replicas);
                        state.endpoints = Some(retained_endpoints);
                        Some(previous)
                    } else {
                        None
                    };
                    let execution = tokio::time::timeout(
                        self.executor_timeout,
                        self.executor.execute(&decision),
                    )
                    .await;
                    let result = match execution {
                        Ok(Ok(result)) if result.accepted => {
                            self.set_current_state(
                                &decision.service,
                                ReplicaState {
                                    replicas: result.actual_replicas,
                                    revision: result.revision,
                                    ready_replicas: result.ready_replicas,
                                    endpoints: result.endpoints,
                                },
                            );
                            Ok(())
                        }
                        Ok(Ok(result)) => {
                            if let Some((ready_replicas, endpoints)) = previous_endpoint_observation
                            {
                                if let Some(state) = self.services.get_mut(&decision.service) {
                                    state.ready_replicas = ready_replicas;
                                    state.endpoints = endpoints;
                                }
                            }
                            Err(crate::error::GatewayError::Scaling(format!(
                                "Autoscaler executor rejected service '{}': {}",
                                decision.service, result.message
                            )))
                        }
                        Ok(Err(error)) => {
                            self.clear_current_replicas(&decision.service);
                            Err(error)
                        }
                        Err(_) => {
                            self.clear_current_replicas(&decision.service);
                            Err(crate::error::GatewayError::Scaling(format!(
                                "Autoscaler executor timed out after {} ms for service '{}'",
                                self.executor_timeout.as_millis(),
                                decision.service
                            )))
                        }
                    };
                    results.push(result);
                }
            }
        }

        results
    }

    /// Get the executor reference
    #[allow(dead_code)]
    pub fn executor(&self) -> &Arc<dyn ScaleExecutor> {
        &self.executor
    }

    /// Check if a service is registered with the autoscaler
    #[allow(dead_code)]
    pub fn has_service(&self, name: &str) -> bool {
        self.services.contains_key(name)
    }

    /// Number of services being autoscaled
    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    /// Update the authoritative replica count observed from an executor.
    #[cfg(test)]
    pub fn set_current_replicas(&mut self, service: &str, replicas: u32) {
        self.set_current_state(
            service,
            ReplicaState {
                replicas,
                revision: None,
                ready_replicas: replicas,
                endpoints: Vec::new(),
            },
        );
    }

    fn set_current_state(&mut self, service: &str, observed: ReplicaState) {
        if let Some(state) = self.services.get_mut(service) {
            state.current_replicas = Some(observed.replicas);
            state.current_revision = observed.revision;
            state.ready_replicas = observed.ready_replicas;
            state.endpoints = Some(observed.endpoints);
        }
    }

    /// Successful live endpoint observations, including authoritative empty
    /// sets after scale-to-zero.
    pub(crate) fn endpoint_observations(&self) -> Vec<(String, u32, Vec<ScaleEndpoint>)> {
        self.services
            .iter()
            .filter_map(|(service, state)| {
                state
                    .endpoints
                    .as_ref()
                    .map(|endpoints| (service.clone(), state.ready_replicas, endpoints.clone()))
            })
            .collect()
    }

    fn clear_current_replicas(&mut self, service: &str) {
        if let Some(state) = self.services.get_mut(service) {
            state.current_replicas = None;
            state.current_revision = None;
        }
    }

    #[cfg(test)]
    fn set_executor_timeout(&mut self, timeout: Duration) {
        self.executor_timeout = timeout;
    }
}

fn scale_operation_id(
    service: &str,
    expected_revision: Option<&str>,
    current_replicas: u32,
    desired_replicas: u32,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"a3s-gateway-scale-v1\0");
    digest.update(service.as_bytes());
    digest.update(b"\0");
    digest.update(expected_revision.unwrap_or("unversioned").as_bytes());
    digest.update(b"\0");
    digest.update(current_replicas.to_be_bytes());
    digest.update(desired_replicas.to_be_bytes());
    format!("scale-v1-{:x}", digest.finalize())
}

#[cfg(test)]
include!("autoscaler_tests.rs");
