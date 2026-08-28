//! Replayable upstream-attempt preparation for managed inference.

use super::{inference_service_is_available, GatewayState};
use crate::inference::{
    AuthenticatedInference, InferenceAccessError, InferenceAttemptIdentity, InferenceAuthorizer,
    InferenceDispatchTarget, InferenceRequestIdentity, InferenceWorkerCandidate,
    InferenceWorkerSelection, InferenceWorkerSelectionRequest, OpenAiJsonRequest,
};
use crate::observability::access_log::RequestAccessLog;
use crate::service::{Backend, ServiceTimeouts};
use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use std::collections::HashSet;
use std::sync::Arc;

/// Request state retained until an upstream response becomes available.
///
/// The validated JSON document is intentionally retained only in memory and
/// only for the lifetime of one request. A fallback can therefore rewrite the
/// model and replay the request without reparsing client input.
pub(crate) struct InferenceDispatchState {
    authorizer: Arc<InferenceAuthorizer>,
    authenticated: AuthenticatedInference,
    model_alias: String,
    request: OpenAiJsonRequest,
    request_identity: InferenceRequestIdentity,
    next_priority: Option<u32>,
    attempt_count: u32,
    scheduled_target: Option<InferenceDispatchTarget>,
    attempted_worker_units: HashSet<String>,
}

/// One concrete upstream attempt prepared from the active snapshot.
pub(crate) struct PreparedInferenceAttempt {
    pub(crate) service_name: String,
    pub(crate) backend: Arc<Backend>,
    pub(crate) body: Bytes,
    pub(crate) timeouts: ServiceTimeouts,
    pub(crate) sticky_new_session: Option<String>,
    pub(crate) identity: InferenceAttemptIdentity,
}

impl InferenceDispatchState {
    pub(crate) fn new(
        authorizer: Arc<InferenceAuthorizer>,
        authenticated: AuthenticatedInference,
        model_alias: String,
        request: OpenAiJsonRequest,
        request_identity: InferenceRequestIdentity,
    ) -> Self {
        Self {
            authorizer,
            authenticated,
            model_alias,
            request,
            request_identity,
            next_priority: Some(0),
            attempt_count: 0,
            scheduled_target: None,
            attempted_worker_units: HashSet::new(),
        }
    }

    pub(crate) fn request_identity(&self) -> &InferenceRequestIdentity {
        &self.request_identity
    }

    pub(crate) fn model_alias(&self) -> &str {
        &self.model_alias
    }

    /// Prepare the first available target at or after the next priority.
    ///
    /// Callers invoke this again only when the preceding attempt failed before
    /// upstream response headers were received. Once a priority is attempted,
    /// the state advances past the complete priority group.
    pub(crate) fn prepare_next(
        &mut self,
        state: &GatewayState,
        headers: &mut http::HeaderMap,
        access_log: Option<&mut RequestAccessLog>,
    ) -> Result<PreparedInferenceAttempt, InferenceAccessError> {
        let now = chrono::Utc::now();
        let scheduled = self.authorizer.model_uses_worker_scheduling(
            self.authenticated,
            &self.model_alias,
            now,
        )?;
        let reusable_target = self.scheduled_target.clone().filter(|target| {
            self.scheduled_service_is_available(state, &target.service, target.target_id, now)
        });
        let (target, reused_target) = if let Some(target) = reusable_target {
            (target, true)
        } else {
            self.scheduled_target = None;
            self.attempted_worker_units.clear();
            let minimum_priority = self
                .next_priority
                .ok_or(InferenceAccessError::Unavailable)?;
            let target = self.authorizer.select_target_from_priority(
                self.authenticated,
                &self.model_alias,
                minimum_priority,
                now,
                |service, target_id| {
                    if scheduled {
                        self.scheduled_service_is_available(state, service, target_id, now)
                    } else {
                        inference_service_is_available(state, service)
                    }
                },
            )?;
            (target, false)
        };
        if !reused_target {
            self.next_priority = target.priority.checked_add(1);
            if scheduled {
                self.scheduled_target = Some(target.clone());
            }
        }
        self.request_identity.set_model_id(target.model_id);

        let scoped_prompt_cache_key = self.request.scoped_prompt_cache_key(
            self.authenticated.credential_id(),
            target.model_id,
            self.request_identity.endpoint(),
        );
        let selected = if scheduled {
            self.select_scheduled_backend(
                state,
                &target.service,
                target.target_id,
                scoped_prompt_cache_key.as_deref(),
                now,
            )?
        } else {
            select_backend(state, &target.service, headers)
                .ok_or(InferenceAccessError::Unavailable)?
        };
        if scheduled {
            if let Some(worker) = selected.backend.managed_target() {
                self.attempted_worker_units.insert(worker.unit_id.clone());
            }
        }
        let body = self
            .request
            .routed_body(&target.upstream_model, scoped_prompt_cache_key.as_deref())
            .map_err(|_| InferenceAccessError::Unavailable)?;
        let content_length = http::HeaderValue::from_str(&body.len().to_string())
            .map_err(|_| InferenceAccessError::Unavailable)?;
        headers.insert(CONTENT_LENGTH, content_length);

        let identity = self.request_identity.begin_attempt(target.target_id);
        identity.prepare_upstream_headers(headers);
        self.attempt_count = self.attempt_count.saturating_add(1);

        if let Some(access_log) = access_log {
            access_log.set_inference_attempt(&identity);
            access_log.set_backend(selected.backend.url.clone());
        }
        if state.metrics_enabled {
            state.metrics.record_service_request(&target.service);
            state
                .metrics
                .record_backend_request_id(selected.backend.metric_id());
        }

        tracing::info!(
            request_id = %identity.request().request_id(),
            attempt_id = %identity.attempt_id(),
            target_id = %identity.target_id(),
            model_id = %target.model_id,
            priority = target.priority,
            attempt_count = self.attempt_count,
            service = %target.service,
            backend = %selected.backend.url,
            is_fallback = self.attempt_count > 1,
            "Prepared managed inference upstream attempt"
        );
        if let Some(scheduling) = selected.scheduling {
            tracing::info!(
                request_id = %identity.request().request_id(),
                attempt_id = %identity.attempt_id(),
                backend_id = %selected.backend.metric_id(),
                observation_generation = scheduling.observation_generation,
                worker_active = scheduling.active,
                worker_waiting = scheduling.waiting,
                worker_pressure_basis_points = scheduling.pressure_basis_points,
                cache_affinity_applied = scheduling.cache_affinity_applied,
                "Selected managed inference worker"
            );
        }

        Ok(PreparedInferenceAttempt {
            service_name: target.service,
            backend: selected.backend,
            body,
            timeouts: selected.timeouts,
            sticky_new_session: selected.sticky_new_session,
            identity,
        })
    }

    fn scheduled_service_is_available(
        &self,
        state: &GatewayState,
        service: &str,
        target_id: uuid::Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let Some(load_balancer) = state.service_registry.get(service) else {
            return false;
        };
        let backends = load_balancer.backends();
        let candidates = worker_candidates(&backends, &self.attempted_worker_units);
        self.authorizer
            .has_eligible_worker(
                self.authenticated,
                &self.model_alias,
                target_id,
                &candidates,
                now,
            )
            .unwrap_or(false)
    }

    fn select_scheduled_backend(
        &self,
        state: &GatewayState,
        service: &str,
        target_id: uuid::Uuid,
        cache_affinity_key: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<SelectedBackend, InferenceAccessError> {
        let load_balancer = state
            .service_registry
            .get(service)
            .ok_or(InferenceAccessError::Unavailable)?;
        let backends = load_balancer.backends();
        let candidates = worker_candidates(&backends, &self.attempted_worker_units);
        let scheduling = self.authorizer.select_worker(
            self.authenticated,
            &self.model_alias,
            InferenceWorkerSelectionRequest {
                target_id,
                candidates: &candidates,
                now,
                routing_key: self.request_identity.request_id().as_bytes(),
                cache_affinity_key,
            },
        )?;
        let backend = backends
            .get(scheduling.index)
            .cloned()
            .ok_or(InferenceAccessError::Unavailable)?;
        Ok(SelectedBackend {
            backend,
            timeouts: load_balancer.timeouts(),
            sticky_new_session: None,
            scheduling: Some(scheduling),
        })
    }
}

struct SelectedBackend {
    backend: Arc<Backend>,
    timeouts: ServiceTimeouts,
    sticky_new_session: Option<String>,
    scheduling: Option<InferenceWorkerSelection>,
}

fn worker_candidates<'a>(
    backends: &'a [Arc<Backend>],
    excluded_worker_units: &HashSet<String>,
) -> Vec<InferenceWorkerCandidate<'a>> {
    backends
        .iter()
        .map(|backend| InferenceWorkerCandidate {
            target: backend.managed_target(),
            healthy: backend.is_healthy()
                && backend
                    .managed_target()
                    .is_some_and(|target| !excluded_worker_units.contains(&target.unit_id)),
            local_connections: u64::try_from(backend.connections()).unwrap_or(u64::MAX),
        })
        .collect()
}

/// Select one concrete backend without entering Gateway-owned scaling loops.
///
/// Cloud-managed mode may use static revisions, capacity-aware selection,
/// sticky affinity, and a configured service failover pool. Scale-from-zero
/// buffering remains a standalone-only control loop.
fn select_backend(
    state: &GatewayState,
    service: &str,
    headers: &http::HeaderMap,
) -> Option<SelectedBackend> {
    let load_balancer = state.service_registry.get(service)?;
    let timeouts = load_balancer.timeouts();
    let mut sticky_new_session = None;
    let sticky_backend = state.sticky_managers.get(service).and_then(|manager| {
        let session_id = headers
            .get("cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|cookie| manager.extract_session_id(cookie));
        manager
            .select_backend(session_id, load_balancer.backends().as_slice())
            .map(|(backend, new_session)| {
                sticky_new_session = new_session;
                backend
            })
    });

    let scaling = state.scaling.as_ref();
    let backend = if sticky_backend.is_some() {
        sticky_backend
    } else if let Some(router) = scaling.and_then(|scaling| scaling.revision_routers.get(service)) {
        router.next_backend().map(|(backend, _revision)| backend)
    } else if let Some(limiter) = scaling.and_then(|scaling| scaling.limiters.get(service)) {
        limiter.select_with_capacity(load_balancer.backends().as_slice())
    } else {
        load_balancer.next_backend()
    }
    .or_else(|| {
        state
            .failovers
            .get(service)
            .and_then(|selector| selector.next_backend().map(|(backend, _)| backend))
    })?;

    Some(SelectedBackend {
        backend,
        timeouts,
        sticky_new_session,
        scheduling: None,
    })
}
