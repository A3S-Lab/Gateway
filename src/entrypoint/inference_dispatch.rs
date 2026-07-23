//! Replayable upstream-attempt preparation for managed inference.

use super::{inference_service_is_available, GatewayState};
use crate::inference::{
    AuthenticatedInference, InferenceAccessError, InferenceAttemptIdentity, InferenceAuthorizer,
    InferenceRequestIdentity, OpenAiJsonRequest,
};
use crate::observability::access_log::RequestAccessLog;
use crate::service::Backend;
use bytes::Bytes;
use http::header::CONTENT_LENGTH;
use std::sync::Arc;
use std::time::Duration;

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
}

/// One concrete upstream attempt prepared from the active snapshot.
pub(crate) struct PreparedInferenceAttempt {
    pub(crate) service_name: String,
    pub(crate) backend: Arc<Backend>,
    pub(crate) body: Bytes,
    pub(crate) request_timeout: Duration,
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
        }
    }

    pub(crate) fn request_identity(&self) -> &InferenceRequestIdentity {
        &self.request_identity
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
        let minimum_priority = self
            .next_priority
            .ok_or(InferenceAccessError::Unavailable)?;
        let target = self.authorizer.select_target_from_priority(
            self.authenticated,
            &self.model_alias,
            minimum_priority,
            chrono::Utc::now(),
            |service| inference_service_is_available(state, service),
        )?;
        self.next_priority = target.priority.checked_add(1);
        self.request_identity.set_model_id(target.model_id);

        let selected = select_backend(state, &target.service, headers)
            .ok_or(InferenceAccessError::Unavailable)?;
        let body = self
            .request
            .routed_body(&target.upstream_model)
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
            state.metrics.record_backend_request(&selected.backend.url);
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

        Ok(PreparedInferenceAttempt {
            service_name: target.service,
            backend: selected.backend,
            body,
            request_timeout: selected.request_timeout,
            sticky_new_session: selected.sticky_new_session,
            identity,
        })
    }
}

struct SelectedBackend {
    backend: Arc<Backend>,
    request_timeout: Duration,
    sticky_new_session: Option<String>,
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
    let request_timeout = load_balancer.request_timeout();
    let mut sticky_new_session = None;
    let sticky_backend = state.sticky_managers.get(service).and_then(|manager| {
        let session_id = headers
            .get("cookie")
            .and_then(|value| value.to_str().ok())
            .and_then(|cookie| manager.extract_session_id(cookie));
        manager
            .select_backend(session_id, load_balancer.backends())
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
        limiter.select_with_capacity(load_balancer.backends())
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
        request_timeout,
        sticky_new_session,
    })
}
