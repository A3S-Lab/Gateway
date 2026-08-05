//! Entrypoint — network listeners for HTTP/HTTPS/TCP
//!
//! Manages the lifecycle of network listeners that accept incoming
//! connections and dispatch them to the router. Supports HTTP, WebSocket,
//! gRPC, SSE/streaming, TCP, and UDP protocols.

mod inference_dispatch;
#[cfg(test)]
mod inference_fallback_tests;
#[cfg(test)]
mod inference_identity_tests;
#[cfg(test)]
mod inference_tests;
#[cfg(test)]
mod inference_usage_tests;
mod listener;
mod native_response;
pub(crate) mod protocol;
#[cfg(test)]
mod tests;
mod udp_listener;
mod websocket_dispatch;

#[cfg(test)]
use listener::start_http_entrypoint;
pub(crate) use listener::{
    start_entrypoints, validate_entrypoints, EntryPointHandles, PreparedEntrypointReconfigure,
};

use inference_dispatch::{InferenceDispatchState, PreparedInferenceAttempt};
use native_response::{
    error_response, finish_access_log, finish_inference_access_log, finish_native_response,
    full_body, BufferedResponsePipeline,
};
use protocol::ProtocolContext;

use crate::inference::{
    collect_json_body, models_response, AuthenticatedInference, InferenceAccessError,
    InferenceAdmissionGuard, InferenceAuthorizer, InferenceRequestIdentity, OpenAiRequestProfile,
};
use crate::middleware::{Pipeline, RequestContext};
use crate::observability::access_log::RequestAccessLog;
use crate::proxy::{
    ForwardOptions, ForwardedContext, ForwardedProto, HttpProxy, HttpTimeouts,
    OwnedStreamingRequest, PreparedForwardedContext,
};
use crate::response_body::ResponseBody;
use crate::router::RouterTable;
use crate::scaling::buffer::RequestBuffer;
use crate::scaling::concurrency::ConcurrencyLimiter;
use crate::scaling::revision::RevisionRouter;
use crate::service::passive_health::PassiveHealthCheck;
use crate::service::sticky::StickySessionManager;
use crate::service::{Backend, LoadBalancer, ServiceRegistry};
use crate::usage::{track_usage_response, UsageRequestLifecycle};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

type UpgradedSession = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
type UpgradedSessionSender = tokio::sync::mpsc::UnboundedSender<UpgradedSession>;

pub(super) struct HttpConnectionContext {
    remote_addr: SocketAddr,
    entrypoint: Arc<str>,
    forwarded: ForwardedContext,
    prepared_forwarded: Option<Arc<PreparedForwardedContext>>,
    upgraded_sessions: UpgradedSessionSender,
}

impl HttpConnectionContext {
    pub(super) fn new(
        remote_addr: SocketAddr,
        entrypoint: Arc<str>,
        forwarded_proto: ForwardedProto,
        local_port: u16,
        upgraded_sessions: UpgradedSessionSender,
    ) -> Self {
        let forwarded = ForwardedContext::new(remote_addr, forwarded_proto);
        Self {
            remote_addr,
            entrypoint,
            forwarded,
            prepared_forwarded: PreparedForwardedContext::new(forwarded, local_port)
                .map(Arc::new)
                .ok(),
            upgraded_sessions,
        }
    }
}

fn inference_service_is_available(state: &GatewayState, service: &str) -> bool {
    let primary_is_available = if let Some(revision_router) = state
        .scaling
        .as_ref()
        .and_then(|scaling| scaling.revision_routers.get(service))
    {
        revision_router.has_healthy_backend()
    } else {
        state
            .service_registry
            .get(service)
            .is_some_and(|load_balancer| load_balancer.healthy_count() > 0)
    };
    primary_is_available
        || state
            .failovers
            .get(service)
            .is_some_and(|failover| failover.has_healthy_backend())
}

/// Scaling-related state for services with autoscaling enabled
pub struct ScalingState {
    /// Per-service request buffers (for scale-from-zero)
    pub buffers: HashMap<String, Arc<RequestBuffer>>,
    /// Per-service concurrency limiters
    pub limiters: HashMap<String, Arc<ConcurrencyLimiter>>,
    /// Per-service revision routers
    pub revision_routers: HashMap<String, Arc<RevisionRouter>>,
}

/// Startup-bound single-backend inputs for a direct ordinary HTTP route.
pub(crate) struct DirectHttpBinding {
    pub backend: Arc<Backend>,
    pub timeouts: HttpTimeouts,
}

/// Startup-bound middleware and service objects for one compiled HTTP route.
pub(crate) struct RoutePlan {
    pub pipeline: Arc<Pipeline>,
    pub load_balancer: Arc<LoadBalancer>,
    pub passive_health: Arc<PassiveHealthCheck>,
    /// This route has no middleware or service features that require the
    /// general request dispatcher. Protocol and observability checks remain
    /// request-scoped before the direct HTTP path is selected.
    pub direct_http_eligible: bool,
    /// Preselected single backend and timeout policy for the common direct
    /// route shape. Multi-backend routes retain request-time selection.
    pub direct_http_binding: Option<DirectHttpBinding>,
}

/// Shared state for request handling
pub struct GatewayState {
    pub router_table: Arc<RouterTable>,
    /// Route plans in the same order as `router_table` runtime indices.
    pub route_plans: Box<[RoutePlan]>,
    pub service_registry: Arc<ServiceRegistry>,
    /// Optional exact-snapshot inference authorization runtime.
    pub inference_authorizer: Option<Arc<InferenceAuthorizer>>,
    /// Optional node-local durable lifecycle spool for managed inference.
    pub usage_spool: Option<Arc<crate::usage::UsageSpool>>,
    pub http_proxy: Arc<HttpProxy>,
    /// gRPC proxy (HTTP/2 with h2c support)
    pub grpc_proxy: Arc<crate::proxy::grpc::GrpcProxy>,
    /// Scaling state (None if no service has scaling config)
    pub scaling: Option<Arc<ScalingState>>,
    /// Traffic mirrors: service_name → TrafficMirror
    pub mirrors: HashMap<String, Arc<crate::service::TrafficMirror>>,
    /// Failover selectors: service_name → FailoverSelector
    pub failovers: HashMap<String, Arc<crate::service::FailoverSelector>>,
    /// Structured access log (counter + background task target)
    pub access_log: Arc<crate::observability::access_log::AccessLog>,
    /// Channel for fire-and-forget log entries — background task does JSON + tracing
    pub log_tx:
        tokio::sync::mpsc::UnboundedSender<crate::observability::access_log::AccessLogEntry>,
    /// Sticky session managers (only for services with sticky config)
    pub sticky_managers: HashMap<String, Arc<StickySessionManager>>,
    /// Passive health checkers for all services
    pub passive_health: HashMap<String, Arc<PassiveHealthCheck>>,
    /// Gateway-wide metrics collector
    pub metrics: Arc<crate::observability::metrics::GatewayMetrics>,
    /// Current process-wide graceful-drain deadline.
    pub shutdown_timeout: Duration,
    /// Whether metrics recording is enabled (hot-path flag)
    pub metrics_enabled: bool,
    /// Whether access logging is enabled (hot-path flag)
    pub access_log_enabled: bool,
    /// Whether distributed tracing is enabled (hot-path flag)
    pub tracing_enabled: bool,
}

/// Shared runtime snapshot used by entrypoints.
///
/// Listeners keep this handle for their lifetime and clone the current
/// `GatewayState` for each new request/connection. Reload can replace the
/// snapshot without rebinding unchanged traffic ports.
#[derive(Clone)]
pub struct GatewayRuntime {
    current: Arc<ArcSwap<GatewayState>>,
}

impl GatewayRuntime {
    pub fn new(state: Arc<GatewayState>) -> Self {
        Self {
            current: Arc::new(ArcSwap::from(state)),
        }
    }

    pub fn load(&self) -> Arc<GatewayState> {
        self.current.load_full()
    }

    pub fn replace(&self, state: Arc<GatewayState>) {
        self.current.store(state);
    }
}

fn request_trace_context(
    headers: &http::HeaderMap,
    tracing_enabled: bool,
) -> Option<crate::observability::tracing::TraceContext> {
    tracing_enabled.then(|| {
        crate::observability::tracing::extract_trace_context(headers)
            .unwrap_or_else(crate::observability::tracing::TraceContext::new_root)
    })
}

/// Forward a feature-free ordinary HTTP route without constructing the
/// general protocol-dispatch state. The caller proves that observability,
/// inference, middleware, mirroring, sticky sessions, failover, and scaling
/// are inactive for this request.
async fn handle_direct_http_request(
    req: hyper::Request<Incoming>,
    state: &GatewayState,
    route_plan: &RoutePlan,
    forwarded: ForwardedContext,
    prepared_forwarded: Option<&PreparedForwardedContext>,
) -> hyper::Response<ResponseBody> {
    let load_balancer = route_plan.load_balancer.as_ref();
    let bound_backend = route_plan.direct_http_binding.as_ref();
    let selected_backend = if bound_backend.is_none() {
        load_balancer.next_backend()
    } else {
        None
    };
    let (backend, timeouts) = if let Some(binding) = bound_backend {
        if !binding.backend.is_healthy() {
            return error_response(503, "No healthy backends");
        }
        (&binding.backend, binding.timeouts)
    } else {
        let Some(backend) = selected_backend.as_ref() else {
            return error_response(503, "No healthy backends");
        };
        let timeouts = load_balancer.timeouts();
        (
            backend,
            HttpTimeouts::new(
                timeouts.request_timeout(),
                timeouts.stream_idle_timeout(),
                timeouts.stream_total_timeout(),
            ),
        )
    };
    let (parts, body) = req.into_parts();
    let result = state
        .http_proxy
        .forward_streaming_exchange_owned(
            &backend,
            OwnedStreamingRequest {
                method: parts.method,
                uri: parts.uri,
                headers: parts.headers,
                body,
            },
            ForwardOptions {
                context: Some(forwarded),
                timeouts: Some(timeouts),
            },
            prepared_forwarded,
        )
        .await;

    match result {
        Ok(proxy_response) => {
            route_plan
                .passive_health
                .record_response(&backend, proxy_response.status.as_u16());
            let mut response = hyper::Response::new(ResponseBody::proxy(proxy_response.body));
            *response.status_mut() = proxy_response.status;
            *response.headers_mut() = proxy_response.headers;
            response
        }
        Err(error) => {
            let status = protocol::proxy_error_status(&error);
            route_plan.passive_health.record_error(&backend, status);
            tracing::error!(error = %error, backend = backend.url, "Proxy error");
            let mut response = hyper::Response::new(ResponseBody::full(Bytes::from(format!(
                r#"{{"error":"{}"}}"#,
                error
            ))));
            *response.status_mut() =
                http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::BAD_GATEWAY);
            response
        }
    }
}

/// Handle an individual HTTP request, dispatching to the correct protocol proxy.
///
/// Protocol detection order:
/// 1. WebSocket upgrade (Upgrade: websocket) → bidirectional relay
/// 2. gRPC (Content-Type: application/grpc) → HTTP/2 h2c proxy
/// 3. SSE (`Accept: text/event-stream` or native OpenAI `stream: true`) →
///    streaming passthrough
/// 4. Plain HTTP → buffered reverse proxy
async fn handle_http_request(
    mut req: hyper::Request<Incoming>,
    state: Arc<GatewayState>,
    connection: Arc<HttpConnectionContext>,
) -> std::result::Result<hyper::Response<ResponseBody>, hyper::Error> {
    let remote_addr = connection.remote_addr;
    let entrypoint = connection.entrypoint.as_ref();
    // Detect protocol from request headers.
    let is_ws = crate::proxy::websocket::is_websocket_upgrade(req.headers());
    let is_grpc = crate::proxy::grpc::is_grpc_request(req.headers());
    let mut is_sse = crate::proxy::streaming::is_streaming_request(req.headers());

    let mut access_log = if state.access_log_enabled {
        let host = req
            .headers()
            .get("Host")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let user_agent = req
            .headers()
            .get("user-agent")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Some(RequestAccessLog::new(
            state.access_log.start_request(),
            state.log_tx.clone(),
            remote_addr.ip().to_string(),
            req.method().as_str().to_owned(),
            req.uri().path().to_owned(),
            host,
            entrypoint.to_owned(),
            user_agent,
        ))
    } else {
        None
    };

    // Build a trace only when propagation is enabled. Managed inference can
    // still create one lazily below when it needs a stable request identity.
    let mut trace_ctx = request_trace_context(req.headers(), state.tracing_enabled);

    // Route the request.
    let (mut route, route_plan_index) = match state.router_table.match_request_cached(
        req.headers()
            .get("Host")
            .and_then(|value| value.to_str().ok()),
        req.uri().path(),
        req.method().as_str(),
        req.headers(),
        entrypoint,
    ) {
        Some(route) => route,
        None => {
            if state.metrics_enabled {
                state.metrics.record_request(404, 0);
            }
            return Ok(finish_access_log(
                access_log,
                error_response(404, "No route matched"),
            ));
        }
    };
    if let Some(access_log) = access_log.as_mut() {
        access_log.set_router(route.router_name.clone());
    }
    let inference_authorizer = state
        .inference_authorizer
        .as_ref()
        .filter(|authorizer| authorizer.owns_router(&route.router_name))
        .cloned();
    let forwarded = connection.forwarded;

    // Middleware and service objects are bound to the sorted route at startup,
    // so the request path uses one checked array lookup instead of name hashes.
    let Some(route_plan) = state.route_plans.get(route_plan_index) else {
        tracing::error!(
            router = %route.router_name,
            "Pre-compiled route plan is missing"
        );
        return Ok(finish_access_log(
            access_log,
            error_response(500, "Internal server error"),
        ));
    };
    let direct_http = route_plan.direct_http_eligible
        && inference_authorizer.is_none()
        && !state.metrics_enabled
        && !state.access_log_enabled
        && !state.tracing_enabled
        && !is_ws
        && !is_grpc
        && !is_sse
        && OpenAiRequestProfile::match_request(req.method(), req.uri().path()).is_none();
    if direct_http {
        return Ok(handle_direct_http_request(
            req,
            state.as_ref(),
            route_plan,
            forwarded,
            connection.prepared_forwarded.as_deref(),
        )
        .await);
    }

    let request_start = std::time::Instant::now();

    // Ordinary routes retain their existing route-time service accounting.
    // Managed inference routes select a service only after authorization and
    // model resolution, so their service count is recorded at that point.
    if state.metrics_enabled {
        state.metrics.record_router_request(&route.router_name);
        if inference_authorizer.is_none() {
            state.metrics.record_service_request(&route.service_name);
        }
    }
    let mut service_request = if state.metrics_enabled && inference_authorizer.is_none() {
        state
            .metrics
            .track_service_request(&route.service_name, request_start)
    } else {
        None
    };
    let pipeline = route_plan.pipeline.clone();

    let request_context = (!pipeline.is_empty()).then(|| RequestContext {
        client_ip: remote_addr.ip().to_string(),
        entrypoint: entrypoint.to_owned(),
        router: route.router_name.clone(),
    });

    // A router present in the managed inference policy is a closed native
    // surface. Authenticate before request middleware or body collection, and
    // remove the client credential before any later upstream dispatch.
    let mut managed_openai_profile = None;
    let mut authenticated_inference: Option<(Arc<InferenceAuthorizer>, AuthenticatedInference)> =
        None;
    let mut inference_admission: Option<InferenceAdmissionGuard> = None;
    let mut inference_request_identity: Option<InferenceRequestIdentity> = None;
    let mut inference_dispatch: Option<InferenceDispatchState> = None;
    let mut prepared_inference_attempt: Option<PreparedInferenceAttempt> = None;
    let mut usage_lifecycle: Option<UsageRequestLifecycle> = None;
    if let Some(authorizer) = inference_authorizer {
        let Some(profile) = OpenAiRequestProfile::match_request(req.method(), req.uri().path())
        else {
            return Ok(finish_native_response(
                BufferedResponsePipeline::new(&pipeline, req.headers()),
                &state,
                &route,
                request_start,
                access_log,
                None,
                InferenceAccessError::Denied.into_response(),
            )
            .await);
        };
        if is_ws || is_grpc {
            return Ok(finish_native_response(
                BufferedResponsePipeline::new(&pipeline, req.headers()),
                &state,
                &route,
                request_start,
                access_log,
                None,
                InferenceAccessError::Denied.into_response(),
            )
            .await);
        }
        let authenticated = match authorizer
            .authenticate(
                &route.router_name,
                profile,
                req.headers(),
                chrono::Utc::now(),
            )
            .await
        {
            Ok(authenticated) => authenticated,
            Err(error) => {
                return Ok(finish_native_response(
                    BufferedResponsePipeline::new(&pipeline, req.headers()),
                    &state,
                    &route,
                    request_start,
                    access_log,
                    None,
                    error.into_response(),
                )
                .await);
            }
        };
        let trace_id = trace_ctx
            .get_or_insert_with(crate::observability::tracing::TraceContext::new_root)
            .trace_id
            .clone();
        let identity =
            match authorizer.request_identity(authenticated, profile, trace_id, chrono::Utc::now())
            {
                Ok(identity) => identity,
                Err(error) => {
                    return Ok(finish_native_response(
                        BufferedResponsePipeline::new(&pipeline, req.headers()),
                        &state,
                        &route,
                        request_start,
                        access_log,
                        None,
                        error.into_response(),
                    )
                    .await);
                }
            };
        req.headers_mut().remove(http::header::AUTHORIZATION);
        identity.prepare_request_headers(req.headers_mut());
        if let Some(access_log) = access_log.as_mut() {
            access_log.set_inference_request(&identity);
        }
        managed_openai_profile = Some(profile);
        authenticated_inference = Some((authorizer, authenticated));
        inference_request_identity = Some(identity);
    }

    // ── WebSocket upgrade path ───────────────────────────────────────────────
    // Must be handled before req.into_parts() since hyper::upgrade::on() needs
    // the full Request<Incoming>.
    if is_ws {
        return Ok(websocket_dispatch::dispatch(
            req,
            websocket_dispatch::WebSocketDispatchContext {
                route,
                state,
                pipeline,
                request_context,
                trace_context: trace_ctx,
                remote_addr,
                forwarded,
                access_log,
                request_start,
                service_request,
                upgraded_sessions: connection.upgraded_sessions.clone(),
            },
        )
        .await);
    }

    // ── Non-WebSocket path: consume request body ─────────────────────────────
    let (mut req_parts, body) = req.into_parts();

    // Run request-phase middleware.
    if let Some(request_context) = request_context.as_ref() {
        match pipeline
            .process_request(&mut req_parts, request_context)
            .await
        {
            Ok(Some(response)) => {
                let (resp_parts, body) = response.into_parts();
                let response = hyper::Response::from_parts(resp_parts, full_body(body));
                return Ok(finish_inference_access_log(
                    access_log,
                    response,
                    inference_request_identity.as_ref(),
                ));
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "Middleware error");
                return Ok(finish_inference_access_log(
                    access_log,
                    error_response(500, "Middleware error"),
                    inference_request_identity.as_ref(),
                ));
            }
        }
    }

    // Standalone and ordinary managed routes retain the post-middleware
    // request profile. A policy-bound inference router uses the exact
    // pre-middleware profile authenticated above.
    let openai_profile = managed_openai_profile
        .or_else(|| OpenAiRequestProfile::match_request(&req_parts.method, req_parts.uri.path()));

    if managed_openai_profile == Some(OpenAiRequestProfile::Models) {
        let response_and_admission = authenticated_inference
            .as_ref()
            .ok_or(InferenceAccessError::Unavailable)
            .and_then(|(authorizer, authenticated)| {
                let models = authorizer.allowed_models(*authenticated, chrono::Utc::now())?;
                let response =
                    models_response(&models).map_err(|_| InferenceAccessError::Unavailable)?;
                let admission = authorizer.admit_request(*authenticated, chrono::Utc::now())?;
                Ok((response, admission))
            });
        let (response, admission) = match response_and_admission {
            Ok(response_and_admission) => response_and_admission,
            Err(error) => {
                return Ok(finish_native_response(
                    BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
                    &state,
                    &route,
                    request_start,
                    access_log,
                    inference_request_identity.as_ref(),
                    error.into_response(),
                )
                .await);
            }
        };
        let response = finish_native_response(
            BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
            &state,
            &route,
            request_start,
            access_log,
            inference_request_identity.as_ref(),
            response,
        )
        .await;
        drop(admission);
        return Ok(response);
    }

    // Sample a mirror before optional body collection so an unsampled request
    // keeps its streaming path. Requests that already require buffering defer
    // sampling until service resolution; managed inference can replace the
    // route's placeholder service after parsing the OpenAI body.
    let buffers_without_mirror =
        is_sse || openai_profile.is_some_and(OpenAiRequestProfile::requires_json_body);
    let mut selected_mirror = if buffers_without_mirror {
        None
    } else {
        state
            .mirrors
            .get(&route.service_name)
            .filter(|mirror| mirror.should_mirror())
            .cloned()
    };
    let needs_buffered_body = buffers_without_mirror || selected_mirror.is_some();

    let (body_bytes, streaming_body) = if openai_profile
        .is_some_and(OpenAiRequestProfile::requires_json_body)
    {
        match collect_json_body(&req_parts.headers, body).await {
            Ok(request) => {
                is_sse |= openai_profile.is_some_and(OpenAiRequestProfile::supports_streaming)
                    && request.stream_requested();
                let body = if let Some((authorizer, authenticated)) = &authenticated_inference {
                    let alias = request.model_alias().to_string();
                    let admission =
                        match authorizer.admit_model(*authenticated, &alias, chrono::Utc::now()) {
                            Ok(admission) => admission,
                            Err(error) => {
                                return Ok(finish_native_response(
                                    BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
                                    &state,
                                    &route,
                                    request_start,
                                    access_log,
                                    inference_request_identity.as_ref(),
                                    error.into_response(),
                                )
                                .await);
                            }
                        };
                    let identity = match inference_request_identity.take() {
                        Some(identity) => identity,
                        None => {
                            return Ok(finish_native_response(
                                BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
                                &state,
                                &route,
                                request_start,
                                access_log,
                                None,
                                InferenceAccessError::Unavailable.into_response(),
                            )
                            .await);
                        }
                    };
                    let mut dispatch = InferenceDispatchState::new(
                        authorizer.clone(),
                        *authenticated,
                        alias,
                        request,
                        identity,
                    );
                    let prepared = match dispatch.prepare_next(
                        &state,
                        &mut req_parts.headers,
                        access_log.as_mut(),
                    ) {
                        Ok(prepared) => prepared,
                        Err(error) => {
                            return Ok(finish_native_response(
                                BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
                                &state,
                                &route,
                                request_start,
                                access_log,
                                Some(dispatch.request_identity()),
                                error.into_response(),
                            )
                            .await);
                        }
                    };
                    if let Some(spool) = state.usage_spool.clone() {
                        let lifecycle = match UsageRequestLifecycle::begin(
                            spool,
                            dispatch.request_identity(),
                            *authenticated,
                            dispatch.model_alias(),
                        )
                        .await
                        {
                            Ok(lifecycle) => lifecycle,
                            Err(error) => {
                                tracing::error!(
                                    error = %error,
                                    request_id = %dispatch.request_identity().request_id(),
                                    "Managed inference rejected because durable usage could not start"
                                );
                                return Ok(finish_native_response(
                                    BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
                                    &state,
                                    &route,
                                    request_start,
                                    access_log,
                                    Some(dispatch.request_identity()),
                                    InferenceAccessError::UsageUnavailable.into_response(),
                                )
                                .await);
                            }
                        };
                        usage_lifecycle = Some(lifecycle);
                        if let Some(lifecycle) = usage_lifecycle.as_mut() {
                            if let Err(error) = lifecycle.begin_attempt(&prepared.identity).await {
                                tracing::error!(
                                    error = %error,
                                    request_id = %dispatch.request_identity().request_id(),
                                    attempt_id = %prepared.identity.attempt_id(),
                                    "Managed inference rejected because durable attempt usage could not start"
                                );
                                let response = finish_native_response(
                                    BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
                                    &state,
                                    &route,
                                    request_start,
                                    access_log,
                                    Some(dispatch.request_identity()),
                                    InferenceAccessError::UsageUnavailable.into_response(),
                                )
                                .await;
                                return Ok(track_usage_response(response, usage_lifecycle.take()));
                            }
                        }
                    }
                    let body = prepared.body.clone();
                    inference_request_identity = Some(dispatch.request_identity().clone());
                    prepared_inference_attempt = Some(prepared);
                    inference_dispatch = Some(dispatch);
                    inference_admission = Some(admission);
                    body
                } else {
                    request.into_body()
                };
                let content_length = match http::HeaderValue::from_str(&body.len().to_string()) {
                    Ok(content_length) => content_length,
                    Err(_) => {
                        return Ok(finish_native_response(
                            BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
                            &state,
                            &route,
                            request_start,
                            access_log,
                            inference_request_identity.as_ref(),
                            InferenceAccessError::Unavailable.into_response(),
                        )
                        .await);
                    }
                };
                req_parts
                    .headers
                    .insert(http::header::CONTENT_LENGTH, content_length);
                (body, None)
            }
            Err(error) => {
                return Ok(finish_native_response(
                    BufferedResponsePipeline::new(&pipeline, &req_parts.headers),
                    &state,
                    &route,
                    request_start,
                    access_log,
                    inference_request_identity.as_ref(),
                    error.into_response(),
                )
                .await);
            }
        }
    } else if needs_buffered_body {
        let collected = match BodyExt::collect(body).await {
            Ok(c) => c.to_bytes(),
            Err(_) => Bytes::new(),
        };
        (collected, None)
    } else {
        (Bytes::new(), Some(body))
    };

    // ── Backend selection ─────────────────────────────────────────────────────
    let (backend, service_timeouts, sticky_new_session, mut inference_attempt) =
        if let Some(prepared) = prepared_inference_attempt.take() {
            Arc::make_mut(&mut route).service_name = prepared.service_name;
            if state.metrics_enabled {
                service_request = state
                    .metrics
                    .track_service_request(&route.service_name, request_start);
            }
            (
                prepared.backend,
                prepared.timeouts,
                prepared.sticky_new_session,
                Some(prepared.identity),
            )
        } else {
            let lb = route_plan.load_balancer.as_ref();
            let service_timeouts = lb.timeouts();

            let scaling = state.scaling.as_ref();

            // Step 1: Sticky session — try to honour an existing affinity cookie.
            let mut sticky_new_session: Option<String> = None;
            let backend_from_sticky =
                state
                    .sticky_managers
                    .get(&route.service_name)
                    .and_then(|mgr| {
                        let session_id = req_parts
                            .headers
                            .get("cookie")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|cookie| mgr.extract_session_id(cookie))
                            .map(|s| s.to_string());
                        match mgr.select_backend(session_id.as_deref(), lb.backends()) {
                            Some((backend, new_id)) => {
                                sticky_new_session = new_id;
                                Some(backend)
                            }
                            None => None,
                        }
                    });

            // Step 2: Normal selection (revision router → concurrency limiter → standard LB).
            let backend = if let Some(b) = backend_from_sticky {
                Some(b)
            } else if let Some(rev_router) = state
                .scaling
                .as_ref()
                .and_then(|s| s.revision_routers.get(&route.service_name))
            {
                rev_router.next_backend().map(|(b, _rev_name)| b)
            } else if let Some(limiter) = state
                .scaling
                .as_ref()
                .and_then(|s| s.limiters.get(&route.service_name))
            {
                limiter.select_with_capacity(lb.backends())
            } else {
                lb.next_backend()
            };

            let backend = match backend {
                Some(b) => b,
                None => {
                    // Step 3: Scale-from-zero buffer or failover.
                    if let Some(buffer) = scaling.and_then(|s| s.buffers.get(&route.service_name)) {
                        if buffer.needs_scale_up() {
                            tracing::info!(
                                service = %route.service_name,
                                "Scale-from-zero triggered, buffering request"
                            );
                        }

                        match buffer.wait_for_backend().await {
                            crate::scaling::buffer::BufferResult::Ready => {
                                match lb.next_backend() {
                                    Some(b) => b,
                                    None => {
                                        return Ok(finish_inference_access_log(
                                            access_log,
                                            error_response(
                                                503,
                                                "No healthy backends after scale-up",
                                            ),
                                            inference_request_identity.as_ref(),
                                        ));
                                    }
                                }
                            }
                            crate::scaling::buffer::BufferResult::Timeout => {
                                return Ok(finish_inference_access_log(
                                    access_log,
                                    error_response(504, "Backend scale-up timed out"),
                                    inference_request_identity.as_ref(),
                                ));
                            }
                            crate::scaling::buffer::BufferResult::Overflow => {
                                return Ok(finish_inference_access_log(
                                    access_log,
                                    error_response(503, "Request buffer full"),
                                    inference_request_identity.as_ref(),
                                ));
                            }
                            crate::scaling::buffer::BufferResult::Shutdown => {
                                return Ok(finish_inference_access_log(
                                    access_log,
                                    error_response(503, "Gateway shutting down"),
                                    inference_request_identity.as_ref(),
                                ));
                            }
                        }
                    } else if let Some(failover) = state.failovers.get(&route.service_name) {
                        match failover.next_backend() {
                            Some((b, _is_failover)) => b,
                            None => {
                                return Ok(finish_inference_access_log(
                                    access_log,
                                    error_response(503, "No healthy backends (primary + failover)"),
                                    inference_request_identity.as_ref(),
                                ));
                            }
                        }
                    } else {
                        return Ok(finish_inference_access_log(
                            access_log,
                            error_response(503, "No healthy backends"),
                            inference_request_identity.as_ref(),
                        ));
                    }
                }
            };
            (backend, service_timeouts, sticky_new_session, None)
        };
    if let Some(identity) = inference_attempt.as_ref() {
        identity.prepare_upstream_headers(&mut req_parts.headers);
        if let Some(access_log) = access_log.as_mut() {
            access_log.set_inference_attempt(identity);
        }
    }
    if let Some(access_log) = access_log.as_mut() {
        access_log.set_backend(backend.url.clone());
    }

    // Record per-backend request.
    if state.metrics_enabled && inference_dispatch.is_none() {
        state.metrics.record_backend_request_id(backend.metric_id());
    }

    // Already-buffered traffic is sampled against the final resolved service.
    if buffers_without_mirror {
        selected_mirror = state
            .mirrors
            .get(&route.service_name)
            .filter(|mirror| mirror.should_mirror())
            .cloned();
    }

    // Mirror traffic if selected (fire-and-forget, before primary forward).
    if let Some(mirror) = selected_mirror {
        mirror.mirror_selected_request(
            req_parts.method.clone(),
            req_parts.uri.clone(),
            req_parts.headers.clone(),
            body_bytes.clone(),
        );
    }

    // Inject outbound trace context (W3C traceparent).
    if let Some(trace_ctx) = trace_ctx.as_ref().filter(|_| state.tracing_enabled) {
        let traceparent = trace_ctx.to_traceparent();
        if let Ok(hval) = hyper::header::HeaderValue::from_str(&traceparent) {
            req_parts
                .headers
                .insert(hyper::header::HeaderName::from_static("traceparent"), hval);
        }
    }

    // ── gRPC dispatch ─────────────────────────────────────────────────────────
    if is_grpc {
        let ctx = ProtocolContext {
            route,
            backend,
            req_parts,
            body_bytes,
            streaming_body,
            pipeline,
            state: state.clone(),
            forwarded,
            prepared_forwarded: None,
            timeouts: service_timeouts,
            access_log,
            sticky_new_session,
            request_start,
            inference_admission: inference_admission.take(),
            inference_attempt: inference_attempt.take(),
            usage_lifecycle: usage_lifecycle.take(),
            inference_dispatch: inference_dispatch.take(),
            service_request,
        };
        return Ok(protocol::handle_grpc_dispatch(ctx, state.grpc_proxy.clone()).await);
    }

    // ── SSE / streaming dispatch ──────────────────────────────────────────────
    if is_sse {
        let ctx = ProtocolContext {
            route,
            backend,
            req_parts,
            body_bytes,
            streaming_body: None,
            pipeline,
            state: state.clone(),
            forwarded,
            prepared_forwarded: None,
            timeouts: service_timeouts,
            access_log,
            sticky_new_session,
            request_start,
            inference_admission: inference_admission.take(),
            inference_attempt: inference_attempt.take(),
            usage_lifecycle: usage_lifecycle.take(),
            inference_dispatch: inference_dispatch.take(),
            service_request,
        };
        return Ok(protocol::handle_sse_dispatch(ctx).await);
    }

    // ── Plain HTTP dispatch ───────────────────────────────────────────────────
    {
        let prepared_forwarded =
            if streaming_body.is_some() && pipeline.is_empty() && inference_dispatch.is_none() {
                connection.prepared_forwarded.clone()
            } else {
                None
            };
        let ctx = ProtocolContext {
            route,
            backend,
            req_parts,
            body_bytes,
            streaming_body,
            pipeline,
            state,
            forwarded,
            prepared_forwarded,
            timeouts: service_timeouts,
            access_log,
            sticky_new_session,
            request_start,
            inference_admission,
            inference_attempt,
            usage_lifecycle,
            inference_dispatch,
            service_request,
        };
        Ok(protocol::handle_http_dispatch(ctx).await)
    }
}
