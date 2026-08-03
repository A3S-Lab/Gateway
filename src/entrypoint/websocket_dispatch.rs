//! WebSocket request validation, backend selection, and upstream preparation.

use super::native_response::{
    error_bytes_response, error_response, finish_access_log, finish_native_response, full_body,
};
use super::protocol::{self, WsContext};
use super::{GatewayState, ResponseBody, UpgradedSessionSender};
use crate::middleware::{Pipeline, RequestContext};
use crate::observability::access_log::RequestAccessLog;
use crate::observability::metrics::ServiceRequestGuard;
use crate::proxy::{websocket, ForwardedContext};
use crate::router::ResolvedRoute;
use std::sync::Arc;
use std::time::Instant;

pub(super) struct WebSocketDispatchContext {
    pub(super) route: ResolvedRoute,
    pub(super) state: Arc<GatewayState>,
    pub(super) pipeline: Arc<Pipeline>,
    pub(super) request_context: RequestContext,
    pub(super) trace_context: crate::observability::tracing::TraceContext,
    pub(super) remote_addr: std::net::SocketAddr,
    pub(super) forwarded: ForwardedContext,
    pub(super) access_log: Option<RequestAccessLog>,
    pub(super) request_start: Instant,
    pub(super) service_request: Option<ServiceRequestGuard>,
    pub(super) upgraded_sessions: UpgradedSessionSender,
}

pub(super) async fn dispatch(
    mut request: hyper::Request<hyper::body::Incoming>,
    context: WebSocketDispatchContext,
) -> hyper::Response<ResponseBody> {
    let WebSocketDispatchContext {
        route,
        state,
        pipeline,
        request_context,
        trace_context,
        remote_addr,
        forwarded,
        mut access_log,
        request_start,
        service_request,
        upgraded_sessions,
    } = context;

    // Middleware receives ordinary request parts but must not replace Hyper's
    // private OnUpgrade extension on the live request.
    let mut middleware_request = http::Request::new(());
    *middleware_request.method_mut() = request.method().clone();
    *middleware_request.uri_mut() = request.uri().clone();
    *middleware_request.version_mut() = request.version();
    *middleware_request.headers_mut() = request.headers().clone();
    let (mut middleware_parts, _) = middleware_request.into_parts();

    match pipeline
        .process_request(&mut middleware_parts, &request_context)
        .await
    {
        Ok(Some(response)) => {
            let (parts, body) = response.into_parts();
            return finish_access_log(
                access_log,
                hyper::Response::from_parts(parts, full_body(body)),
            );
        }
        Ok(None) => {}
        Err(error) => {
            tracing::error!(error = %error, "Middleware error (WebSocket)");
            return finish_access_log(access_log, error_response(500, "Middleware error"));
        }
    }

    *request.method_mut() = middleware_parts.method;
    *request.uri_mut() = middleware_parts.uri;
    *request.version_mut() = middleware_parts.version;
    *request.headers_mut() = middleware_parts.headers;

    let handshake = match websocket::validate_handshake(
        request.method(),
        request.version(),
        request.headers(),
    ) {
        Ok(handshake) => handshake,
        Err(error) => {
            tracing::debug!(error = %error, remote = %remote_addr, "Invalid WebSocket handshake");
            return finish_native_response(
                &pipeline,
                &state,
                &route,
                request_start,
                access_log,
                None,
                error_bytes_response(400, "Invalid WebSocket handshake"),
            )
            .await;
        }
    };
    // Capture this before awaiting the upstream handshake. Hyper removes the
    // upgrade capability if its request extension is not retained.
    let downstream_upgrade = hyper::upgrade::on(&mut request);

    let load_balancer = match state.service_registry.get(&route.service_name) {
        Some(load_balancer) => load_balancer,
        None => {
            return finish_native_response(
                &pipeline,
                &state,
                &route,
                request_start,
                access_log,
                None,
                error_bytes_response(502, "Service not found"),
            )
            .await;
        }
    };
    let request_timeout = load_balancer.timeouts().request_timeout();
    let backend = state
        .scaling
        .as_ref()
        .and_then(|scaling| scaling.revision_routers.get(&route.service_name))
        .and_then(|revision_router| {
            revision_router
                .next_backend()
                .map(|(backend, _revision_name)| backend)
        })
        .or_else(|| load_balancer.next_backend());
    let backend = match backend {
        Some(backend) => backend,
        None => {
            return finish_native_response(
                &pipeline,
                &state,
                &route,
                request_start,
                access_log,
                None,
                error_bytes_response(503, "No healthy backends"),
            )
            .await;
        }
    };
    if let Some(access_log) = access_log.as_mut() {
        access_log.set_backend(backend.url.clone());
    }
    if state.metrics_enabled {
        state.metrics.record_backend_request_id(backend.metric_id());
    }

    if state.tracing_enabled {
        let traceparent = trace_context.to_traceparent();
        if let Ok(value) = http::HeaderValue::from_str(&traceparent) {
            request
                .headers_mut()
                .insert(http::HeaderName::from_static("traceparent"), value);
        }
    }

    let backend_connection = backend.track_connection();
    let upstream_url = websocket::build_ws_url(&backend.url, request.uri());
    let upstream_handshake = match websocket::prepare_upstream(
        &upstream_url,
        request.headers(),
        forwarded,
        request_timeout,
    )
    .await
    {
        Ok(handshake) => handshake,
        Err(error) => {
            let status = match &error {
                crate::error::GatewayError::UpstreamTimeout(_) => 504,
                crate::error::GatewayError::ServiceUnavailable(_)
                | crate::error::GatewayError::UpstreamTransport(_) => 503,
                _ => 502,
            };
            if let Some(passive_health) = state.passive_health.get(&route.service_name) {
                passive_health.record_error(&backend, status);
            }
            tracing::warn!(
                error = %error,
                backend = backend.url,
                "WebSocket upstream handshake failed"
            );
            return finish_native_response(
                &pipeline,
                &state,
                &route,
                request_start,
                access_log,
                None,
                error_bytes_response(status, "WebSocket upstream unavailable"),
            )
            .await;
        }
    };
    let prepared = match upstream_handshake {
        Ok(prepared) => {
            if let Some(passive_health) = state.passive_health.get(&route.service_name) {
                passive_health.record_success(&backend);
            }
            prepared
        }
        Err(rejection) => {
            let status = rejection.status().as_u16();
            if let Some(passive_health) = state.passive_health.get(&route.service_name) {
                if passive_health.is_error_status(status) {
                    passive_health.record_error(&backend, status);
                } else {
                    passive_health.record_success(&backend);
                }
            }
            let mut response =
                error_bytes_response(status, "WebSocket upstream rejected the handshake");
            for (name, value) in rejection.headers() {
                response.headers_mut().append(name.clone(), value.clone());
            }
            return finish_native_response(
                &pipeline,
                &state,
                &route,
                request_start,
                access_log,
                None,
                response,
            )
            .await;
        }
    };

    let websocket_context = WsContext {
        route,
        state,
        remote_addr,
        access_log,
        request_start,
        service_request,
        backend_connection,
    };
    let (response, relay) =
        protocol::handle_ws_upgrade(downstream_upgrade, websocket_context, handshake, prepared);
    if upgraded_sessions.send(relay).is_err() {
        tracing::debug!(
            remote = %remote_addr,
            "WebSocket relay cancelled because the entrypoint is draining"
        );
    }
    response
}
