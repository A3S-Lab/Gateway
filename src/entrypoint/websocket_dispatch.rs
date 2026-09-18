//! WebSocket request validation, backend selection, and upstream preparation.

use super::native_response::{
    error_bytes_response, finish_native_response, BufferedResponsePipeline,
};
use super::protocol::{self, WsContext};
use super::{GatewayState, ResponseBody, UpgradedSessionSender};
use crate::middleware::{Pipeline, RequestContext};
use crate::observability::access_log::RequestAccessLog;
use crate::observability::metrics::ServiceRequestGuard;
use crate::proxy::{websocket, ForwardedContext};
use std::sync::Arc;
use std::time::Instant;

pub(super) struct WebSocketDispatchContext {
    pub(super) route: Arc<crate::router::ResolvedRoute>,
    pub(super) state: Arc<GatewayState>,
    pub(super) pipeline: Arc<Pipeline>,
    pub(super) request_context: Option<RequestContext>,
    pub(super) trace_context: Option<crate::observability::tracing::TraceContext>,
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

    if let Some(request_context) = request_context {
        // Middleware receives ordinary request parts but must not replace
        // Hyper's private OnUpgrade extension on the live request.
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
                return finish_native_response(
                    BufferedResponsePipeline::new(&pipeline, &middleware_parts.headers),
                    &state,
                    &route,
                    request_start,
                    access_log,
                    None,
                    response.map(bytes::Bytes::from),
                )
                .await;
            }
            Ok(None) => {}
            Err(error) => {
                tracing::error!(error = %error, "Middleware error (WebSocket)");
                return finish_native_response(
                    BufferedResponsePipeline::new(&pipeline, &middleware_parts.headers),
                    &state,
                    &route,
                    request_start,
                    access_log,
                    None,
                    error_bytes_response(500, "Middleware error"),
                )
                .await;
            }
        }

        // Preserve the circuit admission token while keeping Hyper's private
        // upgrade extension on the live request.
        crate::middleware::circuit_breaker::copy_request_tokens(
            &middleware_parts.extensions,
            request.extensions_mut(),
        );
        *request.method_mut() = middleware_parts.method;
        *request.uri_mut() = middleware_parts.uri;
        *request.version_mut() = middleware_parts.version;
        *request.headers_mut() = middleware_parts.headers;
    }

    let handshake = match websocket::validate_handshake(
        request.method(),
        request.version(),
        request.headers(),
    ) {
        Ok(handshake) => handshake,
        Err(error) => {
            tracing::debug!(error = %error, remote = %remote_addr, "Invalid WebSocket handshake");
            return finish_native_response(
                BufferedResponsePipeline::new(&pipeline, request.headers()),
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
                BufferedResponsePipeline::new(&pipeline, request.headers()),
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
    let selected = crate::entrypoint::select_backend_for_service_request(
        &state,
        &route.service_name,
        Some(request.headers()),
    );
    let Some(selected) = selected else {
        return finish_native_response(
            BufferedResponsePipeline::new(&pipeline, request.headers()),
            &state,
            &route,
            request_start,
            access_log,
            None,
            error_bytes_response(503, "No healthy backends"),
        )
        .await;
    };
    let backend = selected.backend;
    let sticky_new_session = selected.sticky_new_session;
    if let Some(access_log) = access_log.as_mut() {
        access_log.set_backend(backend.url.clone());
    }
    if state.metrics_enabled {
        state.metrics.record_backend_request_id(backend.metric_id());
    }

    if let Some(trace_context) = trace_context.as_ref().filter(|_| state.tracing_enabled) {
        let traceparent = trace_context.to_traceparent();
        if let Ok(value) = http::HeaderValue::from_str(&traceparent) {
            request
                .headers_mut()
                .insert(http::HeaderName::from_static("traceparent"), value);
        }
    }

    let Some(backend_connection) = backend.try_track_connection_on(0) else {
        return finish_native_response(
            BufferedResponsePipeline::new(&pipeline, request.headers()),
            &state,
            &route,
            request_start,
            access_log,
            None,
            error_bytes_response(503, "Backend generation is draining"),
        )
        .await;
    };
    let upstream_url = match websocket::build_ws_url(&backend.url, request.uri()) {
        Ok(url) => url,
        Err(error) => {
            tracing::warn!(
                error = %error,
                backend = backend.url,
                "WebSocket upstream URL rejected"
            );
            return finish_native_response(
                BufferedResponsePipeline::new(&pipeline, request.headers()),
                &state,
                &route,
                request_start,
                access_log,
                None,
                error_bytes_response(502, "WebSocket upstream unavailable"),
            )
            .await;
        }
    };
    let upstream_handshake = match websocket::prepare_upstream(
        &upstream_url,
        request.headers(),
        forwarded,
        request_timeout,
        state.ws_tls_for_backend(&route.service_name, &backend),
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
            if error.permits_pre_response_fallback() {
                pipeline.observe_upstream_failure_with_request(request.extensions());
                if let Some(passive_health) = state.passive_health.get(&route.service_name) {
                    passive_health.record_error(&backend, status);
                }
            }
            tracing::warn!(
                error = %error,
                backend = backend.url,
                "WebSocket upstream handshake failed"
            );
            return finish_native_response(
                BufferedResponsePipeline::new(&pipeline, request.headers()),
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
            pipeline.observe_upstream_response_with_request(
                request.extensions(),
                http::StatusCode::SWITCHING_PROTOCOLS,
            );
            if let Some(passive_health) = state.passive_health.get(&route.service_name) {
                passive_health.record_response(&backend, 101);
            }
            prepared
        }
        Err(rejection) => {
            let status = rejection.status().as_u16();
            pipeline
                .observe_upstream_response_with_request(request.extensions(), rejection.status());
            if let Some(passive_health) = state.passive_health.get(&route.service_name) {
                passive_health.record_response(&backend, status);
            }
            let mut response =
                error_bytes_response(status, "WebSocket upstream rejected the handshake");
            for (name, value) in rejection.headers() {
                response.headers_mut().append(name.clone(), value.clone());
            }
            return finish_native_response(
                BufferedResponsePipeline::new(&pipeline, request.headers()),
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

    if let (Some(new_id), Some(sticky_mgr)) = (
        &sticky_new_session,
        state.sticky_managers.get(&route.service_name),
    ) {
        if let Err(error) = http::HeaderValue::from_str(&sticky_mgr.build_cookie(new_id)) {
            // Declared sticky affinity must not soft-skip Set-Cookie on upgrades.
            tracing::error!(
                error = %error,
                service = %route.service_name,
                "sticky session cookie is invalid for WebSocket upgrade"
            );
            return finish_native_response(
                BufferedResponsePipeline::new(&pipeline, request.headers()),
                &state,
                &route,
                request_start,
                access_log,
                None,
                error_bytes_response(500, "Middleware error"),
            )
            .await;
        }
    }

    let websocket_context = WsContext {
        route,
        state,
        remote_addr,
        access_log,
        request_start,
        service_request,
        backend_connection,
        sticky_new_session,
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
