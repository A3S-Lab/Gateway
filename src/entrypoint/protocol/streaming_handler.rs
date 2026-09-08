//! SSE/Streaming protocol handler

use crate::entrypoint::protocol::http_handler::proxy_error_status;
use crate::entrypoint::protocol::{
    request_is_replayable, retry_upstream, retryable_upstream_status, ProtocolContext, ResponseBody,
};
use crate::observability::access_log::AccessLogGuard;
use crate::proxy::{ForwardOptions, HttpTimeouts};
use crate::usage::{track_usage_response, UsageTerminalOutcome};
use crate::inference::track_token_budget_response;
use arc_swap::ArcSwap;
use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use std::sync::Arc;

pub async fn handle_sse_dispatch(ctx: ProtocolContext) -> Response<ResponseBody> {
    let inference_admission = ctx.inference_admission;
    let mut inference_attempt = ctx.inference_attempt;
    let mut inference_dispatch = ctx.inference_dispatch;
    let mut backend = ctx.backend;
    let state = ctx.state.clone();
    let mut route = ctx.route;
    let mut req_parts = ctx.req_parts;
    let mut body_bytes = ctx.body_bytes;
    let pipeline = ctx.pipeline;
    let forwarded = ctx.forwarded;
    let mut access_log = ctx.access_log;
    let request_start = ctx.request_start;
    let mut timeouts = ctx.timeouts;
    let mut sticky_new_session = ctx.sticky_new_session;
    let mut usage_lifecycle = ctx.usage_lifecycle;
    let mut service_request = ctx.service_request;

    loop {
        let retry_policy = if request_is_replayable(&req_parts.method, &req_parts.headers) {
            pipeline.retry_policy()
        } else {
            None
        };
        // Ordinary replayable SSE requests may move to another healthy
        // backend after a discarded pre-response attempt. Managed inference
        // remains pinned to its exact attempt until its fallback state moves.
        let retry_backend = Arc::new(ArcSwap::from(backend.clone()));
        let operation_backend = retry_backend.clone();
        let observer_backend = retry_backend.clone();
        let allow_backend_reselection = inference_dispatch.is_none();
        let service_name = route.service_name.clone();
        let operation_state = state.clone();
        let operation_method = Arc::new(req_parts.method.clone());
        let operation_uri = Arc::new(req_parts.uri.clone());
        let operation_headers = Arc::new(req_parts.headers.clone());
        let operation_body = body_bytes.clone();
        let result = retry_upstream(
            retry_policy,
            || {
                let backend = operation_backend.load_full();
                let state = operation_state.clone();
                let method = operation_method.clone();
                let uri = operation_uri.clone();
                let headers = operation_headers.clone();
                let body = operation_body.clone();
                async move {
                    state
                        .http_proxy
                        .forward_streaming_response_with_options(
                            &backend,
                            method.as_ref(),
                            uri.as_ref(),
                            headers.as_ref(),
                            body,
                            ForwardOptions {
                                context: Some(forwarded),
                                timeouts: Some(HttpTimeouts::new(
                                    timeouts.request_timeout(),
                                    timeouts.stream_idle_timeout(),
                                    timeouts.stream_total_timeout(),
                                )),
                            },
                        )
                        .await
                }
            },
            |response| retryable_upstream_status(response.status),
            |result| match result {
                Ok(response) => {
                    let backend = observer_backend.load_full();
                    pipeline.observe_upstream_response_with_request(
                        &req_parts.extensions,
                        response.status,
                    );
                    if let Some(phc) = state.passive_health.get(&service_name) {
                        phc.record_response(&backend, response.status.as_u16());
                    }
                    if allow_backend_reselection {
                        if let Some(next) =
                            crate::entrypoint::select_retry_backend(&state, &service_name, &backend)
                        {
                            if state.metrics_enabled {
                                state.metrics.record_backend_request_id(next.metric_id());
                            }
                            observer_backend.store(next);
                        }
                    }
                }
                Err(error) => {
                    let backend = observer_backend.load_full();
                    pipeline.observe_upstream_failure_with_request(&req_parts.extensions);
                    if let Some(phc) = state.passive_health.get(&service_name) {
                        phc.record_error(&backend, proxy_error_status(error));
                    }
                    if allow_backend_reselection {
                        if let Some(next) =
                            crate::entrypoint::select_retry_backend(&state, &service_name, &backend)
                        {
                            if state.metrics_enabled {
                                state.metrics.record_backend_request_id(next.metric_id());
                            }
                            observer_backend.store(next);
                        }
                    }
                }
            },
        )
        .await;
        backend = retry_backend.load_full();
        if let Some(access_log) = access_log.as_mut() {
            access_log.set_backend(backend.url.clone());
        }
        match result {
            Ok(stream_resp) => {
                let status_code = stream_resp.status.as_u16();
                pipeline.observe_upstream_response_with_request(
                    &req_parts.extensions,
                    stream_resp.status,
                );

                if let Some(phc) = state.passive_health.get(&route.service_name) {
                    phc.record_response(&backend, status_code);
                }

                let mut upstream_response = http::Response::new(stream_resp.body);
                *upstream_response.status_mut() = stream_resp.status;
                *upstream_response.headers_mut() = stream_resp.headers;
                let (mut resp_parts, upstream_body) = upstream_response.into_parts();

                if !pipeline.is_empty() {
                    if let Err(e) = pipeline
                        .process_response_with_request(&req_parts.headers, &mut resp_parts)
                        .await
                    {
                        tracing::warn!(error = %e, "Response middleware error (SSE)");
                    }
                }

                if let (Some(new_id), Some(sticky_mgr)) = (
                    &sticky_new_session,
                    state.sticky_managers.get(&route.service_name),
                ) {
                    match http::HeaderValue::from_str(&sticky_mgr.build_cookie(new_id)) {
                        Ok(cookie) => {
                            resp_parts.headers.append(http::header::SET_COOKIE, cookie);
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "Sticky-session cookie is invalid");
                        }
                    }
                }

                let client_status = resp_parts.status.as_u16();
                let response_identity = inference_attempt.clone();
                let response_metrics = state.metrics_enabled.then(|| state.metrics.clone());
                let track_response_body = inference_admission.is_some()
                    || inference_attempt.is_some()
                    || service_request.is_some()
                    || access_log.is_some()
                    || response_metrics.is_some();
                let hold_admission = inference_admission.is_some();
                let response_body = if track_response_body {
                    let mut access_log_guard = AccessLogGuard::new(access_log, client_status);
                    ResponseBody::boxed(upstream_body.map_frame(move |frame| {
                        let _inference_attempt = &inference_attempt;
                        let _hold_admission = hold_admission;
                        if let Some(bytes) = frame.data_ref() {
                            if !bytes.is_empty() {
                                if let Some(request) = service_request.as_mut() {
                                    request.record_ttft_once();
                                }
                            }
                            access_log_guard.record_bytes(bytes.len() as u64);
                            if let Some(metrics) = response_metrics.as_ref() {
                                metrics.record_response_bytes(bytes.len() as u64);
                            }
                        }
                        frame
                    }))
                } else {
                    ResponseBody::proxy(upstream_body)
                };

                if state.metrics_enabled {
                    state.metrics.record_request(status_code, 0);
                    state.metrics.record_router_latency(
                        &route.router_name,
                        request_start.elapsed().as_micros() as u64,
                    );
                    if status_code >= 400 {
                        state.metrics.record_router_error(&route.router_name);
                        state.metrics.record_service_error(&route.service_name);
                    }
                }

                let mut response = http::Response::from_parts(resp_parts, response_body);
                if let Some(identity) = response_identity.as_ref() {
                    identity.attach_response_header(&mut response);
                }
                let response = track_token_budget_response(response, inference_admission);
                return track_usage_response(response, usage_lifecycle);
            }
            Err(error) => {
                let error_status = proxy_error_status(&error);
                if error.permits_pre_response_fallback() {
                    pipeline.observe_upstream_failure_with_request(&req_parts.extensions);
                    if let Some(phc) = state.passive_health.get(&route.service_name) {
                        phc.record_error(&backend, error_status);
                    }
                }

                if error.permits_pre_response_fallback() {
                    if let Some(dispatch) = inference_dispatch.as_mut() {
                        let failed_service = route.service_name.clone();
                        let failed_backend = backend.url.clone();
                        if let Some(identity) = inference_attempt.as_ref() {
                            tracing::warn!(
                                request_id = %identity.request().request_id(),
                                attempt_id = %identity.attempt_id(),
                                target_id = %identity.target_id(),
                                service = %failed_service,
                                backend = %failed_backend,
                                error = %error,
                                "Managed inference SSE attempt failed before response"
                            );
                        }
                        match dispatch.prepare_next(
                            &state,
                            &mut req_parts.headers,
                            access_log.as_mut(),
                        ) {
                            Ok(prepared) => {
                                let usage_error = if let Some(lifecycle) = usage_lifecycle.as_mut()
                                {
                                    if let Err(error) = lifecycle
                                        .finish_attempt(UsageTerminalOutcome::Fallback, None)
                                        .await
                                    {
                                        Some(error)
                                    } else {
                                        lifecycle.begin_attempt(&prepared.identity).await.err()
                                    }
                                } else {
                                    None
                                };
                                if let Some(error) = usage_error {
                                    tracing::error!(
                                        error = %error,
                                        "Managed inference SSE fallback stopped because durable usage became unavailable"
                                    );
                                } else {
                                    if state.metrics_enabled {
                                        state.metrics.record_service_error(&failed_service);
                                    }
                                    if let Some(request) = service_request.as_mut() {
                                        request.retarget(&prepared.service_name);
                                    }
                                    Arc::make_mut(&mut route).service_name = prepared.service_name;
                                    backend = prepared.backend;
                                    body_bytes = prepared.body;
                                    timeouts = prepared.timeouts;
                                    sticky_new_session = prepared.sticky_new_session;
                                    inference_attempt = Some(prepared.identity);
                                    continue;
                                }
                            }
                            Err(preparation_error) => {
                                tracing::warn!(
                                    service = %failed_service,
                                    backend = %failed_backend,
                                    error = ?preparation_error,
                                    "Managed inference SSE fallback exhausted"
                                );
                            }
                        }
                    }
                }

                if let Some(lifecycle) = usage_lifecycle.as_mut() {
                    if let Err(usage_error) = lifecycle
                        .finish_attempt(UsageTerminalOutcome::Failed, None)
                        .await
                    {
                        tracing::error!(
                            error = %usage_error,
                            "Managed inference SSE attempt terminal append failed"
                        );
                    }
                }
                tracing::error!(error = %error, backend = backend.url, "SSE proxy error");
                if state.metrics_enabled {
                    state.metrics.record_request(error_status, 0);
                    state.metrics.record_router_latency(
                        &route.router_name,
                        request_start.elapsed().as_micros() as u64,
                    );
                    state.metrics.record_router_error(&route.router_name);
                    state.metrics.record_service_error(&route.service_name);
                }

                let (mut err_parts, _) = http::Response::builder()
                    .status(error_status)
                    .body(())
                    .unwrap()
                    .into_parts();
                if let Err(mw_err) = pipeline
                    .process_response_with_request(&req_parts.headers, &mut err_parts)
                    .await
                {
                    tracing::warn!(
                        error = %mw_err,
                        status = error_status,
                        "Response middleware error on SSE proxy failure"
                    );
                }
                let mut builder = http::Response::builder().status(error_status);
                for (key, value) in err_parts.headers.iter() {
                    builder = builder.header(key, value);
                }
                let body = Bytes::from(crate::error::json_error_body(error.to_string()));
                let response_bytes = body.len() as u64;
                let mut response = builder
                    .body(crate::entrypoint::protocol::full_body(body))
                    .unwrap();
                if let Some(identity) = inference_attempt.as_ref() {
                    identity.attach_response_header(&mut response);
                }
                if let Some(access_log) = access_log {
                    access_log.finish(error_status, response_bytes);
                }
                return track_usage_response(response, usage_lifecycle);
            }
        }
    }
}
