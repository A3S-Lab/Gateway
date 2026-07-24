//! SSE/Streaming protocol handler

use crate::entrypoint::protocol::http_handler::proxy_error_status;
use crate::entrypoint::protocol::{ProtocolContext, ResponseBody};
use crate::observability::access_log::AccessLogGuard;
use crate::usage::{track_usage_response, UsageTerminalOutcome};
use bytes::Bytes;
use futures_util::StreamExt;
use http::Response;
use hyper::body::Frame;

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
    let mut access_log = ctx.access_log;
    let request_start = ctx.request_start;
    let mut timeouts = ctx.timeouts;
    let mut sticky_new_session = ctx.sticky_new_session;
    let mut usage_lifecycle = ctx.usage_lifecycle;
    let mut service_request = ctx.service_request;

    loop {
        match crate::proxy::streaming::forward_streaming(
            &backend,
            &req_parts.method,
            &req_parts.uri,
            &req_parts.headers,
            body_bytes.clone(),
            crate::proxy::streaming::StreamingTimeouts::new(
                timeouts.request_timeout(),
                timeouts.stream_idle_timeout(),
                timeouts.stream_total_timeout(),
            ),
        )
        .await
        {
            Ok(stream_resp) => {
                let status_code = stream_resp.status.as_u16();

                if let Some(phc) = state.passive_health.get(&route.service_name) {
                    if phc.is_error_status(status_code) {
                        phc.record_error(&backend, status_code);
                    } else {
                        phc.record_success(&backend);
                    }
                }

                let mut resp_builder =
                    http::Response::builder().status(stream_resp.status.as_u16());
                for (key, value) in stream_resp.headers.iter() {
                    resp_builder = resp_builder.header(key, value);
                }
                let (mut resp_parts, _) = resp_builder.body(()).unwrap().into_parts();

                if let Err(e) = pipeline.process_response(&mut resp_parts).await {
                    tracing::warn!(error = %e, "Response middleware error (SSE)");
                }

                let mut builder = http::Response::builder().status(resp_parts.status);
                for (key, value) in resp_parts.headers.iter() {
                    builder = builder.header(key, value);
                }

                if let (Some(new_id), Some(sticky_mgr)) = (
                    &sticky_new_session,
                    state.sticky_managers.get(&route.service_name),
                ) {
                    builder = builder.header("Set-Cookie", sticky_mgr.build_cookie(new_id));
                }

                let client_status = resp_parts.status.as_u16();
                let mut access_log_guard = AccessLogGuard::new(access_log, client_status);
                let response_identity = inference_attempt.clone();
                let mapped = stream_resp.body_stream.map(move |result| {
                    let _inference_admission = &inference_admission;
                    let _inference_attempt = &inference_attempt;
                    if let Ok(bytes) = &result {
                        if !bytes.is_empty() {
                            if let Some(request) = service_request.as_mut() {
                                request.record_ttft_once();
                            }
                        }
                        access_log_guard.record_bytes(bytes.len() as u64);
                    }
                    result.map(Frame::data)
                });
                let stream_body =
                    http_body_util::BodyExt::boxed_unsync(http_body_util::StreamBody::new(mapped));

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

                let mut response = builder.body(stream_body).unwrap();
                if let Some(identity) = response_identity.as_ref() {
                    identity.attach_response_header(&mut response);
                }
                return track_usage_response(response, usage_lifecycle);
            }
            Err(error) => {
                let error_status = proxy_error_status(&error);
                if let Some(phc) = state.passive_health.get(&route.service_name) {
                    phc.record_error(&backend, error_status);
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
                                    route.service_name = prepared.service_name;
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
                if let Err(mw_err) = pipeline.process_response(&mut err_parts).await {
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
                let body = Bytes::from(format!(r#"{{"error":"{}"}}"#, error));
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
