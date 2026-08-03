//! gRPC protocol handler

use crate::entrypoint::protocol::http_handler::proxy_error_status;
use crate::entrypoint::protocol::{ProtocolContext, ResponseBody};
use crate::observability::access_log::AccessLogGuard;
use crate::proxy::grpc::{GrpcProxy, GrpcTimeouts};
use crate::usage::track_usage_response;
use bytes::Bytes;
use http::Response;
use http_body_util::BodyExt;
use std::sync::Arc;

pub async fn handle_grpc_dispatch(
    ctx: ProtocolContext,
    grpc_proxy: Arc<GrpcProxy>,
) -> Response<ResponseBody> {
    let inference_admission = ctx.inference_admission;
    let inference_attempt = ctx.inference_attempt;
    let backend = ctx.backend.clone();
    let state = ctx.state.clone();
    let route = ctx.route.clone();
    let req_parts = ctx.req_parts;
    let body_bytes = ctx.body_bytes;
    let streaming_body = ctx.streaming_body;
    let pipeline = ctx.pipeline;
    let access_log = ctx.access_log;
    let request_start = ctx.request_start;
    let sticky_new_session = ctx.sticky_new_session;
    let usage_lifecycle = ctx.usage_lifecycle;
    let mut service_request = ctx.service_request;
    let timeouts = GrpcTimeouts::new(
        ctx.timeouts.request_timeout(),
        ctx.timeouts.stream_idle_timeout(),
        ctx.timeouts.stream_total_timeout(),
    );

    let proxy_result = if let Some(body) = streaming_body {
        grpc_proxy
            .forward_streaming_body(
                &backend,
                &req_parts.method,
                &req_parts.uri,
                &req_parts.headers,
                body,
                timeouts,
            )
            .await
    } else {
        grpc_proxy
            .forward_buffered_streaming(
                &backend,
                &req_parts.method,
                &req_parts.uri,
                &req_parts.headers,
                body_bytes,
                timeouts,
            )
            .await
    };

    match proxy_result {
        Ok(grpc_resp) => {
            let status_code = grpc_resp.http_status.as_u16();

            if let Some(phc) = state.passive_health.get(&route.service_name) {
                if phc.is_error_status(status_code) {
                    phc.record_error(&backend, status_code);
                } else {
                    phc.record_success(&backend);
                }
            }

            let mut resp_builder = http::Response::builder().status(grpc_resp.http_status);
            for (key, value) in grpc_resp.headers.iter() {
                resp_builder = resp_builder.header(key, value);
            }
            let (mut resp_parts, _) = resp_builder.body(()).unwrap().into_parts();

            if let Err(e) = pipeline.process_response(&mut resp_parts).await {
                tracing::warn!(error = %e, "Response middleware error (gRPC)");
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

            let client_status = resp_parts.status.as_u16();
            let mut access_log_guard = AccessLogGuard::new(access_log, client_status);
            let response_identity = inference_attempt.clone();
            let response_metrics = state.metrics_enabled.then(|| state.metrics.clone());
            let body = grpc_resp
                .body
                .map_frame(move |frame| {
                    let _inference_admission = &inference_admission;
                    let _inference_attempt = &inference_attempt;
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
                })
                .boxed_unsync();
            let mut response = builder.body(body).unwrap();
            if let Some(identity) = response_identity.as_ref() {
                identity.attach_response_header(&mut response);
            }
            track_usage_response(response, usage_lifecycle)
        }
        Err(e) => {
            let error_status = proxy_error_status(&e);
            tracing::error!(error = %e, backend = backend.url, "gRPC proxy error");
            if let Some(phc) = state.passive_health.get(&route.service_name) {
                phc.record_error(&backend, error_status);
            }

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
                tracing::warn!(error = %mw_err, "Response middleware error on gRPC failure");
            }
            let mut builder = http::Response::builder().status(error_status);
            for (key, value) in err_parts.headers.iter() {
                builder = builder.header(key, value);
            }
            let body = Bytes::from(format!(r#"{{"error":"{}"}}"#, e));
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
            track_usage_response(response, usage_lifecycle)
        }
    }
}
