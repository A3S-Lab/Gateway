//! gRPC protocol handler

use crate::entrypoint::protocol::{ProtocolContext, ResponseBody};
use crate::proxy::grpc::GrpcProxy;
use bytes::Bytes;
use http::Response;
use std::sync::Arc;

pub async fn handle_grpc_dispatch(
    ctx: ProtocolContext,
    grpc_proxy: Arc<GrpcProxy>,
) -> Response<ResponseBody> {
    let _inference_admission = ctx.inference_admission;
    let backend = ctx.backend.clone();
    let state = ctx.state.clone();
    let route = ctx.route.clone();
    let req_parts = ctx.req_parts;
    let body_bytes = ctx.body_bytes;
    let pipeline = ctx.pipeline;
    let access_log = ctx.access_log;
    let request_start = ctx.request_start;

    match grpc_proxy
        .forward(
            &backend,
            &req_parts.method,
            &req_parts.uri,
            &req_parts.headers,
            body_bytes,
        )
        .await
    {
        Ok(grpc_resp) => {
            let status_code = grpc_resp.http_status.as_u16();

            if let Some(phc) = state.passive_health.get(&route.service_name) {
                if phc.is_error_status(status_code) {
                    phc.record_error(&backend, status_code);
                } else {
                    phc.record_success(&backend);
                }
            }

            let mut resp_builder = http::Response::builder().status(grpc_resp.http_status.as_u16());
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

            let body_len = grpc_resp.body.len() as u64;
            state.metrics.record_request(status_code, body_len);
            state.metrics.record_router_latency(
                &route.router_name,
                request_start.elapsed().as_micros() as u64,
            );
            if status_code >= 400 {
                state.metrics.record_router_error(&route.router_name);
                state.metrics.record_service_error(&route.service_name);
            }

            let client_status = resp_parts.status.as_u16();
            let response = builder
                .body(crate::entrypoint::protocol::full_body(grpc_resp.body))
                .unwrap();
            if let Some(access_log) = access_log {
                access_log.finish(client_status, body_len);
            }
            response
        }
        Err(e) => {
            tracing::error!(error = %e, backend = backend.url, "gRPC proxy error");
            if let Some(phc) = state.passive_health.get(&route.service_name) {
                phc.record_error(&backend, 502);
            }

            state.metrics.record_request(502, 0);
            state.metrics.record_router_latency(
                &route.router_name,
                request_start.elapsed().as_micros() as u64,
            );
            state.metrics.record_router_error(&route.router_name);
            state.metrics.record_service_error(&route.service_name);

            let (mut err_parts, _) = http::Response::builder()
                .status(502)
                .body(())
                .unwrap()
                .into_parts();
            if let Err(mw_err) = pipeline.process_response(&mut err_parts).await {
                tracing::warn!(error = %mw_err, "Response middleware error on gRPC 502");
            }
            let mut builder = http::Response::builder().status(502);
            for (key, value) in err_parts.headers.iter() {
                builder = builder.header(key, value);
            }
            let body = Bytes::from(format!(r#"{{"error":"{}"}}"#, e));
            let response_bytes = body.len() as u64;
            let response = builder
                .body(crate::entrypoint::protocol::full_body(body))
                .unwrap();
            if let Some(access_log) = access_log {
                access_log.finish(502, response_bytes);
            }
            response
        }
    }
}
