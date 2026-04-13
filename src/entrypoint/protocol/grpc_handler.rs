//! gRPC protocol handler

use crate::entrypoint::protocol::{ProtocolContext, ResponseBody};
use crate::proxy::grpc::GrpcProxy;
use bytes::Bytes;
use http::Response;
use std::sync::Arc;

pub async fn handle_grpc_dispatch(ctx: ProtocolContext, grpc_proxy: Arc<GrpcProxy>) -> Response<ResponseBody> {
    let backend = ctx.backend.clone();
    let state = ctx.state.clone();
    let route = ctx.route.clone();
    let req_parts = ctx.req_parts;
    let body_bytes = ctx.body_bytes;
    let pipeline = ctx.pipeline;
    let remote_addr = ctx.remote_addr;
    let entrypoint = ctx.entrypoint;
    let access_tracker = ctx.access_tracker;
    let method_str = ctx.method_str;
    let path = ctx.path;
    let host = ctx.host;
    let request_start = ctx.request_start;

    match grpc_proxy.forward(&backend, &req_parts.method, &req_parts.uri, &req_parts.headers, body_bytes).await {
        Ok(grpc_resp) => {
            let status_code = grpc_resp.http_status.as_u16();
            let _ = access_tracker.build_entry(
                remote_addr.ip().to_string(), method_str, path, host, status_code,
                grpc_resp.body.len() as u64, Some(backend.url.clone()),
                Some(route.router_name.clone()), Some(entrypoint),
                req_parts.headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            );

            if let Some(phc) = state.passive_health.get(&route.service_name) {
                if phc.is_error_status(status_code) { phc.record_error(&backend, status_code); }
                else { phc.record_success(&backend); }
            }

            let mut resp_builder = http::Response::builder().status(grpc_resp.http_status.as_u16());
            for (key, value) in grpc_resp.headers.iter() { resp_builder = resp_builder.header(key, value); }
            let (mut resp_parts, _) = resp_builder.body(()).unwrap().into_parts();

            if let Err(e) = pipeline.process_response(&mut resp_parts).await {
                tracing::warn!(error = %e, "Response middleware error (gRPC)");
            }

            let mut builder = http::Response::builder().status(resp_parts.status);
            for (key, value) in resp_parts.headers.iter() { builder = builder.header(key, value); }

            let body_len = grpc_resp.body.len() as u64;
            state.metrics.record_request(status_code, body_len);
            state.metrics.record_router_latency(&route.router_name, request_start.elapsed().as_micros() as u64);
            if status_code >= 400 {
                state.metrics.record_router_error(&route.router_name);
                state.metrics.record_service_error(&route.service_name);
            }

            builder.body(crate::entrypoint::protocol::full_body(grpc_resp.body)).unwrap()
        }
        Err(e) => {
            tracing::error!(error = %e, backend = backend.url, "gRPC proxy error");
            let _ = access_tracker.build_entry(
                remote_addr.ip().to_string(), method_str, path, host, 502, 0,
                Some(backend.url.clone()), Some(route.router_name.clone()), Some(entrypoint),
                req_parts.headers.get("user-agent").and_then(|v| v.to_str().ok()).map(|s| s.to_string()),
            );
            if let Some(phc) = state.passive_health.get(&route.service_name) { phc.record_error(&backend, 502); }

            state.metrics.record_request(502, 0);
            state.metrics.record_router_latency(&route.router_name, request_start.elapsed().as_micros() as u64);
            state.metrics.record_router_error(&route.router_name);
            state.metrics.record_service_error(&route.service_name);

            let (mut err_parts, _) = http::Response::builder().status(502).body(()).unwrap().into_parts();
            if let Err(mw_err) = pipeline.process_response(&mut err_parts).await {
                tracing::warn!(error = %mw_err, "Response middleware error on gRPC 502");
            }
            let mut builder = http::Response::builder().status(502);
            for (key, value) in err_parts.headers.iter() { builder = builder.header(key, value); }
            builder.body(crate::entrypoint::protocol::full_body(Bytes::from(format!(r#"{{"error":"{}"}}"#, e)))).unwrap()
        }
    }
}
