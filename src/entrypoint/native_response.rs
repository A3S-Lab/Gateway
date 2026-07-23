//! Immediate and native HTTP response completion.

use super::{GatewayState, ResponseBody};
use crate::inference::InferenceRequestIdentity;
use crate::middleware::Pipeline;
use crate::observability::access_log::RequestAccessLog;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Body;

pub(super) fn full_body(bytes: impl Into<Bytes>) -> ResponseBody {
    http_body_util::BodyExt::boxed_unsync(
        http_body_util::Full::new(bytes.into()).map_err(|never| match never {}),
    )
}

pub(super) fn error_response(status: u16, message: &str) -> hyper::Response<ResponseBody> {
    let mut response = hyper::Response::new(full_body(Bytes::from(format!(
        r#"{{"error":"{}"}}"#,
        message
    ))));
    *response.status_mut() =
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    response
}

pub(super) fn finish_access_log(
    access_log: Option<RequestAccessLog>,
    response: hyper::Response<ResponseBody>,
) -> hyper::Response<ResponseBody> {
    if let Some(access_log) = access_log {
        let response_bytes = response.body().size_hint().exact().unwrap_or(0);
        access_log.finish(response.status().as_u16(), response_bytes);
    }
    response
}

pub(super) fn finish_inference_access_log(
    access_log: Option<RequestAccessLog>,
    mut response: hyper::Response<ResponseBody>,
    identity: Option<&InferenceRequestIdentity>,
) -> hyper::Response<ResponseBody> {
    if let Some(identity) = identity {
        identity.attach_response_header(&mut response);
    }
    finish_access_log(access_log, response)
}

async fn apply_native_response_pipeline(
    pipeline: &Pipeline,
    response: hyper::Response<Bytes>,
) -> hyper::Response<ResponseBody> {
    let (mut parts, body) = response.into_parts();
    if let Err(error) = pipeline.process_response(&mut parts).await {
        tracing::warn!(error = %error, "Response middleware error on native response");
    }
    hyper::Response::from_parts(parts, full_body(body))
}

pub(super) async fn finish_native_response(
    pipeline: &Pipeline,
    state: &GatewayState,
    route: &crate::router::ResolvedRoute,
    request_start: std::time::Instant,
    access_log: Option<RequestAccessLog>,
    identity: Option<&InferenceRequestIdentity>,
    response: hyper::Response<Bytes>,
) -> hyper::Response<ResponseBody> {
    let response = apply_native_response_pipeline(pipeline, response).await;
    let status = response.status().as_u16();
    let response_bytes = response.body().size_hint().exact().unwrap_or(0);
    if state.metrics_enabled {
        state.metrics.record_request(status, response_bytes);
        state.metrics.record_router_latency(
            &route.router_name,
            request_start.elapsed().as_micros() as u64,
        );
        if status >= 400 {
            state.metrics.record_router_error(&route.router_name);
            state.metrics.record_service_error(&route.service_name);
        }
    }
    finish_inference_access_log(access_log, response, identity)
}
