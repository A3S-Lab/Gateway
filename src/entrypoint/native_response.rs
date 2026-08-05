//! Immediate and native HTTP response completion.

use super::{GatewayState, ResponseBody};
use crate::inference::InferenceRequestIdentity;
use crate::middleware::Pipeline;
use crate::observability::access_log::RequestAccessLog;
use bytes::Bytes;
use hyper::body::Body;

pub(super) fn full_body(bytes: impl Into<Bytes>) -> ResponseBody {
    ResponseBody::full(bytes)
}

pub(super) fn error_response(status: u16, message: &str) -> hyper::Response<ResponseBody> {
    let response = error_bytes_response(status, message);
    let (parts, body) = response.into_parts();
    hyper::Response::from_parts(parts, full_body(body))
}

pub(super) fn error_bytes_response(status: u16, message: &str) -> hyper::Response<Bytes> {
    let mut response = hyper::Response::new(Bytes::from(format!(r#"{{"error":"{}"}}"#, message)));
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

pub(super) struct BufferedResponsePipeline<'a> {
    pipeline: &'a Pipeline,
    request_headers: &'a http::HeaderMap,
}

impl<'a> BufferedResponsePipeline<'a> {
    pub(super) fn new(pipeline: &'a Pipeline, request_headers: &'a http::HeaderMap) -> Self {
        Self {
            pipeline,
            request_headers,
        }
    }

    async fn apply(self, response: hyper::Response<Bytes>) -> hyper::Response<ResponseBody> {
        let (mut parts, mut body) = response.into_parts();
        if let Err(error) = self
            .pipeline
            .process_buffered_response(self.request_headers, &mut parts, &mut body)
            .await
        {
            tracing::warn!(error = %error, "Response middleware error on native response");
        }
        hyper::Response::from_parts(parts, full_body(body))
    }
}

pub(super) async fn finish_native_response(
    response_pipeline: BufferedResponsePipeline<'_>,
    state: &GatewayState,
    route: &crate::router::ResolvedRoute,
    request_start: std::time::Instant,
    access_log: Option<RequestAccessLog>,
    identity: Option<&InferenceRequestIdentity>,
    response: hyper::Response<Bytes>,
) -> hyper::Response<ResponseBody> {
    let response = response_pipeline.apply(response).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MiddlewareConfig;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use std::io::Read as _;

    #[tokio::test]
    async fn native_buffered_response_runs_compression_transform() {
        let configs = HashMap::from([(
            "compress".to_string(),
            MiddlewareConfig {
                middleware_type: "compress".to_string(),
                ..MiddlewareConfig::default()
            },
        )]);
        let pipeline = Pipeline::from_config(&["compress".to_string()], &configs).unwrap();
        let mut request_headers = http::HeaderMap::new();
        request_headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let response = hyper::Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Bytes::from(vec![b'a'; 2048]))
            .unwrap();

        let response = BufferedResponsePipeline::new(&pipeline, &request_headers)
            .apply(response)
            .await;

        assert_eq!(response.headers()[http::header::CONTENT_ENCODING], "gzip");
        let encoded = response.into_body().collect().await.unwrap().to_bytes();
        let mut decoder = flate2::read::GzDecoder::new(encoded.as_ref());
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, vec![b'a'; 2048]);
    }
}
