//! OpenAI presentation adapter for Gateway-owned prefill/decode execution.

use crate::entrypoint::inference_dispatch::PreparedDistributedAttempt;
use crate::entrypoint::protocol::{ProtocolContext, ResponseBody};
use crate::inference::{
    DistributedExecutionRequest, DistributedInferenceResponse, DistributedServingError,
    DistributedWorkerEndpoint, InferenceAdmissionGuard, InferenceAttemptIdentity, ProtocolBinding,
};
use crate::observability::access_log::{AccessLogGuard, RequestAccessLog};
use crate::observability::metrics::ServiceRequestGuard;
use crate::service::{Backend, BackendConnectionGuard};
use crate::usage::{track_usage_response, UsageRequestLifecycle, UsageTerminalOutcome};
use bytes::Bytes;
use futures_util::StreamExt as _;
use http::{HeaderValue, Response, StatusCode};
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::Frame;
use std::sync::Arc;

pub(crate) async fn handle_distributed_dispatch(
    ctx: ProtocolContext,
    mut distributed: PreparedDistributedAttempt,
) -> Response<ResponseBody> {
    let ProtocolContext {
        mut route,
        mut backend,
        mut req_parts,
        mut body_bytes,
        pipeline,
        state,
        mut access_log,
        request_start,
        inference_admission,
        inference_attempt,
        mut usage_lifecycle,
        inference_dispatch,
        mut service_request,
        ..
    } = ctx;
    let (Some(mut inference_attempt), Some(mut inference_dispatch)) =
        (inference_attempt, inference_dispatch)
    else {
        return finish_error(
            ResponseTracking {
                state,
                route,
                request_start,
                access_log,
                inference_admission,
                inference_attempt: None,
                usage_lifecycle,
                service_request,
                backend_guards: None,
            },
            &pipeline,
            &req_parts.headers,
            DistributedServingError::InvalidRequest,
        )
        .await;
    };
    let external_model = inference_dispatch.model_alias().to_string();
    let stream = inference_dispatch.stream_requested();

    loop {
        let prefill_backend = distributed.prefill_backend.clone();
        let admitted = admit_worker_pair(&prefill_backend, &backend);
        let (execution, backend_guards) = match admitted {
            Ok(guards) => {
                let request = execution_request(
                    &distributed,
                    &prefill_backend,
                    &backend,
                    &inference_attempt,
                    &external_model,
                    body_bytes.clone(),
                    stream,
                );
                (
                    state.distributed_serving.execute(request).await,
                    Some(guards),
                )
            }
            Err(error) => (Err(error), None),
        };

        match execution {
            Ok(DistributedInferenceResponse::Buffered(body)) => {
                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::OK;
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                let (mut parts, mut body) = response.into_parts();
                if let Err(error) = pipeline
                    .process_buffered_response(&req_parts.headers, &mut parts, &mut body)
                    .await
                {
                    tracing::warn!(error = %error, "Response middleware error on distributed inference");
                }
                return ResponseTracking {
                    state,
                    route,
                    request_start,
                    access_log,
                    inference_admission,
                    inference_attempt: Some(inference_attempt),
                    usage_lifecycle,
                    service_request,
                    backend_guards,
                }
                .finish(Response::from_parts(parts, ResponseBody::full(body)));
            }
            Ok(DistributedInferenceResponse::Streaming(stream)) => {
                let body = StreamBody::new(stream.map(|result| result.map(Frame::data)));
                let mut response = Response::new(ResponseBody::boxed(body));
                *response.status_mut() = StatusCode::OK;
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    HeaderValue::from_static("text/event-stream"),
                );
                response.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    HeaderValue::from_static("no-cache"),
                );
                response.headers_mut().insert(
                    http::HeaderName::from_static("x-accel-buffering"),
                    HeaderValue::from_static("no"),
                );
                let (mut parts, body) = response.into_parts();
                if let Err(error) = pipeline.process_response(&mut parts).await {
                    tracing::warn!(error = %error, "Response middleware error on distributed inference stream");
                }
                return ResponseTracking {
                    state,
                    route,
                    request_start,
                    access_log,
                    inference_admission,
                    inference_attempt: Some(inference_attempt),
                    usage_lifecycle,
                    service_request,
                    backend_guards,
                }
                .finish(Response::from_parts(parts, body));
            }
            Err(error) => {
                drop(backend_guards);
                let error_status = error.status_code();
                tracing::warn!(
                    request_id = %inference_attempt.request().request_id(),
                    attempt_id = %inference_attempt.attempt_id(),
                    target_id = %inference_attempt.target_id(),
                    prefill_backend_id = %prefill_backend.metric_id(),
                    decode_backend_id = %backend.metric_id(),
                    error = %error,
                    "Distributed inference attempt failed before a downstream response"
                );

                if error.retryable_before_response() {
                    match inference_dispatch.prepare_next(
                        &state,
                        &mut req_parts.headers,
                        access_log.as_mut(),
                    ) {
                        Ok(prepared) => {
                            let usage_error = if let Some(lifecycle) = usage_lifecycle.as_mut() {
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
                            if let Some(usage_error) = usage_error {
                                tracing::error!(
                                    error = %usage_error,
                                    "Distributed inference fallback stopped because durable usage became unavailable"
                                );
                            } else if let Some(next_distributed) = prepared.distributed {
                                if state.metrics_enabled {
                                    state.metrics.record_service_error(&route.service_name);
                                }
                                if let Some(request) = service_request.as_mut() {
                                    request.retarget(&prepared.service_name);
                                }
                                Arc::make_mut(&mut route).service_name = prepared.service_name;
                                backend = prepared.backend;
                                body_bytes = prepared.body;
                                inference_attempt = prepared.identity;
                                distributed = next_distributed;
                                continue;
                            } else {
                                tracing::error!(
                                    "Distributed inference fallback violated the model scheduling invariant"
                                );
                            }
                        }
                        Err(preparation_error) => {
                            tracing::warn!(
                                error = ?preparation_error,
                                "Distributed inference fallback exhausted"
                            );
                        }
                    }
                }

                if let Some(lifecycle) = usage_lifecycle.as_mut() {
                    if let Err(usage_error) = lifecycle
                        .finish_attempt(UsageTerminalOutcome::Failed, Some(error_status))
                        .await
                    {
                        tracing::error!(
                            error = %usage_error,
                            "Distributed inference attempt terminal append failed"
                        );
                    }
                }
                return finish_error(
                    ResponseTracking {
                        state,
                        route,
                        request_start,
                        access_log,
                        inference_admission,
                        inference_attempt: Some(inference_attempt),
                        usage_lifecycle,
                        service_request,
                        backend_guards: None,
                    },
                    &pipeline,
                    &req_parts.headers,
                    error,
                )
                .await;
            }
        }
    }
}

fn execution_request(
    distributed: &PreparedDistributedAttempt,
    prefill_backend: &Backend,
    decode_backend: &Backend,
    identity: &InferenceAttemptIdentity,
    external_model: &str,
    body: Bytes,
    stream: bool,
) -> DistributedExecutionRequest {
    let execution_id = identity.attempt_id();
    DistributedExecutionRequest {
        execution_id,
        endpoint: identity.request().endpoint(),
        external_model: external_model.to_string(),
        body,
        stream,
        api_key_env: distributed.config.api_key_env.clone(),
        execution_timeout_ms: distributed.config.execution_timeout_ms,
        prefill: DistributedWorkerEndpoint {
            url: prefill_backend.url.clone(),
            binding: ProtocolBinding {
                execution_id,
                worker_epoch: distributed.workers.prefill.worker_epoch,
                execution_profile_sha256: distributed
                    .workers
                    .prefill
                    .execution_profile_sha256
                    .clone(),
            },
        },
        decode: DistributedWorkerEndpoint {
            url: decode_backend.url.clone(),
            binding: ProtocolBinding {
                execution_id,
                worker_epoch: distributed.workers.decode.worker_epoch,
                execution_profile_sha256: distributed
                    .workers
                    .decode
                    .execution_profile_sha256
                    .clone(),
            },
        },
    }
}

fn admit_worker_pair(
    prefill: &Arc<Backend>,
    decode: &Arc<Backend>,
) -> Result<DistributedBackendGuards, DistributedServingError> {
    let prefill = prefill
        .try_track_connection_on(0)
        .ok_or(DistributedServingError::WorkerAdmissionClosed)?;
    let decode = decode
        .try_track_connection_on(0)
        .ok_or(DistributedServingError::WorkerAdmissionClosed)?;
    Ok(DistributedBackendGuards {
        _prefill: prefill,
        _decode: decode,
    })
}

async fn finish_error(
    tracking: ResponseTracking,
    pipeline: &crate::middleware::Pipeline,
    request_headers: &http::HeaderMap,
    error: DistributedServingError,
) -> Response<ResponseBody> {
    let status = StatusCode::from_u16(error.status_code()).unwrap_or(StatusCode::BAD_GATEWAY);
    let body = match status {
        StatusCode::SERVICE_UNAVAILABLE => Bytes::from_static(
            br#"{"error":{"message":"Distributed inference is temporarily unavailable.","type":"server_error","param":null,"code":"distributed_inference_unavailable"}}"#,
        ),
        StatusCode::GATEWAY_TIMEOUT => Bytes::from_static(
            br#"{"error":{"message":"Distributed inference timed out.","type":"server_error","param":null,"code":"distributed_inference_timeout"}}"#,
        ),
        _ => Bytes::from_static(
            br#"{"error":{"message":"Distributed inference failed.","type":"server_error","param":null,"code":"distributed_inference_failed"}}"#,
        ),
    };
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let (mut parts, mut body) = response.into_parts();
    if let Err(middleware_error) = pipeline
        .process_buffered_response(request_headers, &mut parts, &mut body)
        .await
    {
        tracing::warn!(
            error = %middleware_error,
            status = status.as_u16(),
            "Response middleware error on distributed inference failure"
        );
    }
    tracking.finish(Response::from_parts(parts, ResponseBody::full(body)))
}

struct DistributedBackendGuards {
    _prefill: BackendConnectionGuard,
    _decode: BackendConnectionGuard,
}

struct ResponseTracking {
    state: Arc<crate::entrypoint::GatewayState>,
    route: Arc<crate::router::ResolvedRoute>,
    request_start: std::time::Instant,
    access_log: Option<RequestAccessLog>,
    inference_admission: Option<InferenceAdmissionGuard>,
    inference_attempt: Option<InferenceAttemptIdentity>,
    usage_lifecycle: Option<UsageRequestLifecycle>,
    service_request: Option<ServiceRequestGuard>,
    backend_guards: Option<DistributedBackendGuards>,
}

impl ResponseTracking {
    fn finish(mut self, mut response: Response<ResponseBody>) -> Response<ResponseBody> {
        let status = response.status().as_u16();
        if self.state.metrics_enabled {
            self.state.metrics.record_request(status, 0);
            self.state.metrics.record_router_latency(
                &self.route.router_name,
                self.request_start.elapsed().as_micros() as u64,
            );
            if status >= 400 {
                self.state
                    .metrics
                    .record_router_error(&self.route.router_name);
                self.state
                    .metrics
                    .record_service_error(&self.route.service_name);
            }
        }
        if let Some(identity) = self.inference_attempt.as_ref() {
            identity.attach_response_header(&mut response);
        }
        let (parts, body) = response.into_parts();
        let mut access_log = AccessLogGuard::new(self.access_log.take(), status);
        let response_metrics = self
            .state
            .metrics_enabled
            .then(|| self.state.metrics.clone());
        let mut service_request = self.service_request.take();
        let inference_admission = self.inference_admission.take();
        let inference_attempt = self.inference_attempt.take();
        let backend_guards = self.backend_guards.take();
        let body = ResponseBody::boxed(body.map_frame(move |frame| {
            let _inference_admission = &inference_admission;
            let _inference_attempt = &inference_attempt;
            let _backend_guards = &backend_guards;
            if let Some(bytes) = frame.data_ref() {
                if !bytes.is_empty() {
                    if let Some(request) = service_request.as_mut() {
                        request.record_ttft_once();
                    }
                }
                access_log.record_bytes(bytes.len() as u64);
                if let Some(metrics) = response_metrics.as_ref() {
                    metrics.record_response_bytes(bytes.len() as u64);
                }
            }
            frame
        }));
        track_usage_response(
            Response::from_parts(parts, body),
            self.usage_lifecycle.take(),
        )
    }
}
