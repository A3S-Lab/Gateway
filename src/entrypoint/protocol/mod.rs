//! Protocol handlers for HTTP request dispatch

pub(super) use distributed_handler::handle_distributed_dispatch;
pub use grpc_handler::handle_grpc_dispatch;
pub use http_handler::handle_http_dispatch;
pub(super) use http_handler::proxy_error_status;
pub use streaming_handler::handle_sse_dispatch;
pub use ws_handler::handle_ws_upgrade;

use crate::entrypoint::GatewayState;
use crate::middleware::Pipeline;
use crate::observability::access_log::RequestAccessLog;
pub(crate) use crate::response_body::ResponseBody;
use bytes::Bytes;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

pub fn full_body(bytes: impl Into<Bytes>) -> ResponseBody {
    ResponseBody::full(bytes)
}

pub fn empty_body() -> ResponseBody {
    ResponseBody::full(Bytes::new())
}

pub struct ProtocolContext {
    pub route: Arc<crate::router::ResolvedRoute>,
    pub backend: Arc<crate::service::Backend>,
    pub req_parts: http::request::Parts,
    pub body_bytes: Bytes,
    pub streaming_body: Option<hyper::body::Incoming>,
    pub pipeline: Arc<Pipeline>,
    pub state: Arc<GatewayState>,
    pub forwarded: crate::proxy::ForwardedContext,
    pub prepared_forwarded: Option<Arc<crate::proxy::PreparedForwardedContext>>,
    pub timeouts: crate::service::ServiceTimeouts,
    pub access_log: Option<RequestAccessLog>,
    pub sticky_new_session: Option<String>,
    pub request_start: std::time::Instant,
    pub inference_admission: Option<crate::inference::InferenceAdmissionGuard>,
    pub inference_attempt: Option<crate::inference::InferenceAttemptIdentity>,
    pub usage_lifecycle: Option<crate::usage::UsageRequestLifecycle>,
    pub(super) inference_dispatch:
        Option<crate::entrypoint::inference_dispatch::InferenceDispatchState>,
    pub service_request: Option<crate::observability::metrics::ServiceRequestGuard>,
}

pub struct WsContext {
    pub route: Arc<crate::router::ResolvedRoute>,
    pub state: Arc<GatewayState>,
    pub remote_addr: std::net::SocketAddr,
    pub access_log: Option<RequestAccessLog>,
    pub request_start: std::time::Instant,
    pub service_request: Option<crate::observability::metrics::ServiceRequestGuard>,
    pub backend_connection: crate::service::BackendConnectionGuard,
}

mod body_buffer;
mod distributed_handler;
mod grpc_handler;
mod http_handler;
mod streaming_handler;
mod ws_handler;

/// Execute a replayable upstream operation under the route retry policy.
///
/// Only transport failures that happen before response headers and explicitly
/// retryable upstream statuses are retried. The caller decides whether the
/// request body is replayable and whether a successful result represents a
/// retryable status; this keeps protocol-specific streaming semantics out of
/// the middleware layer.
pub(super) async fn retry_upstream<T, F, Fut, S, O>(
    policy: Option<crate::middleware::RetryPolicy>,
    mut operation: F,
    retryable_result: S,
    mut observe_retry: O,
) -> crate::error::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = crate::error::Result<T>>,
    S: Fn(&T) -> bool,
    O: FnMut(&crate::error::Result<T>),
{
    let max_retries = policy.as_ref().map_or(0, |policy| policy.max_retries);
    let interval = policy.as_ref().map_or(Duration::ZERO, |policy| {
        Duration::from_millis(policy.interval_ms)
    });

    for attempt in 0..=max_retries {
        let result = operation().await;
        let should_retry = match &result {
            Ok(value) => attempt < max_retries && retryable_result(value),
            Err(error) => attempt < max_retries && error.permits_pre_response_fallback(),
        };
        if should_retry {
            // Feed every discarded attempt into health and circuit observers.
            // The caller observes the terminal result after this helper returns.
            observe_retry(&result);
        }
        match result {
            Ok(value) if should_retry => {
                drop(value);
                if !interval.is_zero() {
                    tokio::time::sleep(interval).await;
                }
            }
            Ok(value) => return Ok(value),
            Err(_error) if should_retry => {
                if !interval.is_zero() {
                    tokio::time::sleep(interval).await;
                }
            }
            Err(error) => return Err(error),
        }
    }

    // Keep the helper total even if its control flow is changed or an
    // unvalidated policy is supplied by a programmatic caller.  Middleware
    // configuration currently bounds this path to a finite retry count.
    Err(crate::error::GatewayError::Other(
        "Retry policy exhausted without an upstream result".to_string(),
    ))
}

pub(super) fn request_is_replayable(method: &http::Method, headers: &http::HeaderMap) -> bool {
    matches!(
        *method,
        http::Method::GET
            | http::Method::HEAD
            | http::Method::OPTIONS
            | http::Method::PUT
            | http::Method::DELETE
    ) || headers.contains_key("idempotency-key")
}

pub(super) fn retryable_upstream_status(status: http::StatusCode) -> bool {
    matches!(status.as_u16(), 502..=504)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn retries_only_the_bounded_pre_response_failure() {
        let calls = Arc::new(AtomicUsize::new(0));
        let operation_calls = calls.clone();
        retry_upstream(
            Some(crate::middleware::RetryPolicy {
                max_retries: 2,
                interval_ms: 0,
            }),
            move || {
                let calls = operation_calls.clone();
                async move {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        Err(crate::error::GatewayError::UpstreamTransport(
                            "connection reset".to_string(),
                        ))
                    } else {
                        Ok(())
                    }
                }
            },
            |_: &()| false,
            |_| {},
        )
        .await
        .unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn does_not_retry_non_retryable_errors() {
        let calls = Arc::new(AtomicUsize::new(0));
        let operation_calls = calls.clone();
        let result = retry_upstream(
            Some(crate::middleware::RetryPolicy {
                max_retries: 2,
                interval_ms: 0,
            }),
            move || {
                operation_calls.fetch_add(1, Ordering::SeqCst);
                async {
                    Err(crate::error::GatewayError::Config(
                        "bad request".to_string(),
                    ))
                }
            },
            |_: &()| false,
            |_| {},
        )
        .await;

        assert!(result.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
