//! Stable OpenAI-compatible managed inference access errors.

use bytes::Bytes;
use http::header::{CONTENT_TYPE, WWW_AUTHENTICATE};
use http::{HeaderValue, Response, StatusCode};

/// Stable native inference authorization and admission failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InferenceAccessError {
    /// No valid inference credential was presented.
    Unauthorized,
    /// The authenticated credential has no matching route, endpoint, or model grant.
    Denied,
    /// The complete authorization snapshot or local verifier is unavailable.
    Unavailable,
    /// Required durable usage evidence cannot be accepted locally.
    UsageUnavailable,
    /// The credential grant has exhausted its local request-rate allowance.
    RateLimited { retry_after_secs: u64 },
    /// The credential grant has reached its local in-flight request cap.
    ConcurrencyLimited,
    /// The model pool's bounded waiting room is full.
    PoolQueueFull,
    /// The model pool could not admit the request before its queue deadline.
    PoolQueueTimeout,
}

impl InferenceAccessError {
    /// Convert a failure into a stable OpenAI-compatible response.
    pub(crate) fn into_response(self) -> Response<Bytes> {
        let (status, body, retry_after_secs) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                br#"{"error":{"message":"Invalid authentication credentials.","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}"#
                    .as_slice(),
                None,
            ),
            Self::Denied => (
                StatusCode::NOT_FOUND,
                br#"{"error":{"message":"The requested inference resource was not found.","type":"invalid_request_error","param":null,"code":"not_found"}}"#
                    .as_slice(),
                None,
            ),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                br#"{"error":{"message":"Inference authorization is temporarily unavailable.","type":"server_error","param":null,"code":"authorization_unavailable"}}"#
                    .as_slice(),
                None,
            ),
            Self::UsageUnavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                br#"{"error":{"message":"Durable inference usage is temporarily unavailable.","type":"server_error","param":null,"code":"usage_unavailable"}}"#
                    .as_slice(),
                None,
            ),
            Self::RateLimited { retry_after_secs } => (
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"error":{"message":"Inference request rate limit exceeded.","type":"rate_limit_error","param":null,"code":"rate_limit_exceeded"}}"#
                    .as_slice(),
                Some(retry_after_secs),
            ),
            Self::ConcurrencyLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"error":{"message":"Inference concurrency limit exceeded.","type":"rate_limit_error","param":null,"code":"concurrency_limit_exceeded"}}"#
                    .as_slice(),
                Some(1),
            ),
            Self::PoolQueueFull => (
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"error":{"message":"Inference pool queue is full.","type":"rate_limit_error","param":null,"code":"pool_queue_full"}}"#
                    .as_slice(),
                Some(1),
            ),
            Self::PoolQueueTimeout => (
                StatusCode::TOO_MANY_REQUESTS,
                br#"{"error":{"message":"Inference pool queue deadline elapsed.","type":"rate_limit_error","param":null,"code":"pool_queue_timeout"}}"#
                    .as_slice(),
                Some(1),
            ),
        };
        let mut response = Response::new(Bytes::from_static(body));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if self == Self::Unauthorized {
            response.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static(r#"Bearer realm="a3s-inference""#),
            );
        }
        if let Some(retry_after_secs) = retry_after_secs {
            if let Ok(retry_after) = HeaderValue::from_str(&retry_after_secs.to_string()) {
                response.headers_mut().insert("retry-after", retry_after);
            }
        }
        response
    }
}
