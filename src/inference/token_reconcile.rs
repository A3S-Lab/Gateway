//! Reconcile grant token budgets from observed OpenAI usage payloads.

use super::InferenceAdmissionGuard;
use crate::response_body::ResponseBody;
use bytes::Bytes;
use http::Response;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Upper bound for buffering a response body while hunting for usage.
const MAX_USAGE_OBSERVE_BYTES: usize = 256 * 1024;

/// Hold the admission guard until the response body ends, then reconcile the
/// token budget from any observed OpenAI `usage.total_tokens`.
pub(crate) fn track_token_budget_response(
    response: Response<ResponseBody>,
    admission: Option<InferenceAdmissionGuard>,
    observed_total_tokens: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
) -> Response<ResponseBody> {
    if admission.is_none() && observed_total_tokens.is_none() {
        return response;
    }
    let (parts, body) = response.into_parts();
    let body = ResponseBody::boxed(TokenBudgetBody {
        inner: Box::pin(body),
        admission,
        observed_total_tokens,
        observed: Vec::new(),
        truncated: false,
    });
    Response::from_parts(parts, body)
}

fn observe_total_tokens_from_bytes(bytes: &[u8]) -> Option<u64> {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(total) = total_tokens_from_value(&value) {
            return Some(total);
        }
    }
    // SSE: scan `data:` lines for the last usage object.
    let text = std::str::from_utf8(bytes).ok()?;
    let mut found = None;
    for line in text.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(data) {
            if let Some(total) = total_tokens_from_value(&value) {
                found = Some(total);
            }
        }
    }
    found
}

fn total_tokens_from_value(value: &serde_json::Value) -> Option<u64> {
    let usage = value.get("usage")?;
    if let Some(total) = usage
        .get("total_tokens")
        .and_then(serde_json::Value::as_u64)
    {
        return Some(total);
    }
    let prompt = usage
        .get("prompt_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let completion = usage
        .get("completion_tokens")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    if prompt == 0 && completion == 0 && usage.get("prompt_tokens").is_none() {
        return None;
    }
    Some(prompt.saturating_add(completion))
}

struct TokenBudgetBody {
    inner: Pin<Box<ResponseBody>>,
    admission: Option<InferenceAdmissionGuard>,
    observed_total_tokens: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    observed: Vec<u8>,
    truncated: bool,
}

impl TokenBudgetBody {
    fn note_data(&mut self, bytes: &[u8]) {
        if self.truncated || bytes.is_empty() {
            return;
        }
        let remaining = MAX_USAGE_OBSERVE_BYTES.saturating_sub(self.observed.len());
        if remaining == 0 {
            self.truncated = true;
            return;
        }
        let take = bytes.len().min(remaining);
        self.observed.extend_from_slice(&bytes[..take]);
        if take < bytes.len() {
            self.truncated = true;
        }
    }

    fn finish(&mut self) {
        let total = observe_total_tokens_from_bytes(&self.observed);
        if let Some(total) = total {
            if let Some(sink) = self.observed_total_tokens.as_ref() {
                sink.store(total, std::sync::atomic::Ordering::Release);
            }
            if let Some(admission) = self.admission.take() {
                admission.reconcile_tokens(total);
            }
        } else if let Some(admission) = self.admission.take() {
            drop(admission);
        }
        self.observed_total_tokens = None;
    }
}

impl Body for TokenBudgetBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let result = this.inner.as_mut().poll_frame(context);
        let inner_ended = this.inner.is_end_stream();
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.note_data(data);
                }
                if inner_ended {
                    this.finish();
                }
            }
            Poll::Ready(Some(Err(_))) | Poll::Ready(None) => this.finish(),
            Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.admission.is_none()
            && self.observed_total_tokens.is_none()
            && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TokenBudgetBody {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_json_usage_total_tokens() {
        let body =
            br#"{"id":"1","usage":{"prompt_tokens":3,"completion_tokens":7,"total_tokens":10}}"#;
        assert_eq!(observe_total_tokens_from_bytes(body), Some(10));
    }

    #[test]
    fn parses_json_usage_without_total_field() {
        let body = br#"{"usage":{"prompt_tokens":2,"completion_tokens":5}}"#;
        assert_eq!(observe_total_tokens_from_bytes(body), Some(7));
    }

    #[test]
    fn parses_sse_usage_from_last_data_line() {
        let body = b"data: {\"choices\":[]}\n\ndata: {\"usage\":{\"total_tokens\":42}}\n\ndata: [DONE]\n\n";
        assert_eq!(observe_total_tokens_from_bytes(body), Some(42));
    }
}
