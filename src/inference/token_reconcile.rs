//! Reconcile grant token budgets from observed OpenAI usage payloads.

use super::InferenceAdmissionGuard;
use crate::response_body::ResponseBody;
use bytes::Bytes;
use http::Response;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Upper bound for buffering a non-SSE JSON response while hunting for usage.
const MAX_JSON_PREFIX_BYTES: usize = 256 * 1024;

/// Rolling tail retained after the JSON prefix truncates. OpenAI places `usage`
/// after `choices`; a bounded tail is enough to recover the object without
/// keeping the whole body.
const MAX_JSON_TAIL_BYTES: usize = 16 * 1024;

/// Incomplete SSE/line remainder retained between body frames. OpenAI usage
/// objects fit in a few hundred bytes; a larger incomplete line is skipped.
const MAX_LINE_CARRY_BYTES: usize = 8 * 1024;

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
        json_prefix: Vec::new(),
        json_truncated: false,
        json_tail: Vec::new(),
        line_carry: Vec::new(),
        skip_until_newline: false,
        sse_total: None,
    });
    Response::from_parts(parts, body)
}

fn observe_json_total_tokens(bytes: &[u8]) -> Option<u64> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes).ok()?;
    total_tokens_from_value(&value)
}

fn total_tokens_from_value(value: &serde_json::Value) -> Option<u64> {
    let usage = value.get("usage")?;
    total_tokens_from_usage_object(usage)
}

fn total_tokens_from_usage_object(usage: &serde_json::Value) -> Option<u64> {
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

/// Recover `usage` from a truncated JSON body by scanning the last `"usage"`
/// object (brace-balanced), without requiring a complete document parse.
fn observe_json_usage_from_tail(bytes: &[u8]) -> Option<u64> {
    if let Some(total) = observe_json_total_tokens(bytes) {
        return Some(total);
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut last = None;
    let mut search_from = 0;
    while let Some(rel) = text[search_from..].find("\"usage\"") {
        let key_at = search_from + rel;
        let after_key = &text[key_at + "\"usage\"".len()..];
        let trimmed = after_key.trim_start();
        if !trimmed.starts_with(':') {
            search_from = key_at + 1;
            continue;
        }
        let after_colon = &trimmed[1..];
        let value = after_colon.trim_start();
        if !value.starts_with('{') {
            search_from = key_at + 1;
            continue;
        }
        if let Some(object) = extract_balanced_json_object(value) {
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(object) {
                if let Some(total) = total_tokens_from_usage_object(&parsed) {
                    last = Some(total);
                }
            }
        }
        search_from = key_at + 1;
    }
    last
}

fn extract_balanced_json_object(input: &str) -> Option<&str> {
    let bytes = input.as_bytes();
    if bytes.first() != Some(&b'{') {
        return None;
    }
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escape = false;
    for (index, &byte) in bytes.iter().enumerate() {
        if in_string {
            if escape {
                escape = false;
            } else if byte == b'\\' {
                escape = true;
            } else if byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&input[..=index]);
                }
            }
            _ => {}
        }
    }
    None
}

fn sse_total_from_complete_line(line: &str) -> Option<u64> {
    let Some(data) = line.strip_prefix("data:") else {
        return None;
    };
    let data = data.trim();
    if data.is_empty() || data == "[DONE]" {
        return None;
    }
    let value = serde_json::from_str::<serde_json::Value>(data).ok()?;
    total_tokens_from_value(&value)
}

struct TokenBudgetBody {
    inner: Pin<Box<ResponseBody>>,
    admission: Option<InferenceAdmissionGuard>,
    observed_total_tokens: Option<std::sync::Arc<std::sync::atomic::AtomicU64>>,
    json_prefix: Vec<u8>,
    json_truncated: bool,
    json_tail: Vec<u8>,
    line_carry: Vec<u8>,
    skip_until_newline: bool,
    sse_total: Option<u64>,
}

impl TokenBudgetBody {
    fn note_json_prefix(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.json_tail.extend_from_slice(bytes);
        if self.json_tail.len() > MAX_JSON_TAIL_BYTES {
            let excess = self.json_tail.len() - MAX_JSON_TAIL_BYTES;
            self.json_tail.drain(..excess);
        }

        if self.json_truncated {
            return;
        }
        let remaining = MAX_JSON_PREFIX_BYTES.saturating_sub(self.json_prefix.len());
        if remaining == 0 {
            self.json_truncated = true;
            return;
        }
        let take = bytes.len().min(remaining);
        self.json_prefix.extend_from_slice(&bytes[..take]);
        if take < bytes.len() {
            self.json_truncated = true;
        }
    }

    fn note_sse_lines(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }

        let mut offset = 0;
        if self.skip_until_newline {
            if let Some(newline) = bytes.iter().position(|&b| b == b'\n') {
                self.skip_until_newline = false;
                offset = newline + 1;
            } else {
                return;
            }
        }

        self.line_carry.extend_from_slice(&bytes[offset..]);
        while let Some(newline) = self.line_carry.iter().position(|&b| b == b'\n') {
            let mut line = self.line_carry.drain(..=newline).collect::<Vec<u8>>();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if let Ok(text) = std::str::from_utf8(&line) {
                if let Some(total) = sse_total_from_complete_line(text) {
                    self.sse_total = Some(total);
                }
            }
        }

        if self.line_carry.len() > MAX_LINE_CARRY_BYTES {
            self.line_carry.clear();
            self.skip_until_newline = true;
        }
    }

    fn note_data(&mut self, bytes: &[u8]) {
        self.note_json_prefix(bytes);
        self.note_sse_lines(bytes);
    }

    fn observed_json_total(&self) -> Option<u64> {
        if !self.json_truncated {
            if let Some(total) = observe_json_total_tokens(&self.json_prefix) {
                return Some(total);
            }
        }
        observe_json_usage_from_tail(&self.json_tail)
            .or_else(|| observe_json_usage_from_tail(&self.json_prefix))
    }

    fn finish(&mut self) {
        if !self.line_carry.is_empty() {
            if let Ok(text) = std::str::from_utf8(&self.line_carry) {
                if let Some(total) =
                    sse_total_from_complete_line(text.trim_end_matches(['\r', '\n']))
                {
                    self.sse_total = Some(total);
                }
            }
            self.line_carry.clear();
        }

        let total = self.sse_total.or_else(|| self.observed_json_total());
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

    fn empty_body() -> TokenBudgetBody {
        TokenBudgetBody {
            inner: Box::pin(ResponseBody::full(Bytes::new())),
            admission: None,
            observed_total_tokens: None,
            json_prefix: Vec::new(),
            json_truncated: false,
            json_tail: Vec::new(),
            line_carry: Vec::new(),
            skip_until_newline: false,
            sse_total: None,
        }
    }

    fn observe_total_tokens_from_bytes(bytes: &[u8]) -> Option<u64> {
        let mut body = empty_body();
        body.note_data(bytes);
        body.finish();
        body.sse_total.or_else(|| body.observed_json_total())
    }

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

    #[test]
    fn observes_sse_usage_after_prefix_larger_than_json_buffer() {
        let sink = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        let mut body = empty_body();
        body.observed_total_tokens = Some(sink.clone());

        let padding_line = b"data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n";
        let mut padded = 0usize;
        while padded <= MAX_JSON_PREFIX_BYTES {
            body.note_data(padding_line);
            padded += padding_line.len();
        }
        assert!(body.json_truncated);
        body.note_data(b"data: {\"usage\":{\"total_tokens\":99}}\n\ndata: [DONE]\n\n");
        body.finish();
        assert_eq!(sink.load(std::sync::atomic::Ordering::Acquire), 99);
    }

    #[test]
    fn observes_sse_usage_split_across_frames() {
        let sink = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        let mut body = empty_body();
        body.observed_total_tokens = Some(sink.clone());
        body.note_data(b"data: {\"usage\":{\"total_tok");
        body.note_data(b"ens\":17}}\n\ndata: [DONE]\n\n");
        body.finish();
        assert_eq!(sink.load(std::sync::atomic::Ordering::Acquire), 17);
    }

    #[test]
    fn observes_json_usage_after_body_exceeds_prefix_budget() {
        let sink = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(u64::MAX));
        let mut body = empty_body();
        body.observed_total_tokens = Some(sink.clone());

        body.note_data(b"{\"id\":\"1\",\"choices\":[{\"message\":{\"content\":\"");
        let mut padded = body.json_prefix.len();
        let chunk = b"x".repeat(4096);
        while padded <= MAX_JSON_PREFIX_BYTES {
            body.note_data(&chunk);
            padded += chunk.len();
        }
        assert!(body.json_truncated);
        body.note_data(
            b"\"}}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":3,\"total_tokens\":88}}",
        );
        body.finish();
        assert_eq!(sink.load(std::sync::atomic::Ordering::Acquire), 88);
    }
}
