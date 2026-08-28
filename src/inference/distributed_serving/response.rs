//! Incremental Power NDJSON validation and OpenAI response translation.

use super::contract::{
    ChatResponseChunk, CompletionResponseChunk, DecodeStreamEvent, DecodeStreamFrame,
    DistributedResponseChunk, ProtocolBinding, TerminalFailureReason, ToolCall,
};
use crate::config::InferenceEndpoint;
use bytes::Bytes;
use serde_json::{json, Map, Value};
use std::fmt;
use thiserror::Error;
use uuid::Uuid;

const MAX_NDJSON_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum StreamContractError {
    #[error("Power decode stream contains an oversized frame")]
    FrameTooLarge,
    #[error("Power decode stream violates the distributed-serving v1 contract")]
    InvalidFrame,
    #[error("Power decode stream binding changed during execution")]
    BindingMismatch,
    #[error("Power decode stream event order is invalid")]
    InvalidSequence,
    #[error("Power decode stream ended before completion")]
    UnexpectedEnd,
    #[error("Power decode execution failed: {0:?}")]
    Failed(TerminalFailureReason),
    #[error("Power response chunk does not match the requested endpoint")]
    EndpointMismatch,
    #[error("OpenAI response translation failed")]
    Translation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValidatedDecodeEvent {
    Chunk(DistributedResponseChunk),
    Completed,
}

pub(crate) struct DecodeFrameDecoder {
    binding: ProtocolBinding,
    buffer: Vec<u8>,
    ready: bool,
    completed: bool,
    next_sequence: u64,
}

impl fmt::Debug for DecodeFrameDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodeFrameDecoder")
            .field("binding", &self.binding)
            .field("buffered_bytes", &self.buffer.len())
            .field("ready", &self.ready)
            .field("completed", &self.completed)
            .field("next_sequence", &self.next_sequence)
            .finish()
    }
}

impl DecodeFrameDecoder {
    pub(crate) fn new(binding: ProtocolBinding) -> Self {
        Self {
            binding,
            buffer: Vec::new(),
            ready: false,
            completed: false,
            next_sequence: 0,
        }
    }

    pub(crate) fn push(
        &mut self,
        chunk: &[u8],
    ) -> Result<Vec<ValidatedDecodeEvent>, StreamContractError> {
        if self.completed && !chunk.is_empty() {
            return Err(StreamContractError::InvalidSequence);
        }
        if self.buffer.len().saturating_add(chunk.len()) > MAX_NDJSON_LINE_BYTES
            && !chunk.contains(&b'\n')
        {
            return Err(StreamContractError::FrameTooLarge);
        }
        self.buffer.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(newline) = self.buffer.iter().position(|byte| *byte == b'\n') {
            if newline > MAX_NDJSON_LINE_BYTES {
                return Err(StreamContractError::FrameTooLarge);
            }
            let mut line = self.buffer.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            if line.is_empty() {
                return Err(StreamContractError::InvalidFrame);
            }
            let frame: DecodeStreamFrame =
                serde_json::from_slice(&line).map_err(|_| StreamContractError::InvalidFrame)?;
            if !self.binding.matches_stream(&frame) {
                return Err(StreamContractError::BindingMismatch);
            }
            if let Some(event) = self.accept(frame.payload)? {
                events.push(event);
            }
        }
        if self.buffer.len() > MAX_NDJSON_LINE_BYTES {
            return Err(StreamContractError::FrameTooLarge);
        }
        Ok(events)
    }

    pub(crate) fn finish(&self) -> Result<(), StreamContractError> {
        if self.completed && self.buffer.is_empty() {
            Ok(())
        } else {
            Err(StreamContractError::UnexpectedEnd)
        }
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready
    }

    fn accept(
        &mut self,
        payload: DecodeStreamEvent,
    ) -> Result<Option<ValidatedDecodeEvent>, StreamContractError> {
        match payload {
            DecodeStreamEvent::Ready if !self.ready && !self.completed => {
                self.ready = true;
                Ok(None)
            }
            DecodeStreamEvent::Chunk { sequence, response }
                if self.ready && !self.completed && sequence == self.next_sequence =>
            {
                self.next_sequence = self.next_sequence.saturating_add(1);
                Ok(Some(ValidatedDecodeEvent::Chunk(response)))
            }
            DecodeStreamEvent::Completed { sequence }
                if self.ready && !self.completed && sequence == self.next_sequence =>
            {
                self.completed = true;
                Ok(Some(ValidatedDecodeEvent::Completed))
            }
            DecodeStreamEvent::Failed { sequence, reason }
                if self.ready && !self.completed && sequence == self.next_sequence =>
            {
                self.completed = true;
                Err(StreamContractError::Failed(reason))
            }
            DecodeStreamEvent::Ready
            | DecodeStreamEvent::Chunk { .. }
            | DecodeStreamEvent::Completed { .. }
            | DecodeStreamEvent::Failed { .. } => Err(StreamContractError::InvalidSequence),
        }
    }
}

pub(crate) struct OpenAiStreamEncoder {
    endpoint: InferenceEndpoint,
    execution_id: Uuid,
    model: String,
    created: i64,
    chat_role_sent: bool,
}

impl OpenAiStreamEncoder {
    pub(crate) fn new(endpoint: InferenceEndpoint, execution_id: Uuid, model: String) -> Self {
        Self {
            endpoint,
            execution_id,
            model,
            created: chrono::Utc::now().timestamp().max(0),
            chat_role_sent: false,
        }
    }

    pub(crate) fn encode_chunk(
        &mut self,
        chunk: DistributedResponseChunk,
    ) -> Result<Bytes, StreamContractError> {
        let value = match (self.endpoint, chunk) {
            (
                InferenceEndpoint::ChatCompletions,
                DistributedResponseChunk::ChatCompletions(chunk),
            ) => self.chat_chunk(chunk)?,
            (InferenceEndpoint::Completions, DistributedResponseChunk::Completions(chunk)) => {
                self.completion_chunk(chunk)
            }
            _ => return Err(StreamContractError::EndpointMismatch),
        };
        encode_sse_json(&value)
    }

    pub(crate) fn encode_done(&self) -> Bytes {
        Bytes::from_static(b"data: [DONE]\n\n")
    }

    fn chat_chunk(&mut self, chunk: ChatResponseChunk) -> Result<Value, StreamContractError> {
        let mut delta = Map::new();
        if !self.chat_role_sent {
            delta.insert("role".to_string(), Value::String("assistant".to_string()));
            self.chat_role_sent = true;
        }
        if !chunk.content.is_empty() {
            delta.insert("content".to_string(), Value::String(chunk.content));
        }
        if let Some(reasoning) = chunk.thinking_content.filter(|value| !value.is_empty()) {
            delta.insert("reasoning_content".to_string(), Value::String(reasoning));
        }
        if let Some(tool_calls) = chunk.tool_calls.filter(|calls| !calls.is_empty()) {
            delta.insert(
                "tool_calls".to_string(),
                serde_json::to_value(tool_calls).map_err(|_| StreamContractError::Translation)?,
            );
        }
        Ok(json!({
            "id": response_id("chatcmpl", self.execution_id),
            "object": "chat.completion.chunk",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "index": 0,
                "delta": delta,
                "finish_reason": if chunk.done { chunk.done_reason.or_else(|| Some("stop".to_string())) } else { None }
            }]
        }))
    }

    fn completion_chunk(&self, chunk: CompletionResponseChunk) -> Value {
        json!({
            "id": response_id("cmpl", self.execution_id),
            "object": "text_completion",
            "created": self.created,
            "model": self.model,
            "choices": [{
                "text": chunk.text,
                "index": 0,
                "logprobs": null,
                "finish_reason": if chunk.done { chunk.done_reason.or_else(|| Some("stop".to_string())) } else { None }
            }]
        })
    }
}

pub(crate) struct OpenAiAccumulator {
    endpoint: InferenceEndpoint,
    execution_id: Uuid,
    model: String,
    created: i64,
    text: String,
    reasoning: String,
    tool_calls: Vec<ToolCall>,
    prompt_tokens: u64,
    completion_tokens: u64,
    finish_reason: Option<String>,
}

impl OpenAiAccumulator {
    pub(crate) fn new(endpoint: InferenceEndpoint, execution_id: Uuid, model: String) -> Self {
        Self {
            endpoint,
            execution_id,
            model,
            created: chrono::Utc::now().timestamp().max(0),
            text: String::new(),
            reasoning: String::new(),
            tool_calls: Vec::new(),
            prompt_tokens: 0,
            completion_tokens: 0,
            finish_reason: None,
        }
    }

    pub(crate) fn push(
        &mut self,
        chunk: DistributedResponseChunk,
    ) -> Result<(), StreamContractError> {
        match (self.endpoint, chunk) {
            (
                InferenceEndpoint::ChatCompletions,
                DistributedResponseChunk::ChatCompletions(chunk),
            ) => {
                if !chunk.done
                    || !chunk.content.is_empty()
                    || chunk
                        .thinking_content
                        .as_ref()
                        .is_some_and(|value| !value.is_empty())
                    || chunk
                        .tool_calls
                        .as_ref()
                        .is_some_and(|calls| !calls.is_empty())
                {
                    self.completion_tokens = self.completion_tokens.saturating_add(1);
                }
                self.text.push_str(&chunk.content);
                if let Some(reasoning) = chunk.thinking_content {
                    self.reasoning.push_str(&reasoning);
                }
                if let Some(tool_calls) = chunk.tool_calls {
                    self.tool_calls.extend(tool_calls);
                }
                self.observe_terminal(chunk.prompt_tokens, chunk.done, chunk.done_reason);
            }
            (InferenceEndpoint::Completions, DistributedResponseChunk::Completions(chunk)) => {
                if chunk.token_id.is_some() || !chunk.done || !chunk.text.is_empty() {
                    self.completion_tokens = self.completion_tokens.saturating_add(1);
                }
                self.text.push_str(&chunk.text);
                self.observe_terminal(chunk.prompt_tokens, chunk.done, chunk.done_reason);
            }
            _ => return Err(StreamContractError::EndpointMismatch),
        }
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<Bytes, StreamContractError> {
        let finish_reason = self.finish_reason.unwrap_or_else(|| "stop".to_string());
        let usage = json!({
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.prompt_tokens.saturating_add(self.completion_tokens)
        });
        let response = match self.endpoint {
            InferenceEndpoint::ChatCompletions => {
                let mut message = Map::new();
                message.insert("role".to_string(), Value::String("assistant".to_string()));
                message.insert("content".to_string(), Value::String(self.text));
                if !self.reasoning.is_empty() {
                    message.insert(
                        "reasoning_content".to_string(),
                        Value::String(self.reasoning),
                    );
                }
                if !self.tool_calls.is_empty() {
                    message.insert(
                        "tool_calls".to_string(),
                        serde_json::to_value(self.tool_calls)
                            .map_err(|_| StreamContractError::Translation)?,
                    );
                }
                json!({
                    "id": response_id("chatcmpl", self.execution_id),
                    "object": "chat.completion",
                    "created": self.created,
                    "model": self.model,
                    "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
                    "usage": usage
                })
            }
            InferenceEndpoint::Completions => json!({
                "id": response_id("cmpl", self.execution_id),
                "object": "text_completion",
                "created": self.created,
                "model": self.model,
                "choices": [{"text": self.text, "index": 0, "logprobs": null, "finish_reason": finish_reason}],
                "usage": usage
            }),
            _ => return Err(StreamContractError::EndpointMismatch),
        };
        serde_json::to_vec(&response)
            .map(Bytes::from)
            .map_err(|_| StreamContractError::Translation)
    }

    fn observe_terminal(
        &mut self,
        prompt_tokens: Option<u32>,
        done: bool,
        done_reason: Option<String>,
    ) {
        if let Some(prompt_tokens) = prompt_tokens {
            self.prompt_tokens = u64::from(prompt_tokens);
        }
        if done {
            self.finish_reason = done_reason.or_else(|| Some("stop".to_string()));
        }
    }
}

fn response_id(prefix: &str, execution_id: Uuid) -> String {
    format!("{prefix}-{}", execution_id.simple())
}

fn encode_sse_json(value: &Value) -> Result<Bytes, StreamContractError> {
    let mut bytes = b"data: ".to_vec();
    serde_json::to_writer(&mut bytes, value).map_err(|_| StreamContractError::Translation)?;
    bytes.extend_from_slice(b"\n\n");
    Ok(Bytes::from(bytes))
}
