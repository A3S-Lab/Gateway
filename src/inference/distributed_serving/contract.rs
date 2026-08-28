//! Versioned Gateway-to-Power distributed-serving wire contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

pub(crate) const DISTRIBUTED_SERVING_SCHEMA: &str = "a3s.power.distributed-serving.v1";
pub(crate) const DISTRIBUTED_SERVING_STREAM_SCHEMA: &str =
    "a3s.power.distributed-serving-stream.v1";

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "endpoint", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PhaseRequestPayload {
    ChatCompletions { body: serde_json::Value },
    Completions { body: serde_json::Value },
}

impl fmt::Debug for PhaseRequestPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChatCompletions { .. } => {
                formatter.write_str("PhaseRequestPayload::ChatCompletions([REDACTED])")
            }
            Self::Completions { .. } => {
                formatter.write_str("PhaseRequestPayload::Completions([REDACTED])")
            }
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct OpaqueTransferValue(serde_json::Value);

impl OpaqueTransferValue {
    #[cfg(test)]
    pub(crate) fn from_value(value: serde_json::Value) -> Self {
        Self(value)
    }
}

impl fmt::Debug for OpaqueTransferValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueTransferValue([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Serialize)]
pub(crate) struct DecodePrepareRequest {
    pub(crate) schema: &'static str,
    pub(crate) execution_id: Uuid,
    pub(crate) worker_epoch: Uuid,
    pub(crate) execution_profile_sha256: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) request: PhaseRequestPayload,
}

impl fmt::Debug for DecodePrepareRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecodePrepareRequest")
            .field("schema", &self.schema)
            .field("execution_id", &self.execution_id)
            .field("worker_epoch", &self.worker_epoch)
            .field("execution_profile_sha256", &self.execution_profile_sha256)
            .field("expires_at", &self.expires_at)
            .field("request", &self.request)
            .finish()
    }
}

#[derive(Clone, PartialEq, Serialize)]
pub(crate) struct PrefillExecuteRequest {
    pub(crate) schema: &'static str,
    pub(crate) execution_id: Uuid,
    pub(crate) worker_epoch: Uuid,
    pub(crate) execution_profile_sha256: String,
    pub(crate) expires_at: DateTime<Utc>,
    pub(crate) request: PhaseRequestPayload,
    pub(crate) target: OpaqueTransferValue,
}

impl fmt::Debug for PrefillExecuteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrefillExecuteRequest")
            .field("schema", &self.schema)
            .field("execution_id", &self.execution_id)
            .field("worker_epoch", &self.worker_epoch)
            .field("execution_profile_sha256", &self.execution_profile_sha256)
            .field("expires_at", &self.expires_at)
            .field("request", &self.request)
            .field("target", &self.target)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct DecodeExecuteRequest {
    pub(crate) schema: &'static str,
    pub(crate) execution_id: Uuid,
    pub(crate) worker_epoch: Uuid,
    pub(crate) execution_profile_sha256: String,
    pub(crate) source: OpaqueTransferValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AbortExecutionRequest {
    pub(crate) schema: &'static str,
    pub(crate) execution_id: Uuid,
    pub(crate) worker_epoch: Uuid,
    pub(crate) execution_profile_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreparedDecodeResult {
    pub(crate) target: OpaqueTransferValue,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublishedPrefillResult {
    pub(crate) source: OpaqueTransferValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub(crate) enum RecomputeReason {
    #[serde(rename = "state-missing")]
    Missing,
    #[serde(rename = "state-stale")]
    Stale,
    #[serde(rename = "state-corrupt")]
    Corrupt,
    #[serde(rename = "state-incompatible")]
    Incompatible,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum RetryableUnavailableReason {
    AdmissionPressure,
    ExecutorUnavailable,
    TransferUnavailable,
    PeerUnavailable,
    ResourcePressure,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TerminalFailureReason {
    InvalidRequest,
    UnsupportedRequest,
    ModelMismatch,
    PolicyViolation,
    ExecutionFailed,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "decision", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum PhaseDecision<T> {
    Ready {
        result: T,
    },
    Recompute {
        reason: RecomputeReason,
    },
    RetryableUnavailable {
        reason: RetryableUnavailableReason,
        #[serde(default)]
        retry_after_ms: Option<u64>,
    },
    TerminalFailure {
        reason: TerminalFailureReason,
    },
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhaseResponse<T> {
    pub(crate) schema: String,
    pub(crate) execution_id: Uuid,
    pub(crate) worker_epoch: Uuid,
    pub(crate) execution_profile_sha256: String,
    pub(crate) outcome: PhaseDecision<T>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AbortExecutionResponse {
    pub(crate) schema: String,
    pub(crate) execution_id: Uuid,
    pub(crate) worker_epoch: Uuid,
    pub(crate) execution_profile_sha256: String,
    pub(crate) accepted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ProtocolErrorCode {
    UnsupportedSchema,
    InvalidRequest,
    StaleWorker,
    ProfileMismatch,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtocolErrorResponse {
    pub(crate) schema: String,
    pub(crate) code: ProtocolErrorCode,
    pub(crate) message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FunctionCall {
    pub(crate) name: String,
    pub(crate) arguments: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToolCall {
    pub(crate) id: String,
    #[serde(rename = "type")]
    pub(crate) tool_type: String,
    pub(crate) function: FunctionCall,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ChatResponseChunk {
    pub(crate) content: String,
    #[serde(default)]
    pub(crate) thinking_content: Option<String>,
    pub(crate) done: bool,
    #[serde(default)]
    pub(crate) prompt_tokens: Option<u32>,
    #[serde(default)]
    pub(crate) done_reason: Option<String>,
    #[serde(default)]
    pub(crate) prompt_eval_duration_ns: Option<u64>,
    #[serde(default)]
    pub(crate) tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompletionResponseChunk {
    pub(crate) text: String,
    pub(crate) done: bool,
    #[serde(default)]
    pub(crate) prompt_tokens: Option<u32>,
    #[serde(default)]
    pub(crate) done_reason: Option<String>,
    #[serde(default)]
    pub(crate) prompt_eval_duration_ns: Option<u64>,
    #[serde(default)]
    pub(crate) token_id: Option<u32>,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "endpoint", content = "chunk", rename_all = "kebab-case")]
pub(crate) enum DistributedResponseChunk {
    ChatCompletions(ChatResponseChunk),
    Completions(CompletionResponseChunk),
}

impl fmt::Debug for DistributedResponseChunk {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChatCompletions(_) => {
                formatter.write_str("DistributedResponseChunk::ChatCompletions([REDACTED])")
            }
            Self::Completions(_) => {
                formatter.write_str("DistributedResponseChunk::Completions([REDACTED])")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "event", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum DecodeStreamEvent {
    Ready,
    Chunk {
        sequence: u64,
        response: DistributedResponseChunk,
    },
    Failed {
        sequence: u64,
        reason: TerminalFailureReason,
    },
    Completed {
        sequence: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DecodeStreamFrame {
    pub(crate) schema: String,
    pub(crate) execution_id: Uuid,
    pub(crate) worker_epoch: Uuid,
    pub(crate) execution_profile_sha256: String,
    pub(crate) payload: DecodeStreamEvent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProtocolBinding {
    pub(crate) execution_id: Uuid,
    pub(crate) worker_epoch: Uuid,
    pub(crate) execution_profile_sha256: String,
}

impl ProtocolBinding {
    pub(crate) fn matches(
        &self,
        schema: &str,
        execution_id: Uuid,
        worker_epoch: Uuid,
        execution_profile_sha256: &str,
    ) -> bool {
        schema == DISTRIBUTED_SERVING_SCHEMA
            && execution_id == self.execution_id
            && worker_epoch == self.worker_epoch
            && execution_profile_sha256 == self.execution_profile_sha256
    }

    pub(crate) fn matches_stream(&self, frame: &DecodeStreamFrame) -> bool {
        frame.schema == DISTRIBUTED_SERVING_STREAM_SCHEMA
            && frame.execution_id == self.execution_id
            && frame.worker_epoch == self.worker_epoch
            && frame.execution_profile_sha256 == self.execution_profile_sha256
    }
}
