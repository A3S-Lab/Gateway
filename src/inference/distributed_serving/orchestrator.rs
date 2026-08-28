//! Application orchestration for one Gateway-owned prefill/decode execution.

use super::cleanup::ExecutionCleanup;
use super::client::{
    DecodeExecuteOutcome, PowerClientError, PowerDecodeStream, PowerDistributedClient,
};
use super::contract::{
    DecodeExecuteRequest, DecodePrepareRequest, PhaseDecision, PhaseRequestPayload,
    PrefillExecuteRequest, ProtocolBinding, RecomputeReason, RetryableUnavailableReason,
    TerminalFailureReason, DISTRIBUTED_SERVING_SCHEMA,
};
use super::response::{
    DecodeFrameDecoder, OpenAiAccumulator, OpenAiStreamEncoder, StreamContractError,
    ValidatedDecodeEvent,
};
use crate::config::{InferenceConfig, InferenceEndpoint};
use bytes::Bytes;
use futures_util::{stream, Stream, StreamExt};
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::pin::Pin;
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;
use uuid::Uuid;

const MAX_POWER_STREAM_PREFLIGHT_BYTES: usize = 1024 * 1024;
const MAX_BUFFERED_POWER_STREAM_BYTES: usize = 16 * 1024 * 1024;

pub(crate) type DistributedByteStream =
    Pin<Box<dyn Stream<Item = io::Result<Bytes>> + Send + 'static>>;

pub(crate) enum DistributedInferenceResponse {
    Buffered(Bytes),
    Streaming(DistributedByteStream),
}

impl fmt::Debug for DistributedInferenceResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Buffered(body) => formatter
                .debug_tuple("Buffered")
                .field(&format_args!("{} bytes", body.len()))
                .finish(),
            Self::Streaming(_) => formatter.write_str("Streaming([REDACTED])"),
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum DistributedServingError {
    #[error("A selected distributed inference worker stopped admitting requests")]
    WorkerAdmissionClosed,
    #[error("Distributed inference request is invalid")]
    InvalidRequest,
    #[error("Distributed inference must recompute prefill: {0:?}")]
    Recompute(RecomputeReason),
    #[error("Distributed inference worker is temporarily unavailable: {0:?}")]
    RetryableUnavailable(RetryableUnavailableReason),
    #[error("Distributed inference failed before response: {0:?}")]
    Terminal(TerminalFailureReason),
    #[error(transparent)]
    Client(#[from] PowerClientError),
    #[error(transparent)]
    Stream(#[from] StreamContractError),
    #[error("Distributed inference buffered response exceeds its fixed limit")]
    BufferedResponseTooLarge,
}

impl DistributedServingError {
    pub(crate) fn retryable_before_response(&self) -> bool {
        matches!(Self::classification(self), ErrorClassification::Retryable)
    }

    pub(crate) fn status_code(&self) -> u16 {
        match Self::classification(self) {
            ErrorClassification::Deadline => 504,
            ErrorClassification::Retryable => 503,
            ErrorClassification::BadGateway => 502,
        }
    }

    fn classification(&self) -> ErrorClassification {
        match self {
            Self::WorkerAdmissionClosed | Self::Recompute(_) | Self::RetryableUnavailable(_) => {
                ErrorClassification::Retryable
            }
            Self::Client(error) if error.retryable_before_response() => {
                if matches!(error, PowerClientError::DeadlineExceeded) {
                    ErrorClassification::Deadline
                } else {
                    ErrorClassification::Retryable
                }
            }
            Self::Terminal(_)
            | Self::InvalidRequest
            | Self::Client(_)
            | Self::Stream(_)
            | Self::BufferedResponseTooLarge => ErrorClassification::BadGateway,
        }
    }
}

enum ErrorClassification {
    Deadline,
    Retryable,
    BadGateway,
}

#[derive(Clone)]
pub(crate) struct DistributedWorkerEndpoint {
    pub(crate) url: String,
    pub(crate) binding: ProtocolBinding,
}

impl fmt::Debug for DistributedWorkerEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributedWorkerEndpoint")
            .field("binding", &self.binding)
            .field("url", &"[REDACTED]")
            .finish()
    }
}

pub(crate) struct DistributedExecutionRequest {
    pub(crate) execution_id: Uuid,
    pub(crate) endpoint: InferenceEndpoint,
    pub(crate) external_model: String,
    pub(crate) body: Bytes,
    pub(crate) stream: bool,
    pub(crate) api_key_env: String,
    pub(crate) execution_timeout_ms: u64,
    pub(crate) prefill: DistributedWorkerEndpoint,
    pub(crate) decode: DistributedWorkerEndpoint,
}

impl fmt::Debug for DistributedExecutionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DistributedExecutionRequest")
            .field("execution_id", &self.execution_id)
            .field("endpoint", &self.endpoint)
            .field("external_model", &self.external_model)
            .field(
                "body",
                &format_args!("[REDACTED; {} bytes]", self.body.len()),
            )
            .field("stream", &self.stream)
            .field("api_key_env", &self.api_key_env)
            .field("execution_timeout_ms", &self.execution_timeout_ms)
            .field("prefill", &self.prefill)
            .field("decode", &self.decode)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct DistributedServingOrchestrator {
    client: PowerDistributedClient,
}

impl DistributedServingOrchestrator {
    pub(crate) fn from_policy(policy: Option<&InferenceConfig>) -> Result<Self, PowerClientError> {
        Ok(Self {
            client: PowerDistributedClient::from_policy(policy)?,
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_key(name: &str, value: &str) -> Self {
        Self {
            client: PowerDistributedClient::with_test_key(name, value),
        }
    }

    pub(crate) async fn execute(
        &self,
        request: DistributedExecutionRequest,
    ) -> Result<DistributedInferenceResponse, DistributedServingError> {
        let body = serde_json::from_slice::<serde_json::Value>(&request.body)
            .map_err(|_| DistributedServingError::InvalidRequest)?;
        if !body.is_object() {
            return Err(DistributedServingError::InvalidRequest);
        }
        let payload = match request.endpoint {
            InferenceEndpoint::ChatCompletions => PhaseRequestPayload::ChatCompletions { body },
            InferenceEndpoint::Completions => PhaseRequestPayload::Completions { body },
            _ => return Err(DistributedServingError::InvalidRequest),
        };
        let timeout = Duration::from_millis(request.execution_timeout_ms);
        let deadline = Instant::now() + timeout;
        let chrono_timeout = chrono::Duration::from_std(timeout)
            .map_err(|_| DistributedServingError::InvalidRequest)?;
        let expires_at = chrono::Utc::now() + chrono_timeout;
        let cleanup = ExecutionCleanup::new(
            self.client.clone(),
            request.api_key_env.clone(),
            request.prefill.clone(),
            request.decode.clone(),
        );

        let prepared = self
            .client
            .prepare_decode(
                &request.decode.url,
                &request.api_key_env,
                deadline,
                &DecodePrepareRequest {
                    schema: DISTRIBUTED_SERVING_SCHEMA,
                    execution_id: request.execution_id,
                    worker_epoch: request.decode.binding.worker_epoch,
                    execution_profile_sha256: request
                        .decode
                        .binding
                        .execution_profile_sha256
                        .clone(),
                    expires_at,
                    request: payload.clone(),
                },
                &request.decode.binding,
            )
            .await;
        let target = match prepared {
            Ok(PhaseDecision::Ready { result }) => result.target,
            Ok(decision) => return cleanup.fail(decision_error(decision)).await,
            Err(error) => return cleanup.fail(error.into()).await,
        };

        let published = self
            .client
            .execute_prefill(
                &request.prefill.url,
                &request.api_key_env,
                deadline,
                &PrefillExecuteRequest {
                    schema: DISTRIBUTED_SERVING_SCHEMA,
                    execution_id: request.execution_id,
                    worker_epoch: request.prefill.binding.worker_epoch,
                    execution_profile_sha256: request
                        .prefill
                        .binding
                        .execution_profile_sha256
                        .clone(),
                    expires_at,
                    request: payload,
                    target,
                },
                &request.prefill.binding,
            )
            .await;
        let source = match published {
            Ok(PhaseDecision::Ready { result }) => result.source,
            Ok(decision) => return cleanup.fail(decision_error(decision)).await,
            Err(error) => return cleanup.fail(error.into()).await,
        };

        let decoded = self
            .client
            .execute_decode(
                &request.decode.url,
                &request.api_key_env,
                deadline,
                &DecodeExecuteRequest {
                    schema: DISTRIBUTED_SERVING_SCHEMA,
                    execution_id: request.execution_id,
                    worker_epoch: request.decode.binding.worker_epoch,
                    execution_profile_sha256: request
                        .decode
                        .binding
                        .execution_profile_sha256
                        .clone(),
                    source,
                },
                request.decode.binding.clone(),
            )
            .await;
        let power_stream = match decoded {
            Ok(DecodeExecuteOutcome::Stream(stream)) => stream,
            Ok(DecodeExecuteOutcome::Decision(decision)) => {
                return cleanup.fail(decision_error(decision)).await;
            }
            Err(error) => return cleanup.fail(error.into()).await,
        };
        let initialized = initialize_stream(power_stream).await;
        let initialized = match initialized {
            Ok(initialized) => initialized,
            Err(error) => return cleanup.fail(error.into()).await,
        };

        if request.stream {
            let response = translated_stream(
                initialized,
                request.endpoint,
                request.execution_id,
                request.external_model,
                cleanup,
            )?;
            Ok(DistributedInferenceResponse::Streaming(response))
        } else {
            let response = collect_buffered(
                initialized,
                request.endpoint,
                request.execution_id,
                request.external_model,
            )
            .await;
            match response {
                Ok(body) => {
                    cleanup.finish().await;
                    Ok(DistributedInferenceResponse::Buffered(body))
                }
                Err(error) => cleanup.fail(error).await,
            }
        }
    }
}

fn decision_error<T>(decision: PhaseDecision<T>) -> DistributedServingError {
    match decision {
        PhaseDecision::Ready { .. } => DistributedServingError::InvalidRequest,
        PhaseDecision::Recompute { reason } => DistributedServingError::Recompute(reason),
        PhaseDecision::RetryableUnavailable { reason, .. } => {
            DistributedServingError::RetryableUnavailable(reason)
        }
        PhaseDecision::TerminalFailure { reason } => DistributedServingError::Terminal(reason),
    }
}

type PowerByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static>>;

struct InitializedPowerStream {
    source: PowerByteStream,
    decoder: DecodeFrameDecoder,
    initial_events: Vec<ValidatedDecodeEvent>,
    observed_bytes: usize,
}

async fn initialize_stream(
    stream: PowerDecodeStream,
) -> Result<InitializedPowerStream, StreamContractError> {
    let mut source: PowerByteStream = Box::pin(stream.response.bytes_stream());
    let mut decoder = DecodeFrameDecoder::new(stream.binding);
    let mut initial_events = Vec::new();
    let mut observed_bytes = 0_usize;
    while !decoder.is_ready() {
        let chunk = source
            .next()
            .await
            .ok_or(StreamContractError::UnexpectedEnd)?
            .map_err(|_| StreamContractError::UnexpectedEnd)?;
        observed_bytes = observed_bytes.saturating_add(chunk.len());
        if observed_bytes > MAX_POWER_STREAM_PREFLIGHT_BYTES {
            return Err(StreamContractError::FrameTooLarge);
        }
        initial_events.extend(decoder.push(&chunk)?);
    }
    Ok(InitializedPowerStream {
        source,
        decoder,
        initial_events,
        observed_bytes,
    })
}

async fn collect_buffered(
    mut initialized: InitializedPowerStream,
    endpoint: InferenceEndpoint,
    execution_id: Uuid,
    external_model: String,
) -> Result<Bytes, DistributedServingError> {
    let mut accumulator = OpenAiAccumulator::new(endpoint, execution_id, external_model);
    let mut completed = accept_buffered_events(&mut accumulator, initialized.initial_events)?;
    let mut observed_bytes = initialized.observed_bytes;
    while let Some(chunk) = initialized.source.next().await {
        let chunk = chunk.map_err(|_| PowerClientError::Transport)?;
        observed_bytes = observed_bytes.saturating_add(chunk.len());
        if observed_bytes > MAX_BUFFERED_POWER_STREAM_BYTES {
            return Err(DistributedServingError::BufferedResponseTooLarge);
        }
        let terminal = accept_buffered_events(&mut accumulator, initialized.decoder.push(&chunk)?)?;
        completed |= terminal;
    }
    initialized.decoder.finish()?;
    if !completed {
        return Err(StreamContractError::UnexpectedEnd.into());
    }
    accumulator.finish().map_err(Into::into)
}

fn accept_buffered_events(
    accumulator: &mut OpenAiAccumulator,
    events: Vec<ValidatedDecodeEvent>,
) -> Result<bool, StreamContractError> {
    let mut completed = false;
    for event in events {
        match event {
            ValidatedDecodeEvent::Chunk(chunk) if !completed => accumulator.push(chunk)?,
            ValidatedDecodeEvent::Completed if !completed => completed = true,
            ValidatedDecodeEvent::Chunk(_) | ValidatedDecodeEvent::Completed => {
                return Err(StreamContractError::InvalidSequence);
            }
        }
    }
    Ok(completed)
}

struct TranslatedStreamState {
    source: PowerByteStream,
    decoder: DecodeFrameDecoder,
    encoder: OpenAiStreamEncoder,
    pending: VecDeque<Bytes>,
    completed: bool,
    done_emitted: bool,
    cleanup: Option<ExecutionCleanup>,
}

fn translated_stream(
    initialized: InitializedPowerStream,
    endpoint: InferenceEndpoint,
    execution_id: Uuid,
    external_model: String,
    cleanup: ExecutionCleanup,
) -> Result<DistributedByteStream, DistributedServingError> {
    let mut state = TranslatedStreamState {
        source: initialized.source,
        decoder: initialized.decoder,
        encoder: OpenAiStreamEncoder::new(endpoint, execution_id, external_model),
        pending: VecDeque::new(),
        completed: false,
        done_emitted: false,
        cleanup: Some(cleanup),
    };
    accept_stream_events(&mut state, initialized.initial_events)?;
    let output = stream::try_unfold(state, |mut state| async move {
        loop {
            if let Some(bytes) = state.pending.pop_front() {
                return Ok(Some((bytes, state)));
            }
            if state.completed {
                if state.done_emitted {
                    if let Some(cleanup) = state.cleanup.take() {
                        cleanup.finish().await;
                    }
                    return Ok(None);
                }
                match state.source.next().await {
                    Some(Ok(chunk)) => {
                        let events = state.decoder.push(&chunk).map_err(stream_io_error)?;
                        accept_stream_events(&mut state, events).map_err(stream_io_error)?;
                        continue;
                    }
                    Some(Err(_)) => {
                        return Err(io::Error::other(
                            "Power distributed-serving stream transport failed",
                        ));
                    }
                    None => {
                        state.decoder.finish().map_err(stream_io_error)?;
                        state.done_emitted = true;
                        return Ok(Some((state.encoder.encode_done(), state)));
                    }
                }
            }
            let chunk = state
                .source
                .next()
                .await
                .ok_or_else(|| stream_io_error(StreamContractError::UnexpectedEnd))?
                .map_err(|_| {
                    io::Error::other("Power distributed-serving stream transport failed")
                })?;
            let events = state.decoder.push(&chunk).map_err(stream_io_error)?;
            accept_stream_events(&mut state, events).map_err(stream_io_error)?;
        }
    });
    Ok(Box::pin(output))
}

fn accept_stream_events(
    state: &mut TranslatedStreamState,
    events: Vec<ValidatedDecodeEvent>,
) -> Result<(), StreamContractError> {
    for event in events {
        match event {
            ValidatedDecodeEvent::Chunk(chunk) if !state.completed => {
                state.pending.push_back(state.encoder.encode_chunk(chunk)?);
            }
            ValidatedDecodeEvent::Completed if !state.completed => {
                state.completed = true;
            }
            ValidatedDecodeEvent::Chunk(_) | ValidatedDecodeEvent::Completed => {
                return Err(StreamContractError::InvalidSequence);
            }
        }
    }
    Ok(())
}

fn stream_io_error(error: StreamContractError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
