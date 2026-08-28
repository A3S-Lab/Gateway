//! Bounded authenticated infrastructure client for Power's internal API.

use super::contract::{
    AbortExecutionRequest, AbortExecutionResponse, DecodeExecuteRequest, DecodePrepareRequest,
    PhaseDecision, PhaseResponse, PrefillExecuteRequest, PreparedDecodeResult, ProtocolBinding,
    ProtocolErrorCode, ProtocolErrorResponse, PublishedPrefillResult, DISTRIBUTED_SERVING_SCHEMA,
};
use crate::config::InferenceConfig;
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::time::Instant;

const MAX_DISTRIBUTED_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_JSON_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_POWER_API_KEY_BYTES: usize = 4 * 1024;
const JSON_MEDIA_TYPE: &str = "application/json";
const NDJSON_MEDIA_TYPE: &str = "application/x-ndjson";

const DECODE_PREPARE_PATH: &str = "/internal/v1/distributed-serving/decode/prepare";
const PREFILL_EXECUTE_PATH: &str = "/internal/v1/distributed-serving/prefill/execute";
const DECODE_EXECUTE_PATH: &str = "/internal/v1/distributed-serving/decode/execute";
const ABORT_PATH: &str = "/internal/v1/distributed-serving/abort";

#[derive(Clone)]
struct PowerApiKey(Arc<str>);

impl PowerApiKey {
    fn parse(value: String) -> Option<Self> {
        if value.is_empty()
            || value.len() > MAX_POWER_API_KEY_BYTES
            || value.bytes().any(|byte| !byte.is_ascii_graphic())
        {
            return None;
        }
        Some(Self(Arc::from(value)))
    }

    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PowerApiKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PowerApiKey([REDACTED])")
    }
}

/// Process-local credentials and pooled HTTP transport for internal Power calls.
#[derive(Clone)]
pub(crate) struct PowerDistributedClient {
    http: reqwest::Client,
    api_keys: Arc<HashMap<String, PowerApiKey>>,
}

impl fmt::Debug for PowerDistributedClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PowerDistributedClient")
            .field("credential_count", &self.api_keys.len())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub(crate) enum PowerClientError {
    #[error(
        "Power distributed-serving credential environment variable '{environment}' is unavailable"
    )]
    MissingCredential { environment: String },
    #[error(
        "Power distributed-serving credential in environment variable '{environment}' is invalid"
    )]
    InvalidCredential { environment: String },
    #[error("Power distributed-serving endpoint is invalid")]
    InvalidEndpoint,
    #[error("Power distributed-serving request exceeds its fixed limit")]
    RequestTooLarge,
    #[error("Power distributed-serving operation deadline expired")]
    DeadlineExceeded,
    #[error("Power distributed-serving transport failed")]
    Transport,
    #[error("Power distributed-serving response has an unsupported media type")]
    UnsupportedMediaType,
    #[error("Power distributed-serving response exceeds its fixed limit")]
    ResponseTooLarge,
    #[error("Power distributed-serving response violates the v1 contract")]
    InvalidResponse,
    #[error("Power distributed-serving protocol rejected the request: {0:?}")]
    Protocol(ProtocolErrorCode),
    #[error("Power distributed-serving returned unexpected HTTP status {0}")]
    UnexpectedStatus(u16),
}

impl PowerClientError {
    pub(crate) fn retryable_before_response(&self) -> bool {
        matches!(
            self,
            Self::DeadlineExceeded
                | Self::Transport
                | Self::Protocol(ProtocolErrorCode::Unavailable)
                | Self::UnexpectedStatus(503)
        )
    }
}

pub(crate) struct PowerDecodeStream {
    pub(crate) response: reqwest::Response,
    pub(crate) binding: ProtocolBinding,
}

pub(crate) enum DecodeExecuteOutcome {
    Stream(PowerDecodeStream),
    Decision(PhaseDecision<()>),
}

impl PowerDistributedClient {
    pub(crate) fn from_policy(policy: Option<&InferenceConfig>) -> Result<Self, PowerClientError> {
        let mut names = HashSet::new();
        if let Some(policy) = policy {
            for route in policy.routes.values() {
                for model in route.models.values() {
                    if let Some(distributed) = model
                        .scheduling
                        .as_ref()
                        .and_then(|scheduling| scheduling.distributed_serving.as_ref())
                    {
                        names.insert(distributed.api_key_env.clone());
                    }
                }
            }
        }
        let mut keys = HashMap::with_capacity(names.len());
        for name in names {
            let value = std::env::var(&name).map_err(|_| PowerClientError::MissingCredential {
                environment: name.clone(),
            })?;
            let key =
                PowerApiKey::parse(value).ok_or_else(|| PowerClientError::InvalidCredential {
                    environment: name.clone(),
                })?;
            keys.insert(name, key);
        }
        Self::new(keys)
    }

    #[cfg(test)]
    pub(crate) fn with_test_key(name: &str, value: &str) -> Self {
        Self::new(HashMap::from([(
            name.to_string(),
            PowerApiKey::parse(value.to_string()).expect("valid test key"),
        )]))
        .expect("test client")
    }

    fn new(api_keys: HashMap<String, PowerApiKey>) -> Result<Self, PowerClientError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| PowerClientError::Transport)?;
        Ok(Self {
            http,
            api_keys: Arc::new(api_keys),
        })
    }

    pub(crate) async fn prepare_decode(
        &self,
        backend_url: &str,
        api_key_env: &str,
        deadline: Instant,
        request: &DecodePrepareRequest,
        binding: &ProtocolBinding,
    ) -> Result<PhaseDecision<PreparedDecodeResult>, PowerClientError> {
        let response = self
            .post_json(
                backend_url,
                DECODE_PREPARE_PATH,
                api_key_env,
                deadline,
                request,
                JSON_MEDIA_TYPE,
            )
            .await?;
        self.parse_phase_response(response, binding).await
    }

    pub(crate) async fn execute_prefill(
        &self,
        backend_url: &str,
        api_key_env: &str,
        deadline: Instant,
        request: &PrefillExecuteRequest,
        binding: &ProtocolBinding,
    ) -> Result<PhaseDecision<PublishedPrefillResult>, PowerClientError> {
        let response = self
            .post_json(
                backend_url,
                PREFILL_EXECUTE_PATH,
                api_key_env,
                deadline,
                request,
                JSON_MEDIA_TYPE,
            )
            .await?;
        self.parse_phase_response(response, binding).await
    }

    pub(crate) async fn execute_decode(
        &self,
        backend_url: &str,
        api_key_env: &str,
        deadline: Instant,
        request: &DecodeExecuteRequest,
        binding: ProtocolBinding,
    ) -> Result<DecodeExecuteOutcome, PowerClientError> {
        let response = self
            .post_json(
                backend_url,
                DECODE_EXECUTE_PATH,
                api_key_env,
                deadline,
                request,
                "application/x-ndjson, application/json",
            )
            .await?;
        if response.status() == reqwest::StatusCode::OK {
            ensure_media_type(&response, NDJSON_MEDIA_TYPE)?;
            return Ok(DecodeExecuteOutcome::Stream(PowerDecodeStream {
                response,
                binding,
            }));
        }
        let decision = self
            .parse_phase_response::<serde_json::Value>(response, &binding)
            .await?;
        Ok(DecodeExecuteOutcome::Decision(map_non_ready_decision(
            decision,
        )?))
    }

    pub(crate) async fn abort(
        &self,
        backend_url: &str,
        api_key_env: &str,
        deadline: Instant,
        request: &AbortExecutionRequest,
        binding: &ProtocolBinding,
    ) -> Result<(), PowerClientError> {
        let response = self
            .post_json(
                backend_url,
                ABORT_PATH,
                api_key_env,
                deadline,
                request,
                JSON_MEDIA_TYPE,
            )
            .await?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(self.protocol_or_status(response).await);
        }
        ensure_media_type(&response, JSON_MEDIA_TYPE)?;
        let bytes = collect_bounded(response, MAX_JSON_RESPONSE_BYTES).await?;
        let decoded: AbortExecutionResponse =
            serde_json::from_slice(&bytes).map_err(|_| PowerClientError::InvalidResponse)?;
        if !binding.matches(
            &decoded.schema,
            decoded.execution_id,
            decoded.worker_epoch,
            &decoded.execution_profile_sha256,
        ) || !decoded.accepted
        {
            return Err(PowerClientError::InvalidResponse);
        }
        Ok(())
    }

    async fn post_json<T: Serialize + ?Sized>(
        &self,
        backend_url: &str,
        path: &str,
        api_key_env: &str,
        deadline: Instant,
        payload: &T,
        accept: &'static str,
    ) -> Result<reqwest::Response, PowerClientError> {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(PowerClientError::DeadlineExceeded)?;
        let key =
            self.api_keys
                .get(api_key_env)
                .ok_or_else(|| PowerClientError::MissingCredential {
                    environment: api_key_env.to_string(),
                })?;
        let url = internal_url(backend_url, path)?;
        let body = serde_json::to_vec(payload).map_err(|_| PowerClientError::InvalidResponse)?;
        if body.len() > MAX_DISTRIBUTED_REQUEST_BYTES {
            return Err(PowerClientError::RequestTooLarge);
        }
        self.http
            .post(url)
            .header(CONTENT_TYPE, JSON_MEDIA_TYPE)
            .header(ACCEPT, accept)
            .bearer_auth(key.expose())
            .timeout(timeout)
            .body(body)
            .send()
            .await
            .map_err(classify_transport_error)
    }

    async fn parse_phase_response<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
        binding: &ProtocolBinding,
    ) -> Result<PhaseDecision<T>, PowerClientError> {
        let status = response.status();
        ensure_media_type(&response, JSON_MEDIA_TYPE)?;
        let bytes = collect_bounded(response, MAX_JSON_RESPONSE_BYTES).await?;
        if let Ok(decoded) = serde_json::from_slice::<PhaseResponse<T>>(&bytes) {
            if !binding.matches(
                &decoded.schema,
                decoded.execution_id,
                decoded.worker_epoch,
                &decoded.execution_profile_sha256,
            ) || !decision_status_matches(status, &decoded.outcome)
            {
                return Err(PowerClientError::InvalidResponse);
            }
            return Ok(decoded.outcome);
        }
        if let Ok(protocol) = serde_json::from_slice::<ProtocolErrorResponse>(&bytes) {
            if protocol.schema == DISTRIBUTED_SERVING_SCHEMA
                && protocol_status_matches(status, protocol.code)
            {
                return Err(PowerClientError::Protocol(protocol.code));
            }
            return Err(PowerClientError::InvalidResponse);
        }
        if status.is_success() {
            Err(PowerClientError::InvalidResponse)
        } else {
            Err(PowerClientError::UnexpectedStatus(status.as_u16()))
        }
    }

    async fn protocol_or_status(&self, response: reqwest::Response) -> PowerClientError {
        let status = response.status();
        if ensure_media_type(&response, JSON_MEDIA_TYPE).is_err() {
            return PowerClientError::UnsupportedMediaType;
        }
        match collect_bounded(response, MAX_JSON_RESPONSE_BYTES).await {
            Ok(bytes) => match serde_json::from_slice::<ProtocolErrorResponse>(&bytes) {
                Ok(protocol)
                    if protocol.schema == DISTRIBUTED_SERVING_SCHEMA
                        && protocol_status_matches(status, protocol.code) =>
                {
                    PowerClientError::Protocol(protocol.code)
                }
                _ => PowerClientError::UnexpectedStatus(status.as_u16()),
            },
            Err(error) => error,
        }
    }
}

fn decision_status_matches<T>(status: reqwest::StatusCode, decision: &PhaseDecision<T>) -> bool {
    match decision {
        PhaseDecision::Ready { .. } => status == reqwest::StatusCode::OK,
        PhaseDecision::Recompute { .. } => status == reqwest::StatusCode::CONFLICT,
        PhaseDecision::RetryableUnavailable { .. } => {
            status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        }
        PhaseDecision::TerminalFailure { .. } => {
            status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
        }
    }
}

fn protocol_status_matches(status: reqwest::StatusCode, code: ProtocolErrorCode) -> bool {
    match code {
        ProtocolErrorCode::UnsupportedSchema => status == reqwest::StatusCode::BAD_REQUEST,
        ProtocolErrorCode::InvalidRequest => matches!(
            status,
            reqwest::StatusCode::BAD_REQUEST
                | reqwest::StatusCode::UNAUTHORIZED
                | reqwest::StatusCode::FORBIDDEN
                | reqwest::StatusCode::PAYLOAD_TOO_LARGE
        ),
        ProtocolErrorCode::StaleWorker | ProtocolErrorCode::ProfileMismatch => {
            status == reqwest::StatusCode::CONFLICT
        }
        ProtocolErrorCode::Unavailable => matches!(
            status,
            reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::SERVICE_UNAVAILABLE
        ),
        ProtocolErrorCode::Internal => status == reqwest::StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn map_non_ready_decision(
    decision: PhaseDecision<serde_json::Value>,
) -> Result<PhaseDecision<()>, PowerClientError> {
    match decision {
        PhaseDecision::Ready { .. } => Err(PowerClientError::InvalidResponse),
        PhaseDecision::Recompute { reason } => Ok(PhaseDecision::Recompute { reason }),
        PhaseDecision::RetryableUnavailable {
            reason,
            retry_after_ms,
        } => Ok(PhaseDecision::RetryableUnavailable {
            reason,
            retry_after_ms,
        }),
        PhaseDecision::TerminalFailure { reason } => Ok(PhaseDecision::TerminalFailure { reason }),
    }
}

fn internal_url(backend_url: &str, path: &str) -> Result<url::Url, PowerClientError> {
    let mut url = url::Url::parse(backend_url).map_err(|_| PowerClientError::InvalidEndpoint)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(PowerClientError::InvalidEndpoint);
    }
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn ensure_media_type(response: &reqwest::Response, expected: &str) -> Result<(), PowerClientError> {
    let actual = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if actual.is_some_and(|actual| actual.eq_ignore_ascii_case(expected)) {
        Ok(())
    } else {
        Err(PowerClientError::UnsupportedMediaType)
    }
}

async fn collect_bounded(
    response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, PowerClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(PowerClientError::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(classify_transport_error)?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(PowerClientError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn classify_transport_error(error: reqwest::Error) -> PowerClientError {
    if error.is_timeout() {
        PowerClientError::DeadlineExceeded
    } else {
        PowerClientError::Transport
    }
}

#[cfg(test)]
pub(super) fn api_key_is_valid_for_test(value: &str) -> bool {
    PowerApiKey::parse(value.to_string()).is_some()
}
