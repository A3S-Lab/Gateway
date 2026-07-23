//! Prompt-free managed inference lifecycle evidence.
//!
//! These events are an internal, versioned Gateway persistence format. They
//! are deliberately not the A3S Cloud ingestion wire contract.

use super::{UsageReservation, UsageSpool, UsageSpoolError};
use crate::inference::{
    AuthenticatedInference, InferenceAttemptIdentity, InferenceRequestIdentity,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{Response, StatusCode};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use serde::Serialize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use uuid::Uuid;

const LIFECYCLE_SCHEMA: &str = "a3s.gateway.usage-lifecycle.v1";

type ResponseBody = UnsyncBoxBody<Bytes, std::io::Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UsageTerminalOutcome {
    Succeeded,
    Failed,
    Fallback,
    Cancelled,
    Disconnected,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum MeasurementCompleteness {
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
struct RequestEvidence {
    request_id: Uuid,
    correlation_id: String,
    environment_id: Uuid,
    credential_id: Uuid,
    credential_generation: u64,
    route_id: Uuid,
    route_policy_revision: u64,
    endpoint: crate::config::InferenceEndpoint,
    model_alias: String,
    model_id: Uuid,
}

impl RequestEvidence {
    fn new(
        identity: &InferenceRequestIdentity,
        authenticated: AuthenticatedInference,
        model_alias: &str,
    ) -> Result<Self, UsageSpoolError> {
        let model_id = identity.model_id().ok_or_else(|| UsageSpoolError::Encode {
            reason: "managed inference request has no resolved model identity".to_string(),
        })?;
        Ok(Self {
            request_id: identity.request_id(),
            correlation_id: identity.correlation_id().to_string(),
            environment_id: authenticated.environment_id(),
            credential_id: authenticated.credential_id(),
            credential_generation: authenticated.credential_generation(),
            route_id: identity.route_id(),
            route_policy_revision: identity.route_policy_revision(),
            endpoint: identity.endpoint(),
            model_alias: model_alias.to_string(),
            model_id,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
struct AttemptEvidence {
    attempt_id: Uuid,
    target_id: Uuid,
}

impl From<&InferenceAttemptIdentity> for AttemptEvidence {
    fn from(identity: &InferenceAttemptIdentity) -> Self {
        Self {
            attempt_id: identity.attempt_id(),
            target_id: identity.target_id(),
        }
    }
}

#[derive(Debug, Serialize)]
struct LifecycleEvent<'a> {
    schema: &'static str,
    kind: LifecycleEventKind,
    occurred_at: DateTime<Utc>,
    request: &'a RequestEvidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    attempt: Option<&'a AttemptEvidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome: Option<UsageTerminalOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    measurement_completeness: Option<MeasurementCompleteness>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleEventKind {
    RequestStarted,
    AttemptStarted,
    AttemptTerminal,
    RequestTerminal,
}

impl<'a> LifecycleEvent<'a> {
    fn request_started(request: &'a RequestEvidence) -> Self {
        Self {
            schema: LIFECYCLE_SCHEMA,
            kind: LifecycleEventKind::RequestStarted,
            occurred_at: Utc::now(),
            request,
            attempt: None,
            outcome: None,
            http_status: None,
            duration_ms: None,
            measurement_completeness: None,
        }
    }

    fn attempt_started(request: &'a RequestEvidence, attempt: &'a AttemptEvidence) -> Self {
        Self {
            schema: LIFECYCLE_SCHEMA,
            kind: LifecycleEventKind::AttemptStarted,
            occurred_at: Utc::now(),
            request,
            attempt: Some(attempt),
            outcome: None,
            http_status: None,
            duration_ms: None,
            measurement_completeness: None,
        }
    }

    fn terminal(
        kind: LifecycleEventKind,
        request: &'a RequestEvidence,
        attempt: Option<&'a AttemptEvidence>,
        outcome: UsageTerminalOutcome,
        http_status: Option<u16>,
        duration_ms: u64,
    ) -> Self {
        Self {
            schema: LIFECYCLE_SCHEMA,
            kind,
            occurred_at: Utc::now(),
            request,
            attempt,
            outcome: Some(outcome),
            http_status,
            duration_ms: Some(duration_ms),
            measurement_completeness: Some(MeasurementCompleteness::Unknown),
        }
    }
}

#[derive(Debug)]
struct AttemptLifecycle {
    evidence: AttemptEvidence,
    started_at: Instant,
    terminal_event_id: Uuid,
    terminal_reservation: UsageReservation,
}

/// Durable request state retained from the first dispatch until the response
/// body completes, fails, disconnects, or is cancelled.
#[derive(Debug)]
pub(crate) struct UsageRequestLifecycle {
    spool: Arc<UsageSpool>,
    request: RequestEvidence,
    started_at: Instant,
    terminal_event_id: Uuid,
    terminal_reservation: Option<UsageReservation>,
    attempt: Option<AttemptLifecycle>,
}

impl UsageRequestLifecycle {
    pub(crate) async fn begin(
        spool: Arc<UsageSpool>,
        identity: &InferenceRequestIdentity,
        authenticated: AuthenticatedInference,
        model_alias: &str,
    ) -> Result<Self, UsageSpoolError> {
        let request = RequestEvidence::new(identity, authenticated, model_alias)?;
        let payload = encode(&LifecycleEvent::request_started(&request))?;
        let (_, terminal_reservation) = spool
            .append_reserving_terminal(Uuid::new_v4(), &payload)
            .await?;
        Ok(Self {
            spool,
            request,
            started_at: Instant::now(),
            terminal_event_id: Uuid::new_v4(),
            terminal_reservation: Some(terminal_reservation),
            attempt: None,
        })
    }

    pub(crate) async fn begin_attempt(
        &mut self,
        identity: &InferenceAttemptIdentity,
    ) -> Result<(), UsageSpoolError> {
        if self.attempt.is_some() {
            return Err(UsageSpoolError::Encode {
                reason: "managed inference attempt started before its predecessor terminated"
                    .to_string(),
            });
        }
        let evidence = AttemptEvidence::from(identity);
        let payload = encode(&LifecycleEvent::attempt_started(&self.request, &evidence))?;
        let (_, terminal_reservation) = self
            .spool
            .append_reserving_terminal(Uuid::new_v4(), &payload)
            .await?;
        self.attempt = Some(AttemptLifecycle {
            evidence,
            started_at: Instant::now(),
            terminal_event_id: Uuid::new_v4(),
            terminal_reservation,
        });
        Ok(())
    }

    /// Persist an attempt terminal before another fallback attempt is allowed
    /// to dispatch. Waiting here preserves lifecycle ordering across fallback.
    pub(crate) async fn finish_attempt(
        &mut self,
        outcome: UsageTerminalOutcome,
        http_status: Option<u16>,
    ) -> Result<(), UsageSpoolError> {
        let Some(attempt) = self.attempt.take() else {
            return Ok(());
        };
        let payload = encode(&LifecycleEvent::terminal(
            LifecycleEventKind::AttemptTerminal,
            &self.request,
            Some(&attempt.evidence),
            outcome,
            http_status,
            elapsed_ms(attempt.started_at),
        ))?;
        attempt
            .terminal_reservation
            .commit(attempt.terminal_event_id, payload)?
            .wait()
            .await?;
        Ok(())
    }

    fn finish_background(&mut self, outcome: UsageTerminalOutcome, http_status: Option<u16>) {
        if let Some(attempt) = self.attempt.take() {
            let event = LifecycleEvent::terminal(
                LifecycleEventKind::AttemptTerminal,
                &self.request,
                Some(&attempt.evidence),
                outcome,
                http_status,
                elapsed_ms(attempt.started_at),
            );
            enqueue_terminal(
                attempt.terminal_reservation,
                attempt.terminal_event_id,
                &event,
            );
        }
        if let Some(reservation) = self.terminal_reservation.take() {
            let event = LifecycleEvent::terminal(
                LifecycleEventKind::RequestTerminal,
                &self.request,
                None,
                outcome,
                http_status,
                elapsed_ms(self.started_at),
            );
            enqueue_terminal(reservation, self.terminal_event_id, &event);
        }
    }
}

impl Drop for UsageRequestLifecycle {
    fn drop(&mut self) {
        self.finish_background(UsageTerminalOutcome::Cancelled, None);
    }
}

/// Attach terminal usage delivery to the actual response-body lifetime.
pub(crate) fn track_usage_response(
    response: Response<ResponseBody>,
    lifecycle: Option<UsageRequestLifecycle>,
) -> Response<ResponseBody> {
    let Some(mut lifecycle) = lifecycle else {
        return response;
    };
    let status = response.status();
    if response.body().is_end_stream() {
        lifecycle.finish_background(outcome_for_status(status), Some(status.as_u16()));
        return response;
    }
    let (parts, body) = response.into_parts();
    let body = UsageTrackedBody {
        inner: Box::pin(body),
        lifecycle: Some(lifecycle),
        status,
    }
    .boxed_unsync();
    Response::from_parts(parts, body)
}

struct UsageTrackedBody {
    inner: Pin<Box<ResponseBody>>,
    lifecycle: Option<UsageRequestLifecycle>,
    status: StatusCode,
}

impl UsageTrackedBody {
    fn finish(&mut self, outcome: UsageTerminalOutcome) {
        if let Some(mut lifecycle) = self.lifecycle.take() {
            lifecycle.finish_background(outcome, Some(self.status.as_u16()));
        }
    }

    fn status_outcome(&self) -> UsageTerminalOutcome {
        outcome_for_status(self.status)
    }
}

impl Body for UsageTrackedBody {
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
            Poll::Ready(Some(Err(_))) => this.finish(UsageTerminalOutcome::Failed),
            Poll::Ready(Some(Ok(_))) if inner_ended => this.finish(this.status_outcome()),
            Poll::Ready(None) => this.finish(this.status_outcome()),
            Poll::Pending | Poll::Ready(Some(Ok(_))) => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.lifecycle.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for UsageTrackedBody {
    fn drop(&mut self) {
        self.finish(UsageTerminalOutcome::Disconnected);
    }
}

fn enqueue_terminal(reservation: UsageReservation, event_id: Uuid, event: &LifecycleEvent<'_>) {
    match encode(event).and_then(|payload| reservation.commit(event_id, payload)) {
        Ok(receipt) => {
            if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                runtime.spawn(async move {
                    if let Err(error) = receipt.wait().await {
                        tracing::error!(error = %error, "Durable usage terminal append failed");
                    }
                });
            }
        }
        Err(error) => {
            tracing::error!(error = %error, "Durable usage terminal enqueue failed");
        }
    }
}

fn encode(event: &LifecycleEvent<'_>) -> Result<Vec<u8>, UsageSpoolError> {
    serde_json::to_vec(event).map_err(|error| UsageSpoolError::Encode {
        reason: error.to_string(),
    })
}

fn elapsed_ms(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn outcome_for_status(status: StatusCode) -> UsageTerminalOutcome {
    if status.is_success() || status.is_redirection() {
        UsageTerminalOutcome::Succeeded
    } else {
        UsageTerminalOutcome::Failed
    }
}
