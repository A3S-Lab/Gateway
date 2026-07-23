//! Cloud-managed inference policy configuration.

mod validation;

#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Audience accepted by the native inference data plane.
pub const INFERENCE_CREDENTIAL_AUDIENCE: &str = "cloud-inference";

/// Complete, expiring inference policy projected by A3S Cloud.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceConfig {
    /// Exclusive end of the policy validity window.
    pub expires_at: DateTime<Utc>,
    /// Credential verifier projections keyed by stable credential ID.
    #[serde(default)]
    pub credentials: HashMap<Uuid, InferenceCredentialConfig>,
    /// Inference routes keyed by stable route ID.
    #[serde(default)]
    pub routes: HashMap<Uuid, InferenceRouteConfig>,
}

/// One inference-key verifier projection.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceCredentialConfig {
    /// Stable Identity-owned credential ID.
    pub credential_id: Uuid,
    /// Environment that owns the credential.
    pub environment_id: Uuid,
    /// Credential audience. Must be `cloud-inference`.
    pub audience: String,
    /// Stable, non-secret lookup prefix.
    pub prefix: String,
    /// Memory-hard Argon2id PHC verifier.
    ///
    /// This value is deliberately omitted from every serialized configuration
    /// view so the management API and CLI cannot expose it.
    #[serde(skip_serializing)]
    pub(crate) verifier_hash: String,
    /// Positive issuance generation.
    pub generation: u64,
    /// Credential expiry evaluated by the request authorization stage.
    pub expires_at: DateTime<Utc>,
    /// Explicit revocation state.
    pub revoked: bool,
}

impl InferenceCredentialConfig {
    pub(crate) fn verifier_hash(&self) -> &str {
        &self.verifier_hash
    }
}

impl fmt::Debug for InferenceCredentialConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InferenceCredentialConfig")
            .field("credential_id", &self.credential_id)
            .field("environment_id", &self.environment_id)
            .field("audience", &self.audience)
            .field("prefix", &self.prefix)
            .field("verifier_hash", &"<redacted>")
            .field("generation", &self.generation)
            .field("expires_at", &self.expires_at)
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// One environment-scoped inference route bound to an ordinary HTTP router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceRouteConfig {
    /// Stable Inference-owned route ID.
    pub route_id: Uuid,
    /// Existing Gateway router that establishes hostname and path ownership.
    pub router: String,
    /// Environment that owns the route and all of its grants.
    pub environment_id: Uuid,
    /// Positive immutable access-policy revision.
    pub policy_revision: u64,
    /// External model aliases available on this route.
    #[serde(default)]
    pub models: HashMap<String, InferenceModelConfig>,
    /// Credential grants keyed by stable credential ID.
    #[serde(default)]
    pub grants: HashMap<Uuid, InferenceGrantConfig>,
}

/// One externally visible model alias and its ordered target groups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceModelConfig {
    /// Stable logical model identity retained for usage correlation.
    pub model_id: Uuid,
    /// Targets ordered by ascending priority, then weighted within a priority.
    pub targets: Vec<InferenceTargetConfig>,
}

/// One local target selected by native model dispatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceTargetConfig {
    /// Stable target identity retained for attempt correlation.
    pub target_id: Uuid,
    /// Existing Gateway service containing the complete allowed endpoint set.
    pub service: String,
    /// Model identifier forwarded to this target.
    pub upstream_model: String,
    /// Zero-based fallback group. Lower priorities are attempted first.
    pub priority: u32,
    /// Positive selection weight within one priority group.
    pub weight: u32,
}

/// One credential's exact grant on an inference route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceGrantConfig {
    /// Credential generation accepted by this immutable policy revision.
    pub credential_generation: u64,
    /// External model aliases visible to and invokable by the credential.
    pub models: Vec<String>,
    /// Closed protocol endpoints allowed by the credential.
    pub endpoints: Vec<InferenceEndpoint>,
    /// Explicit local enforcement limits.
    pub limits: InferenceLimitsConfig,
}

/// Closed native inference endpoint identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InferenceEndpoint {
    Models,
    ChatCompletions,
    Completions,
    Embeddings,
}

impl InferenceEndpoint {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Models => "models",
            Self::ChatCompletions => "chat-completions",
            Self::Completions => "completions",
            Self::Embeddings => "embeddings",
        }
    }
}

impl fmt::Display for InferenceEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for InferenceEndpoint {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "models" => Ok(Self::Models),
            "chat-completions" => Ok(Self::ChatCompletions),
            "completions" => Ok(Self::Completions),
            "embeddings" => Ok(Self::Embeddings),
            other => Err(format!(
                "unknown inference endpoint '{other}'; expected models, chat-completions, completions, or embeddings"
            )),
        }
    }
}

/// Explicit per-Gateway limits attached to one credential grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InferenceLimitsConfig {
    /// Maximum concurrent requests for this grant on one Gateway.
    pub max_concurrent_requests: u64,
    /// Sustained request allowance per minute on one Gateway.
    pub requests_per_minute: u64,
    /// Maximum immediate request burst.
    pub request_burst: u64,
    /// Token budget per minute on one Gateway.
    pub tokens_per_minute: u64,
}
