//! Hosted modern MCP service-profile and route-policy configuration.

mod validation;

#[cfg(test)]
mod tests;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

/// First stateless MCP protocol revision supported by the native data plane.
pub const MCP_PROTOCOL_VERSION: &str = "2026-07-28";

/// Audience accepted by hosted MCP service routes.
pub const MCP_CREDENTIAL_AUDIENCE: &str = "cloud-mcp";

/// Complete expiring MCP projection carried by one Gateway snapshot.
///
/// Immutable hosted-server semantics live in `profiles`. Mutable public access
/// policy and exact Runtime endpoint membership live in `routes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    /// Exclusive end of the route-policy validity window.
    pub expires_at: DateTime<Utc>,
    /// Immutable hosted-server profiles keyed by their opaque SHA-256 binding.
    #[serde(default)]
    pub profiles: HashMap<String, McpServiceProfileConfig>,
    /// Credential verifier projections keyed by stable credential ID.
    #[serde(default)]
    pub credentials: HashMap<Uuid, McpCredentialConfig>,
    /// Mutable route policies keyed by stable route ID.
    #[serde(default)]
    pub routes: HashMap<Uuid, McpRouteConfig>,
}

/// Immutable protocol behavior shared by compatible AssetReleases.
///
/// The digest also covers server-owned behavior that is deliberately not
/// duplicated into Gateway configuration (for example the discovery result).
/// Gateway therefore validates the binding format and target equality, but
/// does not attempt to recreate the digest from this projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServiceProfileConfig {
    /// Opaque immutable semantics binding. Must equal the profile map key.
    pub profile_digest: String,
    /// Exact modern protocol revisions accepted by the hosted server.
    pub protocol_versions: Vec<String>,
    /// One literal Streamable HTTP POST path.
    pub path: String,
    /// Whether request-scoped SSE responses are supported.
    pub request_sse: bool,
    /// Whether long-lived subscription/listen operations are supported.
    pub subscriptions: bool,
    /// Hosted-server request body ceiling.
    pub max_request_bytes: u64,
    /// Hosted-server response body/stream ceiling.
    pub max_response_bytes: u64,
}

/// One service-level credential verifier projection.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCredentialConfig {
    /// Stable Identity-owned credential ID.
    pub credential_id: Uuid,
    /// Environment that owns the credential.
    pub environment_id: Uuid,
    /// Credential audience. Must be `cloud-mcp`.
    pub audience: String,
    /// Stable non-secret lookup prefix.
    pub prefix: String,
    /// Memory-hard Argon2id PHC verifier.
    ///
    /// It is accepted from ACL input but omitted from every serialized or
    /// debug configuration view.
    #[serde(skip_serializing)]
    pub(crate) verifier_hash: String,
    /// Positive issuance generation.
    pub generation: u64,
    /// Credential expiry evaluated locally by Gateway.
    pub expires_at: DateTime<Utc>,
    /// Explicit revocation state.
    pub revoked: bool,
}

impl McpCredentialConfig {
    pub(crate) fn verifier_hash(&self) -> &str {
        &self.verifier_hash
    }
}

impl fmt::Debug for McpCredentialConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("McpCredentialConfig")
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

/// Mutable public route policy bound to one immutable service profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpRouteConfig {
    /// Stable Cloud-owned route identity.
    pub route_id: Uuid,
    /// Existing Gateway router that establishes listener, hostname, and path.
    pub router: String,
    /// Environment that owns the route and all grants.
    pub environment_id: Uuid,
    /// Positive mutable policy revision.
    pub policy_revision: u64,
    /// Exact immutable service profile served by every target.
    pub profile_digest: String,
    /// Exact browser origins accepted when an Origin header is present.
    pub allowed_origins: Vec<String>,
    /// Maximum accepted request-header bytes.
    pub max_header_bytes: u64,
    /// Effective request body ceiling, no greater than the service profile.
    pub max_request_bytes: u64,
    /// Effective response body/stream ceiling, no greater than the profile.
    pub max_response_bytes: u64,
    /// Maximum time to receive upstream response headers.
    pub first_response_timeout: String,
    /// Maximum silence between request-scoped SSE events.
    pub stream_idle_timeout: String,
    /// Maximum total request-scoped SSE lifetime.
    pub stream_total_timeout: String,
    /// Maximum graceful-drain allowance for in-flight work.
    pub drain_timeout: String,
    /// Explicitly approved non-sensitive MCP names allowed as telemetry labels.
    #[serde(default)]
    pub telemetry_names: Vec<String>,
    /// Complete exact-profile target set in deterministic dispatch order.
    pub targets: Vec<McpTargetConfig>,
    /// Credential grants keyed by stable credential ID.
    #[serde(default)]
    pub grants: HashMap<Uuid, McpGrantConfig>,
}

/// One exact Runtime Service replica eligible for an MCP route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTargetConfig {
    /// Stable target identity retained for attempt correlation.
    pub target_id: Uuid,
    /// Cloud node that reported the Runtime observation.
    pub node_id: Uuid,
    /// Published AssetRelease currently running in this replica.
    pub asset_release_id: Uuid,
    /// Exact Runtime Unit identity.
    pub unit_id: String,
    /// Exact positive Runtime generation.
    pub generation: u64,
    /// Existing Gateway service containing exactly this endpoint.
    pub service: String,
    /// Exact loopback HTTP endpoint admitted from Runtime evidence.
    pub endpoint: String,
    /// Runtime-observed immutable semantics binding.
    pub profile_digest: String,
    /// Zero-based fallback group. Lower priorities are selected first.
    pub priority: u32,
    /// Positive selection weight within one priority group.
    pub weight: u32,
}

/// One credential's exact service-level grant on an MCP route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpGrantConfig {
    /// Credential generation accepted by this policy revision.
    pub credential_generation: u64,
    /// Exact MCP method allowlist.
    pub methods: Vec<String>,
    /// Optional exact non-resource name allowlist for applicable methods.
    #[serde(default)]
    pub names: Vec<String>,
    /// Explicit node-local enforcement limits.
    pub limits: McpLimitsConfig,
}

/// Explicit per-Gateway limits attached to one MCP credential grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpLimitsConfig {
    /// Maximum concurrent requests for this grant on one Gateway.
    pub max_concurrent_requests: u64,
    /// Sustained request allowance per minute on one Gateway.
    pub requests_per_minute: u64,
    /// Maximum immediate request burst.
    pub request_burst: u64,
}
