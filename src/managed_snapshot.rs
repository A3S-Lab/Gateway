//! Gateway-native managed snapshot contract and applied-state tracking.
//!
//! This protocol is intentionally separate from the A3S Cloud node-command
//! acknowledgement. It proves which exact configuration the Gateway process
//! accepted and currently considers ready.

use crate::config::{GatewayConfig, OperatingMode};
use crate::error::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Managed snapshot request schema.
pub const MANAGED_SNAPSHOT_SCHEMA: &str = "a3s.gateway.managed-snapshot.v1";
/// Managed snapshot status schema.
pub const MANAGED_SNAPSHOT_STATUS_SCHEMA: &str = "a3s.gateway.managed-snapshot-status.v1";

const MAX_ACL_BYTES: usize = 1024 * 1024;
const MAX_VALIDITY_HOURS: i64 = 24;
const MAX_CLOCK_SKEW_MINUTES: i64 = 5;
const MAX_REJECTION_REASON_BYTES: usize = 4096;

pub(crate) type ConfigReloadFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
pub(crate) type ConfigReloadCallback =
    Arc<dyn Fn(GatewayConfig) -> ConfigReloadFuture + Send + Sync>;

/// A complete, bounded configuration snapshot addressed to one Gateway.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSnapshot {
    /// Versioned request schema.
    pub schema: String,
    /// Stable logical Gateway identity from the bootstrap ACL.
    pub gateway_id: Uuid,
    /// Positive, monotonically increasing snapshot revision.
    pub revision: u64,
    /// Revision that must currently be applied, or `null` for the first apply.
    pub expected_revision: Option<u64>,
    /// SHA-256 digest of the exact UTF-8 ACL bytes.
    pub snapshot_digest: String,
    /// Beginning of the bounded snapshot validity interval.
    pub issued_at: DateTime<Utc>,
    /// Exclusive end of the bounded snapshot validity interval.
    pub expires_at: DateTime<Utc>,
    /// Complete Gateway ACL configuration.
    pub acl: String,
}

impl ManagedSnapshot {
    /// Construct a managed snapshot and calculate its ACL digest.
    pub fn new(
        gateway_id: Uuid,
        revision: u64,
        expected_revision: Option<u64>,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        acl: impl Into<String>,
    ) -> Self {
        let acl = acl.into();
        Self {
            schema: MANAGED_SNAPSHOT_SCHEMA.to_string(),
            gateway_id,
            revision,
            expected_revision,
            snapshot_digest: digest_acl(&acl),
            issued_at,
            expires_at,
            acl,
        }
    }

    fn identity(&self) -> ManagedSnapshotIdentity {
        ManagedSnapshotIdentity {
            gateway_id: self.gateway_id,
            revision: self.revision,
            snapshot_digest: self.snapshot_digest.clone(),
        }
    }
}

/// Calculate the canonical digest for exact managed-snapshot ACL bytes.
pub fn digest_acl(acl: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(acl.as_bytes()))
}

/// Exact identity used to ask whether one snapshot is ready.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSnapshotIdentity {
    pub gateway_id: Uuid,
    pub revision: u64,
    pub snapshot_digest: String,
}

impl ManagedSnapshotIdentity {
    pub(crate) fn from_query(query: Option<&str>) -> std::result::Result<Option<Self>, String> {
        let Some(query) = query.filter(|query| !query.is_empty()) else {
            return Ok(None);
        };

        let mut gateway_id = None;
        let mut revision = None;
        let mut snapshot_digest = None;
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "gateway_id" if gateway_id.is_none() => {
                    gateway_id = Some(
                        Uuid::parse_str(&value)
                            .map_err(|error| format!("Invalid gateway_id query value: {error}"))?,
                    );
                }
                "revision" if revision.is_none() => {
                    revision = Some(
                        value
                            .parse::<u64>()
                            .map_err(|error| format!("Invalid revision query value: {error}"))?,
                    );
                }
                "snapshot_digest" if snapshot_digest.is_none() => {
                    snapshot_digest = Some(value.into_owned());
                }
                "gateway_id" | "revision" | "snapshot_digest" => {
                    return Err(format!("Duplicate managed snapshot query field '{key}'"));
                }
                _ => return Err(format!("Unknown managed snapshot query field '{key}'")),
            }
        }

        let selector = Self {
            gateway_id: gateway_id.ok_or_else(|| {
                "Managed snapshot readiness requires gateway_id, revision, and snapshot_digest"
                    .to_string()
            })?,
            revision: revision.ok_or_else(|| {
                "Managed snapshot readiness requires gateway_id, revision, and snapshot_digest"
                    .to_string()
            })?,
            snapshot_digest: snapshot_digest.ok_or_else(|| {
                "Managed snapshot readiness requires gateway_id, revision, and snapshot_digest"
                    .to_string()
            })?,
        };
        if selector.gateway_id.is_nil() {
            return Err("gateway_id query value must not be the nil UUID".to_string());
        }
        if selector.revision == 0 {
            return Err("revision query value must be positive".to_string());
        }
        validate_digest_format(&selector.snapshot_digest)?;
        Ok(Some(selector))
    }
}

/// Managed snapshot status relative to an exact requested identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedSnapshotState {
    Disabled,
    Uninitialized,
    Applying,
    Applied,
    Rejected,
    Expired,
    NotApplied,
}

/// Metadata retained for the current applied snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedManagedSnapshot {
    pub gateway_id: Uuid,
    pub revision: u64,
    pub expected_revision: Option<u64>,
    pub snapshot_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub applied_at: DateTime<Utc>,
}

impl AppliedManagedSnapshot {
    fn identity(&self) -> ManagedSnapshotIdentity {
        ManagedSnapshotIdentity {
            gateway_id: self.gateway_id,
            revision: self.revision,
            snapshot_digest: self.snapshot_digest.clone(),
        }
    }

    fn is_exact_replay(&self, snapshot: &ManagedSnapshot) -> bool {
        self.gateway_id == snapshot.gateway_id
            && self.revision == snapshot.revision
            && self.expected_revision == snapshot.expected_revision
            && self.snapshot_digest == snapshot.snapshot_digest
            && self.issued_at == snapshot.issued_at
            && self.expires_at == snapshot.expires_at
    }
}

/// Metadata retained for the most recent rejected snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedManagedSnapshot {
    pub gateway_id: Uuid,
    pub revision: u64,
    pub snapshot_digest: String,
    pub rejected_at: DateTime<Utc>,
    pub reason: String,
}

impl RejectedManagedSnapshot {
    fn identity(&self) -> ManagedSnapshotIdentity {
        ManagedSnapshotIdentity {
            gateway_id: self.gateway_id,
            revision: self.revision,
            snapshot_digest: self.snapshot_digest.clone(),
        }
    }
}

/// Bounded Management API view of managed snapshot state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedSnapshotStatus {
    pub schema: String,
    pub gateway_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested: Option<ManagedSnapshotIdentity>,
    pub state: ManagedSnapshotState,
    pub ready: bool,
    pub replayed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<AppliedManagedSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_rejection: Option<RejectedManagedSnapshot>,
}

#[derive(Debug, Default)]
struct StoredSnapshotState {
    applying: Option<ManagedSnapshotIdentity>,
    applied: Option<AppliedManagedSnapshot>,
    last_rejection: Option<RejectedManagedSnapshot>,
}

/// HTTP-independent result returned to the Management API handler.
pub(crate) struct ManagedSnapshotApplyResult {
    pub status_code: u16,
    pub status: ManagedSnapshotStatus,
}

#[derive(Debug, Clone, Copy)]
enum RejectionKind {
    Invalid,
    Conflict,
    Unavailable,
}

impl RejectionKind {
    const fn status_code(self) -> u16 {
        match self {
            Self::Invalid => 422,
            Self::Conflict => 409,
            Self::Unavailable => 503,
        }
    }
}

/// Serializes managed applies and tracks only bounded applied/rejected metadata.
pub(crate) struct ManagedSnapshotStore {
    gateway_id: Option<Uuid>,
    apply_lock: Mutex<()>,
    state: RwLock<StoredSnapshotState>,
}

impl ManagedSnapshotStore {
    pub(crate) fn new(gateway_id: Option<Uuid>) -> Self {
        Self {
            gateway_id,
            apply_lock: Mutex::new(()),
            state: RwLock::new(StoredSnapshotState::default()),
        }
    }

    pub(crate) async fn apply(
        &self,
        snapshot: ManagedSnapshot,
        reload: Option<&ConfigReloadCallback>,
    ) -> ManagedSnapshotApplyResult {
        let _apply = self.apply_lock.lock().await;
        let now = Utc::now();
        let requested = snapshot.identity();

        if let Err(reason) = validate_snapshot_envelope(&snapshot, now) {
            return self.reject(requested, reason, RejectionKind::Invalid, now);
        }

        let Some(gateway_id) = self.gateway_id else {
            return self.reject(
                requested,
                "Managed snapshots require managed.gateway_id in the bootstrap ACL",
                RejectionKind::Conflict,
                now,
            );
        };
        if snapshot.gateway_id != gateway_id {
            return self.reject(
                requested,
                format!(
                    "Snapshot targets Gateway {}, but this process is Gateway {}",
                    snapshot.gateway_id, gateway_id
                ),
                RejectionKind::Conflict,
                now,
            );
        }

        let applied = self.read_state().applied.clone();
        if let Some(applied) = &applied {
            if snapshot.revision == applied.revision {
                if snapshot.snapshot_digest != applied.snapshot_digest {
                    return self.reject(
                        requested,
                        "Snapshot revision conflicts with the digest already applied",
                        RejectionKind::Conflict,
                        now,
                    );
                }
                if !applied.is_exact_replay(&snapshot) {
                    return self.reject(
                        requested,
                        "Snapshot revision and digest conflict with previously applied validity metadata",
                        RejectionKind::Conflict,
                        now,
                    );
                }
                let mut status = self.status(Some(snapshot.identity()), now);
                status.replayed = true;
                return ManagedSnapshotApplyResult {
                    status_code: 200,
                    status,
                };
            }
            if snapshot.revision < applied.revision {
                return self.reject(
                    requested,
                    format!(
                        "Snapshot revision {} is stale; revision {} is already applied",
                        snapshot.revision, applied.revision
                    ),
                    RejectionKind::Conflict,
                    now,
                );
            }
        }

        let applied_revision = applied.as_ref().map(|snapshot| snapshot.revision);
        if snapshot.expected_revision != applied_revision {
            return self.reject(
                requested,
                format!(
                    "Snapshot expected revision {}, but Gateway has applied revision {}",
                    display_revision(snapshot.expected_revision),
                    display_revision(applied_revision)
                ),
                RejectionKind::Conflict,
                now,
            );
        }

        let config = match parse_managed_config(&snapshot) {
            Ok(config) => config,
            Err(reason) => {
                return self.reject(requested, reason, RejectionKind::Invalid, now);
            }
        };

        let Some(reload) = reload else {
            return self.reject(
                requested,
                "Managed snapshot reload is not available",
                RejectionKind::Unavailable,
                now,
            );
        };

        {
            let mut state = self.write_state();
            state.applying = Some(snapshot.identity());
        }

        if let Err(error) = reload(config).await {
            return self.reject(
                requested,
                error.to_string(),
                RejectionKind::Invalid,
                Utc::now(),
            );
        }

        let applied_at = Utc::now();
        {
            let mut state = self.write_state();
            state.applying = None;
            state.applied = Some(AppliedManagedSnapshot {
                gateway_id: snapshot.gateway_id,
                revision: snapshot.revision,
                expected_revision: snapshot.expected_revision,
                snapshot_digest: snapshot.snapshot_digest,
                issued_at: snapshot.issued_at,
                expires_at: snapshot.expires_at,
                applied_at,
            });
        }

        ManagedSnapshotApplyResult {
            status_code: 200,
            status: self.status(Some(requested), applied_at),
        }
    }

    pub(crate) fn status(
        &self,
        requested: Option<ManagedSnapshotIdentity>,
        now: DateTime<Utc>,
    ) -> ManagedSnapshotStatus {
        let state = self.read_state();
        let applied = state.applied.clone();
        let last_rejection = state.last_rejection.clone();

        let (snapshot_state, reason) = match requested.as_ref() {
            Some(requested)
                if state
                    .applying
                    .as_ref()
                    .is_some_and(|applying| applying == requested) =>
            {
                (ManagedSnapshotState::Applying, None)
            }
            Some(requested)
                if applied
                    .as_ref()
                    .is_some_and(|applied| applied.identity() == *requested) =>
            {
                if applied
                    .as_ref()
                    .is_some_and(|applied| applied.expires_at <= now)
                {
                    (
                        ManagedSnapshotState::Expired,
                        Some("Applied snapshot has expired".to_string()),
                    )
                } else {
                    (ManagedSnapshotState::Applied, None)
                }
            }
            Some(requested)
                if last_rejection
                    .as_ref()
                    .is_some_and(|rejected| rejected.identity() == *requested) =>
            {
                (
                    ManagedSnapshotState::Rejected,
                    last_rejection
                        .as_ref()
                        .map(|rejected| rejected.reason.clone()),
                )
            }
            Some(_) => (
                ManagedSnapshotState::NotApplied,
                Some("The requested snapshot is not applied".to_string()),
            ),
            None if self.gateway_id.is_none() => (
                ManagedSnapshotState::Disabled,
                Some(
                    "Managed snapshots require managed.gateway_id in the bootstrap ACL".to_string(),
                ),
            ),
            None if state.applying.is_some() => (ManagedSnapshotState::Applying, None),
            None if applied
                .as_ref()
                .is_some_and(|applied| applied.expires_at <= now) =>
            {
                (
                    ManagedSnapshotState::Expired,
                    Some("Applied snapshot has expired".to_string()),
                )
            }
            None if applied.is_some() => (ManagedSnapshotState::Applied, None),
            None if last_rejection.is_some() => (
                ManagedSnapshotState::Rejected,
                last_rejection
                    .as_ref()
                    .map(|rejected| rejected.reason.clone()),
            ),
            None => (ManagedSnapshotState::Uninitialized, None),
        };

        let ready = requested.as_ref().is_some_and(|requested| {
            state.applying.is_none()
                && applied.as_ref().is_some_and(|applied| {
                    applied.identity() == *requested && applied.expires_at > now
                })
        });

        ManagedSnapshotStatus {
            schema: MANAGED_SNAPSHOT_STATUS_SCHEMA.to_string(),
            gateway_id: self.gateway_id,
            requested,
            state: snapshot_state,
            ready,
            replayed: false,
            reason,
            applied,
            last_rejection,
        }
    }

    fn reject(
        &self,
        requested: ManagedSnapshotIdentity,
        reason: impl AsRef<str>,
        kind: RejectionKind,
        now: DateTime<Utc>,
    ) -> ManagedSnapshotApplyResult {
        let reason = sanitize_reason(reason.as_ref());
        {
            let mut state = self.write_state();
            state.applying = None;
            state.last_rejection = Some(RejectedManagedSnapshot {
                gateway_id: requested.gateway_id,
                revision: requested.revision,
                snapshot_digest: requested.snapshot_digest.clone(),
                rejected_at: now,
                reason: reason.clone(),
            });
        }
        let mut status = self.status(Some(requested), now);
        status.state = ManagedSnapshotState::Rejected;
        status.ready = false;
        status.reason = Some(reason);
        ManagedSnapshotApplyResult {
            status_code: kind.status_code(),
            status,
        }
    }

    fn read_state(&self) -> RwLockReadGuard<'_, StoredSnapshotState> {
        self.state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_state(&self) -> RwLockWriteGuard<'_, StoredSnapshotState> {
        self.state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn validate_snapshot_envelope(
    snapshot: &ManagedSnapshot,
    now: DateTime<Utc>,
) -> std::result::Result<(), String> {
    if snapshot.schema != MANAGED_SNAPSHOT_SCHEMA {
        return Err(format!(
            "Unsupported managed snapshot schema {:?}",
            snapshot.schema
        ));
    }
    if snapshot.gateway_id.is_nil() {
        return Err("Managed snapshot gateway_id must not be the nil UUID".to_string());
    }
    if snapshot.revision == 0 {
        return Err("Managed snapshot revision must be positive".to_string());
    }
    if snapshot
        .expected_revision
        .is_some_and(|expected| expected == 0 || expected >= snapshot.revision)
    {
        return Err(
            "Managed snapshot expected_revision must be positive and precede revision".to_string(),
        );
    }
    if snapshot.acl.is_empty() || snapshot.acl.len() > MAX_ACL_BYTES || snapshot.acl.contains('\0')
    {
        return Err("Managed snapshot ACL must contain 1 byte to 1 MiB without NUL".to_string());
    }
    validate_digest_format(&snapshot.snapshot_digest)?;
    if snapshot.snapshot_digest != digest_acl(&snapshot.acl) {
        return Err("Managed snapshot digest does not match the exact ACL bytes".to_string());
    }
    if snapshot.expires_at <= snapshot.issued_at {
        return Err("Managed snapshot expiry must follow its issue time".to_string());
    }
    if snapshot.expires_at - snapshot.issued_at > Duration::hours(MAX_VALIDITY_HOURS) {
        return Err(format!(
            "Managed snapshot validity must not exceed {MAX_VALIDITY_HOURS} hours"
        ));
    }
    if snapshot.issued_at > now + Duration::minutes(MAX_CLOCK_SKEW_MINUTES) {
        return Err(format!(
            "Managed snapshot issue time exceeds the {MAX_CLOCK_SKEW_MINUTES}-minute clock-skew allowance"
        ));
    }
    if snapshot.expires_at <= now {
        return Err("Managed snapshot has expired".to_string());
    }
    Ok(())
}

fn validate_digest_format(digest: &str) -> std::result::Result<(), String> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err("Managed snapshot digest must use the sha256:<hex> format".to_string());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(
            "Managed snapshot digest must contain 64 lowercase hexadecimal digits".to_string(),
        );
    }
    Ok(())
}

fn parse_managed_config(snapshot: &ManagedSnapshot) -> std::result::Result<GatewayConfig, String> {
    let config = GatewayConfig::from_acl(&snapshot.acl).map_err(|error| error.to_string())?;
    config.validate().map_err(|error| error.to_string())?;
    if config.mode != OperatingMode::CloudManaged {
        return Err("Managed snapshot ACL must use operating mode 'cloud-managed'".to_string());
    }
    if config.managed.gateway_id != Some(snapshot.gateway_id) {
        return Err(
            "Managed snapshot ACL gateway_id must match the envelope gateway_id".to_string(),
        );
    }
    Ok(config)
}

fn display_revision(revision: Option<u64>) -> String {
    revision.map_or_else(|| "none".to_string(), |revision| revision.to_string())
}

fn sanitize_reason(reason: &str) -> String {
    let reason = reason.replace(['\0', '\r', '\n'], " ");
    let reason = reason.trim();
    if reason.is_empty() {
        return "Managed snapshot was rejected".to_string();
    }

    let mut sanitized = String::with_capacity(reason.len().min(MAX_REJECTION_REASON_BYTES));
    for character in reason.chars() {
        if sanitized.len() + character.len_utf8() > MAX_REJECTION_REASON_BYTES {
            break;
        }
        sanitized.push(character);
    }
    sanitized
}

#[cfg(test)]
mod tests;
