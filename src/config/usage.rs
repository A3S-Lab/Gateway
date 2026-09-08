//! Node-local managed inference usage spool configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub(crate) const DEFAULT_USAGE_SPOOL_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MIN_USAGE_SPOOL_MAX_BYTES: u64 = 1024 * 1024;
pub(crate) const DEFAULT_USAGE_CLOUD_INGEST_BATCH_LIMIT: usize = 64;

/// Bootstrap-local storage boundary for durable managed inference events.
///
/// The directory and capacity are node settings. Optional Cloud ingest fields
/// pair this node with the frozen batch/ACK contract in
/// `docs/usage-cloud-ingest.md`; they are still not the Cloud ledger itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageSpoolConfig {
    /// Dedicated absolute directory containing only Gateway usage spool files.
    pub directory: PathBuf,
    /// Hard retained-byte limit. Gateway never silently evicts unacknowledged
    /// records when this limit is reached.
    #[serde(default = "default_usage_spool_max_bytes")]
    pub max_bytes: u64,
    /// Absolute HTTPS (or HTTP for fixtures) URL for Cloud usage batch ingest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_ingest_endpoint: Option<String>,
    /// Environment variable holding the bearer token for Cloud usage ingest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud_ingest_token_env: Option<String>,
}

pub(crate) const fn default_usage_spool_max_bytes() -> u64 {
    DEFAULT_USAGE_SPOOL_MAX_BYTES
}

impl UsageSpoolConfig {
    /// True when Cloud ingest transport should start with the spool.
    pub(crate) fn cloud_ingest_configured(&self) -> bool {
        self.cloud_ingest_endpoint.is_some() || self.cloud_ingest_token_env.is_some()
    }
}
