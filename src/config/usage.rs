//! Node-local managed inference usage spool configuration.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub(crate) const DEFAULT_USAGE_SPOOL_MAX_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MIN_USAGE_SPOOL_MAX_BYTES: u64 = 1024 * 1024;

/// Bootstrap-local storage boundary for durable managed inference events.
///
/// The directory and capacity are node settings. They are not a Cloud usage
/// ingestion or acknowledgement contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UsageSpoolConfig {
    /// Dedicated absolute directory containing only Gateway usage spool files.
    pub directory: PathBuf,
    /// Hard retained-byte limit. Gateway never silently evicts unacknowledged
    /// records when this limit is reached.
    #[serde(default = "default_usage_spool_max_bytes")]
    pub max_bytes: u64,
}

pub(crate) const fn default_usage_spool_max_bytes() -> u64 {
    DEFAULT_USAGE_SPOOL_MAX_BYTES
}
