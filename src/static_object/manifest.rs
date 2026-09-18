//! Sealed static-bundle manifest admission.
//!
//! Cloud/Edge will publish this shape into managed snapshots (`WEB0.1`).
//! Until that contract is fixture-locked, Gateway admits only this closed
//! schema and rejects credentials, endpoints, and mutable discovery fields.

use super::path::normalize_object_path;
use super::StaticObjectError;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

/// Frozen until Cloud publishes a `WEB0.1` fixture lock.
pub const STATIC_BUNDLE_MANIFEST_SCHEMA: &str = "a3s.gateway.static-bundle-manifest.v1";

const MAX_ENTRIES: usize = 50_000;
const MAX_PATH_BYTES: usize = 1024;
const MAX_MEDIA_TYPE_BYTES: usize = 128;
const MAX_CONTENT_ENCODING_BYTES: usize = 32;

/// One digest-bound object in an immutable Web release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticObjectEntry {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
}

/// Sealed release manifest Gateway validates before activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticBundleManifest {
    pub schema: String,
    pub release_digest: String,
    pub entry_document: String,
    pub base_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spa_fallback: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_digest: Option<String>,
    pub entries: BTreeMap<String, StaticObjectEntry>,
}

impl StaticBundleManifest {
    /// Fail closed on traversal, digest shape, duplicates, and missing entry.
    pub fn validate(&self) -> Result<(), StaticObjectError> {
        if self.schema != STATIC_BUNDLE_MANIFEST_SCHEMA {
            return Err(StaticObjectError::Contract(format!(
                "static bundle manifest schema must be {STATIC_BUNDLE_MANIFEST_SCHEMA}"
            )));
        }
        validate_sha256("release_digest", &self.release_digest)?;
        if let Some(provenance) = &self.provenance_digest {
            validate_sha256("provenance_digest", provenance)?;
        }
        if self.base_path != "/" && !self.base_path.starts_with('/') {
            return Err(StaticObjectError::Contract(
                "static bundle base_path must be '/' or an absolute route prefix".into(),
            ));
        }
        if self.base_path.contains("..") || self.base_path.contains('\\') {
            return Err(StaticObjectError::Contract(
                "static bundle base_path must not contain traversal".into(),
            ));
        }
        if self.entries.is_empty() {
            return Err(StaticObjectError::Contract(
                "static bundle manifest must declare at least one entry".into(),
            ));
        }
        if self.entries.len() > MAX_ENTRIES {
            return Err(StaticObjectError::Contract(format!(
                "static bundle manifest exceeds {MAX_ENTRIES} entries"
            )));
        }

        let entry_document = normalize_object_path(&self.entry_document)?;
        if !self.entries.contains_key(&entry_document) {
            return Err(StaticObjectError::Contract(format!(
                "static bundle entry_document '{entry_document}' is missing from entries"
            )));
        }
        if let Some(fallback) = &self.spa_fallback {
            let fallback = normalize_object_path(fallback)?;
            if !self.entries.contains_key(&fallback) {
                return Err(StaticObjectError::Contract(format!(
                    "static bundle spa_fallback '{fallback}' is missing from entries"
                )));
            }
        }

        let mut normalized = HashSet::new();
        let mut case_keys = HashSet::new();
        for (raw_path, entry) in &self.entries {
            if raw_path.len() > MAX_PATH_BYTES {
                return Err(StaticObjectError::InvalidPath(format!(
                    "static object path exceeds {MAX_PATH_BYTES} bytes"
                )));
            }
            let path = normalize_object_path(raw_path)?;
            if path != *raw_path {
                return Err(StaticObjectError::InvalidPath(format!(
                    "static object path '{raw_path}' must already be normalized as '{path}'"
                )));
            }
            if !normalized.insert(path.clone()) {
                return Err(StaticObjectError::InvalidPath(format!(
                    "static object path '{path}' is duplicated"
                )));
            }
            let lower = path.to_ascii_lowercase();
            if !case_keys.insert(lower) {
                return Err(StaticObjectError::InvalidPath(format!(
                    "static object path '{path}' collides with another path under ASCII case folding"
                )));
            }
            validate_entry(&path, entry)?;
        }
        Ok(())
    }

    /// Select a manifest entry for a normalized request path.
    ///
    /// Empty path selects `entry_document`. Missing assets never fall through
    /// to SPA fallback here; SPA eligibility is a separate request-policy gate.
    #[cfg(test)]
    pub fn select_entry<'a>(
        &'a self,
        normalized_path: &str,
    ) -> Result<&'a StaticObjectEntry, StaticObjectError> {
        Ok(self.select_entry_key(normalized_path)?.1)
    }

    /// Select a manifest entry and return the canonical object path.
    ///
    /// Empty path selects `entry_document`. Missing assets never fall through
    /// to SPA fallback here; SPA eligibility is a separate request-policy gate.
    pub fn select_entry_key<'a>(
        &'a self,
        normalized_path: &str,
    ) -> Result<(String, &'a StaticObjectEntry), StaticObjectError> {
        let key = if normalized_path.is_empty() {
            normalize_object_path(&self.entry_document)?
        } else {
            normalized_path.to_owned()
        };
        let entry = self.entries.get(&key).ok_or_else(|| {
            StaticObjectError::NotFound(format!("static object '{key}' not in manifest"))
        })?;
        Ok((key, entry))
    }

    /// Content fingerprint used to namespace the admitted-object cache.
    ///
    /// Distinct from `release_digest`: this hashes the sealed Gateway-facing
    /// manifest fields so a cache entry cannot outlive a silent entry rewrite
    /// under the same release identity.
    pub fn content_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.schema.as_bytes());
        hasher.update([0]);
        hasher.update(self.release_digest.as_bytes());
        hasher.update([0]);
        hasher.update(self.entry_document.as_bytes());
        hasher.update([0]);
        hasher.update(self.base_path.as_bytes());
        hasher.update([0]);
        if let Some(fallback) = &self.spa_fallback {
            hasher.update(fallback.as_bytes());
        }
        hasher.update([0]);
        if let Some(provenance) = &self.provenance_digest {
            hasher.update(provenance.as_bytes());
        }
        hasher.update([0]);
        for (path, entry) in &self.entries {
            hasher.update(path.as_bytes());
            hasher.update([0]);
            hasher.update(entry.digest.as_bytes());
            hasher.update([0]);
            hasher.update(entry.size.to_le_bytes());
            hasher.update([0]);
            hasher.update(entry.media_type.as_bytes());
            hasher.update([0]);
            if let Some(encoding) = &entry.content_encoding {
                hasher.update(encoding.as_bytes());
            }
            hasher.update([0]);
        }
        format!("{:x}", hasher.finalize())
    }
}

fn validate_entry(path: &str, entry: &StaticObjectEntry) -> Result<(), StaticObjectError> {
    validate_sha256("digest", &entry.digest)?;
    if entry.media_type.is_empty() || entry.media_type.len() > MAX_MEDIA_TYPE_BYTES {
        return Err(StaticObjectError::Contract(format!(
            "static object '{path}' media_type must be 1..{MAX_MEDIA_TYPE_BYTES} bytes"
        )));
    }
    if entry
        .media_type
        .as_bytes()
        .iter()
        .any(|byte| byte.is_ascii_control())
    {
        return Err(StaticObjectError::Contract(format!(
            "static object '{path}' media_type must not contain controls"
        )));
    }
    if let Some(encoding) = &entry.content_encoding {
        if encoding.is_empty() || encoding.len() > MAX_CONTENT_ENCODING_BYTES {
            return Err(StaticObjectError::Contract(format!(
                "static object '{path}' content_encoding must be 1..{MAX_CONTENT_ENCODING_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<(), StaticObjectError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(StaticObjectError::Contract(format!(
            "static bundle {field} must be a lowercase sha256 hex digest"
        )))
    }
}

/// Reject snapshot/config blobs that smuggle object credentials or endpoints.
pub fn reject_forbidden_static_snapshot_keys(
    keys: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<(), StaticObjectError> {
    for key in keys {
        let key = key.as_ref();
        let lower = key.to_ascii_lowercase();
        if lower.contains("credential")
            || lower.contains("secret")
            || lower.contains("access_key")
            || lower.contains("secret_key")
            || lower == "endpoint"
            || lower.ends_with("_endpoint")
            || lower.contains("s3://")
            || lower.contains("amazonaws.com")
        {
            return Err(StaticObjectError::Contract(format!(
                "static bundle snapshot must not carry object credential or endpoint field '{key}'"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(n: u8) -> String {
        format!("{n:064x}")
    }

    fn valid_manifest() -> StaticBundleManifest {
        let mut entries = BTreeMap::new();
        entries.insert(
            "index.html".into(),
            StaticObjectEntry {
                digest: digest(1),
                size: 12,
                media_type: "text/html".into(),
                content_encoding: None,
            },
        );
        entries.insert(
            "assets/app.js".into(),
            StaticObjectEntry {
                digest: digest(2),
                size: 4,
                media_type: "application/javascript".into(),
                content_encoding: Some("gzip".into()),
            },
        );
        StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: digest(9),
            entry_document: "index.html".into(),
            base_path: "/".into(),
            spa_fallback: Some("index.html".into()),
            provenance_digest: Some(digest(8)),
            entries,
        }
    }

    #[test]
    fn accepts_a_sealed_manifest() {
        valid_manifest().validate().unwrap();
        assert_eq!(valid_manifest().select_entry("").unwrap().digest, digest(1));
        assert_eq!(
            valid_manifest().select_entry("assets/app.js").unwrap().size,
            4
        );
    }

    #[test]
    fn rejects_missing_entry_document_and_bad_digests() {
        let mut missing = valid_manifest();
        missing.entry_document = "missing.html".into();
        assert!(missing
            .validate()
            .unwrap_err()
            .to_string()
            .contains("entry_document"));

        let mut bad = valid_manifest();
        bad.release_digest = "nope".into();
        assert!(bad
            .validate()
            .unwrap_err()
            .to_string()
            .contains("release_digest"));
    }

    #[test]
    fn rejects_case_colliding_paths() {
        let mut manifest = valid_manifest();
        manifest.entries.insert(
            "Assets/App.js".into(),
            StaticObjectEntry {
                digest: digest(3),
                size: 1,
                media_type: "application/javascript".into(),
                content_encoding: None,
            },
        );
        assert!(manifest
            .validate()
            .unwrap_err()
            .to_string()
            .contains("case folding"));
    }

    #[test]
    fn missing_asset_does_not_silently_select_spa_fallback() {
        let err = valid_manifest()
            .select_entry("missing.js")
            .unwrap_err()
            .to_string();
        assert!(err.contains("not in manifest"));
        assert!(!err.to_lowercase().contains("spa"));
    }

    #[test]
    fn rejects_credential_and_endpoint_snapshot_keys() {
        assert!(reject_forbidden_static_snapshot_keys(["release_digest"]).is_ok());
        for key in [
            "s3_endpoint",
            "object_credential",
            "aws_secret_key",
            "access_key_id",
        ] {
            assert!(
                reject_forbidden_static_snapshot_keys([key]).is_err(),
                "expected rejection for {key}"
            );
        }
    }
}
