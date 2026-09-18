//! Closed `static_bundles` ACL projection for WEB0.4.
//!
//! No S3 endpoint or object credential fields are admitted. Standalone may
//! optionally name a local digest-addressed directory; cloud-managed mode
//! rejects that field so Cloud remains the sole object-authority owner.

use crate::error::{GatewayError, Result};
use crate::static_object::{
    reject_forbidden_static_snapshot_keys, StaticBundleManifest, StaticObjectEntry,
    STATIC_BUNDLE_MANIFEST_SCHEMA,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// One router-facing static bundle target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticBundleConfig {
    pub release_digest: String,
    pub object_namespace: String,
    #[serde(default = "default_base_path")]
    pub base_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spa_fallback: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance_digest: Option<String>,
    pub manifest: StaticBundleManifestConfig,
    /// Standalone-only digest file store (`<dir>/<sha256>`). Forbidden in
    /// cloud-managed mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_digest_store: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticBundleManifestConfig {
    pub entry_document: String,
    #[serde(default)]
    pub entries: BTreeMap<String, StaticObjectEntry>,
}

fn default_base_path() -> String {
    "/".into()
}

impl StaticBundleConfig {
    pub(crate) fn validate(&self, name: &str) -> Result<()> {
        reject_forbidden_static_snapshot_keys([
            "release_digest",
            "object_namespace",
            "base_path",
            "spa_fallback",
            "provenance_digest",
            "local_digest_store",
            "entry_document",
        ])
        .map_err(|error| GatewayError::Config(format!("static_bundles '{name}': {error}")))?;

        if self.object_namespace.trim().is_empty()
            || self.object_namespace.contains("://")
            || self.object_namespace.to_ascii_lowercase().contains("s3")
        {
            return Err(GatewayError::Config(format!(
                "static_bundles '{name}' object_namespace must be a non-empty logical reference without object endpoints"
            )));
        }
        if self.object_namespace.len() > 512 {
            return Err(GatewayError::Config(format!(
                "static_bundles '{name}' object_namespace exceeds 512 bytes"
            )));
        }

        let manifest = self.sealed_manifest();
        manifest.validate().map_err(|error| {
            GatewayError::Config(format!("static_bundles '{name}' manifest: {error}"))
        })?;

        if let Some(store) = &self.local_digest_store {
            if store.as_os_str().is_empty() {
                return Err(GatewayError::Config(format!(
                    "static_bundles '{name}' local_digest_store must be a non-empty path"
                )));
            }
            // Fail closed at validate: a missing store soft-opens as runtime
            // 404s while operators believe the bundle authority is wired.
            if !store.exists() {
                return Err(GatewayError::Config(format!(
                    "static_bundles '{name}' local_digest_store does not exist: {}",
                    store.display()
                )));
            }
            if !store.is_dir() {
                return Err(GatewayError::Config(format!(
                    "static_bundles '{name}' local_digest_store must be a directory: {}",
                    store.display()
                )));
            }
            // Fail closed: missing digest objects soft-open as runtime 404 after
            // a green validate. Stat each sealed entry under the digest store.
            for (object_path, entry) in &manifest.entries {
                let object = store.join(&entry.digest);
                if object.parent() != Some(store.as_path()) {
                    return Err(GatewayError::Config(format!(
                        "static_bundles '{name}' digest for '{object_path}' escaped local_digest_store"
                    )));
                }
                match std::fs::symlink_metadata(&object) {
                    Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                        // Same size+digest admission as the first GET
                        // (`admit_object_bytes`). A present file with the right
                        // name still soft-opens until traffic if bytes disagree.
                        if metadata.len() != entry.size {
                            return Err(GatewayError::Config(format!(
                                "static_bundles '{name}' local_digest_store object for '{object_path}' size mismatch: expected {} bytes, got {}",
                                entry.size,
                                metadata.len()
                            )));
                        }
                        let bytes = std::fs::read(&object).map_err(|error| {
                            GatewayError::Config(format!(
                                "static_bundles '{name}' local_digest_store could not read object for '{object_path}': {error}"
                            ))
                        })?;
                        let actual = crate::static_object::port::sha256_hex(&bytes);
                        if actual != entry.digest || bytes.len() as u64 != entry.size {
                            return Err(GatewayError::Config(format!(
                                "static_bundles '{name}' local_digest_store object for '{object_path}' digest mismatch: expected {}, got {actual}",
                                entry.digest
                            )));
                        }
                    }
                    Ok(_) => {
                        return Err(GatewayError::Config(format!(
                            "static_bundles '{name}' local_digest_store object for '{object_path}' is not a regular file: {}",
                            object.display()
                        )));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        return Err(GatewayError::Config(format!(
                            "static_bundles '{name}' local_digest_store is missing object for '{object_path}' (digest {})",
                            entry.digest
                        )));
                    }
                    Err(error) => {
                        return Err(GatewayError::Config(format!(
                            "static_bundles '{name}' local_digest_store could not inspect object for '{object_path}': {error}"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn sealed_manifest(&self) -> StaticBundleManifest {
        StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: self.release_digest.clone(),
            entry_document: self.manifest.entry_document.clone(),
            base_path: self.base_path.clone(),
            spa_fallback: self.spa_fallback.clone(),
            provenance_digest: self.provenance_digest.clone(),
            entries: self.manifest.entries.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{GatewayConfig, OperatingMode};
    use crate::static_object::sha256_hex;

    #[test]
    fn parses_and_validates_a_static_bundle_with_local_digest_store() {
        let body = b"<html>ok</html>";
        let digest = sha256_hex(body);
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(&digest), body).unwrap();
        let store = directory.path().display().to_string().replace('\\', "/");
        let acl = format!(
            r#"
mode {{
  kind = "standalone"
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}

routers "site" {{
  rule = "PathPrefix(`/`)"
  service = "web"
  entrypoints = ["web"]
}}

static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "org/proj/rel"
  base_path = "/"
  spa_fallback = "index.html"
  local_digest_store = "{store}"
  manifest {{
    entry_document = "index.html"
    entries "index.html" {{
      digest = "{digest}"
      size = {size}
      media_type = "text/html"
    }}
  }}
}}
"#,
            size = body.len()
        );
        let config = GatewayConfig::from_acl(&acl).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.static_bundles["web"].manifest.entry_document,
            "index.html"
        );
    }

    #[test]
    fn standalone_missing_digest_object_in_local_store_fails_validate() {
        let body = b"<html>ok</html>";
        let digest = sha256_hex(body);
        let directory = tempfile::tempdir().unwrap();
        // Store directory exists but the digest object was never copied in.
        let store = directory.path().display().to_string().replace('\\', "/");
        let acl = format!(
            r#"
mode {{
  kind = "standalone"
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}

routers "site" {{
  rule = "PathPrefix(`/`)"
  service = "web"
  entrypoints = ["web"]
}}

static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "org/proj/rel"
  local_digest_store = "{store}"
  manifest {{
    entry_document = "index.html"
    entries "index.html" {{
      digest = "{digest}"
      size = {size}
      media_type = "text/html"
    }}
  }}
}}
"#,
            size = body.len()
        );
        let err = GatewayConfig::from_acl(&acl)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("missing object") && err.contains("index.html"),
            "missing digest objects must fail validate: {err}"
        );
    }

    #[test]
    fn validate_activation_fails_closed_when_static_bundle_object_digest_mismatches() {
        let declared = b"hello";
        let digest = sha256_hex(declared);
        let directory = tempfile::tempdir().unwrap();
        // Same length, different bytes, stored under the declared digest name.
        std::fs::write(directory.path().join(&digest), b"world").unwrap();
        let store = directory.path().display().to_string().replace('\\', "/");
        let acl = format!(
            r#"
mode {{
  kind = "standalone"
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}

routers "site" {{
  rule = "PathPrefix(`/`)"
  service = "web"
  entrypoints = ["web"]
}}

static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "org/proj/rel"
  local_digest_store = "{store}"
  manifest {{
    entry_document = "index.html"
    entries "index.html" {{
      digest = "{digest}"
      size = {size}
      media_type = "text/html"
    }}
  }}
}}
"#,
            size = declared.len()
        );
        let config = GatewayConfig::from_acl(&acl).unwrap();
        let err = crate::validate_activation(&config).unwrap_err().to_string();
        assert!(
            err.contains("digest mismatch") && err.contains("index.html"),
            "byte-mismatched digest objects must fail validate_activation: {err}"
        );
    }

    #[test]
    fn parses_manifest_content_encoding_into_sealed_entries() {
        let body = b"\x1f\x8bencoded";
        let digest = sha256_hex(body);
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join(&digest), body).unwrap();
        let store = directory.path().display().to_string().replace('\\', "/");
        let acl = format!(
            r#"
mode {{
  kind = "standalone"
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}

routers "site" {{
  rule = "PathPrefix(`/`)"
  service = "web"
  entrypoints = ["web"]
}}

static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "org/proj/rel"
  local_digest_store = "{store}"
  manifest {{
    entry_document = "assets/app.js"
    entries "assets/app.js" {{
      digest = "{digest}"
      size = {size}
      media_type = "application/javascript"
      content_encoding = "gzip"
    }}
  }}
}}
"#,
            size = body.len()
        );
        let config = GatewayConfig::from_acl(&acl).unwrap();
        config.validate().unwrap();
        assert_eq!(
            config.static_bundles["web"].manifest.entries["assets/app.js"].content_encoding,
            Some("gzip".into())
        );
    }

    #[test]
    fn cloud_managed_rejects_local_digest_store() {
        let digest = sha256_hex(b"x");
        let acl = format!(
            r#"
mode {{
  kind = "cloud-managed"
}}

managed {{
  gateway_id = "11111111-1111-4111-8111-111111111111"
}}

static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "org/proj/rel"
  local_digest_store = "/tmp/objects"
  manifest {{
    entry_document = "index.html"
    entries "index.html" {{
      digest = "{digest}"
      size = 1
      media_type = "text/html"
    }}
  }}
}}
"#
        );
        let config = GatewayConfig::from_acl(&acl).unwrap();
        assert_eq!(config.mode, OperatingMode::CloudManaged);
        let err = config.validate().unwrap_err().to_string();
        assert!(err.contains("local_digest_store"));
    }

    #[test]
    fn standalone_static_bundle_without_local_digest_store_fails_validate() {
        let digest = sha256_hex(b"x");
        let acl = format!(
            r#"
mode {{
  kind = "standalone"
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}

routers "site" {{
  rule = "PathPrefix(`/`)"
  service = "web"
  entrypoints = ["web"]
}}

static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "org/proj/rel"
  manifest {{
    entry_document = "index.html"
    entries "index.html" {{
      digest = "{digest}"
      size = 1
      media_type = "text/html"
    }}
  }}
}}
"#
        );
        let err = GatewayConfig::from_acl(&acl)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("local_digest_store"),
            "standalone authority-less static_bundles must fail validate: {err}"
        );
    }

    #[test]
    fn cloud_managed_static_bundles_without_object_authority_fail_validate() {
        let digest = sha256_hex(b"x");
        let acl = format!(
            r#"
mode {{
  kind = "cloud-managed"
}}

managed {{
  gateway_id = "11111111-1111-4111-8111-111111111111"
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}

routers "site" {{
  rule = "PathPrefix(`/`)"
  service = "web"
  entrypoints = ["web"]
}}

static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "org/proj/rel"
  manifest {{
    entry_document = "index.html"
    entries "index.html" {{
      digest = "{digest}"
      size = 1
      media_type = "text/html"
    }}
  }}
}}
"#
        );
        let err = GatewayConfig::from_acl(&acl)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("WEB0.1") || err.contains("object authority"),
            "cloud-managed authority-less static_bundles must fail validate: {err}"
        );
    }

    #[test]
    fn rejects_s3_shaped_object_namespace() {
        let digest = sha256_hex(b"x");
        let directory = tempfile::tempdir().unwrap();
        let store = directory.path().display().to_string().replace('\\', "/");
        let acl = format!(
            r#"
static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "s3://bucket/path"
  local_digest_store = "{store}"
  manifest {{
    entry_document = "index.html"
    entries "index.html" {{
      digest = "{digest}"
      size = 1
      media_type = "text/html"
    }}
  }}
}}
"#
        );
        let err = GatewayConfig::from_acl(&acl)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("object_namespace"));
    }

    #[test]
    fn standalone_missing_local_digest_store_directory_fails_validate() {
        let body = b"<html>ok</html>";
        let digest = sha256_hex(body);
        let missing = tempfile::tempdir()
            .unwrap()
            .path()
            .join("digest-store-missing");
        let store = missing.display().to_string().replace('\\', "/");
        let acl = format!(
            r#"
mode {{
  kind = "standalone"
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}

routers "site" {{
  rule = "PathPrefix(`/`)"
  service = "web"
  entrypoints = ["web"]
}}

static_bundles "web" {{
  release_digest = "{digest}"
  object_namespace = "org/proj/rel"
  local_digest_store = "{store}"
  manifest {{
    entry_document = "index.html"
    entries "index.html" {{
      digest = "{digest}"
      size = {size}
      media_type = "text/html"
    }}
  }}
}}
"#,
            size = body.len()
        );
        let err = GatewayConfig::from_acl(&acl)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("local_digest_store") && err.contains("does not exist"),
            "missing digest store must fail closed at validate: {err}"
        );
    }
}
