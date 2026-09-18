//! WEB0.4 read-only static object target foundation.
//!
//! Gateway serves immutable Web releases from a digest-bound object authority.
//! Managed Cloud adapters wait on `WEB0.1` fixture locks; standalone may use a
//! local digest directory without carrying S3 endpoints in ACL.
//!
//! See [`docs/static-object-target.md`](../../docs/static-object-target.md).

mod cache;
mod directory;
mod manifest;
#[cfg(test)]
mod memory;
mod path;
pub(crate) mod port;
mod range;
mod serve;

pub(crate) use cache::AdmittedObjectCache;
pub(crate) use directory::DirectoryObjectAuthority;
pub(crate) use manifest::{
    reject_forbidden_static_snapshot_keys, StaticBundleManifest, StaticObjectEntry,
    STATIC_BUNDLE_MANIFEST_SCHEMA,
};
#[cfg(test)]
pub(crate) use memory::MemoryObjectAuthority;
#[cfg(test)]
pub(crate) use path::normalize_request_path;
#[cfg(test)]
pub(crate) use port::{admit_object_bytes, sha256_hex};
pub(crate) use serve::{
    serve_static_bundle, static_serve_error_response, StaticBundleRuntime, StaticServeHeaders,
};

use thiserror::Error;

/// Fail-closed errors for static object admission and serving.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StaticObjectError {
    #[error("static object contract error: {0}")]
    Contract(String),
    #[error("static object path error: {0}")]
    InvalidPath(String),
    #[error("static object not found: {0}")]
    NotFound(String),
    #[error("static object integrity error: {0}")]
    Integrity(String),
}

#[cfg(test)]
mod foundation_tests {
    use super::*;
    use bytes::Bytes;
    use port::ReadOnlyObjectPort;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn digest_for(body: &[u8]) -> String {
        port::sha256_hex(body)
    }

    #[tokio::test]
    async fn selects_manifest_entry_then_admits_digest_bound_bytes() {
        let index = Bytes::from_static(b"<html>ok</html>");
        let asset = Bytes::from_static(b"console.log(1)");
        let authority = MemoryObjectAuthority::new();
        let index_digest = authority.insert(index.clone()).unwrap();
        let asset_digest = authority.insert(asset.clone()).unwrap();

        let mut entries = BTreeMap::new();
        entries.insert(
            "index.html".into(),
            StaticObjectEntry {
                digest: index_digest.clone(),
                size: index.len() as u64,
                media_type: "text/html".into(),
                content_encoding: None,
            },
        );
        entries.insert(
            "assets/app.js".into(),
            StaticObjectEntry {
                digest: asset_digest.clone(),
                size: asset.len() as u64,
                media_type: "application/javascript".into(),
                content_encoding: None,
            },
        );
        let manifest = StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: digest_for(b"release"),
            entry_document: "index.html".into(),
            base_path: "/".into(),
            spa_fallback: Some("index.html".into()),
            provenance_digest: None,
            entries,
        };
        manifest.validate().unwrap();
        reject_forbidden_static_snapshot_keys(["release_digest", "object_namespace"]).unwrap();

        let path = normalize_request_path("/assets/app.js").unwrap();
        let entry = manifest.select_entry(&path).unwrap();
        let fetched = authority.get(&entry.digest).await.unwrap();
        let admitted = admit_object_bytes(&entry.digest, entry.size, fetched.body).unwrap();
        assert_eq!(admitted.body.as_ref(), b"console.log(1)");

        let runtime = StaticBundleRuntime {
            name: Arc::from("web"),
            manifest_digest: manifest.content_fingerprint(),
            manifest,
            base_path: "/".into(),
            object_namespace: "org/proj/rel".into(),
            port: Arc::new(authority),
            cache: Arc::new(AdmittedObjectCache::with_defaults()),
        };
        let response = serve_static_bundle(
            &runtime,
            &http::Method::GET,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(response.body().as_ref(), b"<html>ok</html>");
    }
}
