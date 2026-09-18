//! HTTP GET/HEAD serving for an admitted static bundle.

use super::cache::{AdmittedObjectCache, StaticObjectCacheKey};
use super::path::{normalize_object_path, normalize_request_path};
use super::port::{admit_object_bytes, ReadOnlyObjectPort};
use super::{StaticBundleManifest, StaticObjectError};
use bytes::Bytes;
use http::{header, Method, StatusCode};
use std::sync::Arc;

/// Runtime binding for one router-facing static bundle.
#[derive(Clone)]
pub struct StaticBundleRuntime {
    pub name: Arc<str>,
    pub manifest: StaticBundleManifest,
    /// Absolute route prefix (`/` or `/app`). Request paths are stripped once.
    pub base_path: String,
    pub object_namespace: String,
    /// Fingerprint of the sealed manifest content (cache-key namespace).
    pub manifest_digest: String,
    pub port: Arc<dyn ReadOnlyObjectPort>,
    /// Snapshot-local admitted-byte cache. Replaced wholesale on reload.
    pub cache: Arc<AdmittedObjectCache>,
}

/// Optional request headers that affect static object serving.
#[derive(Debug, Clone, Copy, Default)]
pub struct StaticServeHeaders<'a> {
    pub accept: Option<&'a str>,
    pub if_none_match: Option<&'a str>,
    pub range: Option<&'a str>,
    /// When present with `Range`, applies the range only if this strong
    /// validator matches the object ETag. HTTP-date forms are unsupported
    /// (no `Last-Modified`), so they disable the range.
    pub if_range: Option<&'a str>,
}

/// Serve one static-bundle request after route match.
pub async fn serve_static_bundle(
    bundle: &StaticBundleRuntime,
    method: &Method,
    request_path: &str,
    headers: StaticServeHeaders<'_>,
) -> Result<http::Response<Bytes>, StaticServeError> {
    if *method != Method::GET && *method != Method::HEAD {
        return Err(StaticServeError::MethodNotAllowed);
    }

    let relative = strip_base_path(request_path, &bundle.base_path)?;
    let normalized = normalize_request_path(&relative).map_err(StaticServeError::Object)?;
    let (selected_path, entry) = match bundle.manifest.select_entry_key(&normalized) {
        Ok(selected) => selected,
        Err(StaticObjectError::NotFound(_))
            if spa_fallback_eligible(&normalized, headers.accept) =>
        {
            let fallback = bundle.manifest.spa_fallback.as_ref().ok_or_else(|| {
                StaticServeError::Object(StaticObjectError::NotFound(format!(
                    "static object '{normalized}' not in manifest"
                )))
            })?;
            let fallback = normalize_object_path(fallback).map_err(StaticServeError::Object)?;
            bundle
                .manifest
                .select_entry_key(&fallback)
                .map_err(StaticServeError::Object)?
        }
        Err(error) => return Err(StaticServeError::Object(error)),
    };

    let etag = strong_etag(&entry.digest);
    let entry_or_fallback = is_entry_or_fallback(&bundle.manifest, &normalized);
    if if_none_match_satisfies(headers.if_none_match, &etag) {
        let mut response = http::Response::new(Bytes::new());
        *response.status_mut() = StatusCode::NOT_MODIFIED;
        apply_common_headers(
            response.headers_mut(),
            entry,
            &etag,
            entry_or_fallback,
            None,
            None,
        )?;
        return Ok(response);
    }

    let range_header = effective_range_header(headers.range, headers.if_range, &etag);
    let range_parse =
        crate::static_object::range::parse_single_byte_range(range_header, entry.size);
    if matches!(
        range_parse,
        crate::static_object::range::RangeParse::Unsatisfiable
    ) {
        let mut response = http::Response::new(Bytes::new());
        *response.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;
        apply_common_headers(
            response.headers_mut(),
            entry,
            &etag,
            entry_or_fallback,
            Some(0),
            Some(format!("bytes */{}", entry.size)),
        )?;
        return Ok(response);
    }

    // HEAD must not pull object bytes: verify existence/size via the read-only
    // port and emit headers only. GET admits digest-bound bytes below.
    if *method == Method::HEAD {
        let meta = bundle
            .port
            .head(&entry.digest)
            .await
            .map_err(StaticServeError::Object)?;
        if meta.digest != entry.digest || meta.size != entry.size {
            return Err(StaticServeError::Object(StaticObjectError::Integrity(
                format!(
                    "static object HEAD mismatch for {}: expected size {} digest {}, got size {} digest {}",
                    entry.digest, entry.size, entry.digest, meta.size, meta.digest
                ),
            )));
        }
        let (status, content_length, content_range) = match range_parse {
            crate::static_object::range::RangeParse::Satisfiable(range) => (
                StatusCode::PARTIAL_CONTENT,
                Some(range.len()),
                Some(format!(
                    "bytes {}-{}/{}",
                    range.start, range.end, entry.size
                )),
            ),
            _ => (StatusCode::OK, Some(entry.size), None),
        };
        let mut response = http::Response::new(Bytes::new());
        *response.status_mut() = status;
        apply_common_headers(
            response.headers_mut(),
            entry,
            &etag,
            entry_or_fallback,
            content_length,
            content_range,
        )?;
        return Ok(response);
    }

    let cache_key = StaticObjectCacheKey::new(
        &bundle.object_namespace,
        &bundle.manifest.release_digest,
        &bundle.manifest_digest,
        &selected_path,
        entry.content_encoding.as_deref(),
    );
    let admitted = if let Some(cached) = bundle.cache.get(&cache_key) {
        if cached.digest != entry.digest || cached.body.len() as u64 != entry.size {
            return Err(StaticServeError::Object(StaticObjectError::Integrity(
                format!("static object cache mismatch for {}", entry.digest),
            )));
        }
        cached
    } else {
        let fetched = bundle
            .port
            .get(&entry.digest)
            .await
            .map_err(StaticServeError::Object)?;
        let admitted = admit_object_bytes(&entry.digest, entry.size, fetched.body)
            .map_err(StaticServeError::Object)?;
        bundle.cache.insert(cache_key, admitted.clone());
        admitted
    };

    tracing::debug!(
        bundle = %bundle.name,
        object_namespace = %bundle.object_namespace,
        digest = %entry.digest,
        "serving static bundle object"
    );

    let selected_range = match range_parse {
        crate::static_object::range::RangeParse::Satisfiable(range) => Some(range),
        _ => None,
    };

    let (status, body, content_length, content_range) = if let Some(range) = selected_range {
        let start = range.start as usize;
        let end_exclusive = (range.end as usize)
            .saturating_add(1)
            .min(admitted.body.len());
        let slice = admitted.body.slice(start..end_exclusive);
        let content_range = format!("bytes {}-{}/{}", range.start, range.end, entry.size);
        let length = range.len();
        (
            StatusCode::PARTIAL_CONTENT,
            slice,
            Some(length),
            Some(content_range),
        )
    } else {
        (StatusCode::OK, admitted.body, Some(entry.size), None)
    };

    let mut response = http::Response::new(body);
    *response.status_mut() = status;
    apply_common_headers(
        response.headers_mut(),
        entry,
        &etag,
        entry_or_fallback,
        content_length,
        content_range,
    )?;
    Ok(response)
}

fn strong_etag(digest: &str) -> String {
    format!("\"{digest}\"")
}

/// Resolve the `Range` header under optional `If-Range` (strong match only).
fn effective_range_header<'a>(
    range: Option<&'a str>,
    if_range: Option<&str>,
    etag: &str,
) -> Option<&'a str> {
    let range = range?;
    match if_range {
        None => Some(range),
        Some(validator) if if_range_matches(validator, etag) => Some(range),
        Some(_) => None,
    }
}

fn if_range_matches(header: &str, etag: &str) -> bool {
    let header = header.trim();
    // Strong comparison only. Weak tags and HTTP-dates do not unlock Range.
    header == etag
}

fn if_none_match_satisfies(header: Option<&str>, etag: &str) -> bool {
    let Some(header) = header.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    if header == "*" {
        return true;
    }
    header.split(',').any(|candidate| {
        let candidate = candidate.trim();
        candidate == etag
            || candidate
                .strip_prefix("W/")
                .is_some_and(|weak| weak == etag)
    })
}

fn apply_common_headers(
    headers: &mut http::HeaderMap,
    entry: &crate::static_object::StaticObjectEntry,
    etag: &str,
    entry_or_fallback: bool,
    content_length: Option<u64>,
    content_range: Option<String>,
) -> Result<(), StaticServeError> {
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_str(&entry.media_type).map_err(|_| {
            StaticServeError::Object(StaticObjectError::Contract(format!(
                "static object media_type '{}' is not a valid header value",
                entry.media_type
            )))
        })?,
    );
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        header::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::ETAG,
        header::HeaderValue::from_str(etag).map_err(|_| {
            StaticServeError::Object(StaticObjectError::Contract(
                "static object digest produced an invalid ETag".into(),
            ))
        })?,
    );
    headers.insert(
        header::ACCEPT_RANGES,
        header::HeaderValue::from_static("bytes"),
    );
    if let Some(length) = content_length {
        headers.insert(
            header::CONTENT_LENGTH,
            header::HeaderValue::from_str(&length.to_string()).expect("u64 fits header"),
        );
    }
    if let Some(content_range) = content_range {
        headers.insert(
            header::CONTENT_RANGE,
            header::HeaderValue::from_str(&content_range).map_err(|_| {
                StaticServeError::Object(StaticObjectError::Contract(
                    "static object Content-Range is not a valid header value".into(),
                ))
            })?,
        );
    }
    if let Some(encoding) = &entry.content_encoding {
        headers.insert(
            header::CONTENT_ENCODING,
            header::HeaderValue::from_str(encoding).map_err(|_| {
                StaticServeError::Object(StaticObjectError::Contract(format!(
                    "static object content_encoding '{encoding}' is not a valid header value"
                )))
            })?,
        );
    }
    let cache_control = if entry_or_fallback {
        "no-cache, no-transform"
    } else {
        "public, max-age=31536000, immutable, no-transform"
    };
    headers.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static(cache_control),
    );
    Ok(())
}

/// Convert a serve error into a native Gateway response.
pub fn static_serve_error_response(error: StaticServeError) -> (u16, &'static str) {
    match error {
        StaticServeError::MethodNotAllowed => (405, "Method not allowed"),
        StaticServeError::Object(StaticObjectError::NotFound(_)) => (404, "Not found"),
        StaticServeError::Object(StaticObjectError::InvalidPath(_)) => (400, "Bad request"),
        StaticServeError::Object(StaticObjectError::Integrity(_)) => {
            (502, "Static object integrity failure")
        }
        StaticServeError::Object(StaticObjectError::Contract(_)) => {
            (500, "Static bundle misconfigured")
        }
        StaticServeError::BasePath => (404, "Not found"),
    }
}

#[derive(Debug)]
pub enum StaticServeError {
    MethodNotAllowed,
    BasePath,
    Object(StaticObjectError),
}

fn strip_base_path(request_path: &str, base_path: &str) -> Result<String, StaticServeError> {
    let request = if request_path.is_empty() {
        "/"
    } else {
        request_path
    };
    if base_path == "/" {
        return Ok(request.to_owned());
    }
    let base = base_path.trim_end_matches('/');
    if request == base {
        return Ok("/".into());
    }
    let prefix = format!("{base}/");
    request
        .strip_prefix(&prefix)
        .map(|rest| format!("/{rest}"))
        .ok_or(StaticServeError::BasePath)
}

fn spa_fallback_eligible(normalized_path: &str, accept: Option<&str>) -> bool {
    if normalized_path.is_empty() {
        return false;
    }
    // Asset-like paths keep a hard 404 so SPA never masks missing files.
    if normalized_path.contains('.') {
        return false;
    }
    // Same-origin `/api` namespaces must fail closed; never soft-200 the
    // SPA index over a missing or misrouted API route.
    if is_reserved_api_namespace_path(normalized_path) {
        return false;
    }
    match accept {
        None => true,
        Some(value) => value.split(',').any(|part| {
            let part = part.trim();
            part.starts_with("text/html") || part == "*/*"
        }),
    }
}

/// True when the first path segment is `api` (ASCII case-insensitive).
fn is_reserved_api_namespace_path(normalized_path: &str) -> bool {
    let path = normalized_path.trim_start_matches('/');
    let first = path.split('/').next().unwrap_or("");
    !first.is_empty() && first.eq_ignore_ascii_case("api")
}

fn is_entry_or_fallback(manifest: &StaticBundleManifest, normalized_path: &str) -> bool {
    let path = if normalized_path.is_empty() {
        manifest.entry_document.as_str()
    } else {
        normalized_path
    };
    path == manifest.entry_document
        || manifest
            .spa_fallback
            .as_deref()
            .is_some_and(|fallback| fallback == path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_object::{
        MemoryObjectAuthority, StaticObjectEntry, STATIC_BUNDLE_MANIFEST_SCHEMA,
    };
    use std::collections::BTreeMap;

    fn digest_for(body: &[u8]) -> String {
        crate::static_object::port::sha256_hex(body)
    }

    async fn bundle() -> StaticBundleRuntime {
        let index = Bytes::from_static(b"<html>home</html>");
        let asset = Bytes::from_static(b"console.log(1)");
        let authority = MemoryObjectAuthority::new();
        let index_digest = authority.insert(index.clone()).unwrap();
        let asset_digest = authority.insert(asset.clone()).unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(
            "index.html".into(),
            StaticObjectEntry {
                digest: index_digest,
                size: index.len() as u64,
                media_type: "text/html".into(),
                content_encoding: None,
            },
        );
        entries.insert(
            "assets/app.js".into(),
            StaticObjectEntry {
                digest: asset_digest,
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
        StaticBundleRuntime {
            name: Arc::from("web"),
            manifest_digest: manifest.content_fingerprint(),
            manifest,
            base_path: "/".into(),
            object_namespace: "org/proj/rel".into(),
            port: Arc::new(authority),
            cache: Arc::new(crate::static_object::AdmittedObjectCache::with_defaults()),
        }
    }

    #[tokio::test]
    async fn serves_get_and_head_with_nosniff() {
        let bundle = bundle().await;
        let get = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(get.status(), StatusCode::OK);
        assert_eq!(get.headers()["x-content-type-options"], "nosniff");
        assert_eq!(get.headers()["cache-control"], "no-cache, no-transform");
        assert!(get.headers().get("etag").is_some());
        assert_eq!(get.body().as_ref(), b"<html>home</html>");

        let head = serve_static_bundle(
            &bundle,
            &Method::HEAD,
            "/assets/app.js",
            StaticServeHeaders::default(),
        )
        .await
        .unwrap();
        assert!(head.body().is_empty());
        assert_eq!(head.headers()["content-length"], "14");
        assert_eq!(
            head.headers()["cache-control"],
            "public, max-age=31536000, immutable, no-transform"
        );
    }

    #[tokio::test]
    async fn spa_fallback_never_masks_missing_assets_or_posts() {
        let bundle = bundle().await;
        let missing_asset = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/assets/missing.js",
            StaticServeHeaders::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            missing_asset,
            StaticServeError::Object(StaticObjectError::NotFound(_))
        ));

        for api_path in ["/api", "/api/v1/x", "/API/health"] {
            let masked = serve_static_bundle(
                &bundle,
                &Method::GET,
                api_path,
                StaticServeHeaders {
                    accept: Some("text/html,application/xhtml+xml"),
                    ..StaticServeHeaders::default()
                },
            )
            .await
            .unwrap_err();
            assert!(
                matches!(
                    masked,
                    StaticServeError::Object(StaticObjectError::NotFound(_))
                ),
                "SPA must not mask {api_path}"
            );
        }

        // Trailing slash is rejected at path normalize (fail-closed), not SPA'd.
        assert!(matches!(
            serve_static_bundle(
                &bundle,
                &Method::GET,
                "/api/",
                StaticServeHeaders {
                    accept: Some("text/html"),
                    ..StaticServeHeaders::default()
                },
            )
            .await
            .unwrap_err(),
            StaticServeError::Object(StaticObjectError::InvalidPath(_))
        ));

        let spa = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/settings",
            StaticServeHeaders {
                accept: Some("text/html,application/xhtml+xml"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(spa.body().as_ref(), b"<html>home</html>");

        assert!(matches!(
            serve_static_bundle(&bundle, &Method::POST, "/", StaticServeHeaders::default())
                .await
                .unwrap_err(),
            StaticServeError::MethodNotAllowed
        ));
    }

    #[test]
    fn spa_fallback_eligibility_rejects_api_namespace() {
        // Normalized request paths are slash-free relative forms.
        assert!(!spa_fallback_eligible("api", Some("text/html")));
        assert!(!spa_fallback_eligible("api/v1", Some("text/html")));
        assert!(!spa_fallback_eligible("API", Some("*/*")));
        assert!(!spa_fallback_eligible("/api", Some("text/html")));
        assert!(spa_fallback_eligible("settings", Some("text/html")));
        assert!(spa_fallback_eligible("dashboard", None));
        assert!(!spa_fallback_eligible("assets/app.js", Some("text/html")));
    }

    #[tokio::test]
    async fn if_none_match_returns_304_without_body_or_authority_get() {
        use crate::static_object::port::{StaticObjectBytes, StaticObjectMeta};
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingPort {
            inner: MemoryObjectAuthority,
            gets: AtomicUsize,
        }

        #[async_trait]
        impl ReadOnlyObjectPort for CountingPort {
            async fn head(&self, digest: &str) -> Result<StaticObjectMeta, StaticObjectError> {
                self.inner.head(digest).await
            }

            async fn get(&self, digest: &str) -> Result<StaticObjectBytes, StaticObjectError> {
                self.gets.fetch_add(1, Ordering::SeqCst);
                self.inner.get(digest).await
            }
        }

        let index = Bytes::from_static(b"<html>home</html>");
        let authority = MemoryObjectAuthority::new();
        let index_digest = authority.insert(index.clone()).unwrap();
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
        let port = Arc::new(CountingPort {
            inner: authority,
            gets: AtomicUsize::new(0),
        });
        let manifest = StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: digest_for(b"release"),
            entry_document: "index.html".into(),
            base_path: "/".into(),
            spa_fallback: None,
            provenance_digest: None,
            entries,
        };
        let bundle = StaticBundleRuntime {
            name: Arc::from("web"),
            manifest_digest: manifest.content_fingerprint(),
            manifest,
            base_path: "/".into(),
            object_namespace: "org/proj/rel".into(),
            port: port.clone(),
            cache: Arc::new(crate::static_object::AdmittedObjectCache::with_defaults()),
        };
        bundle.manifest.validate().unwrap();

        let etag = format!("\"{index_digest}\"");
        let not_modified = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                if_none_match: Some(&etag),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
        assert!(not_modified.body().is_empty());
        assert_eq!(not_modified.headers()["etag"], etag.as_str());
        assert_eq!(port.gets.load(Ordering::SeqCst), 0);

        let miss = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                if_none_match: Some("\"deadbeef\""),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(miss.status(), StatusCode::OK);
        assert_eq!(port.gets.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn head_verifies_via_port_head_without_authority_get() {
        use crate::static_object::port::{StaticObjectBytes, StaticObjectMeta};
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingPort {
            inner: MemoryObjectAuthority,
            heads: AtomicUsize,
            gets: AtomicUsize,
        }

        #[async_trait]
        impl ReadOnlyObjectPort for CountingPort {
            async fn head(&self, digest: &str) -> Result<StaticObjectMeta, StaticObjectError> {
                self.heads.fetch_add(1, Ordering::SeqCst);
                self.inner.head(digest).await
            }

            async fn get(&self, digest: &str) -> Result<StaticObjectBytes, StaticObjectError> {
                self.gets.fetch_add(1, Ordering::SeqCst);
                self.inner.get(digest).await
            }
        }

        let index = Bytes::from_static(b"<html>home</html>");
        let authority = MemoryObjectAuthority::new();
        let index_digest = authority.insert(index.clone()).unwrap();
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
        let port = Arc::new(CountingPort {
            inner: authority,
            heads: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
        });
        let manifest = StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: digest_for(b"release"),
            entry_document: "index.html".into(),
            base_path: "/".into(),
            spa_fallback: None,
            provenance_digest: None,
            entries,
        };
        let bundle = StaticBundleRuntime {
            name: Arc::from("web"),
            manifest_digest: manifest.content_fingerprint(),
            manifest,
            base_path: "/".into(),
            object_namespace: "org/proj/rel".into(),
            port: port.clone(),
            cache: Arc::new(crate::static_object::AdmittedObjectCache::with_defaults()),
        };
        bundle.manifest.validate().unwrap();

        let response = serve_static_bundle(
            &bundle,
            &Method::HEAD,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.body().is_empty());
        assert_eq!(
            response.headers()["content-length"],
            index.len().to_string().as_str()
        );
        assert_eq!(response.headers()["etag"], format!("\"{index_digest}\""));
        assert_eq!(port.heads.load(Ordering::SeqCst), 1);
        assert_eq!(port.gets.load(Ordering::SeqCst), 0);

        let ranged = serve_static_bundle(
            &bundle,
            &Method::HEAD,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                range: Some("bytes=0-3"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(ranged.status(), StatusCode::PARTIAL_CONTENT);
        assert!(ranged.body().is_empty());
        assert_eq!(ranged.headers()["content-length"], "4");
        assert_eq!(
            ranged.headers()["content-range"],
            format!("bytes 0-3/{}", index.len())
        );
        assert_eq!(port.heads.load(Ordering::SeqCst), 2);
        assert_eq!(port.gets.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn single_byte_range_returns_206_and_unsatisfiable_416() {
        let bundle = bundle().await;
        let partial = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/assets/app.js",
            StaticServeHeaders {
                range: Some("bytes=0-6"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(partial.body().as_ref(), b"console");
        assert_eq!(partial.headers()["content-range"], "bytes 0-6/14");
        assert_eq!(partial.headers()["content-length"], "7");
        assert_eq!(partial.headers()["accept-ranges"], "bytes");

        let unsat = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/assets/app.js",
            StaticServeHeaders {
                range: Some("bytes=100-200"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(unsat.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(unsat.headers()["content-range"], "bytes */14");
        assert!(unsat.body().is_empty());
    }

    #[tokio::test]
    async fn if_range_requires_strong_etag_match_before_applying_bytes_range() {
        let bundle = bundle().await;
        let asset_digest = bundle.manifest.entries["assets/app.js"].digest.clone();
        let etag = format!("\"{asset_digest}\"");

        let matched = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/assets/app.js",
            StaticServeHeaders {
                range: Some("bytes=0-6"),
                if_range: Some(&etag),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(matched.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(matched.body().as_ref(), b"console");

        let mismatched = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/assets/app.js",
            StaticServeHeaders {
                range: Some("bytes=0-6"),
                if_range: Some("\"deadbeef\""),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(mismatched.status(), StatusCode::OK);
        assert_eq!(mismatched.body().as_ref(), b"console.log(1)");

        let weak = format!("W/{etag}");
        let weak_if_range = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/assets/app.js",
            StaticServeHeaders {
                range: Some("bytes=0-6"),
                if_range: Some(&weak),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(weak_if_range.status(), StatusCode::OK);
        assert_eq!(weak_if_range.body().as_ref(), b"console.log(1)");
    }

    #[tokio::test]
    async fn snapshot_replacement_purges_cache_while_prior_runtime_arc_still_serves() {
        let old_body = Bytes::from_static(b"<html>old</html>");
        let new_body = Bytes::from_static(b"<html>new</html>");
        let old_authority = MemoryObjectAuthority::new();
        let new_authority = MemoryObjectAuthority::new();
        let old_digest = old_authority.insert(old_body.clone()).unwrap();
        let new_digest = new_authority.insert(new_body.clone()).unwrap();

        let mut old_entries = BTreeMap::new();
        old_entries.insert(
            "index.html".into(),
            StaticObjectEntry {
                digest: old_digest,
                size: old_body.len() as u64,
                media_type: "text/html".into(),
                content_encoding: None,
            },
        );
        let old_manifest = StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: digest_for(b"release-old"),
            entry_document: "index.html".into(),
            base_path: "/".into(),
            spa_fallback: None,
            provenance_digest: None,
            entries: old_entries,
        };
        old_manifest.validate().unwrap();
        let prior = Arc::new(StaticBundleRuntime {
            name: Arc::from("web"),
            manifest_digest: old_manifest.content_fingerprint(),
            manifest: old_manifest,
            base_path: "/".into(),
            object_namespace: "org/proj/rel".into(),
            port: Arc::new(old_authority),
            cache: Arc::new(crate::static_object::AdmittedObjectCache::with_defaults()),
        });

        let first = serve_static_bundle(
            &prior,
            &Method::GET,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(first.body().as_ref(), b"<html>old</html>");
        assert_eq!(prior.cache.len(), 1);

        let mut new_entries = BTreeMap::new();
        new_entries.insert(
            "index.html".into(),
            StaticObjectEntry {
                digest: new_digest,
                size: new_body.len() as u64,
                media_type: "text/html".into(),
                content_encoding: None,
            },
        );
        let new_manifest = StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: digest_for(b"release-new"),
            entry_document: "index.html".into(),
            base_path: "/".into(),
            spa_fallback: None,
            provenance_digest: None,
            entries: new_entries,
        };
        new_manifest.validate().unwrap();
        let successor = StaticBundleRuntime {
            name: Arc::from("web"),
            manifest_digest: new_manifest.content_fingerprint(),
            manifest: new_manifest,
            base_path: "/".into(),
            object_namespace: "org/proj/rel".into(),
            port: Arc::new(new_authority),
            cache: Arc::new(crate::static_object::AdmittedObjectCache::with_defaults()),
        };

        let drained = serve_static_bundle(
            &prior,
            &Method::GET,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(drained.body().as_ref(), b"<html>old</html>");

        let next = serve_static_bundle(
            &successor,
            &Method::GET,
            "/",
            StaticServeHeaders {
                accept: Some("text/html"),
                ..StaticServeHeaders::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(next.body().as_ref(), b"<html>new</html>");
        assert_eq!(successor.cache.len(), 1);
        assert_eq!(prior.cache.len(), 1);
    }

    #[tokio::test]
    async fn admitted_cache_avoids_repeat_object_authority_gets() {
        use crate::static_object::port::{StaticObjectBytes, StaticObjectMeta};
        use async_trait::async_trait;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CountingPort {
            inner: MemoryObjectAuthority,
            gets: AtomicUsize,
        }

        #[async_trait]
        impl ReadOnlyObjectPort for CountingPort {
            async fn head(&self, digest: &str) -> Result<StaticObjectMeta, StaticObjectError> {
                self.inner.head(digest).await
            }

            async fn get(&self, digest: &str) -> Result<StaticObjectBytes, StaticObjectError> {
                self.gets.fetch_add(1, Ordering::SeqCst);
                self.inner.get(digest).await
            }
        }

        let index = Bytes::from_static(b"<html>home</html>");
        let authority = MemoryObjectAuthority::new();
        let index_digest = authority.insert(index.clone()).unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(
            "index.html".into(),
            StaticObjectEntry {
                digest: index_digest,
                size: index.len() as u64,
                media_type: "text/html".into(),
                content_encoding: None,
            },
        );
        let port = Arc::new(CountingPort {
            inner: authority,
            gets: AtomicUsize::new(0),
        });
        let manifest = StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: digest_for(b"release"),
            entry_document: "index.html".into(),
            base_path: "/".into(),
            spa_fallback: None,
            provenance_digest: None,
            entries,
        };
        let bundle = StaticBundleRuntime {
            name: Arc::from("web"),
            manifest_digest: manifest.content_fingerprint(),
            manifest,
            base_path: "/".into(),
            object_namespace: "org/proj/rel".into(),
            port: port.clone(),
            cache: Arc::new(crate::static_object::AdmittedObjectCache::with_defaults()),
        };
        bundle.manifest.validate().unwrap();

        let headers = StaticServeHeaders {
            accept: Some("text/html"),
            ..StaticServeHeaders::default()
        };
        let first = serve_static_bundle(&bundle, &Method::GET, "/", headers)
            .await
            .unwrap();
        let second = serve_static_bundle(&bundle, &Method::GET, "/", headers)
            .await
            .unwrap();
        assert_eq!(first.body(), second.body());
        assert_eq!(port.gets.load(Ordering::SeqCst), 1);
        assert_eq!(bundle.cache.len(), 1);
    }

    #[tokio::test]
    async fn sealed_content_encoding_is_emitted_without_accept_encoding_negotiation() {
        let body = Bytes::from_static(b"\x1f\x8bencoded-bytes");
        let authority = MemoryObjectAuthority::new();
        let digest = authority.insert(body.clone()).unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(
            "assets/app.js".into(),
            StaticObjectEntry {
                digest: digest.clone(),
                size: body.len() as u64,
                media_type: "application/javascript".into(),
                content_encoding: Some("gzip".into()),
            },
        );
        let manifest = StaticBundleManifest {
            schema: STATIC_BUNDLE_MANIFEST_SCHEMA.into(),
            release_digest: digest_for(b"release-encoded"),
            entry_document: "assets/app.js".into(),
            base_path: "/".into(),
            spa_fallback: None,
            provenance_digest: None,
            entries,
        };
        manifest.validate().unwrap();
        let bundle = StaticBundleRuntime {
            name: Arc::from("web"),
            manifest_digest: manifest.content_fingerprint(),
            manifest,
            base_path: "/".into(),
            object_namespace: "org/proj/rel".into(),
            port: Arc::new(authority),
            cache: Arc::new(crate::static_object::AdmittedObjectCache::with_defaults()),
        };

        let response = serve_static_bundle(
            &bundle,
            &Method::GET,
            "/assets/app.js",
            StaticServeHeaders::default(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-encoding"], "gzip");
        assert_eq!(response.headers()["content-type"], "application/javascript");
        assert_eq!(response.body().as_ref(), body.as_ref());
        assert_eq!(bundle.cache.len(), 1);
    }
}
