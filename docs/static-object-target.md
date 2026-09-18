# Gateway static object target (`WEB0.4`)

Status: **Gateway foundation with request path**. Path normalization, sealed
manifest admission, digest integrity gates, ACL `static_bundles`, GET/HEAD
dispatch after the ordinary request middleware pipeline, SPA fallback policy,
a snapshot-local bounded admitted-object cache, and a standalone local digest
store are implemented and tested. Cloud object-authority adapters and managed
snapshot fixtures wait on Cloud `WEB0.1`.

## Ownership

| Component | Owns | Does not own |
| --- | --- | --- |
| A3S Cloud / Edge | Immutable Web release identity, manifest publication, route binding, object credentials | Per-request path serving |
| A3S Gateway | `GET`/`HEAD` delivery, path normalize, manifest select, digest/size admit, response headers | List/write/delete objects; discovering "current" release; S3 endpoints in ACL |
| Object authority | Digest-addressed bytes | Browser-facing URLs or tenant policy |

Gateway never carries S3 endpoints or object credentials in ACL or managed
snapshots. Standalone requires `local_digest_store` (a digest-named file
directory) whenever `static_bundles` are present — validate fails closed
without it. Cloud-managed mode rejects `local_digest_store` and also rejects
any `static_bundles` until Cloud `WEB0.1` wires the shared object authority,
so authority-less bundles never soft-validate then hard-fail at build.

## ACL shape

```acl
static_bundles "web" {
  release_digest = "…"
  object_namespace = "org/project/release"
  base_path = "/"
  spa_fallback = "index.html"
  local_digest_store = "/var/lib/a3s-gateway/static-objects"
  manifest {
    entry_document = "index.html"
    entries "index.html" {
      digest = "…"
      size = 12
      media_type = "text/html"
    }
    entries "assets/app.js" {
      digest = "…"
      size = 64
      media_type = "application/javascript"
      content_encoding = "gzip"
    }
  }
}

routers "site" {
  rule = "Host(`app.example.com`)"
  service = "web"
}
```

## Closed invariants

1. Normalize and decode the request path once; reject traversal, absolute
   forms, backslashes, NULs, empty segments, and ambiguous percent-encoding.
2. Select a manifest entry before any object authority contact.
3. Admit bytes to cache/response only after exact size and lowercase SHA-256
   digest checks.
4. Missing assets fail closed; SPA fallback applies only to extension-less
   navigation GETs and never masks missing assets, `/api` (first path segment,
   ASCII case-insensitive), auth, or integrity failures.
5. Snapshot field names that smuggle credentials or object endpoints are
   rejected.
6. Only `GET`/`HEAD` are served; other methods return 405. `HEAD` verifies the
   digest-bound object through the read-only port `head` and never admits bytes
   through `get`; `GET` alone populates the admitted-byte cache.
7. Responses set `X-Content-Type-Options: nosniff` and derive `Content-Type`
   from the sealed manifest.
8. Static routes run the same request middleware pipeline as proxy routes
   before object serve (auth, rate limits, and other router middlewares apply).
9. Admitted bytes may enter a snapshot-local bounded LRU cache only after
   size/digest checks. Keys are namespaced by object namespace, release digest,
   sealed manifest fingerprint, object path, and content encoding. Reload
   replaces the runtime and drops the prior cache; a cache hit never bypasses
   middleware authorization.
10. Responses carry a strong `ETag` derived from the object digest.
    Matching `If-None-Match` returns 304 without contacting the object
    authority. A single contiguous `bytes=` `Range` returns 206 with
    `Content-Range`; unsatisfiable ranges return 416; multipart ranges are
    ignored and the full representation is served. `If-Range` applies the
    range only under a strong ETag match (HTTP-date / weak forms disable
    Range). Snapshot replacement drops the prior runtime cache while retained
    `Arc` handles continue draining the old release.
11. Sealed `content_encoding` is projected as `Content-Encoding` and namespaced
    in the admitted-object cache key. Gateway does not negotiate
    `Accept-Encoding`; Cloud publishes the exact encoded variant for the path.
12. Static responses set `Cache-Control` with `no-transform` so response
    middleware such as `compress` cannot rewrite admitted digest bytes, weaken
    the strong `ETag`, or invent `Content-Encoding` / `Vary`.

## Evidence

- `src/static_object/` (including `cache.rs`)
- `src/config/static_bundle.rs`
- `src/entrypoint.rs` (post-middleware static dispatch)
- `entrypoint::tests::static_bundle_listener_serves_get_spa_and_honors_middleware`
  (middleware, SPA, `If-None-Match` 304, `Range` 206, strong `If-Range`
  hit→206 / miss→200, sealed `Content-Encoding`)
- `entrypoint::tests::static_bundle_listener_preserves_sealed_bytes_under_compress`
- `entrypoint::tests::static_bundle_listener_drains_inflight_get_across_runtime_replace`
- `config::static_bundle::tests::standalone_static_bundle_without_local_digest_store_fails_validate`
- `config::static_bundle::tests::cloud_managed_static_bundles_without_object_authority_fail_validate`
- `static_object::serve::tests::spa_fallback_never_masks_missing_assets_or_posts`
  (missing assets, reserved `/api…` namespace, SPA `/settings`, POST 405)
- `static_object::serve::tests::sealed_content_encoding_is_emitted_without_accept_encoding_negotiation`
- `static_object::cache::tests::content_encoding_is_part_of_the_cache_key_namespace`
- `docs/first-principles-test-plan.md` §`WEB0.4`

Architecture source:
[Cloud static web hosting architecture](https://github.com/A3S-Lab/Cloud/blob/main/docs/static-web-hosting-architecture.md)
§6.
