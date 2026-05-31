# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-05-31

### Added

- `strip-prefix` middleware now supports a single-segment wildcard prefix (e.g. `/apps/*`): it strips the literal base plus exactly one dynamic path segment, so a single middleware can serve every dynamically-named workload under `/apps/<id>/` without a per-workload middleware entry (avoids ConfigMap churn and the associated reload race).

## [1.0.3] - 2026-05-31

### Fixed

- Host rule matching now strips the port from the request authority before comparing, so a request that reaches the gateway on a non-default port (e.g. `Host: app.example.com:49164`) still matches a port-less Ingress host instead of falling through to a host-less catch-all.
- Router selection now prefers the most-specific / highest-priority route. Effective priority is the explicit `a3s-gateway.io/priority` annotation when set (higher wins, Traefik-style), otherwise the rule length — so a host-less catch-all PathPrefix(/) no longer swallows more-specific (host-qualified or longer-path) routers.
- The Kubernetes Ingress (and IngressRoute CRD) watcher now rebuilds its API client and backs off after a poll failure instead of spinning forever on a poisoned connection, so a transient API-server disconnect no longer freezes the router table until pod restart.

## [1.0.2] - 2026-05-16

### Fixed

- Fixed `tokio-rt-worker` panic on startup when the Kubernetes Ingress watcher
  opened its first TLS connection to the apiserver
  (`Could not automatically determine the process-level CryptoProvider from
  Rustls crate features`). With `kube` and `redis` features both pulling in
  rustls 0.23 alongside `aws-lc-rs` and `ring`, rustls refuses to auto-select a
  provider; the gateway now installs `rustls::crypto::ring` as the process
  default at the top of `main()` before any TLS client is constructed.

## [1.0.1] - 2026-05-15

### Fixed

- Linux release binaries (and OCI images published to ghcr.io) are now built with
  the `kube` and `redis` features enabled, so the published image can act as a
  Kubernetes Ingress Controller and use Redis-backed distributed rate limiting
  out of the box. Prior 1.0.0 image had `default = []` features only and logged
  `Kubernetes provider configured but the 'kube' feature is not enabled` when
  used with a `providers.kubernetes` config block.

## [1.0.0] - 2026-05-12

### Breaking

- Provider re-exports narrowed: `DockerProvider` and `spawn_docker_loop` are no longer
  re-exported from the crate root. Use `from_acl()` Docker provider config instead.
- `GatewayState` enum and `HealthStatus` struct are now `#[non_exhaustive]` —
  match arms must include a wildcard (`_`) pattern.
- Management API `VersionInfo` response now includes an `api_version` field (`"v1"`).
- Minimum Supported Rust Version (MSRV) declared: **1.82**.

### Added

- `EntrypointConfig::new(address)` constructor for convenient programmatic config.
- `VersionInfo.api_version` field for management API versioning.
- `rust-version = "1.82"` in Cargo.toml (MSRV policy).
- Criterion benchmarks: `routing`, `middleware_pipeline`, `acl_parse`.
- 35 new unit tests for the ACL configuration parser.
- 5 new unit tests for rate-limit middleware (deterministic time, edge cases).
- `router` and `middleware` modules exposed as `#[doc(hidden)] pub` for benchmarking.

### Fixed

- `GatewayConfig::default()` now uses `EntrypointConfig::new()` internally.

## [0.2.5] - 2026-05-10

### Added

- ACL config parsing and management API for runtime configuration.

## [0.2.4] - 2026-04-28

### Added

- macOS ARM64 OCI image support.

### Fixed

- Docker image build simplified to linux/amd64 only.

## [0.2.3] - 2026-04-15

### Changed

- Refactored gateway into smaller files (proxy, router, service, middleware modules).
- Split large files to meet 1000-line limit.

## [0.2.2] - 2026-04-01

### Added

- RevisionRouter traffic splitting and load balancer access tests.

## [0.2.1] - 2026-03-15

### Added

- Initial public release with full feature set.
- HTTP/HTTPS, WebSocket, SSE, gRPC, TCP, UDP proxy support.
- 15 built-in middlewares.
- Knative-style autoscaler with scale-to-zero.
- ACME/Let's Encrypt certificate management.
- File, DNS, Docker, and Kubernetes service discovery.
- Management API with mTLS support.
