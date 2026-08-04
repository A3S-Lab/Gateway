# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added a typed coding-agent profile registry for A3S Code, Claude Code,
  OpenAI Codex, Gemini CLI, and OpenCode, plus explicit custom executables.
- Added shell-free native CLI passthrough and standard `SKILL.md`
  `list`, `show`, `path`, and `run` operations with deterministic root
  precedence and bounded reads.
- Added a project website and GitHub Pages deployment workflow.
- Added checksum-enforcing one-command installers for macOS, Linux, and
  Windows, with deterministic platform selection, version pinning, per-user
  installation, and failure-safe replacement.
- Added native Windows x86_64 and ARM64 ZIP artifacts to the release matrix,
  plus POSIX and PowerShell installer contract tests in CI.
- Added transport-neutral production internals for bounded durable-usage
  replay that opens each selected epoch once per batch, exact cursor-gap
  rejection, idempotent contiguous acknowledgement, v1/v2-to-v3 manifest
  migration, crash-recoverable whole-epoch reclamation, and byte-preserving
  acknowledged-prefix compaction for closed epochs. Fixed-width compacted
  sequence bounds reject incomplete tails before the original segment is
  removed; a partially acknowledged live epoch is compacted on restart.
  Usage health now exposes the acknowledged watermark and oldest retained
  cursor without claiming a Cloud ingestion wire contract.
- Added real-entrypoint WebSocket regressions for malformed downstream
  handshakes, unavailable and hanging upstream handshakes, service request
  timeouts, end-to-end request headers, trusted forwarding metadata,
  subprotocol negotiation, transparent application-message relay, and safe
  non-`101` upstream rejection propagation.
- Added real-entrypoint HTTP and SSE regressions for bidirectional
  `Connection`-nominated field isolation, plus WebSocket backend-capture
  coverage for the same downstream boundary.
- Added a real h2c full-duplex gRPC fixture that holds both request and response
  streams open concurrently, verifies downstream trailer delivery, and proves
  exact buffered-body mirroring. Focused tests cover idle and total timeout,
  disconnect cleanup, trailer filtering, terminal access logs, TTFT, and active
  request lifetime.
- Extended the real h2c fixture to capture Gateway-regenerated
  `X-Forwarded-*` metadata, normalized `TE: trailers`, and an end-to-end request
  trailer at the upstream.
- Added a real Gateway/backend compression fixture that verifies raw gzip
  delivery, exact decompression, `Vary: Accept-Encoding`, identity fallback for
  an explicitly excluded coding, and absence of internal marker headers.
- Added real Gateway/backend ordinary HTTP fixtures that prove first-chunk
  delivery before upstream completion, configured response-idle termination,
  and full-duplex progress where a response arrives before the request body is
  complete. Focused body tests cover absolute total bounds and safe trailers.
- Added a local-CA upstream TLS fixture that proves ordinary HTTP dispatch over
  an explicitly trusted HTTP/2 ALPN connection, plus default rejection and
  connection-accounting cleanup for the same untrusted certificate.

### Changed

- WebSocket upgrades now validate the required HTTP/1.1 opening-handshake
  fields and establish the upstream connection under the selected service's
  `request_timeout` before returning `101`. Upstream requests preserve
  end-to-end client headers, use Gateway-generated `X-Forwarded-*` metadata,
  and reflect a negotiated requested subprotocol to the downstream client.
- Split the large ACL, top-level configuration, and inference-authorization
  inline test suites into adjacent test modules. The production files now stay
  below 1,000 lines without changing test names or runtime behavior.
- Split the 1,531-line real-entrypoint integration suite into traffic, reload,
  management, and lifecycle files while preserving every existing top-level
  test name. Every Rust source and test file now stays below 1,000 lines.
- Centralized static and `Connection`-nominated hop-by-hop filtering across
  buffered HTTP, SSE, gRPC, and WebSocket paths. The consuming HTTP response
  filter preserves duplicate end-to-end fields without adding a hot-path
  header-map clone, and gRPC continues to forward `TE: trailers`.
- Replaced the body-buffered reqwest gRPC adapter with a Hyper HTTP/2 frame
  relay, with real-entrypoint h2c coverage. Ordinary calls now stream request
  and response DATA frames plus trailers, preserve the downstream method and
  content type, use per-service first-response/idle/total bounds, and keep
  connection and observability guards until the response body terminates.
  Mirror sampling now happens before optional body collection, so only selected
  calls are buffered once for exact shadow replay while disabled or unsampled
  calls remain full-duplex. Traffic that already requires buffering is sampled
  after final service resolution. The TLS client selects ring explicitly and
  reports initialization failure instead of depending on process-global
  provider state. Streaming SSE and gRPC DATA frames now also advance the
  aggregate response-byte counter as they are relayed.
- Native gRPC requests now use the same forwarded-metadata generator as
  HTTP and WebSocket traffic. Request and response trailer frames pass through
  the shared connection-specific header filter, while arbitrary downstream
  `TE` values are reduced to the HTTP/2-compatible `trailers` token.
- All upstream gRPC responses now use one bounded HTTP/2 frame relay. A selected
  mirror buffers only the replayable request, so shadow traffic no longer
  implies a second collected-response path.
- Ordinary HTTP now relays upstream response DATA and safe trailer frames with
  downstream backpressure instead of collecting each response first. The
  selected service's response-header, idle-body, and total-operation bounds
  apply independently, while backend, inference admission, TTFT, access-log,
  response-byte, and durable usage accounting follow the body lifetime.
  Mirrored responses are drained frame by frame instead of being aggregated.
- Ordinary HTTP and managed OpenAI dispatch now share one Rustls-backed
  HTTP/HTTPS connection pool. HTTPS targets verify certificates and hostnames
  against built-in WebPKI roots and negotiate HTTP/1.1 or HTTP/2 through ALPN
  without changing the existing streaming, timeout, or fallback boundaries.
- Middleware definitions are now validated through their production
  constructors across the CLI, Management API, startup, and reload paths.
  Runtime preparation rejects any router pipeline that cannot compile instead
  of silently omitting it, and requests consume only the precompiled snapshot.
  A rejected reload keeps the prior live configuration serving traffic.
- Active service health checks now follow the committed runtime lifecycle.
  Candidate construction prepares checkers without starting probes, failed
  startup and rejected reload paths remain side-effect free, successful reload
  aborts and joins the superseded checker set before starting its replacement,
  and shutdown aborts and joins the active set. Real probe backends cover each
  boundary.
- Active health-check configuration now fails closed through CLI, Management
  API, startup, reload, and runtime preparation. Probe paths must begin with
  `/`, intervals and timeouts must be positive durations, and both transition
  thresholds must be positive. Runtime checkers receive parsed `Duration`
  values instead of silently substituting defaults. A real reload regression
  proves contextual rejection, zero candidate probes, and continued traffic on
  the prior snapshot.
- Active health checks now start every backend probe in a service round
  concurrently and apply each result as it completes, so a hanging backend no
  longer serializes later backends behind its timeout. Transition counters now
  retain only pending consecutive evidence and saturate at their configured
  thresholds instead of growing for the lifetime of the checker.
- Startup, every reload source, and shutdown now share one asynchronous
  lifecycle transaction. Startup is accepted only from `Created`, reload only
  from `Running`, and a shutdown request prevents queued mutations from
  committing after cleanup. Concurrent shutdown callers all wait for `Stopped`.
  A real streaming-drain regression proves that reload cannot cross the
  shutdown boundary or start candidate health probes afterward.
- The `compress` middleware now transforms eligible ordinary and Gateway-native
  buffered HTTP responses instead of only tagging their headers. Negotiation
  honors exact Brotli, gzip, deflate, wildcard, identity, and quality values;
  compression runs on the blocking pool; deflate uses its required zlib wrapper;
  and transformed responses rebuild coding, length, variance, validator, range,
  and digest metadata. Ordinary responses use at most 8 MiB of compression
  look-ahead; known larger bodies stream immediately, while unknown-length
  overflow replays the consumed prefix before the untouched remainder.
  Existing codings, small or binary bodies, ranges, `no-transform`, SSE, and
  native gRPC remain unchanged.
- WebSocket messages are now explicitly documented and tested as opaque to
  Gateway control logic. The real-Gateway managed TLS recovery fixture verifies
  that a control-looking `_sub:` text message is relayed unchanged.
- Gateway configuration now rejects gradual `rollout` blocks in every
  operating mode with an explicit static revision-weight alternative. The ACL
  shape remains parseable so existing configurations fail with a focused
  compatibility error instead of appearing active while doing nothing.
- Separated coding-agent process operations from the traffic data plane and
  documented both boundaries in the README and project roadmap.
- Release tags now invoke the complete reusable CI workflow, verify the tag
  against Cargo, Helm, and changelog metadata, and defer crates.io publication
  until every macOS, Linux, and Windows release target builds successfully.
- CI now runs the default Rust test suite and pinned official OpenAI SDK
  conformance on Windows before validating the PowerShell installer and ARM64
  release target.
- The official OpenAI SDK harness now uses a dedicated Windows process group
  and native console control events for graceful-drain coverage and cleanup.
- Managed usage-spool locking now recognizes platform-native lock contention
  errors on Windows while preserving I/O failures as distinct errors.

- Added topology-bounded service telemetry to the Management API Prometheus
  endpoint: exact cold-start queue depth, drop-safe active requests,
  fixed-bucket request-duration and first-non-empty-stream-chunk TTFT
  histograms, exact backend active work and health, and per-signal observation
  timestamps and age. Missing event signals remain absent until observed.
- Added unit, cancellation, reload, real-entrypoint SSE, and Management API
  network evidence for active-request lifetime, first-chunk-only TTFT, stale
  signal age, backend pressure, queue cleanup, and orphan-series removal.
- Added positive per-service `stream_idle_timeout` and
  `stream_total_timeout` ACL bounds for SSE and native OpenAI streams. Idle
  time resets after each available upstream chunk, while total time starts at
  dispatch and remains absolute even under continuous output. Body timeout
  releases backend and inference admission accounting, emits terminal access
  log and durable usage outcomes, and never permits post-response fallback.
- Added the opt-in `managed.gateway_id` bootstrap identity and a
  Gateway-native `a3s.gateway.managed-snapshot.v1` Management API contract with
  exact ACL SHA-256 verification, revision compare-and-swap, a 24-hour maximum
  validity interval, idempotent replay, bounded applied/rejected metadata, and
  exact-selector readiness.
- Added `POST /snapshots/apply` and `GET /snapshots/status` under the configured
  Management API prefix. Health now exposes the stable Gateway identity when
  configured, and management audit events distinguish applied, replayed, and
  rejected snapshots.
- Added optional `managed.state_file` durability with an atomic `prepared` /
  `applied` journal, exact snapshot recovery before readiness, preserved
  `applied_at`, and idempotent redelivery across Gateway restart.
- Added a dual-real-binary replicated-readiness gate covering independent
  exact selectors, revision skew, rejected-successor retention, single-process
  loss, durable recovery, and eventual convergence without a replica claiming
  another replica's snapshot ready.
- Added in-place HTTP/TLS and TCP listener-policy replacement for same-name,
  same-address managed snapshots without releasing the bound socket.
- Added in-place UDP listener-policy and target reconciliation. Cloud-managed
  bootstrap can bind UDP before the first traffic snapshot, and snapshot
  cutover retires sessions associated with the superseded target set.
- Added a closed native OpenAI request profile for `GET /v1/models` and the
  three POST completion/embedding endpoints. OpenAI POST bodies require
  `application/json`, are collected under a fixed 8 MiB limit, require a
  bounded string `model` field, and return stable OpenAI-compatible request
  errors without parser details.
- Added a strict Cloud-managed inference policy ACL contract for expiring
  credential verifier projections, environment-scoped routes, ordered model
  targets, generation-bound model/endpoint grants, and explicit per-Gateway
  concurrency, request-rate, burst, and token limits.
- Added snapshot-local managed inference authorization with bounded Argon2id
  verification, endpoint and model grant enforcement, non-enumerating denial,
  a filtered OpenAI-compatible model catalog, and expiry/revocation checks.
- Added health-aware inference target dispatch with ordered priority fallback,
  deterministic weighted selection, service switching, and external-to-upstream
  model rewriting.
- Added exact per-grant request admission with sustained RPM, configurable
  burst, concurrent request caps, stable OpenAI-compatible `429` responses,
  and `Retry-After` headers for managed model-list and invocation requests.
- Added Gateway-owned UUIDv4 identities for managed inference requests and
  concrete upstream attempts. Request IDs are returned to clients, both IDs
  are forwarded upstream, and terminal access logs carry bounded route-policy,
  endpoint, model, target, and trace-correlation context.
- Added replayable managed inference dispatch with lower-priority fallback
  after connection failure or first-response timeout. Fallback preserves one
  request ID, creates a new attempt ID for each dispatch, and ends once any
  upstream response headers arrive. Response-body failures are never replayed.
- Added process-wide bounded graceful drain using `shutdown_timeout_secs`.
  Traffic listeners close before drain, HTTP/1.1 and HTTP/2 connections receive
  protocol-level graceful shutdown, and active SSE, WebSocket, and TCP work is
  tracked until completion or forced cancellation. UDP sessions are cancelled
  immediately.
- Added a pinned official `openai-python` 2.47.0 black-box conformance gate
  against the real Gateway binary and native managed snapshot API. It covers
  typed model and completion responses, stable SDK error parsing, SSE `[DONE]`,
  downstream disconnect, asynchronous cancellation, admission release,
  graceful drain, and forced drain.
- Extended the official SDK gate across the exact Models, Chat Completions,
  Completions, and Embeddings matrix, including the SDK-default base64 embedding
  path and final usage chunks for both completion stream variants.
- Added opt-in `managed.usage_spool` bootstrap storage with an exclusive process
  lock, private manifest and boot-epoch segments, stable Gateway identity,
  monotonic per-epoch sequences, byte-preserving records, SHA-256 integrity,
  bounded capacity, restart recovery, and health visibility.
- Added prompt-free managed inference lifecycle evidence. Gateway persists
  request and attempt starts before upstream dispatch, reserves terminal
  capacity, orders fallback attempt boundaries, and records success, failure,
  disconnect, or forced cancellation at the HTTP or SSE response-lifetime
  boundary.
- Added a stable OpenAI-compatible `usage_unavailable` response that rejects
  configured managed inference before upstream dispatch when complete local
  lifecycle evidence cannot be reserved.

### Changed

- Prometheus labels are now restricted to the active configuration and removed
  on reload. Backend request metrics use opaque SHA-256 `backend_id` labels
  instead of raw locators, and all text labels are escaped before exposition.
- Cold-start queue accounting now uses a drop guard so cancellation cannot
  leave a permanently inflated queue-depth signal.
- Standalone autoscaling now derives healthy-backend and active-operation
  signals from the live service or revision load balancers and combines them
  with bounded queue depth. A new or recreated controller now obtains the
  authoritative current replica count from the selected executor before its
  first decision.
- Autoscaling executor selection now rejects unknown, unavailable, and mixed
  executor types instead of falling back to Box. Kubernetes client
  initialization, replica queries, and scale mutations are time-bounded.
- Prepared autoscalers now remain inactive until startup or reload commits.
  Replacement aborts and joins the previous controller before starting the new
  one. Only accepted executor results advance remembered replica state;
  failed or timed-out mutations clear that state and force reconciliation
  before any retry.
- The Kubernetes autoscaling executor now reads and merge-patches the standard
  Deployment `Scale` subresource instead of the full Deployment. Replica
  queries use `Scale.spec.replicas`, and successful mutations are accepted only
  when the response contains the requested desired count.
- Native chat and legacy completion requests with a boolean `stream: true` now
  select the SSE path without requiring `Accept: text/event-stream`, matching
  official OpenAI SDK behavior. Other JSON values and endpoint profiles do not
  opt into SSE.
- Cloud-managed instances with `managed.gateway_id` reject raw ACL mutation so
  reported readiness cannot outlive an untracked configuration change.
- Native managed bootstrap ACLs may bind process and listener settings but now
  reject traffic routers, services, middlewares, and inference policy; those
  must arrive in the complete managed snapshot.
- Managed inference policy expiry must exactly match the atomic snapshot
  envelope. Plaintext and unknown fields, dynamic verifier expressions, unsafe
  Argon2id parameters, duplicate identities, cross-environment grants, stale
  generations, and invalid route, service, or model references are rejected
  before cutover.
- Inference verifier hashes are omitted from serialized Gateway configuration
  and redacted from debug views. Managed snapshot debug output now redacts the
  complete ACL payload.
- Managed apply keeps the bootstrap management listener immutable, pre-binds
  supported HTTP, TCP, and UDP changes on new addresses, and pre-validates
  same-address TLS acceptors, TCP filters, and bounded UDP session policies
  before cutover.
- Reload transactions are serialized across manual, provider, Management API,
  and managed-snapshot sources.
- Durable journals use synced atomic replacement and owner-only permissions on
  Unix. Corrupt, identity-mismatched, digest-invalid, expired, and insecurely
  permissioned state fails managed startup closed.
- Management request bodies are bounded while they are read rather than only
  after complete buffering.
- Request middleware now runs before buffered non-WebSocket body collection.
  Valid ordinary OpenAI JSON bytes are forwarded unchanged, while non-matching
  method and path combinations retain ordinary streaming proxy behavior.
- Routers bound by managed inference policy now authenticate only the four
  exact OpenAI method/path pairs before middleware or body collection. Accepted
  client authorization is stripped before middleware and upstream dispatch;
  successful verification caches only a token digest for the active snapshot.
- Unchanged immutable inference grants now retain request-bucket and active
  concurrency state across snapshot refresh. Concurrency remains held through
  buffered dispatch and until an SSE stream completes or disconnects.
- Managed inference now replaces client `x-request-id` and
  `x-a3s-attempt-id` values after authorization. Local model catalogs and
  pre-dispatch rejections receive a request ID without claiming an upstream
  attempt, and SSE retains its request/attempt context through termination.
- SSE now applies each service's request timeout only while waiting for
  upstream response headers; established streams continue to use the
  independent idle-read timeout instead of a total-operation deadline.
- Gateway shutdown now waits for entrypoint completion and for aborted
  discovery, provider, autoscaler, management-listener, and ACME task handles
  before publishing the `Stopped` lifecycle state.

### Removed

- Removed the unused internal `proxy::ws_mux` named-channel state machine and
  private control-message grammar, which had no configuration or runtime entry
  point.
- Removed the unconnected internal `scaling::rollout` controller and its
  unit-only state machine. It had no runtime loop, scheduler, persistence, or
  recovery path and could not execute accepted configuration.
- Removed the unused collected `GrpcResponse`/`GrpcStatus` compatibility
  surface, its duplicate metadata parser, and the process-wide gRPC timeout
  field. Runtime bounds remain explicit per-service request options.
- Removed the internal `x-gateway-compress` eligibility marker, which previously
  crossed the downstream boundary without causing response compression.

### Fixed

- gRPC calls no longer wait for the complete downstream request before
  contacting the upstream, buffer the complete upstream response before
  returning headers, or discard `grpc-status` and other HTTP/2 trailers.
- Native gRPC detection no longer captures gRPC-Web or arbitrary
  `application/grpc...` prefixes. Matching is case-insensitive and limited to
  `application/grpc` or a non-empty `+suffix`, with optional media parameters.
- Native gRPC no longer forwards client-supplied `X-Forwarded-Proto` or
  `X-Forwarded-Port` values unchanged, and it appends the observed downstream
  peer to the forwarded address chain.
- HTTP, SSE, gRPC, and WebSocket proxy boundaries no longer allow arbitrary
  one-hop fields named by `Connection` to cross to an upstream or downstream
  peer. The fixed list now also covers the standard `Trailer` field and the
  legacy `Proxy-Connection` field.
- A truncated ordinary HTTP body after upstream response headers no longer
  becomes a new Gateway-generated status or permits managed fallback. The
  started status is preserved and the downstream body terminates with the
  upstream error.
- Invalid WebSocket handshakes now return `400` without backend contact, while
  upstream handshake transport failures and timeouts return `503` and `504`
  before the downstream connection is upgraded instead of returning a false
  `101` followed by an abrupt disconnect. Non-`101` upstream HTTP rejections
  now retain their status and safe end-to-end headers instead of collapsing to
  `503`; Gateway returns its own bounded JSON body and strips hop-by-hop,
  WebSocket-handshake, and discarded-body metadata.
- Structured access logs now reach the background logging task for no-route,
  middleware-rejection, HTTP success and proxy-error, gRPC, SSE, and WebSocket
  terminal paths instead of being constructed and discarded.
- SSE logs count relayed response bytes and finish on stream completion or
  disconnect; WebSocket logs finish when the upgraded relay ends or is dropped.
- Managed model rewriting now updates the outbound content length so a longer
  or shorter upstream model identifier cannot truncate or overrun the JSON
  request body.
- Managed dispatch rebuilds one unambiguous top-level `model` field so duplicate
  JSON keys cannot be interpreted differently by Gateway and the upstream.
- Inference keys are now verified before endpoint-grant denial, so an invalid
  token consistently returns `401` and cannot use `404` or verifier timing to
  enumerate a credential's endpoint grants.
- Streaming backend connection counts now release on stream completion, error,
  or cancellation instead of remaining active after a successful response.
- HTTP, gRPC, SSE, WebSocket, and TCP backend accounting plus downstream
  connection metrics now use drop guards, preventing cancellation from leaking
  active counts. HTTP child connections, upgraded sessions, TCP relays, and UDP
  response tasks no longer outlive process shutdown or retain listener sockets.
- Kubernetes autoscaling now rejects missing, negative, overflowing, or
  mismatched replica values instead of treating unknown Deployment state as
  zero or reporting an unverified mutation as accepted. Programmatic executor
  initialization also selects the rustls crypto provider before kube client
  construction, matching the panic-free CLI path.

### Testing

- Added a real-Gateway-binary managed snapshot fixture covering TLS hostname
  and path routing, multiple services, round-robin targets, HTTP, SSE,
  WebSocket, invalid-successor retention, forced process loss, durable exact
  revision/digest recovery, and idempotent replay.
- Added standalone autoscaling regressions for live backend and revision load,
  inactive prepared controllers, accepted-state advancement, executor failure
  retry, executor timeout, scale-from-zero buffer bounds, unsupported
  executors, and mixed-executor rejection.
- Added real kube-client HTTP contract tests for the Deployment `Scale`
  subresource method, path, merge-patch content type and body, desired-count
  parsing, API errors, invalid responses, and recreated-controller
  reconciliation after an ambiguous mutation failure.
- Added a real-Gateway-binary Kubernetes scaling recovery fixture with a
  process-local kubeconfig and stateful Scale API. It applies a patch before
  dropping the response, verifies reconciliation, forces Gateway process loss,
  restarts against the retained count, and proves that no duplicate patch is
  emitted.
- Added real Management API regressions for first apply, exact replay, stable
  identity, exact readiness, stale revisions, CAS mismatch, digest tampering
  and conflict, expired and overlong validity, rejected raw reload, invalid
  ACL, failed listener bind, and prior-runtime retention.
- Added restart recovery, interrupted prepared-journal recovery, journal
  integrity and permissions, pre-reload storage failure, and post-reload
  rollback failure tests.
- Added real managed-listener regressions for same-address certificate
  rotation, superseded-certificate rejection, invalid-certificate retention,
  TCP allowlist replacement, invalid-filter retention, UDP target replacement,
  UDP session-policy replacement, and invalid-policy retention.
- Added real listener regressions for routing rejection, middleware rejection,
  HTTP success and failure, gRPC failure, SSE completion, WebSocket shutdown,
  response byte counts, and the disabled access-log path.
- Added real OpenAI request-profile regressions for exact and near-miss paths,
  byte-preserving JSON forwarding, media-type and JSON errors, oversized
  declared lengths, over-limit chunked uploads, body/model validation, and
  middleware-before-body rejection.
- Added managed inference policy regressions for strict ACL shape, literal
  bounded Argon2id verifiers, redaction, duplicate identities, ordered targets,
  environment and generation isolation, revocation, references, grants,
  limits, bootstrap rejection, and atomic snapshot-expiry mismatch retention.
- Added real managed inference HTTP regressions for authentication-before-body,
  authorization stripping, filtered model listing, endpoint/model denial,
  near-miss isolation, expiry across delayed body collection, target service
  switching, upstream model rewriting, request-burst exhaustion, stable
  `Retry-After`, rejected-request accounting, snapshot-refresh concurrency,
  and SSE disconnect release, plus unit coverage for exact refill,
  verification concurrency, cancellation-safe verifier permits,
  duplicate-model normalization, and weighted priority fallback.
- Added managed inference identity regressions for spoofed-header replacement,
  native model-list and parse-error responses, upstream and client correlation,
  snapshot/access-log identities, secret exclusion, and SSE completion.
- Added real managed inference fallback regressions for connection failure,
  first-response timeout, stable request and unique attempt identities, model
  rewriting per target, no replay after an upstream status or response-header
  start, SSE pre-response fallback, and streaming connection release.
- Added real graceful-drain regressions for complete SSE delivery within the
  configured deadline, immediate cancellation of hanging SSE and WebSocket
  sessions, hot-reloaded deadline adoption without listener rebinding, TCP
  upstream disconnect, UDP session retirement, listener release, and zero
  leaked downstream connection metrics.
- Added durable usage regressions for ordered byte-preserving append, exact
  replay, conflicting replay, exclusive ownership, capacity backpressure,
  corruption and identity mismatch, restart recovery, terminal reservation
  release, writer drain, prompt/key exclusion, pre-dispatch fail-closed
  behavior, fallback ordering, SSE disconnect, forced-drain cancellation,
  exact and repeated acknowledgement, stale/future cursor gaps, capacity
  recovery, legacy migration, and both sides of the epoch-retirement crash
  boundary. Added partial-epoch compaction coverage for repeated compaction,
  capacity release, current-epoch restart handling, all publication crash
  points, uncommitted staging cleanup, and malformed or truncated staging.

## [1.0.12] - 2026-07-19

### Fixed

- Route-bearing Cloud snapshots with object-list service backends now validate
  without recursive parser failure by upgrading to `a3s-acl` 0.2.2.
- The self-updater dependency now resolves the published 0.3.0 API instead of
  requiring a stale monorepo-local 0.2.x source tree.

### Testing

- Added a real `a3s-gateway validate` regression fixture for the complete
  hostname, path, service, management-listener, and upstream shape emitted by
  A3S Cloud.

### Release Engineering

- Replaced all monorepo-only path dependencies with exact crates.io releases,
  removed the temporary workspace reconstruction script, and added locked
  dependency resolution throughout CI and release workflows.
- Fixed Homebrew asset lookup and checksum generation so missing or renamed
  release archives fail the workflow instead of producing an invalid formula.
- Updated the Helm chart metadata to 1.0.12.

## [1.0.6] - 2026-06-01

### Fixed

- Passive health check no longer deadlocks a backend into permanent unavailability. Previously, once a backend exceeded the error threshold it was marked unhealthy and dropped from rotation; recovery only happened inside `record_success`, but an unhealthy backend receives no traffic, so no success ever arrived and the service returned `503` until the gateway was restarted (a single transient burst of `SendRequest`/5xx errors could take a whole service down indefinitely). A background recovery ticker now drives a half-open probe: after `recovery_time` elapses the backend is re-enabled so it receives traffic again — if it is still broken the next errors re-mark it, otherwise it stays healthy. The ticker holds a `Weak` reference and exits when its checker is dropped (config reload), avoiding task accumulation.

## [1.0.5] - 2026-05-31

### Fixed

- The Kubernetes Ingress watcher now hashes router/service CONTENT (rule, middlewares, priority, backend) instead of only their keys, so an in-place change to an existing Ingress/router — editing a rule from host to path routing, changing middlewares/priority, or a helm upgrade that rewrites the backend — is detected and triggers a reload (previously only router additions/removals were noticed).

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
