# A3S Gateway

<p align="center">
  <strong>AI Traffic and Protocol Data Plane for A3S</strong>
</p>

<p align="center">
  <em>Apply explicit traffic policy, preserve streaming protocols, and run standalone or under A3S Cloud</em>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#operating-modes">Operating Modes</a> •
  <a href="#protocols">Protocols</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#development">Development</a>
</p>

---

## Overview

**A3S Gateway** is an ACL-configured traffic and protocol data plane for AI
services. It accepts traffic, applies one complete local policy snapshot,
selects an allowed healthy endpoint, and relays HTTP, streaming, and transport
protocols without placing A3S Cloud on the request path.

Gateway can run independently with operator-owned configuration or as the data
plane for an A3S Cloud deployment. It is not a tenant database, workload
scheduler, deployment engine, production autoscaler, rollout authority, or
long-term usage ledger. Those responsibilities belong to Cloud in a managed
deployment.

### Basic usage

```acl
mode { kind = "standalone" }

entrypoints "web" {
  address = "0.0.0.0:8080"
}

routers "api" {
  rule        = "PathPrefix(`/v1`)"
  service     = "models"
  entrypoints = ["web"]
  middlewares = ["rate-limit"]
}

services "models" {
  load_balancer {
    strategy             = "least-connections"
    request_timeout      = "60s"
    stream_idle_timeout  = "5m"
    stream_total_timeout = "60m"
    servers = [
      { url = "http://127.0.0.1:8001" },
      { url = "http://127.0.0.1:8002" }
    ]
    health_check { path = "/health" }
  }
}

middlewares "rate-limit" {
  type  = "rate-limit"
  rate  = 60
  burst = 10
}
```

```bash
a3s-gateway --config gateway.acl
```

## Features

- **Streaming Proxy**: Relay HTTP/1.1, HTTP/2, SSE, WebSocket, and gRPC traffic
  without buffering ordinary response streams, with independent first-response,
  idle-stream, and total-operation bounds
- **Bounded Graceful Drain**: Stop new accepts immediately, let active HTTP,
  SSE, WebSocket, and TCP work finish within the configured deadline, then
  cancel and join remaining tasks before reporting `stopped`
- **Transport Routing**: Proxy TCP and UDP alongside HTTP traffic, including
  SNI-based TCP routing
- **Rule-Based Routes**: Match host, path, method, headers, and SNI with
  explicit entrypoint and service bindings
- **Backend Selection**: Use round-robin, weighted, least-connections, or random
  balancing with active and passive health state
- **Static Release Policy**: Apply fixed revision weights, failover pools,
  sticky sessions, and traffic mirroring without owning backend lifecycle
- **TLS**: Terminate TLS with rustls and optionally obtain certificates through
  ACME HTTP-01 or supported DNS-01 providers
- **Middleware Pipeline**: Enforce authentication, limits, retries, circuit
  state, CORS, headers, compression, and network policy
- **Atomic Reload**: Validate and swap traffic configuration while preserving
  unchanged listeners, rotate same-address HTTP/TLS, TCP, and UDP policy on
  the bound socket, and retain the last valid snapshot on failure
- **Durable Managed State**: Optionally recover the exact applied revision and
  ACL from an atomic local journal before managed readiness is exposed
- **Durable Usage Foundation**: Optionally persist prompt-free managed
  inference request and attempt starts before dispatch, reserve terminal
  capacity, and record success, failure, fallback, cancellation, or disconnect
  at the response-lifetime boundary
- **Management Surface**: Inspect health, routes, services, backends, metrics,
  configuration, and bounded security events on a dedicated listener
- **Bounded Service Telemetry**: Export exact queue depth, drop-safe active
  requests, latency and TTFT histograms, backend health and pressure, and
  per-signal observation age using only active-configuration labels
- **Terminal Access Logs**: Emit structured entries for routing rejections,
  middleware responses, proxy outcomes, streams, and upgraded sessions
- **OpenAI Request Profile**: Recognize the closed `/v1` endpoint set, enforce
  bounded JSON and model fields, honor completion `stream: true`, and return
  stable OpenAI-compatible errors
- **Managed Inference Contract**: Validate complete, expiring Cloud projections
  for inference credentials, routes, model targets, grants, and local limits
  without exposing verifier hashes through configuration views
- **Managed Inference Authorization**: Authenticate inference keys locally,
  enforce endpoint and model grants, return a filtered model catalog, strip
  client credentials, enforce per-grant request and concurrency admission, and
  dispatch aliases to healthy snapshot targets with lower-priority fallback
  only before an upstream response starts
- **Managed Inference Identity**: Replace untrusted client correlation headers
  with Gateway-owned request and upstream-attempt UUIDs, return the request ID
  to clients, and attach snapshot route, model, and target context to access
  logs
- **Official SDK Conformance**: Run the pinned official Python SDK through the
  complete Models, Chat Completions, Completions, and Embeddings matrix,
  including usage chunks, `[DONE]`, disconnect, cancellation, graceful drain,
  and forced drain against the real binary
- **Optional Wire Firewall**: Mask selected secrets and PII and scan local
  LLM/MCP proxy traffic with A3S Sentry

### Capability matrix

| Area | Capability | State |
| --- | --- | --- |
| Traffic | HTTP/1.1, HTTP/2, SSE, WebSocket, gRPC, TCP, UDP, TLS, bounded graceful drain, routing, balancing, health, mirroring, and static revision weights | Available |
| Configuration | ACL startup configuration and atomic reload | Available |
| Standalone operation | File, discovery, Docker, and optional Kubernetes providers | Available |
| Managed isolation | Explicit `cloud-managed` mode that rejects local providers, scaling, rollout, and mode changes through reload | Available |
| Managed snapshots | Gateway-native identity, revision/CAS, exact ACL digest, bounded validity, same-policy validity renewal, idempotent replay, rejection status, exact readiness, opt-in durable restart recovery, same-address HTTP/TLS, TCP, or UDP policy replacement, and real-binary managed TLS HTTP/SSE/WebSocket crash/replay conformance | Available Gateway foundation; Cloud native apply/ACK and validity-renewal conformance are available, while joint certificate/target-generation evidence remains in `H0.2` |
| Replicated readiness | Replica-local exact identity/revision/digest readiness, independent revision skew, rejected-successor retention, and durable process-loss recovery against two real Gateway binaries | Gateway foundation available; Cloud owns rollout thresholds, mixed-version delivery, and the aggregate degraded result in `H0.4` |
| Telemetry | Topology-bounded Prometheus counters and age-stamped service queue depth, active requests, request-duration and TTFT histograms, plus exact backend health and active upstream work; streaming TTFT and active requests follow the response-body lifetime and cancellation is drop-safe | Gateway non-token foundation available; trusted token throughput, provider-native capacity such as KV-cache pressure, Cloud ingestion, and autoscaling policy evaluation remain in `H0.5` |
| Scaling | Local scale-to-zero buffering and autoscaling from observed healthy backends, active operations, and queue depth; the controller obtains the current replica count from the selected executor before deciding and reconciles again after an ambiguous failure, with bounded executor queries and mutations; the Kubernetes adapter reads and patches the standard Deployment `Scale` subresource, validates the returned desired count, and passes real-Gateway process restart/reconciliation against a stateful local API fixture without a duplicate patch | Experimental, standalone only; local Kubernetes API wire and real-Gateway process recovery conformance are available, while Box and real-cluster Kubernetes end-to-end conformance, versioned idempotent operations, and recovery against a real executor/control plane remain open |
| Rollout | Gateway-driven gradual rollout | Unavailable; Cloud owns managed rollout and the standalone runtime loop is not wired |
| Access logs | Structured terminal entries for no-route, middleware, HTTP, gRPC, SSE, and WebSocket paths, with optional managed inference identity context | Available |
| Inference request profile | Exact OpenAI endpoint matching plus fixed 8 MiB JSON collection, bounded model-field validation, and stable request errors | Foundation available |
| Managed inference policy | Strict, expiring snapshot contract for credential verifiers, environment-scoped routes, model targets, grants, and per-Gateway limits | Policy-contract foundation available |
| Managed inference authorization | Snapshot-local key verification, route/endpoint/model grants, non-enumerating denial, filtered model listing, credential stripping, per-grant RPM/burst/concurrency admission, health-aware target selection, model rewriting, Gateway-owned request/attempt identities, pre-response lower-priority fallback, per-service idle and total stream bounds, and pinned official OpenAI Python SDK conformance across the exact four-endpoint matrix | Gateway request-path foundation available; token-budget enforcement and Cloud integration evidence remain in `I0.2b` |
| Usage | Private, bounded local spool with exclusive ownership, restart recovery, ordered Gateway/boot/sequence cursors, integrity checks, request/attempt lifecycle evidence, terminal-capacity reservation, health visibility, and fail-closed managed dispatch | Gateway local foundation available; Cloud batch/contiguous-ACK ingestion, acknowledged deletion, token measurement, gap reconciliation, and joint recovery evidence remain in `I0.2c` |
| Agent protocols | Native MCP or Agent protocol data plane | Planned only after the `A0` and `C0` contracts close |

Implemented controller types or parsed configuration do not make an
experimental or planned capability production-ready. See the
[Roadmap](ROADMAP.md) for the evidence gates and delivery order.

### Development status

A3S Gateway is not feature-complete. The core traffic data plane and the
Gateway-local managed-mode foundations in the matrix above are available, but
the following roadmap work remains open:

- trusted input and output token measurement, token-budget enforcement,
  reservation, and reconciliation;
- provider-native capacity signals such as KV-cache pressure after the Runtime
  and backend contracts are accepted;
- Box and real-cluster Kubernetes autoscaling conformance, versioned idempotent
  operations, and recovery against a real executor or control plane;
- mixed-version delivery, graceful replacement, node-loss, and joint
  production HA and load evidence;
- the `I0.5` failure, capacity, protocol-load, and disaster-recovery gates; and
- native MCP or Agent protocol support after the `A0` and `C0` contracts close.

Cloud telemetry ingestion, managed rollout decisions, desired replica counts,
and the durable usage ledger remain A3S Cloud responsibilities. They are
integration gates, not missing control-plane features to duplicate inside
Gateway.

## Quick Start

### Installation

```bash
brew install a3s-lab/tap/a3s-gateway
```

Or install the published crate:

```bash
cargo install a3s-gateway
```

Validate and inspect an ACL file before starting:

```bash
a3s-gateway validate --config gateway.acl
a3s-gateway config --config gateway.acl summary
a3s-gateway --config gateway.acl
```

### Programmatic use

```rust,no_run
use std::sync::Arc;

use a3s_gateway::{config::GatewayConfig, Gateway};

#[tokio::main]
async fn main() -> a3s_gateway::Result<()> {
    let config = GatewayConfig::from_file("gateway.acl").await?;
    let gateway = Arc::new(Gateway::new(config)?);

    gateway.start().await?;
    gateway.wait_for_shutdown().await;
    Ok(())
}
```

## Operating Modes

| Mode | Desired-state authority | Gateway responsibility |
| --- | --- | --- |
| `standalone` | Operator-owned ACL | Validate and apply local traffic, transport, health, middleware, and provider policy |
| `cloud-managed` | A3S Cloud | Enforce the managed boundary and execute the complete traffic configuration delivered through the node agent |

`standalone` is the default when the `mode` block is omitted:

```acl
mode { kind = "standalone" }
```

Use managed mode only when A3S Cloud owns desired state:

```acl
mode { kind = "cloud-managed" }
```

Managed mode rejects file, discovery, Docker, and Kubernetes providers, plus
service-level `scaling` and `rollout` blocks. Static routes, health policy,
mirroring, and revision weights remain valid because they describe data-plane
execution rather than workload lifecycle.

A bootstrap ACL with `managed.gateway_id` also rejects traffic routers,
services, middlewares, and inference policy. Cloud must deliver those together
through the complete managed snapshot.

The operating mode cannot change through hot reload. Changing desired-state
authority requires a process restart. Cloud already records its outer
node-command revision and acknowledgement during the verified `E0` flow.
Gateway now has a separate native v1 snapshot contract for instances with a
stable managed identity. The Cloud node agent now uses that endpoint and exact
status contract, including a same-ACL successor that advances revision and
validity without changing the digest. Gateway invalidates the superseded
selector, preserves traffic, and restores the renewed expiry from its opt-in
local journal. Cross-repository certificate-replacement and target-generation
evidence remain `H0.2` work.

Node-local managed state can be configured only in the bootstrap ACL:

```acl
mode { kind = "cloud-managed" }

managed {
  gateway_id = "7dd6f6ca-e278-4f3b-a230-6e9304f65f00"
  state_file = "/var/lib/a3s-gateway/managed-state.json"

  usage_spool {
    directory = "/var/lib/a3s-gateway/usage"
    max_bytes = 268435456
  }
}
```

The usage directory must be an absolute, non-root path separate from
`managed.state_file`. Its capacity defaults to 256 MiB and must be at least
1 MiB. Managed identity and local storage settings cannot change through hot
reload.

## Traffic Model

An entrypoint owns a listening address. A router matches traffic on that
entrypoint and selects a service. Middleware runs around the selected route, and
the service chooses a healthy backend from its configured pool.

```text
client
  -> entrypoint and TLS
  -> route match
  -> middleware pipeline
  -> service policy
  -> healthy backend
```

### Routing and services

HTTP rules support `Host()`, `PathPrefix()`, `Path()`, `Headers()`, `Method()`,
and `&&`. TCP routes support `HostSNI()`. Services provide:

- round-robin, weighted, least-connections, and random balancing;
- active HTTP probes and passive error-count eviction;
- cookie-based sticky sessions;
- secondary-pool failover;
- normalized `X-Forwarded-*` metadata;
- per-service response-header, idle-stream, and total-stream timeouts;
- static revision weights; and
- fire-and-forget traffic mirroring.

`request_timeout` bounds the wait for upstream response headers.
`stream_idle_timeout` starts after those headers and resets after every
available response chunk. `stream_total_timeout` bounds the complete streaming
attempt from dispatch even when chunks continue to arrive. The defaults are
`30s`, `5m`, and `60m`, respectively, and every value must be positive. A body
timeout occurs after the response has started, so it terminates that stream and
never triggers lower-priority inference fallback.

Static revisions are complete allowed backend sets, not a rollout controller:

```acl
services "models" {
  revisions "stable" {
    traffic_percent = 90
    servers = [{ url = "http://127.0.0.1:8001" }]
  }

  revisions "candidate" {
    traffic_percent = 10
    servers = [{ url = "http://127.0.0.1:8002" }]
  }
}
```

Gateway may suppress an unhealthy endpoint or open a local circuit under the
applied policy. In managed mode it may not add an endpoint, change desired
weights, create a replica, promote a revision, or synchronously ask Cloud to
authorize a request.

### OpenAI request profile

Gateway recognizes only these exact method and path pairs:

- `GET /v1/models`
- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/embeddings`

The three POST endpoints require `application/json` with a top-level object and
a `model` string. Model aliases must contain 1 to 255 bytes, have no surrounding
whitespace, and contain no control characters. Gateway collects the body under
a fixed 8 MiB limit and parses it once. Ordinary routes preserve valid bytes;
managed inference routes rebuild the validated object with one unambiguous
`model` field containing the selected upstream identifier and update the
outbound body length.

For chat and legacy completion requests, a boolean `stream: true` selects the
SSE path even when the client does not send `Accept: text/event-stream`.
Non-boolean values, `stream: false`, model listing, and embeddings do not select
streaming through the JSON field.

Invalid media types, oversized or unreadable bodies, malformed JSON, invalid
body shapes, and missing or invalid model fields return a stable
OpenAI-compatible `error` object without parser details or request content.
Query strings do not affect matching. On ordinary routers, matching occurs
after request middleware and different methods, paths, or trailing-slash
variants retain normal proxy behavior. A router bound by managed inference
policy is instead a closed surface: exact matching and authentication happen
before request middleware or body collection, and near misses return a
non-enumerating `404`.

### Managed inference policy contract

A complete Cloud-managed snapshot may include one expiring `inference` policy.
The policy expiry must exactly match the managed snapshot envelope, so the
authorization projection and its exact readiness window cannot diverge.
Standalone configuration and the native managed bootstrap ACL cannot activate
this policy.

The strict ACL contract covers:

- environment-owned inference credential IDs, a non-secret lookup prefix,
  issuance generation, expiry, revocation, and a literal Argon2id PHC v19
  verifier;
- inference routes bound to existing Gateway routers, immutable policy
  revisions, external model aliases, and ordered weighted/fallback targets
  backed by existing services;
- exact credential-generation grants for model aliases and the closed endpoint
  set; and
- positive per-Gateway concurrency, request-rate, burst, and token limits.

Unknown fields, plaintext-key fields, dynamic verifier expressions, unsafe
Argon2 parameters, duplicate identities, overlapping lookup prefixes,
cross-environment grants, stale generations, and invalid references reject the
complete snapshot before cutover. Verifier hashes are omitted from serialized
Gateway configuration, redacted from debug output, and never returned by the
Management API configuration view.

For a policy-bound router, Gateway accepts one Bearer inference key and resolves
its non-secret prefix before running a bounded Argon2id verifier off the async
runtime. At most two uncached verifications run concurrently. A successful
verification is cached only by SHA-256 token digest for the lifetime of that
exact snapshot; snapshot replacement discards the cache. The accepted plaintext
key is not stored. Neither it nor the verifier enters an error response, debug
view, middleware, or upstream request, and the inbound `Authorization` header
is removed immediately after authentication.

Gateway evaluates policy and credential expiry both before and after expensive
or buffered work. Expired policy returns `503`; missing, invalid, expired, or
revoked credentials return `401`; route, endpoint, and model grant misses
return the same non-enumerating `404`. `GET /v1/models` is answered locally with
a stable, sorted catalog containing only granted aliases.

For POST requests, Gateway selects the first target priority with a locally
healthy service, applies deterministic weighted rotation within that priority,
switches to the selected Gateway service, and rewrites the external alias to
its configured `upstream_model`. This selection never calls Cloud. It can move
to a lower priority when no service in a higher group is initially available.
If a concrete dispatch then fails to connect or reaches the service's
first-response timeout before upstream response headers arrive, Gateway
rebuilds the body for the next lower priority and tries again. It never
implicitly retries the failed priority. One request ID remains stable while
each concrete dispatch receives a new attempt ID.

Any upstream HTTP status ends fallback eligibility, including `5xx`. A response
body failure after headers also terminates the request without replay, so an
upstream that may already be processing work is never duplicated. SSE follows
the same response-start boundary. Its service request timeout limits only the
wait for upstream response headers; the established stream retains the
independent idle-read policy and releases backend connection accounting on
completion, error, or cancellation.

Every granted model-list or invocation request consumes one per-Gateway request
allowance through an exact integer token bucket with the configured sustained
RPM and burst. A separate atomic counter enforces the grant's concurrent
request cap. The concurrency guard remains active through buffered proxy work
and until an SSE response completes or disconnects. Reload reuses both counters
only for the same route policy revision, credential generation, and unchanged
limits. Rejected credentials, endpoint or model grant misses, and malformed
bodies do not consume the allowance. Exhaustion returns a stable
OpenAI-compatible `429` with `Retry-After`.

After credential and endpoint authorization, Gateway replaces any client
`x-request-id` with a Gateway-owned UUIDv4 before request middleware runs and
removes any client `x-a3s-attempt-id`. The request ID remains stable across the
managed request and is returned on native, proxied, error, and SSE responses.
Immediately before a concrete upstream dispatch, Gateway creates a separate
UUIDv4 attempt ID and forwards both headers upstream. A local `GET /v1/models`
response and a request rejected before dispatch have a request ID but no
attempt ID.

Terminal access logs add a nested inference context containing the request,
distributed-trace correlation, route, route-policy revision, endpoint, and,
when selected, model, attempt, and target identities. Ordinary access-log JSON
is unchanged. Credentials, authorization headers, prompts, request bodies, and
responses are not included in this context, and SSE retains the same identity
through completion or downstream disconnect.

The pinned official `openai-python` 2.47.0 black-box suite runs against the real
Gateway binary and applies its inference policy through the native managed
snapshot API. It verifies typed Models, Chat Completions, legacy Completions,
and Embeddings responses; the SDK-default base64 embedding path; model
rewriting; credential stripping; stable authentication and grant errors; final
stream usage chunks; SSE `[DONE]` termination while the upstream remains open;
explicit SDK disconnect; asynchronous consumer cancellation; admission
release; graceful completion inside the drain deadline; and forced termination
at a zero-second deadline.

Usage chunks are relayed protocol evidence only. They do not provide trusted
token accounting, token-budget reservation, reconciliation, or Cloud usage
ingestion. The optional local spool described below records lifecycle evidence,
not token totals.

`tokens_per_minute` is validated as part of the policy contract but is not yet
executed. Token-budget enforcement requires a closed tokenizer, input/output
accounting, reservation, and reconciliation contract. That work and Cloud
integration evidence remain planned for the rest of `I0.2b`.

### Durable usage foundation

Setting `managed.usage_spool` opts policy-bound managed inference POST requests
into required local durability. Gateway opens and exclusively locks the
directory before binding traffic listeners. Startup fails closed on an
identity mismatch, insecure or unexpected filesystem state, corrupt manifests,
corrupt records, or an unavailable lock.

Before the first upstream dispatch, Gateway durably appends prompt-free
`request_started` and `attempt_started` events. It reserves capacity for both
terminal events before allowing the dispatch. A pre-response fallback first
persists the prior attempt as `fallback`, then durably starts the next attempt.
If the spool cannot accept the starts and their terminal reservations, Gateway
does not contact the upstream and returns a stable OpenAI-compatible `503`
with `usage_unavailable`.

Terminal evidence follows the actual response lifetime. Buffered and streaming
responses record success or failure when their bodies finish; downstream drop
records `disconnected`; forced pre-response drain records `cancelled`. Shutdown
drains accepted listener work before flushing the spool writer. A write whose
durability is uncertain makes the spool unavailable until process restart, so
a later request cannot silently continue without evidence.

The local format binds the stable Gateway ID, a new UUID boot epoch, and a
monotonic sequence within each epoch. Records retain exact event bytes with a
SHA-256 integrity digest, survive restart in manifest-listed epoch segments,
and reject conflicting event replay. Health exposes retained records and bytes,
reserved bytes, capacity, boot epoch, next sequence, writability, and any
backpressure or failure reason.

Lifecycle payloads contain bounded request, route-policy, environment,
credential-generation, endpoint, model, attempt, and target identities plus
timestamps and terminal status. They never contain prompts, request or response
bodies, inference keys, verifier hashes, authorization headers, provider
credentials, or provider secrets. Token measurement is currently marked
`unknown`.

This is a Gateway-local persistence foundation, not the Cloud usage wire
contract or long-term ledger. Gateway does not yet upload batches, consume a
highest-contiguous acknowledgement, reconcile Cloud-requested gaps, or delete
acknowledged records. Until those `I0.2c` contracts and joint crash/replay gates
land, retained records are never silently evicted and the configured spool
eventually applies backpressure at its hard capacity.

## Protocols

| Protocol | Included capability |
| --- | --- |
| HTTP/1.1 and HTTP/2 | Reverse proxying, hop-by-hop header filtering, streaming bodies, and forwarded metadata |
| SSE | Chunked event-stream relay selected by `Accept` or native completion `stream: true`, without response buffering, with bounded first-response wait plus configurable idle-stream and total-operation deadlines |
| WebSocket | Upgrade detection, tracked bidirectional relay, named-channel multiplexing, and bounded shutdown |
| gRPC | HTTP/2 h2c forwarding with header translation |
| TCP | Tracked raw byte relay, SNI routing, IP filtering, and bounded shutdown |
| UDP | Session-based datagram relay with current-snapshot routing, healthy-target selection, and immediate session cancellation on shutdown |

Managed inference fallback is restricted to transport or timeout failure before
an upstream response starts. Once headers arrive, idle or total stream timeout
closes the active response, releases backend and admission accounting, emits
terminal access-log and usage state, and never replays the request.

### Graceful shutdown

`shutdown_timeout_secs` sets the process-wide grace period and defaults to 30
seconds. Once shutdown begins, Gateway closes every traffic listener before
draining accepted work. HTTP/1.1 and HTTP/2 connections receive a
protocol-level graceful-shutdown signal so keep-alive connections cannot start
new requests. Active HTTP responses, SSE streams, WebSocket relays, and TCP
relays may finish within the deadline. UDP stops receiving immediately and
cancels its connectionless session relays.

At the deadline, Gateway cancels all remaining tracked connection, stream,
upgrade, and relay tasks and waits for cancellation to complete. Downstream and
backend connection guards release on both ordinary completion and cancellation,
and listener sockets are released before the lifecycle state becomes
`stopped`. Setting the timeout to `0` selects immediate forced cancellation.

## Middleware

Gateway includes 15 middleware types:

| Middleware | Purpose |
| --- | --- |
| `jwt` | HS256 JWT validation |
| `api-key` | Header-based API key enforcement |
| `basic-auth` | HTTP Basic authentication |
| `forward-auth` | Delegated authentication through an external service |
| `rate-limit` | In-process token-bucket limiting |
| `rate-limit-redis` | Optional Redis-backed distributed limiting |
| `cors` | CORS response policy |
| `headers` | Request and response header mutation |
| `strip-prefix` | Route-prefix removal |
| `body-limit` | Request body limit |
| `retry` | Bounded retry before response |
| `circuit-breaker` | Closed, open, and half-open backend state |
| `ip-allow` | CIDR and IP allowlist |
| `compress` | Brotli, gzip, or deflate response compression |
| `tcp-filter` | TCP connection and source-address policy |

Redis support requires the `redis` Cargo feature and an available Redis
service. Kubernetes discovery requires the `kube` feature. The experimental
standalone Kubernetes autoscaler requires `get` and `patch` access to the
`deployments/scale` subresource.

## Wire Firewall

The optional `wire` feature provides a separate, single-upstream local proxy
built on [A3S Sentry](https://github.com/A3S-Lab/Sentry). It can scan request
bodies, mask matched secrets or PII before forwarding, restore placeholders in
responses, block configured injection or jailbreak findings, and append NDJSON
trace records.

```bash
cargo run --features wire -- wire \
  --listen 127.0.0.1:9877 \
  --upstream https://api.anthropic.com \
  --sentry-config sentry.acl
```

Point the client at `http://127.0.0.1:9877/wire/<agent>/...`. The wire proxy
preserves path, query, upstream status, and content type, and caps buffered
request bodies at 8 MiB.

This feature is not a native OpenAI dispatcher, MCP protocol implementation, or
proof that every encoded secret is detectable. Binary bodies bypass text
scanning, provider authorization headers still reach the upstream, and
placeholder restoration is not context-aware. It complements rather than
replaces host-level controls.

## Management and Observability

The optional Management API uses a dedicated listener. It can require a source
IP allowlist, bearer token, HTTPS, and mTLS without claiming paths on traffic
entrypoints.

```acl
management {
  enabled        = true
  address        = "127.0.0.1:9090"
  path_prefix    = "/api/gateway"
  auth_token_env = "A3S_GATEWAY_ADMIN_TOKEN"
  allowed_ips    = ["127.0.0.1", "::1"]
}
```

Enable the Gateway-native snapshot protocol only in `cloud-managed` mode by
binding the process to a stable logical identity:

```acl
mode { kind = "cloud-managed" }

managed {
  gateway_id = "019cdef0-21b0-7b2a-95b0-7f0fd02fa725"
  state_file = "/var/lib/a3s-gateway/managed-snapshot.json"
}
```

`state_file` is optional and must be an absolute path. Without it, applied
state remains process-local. When configured, both `gateway_id` and
`state_file` are immutable bootstrap settings and every delivered snapshot
must repeat them exactly. A native managed bootstrap may define entrypoints,
the management listener, identity, observability, and process settings, but it
cannot define traffic routers, services, or middlewares. Those belong only in
the complete managed snapshot. Once a managed identity is present, mutating
raw ACL reload is rejected and managed configuration must use:

- `POST /api/gateway/snapshots/apply` for a JSON
  `a3s.gateway.managed-snapshot.v1` envelope; and
- `GET /api/gateway/snapshots/status` for bounded applied/rejected metadata.

An apply envelope carries `gateway_id`, positive `revision`,
`expected_revision`, `snapshot_digest`, `issued_at`, `expires_at`, and the
complete `acl`. The digest is lowercase `sha256:` over the exact UTF-8 ACL
bytes. Validity may not exceed 24 hours, issue time allows at most five minutes
of forward clock skew, and an expired snapshot is rejected.

```json
{
  "schema": "a3s.gateway.managed-snapshot.v1",
  "gateway_id": "019cdef0-21b0-7b2a-95b0-7f0fd02fa725",
  "revision": 42,
  "expected_revision": 41,
  "snapshot_digest": "sha256:<64 lowercase hex digits>",
  "issued_at": "2026-07-23T08:00:00Z",
  "expires_at": "2026-07-23T09:00:00Z",
  "acl": "<complete cloud-managed ACL>"
}
```

Readiness is intentionally exact. The status endpoint returns `ready: true`
only when all three query fields match the current unexpired snapshot:

```text
/api/gateway/snapshots/status
  ?gateway_id=<uuid>
  &revision=<positive integer>
  &snapshot_digest=sha256%3A<64 lowercase hex digits>
```

Readiness remains instance-local in a replicated deployment. Cloud queries each
Gateway with that instance's exact selector; Gateway does not aggregate
`min_ready`, `max_unavailable`, or a rollout result. A real-binary regression
keeps two independently addressed Gateways on different revisions, proves that
a rejected successor leaves the lagging instance ready on its prior snapshot,
proves that no instance reports another instance's selector ready, removes one
process, and recovers its exact revision from its own journal before the
replicas converge.

The first apply uses `expected_revision: null`; later applies must name the
currently applied revision. Exact redelivery is acknowledged without another
reload. Stale revisions, same-revision conflicts, identity mismatches, invalid
digests, and expired envelopes are rejected while the prior proven runtime
remains active.

With `state_file`, Gateway writes a bounded `prepared` record before changing
the runtime and atomically advances it to `applied` only after reload succeeds.
The file is replaced through a synced staging file and is mode `0600` on Unix.
On restart, an `applied` record restores the exact ACL, revision, digest, and
original `applied_at`; an interrupted `prepared` record is validated and
completed before the Management API can report readiness. Corrupt,
identity-mismatched, digest-invalid, expired, or insecurely permissioned
journal state fails startup closed. A storage failure cannot report the
candidate ready: Gateway restores the prior runtime and journal when possible,
otherwise readiness stays false until restart recovery.

The bootstrap management listener remains immutable during managed apply.
HTTP, TCP, and UDP listener moves bind a new address before cutover. A
same-name, same-address HTTP listener pre-validates and replaces its TLS
acceptor without releasing the socket; a TCP listener does the same for its
connection limit and IP allowlist while preserving the active-connection
count. A UDP listener keeps its bound socket, resolves each client session
against the current runtime, and replaces its bounded session policy while
retiring sessions from the superseded snapshot. Address ownership transfers
and protocol changes on a bound address remain rejected.

```bash
a3s-gateway management events \
  --url http://127.0.0.1:9090/api/gateway
a3s-gateway management validate \
  --url http://127.0.0.1:9090/api/gateway \
  --file gateway.acl
a3s-gateway management reload \
  --url http://127.0.0.1:9090/api/gateway \
  --file gateway.acl
```

The API exposes health, version, active configuration, routes, services,
backends, Prometheus metrics, recent management security events, and managed
snapshot status. It also validates and reloads ACL payloads for standalone and
legacy deployments. Health includes the active operating mode and configured
Gateway identity.

Prometheus metrics, trace-context propagation, and structured access logs are
available. Buffered responses record their exact body size when the response is
built. SSE streams record relayed bytes and duration when the body completes or
disconnects; WebSocket entries record the `101` session when the relay finishes
or is dropped.

### Bounded telemetry contract

When `observability.metrics_enabled` is true, the Management API metrics
endpoint also exports:

| Signal | Prometheus metric | Semantics |
| --- | --- | --- |
| Queue | `gateway_service_queue_depth` | Exact current cold-start buffer depth; cancelled waits release their slot |
| Active requests | `gateway_service_active_requests` | Accepted service work, including queue time and streaming or upgraded-session lifetime |
| Latency | `gateway_service_request_duration_seconds` | Fixed-bucket histogram recorded when the service operation completes or is dropped |
| TTFT | `gateway_service_ttft_seconds` | Fixed-bucket histogram recorded once, at the first non-empty streaming response chunk |
| Backend pressure | `gateway_backend_active_requests`, `gateway_backend_healthy` | Exact in-process upstream work and local health for each configured backend |
| Freshness | `gateway_service_telemetry_observation_timestamp_seconds`, `gateway_service_telemetry_age_seconds` | Timestamp and age for the closed `active_requests`, `queue_depth`, `request_latency`, `ttft`, and `backend_pressure` signal set |

Request-latency and TTFT freshness samples are absent until the first real
observation. Consumers must treat an absent or policy-stale sample as unknown,
not as zero. Queue, active-request, and backend-pressure values are read
directly at scrape time. Gateway emits observations only; Cloud Workloads
remains the only managed-mode autoscaling evaluator and desired-replica writer.

The label budget is derived only from the active configuration. Let `R` be
routers, `S` services, `B` primary and revision backend entries, and `M`
middlewares. The complete endpoint has at most `7 + 3R + 50S + 3B + M` series,
including the fixed fifteen-bucket latency and TTFT histograms. Reload prunes
removed labels, backends use opaque topology-derived SHA-256 identities instead
of locators, and no tenant, principal, credential, prompt, or response label is
accepted.

Trusted token throughput is intentionally absent until the token-accounting
and Cloud ingestion contract closes.

## Architecture

```text
                         A3S Gateway

client
  -> HTTP / TLS / TCP / UDP entrypoint
  -> host / path / method / header / SNI router
  -> authentication / limits / retry / circuit middleware
  -> load balancing / health / failover / mirror / revisions
  -> HTTP / gRPC / TCP / UDP backend

standalone ACL -----------+
                          +-> validate -> atomic runtime snapshot
A3S Cloud node agent -----+
```

`Gateway` owns lifecycle and listener reconciliation. Routers and middleware
pipelines are compiled before traffic reaches services. Services own backend
selection and local health state. Configuration reload swaps one shared runtime
snapshot. HTTP, TCP, and UDP listeners keep their sockets for supported
same-address policy changes, while listeners moving to new addresses are
prepared before replacement. Accepted connections and upgraded sessions remain
owned by their entrypoint until normal completion or bounded shutdown.

In Cloud-managed deployments, PostgreSQL desired state and durable operations
remain in Cloud. The node agent delivers configuration and observations over
the outbound control channel. Provider bytes never pass through Cloud.

## Deployment

### Docker

```bash
docker run \
  --volume "$(pwd)/gateway.acl:/etc/a3s-gateway/gateway.acl:ro" \
  --publish 8080:8080 \
  ghcr.io/a3s-lab/gateway:latest
```

### Helm

```bash
helm install gateway deploy/helm/a3s-gateway \
  --set-file config=gateway.acl \
  --set service.type=LoadBalancer
```

The Helm package deploys Gateway; it does not turn Kubernetes into an A3S Cloud
scheduler or enable managed control loops.

## Development

Run checks from the `a3s-gateway` crate directory:

```bash
cargo fmt --all -- --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
```

Optional integrations may require their corresponding external services. See
[Roadmap](ROADMAP.md) for product ownership, current capability truth, and the
coordinated Cloud gates. See [CHANGELOG](CHANGELOG.md) for release history and
[Releasing](RELEASING.md) for the release process.

## Stability

A3S Gateway follows [Semantic Versioning](https://semver.org/). The public Rust
API, ACL configuration, Management API, and CLI are stable from `1.0.0`.
Internal modules and provider implementations may change in minor releases.
The current minimum supported Rust version is 1.88.

## License

MIT
