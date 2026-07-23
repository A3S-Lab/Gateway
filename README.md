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
    strategy        = "least-connections"
    request_timeout = "60s"
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
  without buffering ordinary response streams
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
- **Management Surface**: Inspect health, routes, services, backends, metrics,
  configuration, and bounded security events on a dedicated listener
- **Terminal Access Logs**: Emit structured entries for routing rejections,
  middleware responses, proxy outcomes, streams, and upgraded sessions
- **OpenAI Request Profile**: Recognize the closed `/v1` endpoint set and
  enforce bounded JSON requests with stable OpenAI-compatible errors
- **Optional Wire Firewall**: Mask selected secrets and PII and scan local
  LLM/MCP proxy traffic with A3S Sentry

### Capability matrix

| Area | Capability | State |
| --- | --- | --- |
| Traffic | HTTP/1.1, HTTP/2, SSE, WebSocket, gRPC, TCP, UDP, TLS, routing, balancing, health, mirroring, and static revision weights | Available |
| Configuration | ACL startup configuration and atomic reload | Available |
| Standalone operation | File, discovery, Docker, and optional Kubernetes providers | Available |
| Managed isolation | Explicit `cloud-managed` mode that rejects local providers, scaling, rollout, and mode changes through reload | Available |
| Managed snapshots | Gateway-native identity, revision/CAS, exact ACL digest, bounded validity, idempotent replay, rejection status, exact readiness, opt-in durable restart recovery, and same-address HTTP/TLS, TCP, or UDP policy replacement | Available Gateway foundation; Cloud wiring and joint certificate/target-generation evidence remain in `H0.2` |
| Scaling | Local scale-to-zero, buffering, and autoscaling | Experimental, standalone only |
| Rollout | Gateway-driven gradual rollout | Unavailable; Cloud owns managed rollout and the standalone runtime loop is not wired |
| Access logs | Structured terminal entries for no-route, middleware, HTTP, gRPC, SSE, and WebSocket paths | Available |
| Inference | Exact OpenAI endpoint matching plus fixed 8 MiB JSON collection and stable request errors | Request-profile foundation available; snapshot-backed model dispatch and authorization remain planned (`I0.2b`) |
| Usage | Durable ordered request and attempt spool | Planned (`I0.2c`) |
| Agent protocols | Native MCP or Agent protocol data plane | Planned only after the `A0` and `C0` contracts close |

Implemented controller types or parsed configuration do not make an
experimental or planned capability production-ready. See the
[Roadmap](ROADMAP.md) for the evidence gates and delivery order.

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

The operating mode cannot change through hot reload. Changing desired-state
authority requires a process restart. Cloud already records its outer
node-command revision and acknowledgement during the verified `E0` flow.
Gateway now has a separate native v1 snapshot contract for instances with a
stable managed identity. Coordinating the Cloud node agent with that endpoint,
and recording cross-repository certificate and target-generation evidence
remain `H0.2` work. Gateway has native same-address certificate-replacement
coverage and can restore its own applied state from an opt-in local journal;
the outer Cloud acknowledgement is still not Gateway-native readiness.

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
- per-service request timeouts;
- static revision weights; and
- fire-and-forget traffic mirroring.

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

After route middleware runs, Gateway recognizes only these exact method and
path pairs:

- `GET /v1/models`
- `POST /v1/chat/completions`
- `POST /v1/completions`
- `POST /v1/embeddings`

The three POST endpoints require `application/json`. Gateway collects the body
under a fixed 8 MiB limit, validates the JSON once, and forwards valid bytes
unchanged. Invalid media types, oversized bodies, unreadable bodies, and
invalid JSON return a stable OpenAI-compatible `error` object without parser
details or request content. Query strings do not affect matching; different
methods, paths, or trailing-slash variants retain ordinary proxy behavior.

This request profile is the first `I0.2b` slice. It does not yet provide
snapshot-backed model aliases, cached authorization, policy limits, model
listing, or inference fallback.

## Protocols

| Protocol | Included capability |
| --- | --- |
| HTTP/1.1 and HTTP/2 | Reverse proxying, hop-by-hop header filtering, streaming bodies, and forwarded metadata |
| SSE | Chunked event-stream relay without response buffering |
| WebSocket | Upgrade detection, bidirectional relay, and named-channel multiplexing |
| gRPC | HTTP/2 h2c forwarding with header translation |
| TCP | Raw byte relay, SNI routing, and IP filtering |
| UDP | Session-based datagram relay with current-snapshot routing and healthy-target selection |

Retries and fallback are safe only before the first response byte. Long-lived
protocol behavior remains bounded by the configured connection and request
policies.

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
service. Kubernetes discovery requires the `kube` feature.

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
prepared before replacement.

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
