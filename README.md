<p align="center">
  <img src="assets/readme/hero.svg" width="100%" alt="A3S Gateway routes HTTP, SSE, WebSocket, gRPC, TCP, and UDP through one atomic local policy snapshot to healthy backends">
</p>

<p align="center">
  <strong>An ACL-configured AI traffic and protocol data plane for standalone and A3S Cloud-managed deployments.</strong>
</p>

<p align="center">
  <a href="https://github.com/A3S-Lab/Gateway/actions/workflows/ci.yml"><img alt="CI status" src="https://img.shields.io/github/actions/workflow/status/A3S-Lab/Gateway/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="https://github.com/A3S-Lab/Gateway/releases/latest"><img alt="Latest A3S Gateway release" src="https://img.shields.io/github/v/release/A3S-Lab/Gateway?display_name=tag&amp;sort=semver&amp;style=flat-square&amp;color=26d0ce"></a>
  <a href="https://crates.io/crates/a3s-gateway"><img alt="a3s-gateway on crates.io" src="https://img.shields.io/crates/v/a3s-gateway?style=flat-square&amp;color=ff7a59"></a>
  <a href="https://www.rust-lang.org/"><img alt="Minimum supported Rust version 1.88" src="https://img.shields.io/badge/MSRV-1.88-81919b?style=flat-square"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-f2f5f3?style=flat-square"></a>
</p>

<p align="center">
  <a href="#run-your-first-gateway">Quick start</a> ·
  <a href="#one-request-path">Request path</a> ·
  <a href="#operating-modes">Modes</a> ·
  <a href="#managed-openai-traffic">OpenAI</a> ·
  <a href="#management-and-observability">Operations</a> ·
  <a href="#product-boundaries">Status</a>
</p>

---

**A3S Gateway** accepts traffic, applies one validated runtime snapshot,
selects an allowed healthy backend, and relays long-lived application
protocols without placing A3S Cloud on the request path.

It runs independently from operator-owned ACL configuration or as the local
data plane for an A3S Cloud deployment. Gateway owns protocol handling and
policy enforcement. It does not own tenants, workload placement, production
rollout, managed replica counts, or the long-term usage ledger.

## Run your first gateway

Install the latest stable binary with Homebrew or Cargo:

```bash
brew install a3s-lab/tap/a3s-gateway
# or
cargo install a3s-gateway
```

Release archives for macOS and Linux are also available from the
[latest release](https://github.com/A3S-Lab/Gateway/releases/latest).

With an HTTP or OpenAI-compatible backend listening on `127.0.0.1:8000`, save
this as `gateway.acl`:

```acl
mode { kind = "standalone" }

entrypoints "web" {
  address = "127.0.0.1:8080"
}

routers "models" {
  rule        = "PathPrefix(`/v1`)"
  service     = "models"
  entrypoints = ["web"]
  middlewares = ["rate-limit"]
}

services "models" {
  load_balancer {
    strategy             = "least-connections"
    request_timeout      = "30s"
    stream_idle_timeout  = "5m"
    stream_total_timeout = "60m"
    servers = [{ url = "http://127.0.0.1:8000" }]
    health_check { path = "/health" }
  }
}

middlewares "rate-limit" {
  type  = "rate-limit"
  rate  = 60
  burst = 10
}
```

Validate the complete policy before binding a listener, inspect what Gateway
compiled, then start it:

```bash
a3s-gateway validate --config gateway.acl
a3s-gateway config --config gateway.acl summary
a3s-gateway --config gateway.acl
```

Traffic now follows the configured route:

```bash
curl http://127.0.0.1:8080/v1/models
```

## One request path

Every accepted request is evaluated against one immutable runtime snapshot:

```text
operator ACL ───────┐
                    ├─> validate ─> atomic swap ─> active snapshot
A3S Cloud snapshot ─┘                              │
                                                   │
client ─> entrypoint ─> route ─> middleware ─> service ─> healthy backend
```

This separation is the central contract:

- configuration is validated and compiled before cutover;
- a rejected reload leaves the prior proven snapshot active;
- local health may suppress an endpoint but can never invent one;
- retries and managed fallback stop once an upstream response begins;
- ordinary response bodies and streams preserve backpressure; and
- shutdown closes listeners first, drains accepted work within a configured
  deadline, then cancels and joins what remains.

No request needs a synchronous Cloud API, database, or scheduler round trip.

## What Gateway handles

- **Traffic and streaming** — HTTP/1.1, HTTP/2, SSE, WebSocket, gRPC, TCP,
  UDP, TLS termination, and bounded graceful drain.
- **Routing and backend policy** — host, path, method, header, and SNI rules;
  round-robin, weighted, least-connections, and random selection; active and
  passive health; sticky sessions; failover; mirroring; and static revision
  weights.
- **Policy enforcement** — authentication, request limits, retries before
  response, circuit state, CORS, headers, compression, and network controls.
- **Safe configuration** — ACL startup validation, file/provider updates,
  serialized atomic reload, in-place supported listener-policy replacement,
  and prior-snapshot retention on failure.
- **Operations** — a dedicated Management API, Prometheus metrics,
  trace-context propagation, structured terminal access logs, and bounded
  security events.
- **Managed AI traffic** — an exact OpenAI endpoint profile, snapshot-local
  authorization, model grants and rewriting, request/concurrency admission,
  health-aware targets, pre-response fallback, and prompt-free lifecycle
  evidence.

### Protocol behavior

| Protocol | Gateway behavior |
| --- | --- |
| HTTP/1.1 and HTTP/2 | Reverse proxying, hop-by-hop header filtering, streaming bodies, and normalized forwarded metadata |
| SSE | Chunk relay without response buffering, with independent first-response, idle-stream, and total-operation limits |
| WebSocket | Tracked bidirectional relay, named-channel multiplexing, and bounded shutdown |
| gRPC | HTTP/2 h2c forwarding with header translation |
| TCP | Raw byte relay, SNI routing, IP filtering, connection limits, and bounded shutdown |
| UDP | Session-based datagram relay with current-snapshot routing and immediate shutdown cancellation |

<details>
<summary><strong>15 built-in middleware types</strong></summary>

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
| `retry` | Bounded retry before a response starts |
| `circuit-breaker` | Closed, open, and half-open backend state |
| `ip-allow` | CIDR and IP allowlist |
| `compress` | Brotli, gzip, or deflate response compression |
| `tcp-filter` | TCP connection and source-address policy |

Redis support requires the `redis` Cargo feature. Kubernetes discovery
requires `kube`.

</details>

## Operating modes

| Mode | Desired-state authority | Gateway responsibility |
| --- | --- | --- |
| `standalone` | Operator-owned ACL | Validate and execute local traffic, transport, middleware, health, and provider policy |
| `cloud-managed` | A3S Cloud | Enforce the managed boundary and execute one complete delivered traffic snapshot |

`standalone` is the default when the `mode` block is omitted. It may use file,
discovery, Docker, and optional Kubernetes providers.

`cloud-managed` rejects local providers, service-level scaling and rollout,
raw ACL mutation after a managed identity is active, and mode changes through
reload. Static routes, health policy, mirroring, and revision weights remain
valid because they describe data-plane execution rather than workload
lifecycle.

Changing desired-state authority always requires a process restart.

### Managed snapshot foundation

A managed Gateway starts from a small bootstrap ACL that binds process-local
settings and a stable logical identity:

```acl
mode { kind = "cloud-managed" }

managed {
  gateway_id = "019cdef0-21b0-7b2a-95b0-7f0fd02fa725"
  state_file = "/var/lib/a3s-gateway/managed-snapshot.json"
}

management {
  enabled     = true
  address     = "127.0.0.1:9090"
  path_prefix = "/api/gateway"
}
```

The Gateway-native `a3s.gateway.managed-snapshot.v1` protocol exposes:

- `POST /api/gateway/snapshots/apply` for a complete ACL snapshot; and
- `GET /api/gateway/snapshots/status` for exact instance-local readiness.

An envelope binds the Gateway ID, positive revision, expected prior revision,
exact `sha256:` digest, issue time, expiry, and complete ACL bytes. Validity is
limited to 24 hours. Exact replay is idempotent; stale, conflicting, expired,
identity-mismatched, digest-invalid, or invalid-ACL successors are rejected
without replacing the active policy.

Optional `state_file` durability restores the exact applied snapshot before
readiness after process loss. Readiness is deliberately replica-local; A3S
Cloud owns rollout thresholds and the aggregate deployment result.

## Managed OpenAI traffic

Gateway recognizes this closed request profile:

| Method and path | Behavior |
| --- | --- |
| `GET /v1/models` | Return a stable catalog filtered to the credential's granted aliases |
| `POST /v1/chat/completions` | Validate the model and select buffered or SSE behavior from `stream` |
| `POST /v1/completions` | Validate the model and select buffered or SSE behavior from `stream` |
| `POST /v1/embeddings` | Validate, authorize, rewrite the model, and proxy the request |

For policy-bound managed routes, Gateway authenticates inference keys locally,
enforces endpoint and model grants, strips client credentials, applies
per-grant request and concurrency limits, rewrites external model aliases, and
selects a healthy configured target. A lower-priority target is eligible only
before upstream response headers arrive. Any upstream status or started body
ends fallback eligibility, preventing duplicate work.

Gateway replaces untrusted correlation headers with one request UUID and a new
attempt UUID for each concrete dispatch. Terminal access logs retain bounded
route, policy, model, target, and trace context without prompts, bodies,
responses, credentials, or verifier hashes.

The pinned official `openai-python` 2.47.0 suite drives the real Gateway binary
through Models, Chat Completions, Completions, Embeddings, streaming usage,
`[DONE]`, disconnect, cancellation, graceful drain, and forced drain. See the
[SDK conformance harness](tests/openai_sdk/README.md).

> [!IMPORTANT]
> `tokens_per_minute` is validated but not yet enforced. The optional local
> usage spool records prompt-free request and attempt lifecycle evidence, not
> trusted token totals. Cloud batch acknowledgement, deletion, token
> measurement, gap reconciliation, and the durable Cloud ledger remain open
> roadmap work.

## Management and observability

The optional Management API uses a dedicated listener so operational and
mutation endpoints do not claim paths on traffic entrypoints:

```acl
management {
  enabled        = true
  address        = "127.0.0.1:9090"
  path_prefix    = "/api/gateway"
  auth_token_env = "A3S_GATEWAY_ADMIN_TOKEN"
  allowed_ips    = ["127.0.0.1", "::1"]
}

observability {
  metrics_enabled = true
}
```

It exposes health, version, active configuration, routes, services, backends,
Prometheus metrics, recent security events, and managed snapshot status.
Standalone and legacy deployments can validate or atomically reload ACL
payloads through the same listener.

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

Service telemetry includes bounded queue depth, drop-safe active requests,
request-duration and first-non-empty-chunk TTFT histograms, backend active work
and health, and per-signal observation age. Missing or stale event signals mean
unknown, never zero. Labels come only from active topology and are pruned on
reload.

## Deploy or embed

### Docker

```bash
docker run --rm \
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

The [Helm chart](deploy/helm/a3s-gateway/) deploys Gateway. It does not make
Kubernetes the A3S Cloud scheduler or enable managed control loops.

### Rust library

The binary and public Rust API share the same configuration and lifecycle:

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

Optional Cargo features are `redis`, `kube`, and `wire`. The `wire` feature is
a separate single-upstream local proxy built on
[A3S Sentry](https://github.com/A3S-Lab/Sentry); it masks selected text secrets
or PII and scans configured LLM/MCP traffic. It is not native MCP support, an
OpenAI dispatcher, or a replacement for host-level controls.

## Architecture

```text
                             A3S Gateway

operator ACL ───────────┐
                        ├──> validation ──> atomic runtime snapshot
A3S Cloud node agent ───┘                         │
                                                 │
client                                            │
  └─> HTTP / TLS / TCP / UDP entrypoint           │
       └─> host / path / method / header / SNI router
            └─> auth / limits / retry / circuit middleware
                 └─> load balance / health / failover / mirror
                      └─> HTTP / gRPC / TCP / UDP backend
```

`Gateway` owns lifecycle and listener reconciliation. Routers and middleware
pipelines are compiled before traffic reaches services. Services own backend
selection and local health. Accepted connections, streams, and upgrades remain
owned by their entrypoint until normal completion or bounded shutdown.

In managed deployments, PostgreSQL desired state and durable operations remain
in Cloud. The node agent delivers configuration over the outbound control
channel; provider request and response bytes never pass through Cloud.

## Product boundaries

The repository distinguishes implementation from production evidence.

**Available foundations**

- multi-protocol traffic, routing, middleware, health, TLS, static release
  policy, atomic reload, bounded drain, access logs, and Management API;
- standalone operation with file, discovery, Docker, and optional Kubernetes
  providers;
- explicit managed-mode isolation and the Gateway-native snapshot protocol;
- topology-bounded non-token service telemetry; and
- the managed OpenAI request-path and local usage-spool foundations described
  above;
- closed modern MCP ACL, bounded request parsing, mirrored-header validation,
  snapshot-local authentication/authorization, exact healthy-target
  selection, single-attempt dispatch, and bounded JSON/SSE relay foundations.

**Experimental**

- standalone scale-to-zero and autoscaling;
- Kubernetes `Scale` subresource integration; and
- executor recovery that has local fixture evidence but not complete Box or
  real-cluster production conformance.

**Unavailable or still open**

- Gateway-owned gradual rollout in the live runtime;
- managed production rollout thresholds, placement, and replica decisions;
- trusted token accounting, token-budget enforcement, Cloud usage ingestion,
  and acknowledged local deletion;
- complete cross-product HA, mixed-version, load, and disaster-recovery gates;
  and
- end-to-end native modern MCP or Agent protocol handling; real hosted-server
  and client conformance, managed stale/rejected snapshot and restart,
  idle/total timeout, forced drain, exact readiness, telemetry, and joint fault
  evidence remain planned under `MCP0.4`.

Read the gate-driven [Roadmap](ROADMAP.md) before treating an experimental or
planned surface as production-ready.

## Development

Run checks from the repository root:

```bash
cargo fmt --all -- --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
```

The pinned OpenAI SDK gate has its own Python dependencies and drives the real
binary. Optional Redis, Kubernetes, ACME, and host-backed integrations may need
their corresponding external services.

Useful project references:

- [Roadmap and capability evidence](ROADMAP.md)
- [Development plan](docs/development-plan.md)
- [Changelog](CHANGELOG.md)
- [Release process](RELEASING.md)
- [OpenAI SDK conformance harness](tests/openai_sdk/README.md)

## Stability and license

A3S Gateway follows [Semantic Versioning](https://semver.org/). The public Rust
API, ACL configuration, Management API, and CLI are stable from `1.0.0`. The
minimum supported Rust version is 1.88.

Licensed under the [MIT License](LICENSE).
