# A3S Gateway

<p align="center">
  <strong>AI traffic and protocol data plane</strong>
</p>

<p align="center">
  <em>Standalone or A3S Cloud-managed. Single binary. ACL config. Streaming protocols. Atomic snapshot apply.</em>
</p>

<p align="center">
  <a href="#why-a3s-gateway">Why A3S Gateway</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#architecture">Architecture</a> •
  <a href="ROADMAP.md">Roadmap</a> •
  <a href="#deployment">Deployment</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#stability">Stability</a>
</p>

---

## Why A3S Gateway

AI services break the assumptions baked into Web-era gateways:

| Assumption | Web services | AI services |
|---|---|---|
| Response size | Small, bounded | Unbounded (streaming tokens) |
| Latency | Milliseconds | Seconds (model inference) |
| Idle cost | Cheap | Expensive (GPU memory) |
| Deployment risk | Low | High (model quality regression) |
| Protocol | HTTP request/response | SSE, WebSocket, gRPC |

nginx, Caddy, and Traefik were built for the left column. A3S Gateway is built for the right:

- **SSE/Streaming** — chunked transfer without response buffering; first token reaches the client as soon as the model emits it
- **Static revision traffic splitting** — apply explicit weights across healthy backend revisions without changing their desired lifecycle
- **Traffic mirroring** — shadow-test a new model with real requests before it handles a single production response
- **WebSocket multiplexing** — named pub/sub channels over a single connection for real-time AI interactions

Everything else (routing, TLS, rate limiting, circuit breaker, Prometheus) is table-stakes infrastructure packaged so you don't need a second tool.

Production replica count, placement, rollout, and autoscaling are control-plane
decisions in A3S Cloud-managed deployments. The Gateway executes the complete
applied traffic snapshot and remains off the Cloud API request path.

**1098 tests** | **83 source files** | **~34,000 lines of Rust** | **Single statically-linked binary** | **MSRV 1.88**

---

## Product Modes

| Mode | Desired-state authority | Gateway responsibility |
| --- | --- | --- |
| **Standalone** | Operator-owned ACL configuration | Validate and apply local routing, transport, health, and middleware policy |
| **A3S Cloud-managed** | A3S Cloud desired state | Enforce the managed-mode boundary and apply static traffic configuration; complete versioned snapshot delivery remains an `H0.2` gate |

Standalone Gateway does not require Cloud. Local autoscaling remains
experimental, and gradual rollout configuration is not wired into the live
runtime. In Cloud-managed mode, Cloud is the sole production rollout and
autoscaling authority. Gateway rejects local file, discovery, Kubernetes, and
Docker providers, along with service-level `scaling` and `rollout` blocks.
Static routes, health policy, mirroring, and revision weights remain valid.

The mode defaults to `standalone`, is exposed through configuration and health
status, and cannot be changed by hot reload. Changing the desired-state
authority requires a process restart. Versioned snapshot identity, digest,
expiry, and acknowledgement remain part of `H0.2`.

See the [Roadmap](ROADMAP.md) for current capability truth, ownership,
delivery order, and cross-repository exit gates.

---

## Quick Start

```bash
# Install
brew install a3s-lab/tap/a3s-gateway

# Or via cargo
cargo install a3s-gateway

# Start
a3s-gateway --config gateway.acl
```

```acl
# gateway.acl - proxy all traffic to an LLM service
mode { kind = "standalone" }

entrypoints "web" {
  address = "0.0.0.0:8080"
}

routers "llm" {
  rule    = "PathPrefix(`/v1`)"
  service = "llm-backend"
  middlewares = ["rate-limit", "auth-jwt"]
}

services "llm-backend" {
  load_balancer {
    strategy        = "least-connections"
    request_timeout = "60s"
    servers         = [
      { url = "http://127.0.0.1:8001" },
      { url = "http://127.0.0.1:8002" }
    ]
    health_check { path = "/health" }
  }
}

middlewares "rate-limit" { type = "rate-limit"; rate = 60; burst = 10 }
middlewares "auth-jwt"   { type = "jwt"; value = env("JWT_SECRET") }
```

### Programmatic

```rust
use a3s_gateway::{Gateway, config::GatewayConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> a3s_gateway::Result<()> {
    let config = GatewayConfig::from_file("gateway.acl").await?;
    let gateway = Arc::new(Gateway::new(config)?);
    gateway.start().await?;
    gateway.wait_for_shutdown().await;
    Ok(())
}
```

---

## Features

### AI Workload Patterns

| Capability | State | How it works |
|---------|-------------|-------------|
| **SSE / Streaming** | Available | Chunked transfer relay without response buffering |
| **Static revision traffic splitting** | Available | Apply explicit revision weights with per-revision health tracking |
| **Traffic mirroring** | Available | Fire-and-forget copy of live traffic to a shadow backend |
| **Local scale-to-zero and buffering** | Experimental, standalone only | Queue depth currently drives the incomplete local executor path |
| **Automated gradual rollout** | Unavailable | Configuration is parsed, but no runtime loop drives it; Cloud will own managed rollout |
| **OpenAI model dispatch and cached grants** | Planned: `I0.2b` | Body-aware model routing and local enforcement from a complete Cloud snapshot |
| **Durable request and attempt usage** | Planned: `I0.2c` | Local ordered spool uploaded to the Cloud-owned ledger |

### Inline Wire Firewall (`wire` feature)

An agentfw-style local proxy on the LLM/MCP wire, built on [a3s-sentry](https://github.com/A3S-Lab/Sentry).
Point an agent's provider base URL at `http://localhost:<port>/wire/<agent>/...`; the gateway decodes
each request body, runs sentry's tiered detectors over it, **masks secrets/PII before they reach the
upstream** (restoring them on the response), and blocks an injection/jailbreak request outright with a
`403` + JSON reason — then forwards the masked call to the real provider. Every call writes one NDJSON
trace line (agent, path, verdict, tier, severity, redactions). Complementary to a3s-observer's kernel
backstop, which still covers traffic that bypasses the proxy (raw sockets, an agent that ignores the
base URL) — an inline proxy alone is bypassable. Off by default (keeps the base build lean); enable
with `--features wire`. See [`src/wire.rs`](src/wire.rs).

```bash
# run the wire firewall in front of Anthropic; point the agent at http://localhost:9877/wire/<agent>/
cargo run --features wire -- wire \
  --listen 127.0.0.1:9877 --upstream https://api.anthropic.com \
  --sentry-config sentry.acl          # empty = built-in rules, fail-open (masking always on)
# e.g. Claude Code:  ANTHROPIC_BASE_URL=http://localhost:9877/wire/claude-code  claude
```

`--listen` defaults to `127.0.0.1:9877`, `--upstream` is the single required provider origin, and
`--sentry-config` takes a sentry ACL path or inline content (empty = built-in rules, fail-open).
Embeddable too: `wire::serve(addr, gate, upstream)` (or `serve_with_listener` on a pre-bound socket);
the pure `WireGate` gate methods unit-test without a live upstream.

**Wire-correctness hardening** — the transport stays faithful so masking can't be defeated or break a real call:

- **Path *and* query forwarded** verbatim, so Azure OpenAI `?api-version=` / Gemini `?key=` params survive.
- **`accept-encoding` stripped** before forwarding — the upstream replies identity-encoded, so a gzip body can't slip past the placeholder restore (the proxy ships no decompressor).
- **8 MiB request-body cap** (the gate buffers the whole body to mask it); over it → `413`.
- **Upstream status + content-type preserved** (not forced to `application/json`), so a `429`, an error body, or an SSE content-type passes through unchanged.
- **Non-UTF-8 (binary) bodies pass through ungated** — masking regexes can't run on binary, and a lossy decode would corrupt the request.
- **Response leg audited** — after restoring placeholders, `scan_response` re-runs the detectors over the completion and logs a trace line if the model leaked a secret or emitted harmful content. Audit only: the reply reaches the trusted agent unmodified.
- **Per-request restore map** — one request's placeholder can never be restored into another's.

**Honest boundaries** (in scope, not yet closed):

- **Placeholder relocation.** A compromised/injected *model* sees the placeholder (the masked body is what it receives) and could echo it into a dangerous spot in its reply (a URL/command); `ungate_response` restores positionally-blind, so the real value lands there. Hard-blocking such a completion needs an L2 guard (fail-open by default).
- **Encoded secrets.** Byte-level regex detectors don't see a secret that's `\uXXXX`-escaped or base64'd in the JSON — it's decoded only inside the model. Detection is best-effort, not a proof.
- **Authorization passes through.** The provider API key in `Authorization` is forwarded as-is (the upstream needs it); masking targets secrets in the *prompt/body*, not the call's own credential.

**Soak-tested** ([`scripts/soak-wire.sh`](scripts/soak-wire.sh)) — sustained concurrent secret-bearing
load through the live proxy, asserting the secret never reaches the upstream, the response is restored,
RSS stays flat, and it never crashes. A 20s / concurrency-32 run: **71,591 requests, 0 errors, 0 leaks,
RSS flat at ~18 MB (1.15× growth)**.

### Core Proxy

- **Dynamic routing**: Traefik-style rule engine — `Host()`, `PathPrefix()`, `Path()`, `Headers()`, `Method()`, `&&`
- **Load balancing**: Round-robin, weighted, least-connections, random
- **Health checks**: Active HTTP probes + passive error-count eviction
- **Sticky sessions**: Cookie-based backend affinity with TTL and LRU eviction
- **Failover**: Automatic switch to secondary pool when primary has no healthy backends
- **Forwarded headers**: Upstreams receive normalized `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and `X-Forwarded-Port`
- **Upstream timeouts**: Per-service plain HTTP `request_timeout` returns `504 Gateway Timeout` on slow backends
- **TLS termination**: rustls (pure Rust, no OpenSSL) + ACME/Let's Encrypt (HTTP-01, DNS-01/Cloudflare, DNS-01/Route53)
- **Hot reload**: File-watch config reload (inotify/kqueue) — unchanged HTTP/TCP entrypoints are not rebound

### Protocols

| Protocol | Capability |
|----------|-----------|
| HTTP/1.1 & HTTP/2 | Full reverse proxy, hop-by-hop header filtering, normalized `X-Forwarded-*` metadata |
| WebSocket | Upgrade detection, bidirectional relay, named-channel multiplexing |
| SSE / Streaming | Chunked transfer, zero buffering — optimized for LLM token streams |
| gRPC | HTTP/2 h2c forwarding with header translation |
| TCP | Raw byte relay, SNI-based routing (`HostSNI()`), IP filtering |
| UDP | Session-based datagram relay |

### Middlewares (15 built-in)

| Middleware | Config Keys | Purpose |
|------------|-------------|---------|
| `jwt` | `value` | JWT validation (HS256) |
| `api-key` | `header`, `keys` | API key enforcement |
| `basic-auth` | `username`, `password` | HTTP Basic Auth |
| `forward-auth` | `forward_auth_url` | Delegate auth to external IdP |
| `rate-limit` | `rate`, `burst` | Token bucket (in-process) |
| `rate-limit-redis` | `rate`, `burst`, `redis_url` | Distributed rate limiting |
| `cors` | `allowed_origins`, `allowed_methods` | CORS headers |
| `headers` | `request_headers`, `response_headers` | Header manipulation |
| `strip-prefix` | `prefixes` | Path prefix removal |
| `body-limit` | `max_body_bytes` | Request body cap (413 on exceed) |
| `retry` | `max_retries`, `retry_interval_ms` | Retry on upstream failure |
| `circuit-breaker` | `failure_threshold`, `cooldown_secs` | Closed/Open/HalfOpen state machine |
| `ip-allow` | `allowed_ips` | CIDR/IP allowlist |
| `compress` | — | brotli/gzip/deflate (br preferred) |
| `tcp-filter` | — | Connection limit + IP allowlist for TCP |

### Observability

All observability features are individually configurable — disable any of them to reduce per-request overhead in high-throughput scenarios.

```acl
observability {
  metrics_enabled     = true   # Prometheus metrics (default: true)
  access_log_enabled  = true   # Structured JSON access log (default: true)
  tracing_enabled     = false  # W3C Trace Context propagation (default: true)
}
```

- **Prometheus metrics**: Per-router/service/backend request counts, latency histograms, error rates, autoscaler state
- **Structured access-log contract**: The JSON schema and tracker exist, but complete per-request emission is still planned; use ordinary tracing logs for live request visibility today
- **Distributed tracing**: W3C Trace Context and B3/Zipkin propagation; inject spans into upstream requests
- **Management**: CLI-first operations plus an optional authenticated/mTLS Dashboard API on a dedicated listener

### Service Discovery

- **File provider**: ACL with directory watching and hot reload
- **DNS provider**: Hostname resolution with TTL-based caching
- **Docker provider**: Auto-discover services from container labels (`a3s.router.rule`, `a3s.service.port`)
- **Health-based discovery**: Auto-register backends via `/.well-known/a3s-service.json`
- **Kubernetes Ingress** (`kube` feature): Watch `networking.k8s.io/v1/Ingress` resources
- **Kubernetes IngressRoute CRD** (`kube` feature): Traefik-style advanced routing

### Performance

Built for throughput. The proxy hot path uses direct hyper HTTP/1.1 connection pooling with streaming request body passthrough — no intermediate buffering for plain HTTP traffic.

| Metric | Value | Conditions |
|--------|-------|-----------|
| **Throughput** | 67,000 req/s | 200 concurrent connections, Apple Silicon, loopback |
| **Latency overhead** | 69 µs (p50) | Single connection, measures pure gateway overhead |
| **Tail latency** | 5.6 ms (p99) | 200 concurrent connections |
| **Routing** | 90 ns | Match against 100-route table |
| **Middleware pipeline** | 130 ns/middleware | Pre-compiled at startup, no per-request allocation |
| **Config reload** | 3 ms | 300-service configuration, hot reload |

Benchmarked with [oha](https://github.com/hatoo/oha) (Rust HTTP load generator) against a hyper backend on loopback. Criterion micro-benchmarks included in `benches/`.

---

## Configuration

All configuration uses ACL format (`.acl` files). The operating mode is a
process-level boundary:

```acl
# Default when the mode block is omitted.
mode { kind = "standalone" }

# Use this when A3S Cloud is the desired-state authority.
# mode { kind = "cloud-managed" }
```

Standalone changes can be picked up automatically when file watching is
enabled. Cloud-managed configuration rejects all local dynamic providers,
service autoscaling, and service rollout. A reload may update traffic
configuration within the current mode, but it cannot switch modes.

```acl
# LLM API gateway with streaming, health checks, and shadow traffic
mode { kind = "standalone" }

entrypoints "web"       { address = "0.0.0.0:80" }
entrypoints "websecure" {
  address = "0.0.0.0:443"
  tls { cert_file = "/etc/certs/cert.pem"; key_file = "/etc/certs/key.pem" }
}

routers "llm-api" {
  rule        = "Host(`api.example.com`) && PathPrefix(`/v1`)"
  service     = "llm-service"
  entrypoints = ["websecure"]
  middlewares  = ["auth-jwt", "rate-limit", "circuit-breaker"]
}

services "llm-service" {
  load_balancer {
    strategy        = "least-connections"
    request_timeout = "60s"
    servers         = [
      { url = "http://127.0.0.1:8001" },
      { url = "http://127.0.0.1:8002" }
    ]
    health_check { path = "/health"; interval = "10s" }
  }

  # Mirror 5% of traffic to a new model for shadow testing
  mirror { service = "llm-canary"; percentage = 5 }
}

services "llm-canary" {
  load_balancer {
    servers = [{ url = "http://127.0.0.1:8100" }]
  }
}

middlewares "auth-jwt"       { type = "jwt"; value = env("JWT_SECRET") }
middlewares "rate-limit"     { type = "rate-limit"; rate = 100; burst = 20 }
middlewares "circuit-breaker" {
  type              = "circuit-breaker"
  failure_threshold = 5
  cooldown_secs     = 30
  success_threshold = 2
}

providers {
  file { watch = true; directory = "/etc/gateway/conf.d/" }
}
```

### Service Discovery Contract

Backends expose `/.well-known/a3s-service.json` (RFC 8615) for automatic registration:

```json
{
  "name": "llm-service",
  "version": "2.1.0",
  "routes": [
    { "rule": "PathPrefix(`/v1`)", "middlewares": ["rate-limit"] }
  ],
  "health_path": "/health",
  "weight": 1
}
```

---

## Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │              A3S Gateway                      │
                    │                                              │
  Client ──────────┤  Entrypoint (HTTP/HTTPS/TCP/UDP)             │
  (HTTP/WS/SSE/    │      │                                      │
   gRPC/TCP/UDP)   │      ▼                                      │
                    │  TLS Termination (rustls + ACME)            │
                    │      │                                      │
                    │      ▼                                      │
                    │  Router ──── Rule Matching                  │
                    │      │       (Host, Path, Headers, SNI)     │
                    │      ▼                                      │
                    │  Middleware Pipeline                         │
                    │  ┌──────┬────────┬──────────┬───────────┐  │
                    │  │Auth  │  Rate  │  Circuit │  Compress │  │
                    │  │JWT   │  Limit │  Breaker │  CORS     │  │
                    │  └──────┴────────┴──────────┴───────────┘  │
                    │      │                                      │
                    │      ▼                                      │
                    │  Service (LB + Health + Failover + Mirror)  │
                    │      │                                      │
                    └──────┼──────────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌────────┐  ┌────────┐  ┌──────────┐
         │HTTP    │  │gRPC    │  │TCP/UDP   │
         │Backend │  │Backend │  │Backend   │
         └────────┘  └────────┘  └──────────┘
```

### Core Components

| Component | Responsibility |
|-----------|---------------|
| `Gateway` | Lifecycle orchestrator — owns all subsystems |
| `Entrypoint` | Network listener (HTTP, HTTPS, TCP, UDP) |
| `Router` | Rule-based request matching; O(n) scan with priority ordering |
| `Middleware` | Composable request/response pipeline; pre-compiled per-router at startup |
| `Service` | Backend pool — load balancing, health, mirroring, failover |
| `Scaling` | Experimental standalone autoscaler, request buffer, and static revision router; unavailable as a managed control loop |
| `Provider` | Dynamic config sources — file, DNS, discovery, Kubernetes |
| `Proxy` | Protocol forwarder — HTTP, WebSocket, SSE, gRPC, TCP, UDP |

### Gateway Lifecycle

```
Created → Starting → Running ⇄ Reloading → Stopping → Stopped
```

Hot reload (`Reloading`) replaces router table and service registry atomically under a shared runtime snapshot. HTTP/TCP entrypoints keep their sockets when listener configuration is unchanged. If HTTP/TCP listeners are added or moved, only changed entrypoints are reconciled; unchanged listeners remain active if the new bind fails. UDP entrypoints still restart explicitly.

---

## Deployment

### Homebrew

```bash
brew install a3s-lab/tap/a3s-gateway
```

### Helm (Kubernetes)

```bash
helm install gateway deploy/helm/a3s-gateway \
  --set-file config=my-gateway.acl \
  --set service.type=LoadBalancer
```

### Docker

```bash
docker run -v $(pwd)/gateway.acl:/etc/a3s-gateway/gateway.acl \
  -p 8080:8080 ghcr.io/a3s-lab/gateway:latest
```

### Cargo

```bash
cargo install a3s-gateway
```

---

## API Reference

### Rust API

| Method | Description |
|--------|-------------|
| `Gateway::new(config)` | Create from `GatewayConfig` |
| `start()` | Bind listeners and begin proxying |
| `shutdown()` | Graceful drain and stop |
| `reload(new_config)` | Atomic hot reload without downtime |
| `health()` | Current health snapshot |
| `metrics()` | Prometheus metrics collector |
| `state()` | `GatewayState` enum |

### Management

Management is CLI-first by default. The optional Dashboard API runs on a
dedicated listener, so `/api/gateway/*` on traffic entrypoints remains normal
user traffic and can be routed by your own routers. Management requests require
both a matching `allowed_ips` entry and a bearer token when `auth_token_env` is
set. Remote management listeners can also require HTTPS and client certificates.

```bash
a3s-gateway validate --config gateway.acl
a3s-gateway config --config gateway.acl summary
a3s-gateway config --config gateway.acl entrypoints
a3s-gateway config --config gateway.acl routes
a3s-gateway config --config gateway.acl services
a3s-gateway config --config gateway.acl middlewares
a3s-gateway config --config gateway.acl providers
a3s-gateway config --config gateway.acl json
a3s-gateway management events --url http://127.0.0.1:9090/api/gateway
a3s-gateway management validate --url http://127.0.0.1:9090/api/gateway --file gateway.acl
a3s-gateway management reload --url http://127.0.0.1:9090/api/gateway --file gateway.acl
```

Use `--ca-cert`, `--client-cert`, and `--client-key` with
`management events` when the management listener requires mTLS.

```acl
management {
  enabled        = true
  address        = "127.0.0.1:9090"
  path_prefix    = "/api/gateway"
  auth_token_env = "A3S_GATEWAY_ADMIN_TOKEN"
  allowed_ips    = ["127.0.0.1", "::1"]

  tls {
    cert_file           = "/etc/a3s/admin/server.crt"
    key_file            = "/etc/a3s/admin/server.key"
    client_ca_file      = "/etc/a3s/admin/client-ca.crt"
    require_client_cert = true
    min_version         = "1.3"
  }
}
```

| Endpoint | Response |
|----------|---------|
| `GET /api/gateway/health` | Gateway lifecycle, operating mode, uptime, connections, and request count (JSON) |
| `GET /api/gateway/metrics` | Prometheus text format |
| `GET /api/gateway/config` | Active configuration (JSON) |
| `GET /api/gateway/routes` | Configured routes |
| `GET /api/gateway/services` | Services with backend health |
| `GET /api/gateway/backends` | All backends with connection counts |
| `GET /api/gateway/events` | Recent management security audit events |
| `GET /api/gateway/version` | Binary version |
| `POST /api/gateway/config/validate` | Validate an ACL payload without applying it |
| `POST /api/gateway/config/reload` | Transactionally reload from an ACL payload |

---

## Development

```bash
cargo build -p a3s-gateway
cargo test -p a3s-gateway --all-features   # 1098 tests
cargo clippy -p a3s-gateway --all-features -- -D warnings
cargo bench --no-run --all-features        # compile benchmarks
```

Or use the justfile:

```bash
just ci              # fmt + lint + test (full gate)
just bench           # run criterion benchmarks
just release-check   # full pre-release validation
```

The implementation sequence and cross-repository acceptance criteria are in
the [Roadmap](ROADMAP.md). In particular, new Cloud-managed behavior
must preserve one control-plane authority and pass the matching Cloud gate.

### Project Structure

```
src/
├── lib.rs, main.rs          # Public API + CLI
├── gateway.rs               # Lifecycle orchestrator
├── dashboard.rs             # Optional dedicated management API
├── entrypoint.rs            # HTTP/HTTPS/TCP/UDP listeners + hot path
├── error.rs                 # GatewayError, Result
│
├── config/                  # ACL configuration model
│   └── acl.rs, entrypoint.rs, router.rs, service.rs, scaling.rs, middleware.rs
│
├── router/                  # Rule matching engine
│   ├── rule.rs              # Host/Path/Header/Method/SNI matchers
│   └── tcp.rs               # TCP SNI router
│
├── middleware/              # 15 built-in middleware types
│
├── service/                 # Backend pool management
│   └── load_balancer.rs, health_check.rs, passive_health.rs,
│       sticky.rs, mirror.rs, failover.rs
│
├── proxy/                   # Protocol forwarders
│   └── http_proxy.rs, websocket.rs, streaming.rs, grpc.rs,
│       tcp.rs, udp.rs, tls.rs, acme*.rs, ws_mux.rs
│
├── observability/
│   └── metrics.rs, access_log.rs, tracing.rs
│
├── scaling/                 # Knative-style autoscaler
│   └── executor.rs, autoscaler.rs, buffer.rs,
│       concurrency.rs, revision.rs, rollout.rs
│
└── provider/                # Config providers
    └── file_watcher.rs, dns.rs, docker.rs, discovery.rs,
        kubernetes.rs, kubernetes_crd.rs  (feature: kube)

benches/                     # Criterion benchmarks
├── routing.rs               # RouterTable::match_request
├── middleware_pipeline.rs   # Pipeline::process_request
└── acl_parse.rs             # GatewayConfig::from_acl

deploy/
└── helm/a3s-gateway/        # Helm chart
```

---

## Stability

A3S Gateway follows [Semantic Versioning](https://semver.org/). Starting with v1.0.0:

- **Stable**: Public Rust API (`Gateway`, `GatewayConfig`, `GatewayState`, `HealthStatus`, `GatewayError`), ACL configuration format, Management API endpoints, CLI interface.
- **Unstable** (may change in minor releases): `#[doc(hidden)]` modules (`router`, `middleware`), internal provider implementations, benchmark infrastructure.
- **MSRV**: Rust 1.88. May advance in minor releases with at least 3 stable-version lag.

See [CHANGELOG.md](CHANGELOG.md) for release history and [RELEASING.md](RELEASING.md) for the release process.

---

## Community

[Discord](https://discord.gg/XVg6Hu6H) — questions, discussions, updates.

## License

MIT
