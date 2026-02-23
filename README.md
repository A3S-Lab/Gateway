# A3S Gateway

<p align="center">
  <strong>The traffic layer for AI-native services</strong>
</p>

<p align="center">
  <em>Single binary. HCL config. Hot reload. Built for LLM streaming, scale-to-zero, and safe model rollouts.</em>
</p>

<p align="center">
  <a href="#why-a3s-gateway">Why A3S Gateway</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#deployment">Deployment</a> •
  <a href="#api-reference">API Reference</a>
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
- **Scale-to-zero with request buffering** — when a model is cold, incoming requests are held in memory and replayed the moment the replica is ready, not dropped or returned 503
- **Revision traffic splitting** — send 5% of live traffic to a new model version; automatically roll back if error rate or p99 latency crosses a threshold
- **Traffic mirroring** — shadow-test a new model with real requests before it handles a single production response
- **WebSocket multiplexing** — named pub/sub channels over a single connection for real-time AI interactions

Everything else (routing, TLS, rate limiting, circuit breaker, Prometheus) is table-stakes infrastructure packaged so you don't need a second tool.

**877 tests** | **69 source files** | **~26,000 lines of Rust** | **Single statically-linked binary**

---

## Quick Start

```bash
# Install
brew install a3s-lab/tap/a3s-gateway

# Or via cargo
cargo install a3s-gateway

# Start
a3s-gateway --config gateway.hcl
```

```hcl
# gateway.hcl — proxy all traffic to an LLM service
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
    strategy = "least-connections"
    servers  = [
      { url = "http://127.0.0.1:8001" },
      { url = "http://127.0.0.1:8002" }
    ]
    health_check { path = "/health" }
  }

  # Scale to zero — buffer requests during cold start
  scaling {
    min_replicas          = 0
    max_replicas          = 4
    container_concurrency = 10
    buffer_enabled        = true
    executor              = "box"
  }
}

middlewares "rate-limit" { type = "rate-limit"; rate = 60; burst = 10 }
middlewares "auth-jwt"   { type = "jwt"; value = "${JWT_SECRET}" }
```

### Programmatic

```rust
use a3s_gateway::{Gateway, config::GatewayConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> a3s_gateway::Result<()> {
    let config = GatewayConfig::from_file("gateway.hcl").await?;
    let gateway = Arc::new(Gateway::new(config)?);
    gateway.start().await?;
    gateway.wait_for_shutdown().await;
    Ok(())
}
```

---

## Features

### AI Workload Patterns

| Feature | How it works |
|---------|-------------|
| **SSE / Streaming** | Chunked transfer relay — zero response buffering, first token delivered immediately |
| **Scale-to-zero** | Knative formula: `desired = ⌈(in_flight + queue_depth) / (concurrency × utilization)⌉` |
| **Cold-start buffering** | Requests queue in memory during scale-up; replayed once backend is ready |
| **Revision traffic splitting** | Route N% to v1, M% to v2 with per-revision health tracking |
| **Gradual rollout** | Step-by-step traffic shift with automatic rollback on error rate or latency breach |
| **Traffic mirroring** | Fire-and-forget copy of live traffic to a shadow backend (no client impact) |

### Core Proxy

- **Dynamic routing**: Traefik-style rule engine — `Host()`, `PathPrefix()`, `Path()`, `Headers()`, `Method()`, `&&`
- **Load balancing**: Round-robin, weighted, least-connections, random
- **Health checks**: Active HTTP probes + passive error-count eviction
- **Sticky sessions**: Cookie-based backend affinity with TTL and LRU eviction
- **Failover**: Automatic switch to secondary pool when primary has no healthy backends
- **TLS termination**: rustls (pure Rust, no OpenSSL) + ACME/Let's Encrypt (HTTP-01, DNS-01/Cloudflare, DNS-01/Route53)
- **Hot reload**: File-watch config reload (inotify/kqueue) — connections never drop

### Protocols

| Protocol | Capability |
|----------|-----------|
| HTTP/1.1 & HTTP/2 | Full reverse proxy, hop-by-hop header filtering |
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

- **Prometheus metrics**: Per-router/service/backend request counts, latency histograms, error rates, autoscaler state
- **Structured access log**: JSON entries — timestamp, client IP, method, path, status, duration, backend, router
- **Distributed tracing**: W3C Trace Context and B3/Zipkin propagation; inject spans into upstream requests
- **Dashboard API**: `GET /api/gateway/{health,metrics,config,routes,services,backends,version}`

### Service Discovery

- **File provider**: HCL with directory watching and hot reload
- **DNS provider**: Hostname resolution with TTL-based caching
- **Health-based discovery**: Auto-register backends via `/.well-known/a3s-service.json`
- **Kubernetes Ingress** (`kube` feature): Watch `networking.k8s.io/v1/Ingress` resources
- **Kubernetes IngressRoute CRD** (`kube` feature): Traefik-style advanced routing

---

## Configuration

All configuration uses HCL format (`.hcl` files). Changes are picked up automatically when file watching is enabled — no restart required.

```hcl
# Full example — LLM API gateway with safe rollout
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
    strategy = "least-connections"
    servers  = [
      { url = "http://127.0.0.1:8001" },
      { url = "http://127.0.0.1:8002" }
    ]
    health_check { path = "/health"; interval = "10s" }
  }

  # Mirror 5% of traffic to a new model for shadow testing
  mirror { service = "llm-canary"; percentage = 5 }

  # Scale to zero when idle — buffer requests during cold start
  scaling {
    min_replicas          = 0
    max_replicas          = 8
    container_concurrency = 10
    target_utilization    = 0.7
    buffer_enabled        = true
    executor              = "box"
  }

  # Shift traffic from v1 to v2 over 10 steps, 1 minute apart
  # Auto-rollback if error rate > 5% or p99 > 5s
  rollout {
    from                 = "v1"
    to                   = "v2"
    step_percent         = 10
    step_interval_secs   = 60
    error_rate_threshold = 0.05
    latency_threshold_ms = 5000
  }
}

middlewares "auth-jwt"       { type = "jwt"; value = "${JWT_SECRET}" }
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
                    │      ▼                                      │
                    │  Scaling (Knative autoscaler + buffer)      │
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
| `Scaling` | Knative autoscaler — concurrency tracking, request buffer, revision router |
| `Provider` | Dynamic config sources — file, DNS, discovery, Kubernetes |
| `Proxy` | Protocol forwarder — HTTP, WebSocket, SSE, gRPC, TCP, UDP |

### Gateway Lifecycle

```
Created → Starting → Running ⇄ Reloading → Stopping → Stopped
```

Hot reload (`Reloading`) replaces router table and service registry atomically under an `Arc` swap — no connection is dropped.

---

## Deployment

### Homebrew

```bash
brew install a3s-lab/tap/a3s-gateway
```

### Helm (Kubernetes)

```bash
helm install gateway deploy/helm/a3s-gateway \
  --set-file config=my-gateway.hcl \
  --set service.type=LoadBalancer
```

### Docker

```bash
docker run -v $(pwd)/gateway.hcl:/etc/a3s-gateway/gateway.hcl \
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

### Dashboard Endpoints

| Endpoint | Response |
|----------|---------|
| `GET /api/gateway/health` | Gateway + backend health (JSON) |
| `GET /api/gateway/metrics` | Prometheus text format |
| `GET /api/gateway/config` | Active configuration (JSON) |
| `GET /api/gateway/routes` | All matched routes |
| `GET /api/gateway/services` | Services with backend health |
| `GET /api/gateway/backends` | All backends with connection counts |
| `GET /api/gateway/version` | Binary version |

---

## Development

```bash
cargo build -p a3s-gateway
cargo test -p a3s-gateway --lib          # 877 tests
cargo build -p a3s-gateway --all-features  # Redis + K8s support
cargo clippy -p a3s-gateway -- -D warnings
```

### Project Structure

```
src/
├── lib.rs, main.rs          # Public API + CLI
├── gateway.rs               # Lifecycle orchestrator
├── dashboard.rs             # Dashboard API
├── entrypoint.rs            # HTTP/HTTPS/TCP/UDP listeners + hot path
├── error.rs                 # GatewayError, Result
│
├── config/                  # HCL configuration model
│   └── entrypoint.rs, router.rs, service.rs, scaling.rs, middleware.rs
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
    └── file_watcher.rs, dns.rs, discovery.rs,
        kubernetes.rs, kubernetes_crd.rs  (feature: kube)

deploy/
└── helm/a3s-gateway/        # Helm chart
```

---

## Community

[Discord](https://discord.gg/XVg6Hu6H) — questions, discussions, updates.

## License

MIT
