# A3S Gateway

<p align="center">
  <strong>Traefik-compatible Reverse Proxy & K8s Ingress Controller</strong>
</p>

<p align="center">
  <em>Application-agnostic traffic routing for A3S OS — TLS termination, load balancing, 15 middlewares, hot reload, Knative-style autoscaling.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#development">Development</a>
</p>

---

**A3S Gateway** is an application-agnostic reverse proxy and Kubernetes Ingress Controller built for the A3S ecosystem. It speaks Traefik's routing DSL, terminates TLS, enforces middleware policies, and forwards traffic to any HTTP/gRPC/TCP/UDP backend — without knowing or caring what runs behind it.

**825 tests** | **67 source files** | **~20,000 lines of Rust**

## Quick Start

### CLI

```bash
# Start with config file
a3s-gateway --config gateway.toml

# Start with debug logging
a3s-gateway --config gateway.toml --log-level debug

# Validate config before deploy
a3s-gateway validate --config gateway.toml
```

### Programmatic

```rust
use a3s_gateway::{Gateway, config::GatewayConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = GatewayConfig::from_file("gateway.toml").await?;
    let gateway = Arc::new(Gateway::new(config)?);
    gateway.start().await?;
    let health = gateway.health();
    println!("State: {}, Uptime: {}s", health.state, health.uptime_secs);
    gateway.wait_for_shutdown().await;
    Ok(())
}
```

## Features

### Core Proxy
- **Dynamic Routing**: Traefik-style rule engine (`Host()`, `PathPrefix()`, `Path()`, `Headers()`, `Method()`, `&&`)
- **Load Balancing**: Round-robin, weighted, least-connections, random
- **Health Checks**: Active HTTP probes + passive error-count removal
- **TLS Termination**: rustls-based with ACME/Let's Encrypt (HTTP-01 + DNS-01/Cloudflare)
- **Hot Reload**: File-watch based config reload without restart
- **Sticky Sessions**: Cookie-based backend affinity with TTL and eviction
- **Dashboard API**: Built-in `/health`, `/metrics`, `/config` endpoints

### Protocols
- HTTP/1.1 & HTTP/2, WebSocket, SSE/Streaming, gRPC (h2c), TCP, UDP
- **TCP SNI Router**: ClientHello SNI extraction with `HostSNI()` matching and wildcards
- **WebSocket Multiplexing**: Named channel pub/sub over a single WebSocket connection

### Middlewares (15 built-in)

| Type | Config Keys | Description |
|------|-------------|-------------|
| `api-key` | `header`, `keys` | API key validation |
| `basic-auth` | `username`, `password` | HTTP Basic authentication |
| `jwt` | `value` | JWT validation (HS256) |
| `forward-auth` | `forward_auth_url`, `forward_auth_response_headers` | Delegate auth to external IdP |
| `rate-limit` | `rate`, `burst` | Token bucket (in-memory) |
| `rate-limit-redis` | `rate`, `burst`, `redis_url` | Distributed rate limiting (`redis` feature) |
| `cors` | `allowed_origins`, `allowed_methods`, `allowed_headers` | CORS headers |
| `headers` | `request_headers`, `response_headers` | Header manipulation |
| `strip-prefix` | `prefixes` | Path prefix removal |
| `body-limit` | `max_body_bytes` | Max request body size (413 on exceed) |
| `retry` | `max_retries`, `retry_interval_ms` | Retry on failure |
| `circuit-breaker` | `failure_threshold`, `cooldown_secs`, `success_threshold` | Closed/Open/HalfOpen state machine |
| `ip-allow` | `allowed_ips` | CIDR/IP allowlist |
| `compress` | — | brotli/gzip/deflate (br preferred) |
| `tcp-filter` | — | In-flight connection limit + IP allowlist for TCP |

### Observability
- **Prometheus Metrics**: Per-router/service/middleware request counts, latency, errors
- **Structured Access Log**: JSON entries with duration, backend, router
- **Distributed Tracing**: W3C Trace Context and B3/Zipkin propagation

### Service Discovery
- **File Provider**: TOML/YAML with file watching
- **DNS Provider**: Hostname resolution with caching
- **Health-based Discovery**: Auto-register backends via `/.well-known/a3s-service.json`
- **Kubernetes Ingress**: Watch K8s `networking.k8s.io/v1/Ingress` resources (feature-gated `kube`)
- **Kubernetes IngressRoute CRD**: Advanced routing with Traefik-style rules (feature-gated `kube`)

### Knative-Style Autoscaling (Optional)
- Autoscaler decision engine: Knative formula, min/max replicas, scale-down cooldown
- Scale-from-zero request buffering during cold starts
- Per-instance concurrency limit (`containerConcurrency`) with least-loaded selection
- Revision-based traffic splitting and gradual canary rollout with auto-rollback
- Pluggable `ScaleExecutor`: `BoxScaleExecutor` (HTTP), `K8sScaleExecutor` (kube-rs, `kube` feature), `MockScaleExecutor`

## Architecture

### Request Flow

```
                    ┌─────────────────────────────────────────────┐
                    │              A3S Gateway                     │
                    │                                             │
  Client ──────────┤  Entrypoint (HTTP/HTTPS/TCP/UDP)            │
  (HTTP/WS/gRPC)   │      │                                     │
                    │      ▼                                     │
                    │  TLS Termination (rustls)                  │
                    │      │                                     │
                    │      ▼                                     │
                    │  Router ──── Rule Matching                 │
                    │      │       (host, path, headers, SNI)    │
                    │      ▼                                     │
                    │  Middleware Pipeline                       │
                    │  ┌─────┬──────┬───────┬──────────┐       │
                    │  │Auth │Rate  │Retry  │Circuit   │       │
                    │  │JWT  │Limit │CORS   │Breaker   │       │
                    │  └─────┴──────┴───────┴──────────┘       │
                    │      │                                     │
                    │      ▼                                     │
                    │  Load Balancer + Sticky Sessions           │
                    │  (round-robin / weighted / least-conn)     │
                    │      │                                     │
                    └──────┼─────────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌────────┐  ┌────────┐  ┌──────────┐
         │HTTP    │  │gRPC    │  │TCP/UDP   │
         │Backend │  │Backend │  │Backend   │
         └────────┘  └────────┘  └──────────┘
```

### Core Components

| Component | Description |
|-----------|-------------|
| `Gateway` | Top-level orchestrator with lifecycle management |
| `Entrypoint` | Listener on a port (HTTP, HTTPS, TCP, UDP) |
| `Router` | Matches requests by rules (`Host()`, `PathPrefix()`, `HostSNI()`) |
| `Middleware` | Transforms requests/responses in a composable pipeline |
| `Service` | Upstream backend pool with load balancing and health checks |
| `Provider` | Supplies dynamic configuration (file, DNS, discovery) |
| `Proxy` | Request forwarding (HTTP, WebSocket, gRPC, TCP, UDP, SSE) |

### Configuration

```toml
# gateway.toml

[entrypoints.web]
address = "0.0.0.0:80"

[entrypoints.websecure]
address = "0.0.0.0:443"
[entrypoints.websecure.tls]
cert_file = "/etc/certs/cert.pem"
key_file  = "/etc/certs/key.pem"

[entrypoints.tcp-db]
address         = "0.0.0.0:5432"
protocol        = "tcp"
max_connections = 100
tcp_allowed_ips = ["10.0.0.0/8", "192.168.1.0/24"]

[routers.api]
rule        = "Host(`api.example.com`) && PathPrefix(`/v1`)"
service     = "api-service"
entrypoints = ["websecure"]
middlewares = ["auth-jwt", "rate-limit"]

[services.api-service.load_balancer]
strategy = "round-robin"
[[services.api-service.load_balancer.servers]]
url = "http://127.0.0.1:8001"
[[services.api-service.load_balancer.servers]]
url = "http://127.0.0.1:8002"

[middlewares.auth-jwt]
type  = "jwt"
value = "${JWT_SECRET}"

[middlewares.rate-limit]
type  = "rate-limit"
rate  = 100
burst = 50

[middlewares.forward-auth]
type                          = "forward-auth"
forward_auth_url              = "http://auth.internal:9090/verify"
forward_auth_response_headers = ["X-User-Id", "X-User-Role"]

[middlewares.body-limit]
type           = "body-limit"
max_body_bytes = 1048576  # 1 MB

# Requires: cargo build --features redis
[middlewares.rate-limit-redis]
type      = "rate-limit-redis"
rate      = 200
burst     = 100
redis_url = "redis://127.0.0.1:6379"

[providers.file]
watch     = true
directory = "/etc/gateway/conf.d/"

# Health-based service discovery (optional)
[providers.discovery]
poll_interval_secs = 30
timeout_secs       = 5

[[providers.discovery.seeds]]
url = "http://10.0.0.5:8080"

[[providers.discovery.seeds]]
url = "http://10.0.0.6:8080"

# Knative-style scaling (optional)
[services.api-service.scaling]
min_replicas          = 0
max_replicas          = 10
container_concurrency = 50
target_utilization    = 0.7
scale_down_delay_secs = 300
buffer_enabled        = true
buffer_timeout_secs   = 30
buffer_size           = 100
executor              = "box"  # or "k8s" with --features kube

# Revision-based traffic splitting (optional)
[[services.api-service.revisions]]
name            = "v1"
traffic_percent = 90
strategy        = "round-robin"
[[services.api-service.revisions.servers]]
url = "http://127.0.0.1:8001"

[[services.api-service.revisions]]
name            = "v2"
traffic_percent = 10
strategy        = "round-robin"
[[services.api-service.revisions.servers]]
url = "http://127.0.0.1:8003"

# Gradual rollout (optional)
[services.api-service.rollout]
from                 = "v1"
to                   = "v2"
step_percent         = 10
step_interval_secs   = 60
error_rate_threshold = 0.05
latency_threshold_ms = 5000
```

### Service Discovery Contract

Backends expose a JSON document at `/.well-known/a3s-service.json` (RFC 8615) for automatic registration:

```json
{
  "name": "auth-service",
  "version": "1.2.0",
  "routes": [
    {
      "rule": "PathPrefix(`/auth`)",
      "middlewares": ["rate-limit"],
      "priority": 0
    }
  ],
  "health_path": "/health",
  "weight": 1
}
```

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `name` | Yes | — | Service key in gateway config |
| `version` | Yes | — | Used for change detection |
| `routes` | No | `[]` | Traefik-style routing rules |
| `health_path` | No | `/health` | Health check endpoint |
| `weight` | No | `1` | Load balancer weight |

The gateway probes each seed URL, fetches metadata, checks health, and merges discovered services into the running config. Static config always wins on name collisions.

## API Reference

### Gateway

| Method | Description |
|--------|-------------|
| `Gateway::new(config)` | Create a new gateway from configuration |
| `start()` | Start listening and proxying |
| `shutdown()` | Graceful shutdown |
| `reload(new_config)` | Hot reload configuration without downtime |
| `health()` | Get gateway health status snapshot |
| `metrics()` | Get metrics collector |
| `config()` | Get current configuration |
| `state()` | Get current runtime state |
| `is_running()` | Check if gateway is running |

### Dashboard API

| Endpoint | Description |
|----------|-------------|
| `GET /api/gateway/health` | Gateway health status (JSON) |
| `GET /api/gateway/metrics` | Prometheus metrics (text) |
| `GET /api/gateway/config` | Current configuration (JSON) |

## Development

### Build & Test

```bash
# Build
cargo build -p a3s-gateway
cargo build -p a3s-gateway --release
cargo build -p a3s-gateway --all-features   # includes Redis + K8s

# Test
cargo test -p a3s-gateway
cargo test -p a3s-gateway --all-features

# Lint / Format
cargo clippy -p a3s-gateway
cargo fmt -p a3s-gateway
```

### Project Structure

```
src/
├── lib.rs              # Public API + re-exports
├── main.rs             # CLI binary
├── gateway.rs          # Orchestrator + Dashboard API
├── entrypoint.rs       # HTTP/HTTPS/TCP listeners
├── error.rs            # GatewayError and Result
│
├── config/             # Configuration model (TOML)
│   ├── entrypoint.rs, router.rs, service.rs
│   ├── scaling.rs, middleware.rs
│
├── router/             # Rule matching
│   ├── rule.rs         # Host/Path/Header/Method engine
│   └── tcp.rs          # TCP SNI router
│
├── middleware/         # 15 built-in middlewares
│   ├── auth.rs, jwt_auth.rs, forward_auth.rs
│   ├── rate_limit.rs, rate_limit_redis.rs
│   ├── cors.rs, headers.rs, strip_prefix.rs
│   ├── body_limit.rs, retry.rs, circuit_breaker.rs
│   ├── ip_allow.rs, ip_matcher.rs, tcp_filter.rs
│   └── compress.rs
│
├── service/            # Backend management
│   ├── load_balancer.rs, health_check.rs, passive_health.rs
│   ├── sticky.rs, mirror.rs, failover.rs
│
├── proxy/              # Request forwarding
│   ├── http_proxy.rs, websocket.rs, streaming.rs
│   ├── grpc.rs, tcp.rs, udp.rs, tls.rs
│   ├── acme.rs, acme_client.rs, acme_manager.rs, acme_dns.rs
│   └── ws_mux.rs
│
├── observability/
│   ├── metrics.rs, access_log.rs, tracing.rs
│
├── scaling/            # Knative-style autoscaling
│   ├── executor.rs, autoscaler.rs, buffer.rs
│   ├── concurrency.rs, revision.rs, rollout.rs
│
└── provider/           # Config providers
    ├── file_watcher.rs, dns.rs, discovery.rs
    ├── kubernetes.rs, kubernetes_crd.rs  (feature `kube`)
```

## A3S Ecosystem

A3S Gateway is **application-agnostic** — it routes traffic to any backend without knowing what application runs behind it.

```
┌────────────────────────────────────────────────────────────┐
│                     A3S Ecosystem                          │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │      a3s-gateway (this project)  ◄── You are here    │  │
│  │      K8s Ingress Controller / Reverse Proxy           │  │
│  │      Application-agnostic traffic routing             │  │
│  └────────────────────┬─────────────────────────────────┘  │
│                       │ routes to any backend              │
│  ┌────────────────────▼─────────────────────────────────┐  │
│  │              a3s-box (VM Runtime)                     │  │
│  │    ┌───────────────────────────────────────────────┐  │  │
│  │    │  Guest workload (any OCI image)               │  │  │
│  │    │  e.g. SafeClaw, web server, database, ...     │  │  │
│  │    └───────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

| Project | Relationship |
|---------|--------------|
| **a3s-box** | VM runtime that hosts backend workloads; gateway routes traffic to services running inside a3s-box VMs |
| **Any backend** | Gateway routes to any HTTP/gRPC/TCP/UDP service — SafeClaw, web servers, databases, APIs |

## License

MIT
