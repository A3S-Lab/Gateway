# A3S Gateway

<p align="center">
  <strong>AI-Native API Gateway & Reverse Proxy</strong>
</p>

<p align="center">
  <em>HCL-configured traffic routing — TLS termination, 15 middlewares, Knative-style autoscaling, hot reload, Helm deployment.</em>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#features">Features</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#deployment">Deployment</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#development">Development</a>
</p>

---

**A3S Gateway** is an application-agnostic reverse proxy built for the A3S ecosystem. It uses HCL (HashiCorp Configuration Language) for configuration, speaks Traefik's routing DSL, terminates TLS, enforces middleware policies, and forwards traffic to any HTTP/gRPC/TCP/UDP backend.

**872 tests** | **69 source files** | **~26,000 lines of Rust**

## Quick Start

```bash
# Start with HCL config
a3s-gateway --config gateway.hcl

# Debug logging
a3s-gateway --config gateway.hcl --log-level debug

# Validate config
a3s-gateway validate --config gateway.hcl
```

```hcl
# gateway.hcl — minimal reverse proxy
entrypoints "web" {
  address = "0.0.0.0:8080"
}

routers "api" {
  rule    = "PathPrefix(`/api`)"
  service = "backend"
}

services "backend" {
  load_balancer {
    strategy = "round-robin"
    servers  = [{ url = "http://127.0.0.1:8001" }]
  }
}
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

## Features

### Core Proxy
- **Dynamic Routing**: Traefik-style rule engine (`Host()`, `PathPrefix()`, `Path()`, `Headers()`, `Method()`, `&&`)
- **Load Balancing**: Round-robin, weighted, least-connections, random
- **Health Checks**: Active HTTP probes + passive error-count removal
- **TLS Termination**: rustls with ACME/Let's Encrypt (HTTP-01 + DNS-01/Cloudflare + DNS-01/Route53)
- **Hot Reload**: File-watch config reload (inotify/kqueue) without restart
- **Sticky Sessions**: Cookie-based backend affinity with TTL and eviction
- **Traffic Mirroring**: Copy a percentage of live traffic to a shadow service
- **Failover**: Automatic fallback to secondary backend pool
- **Dashboard API**: Built-in `/health`, `/metrics`, `/config` endpoints

### Protocols
- HTTP/1.1 & HTTP/2, WebSocket, SSE/Streaming, gRPC (h2c), TCP, UDP
- **TCP SNI Router**: ClientHello SNI extraction with `HostSNI()` matching
- **WebSocket Multiplexing**: Named channel pub/sub over a single connection

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
- **File Provider**: HCL with file watching and hot reload
- **DNS Provider**: Hostname resolution with caching
- **Health-based Discovery**: Auto-register backends via `/.well-known/a3s-service.json`
- **Kubernetes Ingress**: Watch K8s `networking.k8s.io/v1/Ingress` resources (feature `kube`)
- **Kubernetes IngressRoute CRD**: Advanced routing with Traefik-style rules (feature `kube`)

### Knative-Style Autoscaling (Optional)
- Autoscaler decision engine: Knative formula, min/max replicas, scale-down cooldown
- Scale-from-zero request buffering during cold starts
- Per-instance concurrency limit (`containerConcurrency`) with least-loaded selection
- Revision-based traffic splitting and gradual canary rollout with auto-rollback
- Pluggable `ScaleExecutor`: `BoxScaleExecutor` (HTTP), `K8sScaleExecutor` (kube-rs), `MockScaleExecutor`

## Configuration

All configuration uses HCL format (`.hcl` files).

```hcl
# Entrypoints — network listeners
entrypoints "web" {
  address = "0.0.0.0:80"
}

entrypoints "websecure" {
  address = "0.0.0.0:443"
  tls {
    cert_file = "/etc/certs/cert.pem"
    key_file  = "/etc/certs/key.pem"
  }
}

entrypoints "tcp-db" {
  address         = "0.0.0.0:5432"
  protocol        = "tcp"
  max_connections  = 100
  tcp_allowed_ips  = ["10.0.0.0/8"]
}

# Routers — request matching
routers "api" {
  rule        = "Host(`api.example.com`) && PathPrefix(`/v1`)"
  service     = "api-service"
  entrypoints = ["websecure"]
  middlewares  = ["auth-jwt", "rate-limit"]
}

# Services — backend pools
services "api-service" {
  load_balancer {
    strategy = "round-robin"
    servers  = [
      { url = "http://127.0.0.1:8001" },
      { url = "http://127.0.0.1:8002" }
    ]
    health_check {
      path     = "/health"
      interval = "10s"
    }
    sticky {
      cookie = "srv_id"
    }
  }

  # Traffic mirroring (optional)
  mirror {
    service    = "shadow-backend"
    percentage = 10
  }

  # Failover (optional)
  failover {
    service = "backup-pool"
  }

  # Autoscaling (optional)
  scaling {
    min_replicas          = 0
    max_replicas          = 10
    container_concurrency = 50
    target_utilization    = 0.7
    buffer_enabled        = true
    executor              = "box"
  }

  # Revision traffic splitting (optional)
  revisions = [
    { name = "v1", traffic_percent = 90, strategy = "round-robin",
      servers = [{ url = "http://127.0.0.1:8001" }] },
    { name = "v2", traffic_percent = 10, strategy = "round-robin",
      servers = [{ url = "http://127.0.0.1:8003" }] }
  ]

  # Gradual rollout (optional)
  rollout {
    from                 = "v1"
    to                   = "v2"
    step_percent         = 10
    step_interval_secs   = 60
    error_rate_threshold = 0.05
    latency_threshold_ms = 5000
  }
}

# Middlewares
middlewares "auth-jwt" {
  type  = "jwt"
  value = "${JWT_SECRET}"
}

middlewares "rate-limit" {
  type  = "rate-limit"
  rate  = 100
  burst = 50
}

# Providers
providers {
  file {
    watch     = true
    directory = "/etc/gateway/conf.d/"
  }
  discovery {
    poll_interval_secs = 30
    seeds = [
      { url = "http://10.0.0.5:8080" },
      { url = "http://10.0.0.6:8080" }
    ]
  }
}
```

### Service Discovery Contract

Backends expose `/.well-known/a3s-service.json` (RFC 8615) for automatic registration:

```json
{
  "name": "auth-service",
  "version": "1.2.0",
  "routes": [
    { "rule": "PathPrefix(`/auth`)", "middlewares": ["rate-limit"] }
  ],
  "health_path": "/health",
  "weight": 1
}
```

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              A3S Gateway                     │
                    │                                             │
  Client ──────────┤  Entrypoint (HTTP/HTTPS/TCP/UDP)            │
  (HTTP/WS/gRPC)   │      │                                     │
                    │      ▼                                     │
                    │  TLS Termination (rustls + ACME)           │
                    │      │                                     │
                    │      ▼                                     │
                    │  Router ──── Rule Matching                 │
                    │      │       (host, path, headers, SNI)    │
                    │      ▼                                     │
                    │  Middleware Pipeline (15 built-in)          │
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
| `Middleware` | Composable request/response pipeline (15 types) |
| `Service` | Backend pool with LB, health checks, mirroring, failover |
| `Provider` | Dynamic config sources (file, DNS, discovery, K8s) |
| `Proxy` | Request forwarding (HTTP, WebSocket, gRPC, TCP, UDP, SSE) |
| `Scaling` | Knative-style autoscaler with revision traffic splitting |

## Deployment

### Helm (Kubernetes)

```bash
# Install
helm install gateway deploy/helm/a3s-gateway

# Custom config
helm install gateway deploy/helm/a3s-gateway \
  --set-file config=my-gateway.hcl \
  --set service.type=LoadBalancer

# With autoscaling
helm install gateway deploy/helm/a3s-gateway \
  --set autoscaling.enabled=true \
  --set autoscaling.maxReplicas=10

# With ingress
helm install gateway deploy/helm/a3s-gateway \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=api.example.com
```

### Docker

```bash
docker run -v $(pwd)/gateway.hcl:/etc/a3s-gateway/gateway.hcl \
  -p 8080:8080 ghcr.io/a3s-lab/gateway:latest
```

## API Reference

### Gateway

| Method | Description |
|--------|-------------|
| `Gateway::new(config)` | Create from configuration |
| `start()` | Start listening and proxying |
| `shutdown()` | Graceful shutdown |
| `reload(new_config)` | Hot reload without downtime |
| `health()` | Health status snapshot |
| `metrics()` | Metrics collector |
| `config()` | Current configuration |
| `state()` | Runtime state |

### Dashboard API

| Endpoint | Description |
|----------|-------------|
| `GET /api/gateway/health` | Health status (JSON) |
| `GET /api/gateway/metrics` | Prometheus metrics (text) |
| `GET /api/gateway/config` | Current configuration (JSON) |

## Development

```bash
cargo build -p a3s-gateway
cargo test -p a3s-gateway                  # 872 tests
cargo build -p a3s-gateway --all-features  # includes Redis + K8s
cargo clippy -p a3s-gateway
```

### Project Structure

```
src/
├── lib.rs, main.rs          # Public API + CLI
├── gateway.rs               # Orchestrator
├── dashboard.rs             # Dashboard API types
├── entrypoint.rs            # HTTP/HTTPS/TCP/UDP listeners
├── error.rs                 # GatewayError and Result
│
├── config/                  # Configuration model (HCL)
│   ├── entrypoint.rs, router.rs, service.rs
│   ├── scaling.rs, middleware.rs
│
├── router/                  # Rule matching
│   ├── rule.rs              # Host/Path/Header/Method engine
│   └── tcp.rs               # TCP SNI router
│
├── middleware/              # 15 built-in middlewares
│   ├── auth.rs, jwt_auth.rs, forward_auth.rs
│   ├── rate_limit.rs, rate_limit_redis.rs
│   ├── cors.rs, headers.rs, strip_prefix.rs
│   ├── body_limit.rs, retry.rs, circuit_breaker.rs
│   ├── ip_allow.rs, ip_matcher.rs, tcp_filter.rs
│   └── compress.rs
│
├── service/                 # Backend management
│   ├── load_balancer.rs, health_check.rs, passive_health.rs
│   ├── sticky.rs, mirror.rs, failover.rs
│
├── proxy/                   # Request forwarding
│   ├── http_proxy.rs, websocket.rs, streaming.rs
│   ├── grpc.rs, tcp.rs, udp.rs, tls.rs
│   ├── acme.rs, acme_client.rs, acme_manager.rs, acme_dns.rs
│   └── ws_mux.rs
│
├── observability/
│   ├── metrics.rs, access_log.rs, tracing.rs
│
├── scaling/                 # Knative-style autoscaling
│   ├── executor.rs, autoscaler.rs, buffer.rs
│   ├── concurrency.rs, revision.rs, rollout.rs
│
└── provider/                # Config providers
    ├── file_watcher.rs, dns.rs, discovery.rs
    ├── kubernetes.rs, kubernetes_crd.rs  (feature `kube`)

deploy/
└── helm/a3s-gateway/        # Helm chart for Kubernetes
```

## Community

Join us on [Discord](https://discord.gg/XVg6Hu6H) for questions, discussions, and updates.

## License

MIT
