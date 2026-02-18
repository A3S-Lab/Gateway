# A3S Gateway

<p align="center">
  <strong>K8s Ingress Controller — Application-Agnostic</strong>
</p>

<p align="center">
  <em>Traefik-style reverse proxy and K8s Ingress Controller for A3S OS. Routes all external traffic — TLS, load balancing, 7-platform webhook normalization, privacy-aware routing, token metering. Application-agnostic: doesn't know or care what runs behind it.</em>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#api-reference">API Reference</a> •
  <a href="#development">Development</a>
</p>

---

## Overview

**A3S Gateway** is an application-agnostic K8s Ingress Controller and reverse proxy. It combines Traefik-style proxy capabilities with optional AI-oriented extensions (multi-channel webhook normalization, privacy-aware routing, token metering). Backend services sit behind the gateway and are never exposed to the public network.

A3S Gateway **does not know or care** what runs behind it — SafeClaw, OpenClaw, a plain web server, or any other application. It routes traffic, terminates TLS, enforces middleware policies, and forwards requests to upstream backends.

**825 tests** | **67 source files** | **~20,000 lines of Rust**

### Basic Usage

```rust
use a3s_gateway::{Gateway, config::GatewayConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = GatewayConfig::from_file("gateway.toml").await?;
    let gateway = Gateway::new(config)?;
    gateway.start().await?;
    gateway.wait_for_shutdown().await;
    Ok(())
}
```

## Features

### Core Proxy (Traefik Parity)
- **Reverse Proxy**: HTTP/HTTPS reverse proxy with path-based and host-based routing
- **Dynamic Routing**: Traefik-style rule engine (`Host()`, `PathPrefix()`, `Path()`, `Headers()`, `Method()`, `&&`)
- **Load Balancing**: Round-robin, weighted, least-connections, and random strategies
- **Health Checks**: Active HTTP probes with configurable thresholds + passive error-count based removal
- **TLS Termination**: rustls-based TLS with certificate management
- **ACME/Let's Encrypt**: Automatic certificate issuance and renewal via ACME v2 protocol (HTTP-01 challenge, JWS/ES256 signing, account management, CSR generation)
- **Middleware Pipeline**: Composable middleware chain with 15 built-in middlewares
- **Hot Reload**: File-watch based configuration reload without restart (notify/inotify/kqueue)
- **Sticky Sessions**: Cookie-based backend affinity with TTL and eviction
- **Gateway Orchestrator**: High-level `Gateway` struct with start/reload/shutdown lifecycle
- **Dashboard API**: Built-in `/health`, `/metrics`, `/config` endpoints

### Protocol Support
- **HTTP/1.1 & HTTP/2**: Full protocol support
- **WebSocket**: Native WebSocket proxying with Upgrade detection
- **SSE/Streaming**: Chunked transfer streaming for LLM outputs
- **gRPC**: HTTP/2 h2c forwarding with gRPC status code handling
- **TCP**: Raw TCP proxying with bidirectional byte relay
- **UDP**: Session-based UDP datagram relay with automatic eviction
- **TCP SNI Router**: TLS ClientHello SNI extraction with `HostSNI()` matching and wildcards

### Middleware (15 built-in)
- **Auth**: API Key, BasicAuth, JWT (HS256 HMAC)
- **ForwardAuth**: Delegate authentication to external IdP (Keycloak, Auth0, Authelia, etc.)
- **Rate Limit**: Token bucket with configurable rate and burst
- **Rate Limit (Redis)**: Distributed rate limiting via Redis Lua scripts (optional `redis` feature)
- **CORS**: Cross-origin resource sharing with origin/method/header control
- **Headers**: Add/set/remove request and response headers
- **Strip Prefix**: Path prefix removal for backend routing
- **Body Limit**: Maximum request body size enforcement (413 on oversized requests)
- **Retry**: Configurable retry policy with interval
- **Circuit Breaker**: Closed/Open/HalfOpen state machine with cooldown
- **IP Allow/Block**: CIDR and single IP matching (IPv4/IPv6)
- **TCP Filter**: InFlightConn limit + IP allowlist for TCP entrypoints
- **Compress**: brotli/gzip/deflate response compression (br preferred)
- **JWT Auth**: JSON Web Token validation with claims injection

### Observability
- **Prometheus Metrics**: Request counts, status classes, bytes, connections, per-router/backend tracking
- **Structured Access Log**: JSON access log entries with request duration tracking
- **Distributed Tracing**: W3C Trace Context and B3/Zipkin propagation, span management

### Service Discovery
- **File Provider**: TOML/YAML configuration with file watching
- **DNS Provider**: Hostname resolution with caching and configurable refresh
- **Health-Based Discovery**: Poll `/.well-known/a3s-service.json` for auto-registration with health probing
- **Static**: Direct backend URL configuration

### Knative-Style Serverless Serving
- **Autoscaler Decision Engine**: Knative formula (`ceil((in_flight + queue) / (cc * util))`) with min/max clamping and scale-down cooldown
- **ScaleExecutor Trait**: Pluggable scaling backends — `BoxScaleExecutor` (HTTP), `K8sScaleExecutor` (kube-rs, feature-gated), `MockScaleExecutor` (tests)
- **Scale-from-Zero Buffering**: Bounded async request buffer holds requests during cold starts with configurable timeout and capacity
- **Per-Container Concurrency Limit**: `containerConcurrency` cap per backend with least-loaded selection
- **Revision-Based Traffic Splitting**: Weighted traffic routing across named revisions (e.g., `v1: 90%, v2: 10%`)
- **Gradual Rollout**: Automated canary progression with error rate and latency threshold rollback
- **Traffic Mirroring**: Fire-and-forget shadow traffic to a secondary service for testing (configurable percentage 0–100%)
- **Failover Service**: Automatic fallback to a secondary backend pool when primary has zero healthy backends
- **ACME DNS-01 Challenge**: DNS-based domain validation for wildcard certificates via Cloudflare API (pluggable `DnsSolver` trait)

### Kubernetes Integration
- **Kubernetes Ingress Provider**: Watch K8s `networking.k8s.io/v1/Ingress` resources → auto-generate routers and services (annotation-based middleware/entrypoint/strategy config)
- **Kubernetes IngressRoute CRD**: Custom CRD for advanced Traefik-style routing with direct rule strings, weighted backends, and middleware references

### Observability & DX
- **Per-Router/Service/Middleware Metrics**: Fine-grained Prometheus counters per router, service, middleware, plus latency and error tracking
- **Config Validation CLI**: `a3s-gateway validate --config gateway.toml` for pre-deploy config checking with summary output
- **WebSocket Multiplexing**: Named channel pub/sub over a single WebSocket connection with subscribe/unsubscribe control messages

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
         │HTTP    │  │gRPC    │  │TEE Agent │
         │Backend │  │Backend │  │(vsock)   │
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

### Configuration Model

```toml
# gateway.toml

[entrypoints.web]
address = "0.0.0.0:80"

[entrypoints.websecure]
address = "0.0.0.0:443"
[entrypoints.websecure.tls]
cert_file = "/etc/certs/cert.pem"
key_file = "/etc/certs/key.pem"

[entrypoints.tcp-db]
address = "0.0.0.0:5432"
protocol = "tcp"
max_connections = 100
tcp_allowed_ips = ["10.0.0.0/8", "192.168.1.0/24"]

[routers.api]
rule = "Host(`api.example.com`) && PathPrefix(`/v1`)"
service = "api-service"
entrypoints = ["websecure"]
middlewares = ["auth-jwt", "rate-limit"]

[services.api-service.load_balancer]
strategy = "round-robin"
[[services.api-service.load_balancer.servers]]
url = "http://127.0.0.1:8001"
[[services.api-service.load_balancer.servers]]
url = "http://127.0.0.1:8002"

[middlewares.auth-jwt]
type = "jwt"
value = "${JWT_SECRET}"

[middlewares.rate-limit]
type = "rate-limit"
rate = 100
burst = 50

[middlewares.forward-auth]
type = "forward-auth"
forward_auth_url = "http://auth.internal:9090/verify"
forward_auth_response_headers = ["X-User-Id", "X-User-Role"]

[middlewares.body-limit]
type = "body-limit"
max_body_bytes = 1048576  # 1MB

# Requires: cargo build --features redis
[middlewares.rate-limit-redis]
type = "rate-limit-redis"
rate = 200
burst = 100
redis_url = "redis://127.0.0.1:6379"

[providers.file]
watch = true
directory = "/etc/gateway/conf.d/"

# Health-based service discovery (optional)
[providers.discovery]
poll_interval_secs = 30
timeout_secs = 5

[[providers.discovery.seeds]]
url = "http://10.0.0.5:8080"

[[providers.discovery.seeds]]
url = "http://10.0.0.6:8080"

# Knative-style scaling (optional)
[services.api-service.scaling]
min_replicas = 0
max_replicas = 10
container_concurrency = 50
target_utilization = 0.7
scale_down_delay_secs = 300
buffer_enabled = true
buffer_timeout_secs = 30
buffer_size = 100
executor = "box"  # or "k8s" with --features kube

# Revision-based traffic splitting (optional)
[[services.api-service.revisions]]
name = "v1"
traffic_percent = 90
strategy = "round-robin"
[[services.api-service.revisions.servers]]
url = "http://127.0.0.1:8001"

[[services.api-service.revisions]]
name = "v2"
traffic_percent = 10
strategy = "round-robin"
[[services.api-service.revisions.servers]]
url = "http://127.0.0.1:8003"

# Gradual rollout (optional)
[services.api-service.rollout]
from = "v1"
to = "v2"
step_percent = 10
step_interval_secs = 60
error_rate_threshold = 0.05
latency_threshold_ms = 5000
```

### Service Discovery Contract

Backends can expose a JSON document at `/.well-known/a3s-service.json` (RFC 8615) for automatic registration:

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

The gateway probes each seed URL, fetches metadata, checks health, and merges discovered services into the running config. Static config always wins on name collisions — discovery only adds new entries.

## Quick Start

### CLI

```bash
# Start gateway with config file
a3s-gateway --config gateway.toml

# Start with custom listen address
a3s-gateway --listen 0.0.0.0:8080

# Start with debug logging
a3s-gateway --log-level debug
```

### Programmatic Usage

```rust
use a3s_gateway::{Gateway, config::GatewayConfig};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = GatewayConfig::from_file("gateway.toml").await?;
    let gateway = Arc::new(Gateway::new(config)?);

    gateway.start().await?;

    // Access health and metrics
    let health = gateway.health();
    println!("State: {}, Uptime: {}s", health.state, health.uptime_secs);

    // Wait for Ctrl+C
    gateway.wait_for_shutdown().await;
    Ok(())
}
```

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

### Middleware Types

| Type | Config Key | Description |
|------|-----------|-------------|
| `api-key` | `header`, `keys` | API key authentication |
| `basic-auth` | `username`, `password` | HTTP Basic authentication |
| `jwt` | `value` (secret) | JWT token validation |
| `forward-auth` | `forward_auth_url`, `forward_auth_response_headers` | Delegate auth to external service |
| `rate-limit` | `rate`, `burst` | Token bucket rate limiting |
| `rate-limit-redis` | `rate`, `burst`, `redis_url` | Distributed rate limiting (requires `redis` feature) |
| `cors` | `allowed_origins`, `allowed_methods` | CORS headers |
| `headers` | `request_headers`, `response_headers` | Header manipulation |
| `strip-prefix` | `prefixes` | Path prefix removal |
| `body-limit` | `max_body_bytes` | Max request body size (413 on exceed) |
| `retry` | `max_retries`, `retry_interval_ms` | Retry on failure |
| `ip-allow` | `allowed_ips` | IP allowlist (CIDR) |
| `compress` | — | brotli/gzip/deflate compression |

## Development

### Build Commands

```bash
# Build
cargo build -p a3s-gateway
cargo build -p a3s-gateway --release

# Test
cargo test -p a3s-gateway
cargo test -p a3s-gateway --all-features  # includes Redis + K8s tests

# Lint
cargo clippy -p a3s-gateway

# Format
cargo fmt -p a3s-gateway
```

### Project Structure

```
gateway/
├── Cargo.toml
├── README.md
├── DESIGN.md
└── src/
    ├── lib.rs              # Public API + re-exports
    ├── main.rs             # CLI binary with hot reload
    ├── error.rs            # GatewayError and Result types
    ├── gateway.rs          # Gateway orchestrator + Dashboard API
    │
    ├── config/             # TOML configuration model
    │   ├── mod.rs          # GatewayConfig
    │   ├── entrypoint.rs   # Entrypoint + TLS config
    │   ├── router.rs       # Router rules config
    │   ├── service.rs      # Service + load balancer config
    │   ├── scaling.rs      # Scaling, revision, rollout config
    │   └── middleware.rs   # Middleware config
    │
    ├── entrypoint.rs       # HTTP/HTTPS/TCP listeners
    │
    ├── router/             # Request matching
    │   ├── mod.rs          # HTTP RouterTable
    │   ├── rule.rs         # Rule engine (Host/Path/Header/Method)
    │   └── tcp.rs          # TCP SNI router (HostSNI)
    │
    ├── middleware/          # 15 built-in middlewares
    │   ├── mod.rs          # Middleware trait + Pipeline
    │   ├── auth.rs         # API Key + BasicAuth
    │   ├── jwt_auth.rs     # JWT (HS256)
    │   ├── forward_auth.rs # ForwardAuth (external IdP)
    │   ├── rate_limit.rs   # Token bucket (in-memory)
    │   ├── rate_limit_redis.rs # Token bucket (Redis, feature-gated)
    │   ├── cors.rs         # CORS
    │   ├── headers.rs      # Header manipulation
    │   ├── strip_prefix.rs # Path prefix removal
    │   ├── body_limit.rs   # Request body size limit
    │   ├── retry.rs        # Retry policy
    │   ├── circuit_breaker.rs # Circuit breaker
    │   ├── ip_allow.rs     # IP allowlist (HTTP)
    │   ├── ip_matcher.rs   # Shared IP/CIDR matching
    │   ├── tcp_filter.rs   # TCP connection filter
    │   └── compress.rs     # brotli/gzip/deflate
    │
    ├── service/            # Backend management
    │   ├── mod.rs          # ServiceRegistry
    │   ├── load_balancer.rs # LB strategies
    │   ├── health_check.rs # Active health probes
    │   ├── passive_health.rs # Error-count removal
    │   ├── sticky.rs       # Cookie-based affinity
    │   ├── mirror.rs       # Traffic mirroring (fire-and-forget shadow requests)
    │   └── failover.rs     # Failover service (automatic fallback)
    │
    ├── proxy/              # Request forwarding
    │   ├── mod.rs
    │   ├── http_proxy.rs   # HTTP reverse proxy
    │   ├── websocket.rs    # WebSocket proxy
    │   ├── streaming.rs    # SSE/streaming proxy
    │   ├── grpc.rs         # gRPC (h2c) proxy
    │   ├── tcp.rs          # TCP relay
    │   ├── udp.rs          # UDP relay
    │   ├── tls.rs          # TLS termination (rustls)
    │   ├── acme.rs         # ACME/Let's Encrypt (config, storage, challenge store)
    │   ├── acme_client.rs  # ACME v2 protocol client (JWS, account, order, CSR)
    │   ├── acme_manager.rs # ACME certificate auto-renewal manager
    │   ├── acme_dns.rs     # ACME DNS-01 challenge solver (Cloudflare API, DnsSolver trait)
    │   └── ws_mux.rs       # WebSocket multiplexing (named channel pub/sub)
    │
    ├── observability/      # Monitoring
    │   ├── mod.rs
    │   ├── metrics.rs      # Prometheus metrics
    │   ├── access_log.rs   # Structured JSON logs
    │   └── tracing.rs      # W3C/B3 trace propagation
    │
    ├── scaling/            # Knative-style serverless serving
    │   ├── mod.rs          # Module re-exports
    │   ├── executor.rs     # ScaleExecutor trait + Box/Mock/K8s impls
    │   ├── autoscaler.rs   # Periodic autoscaler decision engine
    │   ├── buffer.rs       # Scale-from-zero request buffer
    │   ├── concurrency.rs  # Per-container concurrency limiter
    │   ├── revision.rs     # Revision-based traffic splitting
    │   └── rollout.rs      # Gradual rollout controller
    │
    └── provider/           # Config providers
        ├── mod.rs
        ├── file_watcher.rs # File watch + hot reload
        ├── dns.rs          # DNS service discovery
        ├── discovery.rs    # Health-based service discovery
        ├── kubernetes.rs   # K8s Ingress provider (feature-gated `kube`)
        └── kubernetes_crd.rs # K8s IngressRoute CRD provider (feature-gated `kube`)
```

## A3S Ecosystem

A3S Gateway is an **application-agnostic Ingress Controller**. It routes external traffic to backend services — it does not know what application runs behind it.

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

> A3S Gateway is application-agnostic. It provides the same routing, TLS, and middleware capabilities regardless of what backend application receives the traffic.

| Project | Relationship |
|---------|--------------|
| **a3s-box** | VM runtime that hosts backend workloads; gateway routes traffic to services running inside a3s-box VMs |
| **a3s-common** | Shared types: gateway delegates content classification to `a3s_common::privacy::KeywordMatcher` for privacy-aware routing |
| **Any backend** | Gateway routes to any HTTP/gRPC/TCP/UDP backend — SafeClaw, web servers, APIs, etc. |

## Roadmap

### Phase 1: Core Proxy ✅
- [x] HTTP reverse proxy with path-based and host-based routing
- [x] Traefik-style rule engine (`Host()`, `PathPrefix()`, `Headers()`, `Method()`)
- [x] Round-robin, weighted, least-connections, random load balancing
- [x] Active health checks with configurable thresholds
- [x] TOML-based configuration with validation
- [x] Middleware pipeline (auth, rate-limit, CORS, headers, strip-prefix)
- [x] TLS termination (rustls)
- [x] Hot reload (notify file watcher)

### Phase 2: Protocol Support ✅
- [x] WebSocket proxying with Upgrade detection
- [x] SSE/streaming proxy for LLM outputs
- [x] gRPC proxy (HTTP/2 h2c)
- [x] TCP proxy with bidirectional relay
- [x] UDP proxy with session management (entrypoint wired to proxy layer with configurable session timeout and max sessions)
- [x] TCP SNI router with ClientHello parsing

### Phase 3: Observability & Security ✅
- [x] Prometheus metrics endpoint
- [x] Structured JSON access logging
- [x] OpenTelemetry tracing (W3C + B3)
- [x] JWT authentication middleware
- [x] IP allowlist/blocklist (CIDR)
- [x] Circuit breaker + retry middleware

### Phase 4: Production Readiness ✅
- [x] ACME/Let's Encrypt certificate management (full ACME v2 client: account registration, HTTP-01 challenge, CSR generation, certificate download, automatic renewal via `AcmeManager`)
- [x] gzip/deflate compression middleware
- [x] Passive health checks (error-count based)
- [x] DNS service discovery with caching
- [x] Gateway orchestrator with lifecycle management
- [x] Dashboard API (/health, /metrics, /config)
- [x] Sticky sessions with cookie-based affinity
- [x] Graceful shutdown

### Phase 5: Service Discovery & Integration ✅

- [x] **Health-based Service Discovery**: Poll backend `/health` and `/.well-known/a3s-service.json` endpoints for auto-registration of any backend service (config-merge + reload pattern, static config wins on collisions)
- [x] **Generic backend routing**: Backends provide `ServiceMetadata` via `/.well-known/a3s-service.json`, gateway auto-generates routers and services from route metadata

### Phase 6: Advanced Middleware ✅
- [x] **ForwardAuth middleware**: Delegate authentication to external IdP (Keycloak, Auth0, Authelia) via forward-auth pattern with configurable response header propagation
- [x] **Brotli compression**: Added brotli (preferred) alongside gzip/deflate — `br > gzip > deflate` preference order
- [x] **Distributed rate limiting (Redis)**: Optional `redis` feature flag — Lua-based atomic token bucket, fail-open on Redis unavailability
- [x] **TCP middleware**: InFlightConn limit + IP allowlist via `TcpFilter` with RAII permit guards, shared `IpMatcher` extracted from ip-allow for DRY reuse
- [x] **Request body size limit**: `body-limit` middleware — checks Content-Length (413 on exceed), injects `x-gateway-body-limit` header for chunked streaming enforcement

### Phase 7: Knative Serving — Traffic Brain ✅

Gateway acts as the "brain" of Knative-style serverless serving — it makes scaling decisions, holds requests during cold starts, and routes traffic across revisions. Box executes the actual instance lifecycle. Works in both standalone and K8s modes via pluggable `ScaleExecutor`.

- [x] **`ScaleExecutor` trait**: Pluggable execution backend for autoscaler decisions — `BoxScaleExecutor` (HTTP), `K8sScaleExecutor` (kube-rs, feature-gated `kube`), `MockScaleExecutor` (tests)
- [x] **Autoscaler decision engine**: Knative formula `ceil((in_flight + queue) / (cc * util))` with min/max clamping, scale-down cooldown, periodic tick loop
- [x] **Scale-from-zero request buffering**: Bounded async buffer with configurable timeout/capacity, `Notify`-based wake on backend ready, overflow/shutdown handling
- [x] **Per-instance concurrency limit**: `containerConcurrency` cap per backend, least-loaded selection via `select_with_capacity()`, capacity tracking
- [x] **Revision-based traffic splitting**: Weighted traffic routing across named revisions with atomic traffic percentage updates
- [x] **Gradual rollout**: Automated canary progression with error rate and P99 latency threshold rollback, `Pending → InProgress → Completed/RolledBack` state machine
- [x] **Scale-down cooldown**: Configurable `scale_down_delay_secs` stabilization window before emitting scale-down decisions
- [x] **Config extensions**: `ScalingConfig` with `min/max_replicas`, `target_utilization`, `scale_down_delay_secs`, `executor` type; validation for min≤max, 0<util≤1

### Phase 8: Traffic Management ✅
- [x] **Traffic mirroring**: Mirror a percentage of live traffic to a shadow backend for testing (fire-and-forget via `tokio::spawn`, deterministic percentage sampling)
- [x] **ACME DNS-01 challenge**: DNS-based ACME challenges for wildcard certificates (Cloudflare API, pluggable `DnsSolver` trait, integrated into `AcmeClient` with `ChallengeType::Dns01`)
- [x] **Failover service**: Automatic fallback to secondary backend pool when primary is fully unhealthy (transparent failover with recovery detection)

### Phase 9: Kubernetes Providers ✅
- [x] **Kubernetes Ingress provider**: Watch K8s Ingress resources → auto-generate routers/services (host/path rules, annotation-based middleware/entrypoint/strategy/priority, cluster-local service URLs, static config wins on collisions)
- [x] **Kubernetes IngressRoute CRD provider**: Custom `IngressRoute` CRD for advanced routing — direct Traefik-style match rules, weighted multi-backend services, middleware references, TLS secret support (ConfigMap-based discovery with `a3s-gateway.io/type=ingressroute` label)

### Phase 10: Dashboard API & DX ✅
- [x] **Per-router metrics granularity**: Fine-grained Prometheus metrics per router, service, and middleware — request counts, latency (cumulative microseconds), error counts (4xx+5xx), middleware invocation counts
- [x] **Config validation CLI**: `a3s-gateway validate --config gateway.toml` — parse, validate, and print config summary (entrypoints, routers, services, middlewares, providers)
- [x] **WebSocket multiplexing**: Named channel pub/sub hub (`WsMuxHub`) with per-connection state (`WsMuxConnection`), subscribe/unsubscribe/ping/list control messages, `channel:payload` wire format, max 64 channels per connection

## License

MIT
