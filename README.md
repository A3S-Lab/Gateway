# A3S Gateway

<p align="center">
  <strong>AI-Native API Gateway</strong>
</p>

<p align="center">
  <em>Infrastructure layer — reverse proxy, routing, and AI agent gateway for the A3S ecosystem</em>
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

**A3S Gateway** is an AI-native API gateway that combines Traefik-style reverse proxy capabilities with AI agent routing and orchestration. It serves as the networking layer for SafeClaw, handling multi-channel message routing, service discovery, load balancing, and intelligent request dispatching to AI agents running in TEE environments.

### Basic Usage

```rust
use a3s_gateway::{GatewayBuilder, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let gateway = GatewayBuilder::new()
        .with_config_file("gateway.toml")
        .build()
        .await?;

    gateway.start().await?;

    Ok(())
}
```

## Features

### Phase 1: Core Proxy (Traefik Parity)
- **Reverse Proxy**: HTTP/HTTPS reverse proxy with path-based and host-based routing
- **Dynamic Routing**: Rule-based request routing with priority and weight support
- **Load Balancing**: Round-robin, weighted, least-connections, and random strategies
- **Health Checks**: Active and passive health checking for upstream services
- **TLS Termination**: Automatic TLS with ACME/Let's Encrypt support
- **Middleware Pipeline**: Composable middleware chain (auth, rate-limit, headers, retry, circuit-breaker)
- **Service Discovery**: Static, file-based, and DNS-based service discovery
- **Hot Reload**: Configuration changes without restart

### Phase 2: Protocol Support
- **HTTP/1.1 & HTTP/2**: Full protocol support with automatic negotiation
- **WebSocket**: Native WebSocket proxying for real-time communication
- **gRPC**: gRPC proxying and load balancing
- **TCP/UDP**: Raw TCP and UDP proxying for non-HTTP protocols

### Phase 3: AI Agent Gateway
- **Agent Routing**: Intelligent routing to AI agents based on message content and context
- **Channel Adapters**: Multi-platform webhook ingestion (Telegram, Slack, Discord, Feishu, DingTalk, WeCom)
- **TEE Routing**: Privacy-aware routing to TEE environments for sensitive data
- **Streaming Support**: SSE and streaming response proxying for LLM outputs
- **Token Metering**: Track and limit token usage per agent/user/session
- **Conversation Affinity**: Sticky sessions for multi-turn conversations

### Phase 4: Observability & Security
- **Metrics**: Prometheus-compatible metrics endpoint
- **Access Logging**: Structured access logs with request/response details
- **Distributed Tracing**: OpenTelemetry trace propagation
- **Rate Limiting**: Global and per-route rate limiting with token bucket
- **Authentication**: API key, JWT, and OAuth2 authentication middleware
- **IP Allowlist/Blocklist**: IP-based access control

## Architecture

### Request Flow

```
                    ┌─────────────────────────────────────────────┐
                    │              A3S Gateway                     │
                    │                                             │
  Client ──────────┤  Entrypoint                                 │
  (HTTP/WS/gRPC)   │      │                                     │
                    │      ▼                                     │
                    │  TLS Termination                           │
                    │      │                                     │
                    │      ▼                                     │
                    │  Router ──── Rule Matching                 │
                    │      │       (host, path, headers)         │
                    │      ▼                                     │
                    │  Middleware Pipeline                       │
                    │  ┌─────┬──────┬───────┬──────────┐       │
                    │  │Auth │Rate  │Retry  │Circuit   │       │
                    │  │     │Limit │       │Breaker   │       │
                    │  └─────┴──────┴───────┴──────────┘       │
                    │      │                                     │
                    │      ▼                                     │
                    │  Load Balancer                             │
                    │  (round-robin / weighted / least-conn)     │
                    │      │                                     │
                    └──────┼─────────────────────────────────────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌────────┐  ┌────────┐  ┌──────────┐
         │Service │  │Service │  │TEE Agent │
         │  A     │  │  B     │  │(SafeClaw)│
         └────────┘  └────────┘  └──────────┘
```

### Core Components

| Component | Description |
|-----------|-------------|
| `Entrypoint` | Listener on a port (HTTP, HTTPS, TCP) |
| `Router` | Matches incoming requests to routes by rules |
| `Middleware` | Transforms requests/responses in a composable pipeline |
| `Service` | Upstream backend with load balancing and health checks |
| `Provider` | Supplies dynamic configuration (file, DNS, API) |

### Configuration Model

```toml
# gateway.toml

[entrypoints]
[entrypoints.web]
address = "0.0.0.0:80"

[entrypoints.websecure]
address = "0.0.0.0:443"
tls = true

[routers]
[routers.api]
rule = "Host(`api.example.com`) && PathPrefix(`/v1`)"
service = "api-service"
middlewares = ["auth", "rate-limit"]

[routers.agent]
rule = "PathPrefix(`/agent`)"
service = "safeclaw-agent"
middlewares = ["auth", "token-meter"]

[services]
[services.api-service]
[services.api-service.load_balancer]
strategy = "round-robin"
[[services.api-service.load_balancer.servers]]
url = "http://127.0.0.1:8001"
[[services.api-service.load_balancer.servers]]
url = "http://127.0.0.1:8002"

[middlewares]
[middlewares.auth]
type = "api-key"
header = "X-API-Key"

[middlewares.rate-limit]
type = "rate-limit"
rate = 100
burst = 50
```

## Quick Start

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
a3s-gateway = "0.1"
```

### CLI

```bash
# Start gateway with config file
a3s-gateway --config gateway.toml

# Start with default settings
a3s-gateway

# Start with custom entrypoint
a3s-gateway --entrypoint 0.0.0.0:8080
```

### Programmatic Usage

```rust
use a3s_gateway::{GatewayBuilder, RouterConfig, ServiceConfig, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let gateway = GatewayBuilder::new()
        .with_entrypoint("web", "0.0.0.0:80")
        .with_router("api", RouterConfig {
            rule: "PathPrefix(`/api`)".into(),
            service: "backend".into(),
            middlewares: vec!["rate-limit".into()],
        })
        .with_service("backend", ServiceConfig::round_robin(vec![
            "http://127.0.0.1:8001".into(),
            "http://127.0.0.1:8002".into(),
        ]))
        .build()
        .await?;

    gateway.start().await?;

    Ok(())
}
```

## API Reference

### GatewayBuilder

| Method | Description |
|--------|-------------|
| `new()` | Create a new builder |
| `with_config_file(path)` | Load configuration from TOML file |
| `with_entrypoint(name, address)` | Add a listener entrypoint |
| `with_router(name, config)` | Add a routing rule |
| `with_service(name, config)` | Add an upstream service |
| `with_middleware(name, config)` | Add a middleware |
| `build()` | Build the Gateway instance |

### Gateway

| Method | Description |
|--------|-------------|
| `start()` | Start listening and proxying |
| `shutdown()` | Graceful shutdown |
| `reload()` | Hot reload configuration |
| `health()` | Get gateway health status |
| `metrics()` | Get metrics snapshot |

## Development

### Build Commands

```bash
# Build
cargo build -p a3s-gateway
cargo build -p a3s-gateway --release

# Test
cargo test -p a3s-gateway

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
├── LICENSE
└── src/
    ├── lib.rs          # Library entry point with module docs
    ├── main.rs         # CLI binary entry point
    └── error.rs        # GatewayError and Result types
```

## A3S Ecosystem

A3S Gateway is the **networking infrastructure** of the A3S ecosystem — the entry point for all external traffic flowing into A3S services.

```
┌──────────────────────────────────────────────────────────┐
│                    A3S Ecosystem                         │
│                                                          │
│  Networking:    a3s-gateway  (API gateway & proxy)       │
│                      │          ▲                        │
│                      ▼          │ You are here           │
│  Application:   a3s-safeclaw (Privacy AI assistant)      │
│                      │                                   │
│  Infrastructure: a3s-box     (MicroVM sandbox runtime)   │
│                      │                                   │
│  AI Runtime:    a3s-code     (AI coding agent)           │
│                    /   \                                 │
│  Utilities:   a3s-lane  a3s-context                     │
│                         (memory/knowledge)               │
└──────────────────────────────────────────────────────────┘
```

| Project | Package | Relationship |
|---------|---------|--------------|
| **safeclaw** | `a3s-safeclaw` | Primary consumer — Gateway handles SafeClaw's multi-channel ingress |
| **box** | `a3s-box-*` | Gateway routes sensitive requests to TEE environments |
| **power** | `a3s-power` | Gateway can proxy to local LLM inference endpoints |
| **code** | `a3s-code` | AI agent requests are routed through Gateway |

## Roadmap

### Phase 1: Core Proxy 🚧

- [ ] HTTP reverse proxy with path-based routing
- [ ] Host-based routing rules
- [ ] Round-robin load balancing
- [ ] Active health checks
- [ ] TOML-based configuration
- [ ] Middleware pipeline (auth, rate-limit, headers)
- [ ] TLS termination
- [ ] Hot reload

### Phase 2: Protocol Support 📋

- [ ] WebSocket proxying
- [ ] gRPC proxying
- [ ] HTTP/2 support
- [ ] TCP/UDP proxying

### Phase 3: AI Agent Gateway 📋

- [ ] Multi-channel webhook ingestion (Telegram, Slack, Discord, etc.)
- [ ] Privacy-aware TEE routing for SafeClaw
- [ ] SSE/streaming response proxying for LLM outputs
- [ ] Token metering per agent/user
- [ ] Conversation affinity (sticky sessions)

### Phase 4: Observability & Security 📋

- [ ] Prometheus metrics endpoint
- [ ] Structured access logging
- [ ] OpenTelemetry tracing
- [ ] JWT/OAuth2 authentication
- [ ] IP allowlist/blocklist

## License

MIT
