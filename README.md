<p align="center">
  <img src="assets/readme/hero.svg" width="100%" alt="A3S Gateway is an AI Native Traffic Layer that validates ACL or Cloud snapshots and routes model traffic locally">
</p>

<p align="center">
  <strong>AI Native Traffic Layer — protocol routing, streaming, and local policy enforcement in Rust.</strong>
</p>

<p align="center">
  <a href="https://github.com/A3S-Lab/Gateway/actions/workflows/ci.yml"><img alt="CI status" src="https://img.shields.io/github/actions/workflow/status/A3S-Lab/Gateway/ci.yml?branch=main&amp;style=flat-square&amp;label=CI"></a>
  <a href="https://github.com/A3S-Lab/Gateway/releases/latest"><img alt="Latest A3S Gateway release" src="https://img.shields.io/github/v/release/A3S-Lab/Gateway?display_name=tag&amp;sort=semver&amp;style=flat-square&amp;color=26d0ce"></a>
  <a href="https://crates.io/crates/a3s-gateway"><img alt="a3s-gateway on crates.io" src="https://img.shields.io/crates/v/a3s-gateway?style=flat-square&amp;color=5794ff"></a>
  <a href="https://www.rust-lang.org/"><img alt="Minimum supported Rust version 1.88" src="https://img.shields.io/badge/MSRV-1.88-81919b?style=flat-square"></a>
  <a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/license-MIT-f2f5f3?style=flat-square"></a>
</p>

<p align="center">
  <a href="https://a3s-lab.github.io/Gateway/">Website</a> &middot;
  <a href="https://a3s-lab.github.io/Gateway/docs/">Documentation</a> &middot;
  <a href="#quick-start">Quick start</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#performance">Performance</a> &middot;
  <a href="ROADMAP.md">Roadmap</a>
</p>

---

A3S Gateway routes HTTP, SSE, WebSocket, gRPC, TCP, and UDP traffic through
one validated runtime snapshot. It applies authentication, admission limits,
model grants, backend health, balancing, retry, and streaming bounds before
relaying traffic to an allowed healthy target.

Run from local ACL in `standalone` mode or consume complete desired
state from A3S Cloud in `cloud-managed` mode. Request decisions remain local;
A3S Cloud owns deployment, tenants, rollout, managed replicas, and the
long-term usage ledger.

<p align="center">
  <img src="website/assets/request-path-demo.gif" width="100%" alt="Animated A3S Gateway request path through route matching, policy checks, backend selection, and streaming response">
</p>

<p align="center">
  <sub><a href="website/assets/request-path-demo.svg">Static request-path diagram</a></sub>
</p>

## Quick start

Install on macOS or Linux:

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://a3s-lab.github.io/Gateway/install.sh | sh
```

Install on Windows PowerShell:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12; irm https://a3s-lab.github.io/Gateway/install.ps1 | iex
```

Cargo and Homebrew are also supported:

```bash
cargo install a3s-gateway
# or
brew install a3s-lab/tap/a3s-gateway
```

With an HTTP backend listening on `127.0.0.1:8000`, save this as
`gateway.acl`:

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

middlewares "rate-limit" {
  type  = "rate-limit"
  rate  = 60
  burst = 10
}

services "models" {
  load_balancer {
    strategy             = "least-connections"
    request_timeout      = "30s"
    stream_idle_timeout  = "5m"
    stream_total_timeout = "60m"
    servers = [{ url = "http://127.0.0.1:8000" }]

    health_check {
      path                 = "/health"
      interval             = "10s"
      timeout              = "5s"
      unhealthy_threshold = 3
      healthy_threshold   = 1
    }
  }
}
```

Validate, inspect, start, and send a request:

```bash
a3s-gateway validate --config gateway.acl
a3s-gateway config --config gateway.acl summary
a3s-gateway --config gateway.acl
curl http://127.0.0.1:8080/v1/models
```

## Features

| Area | Capability |
| --- | --- |
| Protocols | HTTP/1.1, HTTP/2, SSE, WebSocket, native gRPC over h2c, TCP, UDP, TLS termination, and certificate-verified HTTP/HTTPS upstreams |
| Routing | Host, path, method, header, and SNI rules; explicit priority; revision weights; request mirroring |
| Balancing and health | Round-robin, weighted, least-connections, random, active probes, passive recovery, sticky sessions, and failover |
| Middleware | API key, Basic Auth, JWT, forward auth, local/Redis rate limits, retry, circuit breaker, CORS, headers, prefix stripping, body limits, compression, IP allowlists, TCP filtering, and typed Rust extensions |
| Streaming lifecycle | Full-duplex relay, backpressure, first-response/idle/total bounds, pre-response fallback, disconnect accounting, and bounded drain |
| Managed OpenAI | Models, chat completions, completions, embeddings, grants, request and concurrency admission, rewriting, request identities, and health-aware targets |
| Configuration lifecycle | ACL validation, serialized listener reconciliation, atomic snapshot activation, prior-snapshot retention, and exact managed readiness |
| Observability | JSON access logs, W3C/B3 inbound trace context, W3C propagation, Prometheus metrics, service telemetry, and durable request/attempt usage records |
| Providers | File watcher, HTTP discovery, Docker labels, and optional Kubernetes Ingress/Scale integration |

AI model traffic commonly combines long-lived responses, expensive backends,
identity-bound model access, and configuration supplied by a remote control
plane. Gateway keeps these controls in the local data plane:

| Traffic requirement | Gateway mechanism |
| --- | --- |
| Long-lived responses | Separate first-response, idle-stream, and total-operation bounds |
| Uneven backend failure | Active/passive health, circuit state, failover, and pre-response retry |
| Safe policy changes | Complete validation followed by an atomic snapshot swap |
| Model-specific access | Endpoint/model grants, rewriting, RPM, burst, and concurrency admission |
| Remote desired state | Complete Cloud snapshots executed without a synchronous control-plane call |

## Middleware extensions

ACL middleware runs in listed order on requests and unwinds in reverse order
on responses. Embedded deployments can register application-specific Rust
middleware under a stable router-facing name:

```rust
use a3s_gateway::{Gateway, Middleware, MiddlewareRegistry, RequestContext, Result};
use a3s_gateway::config::GatewayConfig;
use async_trait::async_trait;
use http::{request::Parts, HeaderValue, Response};

struct TenantPolicy;

#[async_trait]
impl Middleware for TenantPolicy {
    async fn handle_request(
        &self,
        request: &mut Parts,
        _context: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        request.headers.insert(
            "x-policy-source",
            HeaderValue::from_static("tenant-policy"),
        );
        Ok(None)
    }

    fn name(&self) -> &str {
        "tenant-policy"
    }
}

fn build_gateway(config: GatewayConfig) -> Result<Gateway> {
    let mut registry = MiddlewareRegistry::new();
    registry.register("tenant-policy", TenantPolicy)?;
    Gateway::with_middlewares(config, registry)
}
```

ACL can then reference `middlewares = ["tenant-policy"]`. Registration occurs
before Gateway construction; the standalone binary does not load dynamic
libraries or Wasm plugins. See the [middleware guide](https://a3s-lab.github.io/Gateway/docs/#middleware)
for ordering, built-in configuration, and response hooks.

## Performance

The performance workflow runs Criterion microbenchmarks and five alternating
same-host HTTP proxy trials. The current published run used Ubuntu 24.04,
4 vCPUs, an AMD EPYC 7763 host CPU, HTTP/1.1 keep-alive, 64 connections, one
route, one local upstream, and a 42-byte response.

| In-process operation | Input | Median | 95% confidence interval |
| --- | ---: | ---: | ---: |
| Highest-priority route match | 1,000 routes | 157.1 ns | 157.0–157.2 ns |
| Full route scan with no match | 1,000 routes | 22.845 µs | 22.782–22.912 µs |
| Request middleware pipeline | 10 entries | 0.952 µs | 0.951–0.952 µs |
| Complete ACL parse | 300 services and routes | 4.923 ms | 4.817–5.028 ms |

| Same-host proxy | Median throughput | P50 | P90 | P99 |
| --- | ---: | ---: | ---: | ---: |
| A3S Gateway 1.0.12 | 38,383 req/s | 1.54 ms | 2.62 ms | 3.96 ms |
| NGINX 1.24.0 | 56,399 req/s | 1.02 ms | 2.12 ms | 3.52 ms |

NGINX leads the four proxy metrics in this workload. A3S records 68.1% of
NGINX throughput; P50 and P99 are 1.51× and 1.13× the NGINX latency. The test
disables observability, TLS, and middleware for both proxy paths.

[Workflow run](https://github.com/A3S-Lab/Gateway/actions/runs/30918700867) ·
[Criterion JSON](website/assets/performance-data.json) ·
[Proxy comparison JSON](website/assets/performance-comparison.json) ·
[Methodology](benchmarks/README.md)

## Architecture

<p align="center">
  <img src="assets/readme/architecture.svg" width="100%" alt="A3S Cloud distributes desired state while A3S Gateway validates a complete snapshot and serves traffic locally">
</p>

| Mode | Desired-state owner | Gateway responsibility |
| --- | --- | --- |
| `standalone` | Local ACL | Validate and execute local routing, middleware, health, provider, and optional scaling policy |
| `cloud-managed` | A3S Cloud | Validate and execute one complete identity-, revision-, digest-, and expiry-bound traffic snapshot |

Gateway exposes a machine-only Node API for health, metrics, version, managed
snapshot application, and exact snapshot status. Human operations remain in
A3S Cloud. Changing desired-state authority requires a process restart.

## Deploy or embed

Docker:

```bash
docker run --rm \
  -v "$PWD/gateway.acl:/etc/gateway/gateway.acl:ro" \
  -p 8080:8080 \
  ghcr.io/a3s-lab/gateway:latest \
  --config /etc/gateway/gateway.acl
```

Helm:

```bash
helm install gateway deploy/helm/a3s-gateway \
  --set image.repository=ghcr.io/a3s-lab/gateway \
  --set-file config=./gateway.acl
```

Rust library:

```bash
cargo add a3s-gateway
```

Optional Cargo features:

| Feature | Adds |
| --- | --- |
| `redis` | Redis-backed distributed rate limiting |
| `kube` | Kubernetes Ingress provider and Scale executor |
| `wire` | Inline LLM/MCP secret and PII inspection through `a3s-sentry` |

## Development

Rust 1.88 or newer is required.

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
bash scripts/test-install.sh
python website/scripts/check_site.py
node --check website/app.js
node --check website/docs/docs.js
```

## Documentation and license

- [Product website](https://a3s-lab.github.io/Gateway/)
- [Gateway documentation](https://a3s-lab.github.io/Gateway/docs/)
- [Release process](RELEASING.md)
- [Changelog](CHANGELOG.md)
- [Roadmap](ROADMAP.md)

Licensed under the [MIT License](LICENSE).
