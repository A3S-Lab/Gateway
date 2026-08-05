# Performance

The repository publishes two complementary datasets:

- Criterion measurements for route matching, middleware execution, and ACL
  parsing without socket or upstream work.
- A same-host A3S Gateway and NGINX matrix covering every traffic type
  implemented by the Gateway data plane.

## Criterion

Criterion covers:

- route matching with 10, 100, and 1,000 configured routes;
- request processing through 0, 3, 5, and 10 middleware entries;
- parsing complete ACL configurations with 3, 30, and 300 services.

Each benchmark uses 100 samples, a two-second warm-up, and a five-second
measurement window. Exported JSON includes the median, 95% confidence interval,
commit, CPU, memory, kernel, and Rust compiler. These measurements exclude
sockets, TLS, upstream work, response bodies, and clients.

## Same-host protocol matrix

The matrix runs A3S Gateway and NGINX on one Ubuntu 24.04 GitHub-hosted runner.
Both products use the same certificate and the same local upstream for each
profile. Observability and access logs are disabled. Product order alternates
on every trial to reduce fixed order bias.

| Profile | Workload | Concurrency | Reported operation |
| --- | --- | ---: | --- |
| HTTP/1.1 | GET, keep-alive, 42-byte JSON | 64 connections | completed request |
| HTTPS · HTTP/1.1 | GET, downstream TLS termination | 64 connections | completed request |
| HTTPS · HTTP/2 | GET over multiplexed TLS | 4 × 16 streams | completed request |
| gRPC unary | Empty message, HTTP/2 TLS to proxy, h2c upstream | 4 × 16 streams | completed RPC |
| SSE | Finite three-event HTTP/1.1 response | 64 connections | completed stream |
| WebSocket | Persistent 32-byte binary echo | 64 connections | echoed message |
| TCP | Persistent 32-byte echo | 64 connections | round trip |
| UDP | 32-byte datagram echo | 64 connected sockets | round trip |
| OpenAI JSON | Chat Completions body validation and forwarding | 64 connections | completed request |
| OpenAI stream | JSON `stream: true` detection and finite SSE | 64 connections | completed stream |

Each row uses three 10-second measured trials after a two-second warm-up. The
exporter records every trial and reports the median of requests, streams,
messages, or round trips per second plus average, P50, P90, and P99 end-to-end
latency. Values within three percent are marked within threshold; other
positions state which measured throughput is higher or which latency is lower.

HTTP-family traffic uses the checksum-pinned `oha` 1.15.0 release. The
repository-owned `protocol_benchmark_load` example measures WebSocket, TCP,
and UDP so these protocols are not represented as HTTP requests.

### Capability alignment

HTTP, HTTPS, HTTP/2, gRPC, SSE, WebSocket, TCP, and UDP use comparable
forwarding capabilities in both products. The two OpenAI profiles deliberately
measure a different question: A3S Gateway recognizes and validates the OpenAI
request shape and selects streaming behavior, while NGINX performs
transport-only forwarding. Those rows quantify the cost of enabled A3S
features and are not an equivalent policy-capability comparison.

The result remains a synthetic same-host measurement on shared infrastructure.
It is useful for within-run product ratios and regressions on comparable runner
hardware, not as a universal ranking or a production capacity forecast.

## Reproduce

Run the in-process baselines:

```bash
cargo bench --locked --bench routing
cargo bench --locked --bench middleware_pipeline
cargo bench --locked --bench acl_parse
```

On Ubuntu, install NGINX with its stream module, OpenSSL, and `oha` 1.15.0,
then build the shipped release profile and benchmark fixtures:

```bash
cargo build --locked --release \
  --bin a3s-gateway \
  --example protocol_benchmark_upstream \
  --example protocol_benchmark_load
bash scripts/run-proxy-comparison.sh
```

Environment variables can adjust the local run:

| Variable | Default |
| --- | ---: |
| `PROXY_BENCH_TRIALS` | `3` |
| `PROXY_BENCH_DURATION_SECONDS` | `10` |
| `PROXY_BENCH_WARMUP_SECONDS` | `2` |
| `PROXY_BENCH_CONNECTIONS` | `64` |
| `PROXY_BENCH_HTTP2_CONNECTIONS` | `4` |
| `PROXY_BENCH_HTTP2_PARALLEL` | `16` |

The machine-readable output is
`website/assets/performance-comparison.json`.
