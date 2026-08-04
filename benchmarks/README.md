# Performance

Criterion covers three in-process operations:

- route matching with 10, 100, and 1,000 configured routes;
- request processing through 0, 3, 5, and 10 middleware entries;
- parsing complete ACL configurations with 3, 30, and 300 services.

Each benchmark uses 100 samples, a two-second warm-up, and a five-second
measurement window. Exported JSON includes the median, 95% confidence interval,
commit, CPU, memory, kernel, and Rust compiler. These measurements exclude
sockets, TLS, upstream work, response bodies, and clients.

## Same-host NGINX comparison

The proxy comparison uses one runner, one local upstream, HTTP/1.1 keep-alive,
4 threads, 64 connections, one route, and a 42-byte response. Five alternating
15-second `wrk` trials run with observability, TLS, and middleware disabled.
The exporter records every trial, binary version, runner, median, and a
three-percent comparison threshold.

Published run [`dbf903a`](https://github.com/A3S-Lab/Gateway/actions/runs/30918700867):

| Proxy | Median throughput | P50 | P90 | P99 |
| --- | ---: | ---: | ---: | ---: |
| A3S Gateway 1.0.12 | 38,383 req/s | 1.54 ms | 2.62 ms | 3.96 ms |
| NGINX 1.24.0 | 56,399 req/s | 1.02 ms | 2.12 ms | 3.52 ms |

NGINX leads the four metrics in this workload. A3S records 68.1% of NGINX
throughput; P50 and P99 are 1.51× and 1.13× the NGINX latency. The workload
does not represent TLS, streaming, gRPC, WebSocket, AI policy, or
upstream-dominated traffic.

Run the same baseline locally with:

```bash
cargo bench --locked --bench routing
cargo bench --locked --bench middleware_pipeline
cargo bench --locked --bench acl_parse
```

On Ubuntu with `nginx` and `wrk` installed, reproduce the proxy comparison:

```bash
cargo build --locked --release
bash scripts/run-proxy-comparison.sh
```
