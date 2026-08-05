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

The A3S/NGINX ratio is a within-run comparison. Absolute values and ratios
from different workflow runs are not regression evidence when the hosted
runner CPU model changes.

Published run [`2d2020a`](https://github.com/A3S-Lab/Gateway/actions/runs/30974484063):

| Proxy | Median throughput | P50 | P90 | P99 |
| --- | ---: | ---: | ---: | ---: |
| A3S Gateway 1.0.12 | 40,887 req/s | 1.43 ms | 2.50 ms | 3.86 ms |
| NGINX 1.24.0 | 55,913 req/s | 1.03 ms | 2.17 ms | 3.60 ms |

Measured A3S/NGINX ratios are 73.1% for throughput, 1.39× for P50 latency,
and 1.07× for P99 latency. The preceding AMD EPYC 7763 A3S snapshot recorded
40,701 req/s; the 0.5% change is within the three-percent threshold. The
workload does not represent TLS, streaming, gRPC, WebSocket, AI policy, or
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
