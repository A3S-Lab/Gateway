# Performance baselines

Gateway publishes Criterion microbenchmarks for three in-process operations:

- route matching with 10, 100, and 1,000 configured routes;
- request processing through 0, 3, 5, and 10 middleware entries;
- parsing complete ACL configurations with 3, 30, and 300 services.

The checked-in benchmark definitions use 100 samples, a two-second warm-up,
and a five-second measurement window. The `Performance Baseline` workflow runs
them on an identified GitHub-hosted runner, exports the median and 95% confidence
interval, and records the commit, CPU, memory, kernel, and Rust compiler.

These are regression-oriented microbenchmarks. They exclude sockets, TLS,
upstream latency, response bodies, and client overhead, so they are not
end-to-end requests-per-second claims and must not be used to rank Gateway
against another proxy. Cross-product results require the same host, upstream,
connection reuse, payload, protocol, and timeout model.

## Same-host NGINX comparison

The performance workflow also runs a narrow end-to-end reverse-proxy
comparison. It builds the checked-in Gateway release profile, installs the
Ubuntu-packaged NGINX and `wrk`, and sends the same HTTP/1.1 keep-alive workload
through each proxy to one shared local NGINX upstream. Access logs, TLS, and
middleware are disabled. Five 15-second trials alternate product order; the
exporter reports the median throughput and P50/P90/P99 latency.

The generated `website/assets/performance-comparison.json` records every raw
trial, binary versions, runner identity, aggregation, a three-percent verdict
threshold, and limitations. This answers whether Gateway is better or worse
for that exact small-response proxy workload. It does not rank TLS, streaming,
gRPC, WebSocket, AI policy, or upstream-dominated traffic.

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
