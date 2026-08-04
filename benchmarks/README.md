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

Run the same baseline locally with:

```bash
cargo bench --locked --bench routing
cargo bench --locked --bench middleware_pipeline
cargo bench --locked --bench acl_parse
```
