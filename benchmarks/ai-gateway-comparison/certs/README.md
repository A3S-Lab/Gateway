# AI benchmark TLS material

`bench.crt` / `bench.key` are local self-signed fixtures copied from
`tests/fixtures/tls/revision-1.*` for TLS-termination lanes
(`transport-tls-http1`, `transport-tls-http2`).

Load clients must use `--insecure-tls`. Do not use these files for production.
