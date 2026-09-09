# Gateway → Cloud usage ingest

Gateway delivers managed inference usage events to A3S Cloud using the frozen
batch / receipt schemas owned by Cloud contracts:

- batch: `a3s.gateway.usage-batch.v1`
- receipt: `a3s.gateway.usage-batch-receipt.v1`

Recommended path: `POST /v1/inference-control/usage-batches` on the Cloud
node-control mTLS listener.

## Authentication

Prefer node-control mTLS:

```acl
managed {
  gateway_id = "..."
  usage_spool {
    directory = "/var/lib/a3s-gateway/usage"
    cloud_ingest_endpoint = "https://cloud.example/v1/inference-control/usage-batches"
    cloud_ingest_client_identity_file = "/var/lib/a3s-gateway/node-identity.pem"
    cloud_ingest_server_ca_file = "/var/lib/a3s-gateway/cloud-server-ca.pem"
  }
}
```

Bearer token ingest remains available for fixtures only and must not be paired
with the mTLS identity fields:

```acl
managed {
  gateway_id = "..."
  usage_spool {
    directory = "/var/lib/a3s-gateway/usage"
    cloud_ingest_endpoint = "https://cloud.example/v1/inference-control/usage-batches"
    cloud_ingest_token_env = "A3S_USAGE_INGEST_TOKEN"
  }
}
```

When ingest is configured, Gateway starts `HttpUsageCloudTransport` and the
uploader loop at process start. Gateway-local prefix ACK, transport failure
retry, duplicate ACK idempotency, integrity fail-closed checks, and
process-restart resume are covered by unit tests in `src/usage/cloud_ingest.rs`.

Cloud persists accepted batches in PostgreSQL behind
`IInferenceUsageRepository` (migrations `192`/`193`/`194`,
`PostgresInferenceUsageRepository`), including prompt-free lifecycle payload
bytes plus projected request facts and rebuildable daily rollups. Gateway proves mTLS upload recovery
locally in `src/usage/mtls_ingest_tests.rs` against a TLS ledger that requires
a client certificate and speaks the frozen receipt contract. Cloud also proves
enrolled-node mTLS against a live `NodeControlServer` HTTPS listener in its
control-plane tests. Operator recovery against a provisioned Cloud deployment
with an enrolled node identity remains open under `I0.2c`. Gateway's
`InMemoryUsageLedger` encodes the same contiguous ACK / wrong-after / event-id
conflict semantics for local falsification; wrong-`after` never advertises a
tip outside the submitted batch.
