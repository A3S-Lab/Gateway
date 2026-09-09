# Usage Cloud ingest contract (`I0.2c`)

Gateway owns a node-local usage spool. Cloud owns the long-term ledger. This
document freezes the **Gateway→Cloud** batch and receipt wire shape that
production transport must implement.

Wire schemas are shared with A3S Cloud contracts
(`apps/cloud/crates/contracts/src/inference/usage.rs`):

| Direction | Schema |
| --- | --- |
| Gateway → Cloud batch | `a3s.gateway.usage-batch.v1` |
| Cloud → Gateway receipt | `a3s.gateway.usage-batch-receipt.v1` |

Gateway types live in `src/usage/cloud_ingest.rs`. The local spool still does
not speak HTTP by itself.

## Batch

```json
{
  "schema": "a3s.gateway.usage-batch.v1",
  "gateway_id": "<uuid>",
  "batch_id": "<uuid>",
  "after": { "boot_epoch": "<uuid>", "sequence": 1 },
  "records": [
    {
      "cursor": { "boot_epoch": "<uuid>", "sequence": 2 },
      "event_id": "<uuid>",
      "payload_base64": "<standard-base64>",
      "payload_sha256": "<64-lowercase-hex>"
    }
  ]
}
```

Rules:

- Records are contiguous in spool order from the watermark after
  `acknowledged_through` (or from the oldest retained record when none).
- Within one `boot_epoch`, sequences must be contiguous, and when `after` is
  set for that epoch the first record must be `after.sequence + 1`.
- `after` is the local watermark used to build the batch (omitted when none).
- `payload_base64` is the exact prompt-free lifecycle event already durable on
  the Gateway node (`a3s.gateway.usage-lifecycle.v1`). Cloud must not require
  prompt text.
- `payload_sha256` is the lowercase hex SHA-256 of the decoded payload bytes.
- Authentication, mutual TLS, and URL path are owned by Cloud's management
  plane; this document only freezes the JSON body contract.

## Receipt

```json
{
  "schema": "a3s.gateway.usage-batch-receipt.v1",
  "gateway_id": "<uuid>",
  "batch_id": "<uuid>",
  "acknowledged_through": {
    "boot_epoch": "<uuid>",
    "sequence": 2
  },
  "gaps": []
}
```

Rules:

- `gateway_id` and `batch_id` MUST match the submitted batch.
- `acknowledged_through`, when present, MUST be either the batch `after`
  cursor or a record cursor present in the submitted batch.
- It MAY acknowledge a prefix of the batch (highest contiguous accepted so
  far), but MUST NOT advance past the batch tip.
- Gateway applies a watermark only when `acknowledged_through` advances past
  the prior local watermark. A missing acknowledgement cursor does not move
  the spool.
- A receipt must not acknowledge a cursor listed in `gaps`.

## Uploader loop

1. `read_batch(after = status.acknowledged_through, limit)`
2. Build `UsageIngestBatch` (`batch_id`, optional `after`, integrity fields)
   and submit through `UsageCloudTransport`
3. Validate `UsageIngestAck` against the exact batch
4. `acknowledge(acknowledged_through)` on the local spool when advanced

Idle when the batch is empty.

Bootstrap pairing (ACL):

```acl
managed {
  gateway_id = "..."
  usage_spool {
    directory = "/var/lib/a3s-gateway/usage"
    cloud_ingest_endpoint = "https://cloud.example/v1/usage/batches"
    cloud_ingest_token_env = "A3S_USAGE_INGEST_TOKEN"
  }
}
```

When both ingest fields are set, Gateway starts `HttpUsageCloudTransport` and the
uploader loop at process start. Gateway-local prefix ACK, transport failure
retry, duplicate ACK idempotency, integrity fail-closed checks, and
process-restart resume are covered by unit tests in `src/usage/cloud_ingest.rs`.
Cloud ledger ingestion and live endpoint recovery evidence remain open under
`I0.2c`.
