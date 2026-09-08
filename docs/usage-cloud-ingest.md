# Usage Cloud ingest contract (`I0.2c`)

Gateway owns a node-local usage spool. Cloud owns the long-term ledger. This
document freezes the **Gateway→Cloud** batch and highest-contiguous ACK wire
shape that production transport must implement.

Gateway types live in `src/usage/cloud_ingest.rs`. The local spool still does
not speak HTTP by itself.

## Schemas

| Direction | Schema |
| --- | --- |
| Gateway → Cloud batch | `a3s.cloud.usage-ingest-batch.v1` |
| Cloud → Gateway ACK | `a3s.cloud.usage-ingest-ack.v1` |

## Batch

```json
{
  "schema": "a3s.cloud.usage-ingest-batch.v1",
  "gateway_id": "<uuid>",
  "records": [
    {
      "boot_epoch": "<uuid>",
      "sequence": 1,
      "event_id": "<uuid>",
      "payload": [/* exact lifecycle JSON bytes */]
    }
  ]
}
```

Rules:

- Records are contiguous in spool order from the watermark after
  `acknowledged_through` (or from the oldest retained record when none).
- `payload` is the exact prompt-free lifecycle event already durable on the
  Gateway node (`a3s.gateway.usage-lifecycle.v1`). Cloud must not require
  prompt text.
- Authentication, mutual TLS, and URL path are owned by Cloud's management
  plane; this document only freezes the JSON body contract.

## Acknowledgement

```json
{
  "schema": "a3s.cloud.usage-ingest-ack.v1",
  "gateway_id": "<uuid>",
  "acknowledged_through": {
    "boot_epoch": "<uuid>",
    "sequence": 1
  }
}
```

Rules:

- `acknowledged_through` MUST identify a record present in the submitted batch.
- It MAY acknowledge a prefix of the batch (highest contiguous accepted so
  far), but MUST NOT advance past the batch tip.
- Gateway applies the ACK to the local spool only after contract validation.
  Gap cursors fail closed.

## Uploader loop

1. `read_batch(after = status.acknowledged_through, limit)`
2. Build `UsageIngestBatch` and submit through `UsageCloudTransport`
3. Validate `UsageIngestAck`
4. `acknowledge(acknowledged_through)` on the local spool

Idle when the batch is empty. Production HTTP transport and Cloud ledger
ingest remain open follow-ons under `I0.2c`.
