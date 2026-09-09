# First-principles Gateway test plan

This plan lists **invariants** Gateway must prove locally. Tests exist to
falsify the invariant, not to mirror a particular Cloud fixture or CI job.
Do not add assertions that encode incidental timings, hostnames, or Cloud
ledger shapes unless those are frozen contracts in-repo.

## Product boundary

| Must hold | Must never hold |
| --- | --- |
| Fail closed on invalid/expired/revoked policy | Soft-open on parse errors |
| Atomic snapshot activation with prior runtime retained | Partial apply of a managed snapshot |
| Prompt-free usage lifecycle bytes only | Prompt text in spool or ingest |
| Gateway owns request routing and local admission | Gateway owns Cloud placement/replicas |
| Provisional tokenizer is revisioned and deterministic | Tokenizer pretends to be billing-grade |

## `I0.2b` — inference authorization

1. **Authenticate before body spend** — missing/malformed/wrong credentials fail
   without upstream contact.
2. **Grant surface** — ungranted endpoint/model pairs deny; `/v1/models` lists
   only granted models.
3. **Policy expiry** — expired at request start and after body collection both
   fail closed.
4. **Credential/revocation expiry** — revoked or expired credentials fail closed
   on the request path without contacting upstream.
5. **RPM / burst / concurrency** — admission returns stable errors with
   `Retry-After` where specified; permits are not leaked on cancel.
6. **`tokens_per_minute`** — reserve with `a3s.gateway.tokenizer.v1`, reconcile
   from observed OpenAI `usage` when present; never invent Cloud billing totals.
7. **Fallback** — weighted pick then priority fallback; zero-weight runtime
   state rejects without panic.

Evidence: `src/inference/authorization_tests.rs`,
`src/entrypoint/inference_tests.rs`, `src/inference/tokenizer.rs`,
`src/inference/token_reconcile.rs`, `src/inference/limits.rs`.

## `I0.2c` — usage delivery (Gateway-local)

1. **Batch schema freeze** — `a3s.gateway.usage-batch.v1` /
   `a3s.gateway.usage-batch-receipt.v1` stay aligned with Cloud contracts
   (`batch_id`, nested `cursor`, `payload_base64`, `payload_sha256`).
2. **Integrity fail-closed** — tampered payload hash and receipt `batch_id`
   mismatch are rejected before any local watermark move.
3. **Contiguous spool order** — within one boot epoch, record sequences must be
   contiguous and the first record must immediately follow `after` when set;
   Cloud golden JSON for `a3s.gateway.usage-batch.v1` must decode and validate.
4. **Highest-contiguous ACK** — receipt may ACK a prefix of the submitted
   batch (or the batch `after`); never a cursor outside the batch; never a gap.
5. **Backlog drain** — after a prefix ACK, the next upload contains only the
   unacked suffix and carries `after` equal to the prior watermark.
6. **Transport failure** — failed submit does not advance the watermark; retry
   drains the same backlog.
7. **Idempotent restart** — after a full ACK, process restart uploads nothing.
8. **Crash after prefix ACK** — reopen the durable spool and finish the suffix.
9. **HTTP transport** — empty endpoint/token fail closed; non-OK status,
   malformed JSON, wrong schema, and unknown receipt fields fail closed before
   spool acknowledge.
10. **Empty receipt** — missing `acknowledged_through` advances nothing.

Evidence: `src/usage/cloud_ingest.rs`, `src/usage/http_transport.rs`,
`docs/usage-cloud-ingest.md`.

Still **out of Gateway scope** until Cloud ships a ledger endpoint: live
ingest into the Cloud ledger and cross-product recovery against that endpoint.
Recommended Cloud path (planned): `POST /v1/inference-control/usage-batches`.

## `I0.3` — distributed inference (Gateway-local)

1. **Aggregated worker dispatch** — schedule only from exact Cloud target
   generations and age-bounded Power observations; never invent placement.
2. **P/D pair orchestration** — select distinct compatible prefill/decode
   workers; bind attempt/epoch/profile; relay opaque handles only.
3. **Pre-response fallback** — retryable pre-response failure excludes the
   pair; started streams are never replayed.
4. **Rolling snapshot** — in-flight work can drain on a profile-less snapshot
   while new requests move atomically to a profile-bound P/D snapshot.
5. **Reject-and-fallback** — unsupported schema, stale epoch, and profile
   rollover exclude the exact pair before client response.

Evidence: `src/inference/scheduling*.rs`,
`src/inference/distributed_serving/`, `src/entrypoint/protocol/distributed_handler.rs`,
`docs/distributed-inference-routing.md`.

Still **out of Gateway scope**: Cloud publication, multi-replica cross-product
evidence, real engine state-transfer, and autoscaling (Gateway never changes
desired replicas).

## Data plane (regression bar)

Keep protocol, reload, drain, and managed-snapshot suites green locally
(`cargo test --lib` and focused `tests/*.rs` when touching those paths). Prefer
real listeners and fail-closed config checks over mocks that cannot reject.

## Explicit non-goals (reject overfit)

- Tuning assertions to current MicroVM latency noise.
- Special-casing emoji/billing tokenizers beyond the frozen v1 rules.
- Claiming `VIA_BOX` / Cloud EXIT / LOOP from Gateway unit tests.
- Using CI status as proof of an invariant (run the local command that owns it).
