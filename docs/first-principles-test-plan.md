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
5. **Credential-projection snapshot succession** — a later managed snapshot that
   revokes a projected key (and clears its grants) or rotates verifier+generation
   must atomically replace the prior ready identity; stale CAS / unknown
   `tokenizer_revision` successors reject while the prior runtime stays ready;
   post-succession requests with the prior bearer never contact upstream.
5b. **Grant/target succession without revoke** — a later managed snapshot may
   keep the same authenticatable credential while withdrawing grants or
   removing targets; the prior ready identity is replaced atomically; requests
   for withdrawn models never contact upstream; remaining fallback targets are
   the only dispatch surface after target-set succession.
6. **RPM / burst / concurrency** — admission returns stable errors with
   `Retry-After` where specified; permits are not leaked on cancel.
7. **`tokens_per_minute`** — reserve with `a3s.gateway.tokenizer.v1`, reconcile
   from observed OpenAI `usage` when present; never invent Cloud billing totals.
8. **Tokenizer revision ACL freeze** — managed `inference` blocks must declare
   `tokenizer_revision = "a3s.gateway.tokenizer.v1"`; missing or unknown
   revisions fail closed at parse (and again at validate for programmatic
   policy).
9. **Fallback** — weighted pick then priority fallback; zero-weight runtime
   state rejects without panic.
10. **Observed usage on spool** — when upstream JSON carries `usage.total_tokens`,
   the request-terminal lifecycle event records
   `measurement_completeness=upstream_usage` and that total without prompts or
   credentials.

Evidence: `src/inference/authorization_tests.rs`,
`src/entrypoint/inference_tests.rs`, `src/entrypoint/inference_usage_tests.rs`,
`src/entrypoint/inference_fallback_tests.rs` (target-set succession under
fallback), `src/managed_snapshot/tests.rs` (credential successor / grant
successor / CAS / tokenizer rejection), `src/inference/tokenizer.rs`,
`src/inference/token_reconcile.rs`, `src/inference/limits.rs`,
`src/config/inference/tests.rs`.

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
11. **Wrong-after tip contract** — Cloud/ledger doubles never advertise a tip
    outside the submitted batch; a fuller spool window that includes the tip
    recovers (uploader drains to the durable watermark).

Evidence: `src/usage/cloud_ingest.rs`, `src/usage/http_transport.rs`,
`src/usage/ledger_double.rs`, `src/usage/mtls_ingest_tests.rs`,
`docs/usage-cloud-ingest.md`.

Cloud has shipped `POST /v1/inference-control/usage-batches` (Postgres ledger +
node-control mTLS; migrations `192`/`193`/`194` including request-fact and
daily-rollup projection). Gateway-local evidence includes mTLS recovery against a
Cloud-shaped TLS ledger. Cross-repository live HTTPS evidence lives in Cloud's
`enrolled_node_mtls_posts_usage_batches_over_live_node_control_https`. Still
**out of Gateway EXIT** until operators prove recovery against a provisioned
Cloud deployment with a real enrolled node identity; authorized showback HTTP
over rollups remains Cloud `I0.2e`.

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
