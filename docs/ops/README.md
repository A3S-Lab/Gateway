# Gateway operations evidence

Operator-facing evidence for Production Candidate → Enterprise GA promotion.
These documents do **not** claim Enterprise GA by themselves; they close the
repeatable fault-injection + runbook gate while capacity envelopes, an
independent security review, long soak, and a production adoption case study
remain open (see [`ROADMAP.md`](../../ROADMAP.md)).

| Document | Purpose |
| --- | --- |
| [`enterprise-ga-checklist.md`](enterprise-ga-checklist.md) | Gate-by-gate status toward Enterprise GA |
| [`../../scripts/check-enterprise-ga-status.py`](../../scripts/check-enterprise-ga-status.py) | Fail-closed status verifier (no false promotion) |
| [`fault-injection.md`](fault-injection.md) | Failure-class matrix, curated automated suite, how to run it |
| [`runbooks/`](runbooks/) | Detect → contain → recover → verify for each failure class |
| [`capacity-and-soak.md`](capacity-and-soak.md) | Capacity envelope contract + soak harness (smoke ≠ published) |
| [`capacity-envelope-draft.md`](capacity-envelope-draft.md) | Lab draft table shape (not published envelopes) |
| [`dedicated-hardware-envelopes.md`](dedicated-hardware-envelopes.md) | Fail-closed path to published envelopes |
| [`lab-drill-adoption.md`](lab-drill-adoption.md) | Lab operator drill (not production adoption) |
| [`production-adoption-template.md`](production-adoption-template.md) | Template for the required production case study |
| [`security-review-package.md`](security-review-package.md) | Briefing pack for independent security review |
| [`security-review-findings.md`](security-review-findings.md) | Unsigned findings placeholder (`review_status=unsigned`) |
| [`production-adoption-template.md`](production-adoption-template.md) | Template (`adoption_status=template`) |
| [`../../.cargo/audit.toml`](../../.cargo/audit.toml) | Shared `cargo audit` policy (no advisories ignored after kube 2.0) |
| [`../threat-model.md`](../threat-model.md) | Asset/threat/control model (review still external) |

## Node API signals

Use the management Node API (when configured) during recovery:

| Path | Role |
| --- | --- |
| `GET /health` | Process liveness / Gateway identity |
| `GET /api/gateway/version` | Build identity for skew checks |
| Prometheus metrics scrape (when enabled) | Error rates, upstream health, spool pressure |

Exact bind address and auth are ACL/`management` config; never expose the Node
API on an untrusted network without bearer or mTLS controls.
