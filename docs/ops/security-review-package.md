# Security review package

Package for an **independent** security review of A3S Gateway. Completing this
package does not close the Enterprise GA security gate; signed review findings
and remediation evidence do.

## Scope (in)

- Gateway binary and local data plane (listeners, routing, middleware, health,
  ACL / managed-snapshot activation, Node API, usage spool, providers)
- Threat model: [`../threat-model.md`](../threat-model.md)
- Reporting channel: [`../../SECURITY.md`](../../SECURITY.md)
- Fail-closed / recovery evidence: [`fault-injection.md`](fault-injection.md)
  and [`runbooks/`](runbooks/)

## Scope (out)

- A3S Cloud control-plane UX, long-term usage ledger
- Power `PW0` observation delivery, Box MicroVM, Cloud `WEB0.1` object authority
- Multi-replica Cloud rolling orchestration (`H0.3`/`H0.4` EXIT)

## Suggested review agenda

1. Threat model walkthrough (T1–T10) and residual-risk acceptance
2. Node API authentication / bind surface
3. Managed snapshot CAS, digest, expiry, and succession fail-closed paths
4. Usage spool integrity and permission model
5. Middleware fail-closed (forward-auth, rate-limit-redis, response phase)
6. Provider label/annotation declared-intent fail-closed
7. TLS / ACME storage and client-CA loading
8. Kubernetes Ingress/CRD watcher poisoned-client drop on rebuild failure
9. Managed Runtime Service real OS-process bind/health/drain evidence
10. Supply chain: release artifacts, installers, crate publish; CI
    `supply-chain-audit` (`cargo audit --deny warnings`,
    `.cargo/audit.toml` with empty ignore list after kube 2.0)
11. Capacity publish gate: confirm `envelope_status=published` cannot be set
    without dedicated-runner env pins (see
    [`dedicated-hardware-envelopes.md`](dedicated-hardware-envelopes.md))
12. Maturity honesty: `scripts/check-enterprise-ga-status.py` must stay green
    (refuses Enterprise GA claims while Open gates remain; requires
    `enterprise-ga-smoke` Linux+Windows matrix and managed-runtime evidence)

## Evidence index for reviewers

| Topic | Where to look |
| --- | --- |
| Threats / controls | `docs/threat-model.md` |
| Live-listener fail-closed tests | `docs/ops/fault-injection.md` matrix |
| Activation fail-closed | `docs/first-principles-test-plan.md`, `src/config/config_tests.rs`, `src/gateway/tests.rs` |
| Managed Runtime OS-process | `tests/managed_runtime_real_process.rs`, `scripts/run-managed-runtime-evidence.*` |
| Managed snapshot | `docs/cloud-managed-e0-conformance.md` (if present), `src/managed_snapshot/` |
| Usage spool | `src/usage/` |
| CI continuous smoke | `.github/workflows/ci.yml` jobs `enterprise-ga-smoke` (Linux+Windows), `supply-chain-audit` |

## Deliverables expected from the review

Record signed outcomes in [`security-review-findings.md`](security-review-findings.md)
(`review_status=signed`) — never in the package brief alone.

- Written findings with severity and affected versions
- Explicit residual-risk acceptances
- Remediation PRs linked from a release CHANGELOG entry
- Updated checklist row in [`enterprise-ga-checklist.md`](enterprise-ga-checklist.md)
