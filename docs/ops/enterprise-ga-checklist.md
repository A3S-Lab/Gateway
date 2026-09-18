# Enterprise GA checklist

Authoritative promotion gates from [`ROADMAP.md`](../../ROADMAP.md). This
checklist tracks evidence; it does **not** promote maturity by itself.

| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks (listener, upstream, controller, disk, network) | **Landed** | [`fault-injection.md`](fault-injection.md), [`runbooks/`](runbooks/), `scripts/run-fault-injection-suite.{sh,ps1}`, `scripts/check-fault-suite-inventory.py` + `test_fault_suite_inventory.py`, `scripts/check-runbook-evidence-inventory.py` + `test_runbook_evidence_inventory.py`, Managed Runtime real OS-process evidence (`scripts/run-managed-runtime-evidence.{sh,ps1}`, `tests/managed_runtime_real_process.rs`, managed-runtime inventory + unit tests), CI job `enterprise-ga-smoke` on `ubuntu-latest` and `windows-latest` |
| Authored threat model + vulnerability reporting | **Landed (authored)** | [`../threat-model.md`](../threat-model.md) (Production Candidate; refuses Enterprise GA claim alone), [`../../SECURITY.md`](../../SECURITY.md) (private reporting), [`security-review-package.md`](security-review-package.md) |
| Capacity/soak harness | **Landed (harness)** | [`capacity-and-soak.md`](capacity-and-soak.md), [`capacity-envelope-draft.md`](capacity-envelope-draft.md), [`lab-drill-adoption.md`](lab-drill-adoption.md) (lab ≠ production adoption), `scripts/soak-gateway.py` (smoke / lab / OpenAI-shaped), `scripts/run-soak-gateway-smoke.{sh,ps1}` (pin `smoke-only`), `scripts/run-soak-gateway-extended.{sh,ps1}` (pin `lab-extended`) |
| Fail-closed path to published envelopes | **Landed (gate)** | [`dedicated-hardware-envelopes.md`](dedicated-hardware-envelopes.md) (never relabel lab/smoke; Non-goals: no CI/laptop publish, no 2h-floor cut), `run-soak-gateway-published.*` (4 profiles + dedicated pins), `test_soak_envelope_status.py` |
| Fail-closed Enterprise GA status verifier | **Landed** | `scripts/check-enterprise-ga-status.py`, `scripts/test_enterprise_ga_status.py`, CI `enterprise-ga-smoke` |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | No `published-*.json` yet; lab draft only ([`capacity-envelope-draft.md`](capacity-envelope-draft.md), status **not published**, table checked against `lab-*.json` — verifier refuses draft `Status: published` and numeric drift while this gate is Open) |
| Independent security review + remediation evidence | **Open** | Placeholder [`security-review-findings.md`](security-review-findings.md) is `review_status=unsigned`; package [`security-review-package.md`](security-review-package.md) is briefing only (not a sign-off); CI `supply-chain-audit` is continuous dependency evidence, not a review sign-off |
| Representative production adoption case study | **Open** | Template only: [`production-adoption-template.md`](production-adoption-template.md) (`adoption_status=template`). Lab drill ([`lab-drill-adoption.md`](lab-drill-adoption.md)) is **not** this gate. Complete case study must land as `production-adoption.md` |

## Promotion rule

Enterprise GA requires **every** row above to be **Landed** with linked
evidence, plus ROADMAP Product maturity updated to Enterprise GA. Authored
docs and smoke harnesses alone are insufficient.

## Local verification commands

```bash
# Fault-injection suite (always --features kube,redis,wire)
./scripts/run-fault-injection-suite.sh
# Windows: ./scripts/run-fault-injection-suite.ps1

# Suite / runbook / Managed Runtime evidence inventories (no silent drift)
python3 scripts/check-fault-suite-inventory.py
python3 scripts/check-runbook-evidence-inventory.py
python3 scripts/check-managed-runtime-evidence-inventory.py

# Managed Runtime real OS-process evidence (bind/health/drain)
./scripts/run-managed-runtime-evidence.sh
# Windows: ./scripts/run-managed-runtime-evidence.ps1

# Capacity/soak smoke (not a published envelope)
./scripts/run-soak-gateway-smoke.sh
# Windows: ./scripts/run-soak-gateway-smoke.ps1

# Published status fail-closed unit tests
python3 scripts/test_soak_envelope_status.py

# Enterprise GA status (refuses false promotion while gates are Open)
python3 scripts/check-enterprise-ga-status.py

# Supply-chain audit (requires cargo-audit; uses .cargo/audit.toml)
cargo audit --deny warnings
```
