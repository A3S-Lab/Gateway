#!/usr/bin/env python3
"""Unit tests for check-enterprise-ga-status fail-closed rules."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parent / "check-enterprise-ga-status.py"
    spec = importlib.util.spec_from_file_location("check_enterprise_ga_status", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class EnterpriseGaStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = load_module()

    def test_parse_checklist_open_and_landed(self) -> None:
        text = """
| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks | **Landed** | docs |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | none |
| Independent security review + remediation evidence | **Open** | external |
| Representative production adoption case study | **Open** | template |
| Authored threat model + vulnerability reporting | **Landed (authored)** | tm |
| Capacity/soak harness | **Landed (harness)** | soak |
| Fail-closed path to published envelopes | **Landed (gate)** | gate |
| Fail-closed Enterprise GA status verifier | **Landed** | status |
"""
        statuses = self.mod.parse_checklist_statuses(text)
        self.assertEqual(statuses["fault-injection"], "Landed")
        self.assertEqual(statuses["published-envelopes"], "Open")
        self.assertEqual(statuses["security-review"], "Open")
        self.assertEqual(statuses["publish-gate"], "Landed")
        self.assertEqual(statuses["status-verifier"], "Landed")

    def test_parse_checklist_allows_status_word_in_evidence(self) -> None:
        text = """
| Gate | Status | Evidence |
| --- | --- | --- |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | refuses draft Status: published while Open |
| Independent security review + remediation evidence | **Open** | unsigned |
| Representative production adoption case study | **Open** | template |
| Repeatable fault-injection suite + operator runbooks | **Landed** | docs |
| Authored threat model + vulnerability reporting | **Landed (authored)** | tm |
| Capacity/soak harness | **Landed (harness)** | soak |
| Fail-closed path to published envelopes | **Landed (gate)** | gate |
| Fail-closed Enterprise GA status verifier | **Landed** | status |
"""
        statuses = self.mod.parse_checklist_statuses(text)
        self.assertEqual(statuses["published-envelopes"], "Open")
        self.assertEqual(statuses["security-review"], "Open")

    def test_refuses_published_json_while_gate_open(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = root / "benchmarks" / "soak" / "results"
            results.mkdir(parents=True)
            published = results / "published-http-json.json"
            published.write_text(
                json.dumps({"envelope_status": "published", "profile": "http-json"}),
                encoding="utf-8",
            )
            checklist = root / "docs" / "ops" / "enterprise-ga-checklist.md"
            checklist.parent.mkdir(parents=True)
            checklist.write_text(
                """
| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks | **Landed** | x |
| Authored threat model + vulnerability reporting | **Landed (authored)** | x |
| Capacity/soak harness | **Landed (harness)** | x |
| Fail-closed path to published envelopes | **Landed (gate)** | x |
| Fail-closed Enterprise GA status verifier | **Landed** | x |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | x |
| Independent security review + remediation evidence | **Open** | x |
| Representative production adoption case study | **Open** | x |
""",
                encoding="utf-8",
            )
            (root / "ROADMAP.md").write_text(
                "## Product maturity\n\nThe current `v1.1.1` release is a **Production Candidate**.\n",
                encoding="utf-8",
            )
            (root / ".cargo").mkdir()
            (root / ".cargo" / "audit.toml").write_text(
                '[advisories]\nignore = []\n', encoding="utf-8"
            )
            template = root / "docs" / "ops" / "production-adoption-template.md"
            template.write_text(
                "<!-- enterprise-ga: adoption_status=template -->\n"
                "This file is a **template**, not a completed case study.\n",
                encoding="utf-8",
            )
            drill = root / "docs" / "ops" / "lab-drill-adoption.md"
            drill.write_text(
                "Lab drill does **not** satisfy the production adoption gate.\n",
                encoding="utf-8",
            )
            old = {
                "ROOT": mod.ROOT,
                "CHECKLIST": mod.CHECKLIST,
                "ROADMAP": mod.ROADMAP,
                "AUDIT_TOML": mod.AUDIT_TOML,
                "SOAK_RESULTS": mod.SOAK_RESULTS,
                "ADOPTION_TEMPLATE": mod.ADOPTION_TEMPLATE,
                "LAB_DRILL": mod.LAB_DRILL,
                "LANDED_EVIDENCE": mod.LANDED_EVIDENCE,
            }
            mod.ROOT = root
            mod.CHECKLIST = checklist
            mod.ROADMAP = root / "ROADMAP.md"
            mod.AUDIT_TOML = root / ".cargo" / "audit.toml"
            mod.SOAK_RESULTS = results
            mod.ADOPTION_TEMPLATE = template
            mod.LAB_DRILL = drill
            mod.LANDED_EVIDENCE = {k: [] for k in old["LANDED_EVIDENCE"]}
            try:
                errors = mod.check_status()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(
                any("published artifact" in error for error in errors),
                errors,
            )

    def test_repo_status_is_consistent_pre_ga(self) -> None:
        errors = self.mod.check_status()
        self.assertEqual(errors, [], errors)

    def test_soak_wrapper_envelope_pins_refuse_soft_open(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            (scripts / "run-soak-gateway-smoke.sh").write_text(
                "python3 scripts/soak-gateway.py --profile http-json\n",
                encoding="utf-8",
            )
            (scripts / "run-soak-gateway-smoke.ps1").write_text(
                'Invoke-Python @("scripts/soak-gateway.py", "--envelope-status", "smoke-only")\n',
                encoding="utf-8",
            )
            (scripts / "run-soak-gateway-extended.sh").write_text(
                "--envelope-status lab-extended\n", encoding="utf-8"
            )
            (scripts / "run-soak-gateway-extended.ps1").write_text(
                "--envelope-status lab-extended\n", encoding="utf-8"
            )
            (scripts / "run-soak-gateway-published.sh").write_text(
                "A3S_GATEWAY_DEDICATED_RUNNER\n7200\n--envelope-status published\n",
                encoding="utf-8",
            )
            (scripts / "run-soak-gateway-published.ps1").write_text(
                "A3S_GATEWAY_DEDICATED_RUNNER\n7200\n--envelope-status published\n",
                encoding="utf-8",
            )
            old_root = mod.ROOT
            mod.ROOT = root
            try:
                errors = mod.check_soak_wrapper_envelope_pins()
            finally:
                mod.ROOT = old_root
            self.assertTrue(
                any(
                    "run-soak-gateway-smoke.sh" in error and "smoke-only" in error
                    for error in errors
                ),
                errors,
            )
            self.assertTrue(
                any("cargo build --locked" in error for error in errors),
                errors,
            )

    def test_soak_wrapper_refuses_dropped_profile(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scripts = root / "scripts"
            scripts.mkdir()
            profiles = "http-json sse-finite openai-json"
            for name, status in (
                ("run-soak-gateway-smoke.sh", "smoke-only"),
                ("run-soak-gateway-smoke.ps1", "smoke-only"),
                ("run-soak-gateway-extended.sh", "lab-extended"),
                ("run-soak-gateway-extended.ps1", "lab-extended"),
                ("run-soak-gateway-published.sh", "published"),
                ("run-soak-gateway-published.ps1", "published"),
            ):
                body = f"--envelope-status {status}\n{profiles}\n"
                if "published" in name:
                    body += "A3S_GATEWAY_DEDICATED_RUNNER\n7200\n"
                (scripts / name).write_text(body, encoding="utf-8")
            old_root = mod.ROOT
            mod.ROOT = root
            try:
                errors = mod.check_soak_wrapper_envelope_pins()
            finally:
                mod.ROOT = old_root
            self.assertTrue(
                any("openai-sse" in error and "missing soak profiles" in error for error in errors),
                errors,
            )

    def test_dedicated_hardware_doc_honesty(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs" / "ops"
            docs.mkdir(parents=True)
            (docs / "dedicated-hardware-envelopes.md").write_text(
                "Published envelopes docs without honesty Non-goals.\n",
                encoding="utf-8",
            )
            old_root = mod.ROOT
            mod.ROOT = root
            try:
                errors = mod.check_dedicated_hardware_doc_honesty()
            finally:
                mod.ROOT = old_root
            self.assertTrue(any("relabel" in error for error in errors), errors)
            self.assertTrue(any("2h publish floor" in error for error in errors), errors)

    def test_refuses_missing_adoption_template_marker(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checklist = root / "docs" / "ops" / "enterprise-ga-checklist.md"
            checklist.parent.mkdir(parents=True)
            checklist.write_text(
                """
| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks | **Landed** | x |
| Authored threat model + vulnerability reporting | **Landed (authored)** | x |
| Capacity/soak harness | **Landed (harness)** | x |
| Fail-closed path to published envelopes | **Landed (gate)** | x |
| Fail-closed Enterprise GA status verifier | **Landed** | x |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | x |
| Independent security review + remediation evidence | **Open** | x |
| Representative production adoption case study | **Open** | x |
""",
                encoding="utf-8",
            )
            (root / "ROADMAP.md").write_text(
                "## Product maturity\n\nThe current `v1.1.1` release is a **Production Candidate**.\n",
                encoding="utf-8",
            )
            (root / ".cargo").mkdir()
            (root / ".cargo" / "audit.toml").write_text(
                '[advisories]\nignore = []\n', encoding="utf-8"
            )
            (root / "benchmarks" / "soak" / "results").mkdir(parents=True)
            findings = root / "docs" / "ops" / "security-review-findings.md"
            findings.write_text(
                "<!-- enterprise-ga: review_status=unsigned -->\n",
                encoding="utf-8",
            )
            package = root / "docs" / "ops" / "security-review-package.md"
            package.write_text(
                "Completing this package does not close the Enterprise GA security gate.\n",
                encoding="utf-8",
            )
            threat = root / "docs" / "threat-model.md"
            threat.write_text(
                "Status: **authored for Production Candidate**. Independent security "
                "review and remediation evidence are still required for Enterprise GA.\n"
                "- Claiming Enterprise GA from this document alone.\n",
                encoding="utf-8",
            )
            security = root / "SECURITY.md"
            security.write_text(
                "## Reporting a vulnerability\n\nDo not open a public issue for "
                "undisclosed vulnerabilities.\n",
                encoding="utf-8",
            )
            template = root / "docs" / "ops" / "production-adoption-template.md"
            template.write_text(
                "This file is a **template**, not a completed case study.\n",
                encoding="utf-8",
            )
            drill = root / "docs" / "ops" / "lab-drill-adoption.md"
            drill.write_text(
                "Lab drill does **not** satisfy the production adoption gate.\n",
                encoding="utf-8",
            )
            draft = root / "docs" / "ops" / "capacity-envelope-draft.md"
            draft.write_text("**Status: not published.**\n", encoding="utf-8")
            old = {
                "ROOT": mod.ROOT,
                "CHECKLIST": mod.CHECKLIST,
                "ROADMAP": mod.ROADMAP,
                "AUDIT_TOML": mod.AUDIT_TOML,
                "SOAK_RESULTS": mod.SOAK_RESULTS,
                "ADOPTION_TEMPLATE": mod.ADOPTION_TEMPLATE,
                "ADOPTION_CASE_STUDY": mod.ADOPTION_CASE_STUDY,
                "LAB_DRILL": mod.LAB_DRILL,
                "SECURITY_FINDINGS": mod.SECURITY_FINDINGS,
                "SECURITY_PACKAGE": mod.SECURITY_PACKAGE,
                "ENVELOPE_DRAFT": mod.ENVELOPE_DRAFT,
                "THREAT_MODEL": mod.THREAT_MODEL,
                "SECURITY_MD": mod.SECURITY_MD,
                "LANDED_EVIDENCE": mod.LANDED_EVIDENCE,
            }
            mod.ROOT = root
            mod.CHECKLIST = checklist
            mod.ROADMAP = root / "ROADMAP.md"
            mod.AUDIT_TOML = root / ".cargo" / "audit.toml"
            mod.SOAK_RESULTS = root / "benchmarks" / "soak" / "results"
            mod.ADOPTION_TEMPLATE = template
            mod.ADOPTION_CASE_STUDY = root / "docs" / "ops" / "production-adoption.md"
            mod.LAB_DRILL = drill
            mod.SECURITY_FINDINGS = findings
            mod.SECURITY_PACKAGE = package
            mod.ENVELOPE_DRAFT = draft
            mod.THREAT_MODEL = threat
            mod.SECURITY_MD = security
            mod.LANDED_EVIDENCE = {k: [] for k in old["LANDED_EVIDENCE"]}
            try:
                errors = mod.check_status()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(
                any("adoption_status=template" in error for error in errors),
                errors,
            )

    def test_threat_model_honesty_while_review_open(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            docs = root / "docs"
            docs.mkdir()
            (docs / "threat-model.md").write_text(
                "Status: **Enterprise GA**. Soft-open threat model as review.\n",
                encoding="utf-8",
            )
            old = {"ROOT": mod.ROOT, "THREAT_MODEL": mod.THREAT_MODEL}
            mod.ROOT = root
            mod.THREAT_MODEL = docs / "threat-model.md"
            try:
                errors = mod.check_threat_model_honesty_while_review_open()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(any("Enterprise GA" in error for error in errors), errors)
            self.assertTrue(
                any("Production Candidate" in error for error in errors), errors
            )

    def test_security_md_reporting_required(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SECURITY.md").write_text("# Security\n\nNo reporting section.\n", encoding="utf-8")
            old = {"ROOT": mod.ROOT, "SECURITY_MD": mod.SECURITY_MD}
            mod.ROOT = root
            mod.SECURITY_MD = root / "SECURITY.md"
            try:
                errors = mod.check_security_md_reporting()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(
                any("Reporting a vulnerability" in error for error in errors),
                errors,
            )

    def test_lab_draft_table_must_match_committed_json(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            results = root / "results"
            results.mkdir()
            (results / "lab-http-json.json").write_text(
                json.dumps(
                    {
                        "profile": "http-json",
                        "duration_secs": 20,
                        "concurrency": 4,
                        "requests": {"ok_per_sec": 100.0},
                        "rss_kb": {"growth": 1.01},
                        "hardware": {"host": "lab-host"},
                        "pass": True,
                    }
                ),
                encoding="utf-8",
            )
            draft = (
                "| Profile | Duration | Concurrency | ok/s | RSS growth | Host | Pass | Result file |\n"
                "| `http-json` | 20s | 4 | 999.0 | 1.01× | lab-host | yes | `lab-http-json.json` |\n"
            )
            errors = mod.check_lab_draft_table_matches_json(draft, results)
            self.assertTrue(any("ok_per_sec" in error for error in errors), errors)
            omitted = (
                "| Profile |\n| `http-json` | 20s | 4 | 100.0 | 1.01× | lab-host | yes | `lab-other.json` |\n"
            )
            missing = mod.check_lab_draft_table_matches_json(omitted, results)
            self.assertTrue(
                any("missing from capacity-envelope-draft.md" in error for error in missing),
                missing,
            )

    def test_enterprise_ga_smoke_matrix_helper(self) -> None:
        good = """
  enterprise-ga-smoke:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - run: ./scripts/run-managed-runtime-evidence.sh

  supply-chain-audit:
    runs-on: ubuntu-latest
"""
        self.assertTrue(self.mod.enterprise_ga_smoke_covers_linux_and_windows(good))
        linux_only = """
  enterprise-ga-smoke:
    runs-on: ubuntu-latest
    steps: []

  supply-chain-audit:
    runs-on: ubuntu-latest
"""
        self.assertFalse(
            self.mod.enterprise_ga_smoke_covers_linux_and_windows(linux_only)
        )

    def test_supply_chain_audit_helper(self) -> None:
        good = """
  supply-chain-audit:
    runs-on: ubuntu-latest
    steps:
      - run: cargo audit --deny warnings

  other-job:
    runs-on: ubuntu-latest
"""
        self.assertTrue(self.mod.supply_chain_audit_is_wired(good))
        missing = """
  supply-chain-audit:
    runs-on: ubuntu-latest
    steps:
      - run: cargo audit

  other-job:
    runs-on: ubuntu-latest
"""
        self.assertFalse(self.mod.supply_chain_audit_is_wired(missing))
        self.assertFalse(self.mod.supply_chain_audit_is_wired("no job here"))

    def test_refuses_inventory_unit_test_ci_soft_open(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checklist = root / "docs" / "ops" / "enterprise-ga-checklist.md"
            checklist.parent.mkdir(parents=True)
            checklist.write_text(
                """
| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks | **Landed** | x |
| Authored threat model + vulnerability reporting | **Landed (authored)** | x |
| Capacity/soak harness | **Landed (harness)** | x |
| Fail-closed path to published envelopes | **Landed (gate)** | x |
| Fail-closed Enterprise GA status verifier | **Landed** | x |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | x |
| Independent security review + remediation evidence | **Open** | x |
| Representative production adoption case study | **Open** | x |
""",
                encoding="utf-8",
            )
            (root / "ROADMAP.md").write_text(
                "## Product maturity\n\nThe current `v1.1.1` release is a **Production Candidate**.\n",
                encoding="utf-8",
            )
            (root / ".cargo").mkdir()
            (root / ".cargo" / "audit.toml").write_text(
                '[advisories]\nignore = []\n', encoding="utf-8"
            )
            (root / "benchmarks" / "soak" / "results").mkdir(parents=True)
            findings = root / "docs" / "ops" / "security-review-findings.md"
            findings.write_text(
                "<!-- enterprise-ga: review_status=unsigned -->\n",
                encoding="utf-8",
            )
            template = root / "docs" / "ops" / "production-adoption-template.md"
            template.write_text(
                "<!-- enterprise-ga: adoption_status=template -->\n"
                "This file is a **template**, not a completed case study.\n",
                encoding="utf-8",
            )
            drill = root / "docs" / "ops" / "lab-drill-adoption.md"
            drill.write_text(
                "Lab drill does **not** satisfy the production adoption gate.\n",
                encoding="utf-8",
            )
            ci = root / ".github" / "workflows" / "ci.yml"
            ci.parent.mkdir(parents=True)
            # Checkers present, unit tests absent — soft-open.
            ci.write_text(
                """
  enterprise-ga-smoke:
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest]
    steps:
      - run: ./scripts/run-managed-runtime-evidence.sh
      - run: python scripts/check-fault-suite-inventory.py
      - run: python scripts/check-managed-runtime-evidence-inventory.py
      - run: python scripts/check-runbook-evidence-inventory.py
  supply-chain-audit:
    steps:
      - run: cargo audit --deny warnings
""",
                encoding="utf-8",
            )
            old = {
                "ROOT": mod.ROOT,
                "CHECKLIST": mod.CHECKLIST,
                "ROADMAP": mod.ROADMAP,
                "AUDIT_TOML": mod.AUDIT_TOML,
                "CI_WORKFLOW": mod.CI_WORKFLOW,
                "SOAK_RESULTS": mod.SOAK_RESULTS,
                "ADOPTION_TEMPLATE": mod.ADOPTION_TEMPLATE,
                "ADOPTION_CASE_STUDY": mod.ADOPTION_CASE_STUDY,
                "LAB_DRILL": mod.LAB_DRILL,
                "SECURITY_FINDINGS": mod.SECURITY_FINDINGS,
                "LANDED_EVIDENCE": mod.LANDED_EVIDENCE,
            }
            mod.ROOT = root
            mod.CHECKLIST = checklist
            mod.ROADMAP = root / "ROADMAP.md"
            mod.AUDIT_TOML = root / ".cargo" / "audit.toml"
            mod.CI_WORKFLOW = ci
            mod.SOAK_RESULTS = root / "benchmarks" / "soak" / "results"
            mod.ADOPTION_TEMPLATE = template
            mod.ADOPTION_CASE_STUDY = root / "docs" / "ops" / "production-adoption.md"
            mod.LAB_DRILL = drill
            mod.SECURITY_FINDINGS = findings
            mod.LANDED_EVIDENCE = {k: [] for k in old["LANDED_EVIDENCE"]}
            try:
                errors = mod.check_status()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(
                any("test_fault_suite_inventory.py" in error for error in errors),
                errors,
            )
            self.assertTrue(
                any("test_runbook_evidence_inventory.py" in error for error in errors),
                errors,
            )

    def test_refuses_lab_json_relabel_while_published_gate_open(self) -> None:
        bad = self.mod.check_lab_draft_while_published_open(
            Path("lab-bad.json"),
            {
                "envelope_status": "smoke-only",
                "hardware": {"dedicated_runner": True},
            },
        )
        self.assertTrue(any("lab-extended" in error for error in bad), bad)
        self.assertTrue(any("dedicated_runner=false" in error for error in bad), bad)
        good = self.mod.check_lab_draft_while_published_open(
            Path("lab-ok.json"),
            {
                "envelope_status": "lab-extended",
                "hardware": {"dedicated_runner": False},
            },
        )
        self.assertEqual(good, [])
        ignored = self.mod.check_lab_draft_while_published_open(
            Path("smoke-http-json.json"),
            {"envelope_status": "smoke-only"},
        )
        self.assertEqual(ignored, [])

    def test_refuses_smoke_json_relabel_while_published_gate_open(self) -> None:
        bad = self.mod.check_smoke_while_published_open(
            Path("smoke-http-json.json"),
            {
                "envelope_status": "lab-extended",
                "hardware": {},
            },
        )
        self.assertTrue(any("smoke-only" in error for error in bad), bad)
        self.assertTrue(any("dedicated_runner=false" in error for error in bad), bad)
        good = self.mod.check_smoke_while_published_open(
            Path("smoke-ok.json"),
            {
                "envelope_status": "smoke-only",
                "hardware": {"dedicated_runner": False},
            },
        )
        self.assertEqual(good, [])
        ignored = self.mod.check_smoke_while_published_open(
            Path("lab-http-json.json"),
            {"envelope_status": "lab-extended"},
        )
        self.assertEqual(ignored, [])

    def test_refuses_failed_committed_soak_result(self) -> None:
        bad = self.mod.check_committed_soak_result_contract(
            Path("smoke-http-json.json"),
            {
                "schema": "other",
                "profile": "http-json",
                "pass": False,
                "fail_reasons": ["high error rate"],
                "requests": {"ok": 0, "err": 3},
            },
        )
        self.assertTrue(any("schema=" in error for error in bad), bad)
        self.assertTrue(any("must pass" in error for error in bad), bad)
        self.assertTrue(any("ok_per_sec" in error for error in bad), bad)
        good = self.mod.check_committed_soak_result_contract(
            Path("lab-http-json.json"),
            {
                "schema": "a3s.gateway.soak-result.v1",
                "profile": "http-json",
                "duration_secs": 10,
                "pass": True,
                "fail_reasons": [],
                "requests": {"ok": 10, "err": 0, "ok_per_sec": 1.0},
            },
        )
        self.assertEqual(good, [])
        invented = self.mod.check_committed_soak_result_contract(
            Path("lab-sse-finite.json"),
            {
                "schema": "a3s.gateway.soak-result.v1",
                "profile": "sse-finite",
                "duration_secs": 20,
                "pass": True,
                "fail_reasons": [],
                "requests": {"ok": 100, "err": 0, "ok_per_sec": 999.0},
            },
        )
        self.assertTrue(any("invented rate" in error for error in invented), invented)

    def test_published_envelope_contract_requires_passing_2h(self) -> None:
        bad = self.mod.check_published_envelope_contract(
            Path("published-http-json.json"),
            {
                "profile": "http-json",
                "pass": False,
                "duration_secs": 30,
                "hardware": {"dedicated_runner": False, "memory_gb": None},
            },
        )
        self.assertTrue(any("published must pass" in error for error in bad), bad)
        self.assertTrue(any(">= 7200" in error for error in bad), bad)
        self.assertTrue(any("dedicated_runner must be true" in error for error in bad), bad)
        self.assertTrue(any("gateway.version" in error for error in bad), bad)
        self.assertTrue(any("git_sha" in error for error in bad), bad)
        good = self.mod.check_published_envelope_contract(
            Path("published-http-json.json"),
            {
                "profile": "http-json",
                "pass": True,
                "duration_secs": 7200,
                "hardware": {
                    "dedicated_runner": True,
                    "host": "bench-1",
                    "cpu_model": "Xeon",
                    "memory_gb": 64,
                },
                "gateway": {
                    "version": "a3s-gateway 1.1.1",
                    "git_sha": "a" * 40,
                },
            },
        )
        self.assertEqual(good, [])

    def test_refuses_signed_findings_while_security_review_open(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checklist = root / "docs" / "ops" / "enterprise-ga-checklist.md"
            checklist.parent.mkdir(parents=True)
            checklist.write_text(
                """
| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks | **Landed** | x |
| Authored threat model + vulnerability reporting | **Landed (authored)** | x |
| Capacity/soak harness | **Landed (harness)** | x |
| Fail-closed path to published envelopes | **Landed (gate)** | x |
| Fail-closed Enterprise GA status verifier | **Landed** | x |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | x |
| Independent security review + remediation evidence | **Open** | x |
| Representative production adoption case study | **Open** | x |
""",
                encoding="utf-8",
            )
            (root / "ROADMAP.md").write_text(
                "## Product maturity\n\nThe current `v1.1.1` release is a **Production Candidate**.\n",
                encoding="utf-8",
            )
            (root / ".cargo").mkdir()
            (root / ".cargo" / "audit.toml").write_text(
                '[advisories]\nignore = []\n', encoding="utf-8"
            )
            (root / "benchmarks" / "soak" / "results").mkdir(parents=True)
            findings = root / "docs" / "ops" / "security-review-findings.md"
            findings.write_text(
                "<!-- enterprise-ga: review_status=signed -->\n",
                encoding="utf-8",
            )
            template = root / "docs" / "ops" / "production-adoption-template.md"
            template.write_text(
                "<!-- enterprise-ga: adoption_status=template -->\n"
                "This file is a **template**, not a completed case study.\n",
                encoding="utf-8",
            )
            drill = root / "docs" / "ops" / "lab-drill-adoption.md"
            drill.write_text(
                "Lab drill does **not** satisfy the production adoption gate.\n",
                encoding="utf-8",
            )
            old = {
                "ROOT": mod.ROOT,
                "CHECKLIST": mod.CHECKLIST,
                "ROADMAP": mod.ROADMAP,
                "AUDIT_TOML": mod.AUDIT_TOML,
                "SOAK_RESULTS": mod.SOAK_RESULTS,
                "ADOPTION_TEMPLATE": mod.ADOPTION_TEMPLATE,
                "ADOPTION_CASE_STUDY": mod.ADOPTION_CASE_STUDY,
                "LAB_DRILL": mod.LAB_DRILL,
                "SECURITY_FINDINGS": mod.SECURITY_FINDINGS,
                "LANDED_EVIDENCE": mod.LANDED_EVIDENCE,
            }
            mod.ROOT = root
            mod.CHECKLIST = checklist
            mod.ROADMAP = root / "ROADMAP.md"
            mod.AUDIT_TOML = root / ".cargo" / "audit.toml"
            mod.SOAK_RESULTS = root / "benchmarks" / "soak" / "results"
            mod.ADOPTION_TEMPLATE = template
            mod.ADOPTION_CASE_STUDY = root / "docs" / "ops" / "production-adoption.md"
            mod.LAB_DRILL = drill
            mod.SECURITY_FINDINGS = findings
            mod.LANDED_EVIDENCE = {k: [] for k in old["LANDED_EVIDENCE"]}
            try:
                errors = mod.check_status()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(
                any("review_status=signed" in error for error in errors),
                errors,
            )

    def test_refuses_lab_drill_deletion_while_adoption_open(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checklist = root / "docs" / "ops" / "enterprise-ga-checklist.md"
            checklist.parent.mkdir(parents=True)
            checklist.write_text(
                """
| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks | **Landed** | x |
| Authored threat model + vulnerability reporting | **Landed (authored)** | x |
| Capacity/soak harness | **Landed (harness)** | x |
| Fail-closed path to published envelopes | **Landed (gate)** | x |
| Fail-closed Enterprise GA status verifier | **Landed** | x |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | x |
| Independent security review + remediation evidence | **Open** | x |
| Representative production adoption case study | **Open** | x |
""",
                encoding="utf-8",
            )
            (root / "ROADMAP.md").write_text(
                "## Product maturity\n\nThe current `v1.1.1` release is a **Production Candidate**.\n",
                encoding="utf-8",
            )
            (root / ".cargo").mkdir()
            (root / ".cargo" / "audit.toml").write_text(
                '[advisories]\nignore = []\n', encoding="utf-8"
            )
            (root / "benchmarks" / "soak" / "results").mkdir(parents=True)
            findings = root / "docs" / "ops" / "security-review-findings.md"
            findings.write_text(
                "<!-- enterprise-ga: review_status=unsigned -->\n",
                encoding="utf-8",
            )
            template = root / "docs" / "ops" / "production-adoption-template.md"
            template.write_text(
                "<!-- enterprise-ga: adoption_status=template -->\n"
                "This file is a **template**, not a completed case study.\n",
                encoding="utf-8",
            )
            missing_drill = root / "docs" / "ops" / "lab-drill-adoption.md"
            old = {
                "ROOT": mod.ROOT,
                "CHECKLIST": mod.CHECKLIST,
                "ROADMAP": mod.ROADMAP,
                "AUDIT_TOML": mod.AUDIT_TOML,
                "SOAK_RESULTS": mod.SOAK_RESULTS,
                "ADOPTION_TEMPLATE": mod.ADOPTION_TEMPLATE,
                "ADOPTION_CASE_STUDY": mod.ADOPTION_CASE_STUDY,
                "LAB_DRILL": mod.LAB_DRILL,
                "SECURITY_FINDINGS": mod.SECURITY_FINDINGS,
                "LANDED_EVIDENCE": mod.LANDED_EVIDENCE,
            }
            mod.ROOT = root
            mod.CHECKLIST = checklist
            mod.ROADMAP = root / "ROADMAP.md"
            mod.AUDIT_TOML = root / ".cargo" / "audit.toml"
            mod.SOAK_RESULTS = root / "benchmarks" / "soak" / "results"
            mod.ADOPTION_TEMPLATE = template
            mod.ADOPTION_CASE_STUDY = root / "docs" / "ops" / "production-adoption.md"
            mod.LAB_DRILL = missing_drill
            mod.SECURITY_FINDINGS = findings
            mod.LANDED_EVIDENCE = {k: [] for k in old["LANDED_EVIDENCE"]}
            try:
                errors = mod.check_status()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(
                any("lab-drill-adoption.md" in error for error in errors),
                errors,
            )

    def test_refuses_envelope_draft_published_claim_while_gate_open(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checklist = root / "docs" / "ops" / "enterprise-ga-checklist.md"
            checklist.parent.mkdir(parents=True)
            checklist.write_text(
                """
| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks | **Landed** | x |
| Authored threat model + vulnerability reporting | **Landed (authored)** | x |
| Capacity/soak harness | **Landed (harness)** | x |
| Fail-closed path to published envelopes | **Landed (gate)** | x |
| Fail-closed Enterprise GA status verifier | **Landed** | x |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | x |
| Independent security review + remediation evidence | **Open** | x |
| Representative production adoption case study | **Open** | x |
""",
                encoding="utf-8",
            )
            (root / "ROADMAP.md").write_text(
                "## Product maturity\n\nThe current `v1.1.1` release is a **Production Candidate**.\n",
                encoding="utf-8",
            )
            (root / ".cargo").mkdir()
            (root / ".cargo" / "audit.toml").write_text(
                '[advisories]\nignore = []\n', encoding="utf-8"
            )
            (root / "benchmarks" / "soak" / "results").mkdir(parents=True)
            findings = root / "docs" / "ops" / "security-review-findings.md"
            findings.write_text(
                "<!-- enterprise-ga: review_status=unsigned -->\n",
                encoding="utf-8",
            )
            package = root / "docs" / "ops" / "security-review-package.md"
            package.write_text(
                "Completing this package does not close the Enterprise GA security gate.\n",
                encoding="utf-8",
            )
            template = root / "docs" / "ops" / "production-adoption-template.md"
            template.write_text(
                "<!-- enterprise-ga: adoption_status=template -->\n"
                "This file is a **template**, not a completed case study.\n",
                encoding="utf-8",
            )
            drill = root / "docs" / "ops" / "lab-drill-adoption.md"
            drill.write_text(
                "Lab drill does **not** satisfy the production adoption gate.\n",
                encoding="utf-8",
            )
            draft = root / "docs" / "ops" / "capacity-envelope-draft.md"
            draft.write_text(
                "**Status: published.** Soft-open lab draft as GA capacity.\n",
                encoding="utf-8",
            )
            old = {
                "ROOT": mod.ROOT,
                "CHECKLIST": mod.CHECKLIST,
                "ROADMAP": mod.ROADMAP,
                "AUDIT_TOML": mod.AUDIT_TOML,
                "SOAK_RESULTS": mod.SOAK_RESULTS,
                "ADOPTION_TEMPLATE": mod.ADOPTION_TEMPLATE,
                "ADOPTION_CASE_STUDY": mod.ADOPTION_CASE_STUDY,
                "LAB_DRILL": mod.LAB_DRILL,
                "SECURITY_FINDINGS": mod.SECURITY_FINDINGS,
                "SECURITY_PACKAGE": mod.SECURITY_PACKAGE,
                "ENVELOPE_DRAFT": mod.ENVELOPE_DRAFT,
                "LANDED_EVIDENCE": mod.LANDED_EVIDENCE,
            }
            mod.ROOT = root
            mod.CHECKLIST = checklist
            mod.ROADMAP = root / "ROADMAP.md"
            mod.AUDIT_TOML = root / ".cargo" / "audit.toml"
            mod.SOAK_RESULTS = root / "benchmarks" / "soak" / "results"
            mod.ADOPTION_TEMPLATE = template
            mod.ADOPTION_CASE_STUDY = root / "docs" / "ops" / "production-adoption.md"
            mod.LAB_DRILL = drill
            mod.SECURITY_FINDINGS = findings
            mod.SECURITY_PACKAGE = package
            mod.ENVELOPE_DRAFT = draft
            mod.LANDED_EVIDENCE = {k: [] for k in old["LANDED_EVIDENCE"]}
            try:
                errors = mod.check_status()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(
                any("Status: published" in error for error in errors),
                errors,
            )

    def test_refuses_security_package_signoff_soft_open(self) -> None:
        mod = self.mod
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            checklist = root / "docs" / "ops" / "enterprise-ga-checklist.md"
            checklist.parent.mkdir(parents=True)
            checklist.write_text(
                """
| Gate | Status | Evidence |
| --- | --- | --- |
| Repeatable fault-injection suite + operator runbooks | **Landed** | x |
| Authored threat model + vulnerability reporting | **Landed (authored)** | x |
| Capacity/soak harness | **Landed (harness)** | x |
| Fail-closed path to published envelopes | **Landed (gate)** | x |
| Fail-closed Enterprise GA status verifier | **Landed** | x |
| Dedicated-hardware published capacity envelopes + long soak | **Open** | x |
| Independent security review + remediation evidence | **Open** | x |
| Representative production adoption case study | **Open** | x |
""",
                encoding="utf-8",
            )
            (root / "ROADMAP.md").write_text(
                "## Product maturity\n\nThe current `v1.1.1` release is a **Production Candidate**.\n",
                encoding="utf-8",
            )
            (root / ".cargo").mkdir()
            (root / ".cargo" / "audit.toml").write_text(
                '[advisories]\nignore = []\n', encoding="utf-8"
            )
            (root / "benchmarks" / "soak" / "results").mkdir(parents=True)
            findings = root / "docs" / "ops" / "security-review-findings.md"
            findings.write_text(
                "<!-- enterprise-ga: review_status=unsigned -->\n",
                encoding="utf-8",
            )
            package = root / "docs" / "ops" / "security-review-package.md"
            package.write_text(
                "Package brief only — no disclaimer that this is not a sign-off.\n",
                encoding="utf-8",
            )
            template = root / "docs" / "ops" / "production-adoption-template.md"
            template.write_text(
                "<!-- enterprise-ga: adoption_status=template -->\n"
                "This file is a **template**, not a completed case study.\n",
                encoding="utf-8",
            )
            drill = root / "docs" / "ops" / "lab-drill-adoption.md"
            drill.write_text(
                "Lab drill does **not** satisfy the production adoption gate.\n",
                encoding="utf-8",
            )
            draft = root / "docs" / "ops" / "capacity-envelope-draft.md"
            draft.write_text(
                "**Status: not published.** Lab draft only.\n",
                encoding="utf-8",
            )
            old = {
                "ROOT": mod.ROOT,
                "CHECKLIST": mod.CHECKLIST,
                "ROADMAP": mod.ROADMAP,
                "AUDIT_TOML": mod.AUDIT_TOML,
                "SOAK_RESULTS": mod.SOAK_RESULTS,
                "ADOPTION_TEMPLATE": mod.ADOPTION_TEMPLATE,
                "ADOPTION_CASE_STUDY": mod.ADOPTION_CASE_STUDY,
                "LAB_DRILL": mod.LAB_DRILL,
                "SECURITY_FINDINGS": mod.SECURITY_FINDINGS,
                "SECURITY_PACKAGE": mod.SECURITY_PACKAGE,
                "ENVELOPE_DRAFT": mod.ENVELOPE_DRAFT,
                "LANDED_EVIDENCE": mod.LANDED_EVIDENCE,
            }
            mod.ROOT = root
            mod.CHECKLIST = checklist
            mod.ROADMAP = root / "ROADMAP.md"
            mod.AUDIT_TOML = root / ".cargo" / "audit.toml"
            mod.SOAK_RESULTS = root / "benchmarks" / "soak" / "results"
            mod.ADOPTION_TEMPLATE = template
            mod.ADOPTION_CASE_STUDY = root / "docs" / "ops" / "production-adoption.md"
            mod.LAB_DRILL = drill
            mod.SECURITY_FINDINGS = findings
            mod.SECURITY_PACKAGE = package
            mod.ENVELOPE_DRAFT = draft
            mod.LANDED_EVIDENCE = {k: [] for k in old["LANDED_EVIDENCE"]}
            try:
                errors = mod.check_status()
            finally:
                for key, value in old.items():
                    setattr(mod, key, value)
            self.assertTrue(
                any("security-review-package.md" in error for error in errors),
                errors,
            )


if __name__ == "__main__":
    unittest.main()
