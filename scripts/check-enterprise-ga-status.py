#!/usr/bin/env python3
"""Fail-closed Enterprise GA status check.

Refuses false promotion: while any checklist gate is Open, ROADMAP must not
claim Enterprise GA maturity, published soak artifacts must not claim
`envelope_status=published`, and Landed gates must keep their evidence files.
Does not invent review sign-off, published envelopes, or production adoption.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKLIST = ROOT / "docs" / "ops" / "enterprise-ga-checklist.md"
ROADMAP = ROOT / "ROADMAP.md"
AUDIT_TOML = ROOT / ".cargo" / "audit.toml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
SOAK_RESULTS = ROOT / "benchmarks" / "soak" / "results"
ADOPTION_TEMPLATE = ROOT / "docs" / "ops" / "production-adoption-template.md"
ADOPTION_CASE_STUDY = ROOT / "docs" / "ops" / "production-adoption.md"
LAB_DRILL = ROOT / "docs" / "ops" / "lab-drill-adoption.md"
SECURITY_FINDINGS = ROOT / "docs" / "ops" / "security-review-findings.md"
ENVELOPE_DRAFT = ROOT / "docs" / "ops" / "capacity-envelope-draft.md"
SECURITY_PACKAGE = ROOT / "docs" / "ops" / "security-review-package.md"
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
SECURITY_MD = ROOT / "SECURITY.md"

REVIEW_STATUS_RE = re.compile(
    r"<!--\s*enterprise-ga:\s*review_status\s*=\s*(unsigned|signed)\s*-->",
    re.I,
)
ADOPTION_STATUS_RE = re.compile(
    r"<!--\s*enterprise-ga:\s*adoption_status\s*=\s*(template|complete)\s*-->",
    re.I,
)

LANDED_EVIDENCE = {
    "fault-injection": [
        ROOT / "docs" / "ops" / "fault-injection.md",
        ROOT / "docs" / "ops" / "runbooks" / "listener-failure.md",
        ROOT / "docs" / "ops" / "runbooks" / "upstream-failure.md",
        ROOT / "docs" / "ops" / "runbooks" / "controller-failure.md",
        ROOT / "docs" / "ops" / "runbooks" / "disk-failure.md",
        ROOT / "docs" / "ops" / "runbooks" / "network-failure.md",
        ROOT / "scripts" / "run-fault-injection-suite.sh",
        ROOT / "scripts" / "run-fault-injection-suite.ps1",
        ROOT / "scripts" / "check-fault-suite-inventory.py",
        ROOT / "scripts" / "test_fault_suite_inventory.py",
        ROOT / "scripts" / "check-managed-runtime-evidence-inventory.py",
        ROOT / "scripts" / "test_managed_runtime_evidence_inventory.py",
        ROOT / "scripts" / "check-runbook-evidence-inventory.py",
        ROOT / "scripts" / "test_runbook_evidence_inventory.py",
        ROOT / "scripts" / "run-managed-runtime-evidence.sh",
        ROOT / "scripts" / "run-managed-runtime-evidence.ps1",
        ROOT / "tests" / "managed_runtime_real_process.rs",
    ],
    "threat-model": [
        ROOT / "docs" / "threat-model.md",
        ROOT / "SECURITY.md",
        ROOT / "docs" / "ops" / "security-review-package.md",
    ],
    "capacity-harness": [
        ROOT / "docs" / "ops" / "capacity-and-soak.md",
        ROOT / "docs" / "ops" / "capacity-envelope-draft.md",
        ROOT / "scripts" / "soak-gateway.py",
        ROOT / "scripts" / "run-soak-gateway-smoke.sh",
        ROOT / "scripts" / "run-soak-gateway-smoke.ps1",
        ROOT / "scripts" / "run-soak-gateway-extended.sh",
        ROOT / "scripts" / "run-soak-gateway-extended.ps1",
        ROOT / "docs" / "ops" / "lab-drill-adoption.md",
    ],
    "publish-gate": [
        ROOT / "docs" / "ops" / "dedicated-hardware-envelopes.md",
        ROOT / "scripts" / "run-soak-gateway-published.sh",
        ROOT / "scripts" / "run-soak-gateway-published.ps1",
        ROOT / "scripts" / "test_soak_envelope_status.py",
    ],
    "status-verifier": [
        ROOT / "scripts" / "check-enterprise-ga-status.py",
        ROOT / "scripts" / "test_enterprise_ga_status.py",
    ],
}


def parse_checklist_statuses(text: str) -> dict[str, str]:
    """Map abbreviated gate keys to Landed/Open from the checklist table."""
    statuses: dict[str, str] = {}
    for line in text.splitlines():
        if not line.startswith("|") or line.startswith("| ---"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2:
            continue
        gate, status = cells[0], cells[1]
        # Skip the table header only — Evidence cells may mention "Status: …".
        if gate.lower() == "gate" or status.lower() == "status":
            continue
        status_norm = "Open" if "Open" in status else ("Landed" if "Landed" in status else "")
        if not status_norm:
            continue
        key = gate.lower()
        if "fault-injection" in key:
            statuses["fault-injection"] = status_norm
        elif "threat model" in key:
            statuses["threat-model"] = status_norm
        elif "capacity/soak harness" in key:
            statuses["capacity-harness"] = status_norm
        elif "fail-closed path to published" in key:
            statuses["publish-gate"] = status_norm
        elif "enterprise ga status verifier" in key:
            statuses["status-verifier"] = status_norm
        elif "dedicated-hardware published" in key:
            statuses["published-envelopes"] = status_norm
        elif "independent security review" in key:
            statuses["security-review"] = status_norm
        elif "production adoption" in key:
            statuses["production-adoption"] = status_norm
    return statuses


def audit_ignore_ids(text: str) -> list[str]:
    match = re.search(r"ignore\s*=\s*\[(.*?)\]", text, re.S)
    if not match:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def soak_json_files() -> list[Path]:
    if not SOAK_RESULTS.is_dir():
        return []
    return sorted(SOAK_RESULTS.glob("*.json"))


def marker_status(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    return match.group(1).lower() if match else None


def enterprise_ga_smoke_covers_linux_and_windows(ci_text: str) -> bool:
    """Require the enterprise-ga-smoke job matrix to include both runners."""
    marker = "enterprise-ga-smoke:"
    idx = ci_text.find(marker)
    if idx < 0:
        return False
    # Bound the job body roughly until the next top-level job key.
    rest = ci_text[idx + len(marker) :]
    next_job = re.search(r"\n  [a-z0-9-]+:\n", rest)
    section = rest[: next_job.start()] if next_job else rest[:4000]
    return "ubuntu-latest" in section and "windows-latest" in section


def supply_chain_audit_is_wired(ci_text: str) -> bool:
    """Require the supply-chain-audit job to run cargo audit --deny warnings."""
    marker = "supply-chain-audit:"
    idx = ci_text.find(marker)
    if idx < 0:
        return False
    rest = ci_text[idx + len(marker) :]
    next_job = re.search(r"\n  [a-z0-9-]+:\n", rest)
    section = rest[: next_job.start()] if next_job else rest[:4000]
    return "cargo audit --deny warnings" in section


def check_lab_draft_while_published_open(path: Path, payload: dict) -> list[str]:
    """Refuse lab-*.json soft-opens while published-envelopes is Open."""
    errors: list[str] = []
    if not path.name.startswith("lab-"):
        return errors
    status = payload.get("envelope_status")
    if status != "lab-extended":
        errors.append(
            f"published-envelopes is Open but {path.name} has "
            f"envelope_status={status!r} (expected lab-extended)"
        )
    hardware = payload.get("hardware") or {}
    if hardware.get("dedicated_runner") is not False:
        errors.append(
            f"published-envelopes is Open but {path.name} does not "
            "declare hardware.dedicated_runner=false"
        )
    return errors


def check_smoke_while_published_open(path: Path, payload: dict) -> list[str]:
    """Refuse smoke-*.json soft-opens while published-envelopes is Open."""
    errors: list[str] = []
    if not path.name.startswith("smoke-"):
        return errors
    status = payload.get("envelope_status")
    if status != "smoke-only":
        errors.append(
            f"published-envelopes is Open but {path.name} has "
            f"envelope_status={status!r} (expected smoke-only)"
        )
    hardware = payload.get("hardware") or {}
    if hardware.get("dedicated_runner") is not False:
        errors.append(
            f"published-envelopes is Open but {path.name} does not "
            "declare hardware.dedicated_runner=false"
        )
    return errors


SOAK_RESULT_SCHEMA = "a3s.gateway.soak-result.v1"
SOAK_PROFILES = ("http-json", "sse-finite", "openai-json", "openai-sse")


def check_committed_soak_result_contract(path: Path, payload: dict) -> list[str]:
    """Refuse committed lab/smoke JSON that is not a passing harness result."""
    if not (path.name.startswith("lab-") or path.name.startswith("smoke-")):
        return []
    errors: list[str] = []
    if payload.get("schema") != SOAK_RESULT_SCHEMA:
        errors.append(
            f"{path.name} schema={payload.get('schema')!r} "
            f"(expected {SOAK_RESULT_SCHEMA})"
        )
    profile = payload.get("profile")
    if profile not in SOAK_PROFILES:
        errors.append(f"{path.name} profile={profile!r} is not a harness profile")
    elif not path.name.endswith(f"-{profile}.json"):
        errors.append(f"{path.name} filename does not match profile {profile!r}")
    if payload.get("pass") is not True:
        errors.append(
            f"{path.name} pass={payload.get('pass')!r} (committed evidence must pass)"
        )
    reasons = payload.get("fail_reasons")
    if reasons:
        errors.append(f"{path.name} has fail_reasons={reasons!r}")
    requests = payload.get("requests") or {}
    if requests.get("err") not in (0, 0.0):
        errors.append(f"{path.name} requests.err={requests.get('err')!r} (expected 0)")
    ok = requests.get("ok")
    if not isinstance(ok, int) or ok <= 0:
        errors.append(
            f"{path.name} requests.ok={ok!r} (committed evidence must record successes)"
        )
    rps = requests.get("ok_per_sec")
    if not isinstance(rps, (int, float)) or isinstance(rps, bool):
        errors.append(
            f"{path.name} missing requests.ok_per_sec "
            "(harness contract always records the rate)"
        )
    else:
        duration = payload.get("duration_secs")
        if not isinstance(duration, (int, float)) or isinstance(duration, bool) or duration <= 0:
            errors.append(
                f"{path.name} duration_secs={duration!r} "
                "(ok_per_sec must be derivable from a positive duration)"
            )
        elif isinstance(ok, int) and ok > 0:
            expected = round(ok / float(duration), 2)
            if abs(float(rps) - expected) > 0.001:
                errors.append(
                    f"{path.name} ok_per_sec={rps} != round(ok/duration, 2)={expected} "
                    "(refuse an invented rate)"
                )
    return errors


def check_published_envelope_contract(path: Path, payload: dict) -> list[str]:
    """Refuse a published artifact that is not a passing dedicated 2h envelope."""
    errors: list[str] = []
    if payload.get("pass") is not True:
        errors.append(f"{path.name} pass={payload.get('pass')!r} (published must pass)")
    hardware = payload.get("hardware") or {}
    if hardware.get("dedicated_runner") is not True:
        errors.append(f"{path.name} hardware.dedicated_runner must be true")
    duration = payload.get("duration_secs")
    if (
        not isinstance(duration, (int, float))
        or isinstance(duration, bool)
        or duration < 7200
    ):
        errors.append(
            f"{path.name} duration_secs={duration!r} (published requires >= 7200)"
        )
    if not str(hardware.get("host") or "").strip():
        errors.append(f"{path.name} missing hardware.host")
    if not str(hardware.get("cpu_model") or "").strip():
        errors.append(f"{path.name} missing hardware.cpu_model")
    memory = hardware.get("memory_gb")
    if not isinstance(memory, (int, float)) or isinstance(memory, bool) or memory <= 0:
        errors.append(
            f"{path.name} hardware.memory_gb={memory!r} (published requires > 0)"
        )
    if payload.get("profile") not in SOAK_PROFILES:
        errors.append(
            f"{path.name} profile={payload.get('profile')!r} is not a harness profile"
        )
    gateway = payload.get("gateway") or {}
    if not str(gateway.get("version") or "").strip():
        errors.append(f"{path.name} missing gateway.version")
    sha = str(gateway.get("git_sha") or "")
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        errors.append(
            f"{path.name} gateway.git_sha must be a 40-char lowercase commit"
        )
    return errors


def check_soak_wrapper_envelope_pins() -> list[str]:
    """Refuse soak wrapper soft-opens that drop pinned envelope statuses."""
    errors: list[str] = []
    required_profiles = ("http-json", "sse-finite", "openai-json", "openai-sse")
    pins = (
        (ROOT / "scripts" / "run-soak-gateway-smoke.sh", "smoke-only"),
        (ROOT / "scripts" / "run-soak-gateway-smoke.ps1", "smoke-only"),
        (ROOT / "scripts" / "run-soak-gateway-extended.sh", "lab-extended"),
        (ROOT / "scripts" / "run-soak-gateway-extended.ps1", "lab-extended"),
        (ROOT / "scripts" / "run-soak-gateway-published.sh", "published"),
        (ROOT / "scripts" / "run-soak-gateway-published.ps1", "published"),
    )
    for path, status in pins:
        if not path.is_file():
            errors.append(f"missing soak wrapper: {path.name}")
            continue
        text = path.read_text(encoding="utf-8")
        if status not in text:
            errors.append(
                f"{path.name} must pin envelope-status {status} "
                "(refuse wrapper soft-open to a weaker or stronger status)"
            )
        missing_profiles = [p for p in required_profiles if p not in text]
        if missing_profiles:
            errors.append(
                f"{path.name} missing soak profiles: {', '.join(missing_profiles)} "
                "(refuse dropping an envelope profile from a Landed harness wrapper)"
            )
    for path in (
        ROOT / "scripts" / "run-soak-gateway-published.sh",
        ROOT / "scripts" / "run-soak-gateway-published.ps1",
    ):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        if "A3S_GATEWAY_DEDICATED_RUNNER" not in text:
            errors.append(
                f"{path.name} must require A3S_GATEWAY_DEDICATED_RUNNER"
            )
        if "7200" not in text:
            errors.append(
                f"{path.name} must keep the default 7200s publish duration floor"
            )
        if "cargo build --locked" not in text:
            errors.append(
                f"{path.name} must build the published binary with cargo build --locked "
                "(refuse an unlocked dependency set as a capacity envelope)"
            )
    return errors


def check_dedicated_hardware_doc_honesty() -> list[str]:
    """Refuse dedicated-hardware doc soft-opens that drop publish honesty rules."""
    errors: list[str] = []
    path = ROOT / "docs" / "ops" / "dedicated-hardware-envelopes.md"
    if not path.is_file():
        return [f"missing {path.name}"]
    text = path.read_text(encoding="utf-8")
    if "never be relabeled" not in text:
        errors.append(
            f"{path.name} must refuse relabeling lab/smoke results as published"
        )
    if "Lowering the default 2h floor" not in text:
        errors.append(
            f"{path.name} must keep Non-goals against lowering the 2h publish floor"
        )
    if "GitHub-hosted runners" not in text and "developer laptops" not in text:
        errors.append(
            f"{path.name} must keep Non-goals against publishing from CI/laptops"
        )
    return errors


def check_threat_model_honesty_while_review_open() -> list[str]:
    """Refuse threat-model soft-opens that claim Enterprise GA while review is Open."""
    errors: list[str] = []
    if not THREAT_MODEL.is_file():
        return [f"missing {THREAT_MODEL.name}"]
    text = THREAT_MODEL.read_text(encoding="utf-8")
    if "authored for Production Candidate" not in text:
        errors.append(
            f"{THREAT_MODEL.name} must stay authored for Production Candidate "
            "while security-review is Open"
        )
    if "still required for Enterprise GA" not in text:
        errors.append(
            f"{THREAT_MODEL.name} must keep stating independent review is still "
            "required for Enterprise GA while security-review is Open"
        )
    if "Claiming Enterprise GA from this document alone" not in text:
        errors.append(
            f"{THREAT_MODEL.name} must refuse claiming Enterprise GA from the "
            "threat model alone"
        )
    if re.search(r"Status:\s*\*\*Enterprise GA\*\*", text, re.I):
        errors.append(
            f"{THREAT_MODEL.name} claims Status: Enterprise GA while "
            "security-review is Open"
        )
    return errors


def check_security_md_reporting() -> list[str]:
    """Refuse SECURITY.md soft-opens that drop the private reporting channel."""
    if not SECURITY_MD.is_file():
        return [f"missing {SECURITY_MD.name}"]
    text = SECURITY_MD.read_text(encoding="utf-8")
    if "Reporting a vulnerability" not in text:
        return [
            f"{SECURITY_MD.name} must keep a Reporting a vulnerability section "
            "(threat-model Landed evidence)"
        ]
    if "Do not open a public issue" not in text:
        return [
            f"{SECURITY_MD.name} must keep private-reporting guidance "
            "(do not open a public issue for undisclosed vulnerabilities)"
        ]
    return []


DRAFT_TABLE_ROW_RE = re.compile(
    r"\|\s*`([^`]+)`\s*\|\s*(\d+(?:\.\d+)?)s\s*\|\s*(\d+)\s*\|\s*"
    r"([0-9.]+)\s*\|\s*([0-9.]+)×\s*\|\s*([^|]+?)\s*\|\s*(yes|no)\s*\|\s*`([^`]+)`"
)


def check_lab_draft_table_matches_json(draft_text: str, results_dir: Path) -> list[str]:
    """Refuse capacity-envelope-draft rows that drift from committed lab JSON."""
    errors: list[str] = []
    rows = DRAFT_TABLE_ROW_RE.findall(draft_text)
    lab_files = (
        sorted(results_dir.glob("lab-*.json")) if results_dir.is_dir() else []
    )
    if not rows:
        if lab_files:
            return [
                "capacity-envelope-draft.md draft table has no lab rows "
                "(committed lab JSON cannot be summarized off-book)"
            ]
        return []
    cited: set[str] = set()
    for profile, duration, concurrency, ok_s, growth, host, passed, filename in rows:
        cited.add(filename)
        path = results_dir / filename
        if not path.is_file():
            errors.append(
                f"capacity-envelope-draft.md cites missing soak result {filename}"
            )
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"unreadable soak result {filename}: {exc}")
            continue
        if payload.get("profile") != profile:
            errors.append(
                f"{filename} profile {payload.get('profile')!r} != draft {profile!r}"
            )
        if float(payload.get("duration_secs", -1)) != float(duration):
            errors.append(
                f"{filename} duration_secs={payload.get('duration_secs')!r} != draft {duration}s"
            )
        if int(payload.get("concurrency", -1)) != int(concurrency):
            errors.append(
                f"{filename} concurrency={payload.get('concurrency')!r} != draft {concurrency}"
            )
        actual_rps = float((payload.get("requests") or {}).get("ok_per_sec", -1))
        if abs(actual_rps - float(ok_s)) > 0.06:
            errors.append(
                f"{filename} ok_per_sec={actual_rps} drifts from draft {ok_s}"
            )
        actual_growth = float((payload.get("rss_kb") or {}).get("growth", -1))
        if abs(actual_growth - float(growth)) > 0.006:
            errors.append(
                f"{filename} rss growth={actual_growth} drifts from draft {growth}"
            )
        actual_host = str((payload.get("hardware") or {}).get("host", ""))
        if actual_host != host.strip():
            errors.append(
                f"{filename} host {actual_host!r} != draft {host.strip()!r}"
            )
        expect_pass = passed == "yes"
        if bool(payload.get("pass")) is not expect_pass:
            errors.append(
                f"{filename} pass={payload.get('pass')!r} != draft {passed}"
            )
    if results_dir.is_dir():
        for path in sorted(results_dir.glob("lab-*.json")):
            if path.name not in cited:
                errors.append(
                    f"{path.name} is committed but missing from capacity-envelope-draft.md"
                )
    return errors


def check_status() -> list[str]:
    errors: list[str] = []

    if not CHECKLIST.is_file():
        return [f"missing checklist: {CHECKLIST}"]
    checklist = CHECKLIST.read_text(encoding="utf-8")
    statuses = parse_checklist_statuses(checklist)
    required = {
        "fault-injection",
        "threat-model",
        "capacity-harness",
        "publish-gate",
        "status-verifier",
        "published-envelopes",
        "security-review",
        "production-adoption",
    }
    missing_keys = sorted(required - set(statuses))
    if missing_keys:
        errors.append(f"checklist missing gate rows: {', '.join(missing_keys)}")

    open_gates = sorted(k for k, v in statuses.items() if v == "Open")
    landed_gates = sorted(k for k, v in statuses.items() if v == "Landed")

    for key in landed_gates:
        for path in LANDED_EVIDENCE.get(key, []):
            if not path.is_file():
                errors.append(f"Landed gate {key} missing evidence file: {path}")

    if statuses.get("fault-injection") == "Landed":
        if not CI_WORKFLOW.is_file():
            errors.append(f"Landed fault-injection missing CI workflow: {CI_WORKFLOW}")
        else:
            ci_text = CI_WORKFLOW.read_text(encoding="utf-8")
            if not enterprise_ga_smoke_covers_linux_and_windows(ci_text):
                errors.append(
                    "fault-injection Landed but `.github/workflows/ci.yml` "
                    "enterprise-ga-smoke matrix lacks both ubuntu-latest and "
                    "windows-latest"
                )
            if "run-managed-runtime-evidence" not in ci_text:
                errors.append(
                    "fault-injection Landed but CI enterprise-ga-smoke does not "
                    "run managed-runtime real OS-process evidence scripts"
                )
            if "check-fault-suite-inventory.py" not in ci_text:
                errors.append(
                    "fault-injection Landed but CI enterprise-ga-smoke does not "
                    "run check-fault-suite-inventory.py"
                )
            if "test_fault_suite_inventory.py" not in ci_text:
                errors.append(
                    "fault-injection Landed but CI enterprise-ga-smoke does not "
                    "run test_fault_suite_inventory.py"
                )
            if "check-managed-runtime-evidence-inventory.py" not in ci_text:
                errors.append(
                    "fault-injection Landed but CI enterprise-ga-smoke does not "
                    "run check-managed-runtime-evidence-inventory.py"
                )
            if "test_managed_runtime_evidence_inventory.py" not in ci_text:
                errors.append(
                    "fault-injection Landed but CI enterprise-ga-smoke does not "
                    "run test_managed_runtime_evidence_inventory.py"
                )
            if "check-runbook-evidence-inventory.py" not in ci_text:
                errors.append(
                    "fault-injection Landed but CI enterprise-ga-smoke does not "
                    "run check-runbook-evidence-inventory.py"
                )
            if "test_runbook_evidence_inventory.py" not in ci_text:
                errors.append(
                    "fault-injection Landed but CI enterprise-ga-smoke does not "
                    "run test_runbook_evidence_inventory.py"
                )
        inventory = ROOT / "scripts" / "check-fault-suite-inventory.py"
        if inventory.is_file():
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "check_fault_suite_inventory", inventory
            )
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                fault_docs = ROOT / "docs" / "ops" / "fault-injection.md"
                for error in mod.check_inventory(
                    fault_docs=fault_docs if fault_docs.is_file() else None
                ):
                    errors.append(f"fault-suite inventory: {error}")
        managed_inventory = (
            ROOT / "scripts" / "check-managed-runtime-evidence-inventory.py"
        )
        if managed_inventory.is_file():
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "check_managed_runtime_evidence_inventory", managed_inventory
            )
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for error in mod.check_inventory():
                    errors.append(f"managed-runtime inventory: {error}")
        runbook_inventory = (
            ROOT / "scripts" / "check-runbook-evidence-inventory.py"
        )
        if runbook_inventory.is_file():
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "check_runbook_evidence_inventory", runbook_inventory
            )
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for error in mod.check_inventory():
                    errors.append(f"runbook evidence inventory: {error}")

    if statuses.get("capacity-harness") == "Landed":
        if CI_WORKFLOW.is_file():
            ci_text = CI_WORKFLOW.read_text(encoding="utf-8")
            if "run-soak-gateway-smoke" not in ci_text:
                errors.append(
                    "capacity-harness Landed but CI enterprise-ga-smoke does not "
                    "run soak smoke scripts"
                )
        errors.extend(check_soak_wrapper_envelope_pins())

    if statuses.get("publish-gate") == "Landed":
        if CI_WORKFLOW.is_file():
            ci_text = CI_WORKFLOW.read_text(encoding="utf-8")
            if "test_soak_envelope_status.py" not in ci_text:
                errors.append(
                    "publish-gate Landed but CI enterprise-ga-smoke does not "
                    "run test_soak_envelope_status.py"
                )
        # Publish wrappers are also covered when capacity-harness is Landed; if
        # only publish-gate is Landed, still refuse published-wrapper soft-opens.
        if statuses.get("capacity-harness") != "Landed":
            errors.extend(check_soak_wrapper_envelope_pins())
        errors.extend(check_dedicated_hardware_doc_honesty())

    if statuses.get("status-verifier") == "Landed":
        if CI_WORKFLOW.is_file():
            ci_text = CI_WORKFLOW.read_text(encoding="utf-8")
            if "check-enterprise-ga-status.py" not in ci_text:
                errors.append(
                    "status-verifier Landed but CI enterprise-ga-smoke does not "
                    "run check-enterprise-ga-status.py"
                )
            if "test_enterprise_ga_status.py" not in ci_text:
                errors.append(
                    "status-verifier Landed but CI enterprise-ga-smoke does not "
                    "run test_enterprise_ga_status.py"
                )

    roadmap = ROADMAP.read_text(encoding="utf-8") if ROADMAP.is_file() else ""
    claims_enterprise_ga = bool(
        re.search(
            r"current\s+`?v?[0-9.]+`?\s+release\s+is\s+an?\s+\*\*Enterprise GA\*\*",
            roadmap,
            re.I,
        )
    ) or bool(
        re.search(
            r"Product maturity[^\n]*\n+[^\n]*\*\*Enterprise GA\*\*",
            roadmap,
            re.I,
        )
    )
    # Explicit current-posture line used by this repo.
    production_candidate = "**Production Candidate**" in roadmap.split("## Product maturity", 1)[-1][
        :800
    ]
    if open_gates and claims_enterprise_ga:
        errors.append(
            "ROADMAP claims Enterprise GA while checklist still has Open gates: "
            + ", ".join(open_gates)
        )
    if open_gates and not production_candidate:
        errors.append(
            "checklist has Open gates but ROADMAP Product maturity no longer states "
            "Production Candidate"
        )

    if statuses.get("published-envelopes") == "Open":
        for path in soak_json_files():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"unreadable soak result {path.name}: {exc}")
                continue
            status = payload.get("envelope_status")
            if status == "published" or path.name.startswith("published-"):
                errors.append(
                    f"published-envelopes gate is Open but found published artifact "
                    f"{path.name} (envelope_status={status!r})"
                )
            # Lab drafts must stay lab-extended on non-dedicated hardware while
            # the published-envelopes gate is Open (refuse silent relabel).
            errors.extend(check_lab_draft_while_published_open(path, payload))
            errors.extend(check_smoke_while_published_open(path, payload))
            errors.extend(check_committed_soak_result_contract(path, payload))
        if not ENVELOPE_DRAFT.is_file():
            errors.append(
                f"missing {ENVELOPE_DRAFT.name} (lab draft must remain distinct from "
                "published envelopes while that gate is Open)"
            )
        else:
            draft = ENVELOPE_DRAFT.read_text(encoding="utf-8")
            if "**Status: not published.**" not in draft and "not published" not in draft.lower():
                errors.append(
                    "capacity-envelope-draft.md must keep a not-published status "
                    "while published-envelopes is Open"
                )
            if re.search(r"\*\*Status:\s*published\.\*\*", draft, re.I):
                errors.append(
                    "published-envelopes is Open but capacity-envelope-draft.md "
                    "claims Status: published"
                )
            errors.extend(check_lab_draft_table_matches_json(draft, SOAK_RESULTS))
        # Honesty rules must remain while envelopes stay unpublished, even if
        # publish-gate is not Landed yet.
        if statuses.get("publish-gate") != "Landed":
            errors.extend(check_dedicated_hardware_doc_honesty())

    if statuses.get("published-envelopes") == "Landed":
        published = []
        for path in soak_json_files():
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                errors.append(f"unreadable soak result {path.name}: {exc}")
                continue
            if payload.get("envelope_status") == "published":
                published.append(payload)
                errors.extend(check_published_envelope_contract(path, payload))
        if not published:
            errors.append(
                "published-envelopes marked Landed but no soak JSON with "
                "envelope_status=published exists under benchmarks/soak/results/"
            )
        else:
            profiles = {item.get("profile") for item in published}
            missing = [name for name in SOAK_PROFILES if name not in profiles]
            if missing:
                errors.append(
                    "published-envelopes marked Landed but missing profiles: "
                    + ", ".join(missing)
                )

    if statuses.get("production-adoption") == "Open":
        if not ADOPTION_TEMPLATE.is_file():
            errors.append(f"missing adoption template: {ADOPTION_TEMPLATE}")
        else:
            body = ADOPTION_TEMPLATE.read_text(encoding="utf-8")
            if "This file is a **template**" not in body:
                errors.append(
                    "production-adoption is Open but template disclaimer was removed "
                    "(refusing silent promotion of the template into a case study)"
                )
            template_status = marker_status(ADOPTION_STATUS_RE, body)
            if template_status != "template":
                errors.append(
                    "production-adoption is Open but template marker is "
                    f"{template_status!r} (expected "
                    "<!-- enterprise-ga: adoption_status=template -->)"
                )
        if not LAB_DRILL.is_file():
            errors.append(
                f"missing {LAB_DRILL.name} (lab drill must remain distinct from "
                "the production-adoption gate while that gate is Open)"
            )
        else:
            drill = LAB_DRILL.read_text(encoding="utf-8")
            if (
                "does **not** satisfy" not in drill
                and "does not satisfy" not in drill
            ):
                errors.append(
                    "lab-drill-adoption.md must refuse being treated as the "
                    "production-adoption case study"
                )
        if ADOPTION_CASE_STUDY.is_file():
            case = ADOPTION_CASE_STUDY.read_text(encoding="utf-8")
            if marker_status(ADOPTION_STATUS_RE, case) == "complete":
                errors.append(
                    "production-adoption is Open but production-adoption.md claims "
                    "adoption_status=complete"
                )

    if statuses.get("production-adoption") == "Landed":
        if not ADOPTION_CASE_STUDY.is_file():
            errors.append(
                "production-adoption marked Landed but missing "
                f"{ADOPTION_CASE_STUDY.name}"
            )
        else:
            case = ADOPTION_CASE_STUDY.read_text(encoding="utf-8")
            if marker_status(ADOPTION_STATUS_RE, case) != "complete":
                errors.append(
                    "production-adoption marked Landed but "
                    "production-adoption.md lacks "
                    "<!-- enterprise-ga: adoption_status=complete -->"
                )

    if statuses.get("threat-model") == "Landed":
        errors.extend(check_security_md_reporting())

    if statuses.get("security-review") == "Open":
        if not SECURITY_FINDINGS.is_file():
            errors.append(f"missing security findings placeholder: {SECURITY_FINDINGS}")
        else:
            findings = SECURITY_FINDINGS.read_text(encoding="utf-8")
            status = marker_status(REVIEW_STATUS_RE, findings)
            if status == "signed":
                errors.append(
                    "security-review is Open but security-review-findings.md claims "
                    "review_status=signed"
                )
            elif status != "unsigned":
                errors.append(
                    "security-review-findings.md must declare "
                    "<!-- enterprise-ga: review_status=unsigned --> while the gate "
                    "is Open"
                )
        if not SECURITY_PACKAGE.is_file():
            errors.append(
                f"missing {SECURITY_PACKAGE.name} (review brief must remain available "
                "while security-review is Open)"
            )
        else:
            package = SECURITY_PACKAGE.read_text(encoding="utf-8")
            if "does not close the Enterprise GA security gate" not in package:
                errors.append(
                    "security-review-package.md must refuse being treated as a "
                    "security-review sign-off while that gate is Open"
                )
        errors.extend(check_threat_model_honesty_while_review_open())

    if statuses.get("security-review") == "Landed":
        if not SECURITY_FINDINGS.is_file():
            errors.append(
                "security-review marked Landed but missing security-review-findings.md"
            )
        else:
            findings = SECURITY_FINDINGS.read_text(encoding="utf-8")
            if marker_status(REVIEW_STATUS_RE, findings) != "signed":
                errors.append(
                    "security-review marked Landed but findings lack "
                    "<!-- enterprise-ga: review_status=signed -->"
                )

    if AUDIT_TOML.is_file():
        ignores = audit_ignore_ids(AUDIT_TOML.read_text(encoding="utf-8"))
        if ignores:
            errors.append(
                "`.cargo/audit.toml` still ignores advisories: "
                + ", ".join(ignores)
                + " (supply-chain gate expects an empty ignore list)"
            )
    else:
        errors.append(f"missing {AUDIT_TOML}")

    if not CI_WORKFLOW.is_file():
        errors.append(f"missing CI workflow: {CI_WORKFLOW}")
    elif not supply_chain_audit_is_wired(CI_WORKFLOW.read_text(encoding="utf-8")):
        errors.append(
            "`.github/workflows/ci.yml` missing supply-chain-audit job with "
            "`cargo audit --deny warnings` (ROADMAP Enterprise assurance evidence)"
        )

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable summary on stdout",
    )
    args = parser.parse_args(argv)

    checklist = CHECKLIST.read_text(encoding="utf-8") if CHECKLIST.is_file() else ""
    statuses = parse_checklist_statuses(checklist) if checklist else {}
    errors = check_status()
    open_gates = sorted(k for k, v in statuses.items() if v == "Open")
    summary = {
        "enterprise_ga": len(errors) == 0 and not open_gates,
        "open_gates": open_gates,
        "errors": errors,
        "statuses": statuses,
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print("Enterprise GA status check")
        for key, value in sorted(statuses.items()):
            print(f"  {key}: {value}")
        if open_gates:
            print(f"Open gates ({len(open_gates)}): {', '.join(open_gates)}")
            print("Maturity: Production Candidate (Enterprise GA not achieved)")
        if errors:
            print("FAIL (false promotion or missing evidence):")
            for error in errors:
                print(f"  - {error}")
        elif open_gates:
            print("OK: checklist/ROADMAP/soak artifacts are consistent with Pre-GA")
        else:
            print("OK: all checklist gates Landed with consistent evidence")

    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
