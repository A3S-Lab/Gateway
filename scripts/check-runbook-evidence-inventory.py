#!/usr/bin/env python3
"""Fail-closed inventory: runbook Verify evidence stays Suite-curated.

Enterprise GA marks fault-injection + operator runbooks Landed. Without this
verifier, a Verify backtick (exact name or `family_*` prefix) can drift out of
`run-fault-injection-suite.{sh,ps1}` / `fault-injection.md` while
`check-enterprise-ga-status.py` only checks that the markdown files exist.

Rules:
- Every exact Verify claim must appear in both suite runners and in
  `docs/ops/fault-injection.md` Suite evidence.
- Every `prefix_*` Verify claim must match at least one suite filter, and every
  matching suite filter must also be claimed in `fault-injection.md`.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNBOOK_DIR = ROOT / "docs" / "ops" / "runbooks"
FAULT_DOCS = ROOT / "docs" / "ops" / "fault-injection.md"
SUITE_SH = ROOT / "scripts" / "run-fault-injection-suite.sh"
SUITE_PS1 = ROOT / "scripts" / "run-fault-injection-suite.ps1"
RUNBOOK_NAMES = (
    "listener-failure.md",
    "upstream-failure.md",
    "controller-failure.md",
    "disk-failure.md",
    "network-failure.md",
)

# Snake_case test names and family prefixes (`foo_*`) inside backticks.
CLAIM_RE = re.compile(r"`([a-z][a-z0-9_]*(?:\*)?)`")


def load_fault_suite_inventory():
    path = ROOT / "scripts" / "check-fault-suite-inventory.py"
    spec = importlib.util.spec_from_file_location("check_fault_suite_inventory", path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def discover_verify_section(text: str) -> str:
    if "## Verify" not in text:
        return ""
    section = text.split("## Verify", 1)[1]
    if "\n## " in section:
        section = section.split("\n## ", 1)[0]
    return section


def discover_runbook_claims(text: str) -> tuple[set[str], set[str]]:
    """Return (exact_names, prefix_patterns) from the Verify section."""
    section = discover_verify_section(text)
    exact: set[str] = set()
    prefixes: set[str] = set()
    for claim in CLAIM_RE.findall(section):
        if claim.endswith("*"):
            prefixes.add(claim)
        else:
            exact.add(claim)
    return exact, prefixes


def check_inventory(
    runbook_dir: Path = RUNBOOK_DIR,
    suite_sh: Path = SUITE_SH,
    suite_ps1: Path = SUITE_PS1,
    fault_docs: Path = FAULT_DOCS,
    runbook_names: tuple[str, ...] = RUNBOOK_NAMES,
) -> list[str]:
    errors: list[str] = []
    inv = load_fault_suite_inventory()
    sh_filters = inv.discover_suite_filters(suite_sh.read_text(encoding="utf-8"))
    ps1_filters = inv.discover_suite_filters(suite_ps1.read_text(encoding="utf-8"))
    suite_filters = sh_filters | ps1_filters
    if sh_filters != ps1_filters:
        # Fault-suite inventory owns the detailed mismatch message; surface a
        # short pointer so runbook checks do not paper over runner drift.
        errors.append(
            "suite filter set mismatch between runners "
            "(run check-fault-suite-inventory.py)"
        )

    doc_claims: set[str] = set()
    if fault_docs.is_file():
        doc_claims = inv.discover_doc_suite_claims(fault_docs)

    for name in runbook_names:
        path = runbook_dir / name
        if not path.is_file():
            errors.append(f"missing runbook: {path}")
            continue
        text = path.read_text(encoding="utf-8")
        if not discover_verify_section(text):
            errors.append(f"{name} missing ## Verify section")
            continue
        exact, prefixes = discover_runbook_claims(text)
        if not exact and not prefixes:
            errors.append(f"{name} Verify section has no Suite evidence claims")
            continue
        for claim in sorted(exact):
            missing = []
            if claim not in sh_filters:
                missing.append(suite_sh.name)
            if claim not in ps1_filters:
                missing.append(suite_ps1.name)
            if missing:
                errors.append(
                    f"{name} Verify claims `{claim}` missing from FILTERS in "
                    f"{', '.join(missing)}"
                )
            if fault_docs.is_file() and claim not in doc_claims:
                errors.append(
                    f"{name} Verify claims `{claim}` missing from "
                    f"{fault_docs.name} Suite evidence"
                )
        for pattern in sorted(prefixes):
            prefix = pattern.rstrip("*")
            if not prefix:
                errors.append(f"{name} Verify has empty prefix pattern `{pattern}`")
                continue
            matched = sorted(f for f in suite_filters if f.startswith(prefix))
            if not matched:
                errors.append(
                    f"{name} Verify claims `{pattern}` but no suite filter "
                    f"starts with {prefix!r}"
                )
                continue
            for filt in matched:
                if fault_docs.is_file() and filt not in doc_claims:
                    errors.append(
                        f"{name} Verify prefix `{pattern}` matches suite filter "
                        f"`{filt}` which is missing from {fault_docs.name} "
                        "Suite evidence"
                    )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=ROOT,
        help="Gateway crate root (default: parent of scripts/)",
    )
    args = parser.parse_args(argv)
    root: Path = args.root
    errors = check_inventory(
        runbook_dir=root / "docs" / "ops" / "runbooks",
        suite_sh=root / "scripts" / "run-fault-injection-suite.sh",
        suite_ps1=root / "scripts" / "run-fault-injection-suite.ps1",
        fault_docs=root / "docs" / "ops" / "fault-injection.md",
    )
    if errors:
        print("runbook evidence inventory check FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    # Summarize current claims for operators.
    total_exact = 0
    total_prefix = 0
    for name in RUNBOOK_NAMES:
        path = root / "docs" / "ops" / "runbooks" / name
        if not path.is_file():
            continue
        exact, prefixes = discover_runbook_claims(path.read_text(encoding="utf-8"))
        total_exact += len(exact)
        total_prefix += len(prefixes)
    print(
        f"OK: {len(RUNBOOK_NAMES)} operator runbooks Verify claims "
        f"({total_exact} exact, {total_prefix} prefix) are Suite-curated in "
        "both fault-injection runners and fault-injection.md"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
