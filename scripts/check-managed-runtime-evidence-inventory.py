#!/usr/bin/env python3
"""Fail-closed inventory: every real_os_process_upstream_* case is curated.

Enterprise GA smoke runs `scripts/run-managed-runtime-evidence.{sh,ps1}`.
Without this verifier, a new case in `tests/managed_runtime_real_process.rs`
can soft-open out of smoke while docs still claim the Managed Runtime bar.

Parity with the fault-suite inventory:
- code → FILTERS membership in both runners + docs claim
- docs claims → code + FILTERS
- orphan FILTERS refused
- sh ≡ ps1 FILTERS set equality
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_RS = ROOT / "tests" / "managed_runtime_real_process.rs"
SUITE_SH = ROOT / "scripts" / "run-managed-runtime-evidence.sh"
SUITE_PS1 = ROOT / "scripts" / "run-managed-runtime-evidence.ps1"
DOCS = ROOT / "docs" / "ops" / "fault-injection.md"

TEST_FN_RE = re.compile(r"fn\s+(real_os_process_upstream_\w+)\s*\(")
DOC_CLAIM_RE = re.compile(r"`(real_os_process_upstream_[a-z0-9_]+)`")


def discover_real_os_process_tests(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    return set(TEST_FN_RE.findall(text))


def discover_doc_claims(docs: Path) -> set[str]:
    return set(DOC_CLAIM_RE.findall(docs.read_text(encoding="utf-8")))


def discover_suite_filters(suite_text: str) -> set[str]:
    """Names listed in FILTERS=(...) / $Filters = @(...) blocks."""
    filters: set[str] = set()
    in_filters = False
    for line in suite_text.splitlines():
        stripped = line.strip().rstrip(",")
        if (
            stripped.startswith("FILTERS=(")
            or stripped.startswith("FILTERS+=(")
            or stripped.startswith("$Filters")
        ):
            in_filters = True
            continue
        if in_filters:
            if stripped in {")", "@()"} or stripped == ")":
                in_filters = False
                continue
            match = re.match(r'^"?([a-z][a-z0-9_]+)"?$', stripped)
            if match:
                filters.add(match.group(1))
    return filters


def check_inventory(
    test_rs: Path = TEST_RS,
    suite_sh: Path = SUITE_SH,
    suite_ps1: Path = SUITE_PS1,
    docs: Path = DOCS,
) -> list[str]:
    errors: list[str] = []
    tests = discover_real_os_process_tests(test_rs)
    if not tests:
        return ["no real_os_process_upstream_* tests found in managed_runtime_real_process.rs"]
    sh = suite_sh.read_text(encoding="utf-8")
    ps1 = suite_ps1.read_text(encoding="utf-8")
    sh_filters = discover_suite_filters(sh)
    ps1_filters = discover_suite_filters(ps1)
    if sh_filters != ps1_filters:
        only_sh = sorted(sh_filters - ps1_filters)
        only_ps1 = sorted(ps1_filters - sh_filters)
        if only_sh:
            errors.append(
                "managed-runtime filter set mismatch (only in "
                f"{suite_sh.name}): {', '.join(only_sh)}"
            )
        if only_ps1:
            errors.append(
                "managed-runtime filter set mismatch (only in "
                f"{suite_ps1.name}): {', '.join(only_ps1)}"
            )
    for name in sorted(tests):
        missing = []
        if name not in sh_filters:
            missing.append(suite_sh.name)
        if name not in ps1_filters:
            missing.append(suite_ps1.name)
        if missing:
            errors.append(f"{name} missing from FILTERS in {', '.join(missing)}")
    doc_claims = discover_doc_claims(docs) if docs.is_file() else set()
    for name in sorted(tests):
        if name not in doc_claims:
            errors.append(f"{name} missing from {docs.name}")
    for name in sorted(doc_claims - tests):
        errors.append(
            f"docs claim {name} but missing from managed_runtime_real_process.rs"
        )
    suite_filters = sh_filters | ps1_filters
    for name in sorted(suite_filters - tests):
        errors.append(
            f"{name} listed in managed-runtime runners but missing from "
            "managed_runtime_real_process.rs"
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
        test_rs=root / "tests" / "managed_runtime_real_process.rs",
        suite_sh=root / "scripts" / "run-managed-runtime-evidence.sh",
        suite_ps1=root / "scripts" / "run-managed-runtime-evidence.ps1",
        docs=root / "docs" / "ops" / "fault-injection.md",
    )
    if errors:
        print("managed-runtime evidence inventory check FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    tests = discover_real_os_process_tests(
        root / "tests" / "managed_runtime_real_process.rs"
    )
    print(
        f"OK: {len(tests)} real_os_process_upstream_* cases are listed in both "
        "managed-runtime evidence runners and docs/ops/fault-injection.md "
        "(FILTER membership + sh==ps1)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
