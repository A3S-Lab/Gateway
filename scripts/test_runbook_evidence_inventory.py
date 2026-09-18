#!/usr/bin/env python3
"""Unit tests for check-runbook-evidence-inventory fail-closed rules."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parent / "check-runbook-evidence-inventory.py"
    spec = importlib.util.spec_from_file_location(
        "check_runbook_evidence_inventory", path
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SH_FEATURES = 'FEATURE_CSV="kube,redis,wire"\n'
PS_FEATURES = '$FeaturesArg = "kube,redis,wire"\n'


class RunbookEvidenceInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = load_module()

    def test_discovers_exact_and_prefix_claims(self) -> None:
        text = """
## Verify

- Run `foo_bar_case` and `response_middleware_error_fails_closed_*`.
"""
        exact, prefixes = self.mod.discover_runbook_claims(text)
        self.assertEqual(exact, {"foo_bar_case"})
        self.assertEqual(prefixes, {"response_middleware_error_fails_closed_*"})

    def test_refuses_verify_claim_missing_from_suite(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runbooks = root / "docs" / "ops" / "runbooks"
            scripts = root / "scripts"
            docs = root / "docs" / "ops"
            runbooks.mkdir(parents=True)
            scripts.mkdir(parents=True)
            # docs/ops already created by runbooks.mkdir(parents=True)
            # Minimal suite that satisfies fault-suite loader import path: the
            # checker loads the real inventory module for discover helpers, but
            # uses the suite paths we pass in.
            name = "forward_auth_unreachable_returns_502_on_listener_without_upstream_contact"
            orphan = "runbook_only_verify_claim_not_in_suite"
            (runbooks / "listener-failure.md").write_text(
                f"## Verify\n\n- `{name}`, `{orphan}`\n",
                encoding="utf-8",
            )
            for other in (
                "upstream-failure.md",
                "controller-failure.md",
                "disk-failure.md",
                "network-failure.md",
            ):
                (runbooks / other).write_text(
                    f"## Verify\n\n- `{name}`\n",
                    encoding="utf-8",
                )
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'{SH_FEATURES}FILTERS=(\n  {name}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'{PS_FEATURES}$Filters = @(\n  "{name}"\n)\n',
                encoding="utf-8",
            )
            (docs / "fault-injection.md").write_text(
                f"| Class | Evidence |\n| --- | --- |\n| Listener | `{name}` |\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                runbook_dir=runbooks,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
                fault_docs=docs / "fault-injection.md",
            )
            self.assertTrue(
                any(orphan in error and "missing from FILTERS" in error for error in errors),
                errors,
            )

    def test_refuses_prefix_with_no_suite_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runbooks = root / "docs" / "ops" / "runbooks"
            scripts = root / "scripts"
            docs = root / "docs" / "ops"
            runbooks.mkdir(parents=True)
            scripts.mkdir(parents=True)
            # docs/ops already created by runbooks.mkdir(parents=True)
            name = "forward_auth_unreachable_returns_502_on_listener_without_upstream_contact"
            for rb in self.mod.RUNBOOK_NAMES:
                claim = (
                    "`missing_family_*`"
                    if rb == "listener-failure.md"
                    else f"`{name}`"
                )
                (runbooks / rb).write_text(
                    f"## Verify\n\n- {claim}\n",
                    encoding="utf-8",
                )
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'{SH_FEATURES}FILTERS=(\n  {name}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'{PS_FEATURES}$Filters = @(\n  "{name}"\n)\n',
                encoding="utf-8",
            )
            (docs / "fault-injection.md").write_text(
                f"| Class | Evidence |\n| --- | --- |\n| Listener | `{name}` |\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                runbook_dir=runbooks,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
                fault_docs=docs / "fault-injection.md",
            )
            self.assertTrue(
                any(
                    "missing_family_*" in error and "no suite filter" in error
                    for error in errors
                ),
                errors,
            )

    def test_repo_runbooks_are_consistent(self) -> None:
        errors = self.mod.check_inventory()
        self.assertEqual(errors, [], errors)


if __name__ == "__main__":
    unittest.main()
