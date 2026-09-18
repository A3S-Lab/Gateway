#!/usr/bin/env python3
"""Unit tests for check-managed-runtime-evidence-inventory fail-closed rules."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parent / "check-managed-runtime-evidence-inventory.py"
    spec = importlib.util.spec_from_file_location(
        "check_managed_runtime_evidence_inventory", path
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ManagedRuntimeEvidenceInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = load_module()

    def test_discovers_real_os_process_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "managed_runtime_real_process.rs"
            path.write_text(
                """
async fn real_os_process_upstream_survives_bind_health_traffic_drain_remove() {}
async fn real_os_process_upstream_restart_restores_route_and_replay_preserves_identity() {}
fn not_a_match() {}
""",
                encoding="utf-8",
            )
            names = self.mod.discover_real_os_process_tests(path)
            self.assertEqual(
                names,
                {
                    "real_os_process_upstream_survives_bind_health_traffic_drain_remove",
                    "real_os_process_upstream_restart_restores_route_and_replay_preserves_identity",
                },
            )

    def test_refuses_runner_or_docs_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tests = root / "tests"
            scripts = root / "scripts"
            docs = root / "docs" / "ops"
            tests.mkdir(parents=True)
            scripts.mkdir(parents=True)
            docs.mkdir(parents=True)
            name = "real_os_process_upstream_survives_bind_health_traffic_drain_remove"
            (tests / "managed_runtime_real_process.rs").write_text(
                f"fn {name}() {{}}\nfn real_os_process_upstream_new_case() {{}}\n",
                encoding="utf-8",
            )
            (scripts / "run-managed-runtime-evidence.sh").write_text(
                f"FILTERS=(\n  {name}\n)\n",
                encoding="utf-8",
            )
            (scripts / "run-managed-runtime-evidence.ps1").write_text(
                f'$Filters = @("{name}")\n',
                encoding="utf-8",
            )
            (docs / "fault-injection.md").write_text(
                f"- `{name}`\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                test_rs=tests / "managed_runtime_real_process.rs",
                suite_sh=scripts / "run-managed-runtime-evidence.sh",
                suite_ps1=scripts / "run-managed-runtime-evidence.ps1",
                docs=docs / "fault-injection.md",
            )
            self.assertTrue(any("new_case" in error for error in errors))

    def test_refuses_orphan_runner_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tests = root / "tests"
            scripts = root / "scripts"
            docs = root / "docs" / "ops"
            tests.mkdir(parents=True)
            scripts.mkdir(parents=True)
            docs.mkdir(parents=True)
            name = "real_os_process_upstream_survives_bind_health_traffic_drain_remove"
            orphan = "real_os_process_upstream_orphan_not_in_tests"
            (tests / "managed_runtime_real_process.rs").write_text(
                f"fn {name}() {{}}\n",
                encoding="utf-8",
            )
            (scripts / "run-managed-runtime-evidence.sh").write_text(
                f"FILTERS=(\n  {name}\n  {orphan}\n)\n",
                encoding="utf-8",
            )
            (scripts / "run-managed-runtime-evidence.ps1").write_text(
                f'$Filters = @(\n  "{name}",\n  "{orphan}"\n)\n',
                encoding="utf-8",
            )
            (docs / "fault-injection.md").write_text(
                f"- `{name}`\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                test_rs=tests / "managed_runtime_real_process.rs",
                suite_sh=scripts / "run-managed-runtime-evidence.sh",
                suite_ps1=scripts / "run-managed-runtime-evidence.ps1",
                docs=docs / "fault-injection.md",
            )
            self.assertTrue(
                any(orphan in error for error in errors),
                errors,
            )

    def test_refuses_filter_set_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tests = root / "tests"
            scripts = root / "scripts"
            docs = root / "docs" / "ops"
            tests.mkdir(parents=True)
            scripts.mkdir(parents=True)
            docs.mkdir(parents=True)
            name = "real_os_process_upstream_survives_bind_health_traffic_drain_remove"
            (tests / "managed_runtime_real_process.rs").write_text(
                f"fn {name}() {{}}\n",
                encoding="utf-8",
            )
            (scripts / "run-managed-runtime-evidence.sh").write_text(
                f"FILTERS=(\n  {name}\n  real_os_process_upstream_only_sh\n)\n",
                encoding="utf-8",
            )
            (scripts / "run-managed-runtime-evidence.ps1").write_text(
                f'$Filters = @("{name}")\n',
                encoding="utf-8",
            )
            (docs / "fault-injection.md").write_text(
                f"- `{name}`\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                test_rs=tests / "managed_runtime_real_process.rs",
                suite_sh=scripts / "run-managed-runtime-evidence.sh",
                suite_ps1=scripts / "run-managed-runtime-evidence.ps1",
                docs=docs / "fault-injection.md",
            )
            self.assertTrue(
                any("mismatch" in error for error in errors),
                errors,
            )

    def test_accepts_listed_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tests = root / "tests"
            scripts = root / "scripts"
            docs = root / "docs" / "ops"
            tests.mkdir(parents=True)
            scripts.mkdir(parents=True)
            docs.mkdir(parents=True)
            names = [
                "real_os_process_upstream_survives_bind_health_traffic_drain_remove",
                "real_os_process_upstream_restart_restores_route_and_replay_preserves_identity",
            ]
            (tests / "managed_runtime_real_process.rs").write_text(
                "\n".join(f"fn {n}() {{}}" for n in names) + "\n",
                encoding="utf-8",
            )
            (scripts / "run-managed-runtime-evidence.sh").write_text(
                "FILTERS=(\n" + "\n".join(f"  {n}" for n in names) + "\n)\n",
                encoding="utf-8",
            )
            (scripts / "run-managed-runtime-evidence.ps1").write_text(
                "$Filters = @(\n" + ",\n".join(f'  "{n}"' for n in names) + "\n)\n",
                encoding="utf-8",
            )
            (docs / "fault-injection.md").write_text(
                "\n".join(f"- `{n}`" for n in names) + "\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                test_rs=tests / "managed_runtime_real_process.rs",
                suite_sh=scripts / "run-managed-runtime-evidence.sh",
                suite_ps1=scripts / "run-managed-runtime-evidence.ps1",
                docs=docs / "fault-injection.md",
            )
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
