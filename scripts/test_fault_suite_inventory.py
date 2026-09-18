#!/usr/bin/env python3
"""Unit tests for check-fault-suite-inventory fail-closed rules."""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


def load_module():
    path = Path(__file__).resolve().parent / "check-fault-suite-inventory.py"
    spec = importlib.util.spec_from_file_location("check_fault_suite_inventory", path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SH_FEATURES = 'FEATURE_CSV="kube,redis,wire"\n'
PS_FEATURES = '$FeaturesArg = "kube,redis,wire"\n'


def write_suite_runners(scripts: Path, *, sh_filters: str, ps_filters: str) -> None:
    (scripts / "run-fault-injection-suite.sh").write_text(
        f"{SH_FEATURES}FILTERS=(\n{sh_filters}\n)\n",
        encoding="utf-8",
    )
    (scripts / "run-fault-injection-suite.ps1").write_text(
        f"{PS_FEATURES}$Filters = @(\n{ps_filters}\n)\n",
        encoding="utf-8",
    )


class FaultSuiteInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mod = load_module()

    def test_discovers_fail_closed_fn_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            src.mkdir()
            (src / "a.rs").write_text(
                """
#[test]
fn validate_activation_fails_closed_when_example() {}
fn probe_activation_fails_closed_when_other() {}
fn probe_activation_rejects_missing_boot_epoch_headroom_like_open() {}
fn probe_activation_projects_empty_epoch_reclaim_before_capacity_like_open() {}
fn probe_activation_accepts_deleted_retiring_epoch_like_open() {}
fn probe_activation_rejects_unreachable_redis() {}
fn probe_activation_accepts_reachable_auth_service() {}
fn validate_activation_rejects_cloud_managed_bootstrap_with_inline_traffic() {}
fn validate_activation_probes_reachable_forward_auth() {}
fn validate_activation_at_path_attaches_config_parent_watch() {}
fn validate_activation_accepts_usable_acme_account_key() {}
fn test_validate_activation_builds_discovery_http_client() {}
fn validate_activation_skips_redis_probe_when_fail_open() {}
fn validate_activation_prepares_revision_health_checkers() {}
fn load_merged_gateway_config_probes_file_watch_when_enabled() {}
fn probe_file_watch_activation_accepts_existing_paths() {}
fn load_merged_gateway_config_fails_closed_when_directory_missing() {}
fn with_middlewares_fails_closed_on_dual_retry_with_custom_policy() {}
fn load_config_fails_closed_when_configured_directory_is_missing() {}
fn generate_config_fails_closed_on_missing_port_label() {}
fn scheduled_models_fail_closed_when_worker_observations_are_absent() {}
fn not_a_match() {}
""",
                encoding="utf-8",
            )
            names = self.mod.discover_fail_closed_tests(src)
            self.assertEqual(
                names,
                {
                    "validate_activation_fails_closed_when_example",
                    "probe_activation_fails_closed_when_other",
                    "probe_activation_rejects_missing_boot_epoch_headroom_like_open",
                    "probe_activation_projects_empty_epoch_reclaim_before_capacity_like_open",
                    "probe_activation_accepts_deleted_retiring_epoch_like_open",
                    "probe_activation_rejects_unreachable_redis",
                    "probe_activation_accepts_reachable_auth_service",
                    "validate_activation_rejects_cloud_managed_bootstrap_with_inline_traffic",
                    "validate_activation_probes_reachable_forward_auth",
                    "validate_activation_at_path_attaches_config_parent_watch",
                    "validate_activation_accepts_usable_acme_account_key",
                    "test_validate_activation_builds_discovery_http_client",
                    "validate_activation_skips_redis_probe_when_fail_open",
                    "validate_activation_prepares_revision_health_checkers",
                    "load_merged_gateway_config_probes_file_watch_when_enabled",
                    "probe_file_watch_activation_accepts_existing_paths",
                    "load_merged_gateway_config_fails_closed_when_directory_missing",
                    "with_middlewares_fails_closed_on_dual_retry_with_custom_policy",
                    "load_config_fails_closed_when_configured_directory_is_missing",
                    "generate_config_fails_closed_on_missing_port_label",
                    "scheduled_models_fail_closed_when_worker_observations_are_absent",
                },
            )

    def test_refuses_suite_filter_set_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            name = "validate_activation_fails_closed_when_ok"
            required = [name, *sorted(self.mod.REQUIRED_CURATED)]
            sh_body = "\n".join(f"  {n}" for n in required)
            ps_body = ",\n".join(f'  "{n}"' for n in required)
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis,wire"\nFILTERS=(\n{sh_body}\n  only_in_shell\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @(\n{ps_body}\n)\n',
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertTrue(
                any("only_in_shell" in error and "mismatch" in error for error in errors),
                errors,
            )

    def test_refuses_doc_suite_claim_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            docs = root / "docs" / "ops"
            src.mkdir()
            scripts.mkdir(parents=True)
            docs.mkdir(parents=True)
            name = "validate_activation_fails_closed_when_ok"
            claimed = "validate_activation_fails_closed_when_doc_only"
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            required = [name, *sorted(self.mod.REQUIRED_CURATED)]
            sh_body = "\n".join(f"  {n}" for n in required)
            ps_body = ",\n".join(f'  "{n}"' for n in required)
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis,wire"\nFILTERS=(\n{sh_body}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @(\n{ps_body}\n)\n',
                encoding="utf-8",
            )
            (docs / "fault-injection.md").write_text(
                f"--features kube,redis,wire\n"
                f"| Class | Evidence |\n| --- | --- |\n| Disk | `{claimed}` |\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
                fault_docs=docs / "fault-injection.md",
            )
            self.assertTrue(
                any(claimed in error and "Suite evidence" in error for error in errors),
                "matrix claims missing from suite runners must fail closed",
            )

    def test_refuses_docs_suite_feature_claim_soft_open(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            docs = root / "docs" / "ops"
            src.mkdir()
            scripts.mkdir(parents=True)
            docs.mkdir(parents=True)
            name = "validate_activation_fails_closed_when_ok"
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            required = [name, *sorted(self.mod.REQUIRED_CURATED)]
            sh_body = "\n".join(f"  {n}" for n in required)
            ps_body = ",\n".join(f'  "{n}"' for n in required)
            write_suite_runners(scripts, sh_filters=sh_body, ps_filters=ps_body)
            (docs / "fault-injection.md").write_text(
                "Suite docs that omit the required feature CSV.\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
                fault_docs=docs / "fault-injection.md",
            )
            self.assertTrue(
                any("must claim Suite features" in error for error in errors),
                errors,
            )

    def test_refuses_orphan_suite_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            name = "validate_activation_fails_closed_when_ok"
            orphan = "orphan_listener_case_not_inventory_protected"
            required = [name, orphan, *sorted(self.mod.REQUIRED_CURATED)]
            sh_body = "\n".join(f"  {n}" for n in required)
            ps_body = ",\n".join(f'  "{n}"' for n in required)
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis,wire"\nFILTERS=(\n{sh_body}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @(\n{ps_body}\n)\n',
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertTrue(
                any(orphan in error and "REQUIRED_CURATED" in error for error in errors),
                "suite filters outside auto|REQUIRED_CURATED must fail closed",
            )

    def test_discovers_powershell_filters_plus_equals(self) -> None:
        text = '''
$Filters = @(
  "validate_activation_fails_closed_when_ok"
)
$Filters += "spool_storage_is_private_and_insecure_permissions_fail_closed"
'''
        names = self.mod.discover_suite_filters(text)
        self.assertEqual(
            names,
            {
                "validate_activation_fails_closed_when_ok",
                "spool_storage_is_private_and_insecure_permissions_fail_closed",
            },
        )


    def test_refuses_suite_feature_csv_without_wire(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            name = "validate_activation_fails_closed_when_ok"
            required = [name, *sorted(self.mod.REQUIRED_CURATED)]
            sh_body = "\n".join(f"  {n}" for n in required)
            ps_body = ",\n".join(f'  "{n}"' for n in required)
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis"\nFILTERS=(\n{sh_body}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @(\n{ps_body}\n)\n',
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertTrue(
                any("wire" in error and "soft-opens" in error for error in errors),
                "FEATURE_CSV without wire must fail closed",
            )

    def test_refuses_suite_feature_set_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            name = "validate_activation_fails_closed_when_ok"
            required = [name, *sorted(self.mod.REQUIRED_CURATED)]
            sh_body = "\n".join(f"  {n}" for n in required)
            ps_body = ",\n".join(f'  "{n}"' for n in required)
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis,wire,extra"\nFILTERS=(\n{sh_body}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @(\n{ps_body}\n)\n',
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertTrue(
                any(
                    "feature set mismatch" in error and "extra" in error
                    for error in errors
                ),
                "asymmetric suite features must fail closed",
            )

    def test_refuses_missing_suite_feature_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            name = "validate_activation_fails_closed_when_ok"
            required = [name, *sorted(self.mod.REQUIRED_CURATED)]
            sh_body = "\n".join(f"  {n}" for n in required)
            ps_body = ",\n".join(f'  "{n}"' for n in required)
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            (scripts / "run-fault-injection-suite.sh").write_text(
                f"FILTERS=(\n{sh_body}\n)\n",
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f"$Filters = @(\n{ps_body}\n)\n",
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertTrue(
                any("FEATURE_CSV" in error or "FeaturesArg" in error for error in errors),
                "missing FEATURE_CSV/$FeaturesArg must fail closed",
            )

    def test_refuses_like_open_probe_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            name = "probe_activation_rejects_missing_boot_epoch_headroom_like_open"
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            curated = "\n".join(f"  {n}" for n in sorted(self.mod.REQUIRED_CURATED))
            curated_ps = ",\n".join(
                f'  "{n}"' for n in sorted(self.mod.REQUIRED_CURATED)
            )
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis,wire"\nFILTERS=(\n{curated}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @(\n{curated_ps}\n)\n',
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertTrue(
                any(name in error for error in errors),
                "probe_*_like_open capacity proofs must be auto-required in both runners",
            )

    def test_refuses_suite_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            (src / "t.rs").write_text(
                "fn validate_activation_fails_closed_when_drift() {}\n",
                encoding="utf-8",
            )
            curated = "\n".join(f"  {name}" for name in sorted(self.mod.REQUIRED_CURATED))
            curated_ps = ",\n".join(
                f'  "{name}"' for name in sorted(self.mod.REQUIRED_CURATED)
            )
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis,wire"\nFILTERS=(\n  other_test\n{curated}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @("other_test",\n{curated_ps}\n)\n',
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertTrue(any("when_drift" in error for error in errors))

    def test_refuses_required_curated_listener_drift(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            name = "validate_activation_fails_closed_when_ok"
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis,wire"\nFILTERS=(\n  {name}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @("{name}")\n',
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertTrue(
                any(
                    "acme_http01_challenge_is_served_from_runtime_store_before_routes" in error
                    for error in errors
                )
            )
            self.assertTrue(
                any(
                    "response_middleware_error_fails_closed_instead_of_returning_upstream_body"
                    in error
                    for error in errors
                ),
                "Listener matrix response-middleware proofs must be REQUIRED_CURATED",
            )
            self.assertTrue(
                any(
                    "forward_auth_unreachable_returns_502_on_listener_without_upstream_contact"
                    in error
                    for error in errors
                ),
                "forward-auth live listener proofs must be REQUIRED_CURATED",
            )
            self.assertTrue(
                any(
                    "rate_limit_redis_unreachable_returns_503_on_listener_without_upstream_contact"
                    in error
                    for error in errors
                ),
                "Redis fail-closed listener twin must be REQUIRED_CURATED",
            )
            self.assertTrue(
                any(
                    "passive_health_half_open_recovery_readmits_traffic_after_recovery_time"
                    in error
                    for error in errors
                ),
                "Upstream half-open recovery proofs must be REQUIRED_CURATED",
            )
            self.assertTrue(
                any(
                    "gateway_new_fails_closed_on_a_usage_spool_identity_mismatch" in error
                    for error in errors
                ),
                "Disk construct path regressions must be REQUIRED_CURATED",
            )
            self.assertTrue(
                any(
                    "spool_storage_is_private_and_insecure_permissions_fail_closed" in error
                    for error in errors
                ),
                "Unix Disk permissions proof must be REQUIRED_CURATED",
            )
            self.assertTrue(
                any(
                    "corrupt_managed_service_state_fails_gateway_construct_closed" in error
                    for error in errors
                ),
                "Corrupt Managed Service state construct proof must be REQUIRED_CURATED",
            )
            self.assertTrue(
                any(
                    "probe_activation_write_probe_leaves_no_untracked_artifact" in error
                    for error in errors
                ),
                "Write-probe hygiene proof must be REQUIRED_CURATED",
            )

    def test_accepts_listed_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            scripts = root / "scripts"
            src.mkdir()
            scripts.mkdir()
            name = "validate_activation_fails_closed_when_ok"
            required = [name, *sorted(self.mod.REQUIRED_CURATED)]
            sh_body = "\n".join(f"  {n}" for n in required)
            ps_body = ",\n".join(f'  "{n}"' for n in required)
            (src / "t.rs").write_text(f"fn {name}() {{}}\n", encoding="utf-8")
            (scripts / "run-fault-injection-suite.sh").write_text(
                f'FEATURE_CSV="kube,redis,wire"\nFILTERS=(\n{sh_body}\n)\n',
                encoding="utf-8",
            )
            (scripts / "run-fault-injection-suite.ps1").write_text(
                f'$FeaturesArg = "kube,redis,wire"\n$Filters = @(\n{ps_body}\n)\n',
                encoding="utf-8",
            )
            errors = self.mod.check_inventory(
                src=src,
                suite_sh=scripts / "run-fault-injection-suite.sh",
                suite_ps1=scripts / "run-fault-injection-suite.ps1",
            )
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
