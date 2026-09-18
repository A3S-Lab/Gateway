#!/usr/bin/env python3
"""Fail-closed inventory: every in-tree activation fail-closed / like_open probe is curated.

CHANGELOG / Enterprise GA claim that the fault-injection suite includes every
`validate_activation_fails_closed_*` / `probe_activation_fails_closed_*`
regression plus Disk `probe_activation_(rejects|projects|accepts)_*_like_open`
capacity contracts, middleware
`probe_activation_(rejects_unreachable|accepts_reachable)_*` twins, validate≡activate
positive/skip/prepare legs (`validate_activation_probes_*` /
`validate_activation_skips_*` / `validate_activation_prepares_*`,
`validate_activation_at_path_*`, `validate_activation_accepts_*`,
`test_validate_activation_builds_*`,
`load_merged_gateway_config_probes_*`, `probe_*_activation_accepts_*`), and
construct/provider fail-closed families (`probe_*_activation_rejects_*`,
`*_fails_gateway_construct_closed`, static-bundle `*_fails_validate`, Windows
`default_docker_block_fails_validate_on_windows`), plus config-validate
`test_validate_*_fails_closed` and entrypoint `*_fails_listener_policy`, plus
managed live-listener soft-open bars (`managed_snapshot_expiry_rejects_*`,
`managed_snapshot_apply_*_without_upstream`, credential/grant successor
`*_without_upstream`, `managed_inference_*fails_closed*`), and validate
soft-open prevention for Node API management, discovery seeds, health-check
noop probes, sticky names, non-`.acl` main paths, unusable CA PEM, Docker
unix-socket hosts, and WEB0.4 SPA / sealed-byte soft-open bars
(`spa_fallback_*`, HEAD-without-GET, compress no-transform, static-bundle
inflight drain, sealed content-encoding), and wire `fail_closed` escalation
blocks (`fail_closed_blocks_escalation_*`,
`blocks_escalation_on_response_when_fail_closed`). This verifier refuses silent
drift when a new matching test lands without a suite filter entry in both shell
and PowerShell runners.

It also refuses Suite soft-opens in the opposite direction: every full test
name claimed as Automated evidence in `docs/ops/fault-injection.md` (failure-
class matrix + distributed listener bullets) must appear in both runners, and
every filter listed in those runners must be auto-discovered or present in
`REQUIRED_CURATED` (no unprotected orphans). Suite runners must keep
`FEATURE_CSV` / `$FeaturesArg` at least `kube,redis,wire` so wire
`fail_closed` (and redis/kube) coverage cannot soft-open by downgrading
cargo features while filters still list the names. Shell and PowerShell
runners must also keep identical feature sets (same soft-open class as
filter-set mismatch). Managed Runtime
`real_os_process_upstream_*` names are owned by
`check-managed-runtime-evidence-inventory.py` and are excluded here.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
SUITE_SH = ROOT / "scripts" / "run-fault-injection-suite.sh"
SUITE_PS1 = ROOT / "scripts" / "run-fault-injection-suite.ps1"
FAULT_DOCS = ROOT / "docs" / "ops" / "fault-injection.md"

# Default Suite cargo features. Downgrading off `wire` (or kube/redis)
# soft-opens curated fail_closed filters that need those feature gates.
REQUIRED_SUITE_FEATURES = frozenset({"kube", "redis", "wire"})
SUITE_FEATURES_RE = re.compile(
    r'^\s*(?:FEATURE_CSV|\$FeaturesArg)\s*=\s*"([^"]*)"\s*$',
    re.MULTILINE,
)

TEST_FN_RE = re.compile(
    r"fn\s+("
    r"(?:validate|probe)_activation_fails_closed_\w+"
    r"|validate_activation_rejects_\w+"
    r"|load_merged_gateway_config_fails_closed_\w+"
    r"|load_config_fails_closed_\w+"
    r"|watch_fails_closed_\w+"
    r"|with_middlewares_fails_closed_\w+"
    r"|generate_config_fails_closed_\w+"
    r"|ingress_to_config_fails_closed_\w+"
    r"|ingress_routes_to_config_fails_closed_\w+"
    r"|build_mirror_failover_fails_closed_\w+"
    r"|build_sticky_managers_fails_closed_\w+"
    r"|scheduled_models_fail_closed_\w+"
    r"|expired_worker_observations_fail_closed_\w+"
    r"|probe_activation_(?:rejects|projects|accepts)_\w+_like_open"
    r"|probe_activation_rejects_unreachable_\w+"
    r"|probe_activation_accepts_reachable_\w+"
    # Validate≡activate positive / skip / prepare legs (middle of the triad).
    r"|validate_activation_probes_\w+"
    r"|validate_activation_skips_\w+"
    r"|validate_activation_prepares_\w+"
    r"|validate_activation_at_path_\w+"
    r"|validate_activation_accepts_\w+"
    r"|test_validate_activation_builds_\w+"
    r"|load_merged_gateway_config_probes_\w+"
    r"|probe_\w+_activation_accepts_\w+"
    # Provider/construct fail-closed families that escape validate_/probe_activation_*.
    r"|probe_\w+_activation_rejects_\w+"
    r"|[a-z0-9_]+_fails_gateway_construct_closed"
    r"|[a-z0-9_]+_fails_construct_closed"
    r"|standalone_\w+_fails_validate"
    r"|cloud_managed_\w+_fail_validate"
    r"|default_docker_block_fails_validate_on_windows"
    r"|test_validate_\w+_fails_closed"
    r"|[a-z0-9_]+_fails_listener_policy"
    # Managed live-listener fail-closed / without-upstream soft-open bar.
    r"|managed_snapshot_expiry_rejects_\w+"
    r"|managed_snapshot_apply_\w+_without_upstream"
    r"|credential_successor_runtime_\w+_without_upstream"
    r"|grant_successor_runtime_\w+_without_upstream"
    r"|managed_inference_fails_closed_\w+"
    r"|managed_inference_policy_expiry_fails_closed_\w+"
    r"|managed_inference_revoked_or_expired_credentials_fail_closed_\w+"
    # Validate soft-open prevention for management / discovery / health / Docker.
    r"|node_api_client_ca_refuses_\w+"
    r"|test_management_config_rejects_\w+"
    r"|test_validate_rejects_health_check_\w+"
    r"|test_validate_rejects_tls_ca_file_\w+"
    r"|test_validate_rejects_invalid_sticky_cookie_name"
    r"|test_validate_discovery_rejects_\w+"
    r"|discovery_provider_new_requires_\w+"
    r"|test_load_config_rejects_\w+"
    r"|health_checker_probe_rejects_\w+"
    r"|grpc_proxy_try_with_ca_file_rejects_\w+"
    r"|validate_rejects_docker_unix_socket_host_\w+"
    # WEB0.4 SPA / sealed-byte soft-open prevention (never soft-200 as index.html).
    r"|spa_fallback_never_masks_\w+"
    r"|spa_fallback_eligibility_rejects_\w+"
    r"|head_verifies_via_port_head_\w+"
    r"|static_bundle_listener_preserves_sealed_bytes_\w+"
    r"|static_bundle_listener_drains_inflight_\w+"
    r"|sealed_content_encoding_\w+"
    r"|fail_closed_blocks_escalation_\w+"
    r"|blocks_escalation_on_response_when_fail_closed"
    r")\s*\("
)
# Full evidence names claimed in docs/ops/fault-injection.md (matrix + bullets).
DOC_CLAIM_RE = re.compile(
    r"`("
    r"(?:validate|probe)_activation_[a-z0-9_]+"
    r"|gateway_new_[a-z0-9_]+"
    r"|load_merged_gateway_config_[a-z0-9_]+"
    r"|load_config_fails_closed_[a-z0-9_]+"
    r"|watch_fails_closed_[a-z0-9_]+"
    r"|with_middlewares_fails_closed_[a-z0-9_]+"
    r"|generate_config_fails_closed_[a-z0-9_]+"
    r"|ingress_to_config_fails_closed_[a-z0-9_]+"
    r"|ingress_routes_to_config_fails_closed_[a-z0-9_]+"
    r"|build_mirror_failover_fails_closed_[a-z0-9_]+"
    r"|build_sticky_managers_fails_closed_[a-z0-9_]+"
    r"|scheduled_models_fail_closed_[a-z0-9_]+"
    r"|expired_worker_observations_fail_closed_[a-z0-9_]+"
    r"|response_middleware_error_fails_closed_[a-z0-9_]+"
    r"|forward_auth_[a-z0-9_]+"
    r"|rate_limit_redis_[a-z0-9_]+"
    r"|sticky_session_[a-z0-9_]+"
    r"|traffic_mirror_[a-z0-9_]+"
    r"|passive_health_[a-z0-9_]+"
    r"|circuit_breaker_[a-z0-9_]+"
    r"|failover_[a-z0-9_]+"
    r"|active_health_[a-z0-9_]+"
    r"|acme_[a-z0-9_]+"
    r"|activate_stored_certificate_[a-z0-9_]+"
    r"|with_managed_service_state_[a-z0-9_]+"
    r"|corrupt_managed_service_state_[a-z0-9_]+"
    r"|reload_[a-z0-9_]+"
    r"|spool_storage_[a-z0-9_]+"
    r"|probe_[a-z0-9_]+_activation_rejects_[a-z0-9_]+"
    r"|probe_[a-z0-9_]+_activation_accepts_[a-z0-9_]+"
    r"|[a-z0-9_]+_fails_gateway_construct_closed"
    r"|[a-z0-9_]+_fails_construct_closed"
    r"|standalone_[a-z0-9_]+_fails_validate"
    r"|cloud_managed_[a-z0-9_]+_fail_validate"
    r"|default_docker_block_fails_validate_on_windows"
    r"|test_validate_[a-z0-9_]+_fails_closed"
    r"|test_validate_activation_builds_[a-z0-9_]+"
    r"|[a-z0-9_]+_fails_listener_policy"
    r"|managed_snapshot_expiry_rejects_[a-z0-9_]+"
    r"|managed_snapshot_apply_[a-z0-9_]+_without_upstream"
    r"|credential_successor_runtime_[a-z0-9_]+"
    r"|grant_successor_runtime_[a-z0-9_]+"
    r"|managed_inference_fails_closed_[a-z0-9_]+"
    r"|managed_inference_policy_expiry_fails_closed_[a-z0-9_]+"
    r"|managed_inference_revoked_or_expired_credentials_fail_closed_[a-z0-9_]+"
    r"|node_api_client_ca_refuses_[a-z0-9_]+"
    r"|test_management_config_rejects_[a-z0-9_]+"
    r"|test_validate_rejects_health_check_[a-z0-9_]+"
    r"|test_validate_rejects_tls_ca_file_[a-z0-9_]+"
    r"|test_validate_rejects_invalid_sticky_cookie_name"
    r"|test_validate_discovery_rejects_[a-z0-9_]+"
    r"|discovery_provider_new_requires_[a-z0-9_]+"
    r"|test_load_config_rejects_[a-z0-9_]+"
    r"|health_checker_probe_rejects_[a-z0-9_]+"
    r"|grpc_proxy_try_with_ca_file_rejects_[a-z0-9_]+"
    r"|validate_rejects_docker_unix_socket_host_[a-z0-9_]+"
    r"|spa_fallback_never_masks_[a-z0-9_]+"
    r"|spa_fallback_eligibility_rejects_[a-z0-9_]+"
    r"|head_verifies_via_port_head_[a-z0-9_]+"
    r"|static_bundle_listener_preserves_sealed_bytes_[a-z0-9_]+"
    r"|static_bundle_listener_drains_inflight_[a-z0-9_]+"
    r"|sealed_content_encoding_[a-z0-9_]+"
    r"|fail_closed_blocks_escalation_[a-z0-9_]+"
    r"|blocks_escalation_on_response_when_fail_closed"
    r")`"
)
# Curated regressions claimed in docs/ops/fault-injection.md (and runbooks)
# that are not auto-discovered via validate_/probe_activation_fails_closed_*
# or probe_activation_(rejects|projects|accepts)_*_like_open /
# rejects_unreachable_* / accepts_reachable_* names. Without REQUIRED_CURATED
# they can soft-open out of enterprise-ga-smoke while the matrix still lists
# them as evidence.
REQUIRED_CURATED = {
    "acme_http01_challenge_is_served_from_runtime_store_before_routes",
    "acme_certificate_install_hot_swaps_live_https_acceptor",
    "gateway_new_at_path_fails_closed_when_config_parent_missing",
    "load_merged_gateway_config_fails_closed_on_missing_entrypoint_tls_pem",
    "load_merged_gateway_config_fails_closed_when_management_token_env_unset",
    # Listener fail-closed bar claimed in ROADMAP / fault-injection.md.
    # Only proxy_failure was curated previously; siblings could soft-open out
    # of enterprise-ga-smoke while the matrix still listed them.
    "response_middleware_error_fails_closed_instead_of_returning_upstream_body",
    "response_middleware_error_fails_closed_on_sse_listener_without_upstream_body",
    "response_middleware_error_fails_closed_on_grpc_listener_without_upstream_stream",
    "response_middleware_error_fails_closed_on_distributed_json_listener_without_power_body",
    "response_middleware_error_fails_closed_on_distributed_sse_listener_without_power_body",
    "response_middleware_error_fails_closed_on_native_models_listener_without_policy_body",
    "response_middleware_error_fails_closed_on_proxy_failure",
    "forward_auth_unreachable_returns_502_on_listener_without_upstream_contact",
    "forward_auth_deny_returns_auth_status_on_listener_without_upstream_contact",
    "sticky_session_cookie_pins_backend_on_listener",
    "sticky_session_cookie_pins_websocket_backend_on_listener",
    "traffic_mirror_copies_buffered_request_to_shadow_on_listener",
    "traffic_mirror_primary_still_succeeds_when_shadow_unreachable_on_listener",
    # Upstream health / circuit / failover bar (matrix Upstream row).
    "passive_health_half_open_recovery_readmits_traffic_after_recovery_time",
    "passive_health_half_open_still_broken_reblacklists_after_threshold",
    "circuit_breaker_half_open_probe_closes_after_success_on_listener",
    "circuit_breaker_half_open_still_failing_reopens_on_listener",
    "failover_routes_to_backup_on_listener_when_primary_unhealthy",
    "active_health_check_evicts_backend_on_listener_then_readmits_when_healthy",
    "active_health_check_evicts_revision_only_backend_on_listener_then_readmits_when_healthy",
    "active_health_redirect_does_not_follow_or_mark_healthy",
    # Disk / construct path regressions claimed alongside the Disk matrix row.
    "gateway_new_fails_closed_on_a_usage_spool_identity_mismatch",
    "with_managed_service_state_fails_construct_when_owner_lock_held",
    "corrupt_managed_service_state_fails_gateway_construct_closed",
    "reload_rejects_standalone_to_cloud_managed_transition",
    # Unix-only Disk permissions bar (listed in both runners; executed on Unix).
    "spool_storage_is_private_and_insecure_permissions_fail_closed",
    # Write-probe hygiene: lock/create probe must leave no untracked artifact
    # (claimed in CHANGELOG / first-principles; name escapes like_open discovery).
    "probe_activation_write_probe_leaves_no_untracked_artifact",
    # Fail-closed Redis twin of curated redis_fail_open.
    "rate_limit_redis_unreachable_returns_503_on_listener_without_upstream_contact",
    "rate_limit_redis_fail_open_reaches_upstream_on_listener_when_redis_unreachable",
    "reload_disabling_acme_aborts_manager",
    # ACME activate-path twin of curated stored-cert validate fail-closed.
    "activate_stored_certificate_fails_closed_when_sink_rejects_unusable_pem",
}
UNIX_ONLY = {
    "spool_storage_is_private_and_insecure_permissions_fail_closed",
    "validate_activation_fails_closed_when_usage_spool_directory_is_not_writable",
    "probe_activation_fails_closed_when_usage_spool_directory_is_not_writable",
    "linked_managed_service_state_fails_gateway_construct_closed",
    "broadly_readable_managed_service_state_fails_gateway_construct_closed",
    "validate_rejects_docker_unix_socket_host_when_path_missing",
}
WINDOWS_ONLY = {
    "default_docker_block_fails_validate_on_windows",
    "validate_rejects_docker_unix_socket_host_on_non_unix",
}


def discover_fail_closed_tests(src: Path) -> set[str]:
    names: set[str] = set()
    for path in src.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        for match in TEST_FN_RE.finditer(text):
            names.add(match.group(1))
    return names


def discover_doc_suite_claims(docs: Path) -> set[str]:
    """Full test names claimed as Suite Automated evidence in fault-injection.md."""
    text = docs.read_text(encoding="utf-8")
    return {
        name
        for name in DOC_CLAIM_RE.findall(text)
        if not name.startswith("real_os_process_upstream_")
    }


def discover_suite_filters(suite_text: str) -> set[str]:
    """Names listed in FILTERS=(...) / FILTERS+=(...) / $Filters = @(...) / $Filters +=."""
    filters: set[str] = set()
    in_filters = False
    for line in suite_text.splitlines():
        stripped = line.strip().rstrip(",")
        # PowerShell append form used for Unix-only cases.
        append = re.match(
            r'^\$Filters\s*\+=\s*"([a-z][a-z0-9_]+)"\s*$', stripped
        )
        if append:
            filters.add(append.group(1))
            continue
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


def discover_suite_features(suite_text: str) -> set[str] | None:
    """Cargo features from FEATURE_CSV / $FeaturesArg. None if assignment missing."""
    matches = SUITE_FEATURES_RE.findall(suite_text)
    if not matches:
        return None
    # Last assignment wins (mirrors shell/PowerShell override semantics).
    return {part.strip() for part in matches[-1].split(",") if part.strip()}


def check_suite_feature_set(
    suite_text: str, *, runner_name: str
) -> list[str]:
    """Refuse Suite feature soft-opens that skip kube/redis/wire-gated filters."""
    features = discover_suite_features(suite_text)
    required = ",".join(sorted(REQUIRED_SUITE_FEATURES))
    if features is None:
        return [
            f"{runner_name} missing FEATURE_CSV/$FeaturesArg "
            f"(must include {required})"
        ]
    missing = REQUIRED_SUITE_FEATURES - features
    if missing:
        found = ",".join(sorted(features)) or "(empty)"
        return [
            f"{runner_name} feature set {found!r} soft-opens fail-closed coverage; "
            f"missing required features: {','.join(sorted(missing))} "
            f"(must include {required})"
        ]
    return []


def check_inventory(
    src: Path = SRC,
    suite_sh: Path = SUITE_SH,
    suite_ps1: Path = SUITE_PS1,
    fault_docs: Path | None = None,
) -> list[str]:
    errors: list[str] = []
    tests = discover_fail_closed_tests(src)
    if not tests:
        return ["no validate_/probe_activation_fails_closed_* tests found under src/"]
    sh = suite_sh.read_text(encoding="utf-8")
    ps1 = suite_ps1.read_text(encoding="utf-8")
    errors.extend(check_suite_feature_set(sh, runner_name=suite_sh.name))
    errors.extend(check_suite_feature_set(ps1, runner_name=suite_ps1.name))
    if fault_docs is not None and fault_docs.is_file():
        docs_text = fault_docs.read_text(encoding="utf-8")
        # Docs must keep claiming the required Suite feature set so operators
        # cannot be told a weaker default while runners stay kube,redis,wire.
        required_csv = ",".join(sorted(REQUIRED_SUITE_FEATURES))
        if f"--features {required_csv}" not in docs_text and required_csv not in docs_text:
            errors.append(
                f"{fault_docs.name} must claim Suite features {required_csv} "
                "(docs cannot soft-open a weaker default than the runners)"
            )
    sh_features = discover_suite_features(sh)
    ps1_features = discover_suite_features(ps1)
    if (
        sh_features is not None
        and ps1_features is not None
        and sh_features != ps1_features
    ):
        only_sh = sorted(sh_features - ps1_features)
        only_ps1 = sorted(ps1_features - sh_features)
        if only_sh:
            errors.append(
                "suite feature set mismatch (only in "
                f"{suite_sh.name}): {', '.join(only_sh)}"
            )
        if only_ps1:
            errors.append(
                "suite feature set mismatch (only in "
                f"{suite_ps1.name}): {', '.join(only_ps1)}"
            )
    sh_filters = discover_suite_filters(sh)
    ps1_filters = discover_suite_filters(ps1)
    if sh_filters != ps1_filters:
        only_sh = sorted(sh_filters - ps1_filters)
        only_ps1 = sorted(ps1_filters - sh_filters)
        if only_sh:
            errors.append(
                "suite filter set mismatch (only in "
                f"{suite_sh.name}): {', '.join(only_sh)}"
            )
        if only_ps1:
            errors.append(
                "suite filter set mismatch (only in "
                f"{suite_ps1.name}): {', '.join(only_ps1)}"
            )
    required = set(tests) | REQUIRED_CURATED
    for name in sorted(required):
        missing = []
        if name not in sh_filters:
            missing.append(suite_sh.name)
        if name not in ps1_filters:
            missing.append(suite_ps1.name)
        if missing:
            hint = ""
            if name in UNIX_ONLY:
                hint = " (Unix-only filters must still list the name)"
            elif name in WINDOWS_ONLY:
                hint = " (Windows-only filters must still list the name)"
            errors.append(
                f"{name} missing from FILTERS in {', '.join(missing)}{hint}"
            )
    if fault_docs is not None and fault_docs.is_file():
        for name in sorted(discover_doc_suite_claims(fault_docs)):
            missing = []
            if name not in sh_filters:
                missing.append(suite_sh.name)
            if name not in ps1_filters:
                missing.append(suite_ps1.name)
            if missing:
                errors.append(
                    f"docs claim {name} as Suite evidence but missing from "
                    f"FILTERS in {', '.join(missing)}"
                )
    # Refuse suite→inventory soft-opens: every runner filter must be
    # auto-discovered or REQUIRED_CURATED (docs claim this invariant).
    suite_filters = sh_filters | ps1_filters
    for name in sorted(suite_filters - required):
        errors.append(
            f"{name} listed in suite runners but neither auto-discovered nor "
            "REQUIRED_CURATED (inventory cannot protect it from silent drop)"
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
    fault_docs = root / "docs" / "ops" / "fault-injection.md"
    errors = check_inventory(
        src=root / "src",
        suite_sh=root / "scripts" / "run-fault-injection-suite.sh",
        suite_ps1=root / "scripts" / "run-fault-injection-suite.ps1",
        fault_docs=fault_docs if fault_docs.is_file() else None,
    )
    if errors:
        print("fault-suite inventory check FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    tests = discover_fail_closed_tests(root / "src")
    claims = (
        discover_doc_suite_claims(fault_docs) if fault_docs.is_file() else set()
    )
    suite_filters = discover_suite_filters(
        (root / "scripts" / "run-fault-injection-suite.sh").read_text(encoding="utf-8")
    ) | discover_suite_filters(
        (root / "scripts" / "run-fault-injection-suite.ps1").read_text(encoding="utf-8")
    )
    unique = len(set(tests) | REQUIRED_CURATED)
    features = discover_suite_features(
        (root / "scripts" / "run-fault-injection-suite.sh").read_text(encoding="utf-8")
    ) or set()
    feature_csv = ",".join(sorted(features)) if features else "(missing)"
    print(
        f"OK: {len(tests)} auto-discovered fail-closed probes plus "
        f"{len(REQUIRED_CURATED)} required curated cases "
        f"({unique} unique) are listed in both fault-injection suite runners; "
        f"{len(claims)} fault-injection.md Suite claims are curated; "
        f"{len(suite_filters)} suite filters are inventory-protected; "
        f"suite features={feature_csv}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
