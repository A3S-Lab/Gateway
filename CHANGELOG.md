# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- An inference route bound only to TCP or UDP listeners now fails at
  validate. Inference reads the HTTP request body; a raw listener never
  reaches that parser, so the route looked active and never admitted a
  model call. An omitted entrypoint list is the same failure when every
  configured listener is non-HTTP. Covered by
  `inference_route_on_non_http_entrypoint_is_not_a_silent_noop`.
- A static bundle routed only through TCP or UDP listeners now fails at
  validate. Object bytes are served on the HTTP path; a raw listener matched
  the router and then dropped the connection. An omitted entrypoint list is
  the same failure when every configured listener is non-HTTP. Covered by
  `static_bundle_on_non_http_entrypoint_is_not_a_silent_noop`.
- Router middleware bound only to TCP or UDP entrypoints now fails at
  validate. The HTTP pipeline is the only place that chain runs, so an
  `api-key` or rate limit on a raw listener was accepted and never enforced.
  An omitted entrypoint list is the same failure when every configured
  listener is TCP or UDP. A router that is also bound to an HTTP entrypoint,
  and a config with no listeners yet, are unchanged. Covered by
  `router_middleware_on_non_http_entrypoint_is_not_a_silent_noop`.
- Traffic mirror targets whose backends are only non-HTTP schemes now fail
  at validate. Mirror copies use the HTTP proxy and discard failures, so a
  `tcp://`, `udp://`, `h2c://`, or WebSocket shadow looked enabled while no
  copy could succeed. `percentage = 0` and an empty shadow server list are
  unchanged. Covered by `mirror_target_must_speak_http`.
- Sticky cookie affinity on a service whose backends are only `tcp://` or
  `udp://` now fails at validate. Those listeners never read or write
  `Set-Cookie`, so the ACL claimed session affinity that could not apply.
  HTTP, gRPC, and WebSocket backends are unchanged. Covered by
  `sticky_on_tcp_backends_is_not_a_silent_noop`.
- Listener fields that the selected protocol does not enforce now fail at
  validate. An HTTP entrypoint with `tcp_allowed_ips` was accepted while
  every client could connect, and a TCP or UDP entrypoint with `tls` was
  accepted while the listener never terminated TLS. Covered by
  `http_tcp_allowlist_is_not_a_silent_noop` and `tcp_tls_is_not_a_silent_noop`.
- TCP and UDP dial failures now count as upstream transport errors, so the
  always-on passive health checker can remove a dead backend. Connection
  refusal was previously `ServiceUnavailable`, the same variant as local
  admission, which must not eject a backend. Covered by
  `dial_failure_marks_backend_unhealthy_but_admission_does_not` and
  `test_connect_upstream_invalid`.
- TCP and UDP dial the parsed host and port. A scheme prefix is no longer
  left in the address (`ws://` was dialed as host `ws`), omitted `https`/`wss`
  ports become 443, and a URL path is not part of the socket. `tcp` and `udp`
  URLs without an explicit port fail at validate. Covered by
  `test_extract_address_https_default_port_and_ignored_path` and
  `test_validate_server_url_rejects_unknown_scheme`.
- HTTP, gRPC, and WebSocket forwards now reject backends whose scheme they
  do not speak. Prefixing `http://` or `ws://` onto `tcp://` parsed as host
  `tcp` and could dial the wrong machine. Covered by
  `http_forward_rejects_non_http_backend_scheme`,
  `test_normalized_grpc_backend_rejects_non_grpc_scheme`, and
  `test_build_ws_url_rejects_non_websocket_scheme`.
- Upstream server URLs now reject schemes the data plane does not speak.
  `ftp://` and other unknown schemes fail at validate instead of staying
  healthy and failing on the first forward. Accepted schemes are `http`,
  `https`, `h2c`, `ws`, `wss`, `tcp`, and `udp`. Covered by
  `test_validate_server_url_rejects_unknown_scheme`.
- Failover to a backup service now uses that service's upstream TLS client
  (HTTP, gRPC, and WebSocket), so a backup `tls_ca_file` is not ignored in
  favor of the primary route's trust store. Covered by
  `failover_backend_uses_backup_upstream_tls_service`.
- WebSocket upgrades to `https` backends now use rustls with the public webpki
  roots, the same trust store as the HTTP proxy. A service `tls_ca_file`
  replaces those roots on the upgrade path (`ws_tls_for`) and is built at
  `validate_activation`, so a private CA cannot be skipped and an unusable PEM
  cannot wait until the first handshake. Covered by
  `validate_activation_probes_service_tls_ca_websocket_clients`.
- Published soak gate refuses `A3S_GATEWAY_PUBLISH_MIN_DURATION` below 7200s.
  The env may only raise the 2h floor; a short run can no longer be marked
  `envelope_status=published` by lowering it. A failed published run is written
  as `publish-refused-*.json` (`envelope_status=publish-refused`), not
  `published-*.json`. `--out` cannot place a non-published result under a
  `published-*` filename. Published wrappers build with `cargo build --locked`
  so an unlocked dependency set cannot become the capacity envelope. A passing
  published run without `a3s-gateway --version` or a 40-character lowercase git
  sha embedded in that version string is `publish-refused`, not `published`.
  The recorded sha is the binary's commit, not the working tree. A dirty build
  cannot be published. Landing the published-envelopes gate requires a passing
  dedicated artifact per profile (`http-json`, `sse-finite`, `openai-json`,
  `openai-sse`) with duration >= 7200s and hardware pins. Covered by
  `test_soak_envelope_status.py` and `test_enterprise_ga_status.py`.
- Enterprise GA status verifier refuses committed `lab-*.json` / `smoke-*.json`
  that drop the soak-result contract (`schema`, matching profile filename,
  `pass: true`, empty `fail_reasons`, `requests.err=0`, positive `ok`, and
  `ok_per_sec`). `ok_per_sec` must equal `round(ok/duration_secs, 2)` so a
  committed rate cannot be invented. Smoke artifacts record `ok_per_sec` from
  their existing ok counts and durations. Covered by
  `test_enterprise_ga_status.py`.
- Enterprise GA status verifier refuses committed `smoke-*.json` that is not
  `envelope_status=smoke-only` or that omits `hardware.dedicated_runner=false`
  while published-envelopes is Open. Existing smoke artifacts now declare
  `dedicated_runner: false`. Covered by `test_enterprise_ga_status.py`.
- Enterprise GA status verifier refuses capacity-envelope-draft table rows that
  drift from committed `lab-*.json` (profile, duration, concurrency, ok/s, RSS
  growth, host, pass) and refuses committed `lab-*.json` missing from that
  table. Covered by `test_enterprise_ga_status.py`.
- Enterprise GA status verifier refuses production-adoption template soft-opens
  that drop `<!-- enterprise-ga: adoption_status=template -->` (disclaimer text
  alone is insufficient). While security-review is Open, refuses threat-model
  soft-opens that drop Production Candidate authorship, “still required for
  Enterprise GA”, or “Claiming Enterprise GA from this document alone”, and
  refuses `Status: **Enterprise GA**`. Threat-model Landed also requires
  `SECURITY.md` keep private vulnerability reporting guidance. Covered by
  `test_enterprise_ga_status.py`.
- Soak wrapper inventory refuses dropping any of the four envelope profiles
  (`http-json`, `sse-finite`, `openai-json`, `openai-sse`) from smoke /
  lab-extended / published wrappers. Publish-gate Landed also refuses
  `dedicated-hardware-envelopes.md` soft-opens that drop “never be relabeled”,
  the 2h-floor Non-goal, or the CI/laptop Non-goal. Covered by
  `test_enterprise_ga_status.py`.
- Capacity/soak smoke wrappers pin `--envelope-status smoke-only` (sh + ps1) so
  CI smoke cannot inherit a changed soak-gateway.py default. Enterprise GA
  status verifier refuses soak wrapper soft-opens that drop pinned statuses
  (`smoke-only` / `lab-extended` / `published`) or published wrappers that drop
  `A3S_GATEWAY_DEDICATED_RUNNER` / the 7200s floor. Covered by
  `test_enterprise_ga_status.py`.
- Enterprise GA status verifier refuses capacity-envelope-draft soft-opens while
  published-envelopes is Open (`**Status: published.**` / missing not-published
  disclaimer). Also refuses security-review-package.md dropping its
  “does not close the Enterprise GA security gate” disclaimer while
  security-review is Open. Checklist parser no longer skips gate rows whose
  Evidence column mentions the word `Status` (that soft-open dropped
  published-envelopes from the gate map). Covered by
  `test_enterprise_ga_status.py`.
- Fault-suite inventory refuses docs↔Suite feature soft-opens: when
  `fault-injection.md` is present it must claim `kube,redis,wire` (same set as
  `REQUIRED_SUITE_FEATURES` / Suite runners). Covered by
  `test_fault_suite_inventory.py`.
- Enterprise GA status verifier refuses deleting or weakening
  `lab-drill-adoption.md` while production-adoption is Open (lab drill must
  remain explicitly distinct from the case-study gate). Capacity-harness Landed
  evidence also requires that file. Covered by `test_enterprise_ga_status.py`.
- Enterprise GA status verifier refuses CI soft-opens that keep inventory
  checkers but drop their unit tests (`test_fault_suite_inventory.py`,
  `test_managed_runtime_evidence_inventory.py`,
  `test_runbook_evidence_inventory.py`). Those test files are also Landed
  fault-injection evidence.
- Fault-suite inventory auto-discovers ACME/discovery validate≡activate positive
  legs (`validate_activation_accepts_*`, `test_validate_activation_builds_*`)
  claimed in first-principles. Curated 4 Suite escapes into both runners +
  Controller matrix/runbook.
- Managed-runtime inventory OK line uses ASCII `sh==ps1` (Windows console-safe).
- Fault-suite inventory auto-discovers path-aware
  `validate_activation_at_path_*` so the positive twin of
  `gateway_new_at_path_fails_closed_when_config_parent_missing` cannot soft-open
  out of `enterprise-ga-smoke`. Curated
  `validate_activation_at_path_attaches_config_parent_watch` into both runners +
  Controller matrix/runbook.
- Capacity-harness Landed evidence now requires lab-extended soak wrappers
  (`run-soak-gateway-extended.{sh,ps1}`) and `capacity-envelope-draft.md`. While
  published-envelopes is Open, committed `lab-*.json` must keep
  `envelope_status=lab-extended` and `hardware.dedicated_runner=false` (refuse
  silent relabel). Covered by `test_enterprise_ga_status.py`.
- Runbook Verify evidence inventory (`check-runbook-evidence-inventory.py`)
  refuses operator-runbook soft-opens: every exact/`family_*` Verify claim in
  the five failure-class runbooks must stay curated in both fault-injection
  suite runners and `fault-injection.md`. Wired into `enterprise-ga-smoke` and
  the Enterprise GA status verifier. Covered by
  `test_runbook_evidence_inventory.py`.
- Fault-suite inventory auto-discovers validate≡activate positive/skip/prepare
  legs (`validate_activation_probes_*`, `validate_activation_skips_*`,
  `validate_activation_prepares_*`, `load_merged_gateway_config_probes_*`,
  `probe_*_activation_accepts_*`) so the middle triad cannot soft-open out of
  `enterprise-ga-smoke` while fail-closed twins remain curated. Curated 14
  Suite escapes into both runners + Controller/Network matrix.
- Enterprise GA status verifier refuses CI soft-opens that drop the
  `supply-chain-audit` job (`cargo audit --deny warnings`) while ROADMAP still
  claims supply-chain assurance. Covered by `test_enterprise_ga_status.py`.
- Fault-suite inventory refuses Suite `FEATURE_CSV` / `$FeaturesArg` soft-opens:
  both runners must keep at least `kube,redis,wire` so wire `fail_closed` (and
  redis/kube) curated filters cannot soft-open by downgrading cargo features
  while filter names remain listed. Shell and PowerShell feature sets must also
  match (same soft-open class as filter-set mismatch). Covered by
  `test_fault_suite_inventory.py`.
- Fault-injection suite default features are now `kube,redis,wire` so CHANGELOG
  wire `fail_closed` escalation blocks cannot soft-open out of
  `enterprise-ga-smoke`. Curated `fail_closed_blocks_escalation_in_upstream_response`,
  `blocks_escalation_on_response_when_fail_closed`, and WEB0.4
  `sealed_content_encoding_is_emitted_without_accept_encoding_negotiation` into
  both runners + Listener/Disk matrix.
- Fault-suite inventory auto-discovers WEB0.4 SPA / sealed-byte soft-open
  prevention claimed in first-principles (`spa_fallback_*`, HEAD-without-GET,
  compress no-transform, inflight GET drain across runtime replace). Curated 5
  Suite escapes into both runners + Disk matrix/runbook.
- Fault-suite inventory auto-discovers validate soft-open prevention for
  Node API management auth/mTLS, empty/duplicate discovery seeds, health-check
  noop servers, sticky cookie names, non-`.acl` main config, unusable health/
  gRPC CA PEM, and platform Docker unix-socket hosts. Curated 16 Suite escapes
  into both runners + Controller matrix/runbook (Unix socket-path + Windows
  unix-host rejects platform-gated).
- Fault-suite inventory auto-discovers managed live-listener fail-closed /
  without-upstream soft-open proofs claimed in first-principles (snapshot
  expiry HTTP/TCP/UDP, credential/grant successor revoke, usage-capacity and
  policy-expiry inference). Curated 11 Suite escapes into both runners +
  Listener matrix and operator runbooks; synced Controller/Upstream runbook
  Verify lists with already-curated Docker/K8s/scheduled/file-watch/sticky/
  mirror Suite filters.
- Fault-suite inventory auto-discovers config-validate and listener-policy
  fail-closed families claimed in first-principles
  (`test_validate_*_fails_closed`, `*_fails_listener_policy`). Curated 7 Suite
  escapes into both runners + Listener/Controller matrix and operator
  runbooks (UDP zero timeout, ACME email/domains, TCP allowed-IP policy).
- Fault-suite inventory auto-discovers construct/provider fail-closed families
  that escaped `validate_`/`probe_activation_*` naming
  (`probe_*_activation_rejects_*`, `*_fails_gateway_construct_closed`,
  `*_fails_construct_closed`, `standalone_*_fails_validate`,
  `cloud_managed_*_fail_validate`, Windows
  `default_docker_block_fails_validate_on_windows`). Curated 12 Suite escapes
  into both runners + Controller/Disk matrix (Unix Managed Service symlink /
  permissions construct probes; Windows empty `docker {}` validate).
- Fault-suite inventory auto-discovers Docker/K8s provider translation,
  file-watch `load_config`/`watch`, sticky/mirror build-time, and scheduled-
  models / expired-worker fail-closed families claimed in first-principles
  (28 Suite escapes curated into both runners + Controller/Upstream matrix).
  Inventory OK-line now reports unique auto∪REQUIRED coverage instead of
  double-counting overlap.
- Fault-suite inventory auto-discovers `validate_activation_rejects_*`,
  `load_merged_gateway_config_fails_closed_*`, and
  `with_middlewares_fails_closed_*`, curating the first-principles fail-closed
  cases that escaped Suite
  (`load_merged_gateway_config_fails_closed_when_directory_missing`,
  `with_middlewares_fails_closed_on_dual_retry_with_custom_policy`,
  `validate_activation_rejects_cloud_managed_bootstrap_with_inline_traffic`,
  reserved managed-service name rejects). Inventory now requires FILTER
  membership (not substring) and sh≡ps1 filter-set equality; Managed Runtime
  evidence inventory gains the same orphan / docs↔code / sh≡ps1 protections.
- Curated ACME activate-path fail-closed twin
  `activate_stored_certificate_fails_closed_when_sink_rejects_unusable_pem` into
  both suite runners / Controller matrix / `REQUIRED_CURATED` (validate stored-
  PEM twin was already curated). Fault-suite filter discovery now parses
  PowerShell `$Filters +=` Unix-only appends. Enterprise GA status verifier is
  tracked as its own Landed checklist gate (evidence + CI self-check). ROADMAP
  Standalone operations promotion gate no longer asks to "add" fault-injection
  evidence that the checklist already marks Landed.
- Fault-suite inventory now refuses unprotected suite orphans (filters listed
  in either runner but neither auto-discovered nor `REQUIRED_CURATED`), and
  `check-enterprise-ga-status.py` Landed evidence now requires operator
  runbooks, Windows published-soak runner, soak smoke scripts, plus CI wiring
  for soak smoke / envelope-status when those gates are Landed. Listener and
  network runbooks Verify align with matrix ACME and `redis_fail_open` twins.
- Fault-suite inventory now also fail-closes doc→suite drift: every full test
  name claimed as Automated evidence in `docs/ops/fault-injection.md` must
  appear in both suite runners (Managed Runtime `real_os_process_*` stay on
  their own inventory). Controller runbook Verify aligns with the Controller
  matrix forward-auth validate≡activate twins and drops the misplaced Disk
  `usage_spool_locked` entry.
- Disk fault-injection matrix and `disk-failure` runbook Verify now list the
  already-curated validate≡activate Disk twins
  (`probe_activation_fails_closed_when_exclusive_lock_is_held`,
  `probe_activation_fails_closed_when_spool_parent_is_not_a_directory`,
  `probe_activation_fails_closed_when_ready_epoch_record_is_corrupt`,
  `probe_activation_fails_closed_when_prepared_epoch_record_is_corrupt`,
  `probe_activation_fails_closed_when_recovery_artifact_is_a_directory`) plus
  construct-path managed-state / static-digest cases that were suite-curated
  but under-documented for operators.
- Fault-suite inventory now auto-discovers
  `probe_activation_rejects_unreachable_*` /
  `probe_activation_accepts_reachable_*` and curates the middleware
  validate≡activate twins already claimed in first-principles
  (`probe_activation_rejects_unreachable_auth_service`,
  `probe_activation_accepts_reachable_auth_service`,
  `probe_activation_rejects_unreachable_redis`) into both suite runners /
  Controller+Network matrix — closing the last forward-auth / Redis probe
  soft-opens that sat beside curated `validate_activation_fails_closed_when_*`
  twins only.
- Fault-suite inventory now auto-discovers
  `probe_activation_accepts_*_like_open` and curates
  `probe_activation_accepts_deleted_retiring_epoch_like_open` plus
  `probe_activation_write_probe_leaves_no_untracked_artifact` into both suite
  runners / Disk matrix — closing the last Disk validate≡activate proofs that
  escaped `(rejects|projects)_*_like_open` discovery. `check-enterprise-ga-status.py`
  now also runs `check-managed-runtime-evidence-inventory.py` (and requires CI
  to) the same way as the fault-suite inventory.
- Fault-suite inventory now auto-discovers
  `probe_activation_(rejects|projects)_*_like_open` (Disk capacity Full twins +
  reclaim/compaction projections) and curates
  `probe_activation_rejects_retained_bytes_over_capacity_like_open`,
  `probe_activation_rejects_missing_boot_epoch_headroom_like_open`, and
  `probe_activation_rejects_untracked_paths_like_open` into both suite runners —
  first-principles already claimed these validate≡activate contracts but they
  could soft-open out of `enterprise-ga-smoke` after only `projects_*` landed.
- Curated Enterprise GA fault-injection suite now runs and inventory-protects
  the Disk capacity-projection probes already claimed in
  `docs/ops/runbooks/disk-failure.md` Verify
  (`probe_activation_projects_empty_epoch_reclaim_before_capacity_like_open`,
  `probe_activation_projects_partial_ack_compaction_before_capacity_like_open`),
  closing a false Suite claim. Also lands
  `scripts/check-managed-runtime-evidence-inventory.py` so new
  `real_os_process_upstream_*` cases cannot soft-open out of
  `run-managed-runtime-evidence.*` / `enterprise-ga-smoke` (wired in CI next to
  the fault-suite inventory check).
- Usage spool boot-epoch capacity projection no longer samples live
  `Utc::now()` digit width: `probe_activation` and `open` share a fixed
  max-width sentinel so RFC3339 fractional-second length cannot soft-open
  validate while cold start `Full`-fails (caught by the empty-epoch reclaim
  probe when curated into the suite).
- Managed Runtime real OS-process evidence now covers restart → route restore
  and exact-generation replay identity preservation against a living child
  upstream
  (`real_os_process_upstream_restart_restores_route_and_replay_preserves_identity`),
  closing the gap where ROADMAP/README claimed restart replay while
  `run-managed-runtime-evidence.*` only ran bind/drain/stream cases. Wired into
  both evidence runners and Enterprise GA smoke.
- Curated Enterprise GA fault-injection suite now inventory-protects the Unix
  Disk permissions proof
  (`spool_storage_is_private_and_insecure_permissions_fail_closed`) and adds
  the already-landed corrupt Managed Service state construct fail-closed case
  (`corrupt_managed_service_state_fails_gateway_construct_closed`) to both
  suite runners + `REQUIRED_CURATED`, closing the Disk-row evidence soft-open
  where MS-state corrupt was claimed but only owner-lock was curated.
- Curated Enterprise GA fault-injection suite now inventory-protects the
  remaining Upstream health/circuit/failover listener proofs and Disk
  construct-path regressions already claimed in ROADMAP /
  `docs/ops/fault-injection.md` (`passive_health_half_open_*`,
  `circuit_breaker_half_open_*`, `failover_routes_to_backup_*`,
  `active_health_*`, `gateway_new_fails_closed_on_a_usage_spool_identity_mismatch`,
  `with_managed_service_state_fails_construct_when_owner_lock_held`,
  `reload_rejects_standalone_to_cloud_managed_transition`). Every non-auto
  filter in both suite runners is now in `REQUIRED_CURATED`, so matrix
  evidence cannot soft-open out of `enterprise-ga-smoke`.
- Curated Enterprise GA fault-injection suite now inventory-protects the full
  Listener fail-closed bar already claimed in ROADMAP /
  `docs/ops/fault-injection.md`: the remaining response-middleware proofs
  (HTTP/SSE/gRPC/distributed JSON+SSE/native models), both `forward_auth`
  live-listener proofs, and the Redis fail-closed `503` twin of curated
  `redis_fail_open`. Previously only
  `response_middleware_error_fails_closed_on_proxy_failure` /
  `redis_fail_open` were in `REQUIRED_CURATED`, so siblings could soft-open
  out of `enterprise-ga-smoke` while the matrix still listed them.
- Optional `wire` feature: response-leg enforcement now honors sentry
  `blocked()` the same way as the request leg (`gate_response` after
  `ungate_response`). Fail-open still audits and forwards escalations;
  `fail_closed` / L2 `Block` returns `403` and withholds the completion
  (`blocks_escalation_on_response_when_fail_closed`,
  `fail_closed_blocks_escalation_in_upstream_response`).
- `reload_disabling_acme_aborts_manager` no longer soft-passes on invalid
  bootstrap PEMs (early `return` when `Gateway::new`/`start` failed). It now
  uses fixture TLS material + writable ACME storage and always asserts the
  manager handle is aborted when reload clears ACME entrypoints; curated into
  the fault suite / `REQUIRED_CURATED` so `enterprise-ga-smoke` cannot skip it.
- Curated Enterprise GA fault-injection suite now executes the Redis
  `redis_fail_open` listener contract already claimed in ROADMAP /
  first-principles
  (`rate_limit_redis_fail_open_reaches_upstream_on_listener_when_redis_unreachable`),
  pairing the fail-closed `503` case already in smoke; `REQUIRED_CURATED`
  refuses silent drift.
- Curated Enterprise GA fault-injection suite now executes ROADMAP balancing
  listener proofs already claimed in first-principles /
  `ROADMAP.md` (`sticky_session_cookie_pins_backend_on_listener`,
  `sticky_session_cookie_pins_websocket_backend_on_listener`,
  `traffic_mirror_copies_buffered_request_to_shadow_on_listener`,
  `traffic_mirror_primary_still_succeeds_when_shadow_unreachable_on_listener`),
  and `REQUIRED_CURATED` refuses silent drift if any leave the suite runners.
- Curated Enterprise GA fault-injection suite now executes
  `response_middleware_error_fails_closed_on_proxy_failure` (response middleware
  must fail closed on the proxy-failure path without leaking upstream body),
  already claimed in CHANGELOG / first-principles but previously absent from
  `enterprise-ga-smoke`; `REQUIRED_CURATED` refuses silent drift.
- Curated Enterprise GA fault-injection suite now executes the CLI
  validate≡activate path regressions already claimed in runbooks /
  first-principles docs (`gateway_new_at_path_fails_closed_when_config_parent_missing`,
  `load_merged_gateway_config_fails_closed_on_missing_entrypoint_tls_pem`,
  `load_merged_gateway_config_fails_closed_when_management_token_env_unset`),
  and `check-fault-suite-inventory.py` `REQUIRED_CURATED` refuses silent drift
  if any leave the shell/PowerShell runners.
- Power `distributed_serving.api_key_env` fail-closed evidence now exercises the
  shared activation credential probe used by composed cloud-managed runtimes
  (`validate_runtime_activation` / `validate_activation` inner), covering both
  unset and present-but-invalid credentials so structural `config.validate`
  alone cannot soft-open a promotion claim. Covered by
  `validate_activation_fails_closed_when_distributed_serving_api_key_env_unset`
  and `validate_activation_fails_closed_when_distributed_serving_api_key_invalid`
  (replaces helper-only
  `distributed_serving_api_key_env_unset_fails_credential_activation`).
- Curated Enterprise GA fault-injection suite now executes the ACME listener
  regressions already claimed in `docs/ops/fault-injection.md`
  (`acme_http01_challenge_is_served_from_runtime_store_before_routes`,
  `acme_certificate_install_hot_swaps_live_https_acceptor`), and
  `check-fault-suite-inventory.py` refuses silent drift if either name leaves
  the shell/PowerShell runners — so ACME issuance-path evidence cannot
  soft-open out of `enterprise-ga-smoke` while the matrix still lists it.
- ACME `validate_activation` / cold start no longer soft-open Running when
  storage already holds domain certificates whose PEMs cannot build the same
  rustls acceptor as hot-install (`CertStorage::probe_existing_domain_certificates`
  + fail-closed `activate_stored_certificate` before ACME task spawn). Valid
  expiry timestamps with corrupt PEMs also re-enter `check_and_renew` instead
  of forever-skipping issuance. Covered by
  `validate_activation_fails_closed_when_acme_stored_cert_pem_corrupt`,
  `validate_activation_accepts_usable_acme_stored_cert_pem`, and
  `activate_stored_certificate_fails_closed_when_sink_rejects_unusable_pem`.
- ACME-issued (and previously stored) certificates are hot-installed onto live
  HTTPS listeners via `build_tls_acceptor_from_pem` +
  `EntryPointHandle::install_http_tls_acceptor`, so issuance cannot soft-open
  Running while only bootstrap PEMs terminate TLS. Covered by
  `acme_certificate_install_hot_swaps_live_https_acceptor`,
  `activate_stored_certificate_loads_from_storage`, and
  `test_build_tls_acceptor_from_pem_matches_file_surface`.
- ACME HTTP-01 challenges are served from the same `ChallengeStore` Arc the
  manager writes: `GatewayRuntime` attaches the store when the ACME manager
  starts/restarts, and the HTTP data plane answers
  `/.well-known/acme-challenge/*` before route match so issuance cannot
  soft-open a forever-warn loop while challenges only 404. Covered by
  `acme_http01_challenge_is_served_from_runtime_store_before_routes`.
- `Gateway::new_at_path` / `with_middlewares_at_path` /
  `validate_activation_with_custom_middlewares_at_path` probe the same root ACL
  parent watch surface as `FileWatcher::watch` when `providers.file.watch` is
  enabled, so path-aware embedders and CLI `run` cannot soft-open construct
  while only hot reload attaches the config parent. Covered by
  `validate_activation_at_path_attaches_config_parent_watch` and
  `gateway_new_at_path_fails_closed_when_config_parent_missing`.
- `load_merged_gateway_config` rejects non-`.acl` root paths with the same
  extension gate as conf.d merge, so `FileWatcher::load_config` /
  CLI load cannot soft-open a `.txt` (or other) main file when no directory
  merge runs. Covered by `test_load_config_rejects_non_acl_main_extension`.
- Fail-closed fault-suite inventory verifier
  (`scripts/check-fault-suite-inventory.py`,
  `scripts/test_fault_suite_inventory.py`) refuses silent drift when an in-tree
  `validate_activation_fails_closed_*` / `probe_activation_fails_closed_*`
  regression is missing from both curated suite runners. Wired into
  `enterprise-ga-smoke` and the Landed fault-injection evidence check. Suite
  filters now also include the complementary usage-spool
  `probe_activation_fails_closed_*` cases that previously existed only as
  unit tests.
- Enterprise GA evidence foundation: curated fault-injection suite and operator
  runbooks for listener / upstream / controller / disk / network failures
  (`docs/ops/`, `scripts/run-fault-injection-suite.sh`,
  `scripts/run-fault-injection-suite.ps1`), plus an authored threat model and
  `SECURITY.md`. Capacity/soak harness and smoke runners landed
  (`docs/ops/capacity-and-soak.md`, `scripts/soak-gateway.py`,
  `scripts/run-soak-gateway-smoke.{sh,ps1}`, `benchmarks/soak/`). Added
  `docs/ops/enterprise-ga-checklist.md`, `docs/ops/security-review-package.md`,
  and CI job `enterprise-ga-smoke` (matrix: `ubuntu-latest` + `windows-latest`
  for fault suite, Managed Runtime real OS-process evidence,
  soak smoke, and GA status verifiers). OpenAI-shaped soak
  profiles (`openai-json`, `openai-sse`), lab-extended runner, capacity envelope
  draft, and lab-drill doc landed without claiming published envelopes or
  production adoption.
  Fail-closed dedicated-runner publish path
  (`docs/ops/dedicated-hardware-envelopes.md`,
  `scripts/run-soak-gateway-published.*`,
  `scripts/test_soak_envelope_status.py`) and CI `supply-chain-audit`
  (`cargo audit`) landed. Fail-closed Enterprise GA status verifier
  (`scripts/check-enterprise-ga-status.py`,
  `scripts/test_enterprise_ga_status.py`) refuses checklist/ROADMAP/soak
  false promotion while Open gates remain. Security-review and production-
  adoption markers (`security-review-findings.md` unsigned,
  `production-adoption-template.md`) refuse silent sign-off. Default
  fault-injection suite now always builds with `--features kube,redis` and
  includes Redis network fail-closed, active health eviction/readmit, active
  health redirect non-follow, Box scale / kube client / Ingress list / k8s
  autoscaler kubeconfig / Scale subresource / gRPC TLS CA / invalid health-check
  interval / relative ACME storage / unusable health-check TLS CA activation
  cases, forward-auth deny without upstream contact, usage-spool identity
  mismatch at `Gateway::new`, Power `api_key_env` unset credential activation,
  and usage Cloud-ingest activation cases (no `A3S_GATEWAY_FAULT_REDIS`
  opt-in). Curated suite now includes every in-tree
  `validate_activation_fails_closed_*` regression. File-watch notify activation
  and missing conf.d directory fail closed at `validate_activation` (not only
  at CLI `load_merged` / hot-reload start).
  Published dedicated-hardware envelopes, independent review sign-off, and a
  filled production adoption case study remain open.

### Fixed

- Cold-start usage-spool activation now create_new-probes spool directory
  writability the same way `open` allocates a boot epoch. An existing `.lock`
  alone can no longer soft-open validate while start fails to create
  `manifest.json` / epoch segments. Covered by
  `probe_activation_fails_closed_when_usage_spool_directory_is_not_writable`,
  `probe_activation_write_probe_leaves_no_untracked_artifact`, and
  `validate_activation_fails_closed_when_usage_spool_directory_is_not_writable`.
- Usage-spool activation projects partial-ack epoch compaction before capacity
  and boot-headroom checks. `open` shrinks the acknowledged prefix on reclaim;
  counting the full pre-compact segment at validate could Full-fail a spool
  start would compact then open. Covered by
  `probe_activation_projects_partial_ack_compaction_before_capacity_like_open`.
- Usage-spool activation projects empty / fully-acknowledged epoch reclaim
  before capacity and boot-headroom checks. `open` retires those epochs first;
  counting them at validate could Full-fail a spool start would reclaim then
  open. Covered by
  `probe_activation_projects_empty_epoch_reclaim_before_capacity_like_open`.
- Usage-spool activation now inspects the pre-compaction epoch file the same
  way `publish` does when a compacted staging file is already present. A
  directory at the final path can no longer pass `validate_activation` and
  then fail when start removes it. Covered by
  `probe_activation_fails_closed_when_compacting_epoch_final_is_a_directory`.
- Usage-spool activation no longer treats a crash-recovery artifact name as
  safe when the path is a directory. `open` deletes those names with
  `remove_file` and fails if that delete fails; `validate_activation` now
  fails the same way. A regular staging file is still accepted and removed on
  start. Covered by
  `probe_activation_fails_closed_when_recovery_artifact_is_a_directory` and
  `validate_activation_fails_closed_when_usage_spool_recovery_artifact_is_a_directory`.
- `validate_activation` / `Gateway::new` project usage-spool crash recovery
  without mutating the directory, then scan the same bytes `open` would scan.
  A corrupt Prepared or Compacting segment fails closed, and a Retiring epoch
  whose file recovery deletes is not a false failure. Covered by
  `probe_activation_fails_closed_when_prepared_epoch_record_is_corrupt`,
  `probe_activation_accepts_deleted_retiring_epoch_like_open`, and
  `validate_activation_fails_closed_when_usage_spool_prepared_epoch_corrupt`.
- `validate_activation` / `Gateway::new` no longer soft-open a Ready usage spool
  whose epoch JSONL records are corrupt. Cold start already fails in
  `segments::scan`; the activation probe runs that same scan. Covered by
  `probe_activation_fails_closed_when_ready_epoch_record_is_corrupt` and
  `validate_activation_fails_closed_when_usage_spool_epoch_record_corrupt`.
- Standalone `static_bundles.local_digest_store` no longer soft-opens
  `validate_activation` when a digest-named file exists but its bytes or size
  disagree with the sealed entry. Validate uses the same size and SHA-256
  admission as the first GET (`admit_object_bytes`). Covered by
  `validate_activation_fails_closed_when_static_bundle_object_digest_mismatches`.
- Configured `managed.state_file` no longer soft-opens `validate_activation`
  when the journal is absent but its parent cannot be created or written (same
  `create_dir_all` + staging write surface as the first durable apply). Covered
  by `validate_activation_fails_closed_when_managed_snapshot_journal_parent_unusable`.
- ACME `validate_activation` / cold start no longer soft-open a forever-warn
  renewal loop when storage already contains a corrupt or unreadable
  `account.key`. `CertStorage::probe_activation` parses a present key with the
  same PKCS#8 surface as `ensure_account_key` (missing key still allowed —
  generated on first issuance). Covered by
  `validate_activation_fails_closed_when_acme_account_key_corrupt` and
  `validate_activation_accepts_usable_acme_account_key`.
- Cold-start `validate_activation` / `Gateway::new` no longer soft-open when
  another process holds `managed.usage_spool` `.lock` while `start` would fail
  with `UsageSpoolError::Locked`, or when the spool directory is missing and
  its parent cannot be created (same `create_dir_all` surface as `open`).
  Exclusive-lock contention and missing-dir create are probed at cold validate;
  runtime re-validation after open skips both. Covered by
  `probe_activation_fails_closed_when_exclusive_lock_is_held`,
  `probe_activation_fails_closed_when_spool_parent_is_not_a_directory`,
  `validate_activation_fails_closed_when_usage_spool_locked`, and
  `validate_activation_fails_closed_when_usage_spool_parent_unusable`.
- `Gateway::with_managed_service_state` no longer soft-opens construct while
  another Gateway holds the Managed Service owner lock and only fails at
  `start`/`load`. Construct try-locks `.{state}.lock` and releases it
  immediately (same fail-closed pattern as usage-spool). Covered by
  `one_gateway_exclusively_owns_the_managed_service_state` and
  `with_managed_service_state_fails_construct_when_owner_lock_held`.
- `providers.file.watch` (ACL default `true`) no longer soft-opens
  `validate_activation` / `Gateway::new` while notify watcher creation or a
  configured conf.d directory only fails when CLI hot reload starts. Notify
  backend (+ optional directory attach) is probed at validate; path-aware
  `validate_activation_at_path` / `Gateway::new_at_path` /
  `load_merged_gateway_config` / CLI `run` attach the root ACL parent watch
  surface used by `FileWatcher::watch`. Covered by
  `validate_activation_at_path_attaches_config_parent_watch` and
  `gateway_new_at_path_fails_closed_when_config_parent_missing`.
- Kubernetes Ingress and IngressRoute CRD watchers no longer soft-retain a
  poisoned kube client when `Client::try_default` rebuild fails after a poll
  error. The poisoned client is dropped; rebuild retries retain the prior
  overlay without reusing the dead connection pool.

### Security

- Supply-chain remediation toward Enterprise GA `cargo audit --deny warnings`:
  upgraded rustls / rustls-webpki / aws-lc-sys / h2 / quinn-proto / tar /
  crossbeam-epoch / anyhow / event-listener / rand; migrated PEM parsing from
  unmaintained `rustls-pemfile` to `rustls-pki-types`; bumped `kube` 0.98→0.99
  (drops unmaintained `backoff`), `notify` 7→8 (drops unmaintained `instant`),
  `redis` 0.27→0.30, `tokio-tungstenite` 0.24→0.26. Bumped `kube` 0.99→2.0 /
  `k8s-openapi` 0.24→0.26 so the unused optional `http-proxy` →
  `rustls-pemfile` lock path is gone; `.cargo/audit.toml` ignore list is empty
  and `cargo audit --deny warnings` is clean.

### Added

- Cross-platform Managed Runtime Service real OS-process gRPC drain-wait:
  `managed-runtime-grpc-upstream` (HTTP/1 health + HTTP/2 hold) and
  `real_os_process_upstream_grpc_drain_waits_for_admitted_stream` prove
  `drain_managed_service` stays open while an admitted gRPC body is live
  against a child process — completing the real-process HTTP/SSE/WS/gRPC
  drain matrix (Windows + Unix).
- Cross-platform Managed Runtime Service real OS-process WebSocket drain-wait:
  `managed-runtime-upstream` holds `/ws-hold` until `POST /release`, and
  `real_os_process_upstream_websocket_drain_waits_for_admitted_stream` proves
  `drain_managed_service` stays open while an admitted WebSocket is live
  against a child process (Windows + Unix).
- Cross-platform Managed Runtime Service real OS-process SSE drain-wait:
  `managed-runtime-upstream` holds `/sse-hold` until `POST /release`, and
  `real_os_process_upstream_sse_drain_waits_for_admitted_stream` proves
  `drain_managed_service` stays open while an admitted SSE body is live
  against a child process (Windows + Unix).
- Managed Runtime Service drain evidence for an admitted SSE stream: after route
  hide, `drain_managed_service` waits on the `handle_sse_dispatch` response-body
  guard (`Accept: text/event-stream`), completing the HTTP / SSE / WebSocket /
  gRPC accepted-stream matrix. Covered by
  `drain_hides_then_waits_for_the_exact_admitted_sse_stream`.
- Cross-platform Managed Runtime Service real OS-process qualification:
  `tests/managed_runtime_real_process.rs` spawns the
  `managed-runtime-upstream` fixture child, then exercises bind (Gateway-path
  health) → private traffic → drain → remove on Windows and Unix. Covered by
  `real_os_process_upstream_survives_bind_health_traffic_drain_remove`. Host
  Use/Code provider composition remains outside this crate.

### Fixed

- `Gateway::with_middlewares` / construct now compiles router pipelines via the
  same `build_pipeline_cache` path as cold start, so ACL retry plus a custom
  `Middleware::retry_policy` on one router fails at construct instead of
  soft-opening `Created` until `start`/`reload`. Covered by
  `with_middlewares_fails_closed_on_dual_retry_with_custom_policy` and
  `build_pipeline_cache_rejects_acl_retry_plus_custom_retry_policy`.
- Per-service `tls_ca_file` now activates gRPC private-CA clients via the same
  `build_service_grpc_proxies` / `GrpcProxy::try_with_ca_file` path as HTTP
  (`build_service_http_proxies`), and gRPC dispatch selects
  `GatewayState::grpc_proxy_for` so application/grpc no longer soft-opens on
  system roots until the first forward. Covered by
  `validate_activation_probes_service_tls_ca_grpc_clients`,
  `validate_activation_fails_closed_on_unusable_service_tls_ca_for_grpc`,
  `grpc_proxy_try_with_ca_file_activates_private_trust_store`, and
  `grpc_proxy_try_with_ca_file_rejects_unusable_pem`.
- `validate_activation` now builds active health checkers via the same
  `ServiceRegistry::from_config` + `build_scaling_state` +
  `prepare_health_checks` path as cold start (including revision-pool
  checkers and duration revalidation), instead of probing only a bare HTTP
  client. Covered by `validate_activation_probes_health_check_http_clients`,
  `validate_activation_prepares_revision_health_checkers`, and
  `validate_activation_fails_closed_on_invalid_health_check_interval`.
- CLI `validate` / `load_merged_gateway_config` now probe the same notify
  `Watcher::new` + path attach surface as `FileWatcher::watch` when
  `providers.file.watch = true`, so validate cannot pass while
  `a3s-gateway run` later aborts because the watcher cannot start. Covered by
  `load_merged_gateway_config_probes_file_watch_when_enabled`,
  `probe_file_watch_activation_rejects_missing_directory`, and
  `probe_file_watch_activation_accepts_existing_paths`.
- `validate_activation` and cold start probe `providers.kubernetes` via the same
  Ingress list (and optional IngressRoute ConfigMap list) as the first watcher
  poll, so a buildable kube client cannot soft-open a forever-warn provider after
  logging "Kubernetes Ingress watcher started". Covered by
  `validate_activation_fails_closed_when_kubernetes_ingress_list_unreachable` and
  `validate_activation_probes_kubernetes_ingress_list` (`--features kube`).
- Labeled IngressRoute ConfigMaps no longer warn-and-skip unparseable or missing
  `data.spec`: parse failures fail the ConfigMap poll (and therefore activation
  when `ingress_route_crd` is enabled), so a partial overlay cannot soft-open.
  Covered by `parse_ingress_route_configmap_spec_rejects_malformed_json`,
  `parse_ingress_route_configmap_spec_rejects_wrong_shape`,
  `ingress_route_from_configmap_data_rejects_missing_data`, and
  `ingress_route_from_configmap_data_rejects_missing_spec`.
- Declared load-balancing `strategy` on Docker / Kubernetes Ingress /
  IngressRoute no longer soft-defaults invalid values to RoundRobin: present
  but unknown strategies fail conversion (and Kubernetes activation probes
  conversion). Absent strategy still defaults to RoundRobin. Covered by
  `parse_declared_strategy_rejects_unknown`,
  `generate_config_fails_closed_on_invalid_strategy_label`,
  `ingress_to_config_fails_closed_on_invalid_strategy_annotation`, and
  `ingress_routes_to_config_fails_closed_on_invalid_backend_strategy`.
- Docker `enable=true` containers no longer warn-and-skip on missing/invalid IP,
  missing/invalid/`0` `service.port`, or non-positive `service.weight`:
  `generate_config` fails closed and the poll loop retains the prior overlay.
  Covered by `generate_config_fails_closed_on_missing_port_label`,
  `generate_config_fails_closed_on_invalid_port_label`,
  `generate_config_fails_closed_on_missing_or_invalid_ip`, and
  `generate_config_fails_closed_on_invalid_weight_label`.
- Declared Docker/Kubernetes `protocol=tcp|udp` without a listen address no
  longer soft-opens an orphan service with no entrypoint; unknown protocol
  values no longer soft-default to HTTP. Covered by
  `generate_config_fails_closed_on_tcp_protocol_without_listen_address`,
  `generate_config_fails_closed_on_udp_protocol_without_listen_address`,
  `generate_config_fails_closed_on_unknown_protocol_label`,
  `ingress_to_config_fails_closed_on_tcp_without_listen`,
  `ingress_to_config_fails_closed_on_udp_without_listen`, and
  `ingress_to_config_fails_closed_on_unknown_protocol_annotation`.
- Declared Docker/Kubernetes router `priority` no longer soft-defaults invalid
  values to `0`: present but empty or non-integer priorities fail conversion.
  Absent priority still defaults to `0`. Covered by
  `parse_declared_priority_rejects_non_integer`,
  `generate_config_fails_closed_on_invalid_priority_label`, and
  `ingress_to_config_fails_closed_on_invalid_priority_annotation`.
- Kubernetes Ingress backends no longer soft-default `port.number == 0` to
  `:80`, and name-only backend ports fail closed (named ports are not
  resolved).   Covered by `ingress_to_config_fails_closed_on_zero_backend_port`,
  `ingress_to_config_fails_closed_on_named_backend_port_without_number`, and
  `ingress_to_config_uses_explicit_backend_port`.
- Declared Ingress `a3s-gateway.io/request-timeout` no longer soft-defaults
  present empty/whitespace (or unparseable) values to `30s`: conversion fails
  closed. Absent annotation still defaults to `30s`. Covered by
  `parse_declared_request_timeout_rejects_empty`,
  `ingress_to_config_fails_closed_on_empty_request_timeout_annotation`, and
  `ingress_to_config_fails_closed_on_invalid_request_timeout_annotation`.
- `validate_activation` probes standalone `scaling.executor = "k8s"` services via
  the same Deployment Scale `get_scale` observation as the first autoscaler
  reconcile (bounded by `executor_timeout_secs`), so a usable Kubernetes client
  alone cannot soft-open a Running autoscaler that only errors on the first tick.
  Covered by `validate_activation_fails_closed_when_k8s_scale_subresource_unreachable`
  and `validate_activation_probes_k8s_scale_subresource` (`--features kube`).
- `validate_activation` probes standalone Box autoscaling via the same
  `GET /v1/scale/{service}` observation as the first autoscaler reconcile
  (bounded by `executor_timeout_secs`), so a present `executor_endpoint` cannot
  soft-open a Running autoscaler that only errors on the first tick. Covered by
  `validate_activation_fails_closed_when_box_scale_unreachable`,
  `validate_activation_probes_box_scale_http_client`, and
  `probe_box_scale_activation_rejects_unreachable_executor`.
- `validate_activation` probes `forward-auth` middlewares with the same HTTP
  connect surface as the first auth request: any HTTP response proves
  reachability; connection errors fail closed so a present `forward_auth_url`
  cannot soft-open Running and only return 502 on traffic. Covered by
  `validate_activation_fails_closed_when_forward_auth_unreachable`,
  `validate_activation_probes_reachable_forward_auth`,
  `probe_activation_rejects_unreachable_auth_service`, and
  `probe_activation_accepts_reachable_auth_service`.
- `validate_activation` probes fail-closed `rate-limit-redis` middlewares with the
  same multiplexed connect + `PING` surface as the first rate-limit request, so a
  present `redis_url` cannot soft-open Running and only return 503 on traffic.
  Explicit `redis_fail_open = true` skips the probe. Covered by
  `validate_activation_fails_closed_when_redis_rate_limit_unreachable`,
  `validate_activation_skips_redis_probe_when_fail_open`,
  `probe_activation_rejects_unreachable_redis`, and
  `validate_skips_fail_open_middlewares` (`--features redis`).
- `validate_activation` and cold start probe `providers.docker` via Docker
  `/_ping` on the same transport as the poll loop, so a present Unix socket
  path or parseable TCP URL cannot soft-open a forever-warn poller when the
  daemon is unreachable. Covered by
  `validate_activation_fails_closed_when_docker_daemon_unreachable`,
  `validate_activation_probes_reachable_docker_daemon`,
  `test_gateway_start_tracks_docker_provider_handles`, and
  `reload_removing_docker_aborts_provider_handles`.
- `validate_activation` usage-spool probe now mirrors cold-start readiness
  beyond manifest identity: untracked directory paths, retained bytes over
  `max_bytes`, missing/unusable epoch files, insufficient headroom for the
  mandatory new boot epoch (manifest growth + epoch header), exclusive
  `.lock` contention, and missing-directory create/`create_dir_all` parent
  writability fail closed without allocating a boot epoch. Cold-start /
  CLI validate / `Gateway::new` probe lock + create; runtime re-validation
  after open skips both so the caller's held lock cannot soft-open or
  self-deadlock. Covered by
  `probe_activation_rejects_untracked_paths_like_open`,
  `probe_activation_rejects_retained_bytes_over_capacity_like_open`,
  `probe_activation_rejects_missing_boot_epoch_headroom_like_open`,
  `probe_activation_fails_closed_when_exclusive_lock_is_held`,
  `probe_activation_fails_closed_when_spool_parent_is_not_a_directory`,
  `validate_activation_fails_closed_when_usage_spool_has_untracked_file`,
  `validate_activation_fails_closed_when_usage_spool_locked`, and
  `validate_activation_fails_closed_when_usage_spool_parent_unusable`.
- `validate_activation` builds the Kubernetes client via the same
  `Client::try_default` surface as `prepare_kubernetes_client` / cold start
  (not kubeconfig YAML parse alone), so a parseable config with a missing CA
  or broken auth fails before Running. Covered by
  `validate_activation_fails_closed_when_kubernetes_kubeconfig_unusable`,
  `validate_activation_fails_closed_when_kubernetes_client_cannot_build`, and
  `validate_activation_fails_closed_when_k8s_autoscaler_kubeconfig_unusable`.
- Active health-check clients with `tls_ca_file` now parse CA material via
  `Certificate::from_pem_bundle` (and reject empty bundles) at
  `validate_activation` / `prepare_health_checks`. Under `rustls-tls`,
  `from_pem` only stores bytes, so junk PEM previously soft-opened an empty
  private trust store until HTTPS probes failed at runtime. Covered by
  `validate_activation_probes_health_check_http_clients` and
  `health_checker_probe_rejects_unusable_pem`.
- Operator/config hot reload now restarts dynamic providers (`discovery` /
  Docker / Kubernetes) and the ACME manager when `providers.*` or the ACME
  activation fingerprint changes, so validate≡activate does not leave stale
  poll loops or skip newly configured providers after reload. Provider overlay
  applies still use `reload_locked` without restarting those loops (avoids
  aborting the applying provider). Covered by
  `reload_adding_discovery_starts_poll_loop`,
  `reload_removing_docker_aborts_provider_handles`, and
  `reload_disabling_acme_aborts_manager`.
- Standalone Box autoscaling no longer soft-opens a Running autoscaler when the
  scale HTTP client cannot build: `BoxScaleExecutor::try_new` fails closed at
  `validate_activation` and `prepare_autoscaler` (same surface as Discovery /
  health-check client probes). Covered by
  `box_executor_client_initialization_failure_is_explicit` and
  `validate_activation_probes_box_scale_http_client`.
- Default upstream HTTP/gRPC TLS clients no longer soft-open as deferred
  `Result` fields that only fail on the first forward: `HttpProxy::try_with_timeouts`
  and `GrpcProxy::try_new` fail closed at `validate_activation` and
  `build_runtime` (same class as private `tls_ca_file` proxies and health-check
  `ensure_ready`). Covered by
  `try_with_timeouts_activates_default_upstream_tls_client`,
  `grpc_proxy_try_new_activates_tls_client`, and
  `validate_activation_probes_default_upstream_tls_clients`.
- Kubernetes Ingress/CRD watchers now take the client from
  `prepare_kubernetes_client` instead of soft-exiting on a second
  `Client::try_default` after startup already logged "watcher started". Poll
  poison still rebuilds via `try_default`. Covered by
  `ingress_watcher_keeps_running_with_prepared_client_when_kubeconfig_missing`.
- `validate_activation` builds per-service `tls_ca_file` HTTP proxies via
  `build_service_http_proxies` (same Hyper/rustls path as `build_runtime`), so
  PEM-only CA checks cannot soft-open a config that only fails when private-CA
  clients are constructed. Covered by
  `validate_activation_probes_service_tls_ca_http_clients`.
- `tls_ca_file` HTTPS detection now includes revision servers (same union as
  `health_check`), so revision-only HTTPS pools are not left on WebPKI while a
  private CA is declared, and private CA is not rejected when HTTPS lives only
  in revisions. Covered by
  `test_validate_accepts_tls_ca_file_with_revision_only_https_servers` and
  `test_validate_rejects_tls_ca_file_without_https_servers`.
- Standalone `static_bundles.local_digest_store` must exist and be a directory
  at validate (no soft-open as runtime 404). Covered by
  `standalone_missing_local_digest_store_directory_fails_validate`.
- CLI `run` and `validate` now load `providers.file.directory` conf.d
  fragments at cold start (not only after a hot-reload event), matching
  `FileWatcher` merge so validate ≡ activate even when `watch = false`.
  Missing directories fail closed. Covered by
  `load_merged_gateway_config_merges_directory_from_root_acl` and
  `load_merged_gateway_config_fails_closed_when_directory_missing`.
- `validate_activation` (CLI validate, merged load, and `Gateway::new`) now
  also runs entrypoint TLS PEM load and node API listener prepare so missing
  cert/key files or an unset management auth token fail before bind.
  Covered by `load_merged_gateway_config_fails_closed_on_missing_entrypoint_tls_pem`
  and `load_merged_gateway_config_fails_closed_when_management_token_env_unset`.
- `validate_activation` also builds the managed usage Cloud ingest transport
  (bearer env + mTLS PEM) with the same checks as `Gateway::start`, so unset
  `cloud_ingest_token_env` or invalid/missing mTLS identity/CA fail before
  bind. Covered by
  `validate_activation_fails_closed_when_usage_cloud_ingest_bearer_env_unset` and
  `validate_activation_fails_closed_when_usage_cloud_ingest_mtls_identity_missing`.
- `validate_activation` now includes `validate_managed_bootstrap`, so a
  cloud-managed ACL with `managed.gateway_id` that also defines inline routers,
  services, middlewares, or inference fails at CLI validate the same way as
  `Gateway::new`. Covered by
  `validate_activation_rejects_cloud_managed_bootstrap_with_inline_traffic`.
- `validate_activation` builds the discovery HTTP client via
  `DiscoveryProvider::new` (same path as `spawn_discovery_loop`) so a discovery
  block cannot soft-open until provider start. Covered by
  `test_validate_activation_builds_discovery_http_client`.
- `validate_activation` probes an existing `managed.state_file` journal with the
  same recovery checks as cold start (JSON/shape/gateway identity), so a
  corrupt or mismatched journal fails before bind. Covered by
  `validate_activation_fails_closed_on_corrupt_managed_snapshot_journal`.
- `validate_activation` probes an existing `managed.usage_spool` directory and
  `manifest.json` without allocating a new boot epoch, so gateway-id mismatch
  and corrupt manifests fail at CLI validate / `Gateway::new` the same way cold
  start would. Covered by
  `gateway_new_fails_closed_on_a_usage_spool_identity_mismatch`.
- Standalone `static_bundles.local_digest_store` now fails validate when a sealed
  manifest entry's digest object is missing from the store (no soft-open as
  runtime 404). Covered by
  `standalone_missing_digest_object_in_local_store_fails_validate`.
- Managed snapshot parse/apply and `validate_activation` resolve Power
  `distributed_serving.api_key_env` credentials with the same checks as
  `build_runtime`, so unset/invalid keys fail before bind. Covered by
  `distributed_serving_api_key_env_unset_fails_credential_activation`.
  (Superseded in Unreleased by
  `validate_activation_fails_closed_when_distributed_serving_api_key_env_unset`
  and
  `validate_activation_fails_closed_when_distributed_serving_api_key_invalid`.)
- `Gateway::with_managed_service_state` probes an existing Managed Service state
  file at construct (JSON/schema/perms/record validate) and exclusive
  owner-lock contention (try-lock + drop), so corrupt, inconsistent, or
  already-owned state fails before `Gateway::start`. Covered by
  `corrupt_managed_service_state_fails_gateway_construct_closed`,
  `retiring_state_without_the_exact_drain_key_fails_construct_closed`,
  `one_gateway_exclusively_owns_the_managed_service_state`, and
  `with_managed_service_state_fails_construct_when_owner_lock_held`.
- Managed Service construct probe also composes the overlay against the base ACL
  (same path as `effective_config`), so a Ready binding whose entrypoint was
  removed or that conflicts with a maximum-priority base router fails before
  `Gateway::start`. Covered by
  `ready_binding_missing_entrypoint_fails_gateway_construct_closed` and
  `ready_binding_max_priority_base_router_fails_gateway_construct_closed`.
- After Managed Service / managed-snapshot composition, `Gateway::start` and
  hot reload run `validate_runtime_activation` on the effective config (skipping
  bootstrap-empty-traffic rules that would reject legitimate composed traffic)
  so overlay/snapshot-derived TLS, discovery, usage spool, Power credentials,
  and ACME activation stay fail-closed through bind and reload. Host-owned
  Managed Service overlays keep generation-bound targets in standalone mode
  (reserved service prefix + overlay middleware signature); raw operator ACL
  cannot claim those reserved names. Covered by
  `ready_binding_with_targets_starts_gateway_closed_aligned`,
  `validate_activation_rejects_reserved_managed_service_middleware_name`, and
  `validate_activation_rejects_reserved_managed_service_name_prefix`.
- On non-Unix platforms, `providers.docker.host` Unix socket paths (including
  the default `/var/run/docker.sock` from an empty `docker {}` block) fail at
  validate instead of soft-opening a never-working provider poll loop. Covered
  by `validate_rejects_docker_unix_socket_host_on_non_unix`,
  `validate_accepts_docker_tcp_host_on_non_unix`, and
  `default_docker_block_fails_validate_on_windows`.
- ACME `acme_storage_path` (default `/etc/gateway/acme`) is probed at
  `AcmeManager::try_from_gateway_config` / `validate_activation` with the same
  create-and-write surface as `ensure_account_key` / `CertStorage::save`, and a
  present `account.key` is parsed with the same PKCS#8 surface, so a relative
  path, a file path, an unwritable directory, or corrupt account material fails
  before the renewal loop soft-opens forever. Covered by
  `test_validate_activation_builds_acme_manager_when_configured`,
  `validate_activation_fails_closed_when_acme_storage_path_is_a_file`,
  `validate_activation_fails_closed_when_acme_storage_path_is_relative`,
  `validate_activation_fails_closed_when_acme_account_key_corrupt`, and
  `validate_activation_accepts_usable_acme_account_key`.
- `providers.kubernetes` (with the `kube` feature) loads kubeconfig at
  `validate_activation` and awaits `Client::try_default` before spawning
  Ingress/CRD watchers, so a missing/unusable kubeconfig fails closed instead
  of logging "watcher started" and soft-exiting the task. Covered by
  `validate_activation_fails_closed_when_kubernetes_kubeconfig_unusable`.
- On Unix, `providers.docker.host` Unix socket paths must exist at validate
  (same missing-directory class as `providers.file.directory`). Covered by
  `validate_rejects_docker_unix_socket_host_when_path_missing` and
  `validate_accepts_docker_unix_socket_host_when_path_exists`.
- `validate_activation` builds the ACME manager via the same
  `AcmeManager::try_from_gateway_config` path as cold start (without spawning
  the renewal loop). Covered by
  `test_validate_activation_builds_acme_manager_when_configured`.
- Node API TLS `client_ca_file` without `require_client_cert = true` is
  rejected (optional client auth soft-opened mTLS). Covered by
  `test_management_config_rejects_client_ca_without_require_client_cert`.
- Enabled node API (`management.enabled`) no longer soft-opens without
  bearer auth or with `allowed_ips = []`: validate and listener prepare
  require a non-empty `auth_token_env` and at least one allowlisted IP.
  Covered by `test_management_config_rejects_empty_auth_token_env` and
  `test_management_config_rejects_empty_allowed_ips`.
- Sticky session cookie names no longer soft-skip `Set-Cookie` at response
  time: invalid cookie-name tokens fail at `config validate` and runtime
  build, and HTTP/SSE/gRPC/WebSocket response paths fail closed if a cookie
  header cannot be formed. Covered by
  `test_validate_rejects_invalid_sticky_cookie_name`,
  `test_validate_accepts_valid_sticky_cookie_name`, and
  `build_sticky_managers_fails_closed_on_invalid_cookie_name`.
- Response middleware errors no longer warn-and-continue with an unpolicied
  body on success *or* proxy-failure decoration paths: HTTP, SSE, gRPC,
  distributed inference, and native/local responses fail closed with HTTP 500
  (`response_middleware_error_fails_closed_instead_of_returning_upstream_body`,
  `response_middleware_error_fails_closed_on_proxy_failure`,
  `response_middleware_error_fails_closed_on_distributed_json_listener_without_power_body`,
  `response_middleware_error_fails_closed_on_distributed_sse_listener_without_power_body`,
  `response_middleware_error_fails_closed_on_native_models_listener_without_policy_body`).
- `health_check` no longer soft-opens as a no-op on non-HTTP pools: validate
  requires every configured service and revision server to be `http://` or
  `https://` (mirroring `tls_ca_file` without https). Covered by
  `test_validate_rejects_health_check_without_probeable_servers`,
  `test_validate_rejects_health_check_with_non_http_revision_servers`, and
  `test_validate_accepts_health_check_with_revision_only_http_servers`.
- `providers.discovery` no longer soft-opens with `seeds = []`: validate
  requires at least one seed URL. Covered by
  `test_validate_discovery_rejects_empty_seeds`. Discovery HTTP client
  construction failure also fails closed at Gateway start instead of polling
  with a missing client (`discovery_provider_new_requires_buildable_http_client`).
- CLI run no longer soft-opens on a missing `--config` path: missing ACL fails
  closed with the same posture as `a3s-gateway validate` instead of binding a
  default empty `0.0.0.0:80` listener.
- `providers.file.directory` no longer soft-skips a missing conf.d path during
  load or watch start, and `providers.file.watch = true` no longer continues
  after watcher creation failure. Covered by
  `load_config_fails_closed_when_configured_directory_is_missing` and
  `watch_fails_closed_when_configured_directory_is_missing`.
- Node API mTLS no longer warn-skips unusable certificates in `client_ca_file`:
  a partial trust-anchor load fails closed so operators cannot believe a bad
  PEM was trusted. Covered by
  `node_api_client_ca_refuses_partial_trust_anchor_load` and
  `node_api_client_ca_accepts_clean_trust_anchor_bundle`.
- Mirror/failover runtime build no longer warn-skips missing targets: registry
  skew fails closed with the same error shape as `config validate`. Covered by
  `build_mirror_failover_fails_closed_when_mirror_target_missing_from_registry`
  and
  `build_mirror_failover_fails_closed_when_failover_target_missing_from_registry`.
- ACME no longer soft-opens without certificate domains: `config validate`
  requires `acme_domains` or at least one `Host(\`...\`)` router, Host conjunction
  rules resolve domains correctly, and `AcmeManager::new` failure aborts startup
  before `Running`. Covered by `test_validate_acme_without_domains_fails_closed`
  and `test_validate_acme_with_host_router_domains_ok`.
- `providers.kubernetes` without the `kube` feature no longer soft-validates
  then warn-skips the watcher: `config validate` fails closed. Covered by
  `test_validate_rejects_kubernetes_without_kube_feature`.
- Entrypoint listener policy no longer soft-validates then hard-fails only at
  bind: `config validate` rejects zero UDP session budgets, invalid TCP
  allowlists, and `acme = true` without `acme_email`. Covered by
  `test_validate_udp_zero_timeout_fails_closed`,
  `test_validate_acme_without_email_fails_closed`,
  `udp_zero_session_timeout_fails_listener_policy`,
  `udp_zero_max_sessions_fails_listener_policy`,
  `tcp_invalid_allowed_ip_fails_listener_policy`, and
  `acme_without_email_fails_listener_policy`.
- `static_bundles` without a usable object authority no longer soft-validate
  then hard-fail at runtime build: standalone requires `local_digest_store`,
  and cloud-managed rejects every bundle until Cloud `WEB0.1` wires the shared
  object authority. Covered by
  `standalone_static_bundle_without_local_digest_store_fails_validate` and
  `cloud_managed_static_bundles_without_object_authority_fail_validate`.
- Inference SSE token observation no longer drops terminal OpenAI `usage` when
  the stream exceeds the JSON prefix buffer: Gateway scans SSE `data:` lines
  incrementally and still records
  `measurement_completeness = upstream_usage` on the usage spool. Covered by
  `managed_sse_persists_upstream_usage_on_request_terminal` and
  `managed_sse_persists_upstream_usage_after_body_exceeds_json_prefix_budget`.
- Non-streaming JSON completions larger than the prefix budget no longer drop
  trailing `usage`: a bounded rolling tail recovers the object for spool
  metering and token-budget reconcile. Covered by
  `observes_json_usage_after_body_exceeds_prefix_budget` and
  `managed_json_persists_upstream_usage_after_body_exceeds_json_prefix_budget`.
- Static SPA fallback no longer soft-200s the entry document for reserved
  `/api…` namespaces (first path segment `api`, ASCII case-insensitive).
  Covered by `spa_fallback_never_masks_missing_assets_or_posts` and
  `spa_fallback_eligibility_rejects_api_namespace`.

### Removed

- Deleted the unwired DNS service-discovery helper (`src/provider/dns.rs`); ACL
  never accepted `providers.dns`, and the module was dead under `allow(dead_code)`.

### Added

- Locked live-listener evidence that managed-snapshot expiry rejects new TCP
  connections and UDP datagrams without upstream contact
  (`managed_snapshot_expiry_rejects_new_tcp_connections_without_upstream`,
  `managed_snapshot_expiry_rejects_new_udp_datagrams_without_upstream`).
- Locked PathPrefix-only TCP evidence that an empty `TcpRouterTable` skips
  ClientHello peek so server-first backends relay without a ~200ms client-byte
  stall
  (`tcp_pathprefix_only_relays_server_first_without_clienthello_peek_wait`).
- Locked I0.2b §5b store-only evidence that managed-snapshot target-set
  succession withdraws the primary while retaining the fallback, atomically
  replacing the prior ready identity without revoking the credential
  (`target_successor_snapshot_withdraws_primary_with_fallback_retained`).
- Locked I0.3 rolling-snapshot evidence that an in-flight profile-bound P/D
  buffered OpenAI JSON completion keeps draining on snapshot-A workers while
  new requests move atomically to a successor P/D pair
  (`rolling_snapshot_drains_inflight_pd_json_while_new_requests_use_successor_pd_snapshot`).
- Locked Dual-track I0 evidence that a stale-worker scheduled successor is
  rejected by `ManagedSnapshotStore::apply` (`422` / `freshness`) without
  reload, while the prior ready scheduled snapshot stays applied and continues
  routing chat completions to the same upstream
  (`stale_worker_successor_is_rejected_with_prior_scheduled_runtime_retained`,
  `managed_snapshot_apply_stale_worker_successor_retains_prior_scheduled_routing_on_listener`).
- Locked live-listener evidence that a stale `expected_revision` CAS successor is
  rejected by `ManagedSnapshotStore::apply` (`409` / `expected revision`)
  without reload, while the prior ready snapshot stays applied and continues
  routing chat completions — even when the rejected ACL would revoke the live
  credential
  (`managed_snapshot_apply_stale_cas_successor_retains_prior_routing_on_listener`).
- Locked live-listener evidence that an unknown `tokenizer_revision` successor is
  rejected by `ManagedSnapshotStore::apply` (`422` / `tokenizer_revision`)
  without reload, while the prior ready snapshot stays applied and continues
  routing chat completions to the same upstream
  (`managed_snapshot_apply_unknown_tokenizer_successor_retains_prior_routing_on_listener`).
- Locked live-listener evidence that an empty-worker scheduled successor is
  rejected by `ManagedSnapshotStore::apply` (`422` / `no worker observation`)
  without reload, while the prior ready scheduled snapshot stays applied and
  continues routing chat completions to the same upstream
  (`managed_snapshot_apply_empty_worker_successor_retains_prior_scheduled_routing_on_listener`).
- Locked live-listener evidence that managed-snapshot target-set succession (via
  `ManagedSnapshotStore::apply` + reload) routes only to the remaining fallback
  and never contacts the withdrawn primary upstream
  (`managed_snapshot_apply_target_successor_routes_only_to_remaining_fallback_without_primary`).
- Locked I0.3 rolling-snapshot evidence that an in-flight profile-bound P/D
  OpenAI SSE stream keeps draining on snapshot-A workers while new requests
  move atomically to a successor P/D pair
  (`rolling_snapshot_drains_inflight_pd_sse_while_new_requests_use_successor_pd_snapshot`).
- Locked live-listener evidence that managed-snapshot verifier+generation
  rotation (via `ManagedSnapshotStore::apply` + reload) denies the prior bearer
  with `401` / `invalid_api_key`, never contacts upstream, and admits the
  rotated bearer
  (`managed_snapshot_apply_credential_generation_bump_invalidates_prior_bearer_without_upstream`).
- Locked live-listener evidence that managed-snapshot credential succession (via
  `ManagedSnapshotStore::apply` + reload) revokes the prior bearer with
  `401` / `invalid_api_key` and never contacts upstream
  (`managed_snapshot_apply_credential_successor_revokes_prior_key_without_upstream`).
- Locked I0.3 rolling-snapshot evidence that an in-flight aggregated OpenAI SSE
  stream keeps draining on the profile-less upstream while new requests move
  atomically to a profile-bound P/D snapshot
  (`rolling_snapshot_drains_inflight_aggregated_sse_while_new_requests_use_pd_snapshot`).
- Locked live-listener evidence that managed-snapshot grant succession (via
  `ManagedSnapshotStore::apply` + reload) keeps the credential authenticatable
  while withdrawing a model and never contacts upstream for the withdrawn
  alias
  (`managed_snapshot_apply_grant_successor_denies_withdrawn_model_without_upstream`).
- Locked Managed Runtime Service evidence that `drain_managed_service` waits for
  an admitted gRPC response body on the live private entrypoint before
  `Drained`
  (`drain_hides_then_waits_for_the_exact_admitted_grpc_stream`).
- Locked live-listener evidence that an expired managed snapshot fails closed
  with `503` / `Managed snapshot expired` and never reaches upstream
  (`managed_snapshot_expiry_rejects_new_requests_on_the_listener_with_503`).
- Locked request-path evidence that dropping a scheduled-model OpenAI SSE
  stream after the first chunk releases the model-pool active slot
  (`managed_inference_pool_releases_active_slot_when_streaming_client_aborts`).
- Locked aggregated OpenAI SSE evidence that `stream_total_timeout` fails closed
  on an actively dripping upstream (idle refreshed), releases grant concurrency
  and backend guards, and persists usage-spool `failed` terminals
  (`managed_sse_total_timeout_releases_admission_and_persists_failed_terminals`).
- Locked request-path evidence that aborting a client waiting in the model-pool
  queue frees the queue slot for a follow-up admit
  (`managed_inference_pool_releases_queue_slot_when_waiting_client_aborts`).
- Locked I0.2b request-path evidence that dropping an aggregated OpenAI SSE
  response after the first chunk releases grant concurrency
  (`managed_sse_client_drop_after_headers_releases_concurrency_permit`).
- Locked real-listener evidence that passive health half-open recovery re-admits
  traffic after `recovery_time` without a Gateway restart
  (`passive_health_half_open_recovery_readmits_traffic_after_recovery_time`).
  The recovery ticker now polls on a `recovery_time`-relative interval
  (clamped 50ms–5s) so short windows are honored promptly.
- Locked real-listener evidence that a still-broken half-open probe re-blacklists
  after the error threshold and fails closed with
  `{"error":"No healthy backends"}` again without a Gateway restart
  (`passive_health_half_open_still_broken_reblacklists_after_threshold`).
- Locked real-listener evidence that circuit-breaker half-open closes after a
  successful probe and re-opens when the probe still fails
  (`circuit_breaker_half_open_probe_closes_after_success_on_listener`,
  `circuit_breaker_half_open_still_failing_reopens_on_listener`).
- Locked real-listener evidence that active health checks evict a failing
  backend then re-admit it after probe recovery without a Gateway restart
  (`active_health_check_evicts_backend_on_listener_then_readmits_when_healthy`).
- Locked real-listener evidence that revision-only active health checks (via
  `prepare_health_checks(..., Some(revision_routers))`) evict then re-admit
  without falling back to an empty service-level pool
  (`active_health_check_evicts_revision_only_backend_on_listener_then_readmits_when_healthy`).
- Locked real-listener evidence that configured service failover routes to the
  backup pool when the primary has zero healthy backends
  (`failover_routes_to_backup_on_listener_when_primary_unhealthy`).
- Locked real-listener evidence that `forward-auth` returns `502` /
  `{"error":"Auth service unavailable"}` when auth is unreachable and relays
  a deny status when auth rejects — both without contacting upstream
  (`forward_auth_unreachable_returns_502_on_listener_without_upstream_contact`,
  `forward_auth_deny_returns_auth_status_on_listener_without_upstream_contact`).
- Locked real-listener evidence that sticky session cookies pin subsequent
  requests to the bound backend (`sticky_session_cookie_pins_backend_on_listener`).
- Locked real-listener evidence that sticky session cookies pin subsequent
  WebSocket upgrades to the bound backend (`101` + `Set-Cookie`; cookie affinity
  no longer soft-skips on upgrades)
  (`sticky_session_cookie_pins_websocket_backend_on_listener`).
- Locked real-listener evidence that response-phase middleware fail-closed
  drops unpolicied SSE and gRPC upstream bodies
  (`response_middleware_error_fails_closed_on_sse_listener_without_upstream_body`,
  `response_middleware_error_fails_closed_on_grpc_listener_without_upstream_stream`).
- Locked real-listener evidence that response-phase middleware fail-closed on
  distributed OpenAI JSON and SSE paths returns `500` / Middleware error without
  leaking Power completion or SSE frames
  (`response_middleware_error_fails_closed_on_distributed_json_listener_without_power_body`,
  `response_middleware_error_fails_closed_on_distributed_sse_listener_without_power_body`).
- Locked real-listener evidence that response-phase middleware fail-closed on
  native managed `/v1/models` returns `500` / Middleware error without leaking
  the granted model list
  (`response_middleware_error_fails_closed_on_native_models_listener_without_policy_body`).
- Locked real-listener evidence that configured traffic mirroring copies a
  buffered request body to the shadow service without changing the primary
  response (`traffic_mirror_copies_buffered_request_to_shadow_on_listener`).
- Locked real-listener evidence that an unreachable traffic-mirror shadow does
  not fail or block the primary response
  (`traffic_mirror_primary_still_succeeds_when_shadow_unreachable_on_listener`).
- Locked real-listener evidence (with `--features redis`) that
  `rate-limit-redis` returns `503` /
  `{"error":"Distributed rate limiter unavailable"}` without upstream contact
  when Redis is unreachable, and that explicit `redis_fail_open = true` still
  reaches upstream
  (`rate_limit_redis_unreachable_returns_503_on_listener_without_upstream_contact`,
  `rate_limit_redis_fail_open_reaches_upstream_on_listener_when_redis_unreachable`).
- Locked durable Managed Runtime Service evidence that a process restart while
  `Draining` keeps the route hidden and the original drain key replayable to
  `Drained` (`restart_preserves_draining_route_for_exact_drain_replay`).
- Locked request-path evidence that a waiting inference pool request fails
  closed with `429` / `pool_queue_timeout` when `queue_timeout_ms` elapses while
  the active slot is held
  (`managed_inference_pool_rejects_when_queue_deadline_elapses`).
- Managed Runtime Service drain evidence for an admitted WebSocket: after route
  hide, `drain_managed_service` stays open until the WebSocket backend guard
  releases (`drain_hides_then_waits_for_the_exact_admitted_websocket`).
- Locked I0.2b concurrency permit release when the client aborts before the
  upstream response starts
  (`client_abort_before_upstream_response_releases_concurrency_permit`).
- Locked I0.2b evidence that completed JSON without upstream `usage` keeps the
  provisional `tokens_per_minute` reservation charged (no invented refund)
  (`managed_json_without_usage_keeps_provisional_token_reservation_charged`).
- Distributed P/D OpenAI translation now emits a terminal SSE `usage` chunk
  (Power-derived prompt tokens + counted completions) before `[DONE]`, matching
  buffered P/D JSON `usage`. Request-path evidence:
  `managed_distributed_json_persists_upstream_usage_on_request_terminal`,
  `managed_distributed_sse_persists_upstream_usage_on_request_terminal`,
  `managed_distributed_json_upstream_usage_reconciles_token_budget_for_follow_up_request`,
  `managed_distributed_sse_upstream_usage_reconciles_token_budget_for_follow_up_request`,
  and
  `managed_distributed_sse_without_usage_keeps_provisional_token_reservation_charged`.
- Locked I0.3 evidence that mid-stream P/D SSE client cancel aborts both Power
  workers and releases grant concurrency
  (`managed_distributed_sse_client_cancel_aborts_both_workers_and_releases_concurrency`),
  and persists usage-spool `disconnected` attempt/request terminals
  (`managed_distributed_sse_client_cancel_persists_terminal_disconnect_outcomes`).
- Locked I0.3 evidence that P/D SSE `stream_idle_timeout` after headers fails
  closed like aggregated SSE: dual Power abort, grant concurrency release, and
  usage-spool `failed` terminals
  (`managed_distributed_sse_idle_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals`).
- Locked I0.3 evidence that P/D SSE `stream_total_timeout` wins on an active
  drip (idle refreshed) with the same dual-abort / admission / `failed` spool
  outcomes
  (`managed_distributed_sse_total_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals`).
- Locked I0.3 evidence that hung Power `decode/prepare` past
  `execution_timeout_ms` fails closed before headers: `504` /
  `distributed_inference_timeout`, dual abort, grant concurrency release, and
  usage-spool `failed` terminals
  (`managed_distributed_execution_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals`).
- Locked WEB0.4 evidence that HTTP `HEAD` verifies via the read-only object
  port `head` without admitting object bytes (`get` is never called)
  (`head_verifies_via_port_head_without_authority_get`).
- Buffered P/D OpenAI JSON no longer invents a zero `usage` object when Power
  reports no prompt/completion tokens (mirrors streaming `encode_usage`). Covered
  by `buffered_translation_omits_usage_when_power_reports_no_tokens` and
  `managed_distributed_json_without_usage_keeps_provisional_token_reservation_charged`.
- Locked I0.2b request-path evidence that completed SSE upstream `usage`
  reconciles the provisional `tokens_per_minute` reservation (follow-up admits
  after refund) while SSE without usage keeps the reservation charged
  (`managed_sse_upstream_usage_reconciles_token_budget_for_follow_up_request`,
  `managed_sse_without_usage_keeps_provisional_token_reservation_charged`).
- Locked the same `tokens_per_minute` refund path for non-streaming JSON
  completions
  (`managed_json_upstream_usage_reconciles_token_budget_for_follow_up_request`).
- Real-listener WEB0.4 evidence that an in-flight static GET keeps serving the
  prior release `Arc` across `GatewayRuntime::replace` while concurrent requests
  use the successor
  (`static_bundle_listener_drains_inflight_get_across_runtime_replace`).
- Extended Gateway-local H0.3 exact-generation retirement across the full
  listener matrix: in-flight HTTP, SSE, WebSocket, gRPC, TCP, and UDP keep
  receiving on the retired managed generation while new requests admit only on
  the successor. UDP now preserves sticky sessions across snapshot applies that
  keep the same session policy, and holds an exact-generation admission lease
  for the session lifetime. Covered by
  `generation_bump_preserves_inflight_{sse,websocket,grpc,tcp}_on_retired_target`,
  `generation_bump_preserves_inflight_udp_session_on_retired_target`,
  and the existing buffered-HTTP drain case.
- Added real-listener TCP `HostSNI` routing evidence: ClientHello peek selects
  the matching service and unmatched SNI fails closed without backend contact
  (`tests/tcp_hostsni.rs`).
- Extended the static-bundle real-listener regression to strong `If-Range`:
  matching ETag keeps single-byte `Range` 206; mismatched `If-Range` serves the
  full representation as 200.
- Locked sealed WEB0.4 `content_encoding`: ACL projects into manifest entries,
  responses emit `Content-Encoding` without `Accept-Encoding` negotiation, and
  encoding participates in the admitted-object cache key. Covered by serve,
  cache, ACL, and real-listener regressions.
- Static object responses now include `Cache-Control: …, no-transform` so
  response middleware such as `compress` cannot rewrite admitted digest bytes,
  weaken the strong `ETag`, or invent `Content-Encoding` / `Vary`. Covered by
  `static_bundle_listener_preserves_sealed_bytes_under_compress`.
- Added Gateway-owned distributed inference orchestration over Power's
  authenticated v1 protocol: exact profile-bound prefill/decode pair
  selection, opaque state-handle relay, strict bounded NDJSON validation,
  OpenAI JSON/SSE translation, drop-safe dual-worker cleanup, and
  pre-response pair fallback. Configuration remains an immutable Cloud
  projection while Power credentials are resolved only from process
  environment variables.
- Added Gateway-local rolling-version conformance for distributed inference.
  In-flight aggregated v1 requests retain their immutable snapshot while new
  requests atomically move to profile-bound prefill/decode workers. Typed
  unsupported-schema, stale-worker, and profile-mismatch rejections now
  exclude the exact pair and safely retry another pair before client response.

### Fixed

- Resolve `Host(...)` routing and access-log authority from the request URI
  authority first (HTTP/2 `:authority`), falling back to the `Host` header for
  HTTP/1.1 origin-form. Cloud-managed Host routers no longer miss every
  default HTTP/2 request that omits `Host`. Covered by unit checks and a
  real-listener HTTP/2 regression that matches with no `Host` header and when
  `Host` conflicts with `:authority`.
- Allow multiple inference model aliases to share one managed aggregated
  target and Power worker observation (chat + embeddings). Distinct target IDs
  still cannot share one worker `unit_id`.
- Force HTTP/1.1 for mTLS usage-batch uploads and surface nested transport
  error causes so failed Cloud ingest is diagnosable instead of an opaque
  reqwest message. Covered by `transport_errors_surface_nested_source_causes`.

### Added

- Added the `WEB0.4` static-object foundation and request path: fail-closed path
  normalization, sealed `a3s.gateway.static-bundle-manifest.v1` admission,
  digest/size object admit, credential/endpoint snapshot-key rejection,
  `static_bundles` ACL, GET/HEAD dispatch after the ordinary request middleware
  pipeline with `nosniff` and SPA eligibility, a snapshot-local bounded
  admitted-object LRU cache, digest-strong `ETag` / `If-None-Match` 304,
  single contiguous `bytes=` ranges (206/416; multipart ignored), strong
  `If-Range` gating, prior-runtime drain across snapshot replacement, a
  standalone local digest-store authority, and a real-listener regression for
  auth middleware + SPA serve. Cloud object adapters remain blocked on Cloud
  `WEB0.1`.

## [1.1.1] - 2026-08-25

### Added

- Added an embedded-host Managed Runtime Service lifecycle with durable
  exact-generation loopback bindings, Gateway-path health verification,
  admission closure, accepted-stream draining, receipt-owned removal, and
  restart replay. This is the Gateway foundation; A3S Use/Code composition and
  production qualification remain open.

### Fixed

- Made a completed Managed Runtime Service drain terminally idempotent for the
  exact binding identity, so a later remove operation may carry its own
  lifecycle key without reopening admission or conflicting with the earlier
  stop operation. Active `Draining` retries still require the original key.

## [1.1.0] - 2026-08-13

### Added

- Added a gateway-native multimodal adaptation proposal informed by the
  Qwen-MM-Plugins architecture. It distinguishes intrinsic multimodality from
  lossy VLM/OCR/ASR-to-text assistance, identifies the native inference
  insertion point, defines fail-closed media, SSRF, prompt-injection, privacy,
  usage, and TTFT-accounting requirements, and adds image, document, audio,
  video, protocol, load, recovery, security, and quality benchmark lanes. No
  multimodal adapter is enabled in v1.1.0.
- Added the exact A3S Cloud E0/H0.2 conformance record, including released
  Gateway and pinned Cloud revisions, clean-host workflow runs, process-loss
  and redelivery behavior, certificate and target-generation replacement,
  independent replica readiness, and the remaining H0.3/H0.4 boundary.

### Changed

- Redesigned the GitHub README with project-native SVG evidence and an
  AI-first information path: value, the eight-profile/80-trial token-aware
  A3S-versus-NGINX matrix, first use, architecture, maturity boundaries, and
  delivery options. The zero-delay C64 TTFT and goodput constraint remains
  visible instead of being hidden behind aggregate protocol throughput.
- Updated the product website to make exact-token TTFT, ITL, and token-goodput
  evidence primary, while retaining the ten-profile transport matrix as
  separate regression evidence. Published AI JSON refreshes the visible rows
  without removing audited static fallbacks.
- Promoted the default stable documentation channel from `v1.0` to `v1.1`,
  aligned package and Helm metadata at 1.1.0, and documented that the website
  and documentation are hand-authored static HTML/CSS/JavaScript rather than
  Rspress.
- Synchronized the managed-target roadmap with the completed A3S Cloud E0/H0.2
  conformance. The repository now records the exact released Gateway revision,
  pinned Cloud revision, successful clean-host gates, local real-process
  regressions, certificate-lifecycle ownership, and the remaining H0.3/H0.4
  production-topology boundary.

## [1.0.14] - 2026-08-13

### Added

- Added a deterministic OpenAI-compatible upstream, a streaming-aware Rust
  load client, and a same-host A3S Gateway/NGINX comparison focused on AI
  traffic. The published core matrix alternates five trials across eight
  concurrency, pacing, output-length, endpoint, and prompt-size profiles and
  records TTFT, inter-token latency, time per output token, end-to-end latency,
  stream rate, completed-token goodput, exact token-sequence correctness, raw
  trials, environment, and component versions.
- Added a 59-scenario AI gateway benchmark plan covering SSE framing, long-context
  upload, concurrency, queueing, backpressure, cancellation, upstream faults,
  timeouts, model policy, fallback, observability cost, real inference engines,
  and the full Gateway-to-Box-to-OCI Sandbox lifecycle.

### Changed

- The product site, stable documentation, development documentation, 404 page,
  favicon, web manifest, and social card now use the Gateway-specific route
  mark and explicit `A3S Gateway` labels instead of presenting the product as
  A3S OS. Site validation rejects the obsolete documentation branding.
- Release tags now require a successful main-branch Performance Baseline for
  the exact release commit in addition to the reusable full CI, synchronized
  Cargo/Helm metadata, and a dated changelog section. The benchmark and Pages
  workflows validate and preserve the separate token-aware AI evidence, and
  both documentation channels render its current TTFT/ITL/goodput matrix.
- The Windows installer fixture now prefers the Python launcher and falls back
  to a direct Python executable, so WindowsApps command aliases cannot silently
  prevent its loopback release server from starting.
- The Box executor now treats a successful mutation response as an acceptance
  receipt and normalizes its transient `actual_replicas` from the immediately
  following authoritative observation. A cold-start acknowledgement may report
  zero ready workloads while the durable desired count has already advanced.
- Standalone autoscaling now applies a validated per-service
  `executor_timeout_secs` budget instead of cancelling every Box query and
  mutation after a hard-coded five seconds. The 30-second default remains
  bounded, while slow Sandbox cold starts can select a larger budget below the
  scale-from-zero request buffer deadline.
- Standalone Box scaling now has a privileged real-Linux Sandbox gate. It
  builds exact Gateway, Box, and OCI Runtime revisions, boots a digest-pinned
  BusyBox workload through the production Box `scale-api`, releases a buffered
  scale-from-zero request through the runtime-owned endpoint relay, and proves
  a compare-and-set scale-down retires that relay before cleanup.
- The standalone Kubernetes Scale adapter now has a dedicated real-cluster CI
  gate. A checksum-verified Kind binary starts a digest-pinned Kubernetes
  1.32.2 cluster and proves Scale subresource reads, optimistic
  `resourceVersion` conflicts, scale-up and scale-down convergence, and
  controller recreation without duplicate mutations. Autoscaler tests now
  live outside the production module so the implementation remains below the
  repository's 1,000-line architecture limit.
- Versioned standalone scale decisions now carry a deterministic operation ID
  and the executor revision used to derive the mutation. The Kubernetes Scale
  executor reads `metadata.resourceVersion`, applies it as an optimistic
  concurrency precondition, retains the successor revision, and reconciles
  authoritative state after ambiguous failures or process restart instead of
  allowing a stale controller to overwrite a newer replica decision.
- The Box executor now consumes backward-compatible `ready_replicas` and live
  replica-slot endpoints from the v1 observation API. Endpoint identities and
  URLs are validated strictly, the active backend pool and health probes update
  atomically without losing unchanged counters, and bounded telemetry labels
  remain stable when a slot receives a new URL. Services may omit static
  servers for Box-managed scale-to-zero. A real Gateway process regression
  covers a response lost after Box applies the mutation, buffered request
  release through the discovered endpoint, and restart without duplicate POST.
- Box scale-down now atomically removes surplus dynamic slots before the
  executor mutation. Explicit rejection restores the prior endpoint set;
  ambiguous failure keeps it withdrawn until the next authoritative GET. A
  real Gateway process fixture probes the traffic listener from inside the Box
  POST and proves removal precedes Box workload termination, while Box owns the
  bounded drain of already established relay connections.

## [1.0.13] - 2026-08-06

### Added

- Added `MiddlewareRegistry` and `Gateway::with_middlewares` so embedded Rust
  deployments can register typed request/response policies by the stable names
  referenced from router ACL. The immutable registry participates in startup,
  pipeline compilation, and every atomic reload without claiming dynamic
  library or Wasm plugin loading.
- Added a repeatable same-host HTTP/1.1 comparison between the shipped Gateway
  release profile and NGINX. CI alternates five `wrk` trials against one shared
  local upstream and exports throughput plus P50/P90/P99 latency, environment,
  versions, methodology, comparison thresholds, and limitations as JSON. The
  current published workload records 40,887 req/s and 3.86 ms P99 for Gateway
  and 55,913 req/s and 3.60 ms P99 for NGINX. The result is scoped to this
  small-response HTTP case.
- Added a typed coding-agent profile registry for A3S Code, Claude Code,
  OpenAI Codex, Gemini CLI, and OpenCode, plus explicit custom executables.
- Added shell-free native CLI passthrough and standard `SKILL.md`
  `list`, `show`, `path`, and `run` operations with deterministic root
  precedence and bounded reads.
- Added a project website and GitHub Pages deployment workflow.
- Added checksum-enforcing one-command installers for macOS, Linux, and
  Windows, with deterministic platform selection, version pinning, per-user
  installation, and failure-safe replacement.
- Added native Windows x86_64 and ARM64 ZIP artifacts to the release matrix,
  plus POSIX and PowerShell installer contract tests in CI.
- Added transport-neutral production internals for bounded durable-usage
  replay that opens each selected epoch once per batch, exact cursor-gap
  rejection, idempotent contiguous acknowledgement, v1/v2-to-v3 manifest
  migration, crash-recoverable whole-epoch reclamation, and byte-preserving
  acknowledged-prefix compaction for closed epochs. Fixed-width compacted
  sequence bounds reject incomplete tails before the original segment is
  removed; a partially acknowledged live epoch is compacted on restart.
  Usage health now exposes the acknowledged watermark and oldest retained
  cursor without claiming a Cloud ingestion wire contract.
- Added real-entrypoint WebSocket regressions for malformed downstream
  handshakes, unavailable and hanging upstream handshakes, service request
  timeouts, end-to-end request headers, trusted forwarding metadata,
  subprotocol negotiation, transparent application-message relay, and safe
  non-`101` upstream rejection propagation.
- Added real-entrypoint HTTP and SSE regressions for bidirectional
  `Connection`-nominated field isolation, plus WebSocket backend-capture
  coverage for the same downstream boundary.
- Added a real h2c full-duplex gRPC fixture that holds both request and response
  streams open concurrently, verifies downstream trailer delivery, and proves
  exact buffered-body mirroring. Focused tests cover idle and total timeout,
  disconnect cleanup, trailer filtering, terminal access logs, TTFT, and active
  request lifetime.
- Extended the real h2c fixture to capture Gateway-regenerated
  `X-Forwarded-*` metadata, normalized `TE: trailers`, and an end-to-end request
  trailer at the upstream.
- Added a real Gateway/backend compression fixture that verifies raw gzip
  delivery, exact decompression, `Vary: Accept-Encoding`, identity fallback for
  an explicitly excluded coding, and absence of internal marker headers.
- Added real Gateway/backend ordinary HTTP fixtures that prove first-chunk
  delivery before upstream completion, configured response-idle termination,
  and full-duplex progress where a response arrives before the request body is
  complete. Focused body tests cover absolute total bounds and safe trailers.
- Added a local-CA upstream TLS fixture that proves ordinary HTTP dispatch over
  an explicitly trusted HTTP/2 ALPN connection, plus default rejection and
  connection-accounting cleanup for the same untrusted certificate.

### Changed

- Reduced common HTTP proxy overhead with owned request transfer, a concrete
  response-body fast path, deferred response-timer registration, exact-host
  route indexing, startup-bound route plans, a compiled direct path for plain
  HTTP routes, single-backend selection, in-place forwarding-header
  replacement, prebound passive-health checks, constant-time error-status
  classification, sharded upstream pools and backend operation counters,
  `TCP_NODELAY`, and an end-to-end-only header-filtering bypass. Middleware,
  inference, streaming, and managed-state behavior remain on their existing
  paths.
- Shortened the README, product website, documentation, benchmark guide, and
  roadmap around executable examples, implemented features, measured results,
  ownership boundaries, and remaining work.
- The historical `management` ACL block now configures a bounded, machine-only
  Node API. Its dedicated listener, bearer authentication, IP allowlist, and
  TLS/mTLS controls remain compatible for Cloud bootstrap and node integration.
  Human-facing operations are owned by A3S Cloud.
- WebSocket upgrades now validate the required HTTP/1.1 opening-handshake
  fields and establish the upstream connection under the selected service's
  `request_timeout` before returning `101`. Upstream requests preserve
  end-to-end client headers, use Gateway-generated `X-Forwarded-*` metadata,
  and reflect a negotiated requested subprotocol to the downstream client.
- Split the large ACL, top-level configuration, and inference-authorization
  inline test suites into adjacent test modules. The production files now stay
  below 1,000 lines without changing test names or runtime behavior.
- Split the 1,531-line real-entrypoint integration suite into traffic, reload,
  management, and lifecycle files while preserving every existing top-level
  test name. Every Rust source and test file now stays below 1,000 lines.
- Centralized static and `Connection`-nominated hop-by-hop filtering across
  buffered HTTP, SSE, gRPC, and WebSocket paths. The consuming HTTP response
  filter preserves duplicate end-to-end fields without adding a hot-path
  header-map clone, and gRPC continues to forward `TE: trailers`.
- Replaced the body-buffered reqwest gRPC adapter with a Hyper HTTP/2 frame
  relay, with real-entrypoint h2c coverage. Ordinary calls now stream request
  and response DATA frames plus trailers, preserve the downstream method and
  content type, use per-service first-response/idle/total bounds, and keep
  connection and observability guards until the response body terminates.
  Mirror sampling now happens before optional body collection, so only selected
  calls are buffered once for exact shadow replay while disabled or unsampled
  calls remain full-duplex. Traffic that already requires buffering is sampled
  after final service resolution. The TLS client selects ring explicitly and
  reports initialization failure instead of depending on process-global
  provider state. Streaming SSE and gRPC DATA frames now also advance the
  aggregate response-byte counter as they are relayed.
- Native gRPC requests now use the same forwarded-metadata generator as
  HTTP and WebSocket traffic. Request and response trailer frames pass through
  the shared connection-specific header filter, while arbitrary downstream
  `TE` values are reduced to the HTTP/2-compatible `trailers` token.
- All upstream gRPC responses now use one bounded HTTP/2 frame relay. A selected
  mirror buffers only the replayable request, so shadow traffic no longer
  implies a second collected-response path.
- Ordinary HTTP now relays upstream response DATA and safe trailer frames with
  downstream backpressure instead of collecting each response first. The
  selected service's response-header, idle-body, and total-operation bounds
  apply independently, while backend, inference admission, TTFT, access-log,
  response-byte, and durable usage accounting follow the body lifetime.
  Mirrored responses are drained frame by frame instead of being aggregated.
- Ordinary HTTP and managed OpenAI dispatch now share one Rustls-backed
  HTTP/HTTPS connection pool. HTTPS targets verify certificates and hostnames
  against built-in WebPKI roots and negotiate HTTP/1.1 or HTTP/2 through ALPN
  without changing the existing streaming, timeout, or fallback boundaries.
- Middleware definitions are now validated through their production
  constructors across the CLI, startup, and reload paths.
  Runtime preparation rejects any router pipeline that cannot compile instead
  of silently omitting it, and requests consume only the precompiled snapshot.
  A rejected reload keeps the prior live configuration serving traffic.
- Active service health checks now follow the committed runtime lifecycle.
  Candidate construction prepares checkers without starting probes, failed
  startup and rejected reload paths remain side-effect free, successful reload
  aborts and joins the superseded checker set before starting its replacement,
  and shutdown aborts and joins the active set. Real probe backends cover each
  boundary.
- Active health-check configuration now fails closed through CLI, startup,
  reload, and runtime preparation. Probe paths must begin with
  `/`, intervals and timeouts must be positive durations, and both transition
  thresholds must be positive. Runtime checkers receive parsed `Duration`
  values instead of silently substituting defaults. A real reload regression
  proves contextual rejection, zero candidate probes, and continued traffic on
  the prior snapshot.
- Active health checks now start every backend probe in a service round
  concurrently and apply each result as it completes, so a hanging backend no
  longer serializes later backends behind its timeout. Transition counters now
  retain only pending consecutive evidence and saturate at their configured
  thresholds instead of growing for the lifetime of the checker.
- Active health-check HTTP clients are now built during runtime preparation.
  Initialization failure rejects a Gateway startup or reload candidate with
  service context instead of silently replacing the configured client and
  losing its timeout. Library callers can use the new fallible
  `HealthChecker::try_new`; the compatible `new` path stores an initialization
  error, and `run` reports it and exits without contacting a backend.
- Startup, every reload source, and shutdown now share one asynchronous
  lifecycle transaction. Startup is accepted only from `Created`, reload only
  from `Running`, and a shutdown request prevents queued mutations from
  committing after cleanup. Concurrent shutdown callers all wait for `Stopped`.
  A real streaming-drain regression proves that reload cannot cross the
  shutdown boundary or start candidate health probes afterward.
- The `compress` middleware now transforms eligible ordinary and Gateway-native
  buffered HTTP responses instead of only tagging their headers. Negotiation
  honors exact Brotli, gzip, deflate, wildcard, identity, and quality values;
  compression runs on the blocking pool; deflate uses its required zlib wrapper;
  and transformed responses rebuild coding, length, variance, validator, range,
  and digest metadata. Ordinary responses use at most 8 MiB of compression
  look-ahead; known larger bodies stream immediately, while unknown-length
  overflow replays the consumed prefix before the untouched remainder.
  Existing codings, small or binary bodies, ranges, `no-transform`, SSE, and
  native gRPC remain unchanged.
- WebSocket messages are now explicitly documented and tested as opaque to
  Gateway control logic. The real-Gateway managed TLS recovery fixture verifies
  that a control-looking `_sub:` text message is relayed unchanged.
- Gateway configuration now rejects gradual `rollout` blocks in every
  operating mode with an explicit static revision-weight alternative. The ACL
  shape remains parseable so existing configurations fail with a focused
  compatibility error instead of appearing active while doing nothing.
- Separated coding-agent process operations from the traffic data plane and
  documented both boundaries in the README and project roadmap.
- Release tags now invoke the complete reusable CI workflow, verify the tag
  against Cargo, Helm, and changelog metadata, and defer crates.io publication
  until every macOS, Linux, and Windows release target builds successfully.
- CI now runs the default Rust test suite and pinned official OpenAI SDK
  conformance on Windows before validating the PowerShell installer and ARM64
  release target.
- The official OpenAI SDK harness now uses a dedicated Windows process group
  and native console control events for graceful-drain coverage and cleanup.
- Managed usage-spool locking now recognizes platform-native lock contention
  errors on Windows while preserving I/O failures as distinct errors.

- Added topology-bounded service telemetry to the Node API Prometheus
  endpoint: exact cold-start queue depth, drop-safe active requests,
  fixed-bucket request-duration and first-non-empty-stream-chunk TTFT
  histograms, exact backend active work and health, and per-signal observation
  timestamps and age. Missing event signals remain absent until observed.
- Added unit, cancellation, reload, real-entrypoint SSE, and Node API
  network evidence for active-request lifetime, first-chunk-only TTFT, stale
  signal age, backend pressure, queue cleanup, and orphan-series removal.
- Added positive per-service `stream_idle_timeout` and
  `stream_total_timeout` ACL bounds for SSE and native OpenAI streams. Idle
  time resets after each available upstream chunk, while total time starts at
  dispatch and remains absolute even under continuous output. Body timeout
  releases backend and inference admission accounting, emits terminal access
  log and durable usage outcomes, and never permits post-response fallback.
- Added the opt-in `managed.gateway_id` bootstrap identity and a
  Gateway-native `a3s.gateway.managed-snapshot.v1` Node API contract with
  exact ACL SHA-256 verification, revision compare-and-swap, a 24-hour maximum
  validity interval, idempotent replay, bounded applied/rejected metadata, and
  exact-selector readiness.
- Added `POST /snapshots/apply` and `GET /snapshots/status` under the configured
  Node API prefix. Health now exposes the stable Gateway identity when
  configured, and structured logs distinguish applied, replayed, and rejected
  snapshots.
- Added optional `managed.state_file` durability with an atomic `prepared` /
  `applied` journal, exact snapshot recovery before readiness, preserved
  `applied_at`, and idempotent redelivery across Gateway restart.
- Added a dual-real-binary replicated-readiness gate covering independent
  exact selectors, revision skew, rejected-successor retention, single-process
  loss, durable recovery, and eventual convergence without a replica claiming
  another replica's snapshot ready.
- Added in-place HTTP/TLS and TCP listener-policy replacement for same-name,
  same-address managed snapshots without releasing the bound socket.
- Added in-place UDP listener-policy and target reconciliation. Cloud-managed
  bootstrap can bind UDP before the first traffic snapshot, and snapshot
  cutover retires sessions associated with the superseded target set.
- Added a closed native OpenAI request profile for `GET /v1/models` and the
  three POST completion/embedding endpoints. OpenAI POST bodies require
  `application/json`, are collected under a fixed 8 MiB limit, require a
  bounded string `model` field, and return stable OpenAI-compatible request
  errors without parser details.
- Added a strict Cloud-managed inference policy ACL contract for expiring
  credential verifier projections, environment-scoped routes, ordered model
  targets, generation-bound model/endpoint grants, and explicit per-Gateway
  concurrency, request-rate, burst, and token limits.
- Added snapshot-local managed inference authorization with bounded Argon2id
  verification, endpoint and model grant enforcement, non-enumerating denial,
  a filtered OpenAI-compatible model catalog, and expiry/revocation checks.
- Added health-aware inference target dispatch with ordered priority fallback,
  deterministic weighted selection, service switching, and external-to-upstream
  model rewriting.
- Added exact per-grant request admission with sustained RPM, configurable
  burst, concurrent request caps, stable OpenAI-compatible `429` responses,
  and `Retry-After` headers for managed model-list and invocation requests.
- Added Gateway-owned UUIDv4 identities for managed inference requests and
  concrete upstream attempts. Request IDs are returned to clients, both IDs
  are forwarded upstream, and terminal access logs carry bounded route-policy,
  endpoint, model, target, and trace-correlation context.
- Added replayable managed inference dispatch with lower-priority fallback
  after connection failure or first-response timeout. Fallback preserves one
  request ID, creates a new attempt ID for each dispatch, and ends once any
  upstream response headers arrive. Response-body failures are never replayed.
- Added process-wide bounded graceful drain using `shutdown_timeout_secs`.
  Traffic listeners close before drain, HTTP/1.1 and HTTP/2 connections receive
  protocol-level graceful shutdown, and active SSE, WebSocket, and TCP work is
  tracked until completion or forced cancellation. UDP sessions are cancelled
  immediately.
- Added a pinned official `openai-python` 2.47.0 black-box conformance gate
  against the real Gateway binary and native managed snapshot API. It covers
  typed model and completion responses, stable SDK error parsing, SSE `[DONE]`,
  downstream disconnect, asynchronous cancellation, admission release,
  graceful drain, and forced drain.
- Extended the official SDK gate across the exact Models, Chat Completions,
  Completions, and Embeddings matrix, including the SDK-default base64 embedding
  path and final usage chunks for both completion stream variants.
- Added opt-in `managed.usage_spool` bootstrap storage with an exclusive process
  lock, private manifest and boot-epoch segments, stable Gateway identity,
  monotonic per-epoch sequences, byte-preserving records, SHA-256 integrity,
  bounded capacity, restart recovery, and health visibility.
- Added prompt-free managed inference lifecycle evidence. Gateway persists
  request and attempt starts before upstream dispatch, reserves terminal
  capacity, orders fallback attempt boundaries, and records success, failure,
  disconnect, or forced cancellation at the HTTP or SSE response-lifetime
  boundary.
- Added a stable OpenAI-compatible `usage_unavailable` response that rejects
  configured managed inference before upstream dispatch when complete local
  lifecycle evidence cannot be reserved.

### Changed

- Prometheus labels are now restricted to the active configuration and removed
  on reload. Backend request metrics use opaque SHA-256 `backend_id` labels
  instead of raw locators, and all text labels are escaped before exposition.
- Cold-start queue accounting now uses a drop guard so cancellation cannot
  leave a permanently inflated queue-depth signal.
- Standalone autoscaling now derives healthy-backend and active-operation
  signals from the live service or revision load balancers and combines them
  with bounded queue depth. A new or recreated controller now obtains the
  authoritative current replica count from the selected executor before its
  first decision.
- Autoscaling executor selection now rejects unknown, unavailable, and mixed
  executor types instead of falling back to Box. Kubernetes client
  initialization, replica queries, and scale mutations are time-bounded.
- Prepared autoscalers now remain inactive until startup or reload commits.
  Replacement aborts and joins the previous controller before starting the new
  one. Only accepted executor results advance remembered replica state;
  failed or timed-out mutations clear that state and force reconciliation
  before any retry.
- The Kubernetes autoscaling executor now reads and merge-patches the standard
  Deployment `Scale` subresource instead of the full Deployment. Replica
  queries use `Scale.spec.replicas`, and successful mutations are accepted only
  when the response contains the requested desired count.
- Native chat and legacy completion requests with a boolean `stream: true` now
  select the SSE path without requiring `Accept: text/event-stream`, matching
  official OpenAI SDK behavior. Other JSON values and endpoint profiles do not
  opt into SSE.
- Cloud-managed instances with `managed.gateway_id` reject raw ACL mutation so
  reported readiness cannot outlive an untracked configuration change.
- Native managed bootstrap ACLs may bind process and listener settings but now
  reject traffic routers, services, middlewares, and inference policy; those
  must arrive in the complete managed snapshot.
- Managed inference policy expiry must exactly match the atomic snapshot
  envelope. Plaintext and unknown fields, dynamic verifier expressions, unsafe
  Argon2id parameters, duplicate identities, cross-environment grants, stale
  generations, and invalid route, service, or model references are rejected
  before cutover.
- Inference verifier hashes are omitted from serialized Gateway configuration
  and redacted from debug views. Managed snapshot debug output now redacts the
  complete ACL payload.
- Managed apply keeps the bootstrap node API listener immutable, pre-binds
  supported HTTP, TCP, and UDP changes on new addresses, and pre-validates
  same-address TLS acceptors, TCP filters, and bounded UDP session policies
  before cutover.
- Reload transactions are serialized across manual, provider, and
  managed-snapshot sources.
- Durable journals use synced atomic replacement and owner-only permissions on
  Unix. Corrupt, identity-mismatched, digest-invalid, expired, and insecurely
  permissioned state fails managed startup closed.
- Managed snapshot request bodies are bounded while they are read rather than
  only after complete buffering.
- Request middleware now runs before buffered non-WebSocket body collection.
  Valid ordinary OpenAI JSON bytes are forwarded unchanged, while non-matching
  method and path combinations retain ordinary streaming proxy behavior.
- Routers bound by managed inference policy now authenticate only the four
  exact OpenAI method/path pairs before middleware or body collection. Accepted
  client authorization is stripped before middleware and upstream dispatch;
  successful verification caches only a token digest for the active snapshot.
- Unchanged immutable inference grants now retain request-bucket and active
  concurrency state across snapshot refresh. Concurrency remains held through
  buffered dispatch and until an SSE stream completes or disconnects.
- Managed inference now replaces client `x-request-id` and
  `x-a3s-attempt-id` values after authorization. Local model catalogs and
  pre-dispatch rejections receive a request ID without claiming an upstream
  attempt, and SSE retains its request/attempt context through termination.
- SSE now applies each service's request timeout only while waiting for
  upstream response headers; established streams continue to use the
  independent idle-read timeout instead of a total-operation deadline.
- Gateway shutdown now waits for entrypoint completion and for aborted
  discovery, provider, autoscaler, node-API-listener, and ACME task handles
  before publishing the `Stopped` lifecycle state.

### Removed

- Removed Gateway's operator-facing HTTP surface: active configuration, route,
  service, backend, security-event, ACL validation, and raw ACL reload
  endpoints now return `404`. The in-memory management audit ring and exported
  `dashboard` Rust module were removed with that surface.
- Removed the `a3s-gateway management` CLI and its event, validation, and reload
  commands. These human-facing operations belong to A3S Cloud.
- Removed the unused internal `proxy::ws_mux` named-channel state machine and
  private control-message grammar, which had no configuration or runtime entry
  point.
- Removed the unconnected internal `scaling::rollout` controller and its
  unit-only state machine. It had no runtime loop, scheduler, persistence, or
  recovery path and could not execute accepted configuration.
- Removed the unused collected `GrpcResponse`/`GrpcStatus` compatibility
  surface, its duplicate metadata parser, and the process-wide gRPC timeout
  field. Runtime bounds remain explicit per-service request options.
- Removed the internal `x-gateway-compress` eligibility marker, which previously
  crossed the downstream boundary without causing response compression.

### Fixed

- gRPC calls no longer wait for the complete downstream request before
  contacting the upstream, buffer the complete upstream response before
  returning headers, or discard `grpc-status` and other HTTP/2 trailers.
- Native gRPC detection no longer captures gRPC-Web or arbitrary
  `application/grpc...` prefixes. Matching is case-insensitive and limited to
  `application/grpc` or a non-empty `+suffix`, with optional media parameters.
- Native gRPC no longer forwards client-supplied `X-Forwarded-Proto` or
  `X-Forwarded-Port` values unchanged, and it appends the observed downstream
  peer to the forwarded address chain.
- HTTP, SSE, gRPC, and WebSocket proxy boundaries no longer allow arbitrary
  one-hop fields named by `Connection` to cross to an upstream or downstream
  peer. The fixed list now also covers the standard `Trailer` field and the
  legacy `Proxy-Connection` field.
- A truncated ordinary HTTP body after upstream response headers no longer
  becomes a new Gateway-generated status or permits managed fallback. The
  started status is preserved and the downstream body terminates with the
  upstream error.
- Invalid WebSocket handshakes now return `400` without backend contact, while
  upstream handshake transport failures and timeouts return `503` and `504`
  before the downstream connection is upgraded instead of returning a false
  `101` followed by an abrupt disconnect. Non-`101` upstream HTTP rejections
  now retain their status and safe end-to-end headers instead of collapsing to
  `503`; Gateway returns its own bounded JSON body and strips hop-by-hop,
  WebSocket-handshake, and discarded-body metadata.
- Structured access logs now reach the background logging task for no-route,
  middleware-rejection, HTTP success and proxy-error, gRPC, SSE, and WebSocket
  terminal paths instead of being constructed and discarded.
- SSE logs count relayed response bytes and finish on stream completion or
  disconnect; WebSocket logs finish when the upgraded relay ends or is dropped.
- Managed model rewriting now updates the outbound content length so a longer
  or shorter upstream model identifier cannot truncate or overrun the JSON
  request body.
- Managed dispatch rebuilds one unambiguous top-level `model` field so duplicate
  JSON keys cannot be interpreted differently by Gateway and the upstream.
- Inference keys are now verified before endpoint-grant denial, so an invalid
  token consistently returns `401` and cannot use `404` or verifier timing to
  enumerate a credential's endpoint grants.
- Streaming backend connection counts now release on stream completion, error,
  or cancellation instead of remaining active after a successful response.
- HTTP, gRPC, SSE, WebSocket, and TCP backend accounting plus downstream
  connection metrics now use drop guards, preventing cancellation from leaking
  active counts. HTTP child connections, upgraded sessions, TCP relays, and UDP
  response tasks no longer outlive process shutdown or retain listener sockets.
- Kubernetes autoscaling now rejects missing, negative, overflowing, or
  mismatched replica values instead of treating unknown Deployment state as
  zero or reporting an unverified mutation as accepted. Programmatic executor
  initialization also selects the rustls crypto provider before kube client
  construction, matching the panic-free CLI path.

### Testing

- Added a real-Gateway-binary managed snapshot fixture covering TLS hostname
  and path routing, multiple services, round-robin targets, HTTP, SSE,
  WebSocket, invalid-successor retention, forced process loss, durable exact
  revision/digest recovery, and idempotent replay.
- Added standalone autoscaling regressions for live backend and revision load,
  inactive prepared controllers, accepted-state advancement, executor failure
  retry, executor timeout, scale-from-zero buffer bounds, unsupported
  executors, and mixed-executor rejection.
- Added real kube-client HTTP contract tests for the Deployment `Scale`
  subresource method, path, merge-patch content type and body, desired-count
  parsing, API errors, invalid responses, and recreated-controller
  reconciliation after an ambiguous mutation failure.
- Added a real-Gateway-binary Kubernetes scaling recovery fixture with a
  process-local kubeconfig and stateful Scale API. It applies a patch before
  dropping the response, verifies reconciliation, forces Gateway process loss,
  restarts against the retained count, and proves that no duplicate patch is
  emitted.
- Added real Node API regressions for first apply, exact replay, stable
  identity, exact readiness, stale revisions, CAS mismatch, digest tampering
  and conflict, expired and overlong validity, rejected raw reload, invalid
  ACL, failed listener bind, and prior-runtime retention.
- Added restart recovery, interrupted prepared-journal recovery, journal
  integrity and permissions, pre-reload storage failure, and post-reload
  rollback failure tests.
- Added real managed-listener regressions for same-address certificate
  rotation, superseded-certificate rejection, invalid-certificate retention,
  TCP allowlist replacement, invalid-filter retention, UDP target replacement,
  UDP session-policy replacement, and invalid-policy retention.
- Added real listener regressions for routing rejection, middleware rejection,
  HTTP success and failure, gRPC failure, SSE completion, WebSocket shutdown,
  response byte counts, and the disabled access-log path.
- Added real OpenAI request-profile regressions for exact and near-miss paths,
  byte-preserving JSON forwarding, media-type and JSON errors, oversized
  declared lengths, over-limit chunked uploads, body/model validation, and
  middleware-before-body rejection.
- Added managed inference policy regressions for strict ACL shape, literal
  bounded Argon2id verifiers, redaction, duplicate identities, ordered targets,
  environment and generation isolation, revocation, references, grants,
  limits, bootstrap rejection, and atomic snapshot-expiry mismatch retention.
- Added real managed inference HTTP regressions for authentication-before-body,
  authorization stripping, filtered model listing, endpoint/model denial,
  near-miss isolation, expiry across delayed body collection, target service
  switching, upstream model rewriting, request-burst exhaustion, stable
  `Retry-After`, rejected-request accounting, snapshot-refresh concurrency,
  and SSE disconnect release, plus unit coverage for exact refill,
  verification concurrency, cancellation-safe verifier permits,
  duplicate-model normalization, and weighted priority fallback.
- Added managed inference identity regressions for spoofed-header replacement,
  native model-list and parse-error responses, upstream and client correlation,
  snapshot/access-log identities, secret exclusion, and SSE completion.
- Added real managed inference fallback regressions for connection failure,
  first-response timeout, stable request and unique attempt identities, model
  rewriting per target, no replay after an upstream status or response-header
  start, SSE pre-response fallback, and streaming connection release.
- Added real graceful-drain regressions for complete SSE delivery within the
  configured deadline, immediate cancellation of hanging SSE and WebSocket
  sessions, hot-reloaded deadline adoption without listener rebinding, TCP
  upstream disconnect, UDP session retirement, listener release, and zero
  leaked downstream connection metrics.
- Added durable usage regressions for ordered byte-preserving append, exact
  replay, conflicting replay, exclusive ownership, capacity backpressure,
  corruption and identity mismatch, restart recovery, terminal reservation
  release, writer drain, prompt/key exclusion, pre-dispatch fail-closed
  behavior, fallback ordering, SSE disconnect, forced-drain cancellation,
  exact and repeated acknowledgement, stale/future cursor gaps, capacity
  recovery, legacy migration, and both sides of the epoch-retirement crash
  boundary. Added partial-epoch compaction coverage for repeated compaction,
  capacity release, current-epoch restart handling, all publication crash
  points, uncommitted staging cleanup, and malformed or truncated staging.

## [1.0.12] - 2026-07-19

### Fixed

- Route-bearing Cloud snapshots with object-list service backends now validate
  without recursive parser failure by upgrading to `a3s-acl` 0.2.2.
- The self-updater dependency now resolves the published 0.3.0 API instead of
  requiring a stale monorepo-local 0.2.x source tree.

### Testing

- Added a real `a3s-gateway validate` regression fixture for the complete
  hostname, path, service, management-listener, and upstream shape emitted by
  A3S Cloud.

### Release Engineering

- Replaced all monorepo-only path dependencies with exact crates.io releases,
  removed the temporary workspace reconstruction script, and added locked
  dependency resolution throughout CI and release workflows.
- Fixed Homebrew asset lookup and checksum generation so missing or renamed
  release archives fail the workflow instead of producing an invalid formula.
- Updated the Helm chart metadata to 1.0.12.

## [1.0.6] - 2026-06-01

### Fixed

- Passive health check no longer deadlocks a backend into permanent unavailability. Previously, once a backend exceeded the error threshold it was marked unhealthy and dropped from rotation; recovery only happened inside `record_success`, but an unhealthy backend receives no traffic, so no success ever arrived and the service returned `503` until the gateway was restarted (a single transient burst of `SendRequest`/5xx errors could take a whole service down indefinitely). A background recovery ticker now drives a half-open probe: after `recovery_time` elapses the backend is re-enabled so it receives traffic again — if it is still broken the next errors re-mark it, otherwise it stays healthy. The ticker holds a `Weak` reference and exits when its checker is dropped (config reload), avoiding task accumulation.

## [1.0.5] - 2026-05-31

### Fixed

- The Kubernetes Ingress watcher now hashes router/service CONTENT (rule, middlewares, priority, backend) instead of only their keys, so an in-place change to an existing Ingress/router — editing a rule from host to path routing, changing middlewares/priority, or a helm upgrade that rewrites the backend — is detected and triggers a reload (previously only router additions/removals were noticed).

## [1.0.4] - 2026-05-31

### Added

- `strip-prefix` middleware now supports a single-segment wildcard prefix (e.g. `/apps/*`): it strips the literal base plus exactly one dynamic path segment, so a single middleware can serve every dynamically-named workload under `/apps/<id>/` without a per-workload middleware entry (avoids ConfigMap churn and the associated reload race).

## [1.0.3] - 2026-05-31

### Fixed

- Host rule matching now strips the port from the request authority before comparing, so a request that reaches the gateway on a non-default port (e.g. `Host: app.example.com:49164`) still matches a port-less Ingress host instead of falling through to a host-less catch-all.
- Router selection now prefers the most-specific / highest-priority route. Effective priority is the explicit `a3s-gateway.io/priority` annotation when set (higher wins, Traefik-style), otherwise the rule length — so a host-less catch-all PathPrefix(/) no longer swallows more-specific (host-qualified or longer-path) routers.
- The Kubernetes Ingress (and IngressRoute CRD) watcher now rebuilds its API client and backs off after a poll failure instead of spinning forever on a poisoned connection, so a transient API-server disconnect no longer freezes the router table until pod restart.

## [1.0.2] - 2026-05-16

### Fixed

- Fixed `tokio-rt-worker` panic on startup when the Kubernetes Ingress watcher
  opened its first TLS connection to the apiserver
  (`Could not automatically determine the process-level CryptoProvider from
  Rustls crate features`). With `kube` and `redis` features both pulling in
  rustls 0.23 alongside `aws-lc-rs` and `ring`, rustls refuses to auto-select a
  provider; the gateway now installs `rustls::crypto::ring` as the process
  default at the top of `main()` before any TLS client is constructed.

## [1.0.1] - 2026-05-15

### Fixed

- Linux release binaries (and OCI images published to ghcr.io) are now built with
  the `kube` and `redis` features enabled, so the published image can act as a
  Kubernetes Ingress Controller and use Redis-backed distributed rate limiting
  out of the box. Prior 1.0.0 image had `default = []` features only and logged
  `Kubernetes provider configured but the 'kube' feature is not enabled` when
  used with a `providers.kubernetes` config block.

## [1.0.0] - 2026-05-12

### Breaking

- Provider re-exports narrowed: `DockerProvider` and `spawn_docker_loop` are no longer
  re-exported from the crate root. Use `from_acl()` Docker provider config instead.
- `GatewayState` enum and `HealthStatus` struct are now `#[non_exhaustive]` —
  match arms must include a wildcard (`_`) pattern.
- Management API `VersionInfo` response now includes an `api_version` field (`"v1"`).
- Minimum Supported Rust Version (MSRV) declared: **1.82**.

### Added

- `EntrypointConfig::new(address)` constructor for convenient programmatic config.
- `VersionInfo.api_version` field for management API versioning.
- `rust-version = "1.82"` in Cargo.toml (MSRV policy).
- Criterion benchmarks: `routing`, `middleware_pipeline`, `acl_parse`.
- 35 new unit tests for the ACL configuration parser.
- 5 new unit tests for rate-limit middleware (deterministic time, edge cases).
- `router` and `middleware` modules exposed as `#[doc(hidden)] pub` for benchmarking.

### Fixed

- `GatewayConfig::default()` now uses `EntrypointConfig::new()` internally.

## [0.2.5] - 2026-05-10

### Added

- ACL config parsing and management API for runtime configuration.

## [0.2.4] - 2026-04-28

### Added

- macOS ARM64 OCI image support.

### Fixed

- Docker image build simplified to linux/amd64 only.

## [0.2.3] - 2026-04-15

### Changed

- Refactored gateway into smaller files (proxy, router, service, middleware modules).
- Split large files to meet 1000-line limit.

## [0.2.2] - 2026-04-01

### Added

- RevisionRouter traffic splitting and load balancer access tests.

## [0.2.1] - 2026-03-15

### Added

- Initial public release with full feature set.
- HTTP/HTTPS, WebSocket, SSE, gRPC, TCP, UDP proxy support.
- 15 built-in middlewares.
- Knative-style autoscaler with scale-to-zero.
- ACME/Let's Encrypt certificate management.
- File, DNS, Docker, and Kubernetes service discovery.
- Management API with mTLS support.
