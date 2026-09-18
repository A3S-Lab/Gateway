# Runbook: disk / durable-state failure

## Detect

- Activation fails on usage-spool untracked files, corrupt managed snapshot
  journals, insecure spool permissions, or missing Cloud usage-ingest
  credentials / mTLS identity when ingest is configured.
- Managed recoveries refuse to soft-open on tampered on-disk state.

## Contain

1. Quarantine the spool/journal directory — do not manually edit record bytes.
2. Keep the prior process (if still running) until a clean store is prepared.

## Recover

1. Restore spool/journal from known-good backup, or initialize an empty spool
   only when loss of unacked usage is accepted by policy.
2. Fix directory permissions to the private layout Gateway expects.
3. Restart or reload only after `validate_activation` succeeds.

## Verify

- Suite: `validate_activation_fails_closed_when_usage_spool_has_untracked_file`,
  `validate_activation_fails_closed_when_usage_spool_locked`,
  `probe_activation_fails_closed_when_exclusive_lock_is_held`,
  `validate_activation_fails_closed_when_usage_spool_parent_unusable`,
  `probe_activation_fails_closed_when_spool_parent_is_not_a_directory`,
  `validate_activation_fails_closed_when_usage_spool_directory_is_not_writable`,
  `probe_activation_fails_closed_when_usage_spool_directory_is_not_writable`,
  `validate_activation_fails_closed_when_usage_spool_epoch_record_corrupt`,
  `probe_activation_fails_closed_when_ready_epoch_record_is_corrupt`,
  `validate_activation_fails_closed_when_usage_spool_prepared_epoch_corrupt`,
  `probe_activation_fails_closed_when_prepared_epoch_record_is_corrupt`,
  `validate_activation_fails_closed_when_usage_spool_recovery_artifact_is_a_directory`,
  `probe_activation_fails_closed_when_recovery_artifact_is_a_directory`,
  `probe_activation_fails_closed_when_compacting_epoch_final_is_a_directory`,
  `probe_activation_rejects_retained_bytes_over_capacity_like_open`,
  `probe_activation_rejects_missing_boot_epoch_headroom_like_open`,
  `probe_activation_rejects_untracked_paths_like_open`,
  `probe_activation_accepts_deleted_retiring_epoch_like_open`,
  `probe_activation_write_probe_leaves_no_untracked_artifact`,
  `probe_activation_projects_empty_epoch_reclaim_before_capacity_like_open`,
  `probe_activation_projects_partial_ack_compaction_before_capacity_like_open`,
  `validate_activation_fails_closed_when_usage_cloud_ingest_bearer_env_unset`,
  `validate_activation_fails_closed_when_usage_cloud_ingest_mtls_identity_missing`,
  `validate_activation_fails_closed_on_corrupt_managed_snapshot_journal`,
  `validate_activation_fails_closed_when_managed_snapshot_journal_parent_unusable`,
  `validate_activation_fails_closed_when_static_bundle_object_digest_mismatches`,
  `standalone_missing_digest_object_in_local_store_fails_validate`,
  `standalone_missing_local_digest_store_directory_fails_validate`,
  `standalone_static_bundle_without_local_digest_store_fails_validate`,
  `cloud_managed_static_bundles_without_object_authority_fail_validate`,
  `spa_fallback_never_masks_missing_assets_or_posts`,
  `spa_fallback_eligibility_rejects_api_namespace`,
  `head_verifies_via_port_head_without_authority_get`,
  `static_bundle_listener_preserves_sealed_bytes_under_compress`,
  `static_bundle_listener_drains_inflight_get_across_runtime_replace`,
  `sealed_content_encoding_is_emitted_without_accept_encoding_negotiation`,
  `gateway_new_fails_closed_on_a_usage_spool_identity_mismatch`,
  `with_managed_service_state_fails_construct_when_owner_lock_held`,
  `corrupt_managed_service_state_fails_gateway_construct_closed`,
  `linked_managed_service_state_fails_gateway_construct_closed`,
  `broadly_readable_managed_service_state_fails_gateway_construct_closed`,
  `ready_binding_missing_entrypoint_fails_gateway_construct_closed`,
  `ready_binding_max_priority_base_router_fails_gateway_construct_closed`,
  `retiring_state_without_the_exact_drain_key_fails_construct_closed`,
  `spool_storage_is_private_and_insecure_permissions_fail_closed`.
- New usage appends succeed; managed snapshot apply recovers exact revision.
