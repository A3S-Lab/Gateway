use super::*;

fn managed_acl(gateway_id: Uuid) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
entrypoints "web" {{ address = "127.0.0.1:8080" }}
"#
    )
}

fn durable_managed_acl(gateway_id: Uuid, state_file: &std::path::Path) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{
  gateway_id = "{gateway_id}"
  state_file = "{}"
}}
entrypoints "web" {{ address = "127.0.0.1:8080" }}
"#,
        state_file.display()
    )
}

fn inference_managed_acl(gateway_id: Uuid, expires_at: DateTime<Utc>) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
entrypoints "web" {{ address = "127.0.0.1:8080" }}
inference {{ expires_at = "{}" }}
"#,
        expires_at.to_rfc3339()
    )
}

fn snapshot(gateway_id: Uuid, revision: u64) -> ManagedSnapshot {
    let now = Utc::now();
    ManagedSnapshot::new(
        gateway_id,
        revision,
        (revision > 1).then_some(revision - 1),
        now,
        now + Duration::hours(1),
        managed_acl(gateway_id),
    )
}

fn durable_snapshot(
    gateway_id: Uuid,
    revision: u64,
    state_file: &std::path::Path,
) -> ManagedSnapshot {
    let now = Utc::now();
    ManagedSnapshot::new(
        gateway_id,
        revision,
        (revision > 1).then_some(revision - 1),
        now,
        now + Duration::hours(1),
        durable_managed_acl(gateway_id, state_file),
    )
}

#[test]
fn digest_is_over_exact_acl_bytes() {
    assert_ne!(digest_acl("mode {}"), digest_acl("mode {}\n"));
    assert_eq!(
        digest_acl(""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn managed_snapshot_debug_redacts_acl_content() {
    let gateway_id = Uuid::new_v4();
    let now = Utc::now();
    let sensitive = "verifier_hash-do-not-log";
    let snapshot = ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        now,
        now + Duration::hours(1),
        sensitive,
    );

    let debug = format!("{snapshot:?}");
    assert!(!debug.contains(sensitive));
    assert!(debug.contains("<redacted-config>"));
}

#[test]
fn selector_requires_all_exact_identity_fields() {
    let gateway_id = Uuid::new_v4();
    let digest = digest_acl("test");
    let query = format!("gateway_id={gateway_id}&revision=7&snapshot_digest={digest}");
    let selector = ManagedSnapshotIdentity::from_query(Some(&query))
        .unwrap()
        .unwrap();
    assert_eq!(selector.gateway_id, gateway_id);
    assert_eq!(selector.revision, 7);
    assert_eq!(selector.snapshot_digest, digest);

    assert!(ManagedSnapshotIdentity::from_query(Some("revision=7")).is_err());
}

#[test]
fn managed_snapshot_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<ManagedSnapshot>();
    assert_send_sync::<ManagedSnapshotStatus>();
    assert_send_sync::<ManagedSnapshotStore>();
}

#[tokio::test]
async fn exact_replay_does_not_reload() {
    let gateway_id = Uuid::new_v4();
    let store = ManagedSnapshotStore::new(Some(gateway_id), None);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(GatewayConfig::default()) })
        })
    };
    let snapshot = snapshot(gateway_id, 1);

    let first = store.apply(snapshot.clone(), Some(&callback)).await;
    assert_eq!(first.status.state, ManagedSnapshotState::Applied);
    assert!(first.status.ready);
    assert!(!first.status.replayed);

    let replay = store.apply(snapshot, Some(&callback)).await;
    assert_eq!(replay.status.state, ManagedSnapshotState::Applied);
    assert!(replay.status.ready);
    assert!(replay.status.replayed);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn exact_readiness_ends_at_snapshot_expiry() {
    let gateway_id = Uuid::new_v4();
    let store = ManagedSnapshotStore::new(Some(gateway_id), None);
    let callback: ManagedSnapshotReloadCallback =
        Arc::new(|_| Box::pin(async { Ok(GatewayConfig::default()) }));
    let snapshot = snapshot(gateway_id, 1);
    let identity = snapshot.identity();
    let expires_at = snapshot.expires_at;

    assert!(store.apply(snapshot, Some(&callback)).await.status.ready);
    let expired = store.status(Some(identity), expires_at);
    assert_eq!(expired.state, ManagedSnapshotState::Expired);
    assert!(!expired.ready);
}

#[tokio::test]
async fn inference_policy_expiry_must_match_the_atomic_managed_snapshot() {
    let gateway_id = Uuid::new_v4();
    let store = ManagedSnapshotStore::new(Some(gateway_id), None);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let calls = calls.clone();
        Arc::new(move |config| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                assert!(config.inference.is_some());
                Ok(GatewayConfig::default())
            })
        })
    };
    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::hours(1);
    let first = ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        issued_at,
        expires_at,
        inference_managed_acl(gateway_id, expires_at),
    );
    let first_identity = first.identity();

    let applied = store.apply(first, Some(&callback)).await;
    assert_eq!(applied.status.state, ManagedSnapshotState::Applied);
    assert!(applied.status.ready);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    let second_issued_at = Utc::now();
    let second_expires_at = second_issued_at + Duration::hours(1);
    let mismatch = ManagedSnapshot::new(
        gateway_id,
        2,
        Some(1),
        second_issued_at,
        second_expires_at,
        inference_managed_acl(gateway_id, second_expires_at - Duration::minutes(1)),
    );
    let rejected = store.apply(mismatch, Some(&callback)).await;

    assert_eq!(rejected.status_code, 422);
    assert_eq!(rejected.status.state, ManagedSnapshotState::Rejected);
    assert!(rejected
        .status
        .reason
        .unwrap()
        .contains("exactly match the managed snapshot expiry"));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(store.status(Some(first_identity), Utc::now()).ready);
}

#[tokio::test]
async fn concurrent_applies_are_serialized_by_revision() {
    let gateway_id = Uuid::new_v4();
    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id), None));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let entered = entered.clone();
        let release = release.clone();
        let calls = calls.clone();
        Arc::new(move |_| {
            let entered = entered.clone();
            let release = release.clone();
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if call == 0 {
                    entered.notify_one();
                    release.notified().await;
                }
                Ok(GatewayConfig::default())
            })
        })
    };
    let first_snapshot = snapshot(gateway_id, 1);
    let first_identity = first_snapshot.identity();
    let second_snapshot = snapshot(gateway_id, 2);
    let second_identity = second_snapshot.identity();

    let first = {
        let store = store.clone();
        let callback = callback.clone();
        tokio::spawn(async move { store.apply(first_snapshot, Some(&callback)).await })
    };
    entered.notified().await;
    assert_eq!(
        store.status(Some(first_identity), Utc::now()).state,
        ManagedSnapshotState::Applying
    );
    let second = {
        let store = store.clone();
        let callback = callback.clone();
        tokio::spawn(async move { store.apply(second_snapshot, Some(&callback)).await })
    };
    release.notify_one();

    assert_eq!(
        first.await.unwrap().status.state,
        ManagedSnapshotState::Applied
    );
    assert_eq!(
        second.await.unwrap().status.state,
        ManagedSnapshotState::Applied
    );
    assert!(store.status(Some(second_identity), Utc::now()).ready);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[tokio::test]
async fn durable_applied_snapshot_recovers_and_replays_without_reload() {
    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let snapshot = durable_snapshot(gateway_id, 1, &state_file);
    let store = ManagedSnapshotStore::new(Some(gateway_id), Some(state_file.clone()));
    let callback: ManagedSnapshotReloadCallback =
        Arc::new(|_| Box::pin(async { Ok(GatewayConfig::default()) }));

    let applied = store.apply(snapshot.clone(), Some(&callback)).await;
    assert_eq!(applied.status.state, ManagedSnapshotState::Applied);
    assert!(applied.status.ready);
    drop(store);

    let recovered = ManagedSnapshotStore::new(Some(gateway_id), Some(state_file));
    let recovery = recovered.load_recovery(Utc::now()).await.unwrap().unwrap();
    recovered
        .complete_recovery(recovery, Utc::now())
        .await
        .unwrap();
    assert!(
        recovered
            .status(Some(snapshot.identity()), Utc::now())
            .ready
    );

    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(GatewayConfig::default()) })
        })
    };
    let replay = recovered.apply(snapshot, Some(&callback)).await;
    assert!(replay.status.replayed);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn durable_snapshot_cannot_change_the_bootstrap_state_file() {
    let directory = tempfile::tempdir().unwrap();
    let bootstrap_state_file = directory.path().join("bootstrap.json");
    let candidate_state_file = directory.path().join("candidate.json");
    let gateway_id = Uuid::new_v4();
    let snapshot = durable_snapshot(gateway_id, 1, &candidate_state_file);
    let store = ManagedSnapshotStore::new(Some(gateway_id), Some(bootstrap_state_file.clone()));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(GatewayConfig::default()) })
        })
    };

    let result = store.apply(snapshot, Some(&callback)).await;
    assert_eq!(result.status_code, 409);
    assert!(result
        .status
        .reason
        .unwrap()
        .contains("bootstrap state_file"));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(tokio::fs::metadata(bootstrap_state_file).await.is_err());
    assert!(tokio::fs::metadata(candidate_state_file).await.is_err());
}

#[tokio::test]
async fn prepared_journal_is_completed_only_after_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let snapshot = durable_snapshot(gateway_id, 1, &state_file);
    let persistence = ManagedSnapshotPersistence::new(state_file.clone());
    persistence
        .write(&ManagedSnapshotJournal::prepared(snapshot.clone()))
        .await
        .unwrap();

    let store = ManagedSnapshotStore::new(Some(gateway_id), Some(state_file.clone()));
    let recovery = store.load_recovery(Utc::now()).await.unwrap().unwrap();
    let before = persistence.read().await.unwrap().unwrap();
    assert_eq!(before.phase, JournalPhase::Prepared);
    assert_eq!(
        store.status(None, Utc::now()).state,
        ManagedSnapshotState::Uninitialized
    );

    store.complete_recovery(recovery, Utc::now()).await.unwrap();
    let after = persistence.read().await.unwrap().unwrap();
    assert_eq!(after.phase, JournalPhase::Applied);
    assert!(store.status(Some(snapshot.identity()), Utc::now()).ready);
}

#[tokio::test]
async fn corrupt_durable_journal_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-snapshot.json");
    tokio::fs::write(&state_file, b"{not-json").await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&state_file, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
    }
    let store = ManagedSnapshotStore::new(Some(Uuid::new_v4()), Some(state_file));

    let error = store.load_recovery(Utc::now()).await.unwrap_err();
    assert!(error.to_string().contains("invalid JSON"));
}

#[tokio::test]
async fn durable_recovery_rejects_identity_digest_and_expiry_mismatches() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();

    let identity_file = directory.path().join("identity.json");
    let identity_snapshot = durable_snapshot(gateway_id, 1, &identity_file);
    ManagedSnapshotPersistence::new(identity_file.clone())
        .write(&ManagedSnapshotJournal::applied(
            identity_snapshot,
            Utc::now(),
        ))
        .await
        .unwrap();
    let identity_store = ManagedSnapshotStore::new(Some(Uuid::new_v4()), Some(identity_file));
    assert!(identity_store
        .load_recovery(Utc::now())
        .await
        .unwrap_err()
        .to_string()
        .contains("targets Gateway"));

    let digest_file = directory.path().join("digest.json");
    let mut digest_snapshot = durable_snapshot(gateway_id, 1, &digest_file);
    digest_snapshot.acl.push('\n');
    ManagedSnapshotPersistence::new(digest_file.clone())
        .write(&ManagedSnapshotJournal::applied(
            digest_snapshot,
            Utc::now(),
        ))
        .await
        .unwrap();
    let digest_store = ManagedSnapshotStore::new(Some(gateway_id), Some(digest_file));
    assert!(digest_store
        .load_recovery(Utc::now())
        .await
        .unwrap_err()
        .to_string()
        .contains("exact ACL bytes"));

    let expiry_file = directory.path().join("expiry.json");
    let mut expiry_snapshot = durable_snapshot(gateway_id, 1, &expiry_file);
    expiry_snapshot.issued_at = Utc::now() - Duration::hours(2);
    expiry_snapshot.expires_at = Utc::now() - Duration::hours(1);
    ManagedSnapshotPersistence::new(expiry_file.clone())
        .write(&ManagedSnapshotJournal::applied(
            expiry_snapshot,
            Utc::now() - Duration::hours(2),
        ))
        .await
        .unwrap();
    let expiry_store = ManagedSnapshotStore::new(Some(gateway_id), Some(expiry_file));
    assert!(expiry_store
        .load_recovery(Utc::now())
        .await
        .unwrap_err()
        .to_string()
        .contains("expired"));
}

#[cfg(unix)]
#[tokio::test]
async fn durable_journal_is_owner_readable_and_writable_only() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let snapshot = durable_snapshot(gateway_id, 1, &state_file);
    ManagedSnapshotPersistence::new(state_file.clone())
        .write(&ManagedSnapshotJournal::prepared(snapshot))
        .await
        .unwrap();

    let mode = tokio::fs::metadata(state_file)
        .await
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[tokio::test]
async fn durable_recovery_rejects_group_or_world_accessible_journal() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let snapshot = durable_snapshot(gateway_id, 1, &state_file);
    let persistence = ManagedSnapshotPersistence::new(state_file.clone());
    persistence
        .write(&ManagedSnapshotJournal::applied(snapshot, Utc::now()))
        .await
        .unwrap();
    tokio::fs::set_permissions(&state_file, PermissionsExt::from_mode(0o640))
        .await
        .unwrap();

    let store = ManagedSnapshotStore::new(Some(gateway_id), Some(state_file));
    let error = store.load_recovery(Utc::now()).await.unwrap_err();
    assert!(error.to_string().contains("group or other users"));
}

#[tokio::test]
async fn post_reload_storage_failure_rolls_runtime_back_and_disables_readiness() {
    let directory = tempfile::tempdir().unwrap();
    let state_file = directory.path().join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let snapshot = durable_snapshot(gateway_id, 1, &state_file);
    let store = ManagedSnapshotStore::new(Some(gateway_id), Some(state_file.clone()));
    let current_address = Arc::new(std::sync::Mutex::new("bootstrap".to_string()));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let current_address = current_address.clone();
        let calls = calls.clone();
        let state_file = state_file.clone();
        Arc::new(move |config| {
            let current_address = current_address.clone();
            let calls = calls.clone();
            let state_file = state_file.clone();
            Box::pin(async move {
                let next_address = config.entrypoints["web"].address.clone();
                let previous_address = {
                    let mut current = current_address.lock().unwrap();
                    std::mem::replace(&mut *current, next_address)
                };
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    tokio::fs::remove_file(&state_file).await.unwrap();
                    tokio::fs::create_dir(&state_file).await.unwrap();
                }
                let mut previous = GatewayConfig::default();
                previous.entrypoints.get_mut("web").unwrap().address = previous_address;
                Ok(previous)
            })
        })
    };

    let result = store.apply(snapshot, Some(&callback)).await;
    assert_eq!(result.status_code, 503);
    assert_eq!(result.status.state, ManagedSnapshotState::Applying);
    assert!(!result.status.ready);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(*current_address.lock().unwrap(), "bootstrap");
    assert!(result
        .status
        .reason
        .unwrap()
        .contains("journal rollback failed"));
}

#[tokio::test]
async fn post_reload_storage_failure_restores_the_prior_runtime_and_journal() {
    let directory = tempfile::tempdir().unwrap();
    let state_directory = directory.path().join("state");
    let backup_directory = directory.path().join("state-backup");
    let state_file = state_directory.join("managed-snapshot.json");
    let gateway_id = Uuid::new_v4();
    let snapshot = durable_snapshot(gateway_id, 1, &state_file);
    let store = ManagedSnapshotStore::new(Some(gateway_id), Some(state_file.clone()));
    let current_address = Arc::new(std::sync::Mutex::new("bootstrap".to_string()));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ManagedSnapshotReloadCallback = {
        let current_address = current_address.clone();
        let calls = calls.clone();
        let state_directory = state_directory.clone();
        let backup_directory = backup_directory.clone();
        Arc::new(move |config| {
            let current_address = current_address.clone();
            let calls = calls.clone();
            let state_directory = state_directory.clone();
            let backup_directory = backup_directory.clone();
            Box::pin(async move {
                let next_address = config.entrypoints["web"].address.clone();
                let previous_address = {
                    let mut current = current_address.lock().unwrap();
                    std::mem::replace(&mut *current, next_address)
                };
                match calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                    0 => {
                        tokio::fs::rename(&state_directory, &backup_directory)
                            .await
                            .unwrap();
                        tokio::fs::write(&state_directory, b"not-a-directory")
                            .await
                            .unwrap();
                    }
                    1 => {
                        tokio::fs::remove_file(&state_directory).await.unwrap();
                        tokio::fs::rename(&backup_directory, &state_directory)
                            .await
                            .unwrap();
                    }
                    _ => unreachable!("unexpected reload call"),
                }
                let mut previous = GatewayConfig::default();
                previous.entrypoints.get_mut("web").unwrap().address = previous_address;
                Ok(previous)
            })
        })
    };

    let result = store.apply(snapshot, Some(&callback)).await;
    assert_eq!(result.status_code, 503);
    assert_eq!(result.status.state, ManagedSnapshotState::Rejected);
    assert!(!result.status.ready);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(*current_address.lock().unwrap(), "bootstrap");
    let reason = result.status.reason.unwrap();
    assert!(reason.contains("prior runtime was restored"));
    assert!(reason.contains("prior journal was restored"));
    assert!(tokio::fs::metadata(state_file).await.is_err());
}
