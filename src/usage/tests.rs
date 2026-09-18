use super::{UsageCursor, UsageSpool, UsageSpoolError, UsageSpoolOptions, MAX_USAGE_EVENT_BYTES};
use uuid::Uuid;

fn options(directory: &std::path::Path, gateway_id: Uuid, max_bytes: u64) -> UsageSpoolOptions {
    UsageSpoolOptions {
        directory: spool_directory(directory),
        gateway_id,
        max_bytes,
    }
}

fn spool_directory(directory: &std::path::Path) -> std::path::PathBuf {
    directory.join("usage-spool")
}

#[tokio::test]
async fn append_is_durable_ordered_and_byte_preserving() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    let boot_epoch = spool.status().boot_epoch;
    let first_id = Uuid::new_v4();
    let second_id = Uuid::new_v4();

    let first = spool
        .append(first_id, br#"{"kind":"first"}"#)
        .await
        .unwrap();
    let second = spool.append(second_id, b"\x00binary\xff").await.unwrap();

    assert_eq!(
        first,
        UsageCursor {
            boot_epoch,
            sequence: 1
        }
    );
    assert_eq!(
        second,
        UsageCursor {
            boot_epoch,
            sequence: 2
        }
    );
    let records = spool.read_batch(None, 10).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].event_id, first_id);
    assert_eq!(records[0].payload, br#"{"kind":"first"}"#);
    assert_eq!(records[1].event_id, second_id);
    assert_eq!(records[1].payload, b"\x00binary\xff");

    let status = spool.status();
    assert!(status.writable);
    assert_eq!(status.gateway_id, gateway_id);
    assert_eq!(status.boot_epoch, boot_epoch);
    assert_eq!(status.next_sequence, 3);
    assert_eq!(status.retained_records, 2);
    assert!(status.retained_bytes > 0);
    assert_eq!(status.capacity_bytes, 1024 * 1024);
    assert_eq!(status.reason, None);
}

#[tokio::test]
async fn restart_retains_old_epochs_and_exact_event_replay_is_idempotent() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let first_cursor = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(event_id, b"stable").await.unwrap()
    };

    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    assert_ne!(spool.status().boot_epoch, first_cursor.boot_epoch);
    assert_eq!(
        spool.append(event_id, b"stable").await.unwrap(),
        first_cursor
    );

    let conflict = spool.append(event_id, b"changed").await.unwrap_err();
    assert!(matches!(conflict, UsageSpoolError::EventConflict { .. }));

    let second_id = Uuid::new_v4();
    let second_cursor = spool.append(second_id, b"next boot").await.unwrap();
    assert_eq!(second_cursor.boot_epoch, spool.status().boot_epoch);
    assert_eq!(second_cursor.sequence, 1);

    let first_batch = spool.read_batch(None, 1).await.unwrap();
    assert_eq!(first_batch.len(), 1);
    assert_eq!(first_batch[0].cursor, first_cursor);
    let second_batch = spool
        .read_batch(Some(first_batch[0].cursor), 10)
        .await
        .unwrap();
    assert_eq!(second_batch.len(), 1);
    assert_eq!(second_batch[0].cursor, second_cursor);
}

#[tokio::test]
async fn capacity_and_event_size_fail_explicitly_without_advancing_sequence() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let spool = UsageSpool::open(options(directory.path(), gateway_id, 16 * 1024))
        .await
        .unwrap();
    let first = spool
        .append(Uuid::new_v4(), &vec![b'a'; 8 * 1024])
        .await
        .unwrap();
    assert_eq!(first.sequence, 1);

    let full = spool
        .append(Uuid::new_v4(), &vec![b'b'; 8 * 1024])
        .await
        .unwrap_err();
    assert!(matches!(full, UsageSpoolError::Full { .. }));
    assert_eq!(spool.status().next_sequence, 2);

    let oversized = spool
        .append(Uuid::new_v4(), &vec![0; MAX_USAGE_EVENT_BYTES + 1])
        .await
        .unwrap_err();
    assert!(matches!(oversized, UsageSpoolError::EventTooLarge { .. }));
    assert_eq!(spool.status().retained_records, 1);
}

#[tokio::test]
async fn a_spool_directory_is_exclusively_owned_by_one_process() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let first = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();

    let second = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(
        matches!(second, UsageSpoolError::Locked { .. }),
        "expected a lock-contention error, got {second:?}"
    );

    drop(first);
    UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
}

#[tokio::test]
async fn probe_activation_fails_closed_when_exclusive_lock_is_held() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let held = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();

    let error = super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        true,
    )
    .unwrap_err();
    assert!(
        matches!(error, UsageSpoolError::Locked { .. }),
        "cold-start probe must fail Locked while another process holds .lock: {error}"
    );

    // Runtime re-validation after open must skip lock probe.
    super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        false,
    )
    .expect("post-open probe must not contend with the caller's held lock");

    drop(held);
}

#[tokio::test]
async fn probe_activation_fails_closed_when_spool_parent_is_not_a_directory() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let blocker = directory.path().join("not-a-directory");
    std::fs::write(&blocker, b"blocker").unwrap();
    let spool = blocker.join("usage-spool");

    let error = super::persistence::probe_activation(
        &UsageSpoolOptions {
            directory: spool.clone(),
            gateway_id,
            max_bytes: 1024 * 1024,
        },
        true,
    )
    .unwrap_err();
    assert!(
        matches!(error, UsageSpoolError::Io { .. })
            || error.to_string().contains("create directory"),
        "cold-start probe must fail when spool parent cannot be created: {error}"
    );

    // Runtime re-validation must not create-or-fail on a missing path.
    super::persistence::probe_activation(
        &UsageSpoolOptions {
            directory: spool,
            gateway_id,
            max_bytes: 1024 * 1024,
        },
        false,
    )
    .expect("post-open probe must skip missing-directory create");
}

#[tokio::test]
#[cfg(unix)]
async fn probe_activation_fails_closed_when_usage_spool_directory_is_not_writable() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let spool_dir = spool_directory(directory.path());
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.shutdown().await;
    }
    // Keep .lock so exclusive lock still succeeds; only create_new for a boot
    // epoch (and the activation probe) must fail.
    let mut permissions = std::fs::metadata(&spool_dir).unwrap().permissions();
    permissions.set_mode(0o555);
    std::fs::set_permissions(&spool_dir, permissions).unwrap();

    let error = super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        true,
    )
    .unwrap_err();
    assert!(
        matches!(error, UsageSpoolError::Io { .. })
            && error.to_string().contains("activation probe"),
        "cold-start probe must fail closed when the spool directory rejects create_new: {error}"
    );
    let open_error = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(
        matches!(open_error, UsageSpoolError::Io { .. }),
        "open must share create_new fail-closed: {open_error}"
    );

    // Restore writability so TempDir cleanup succeeds.
    let mut permissions = std::fs::metadata(&spool_dir).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&spool_dir, permissions).unwrap();
}

#[tokio::test]
async fn probe_activation_write_probe_leaves_no_untracked_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.shutdown().await;
    }
    super::persistence::probe_activation(&options(directory.path(), gateway_id, 1024 * 1024), true)
        .expect("writable spool must pass cold-start write probe");
    let leftover = std::fs::read_dir(spool_directory(directory.path()))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".a3s-usage-spool-activation-probe.")
        });
    assert!(
        !leftover,
        "activation write probe must remove its temporary file"
    );
}

#[tokio::test]
async fn gateway_identity_mismatch_and_corruption_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"retained").await.unwrap();
    }

    let mismatch = UsageSpool::open(options(directory.path(), Uuid::new_v4(), 1024 * 1024))
        .await
        .unwrap_err();
    assert!(matches!(
        mismatch,
        UsageSpoolError::GatewayIdentityMismatch { .. }
    ));

    let manifest =
        tokio::fs::read_to_string(spool_directory(directory.path()).join("manifest.json"))
            .await
            .unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    let segment = manifest["epochs"][0]["file"].as_str().unwrap();
    let segment_path = spool_directory(directory.path()).join(segment);
    let mut bytes = tokio::fs::read(&segment_path).await.unwrap();
    let last = bytes.len() - 2;
    bytes[last] ^= 0x01;
    tokio::fs::write(&segment_path, bytes).await.unwrap();

    let corrupt = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(matches!(corrupt, UsageSpoolError::Corrupt { .. }));
}

#[tokio::test]
async fn unknown_replay_cursor_is_reported_as_a_gap() {
    let directory = tempfile::tempdir().unwrap();
    let spool = UsageSpool::open(options(directory.path(), Uuid::new_v4(), 1024 * 1024))
        .await
        .unwrap();
    spool.append(Uuid::new_v4(), b"record").await.unwrap();

    let error = spool
        .read_batch(
            Some(UsageCursor {
                boot_epoch: Uuid::new_v4(),
                sequence: 99,
            }),
            10,
        )
        .await
        .unwrap_err();
    assert!(matches!(error, UsageSpoolError::CursorGap { .. }));
}

#[tokio::test]
async fn terminal_reservation_survives_response_side_enqueue_and_flushes_before_shutdown() {
    let directory = tempfile::tempdir().unwrap();
    let spool = UsageSpool::open(options(directory.path(), Uuid::new_v4(), 1024 * 1024))
        .await
        .unwrap();
    let start_id = Uuid::new_v4();
    let terminal_id = Uuid::new_v4();
    let (_, reservation) = spool
        .append_reserving_terminal(start_id, b"started")
        .await
        .unwrap();
    assert!(spool.status().reserved_bytes > 0);

    let receipt = reservation
        .commit(terminal_id, b"terminal".to_vec())
        .unwrap();
    let terminal_cursor = receipt.wait().await.unwrap();
    assert_eq!(terminal_cursor.sequence, 2);
    assert_eq!(spool.status().reserved_bytes, 0);

    let records = spool.read_batch(None, 10).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].event_id, start_id);
    assert_eq!(records[1].event_id, terminal_id);
    spool.shutdown().await;
}

#[tokio::test]
async fn dropping_a_terminal_reservation_releases_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let spool = UsageSpool::open(options(directory.path(), Uuid::new_v4(), 1024 * 1024))
        .await
        .unwrap();
    let (_, reservation) = spool
        .append_reserving_terminal(Uuid::new_v4(), b"started")
        .await
        .unwrap();
    assert!(spool.status().reserved_bytes > 0);
    drop(reservation);

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while spool.status().reserved_bytes != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(spool.status().reserved_bytes, 0);
    spool.shutdown().await;
}

#[tokio::test]
async fn shutdown_drains_an_unobserved_terminal_append() {
    let directory = tempfile::tempdir().unwrap();
    let spool = UsageSpool::open(options(directory.path(), Uuid::new_v4(), 1024 * 1024))
        .await
        .unwrap();
    let (_, reservation) = spool
        .append_reserving_terminal(Uuid::new_v4(), b"started")
        .await
        .unwrap();
    let receipt = reservation
        .commit(Uuid::new_v4(), b"terminal".to_vec())
        .unwrap();
    drop(receipt);

    spool.shutdown().await;
    let records = spool.read_batch(None, 10).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[1].payload, b"terminal");
    assert_eq!(spool.status().reserved_bytes, 0);
}

#[cfg(unix)]
#[tokio::test]
async fn spool_storage_is_private_and_insecure_permissions_fail_closed() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let path = spool_directory(directory.path());
    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    spool.append(Uuid::new_v4(), b"private").await.unwrap();

    let directory_mode = tokio::fs::metadata(&path)
        .await
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(directory_mode & 0o077, 0);
    let mut entries = tokio::fs::read_dir(&path).await.unwrap();
    while let Some(entry) = entries.next_entry().await.unwrap() {
        let metadata = entry.metadata().await.unwrap();
        assert_eq!(metadata.permissions().mode() & 0o077, 0);
    }
    drop(spool);

    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .await
        .unwrap();
    let error = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(matches!(error, UsageSpoolError::Corrupt { .. }));
}

#[tokio::test]
async fn probe_activation_rejects_untracked_paths_like_open() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"tracked").await.unwrap();
        spool.shutdown().await;
    }
    let junk = spool_directory(directory.path()).join("untracked.txt");
    tokio::fs::write(&junk, b"should not be here")
        .await
        .unwrap();

    let error = super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(error, UsageSpoolError::Corrupt { .. }) && error.to_string().contains("untracked"),
        "unexpected probe error: {error}"
    );
    let open_error = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(
        matches!(open_error, UsageSpoolError::Corrupt { .. })
            && open_error.to_string().contains("untracked"),
        "open must share untracked fail-closed: {open_error}"
    );
}

#[tokio::test]
async fn probe_activation_fails_closed_when_ready_epoch_record_is_corrupt() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"tracked").await.unwrap();
        spool.shutdown().await;
    }
    let spool_dir = spool_directory(directory.path());
    let epoch = std::fs::read_dir(&spool_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().starts_with("epoch-"))
        .expect("shutdown must leave a Ready epoch file");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(epoch.path())
        .unwrap();
    std::io::Write::write_all(&mut file, b"truncated").unwrap();
    drop(file);

    let error = super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(error, UsageSpoolError::Corrupt { .. })
            && error.to_string().contains("incomplete"),
        "probe must fail closed on a corrupt Ready epoch record: {error}"
    );
    let open_error = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(
        matches!(open_error, UsageSpoolError::Corrupt { .. })
            && open_error.to_string().contains("incomplete"),
        "open must share corrupt-record fail-closed: {open_error}"
    );
}

fn rewrite_manifest_phase(directory: &std::path::Path, from: &str, to: &str) {
    let path = spool_directory(directory).join("manifest.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let needle = format!("\"phase\":\"{from}\"");
    let updated = text.replacen(&needle, &format!("\"phase\":\"{to}\""), 1);
    assert_ne!(text, updated, "manifest was missing {needle}");
    std::fs::write(path, updated).unwrap();
}

#[tokio::test]
async fn probe_activation_fails_closed_when_prepared_epoch_record_is_corrupt() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"tracked").await.unwrap();
        spool.shutdown().await;
    }
    rewrite_manifest_phase(directory.path(), "ready", "prepared");
    let epoch = std::fs::read_dir(spool_directory(directory.path()))
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().starts_with("epoch-"))
        .expect("shutdown must leave an epoch file");
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(epoch.path())
        .unwrap();
    std::io::Write::write_all(&mut file, b"truncated").unwrap();
    drop(file);

    let error = super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(error, UsageSpoolError::Corrupt { .. })
            && error.to_string().contains("incomplete"),
        "probe must fail closed on a corrupt Prepared epoch record: {error}"
    );
    let open_error = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(
        matches!(open_error, UsageSpoolError::Corrupt { .. })
            && open_error.to_string().contains("incomplete"),
        "open must share Prepared corrupt-record fail-closed: {open_error}"
    );
}

#[tokio::test]
async fn probe_activation_accepts_deleted_retiring_epoch_like_open() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.shutdown().await;
    }
    rewrite_manifest_phase(directory.path(), "ready", "gc");
    let spool_dir = spool_directory(directory.path());
    let epoch = std::fs::read_dir(&spool_dir)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().starts_with("epoch-"))
        .expect("shutdown must leave an epoch file");
    std::fs::remove_file(epoch.path()).unwrap();

    super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        false,
    )
    .expect("probe must accept a Retiring epoch whose file recovery would delete");
    UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .expect("open must recover a missing Retiring epoch");
}

#[tokio::test]
async fn probe_activation_fails_closed_when_recovery_artifact_is_a_directory() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.shutdown().await;
    }
    let spool_dir = spool_directory(directory.path());
    let staging_file = spool_dir.join(".manifest-ok.tmp");
    std::fs::write(&staging_file, b"stale").unwrap();
    super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        false,
    )
    .expect("a regular manifest staging file is removed by open");
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .expect("open must delete a regular manifest staging file");
        spool.shutdown().await;
    }
    assert!(!staging_file.exists());

    let artifact = spool_dir.join(".manifest-blocked.tmp");
    std::fs::create_dir(&artifact).unwrap();
    let error = super::persistence::probe_activation(
        &options(directory.path(), gateway_id, 1024 * 1024),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(error, UsageSpoolError::Io { .. }),
        "probe must fail when a recovery artifact is a directory: {error}"
    );
    let open_error = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(
        matches!(open_error, UsageSpoolError::Io { .. }),
        "open must fail when a recovery artifact is a directory: {open_error}"
    );
}

#[tokio::test]
async fn probe_activation_rejects_retained_bytes_over_capacity_like_open() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool
            .append(Uuid::new_v4(), &vec![b'x'; 8 * 1024])
            .await
            .unwrap();
        spool.shutdown().await;
    }
    // Tiny capacity still validates options but retained bytes exceed it.
    let error =
        super::persistence::probe_activation(&options(directory.path(), gateway_id, 64), false)
            .unwrap_err();
    assert!(
        matches!(error, UsageSpoolError::Full { .. }),
        "probe must fail Full when retained bytes exceed capacity: {error}"
    );
}

#[tokio::test]
async fn probe_activation_projects_empty_epoch_reclaim_before_capacity_like_open() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        // No append: shutdown leaves an empty Ready epoch that open reclaims
        // before the capacity / boot-headroom gates.
        spool.shutdown().await;
    }

    let spool_dir = spool_directory(directory.path());
    let mut retained_bytes = 0_u64;
    for entry in std::fs::read_dir(&spool_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".lock" {
            continue;
        }
        retained_bytes += entry.metadata().unwrap().len();
    }
    assert!(
        retained_bytes > 1,
        "empty spool must retain manifest + epoch bytes"
    );

    // Capacity one byte under on-disk retained. Without reclaim projection,
    // validate Full-fails with requested_bytes == 0 (retained > capacity).
    // With reclaim, the empty epoch is dropped first so either probe succeeds
    // or Full reports post-reclaim boot headroom (requested_bytes > 0).
    let under_retained = retained_bytes - 1;
    match super::persistence::probe_activation(
        &options(directory.path(), gateway_id, under_retained),
        false,
    ) {
        Ok(()) => {
            let spool = UsageSpool::open(options(directory.path(), gateway_id, under_retained))
                .await
                .expect("open must reclaim the empty epoch then allocate a boot epoch");
            spool.shutdown().await;
        }
        Err(UsageSpoolError::Full {
            retained_bytes: projected_retained,
            requested_bytes,
            ..
        }) if requested_bytes > 0 => {
            assert!(
                projected_retained < retained_bytes,
                "reclaim projection must drop empty-epoch bytes before boot headroom ({projected_retained} vs on-disk {retained_bytes})"
            );
            let capacity = projected_retained
                .checked_add(requested_bytes)
                .expect("capacity overflow");
            super::persistence::probe_activation(
                &options(directory.path(), gateway_id, capacity),
                false,
            )
            .expect("probe must project empty-epoch reclaim before capacity");
            let spool = UsageSpool::open(options(directory.path(), gateway_id, capacity))
                .await
                .expect("open must reclaim the empty epoch then allocate a boot epoch");
            spool.shutdown().await;
        }
        other => panic!(
            "expected Ok or Full boot-headroom after empty-epoch reclaim projection, got {other:?}"
        ),
    }
}

#[tokio::test]
async fn probe_activation_rejects_missing_boot_epoch_headroom_like_open() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool
            .append(Uuid::new_v4(), &vec![b'y'; 4 * 1024])
            .await
            .unwrap();
        spool.shutdown().await;
    }

    let spool_dir = spool_directory(directory.path());
    let mut retained_bytes = 0_u64;
    for entry in std::fs::read_dir(&spool_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".lock" {
            continue;
        }
        retained_bytes += entry.metadata().unwrap().len();
    }

    // Capacity fits retained bytes but not the mandatory new boot epoch.
    let tight_capacity = retained_bytes;
    let error = super::persistence::probe_activation(
        &options(directory.path(), gateway_id, tight_capacity),
        false,
    )
    .unwrap_err();
    assert!(
        matches!(
            error,
            UsageSpoolError::Full {
                requested_bytes: requested,
                ..
            } if requested > 0
        ),
        "probe must fail Full for missing boot-epoch headroom: {error}"
    );

    let open_error = UsageSpool::open(options(directory.path(), gateway_id, tight_capacity))
        .await
        .unwrap_err();
    assert!(
        matches!(
            open_error,
            UsageSpoolError::Full {
                requested_bytes: requested,
                ..
            } if requested > 0
        ),
        "open must share boot-epoch headroom fail-closed: {open_error}"
    );
}
