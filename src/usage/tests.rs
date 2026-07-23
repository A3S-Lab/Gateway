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
    assert!(matches!(second, UsageSpoolError::Locked { .. }));

    drop(first);
    UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
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
