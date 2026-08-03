use super::{UsageCursor, UsageSpool, UsageSpoolError, UsageSpoolOptions};
use std::path::{Path, PathBuf};
use uuid::Uuid;

fn spool_directory(directory: &Path) -> PathBuf {
    directory.join("usage-spool")
}

fn options(directory: &Path, gateway_id: Uuid, max_bytes: u64) -> UsageSpoolOptions {
    UsageSpoolOptions {
        directory: spool_directory(directory),
        gateway_id,
        max_bytes,
    }
}

async fn read_manifest(directory: &Path) -> serde_json::Value {
    let bytes = tokio::fs::read(spool_directory(directory).join("manifest.json"))
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn write_manifest(directory: &Path, manifest: &serde_json::Value) {
    let mut bytes = serde_json::to_vec(manifest).unwrap();
    bytes.push(b'\n');
    tokio::fs::write(spool_directory(directory).join("manifest.json"), bytes)
        .await
        .unwrap();
}

async fn rewrite_segments_as_v1(directory: &Path, manifest: &serde_json::Value) {
    for epoch in manifest["epochs"].as_array().unwrap() {
        let path = spool_directory(directory).join(epoch["file"].as_str().unwrap());
        let bytes = tokio::fs::read(&path).await.unwrap();
        let header_end = bytes.iter().position(|byte| *byte == b'\n').unwrap();
        let mut header: serde_json::Value = serde_json::from_slice(&bytes[..header_end]).unwrap();
        header["schema"] =
            serde_json::Value::String("a3s.gateway.usage-spool-segment.v1".to_string());
        header.as_object_mut().unwrap().remove("first_sequence");
        let mut migrated = serde_json::to_vec(&header).unwrap();
        migrated.push(b'\n');
        migrated.extend_from_slice(&bytes[header_end + 1..]);
        tokio::fs::write(path, migrated).await.unwrap();
    }
}

fn manifest_cursor(cursor: UsageCursor) -> serde_json::Value {
    serde_json::json!({
        "boot_epoch": cursor.boot_epoch,
        "sequence": format!("{:016x}", cursor.sequence),
    })
}

#[tokio::test]
async fn exact_acknowledgement_is_contiguous_idempotent_and_restart_durable() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let first_id = Uuid::new_v4();
    let second_id = Uuid::new_v4();
    let third_id = Uuid::new_v4();
    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    let first = spool.append(first_id, b"first").await.unwrap();
    let second = spool.append(second_id, b"second").await.unwrap();
    let third = spool.append(third_id, b"third").await.unwrap();
    let manifest_bytes_before =
        tokio::fs::metadata(spool_directory(directory.path()).join("manifest.json"))
            .await
            .unwrap()
            .len();

    let acknowledged = spool.acknowledge(second).await.unwrap();
    assert_eq!(acknowledged.acknowledged_through, second);
    assert_eq!(acknowledged.newly_acknowledged_records, 2);
    assert_eq!(acknowledged.reclaimed_bytes, 0);
    assert!(!acknowledged.cleanup_pending);

    let status = spool.status();
    assert_eq!(status.acknowledged_through, Some(second));
    assert_eq!(status.oldest_retained_cursor, Some(third));
    assert_eq!(status.retained_records, 1);
    let records = spool.read_batch(Some(second), 10).await.unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].cursor, third);
    assert!(matches!(
        spool.read_batch(Some(first), 10).await.unwrap_err(),
        UsageSpoolError::CursorGap { .. }
    ));
    assert!(matches!(
        spool
            .acknowledge(UsageCursor {
                boot_epoch: Uuid::new_v4(),
                sequence: 1,
            })
            .await
            .unwrap_err(),
        UsageSpoolError::CursorGap { .. }
    ));

    let replay = spool.append(first_id, b"first").await.unwrap();
    assert_eq!(replay, first, "physical retention keeps append idempotent");
    let repeated = spool.acknowledge(second).await.unwrap();
    assert_eq!(repeated.newly_acknowledged_records, 0);
    assert_eq!(repeated.reclaimed_bytes, 0);
    let manifest_bytes_after =
        tokio::fs::metadata(spool_directory(directory.path()).join("manifest.json"))
            .await
            .unwrap()
            .len();
    assert!(manifest_bytes_after <= manifest_bytes_before);
    drop(spool);

    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    let status = spool.status();
    assert_eq!(status.acknowledged_through, Some(second));
    assert_eq!(status.oldest_retained_cursor, Some(third));
    assert_eq!(status.retained_records, 1);
    assert_eq!(
        spool.read_batch(Some(second), 10).await.unwrap()[0].cursor,
        third
    );
}

#[tokio::test]
async fn acknowledgement_manifest_size_is_constant_across_sequence_widths() {
    let directory = tempfile::tempdir().unwrap();
    let spool = UsageSpool::open(options(directory.path(), Uuid::new_v4(), 1024 * 1024))
        .await
        .unwrap();
    let mut cursors = Vec::new();
    for _ in 0..10 {
        cursors.push(spool.append(Uuid::new_v4(), b"record").await.unwrap());
    }

    spool.acknowledge(cursors[8]).await.unwrap();
    let nine_bytes = tokio::fs::metadata(spool_directory(directory.path()).join("manifest.json"))
        .await
        .unwrap()
        .len();
    spool.acknowledge(cursors[9]).await.unwrap();
    let ten_bytes = tokio::fs::metadata(spool_directory(directory.path()).join("manifest.json"))
        .await
        .unwrap()
        .len();

    assert_eq!(nine_bytes, ten_bytes);
    assert_eq!(spool.status().acknowledged_through, Some(cursors[9]));
}

#[tokio::test]
async fn acknowledging_a_closed_epoch_reclaims_only_its_segment() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let max_bytes = 16 * 1024;
    let first = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, max_bytes))
            .await
            .unwrap();
        spool
            .append(Uuid::new_v4(), &vec![b'a'; 6000])
            .await
            .unwrap()
    };
    let manifest = read_manifest(directory.path()).await;
    let first_file = manifest["epochs"][0]["file"].as_str().unwrap();
    let first_path = spool_directory(directory.path()).join(first_file);
    assert!(first_path.exists());

    let spool = UsageSpool::open(options(directory.path(), gateway_id, max_bytes))
        .await
        .unwrap();
    let second_id = Uuid::new_v4();
    assert!(matches!(
        spool
            .append(second_id, &vec![b'b'; 6000])
            .await
            .unwrap_err(),
        UsageSpoolError::Full { .. }
    ));
    let retained_before = spool.status().retained_bytes;
    let acknowledged = spool.acknowledge(first).await.unwrap();

    assert_eq!(acknowledged.newly_acknowledged_records, 1);
    assert!(acknowledged.reclaimed_bytes > 6000);
    assert!(!acknowledged.cleanup_pending);
    assert!(!first_path.exists());
    assert_eq!(spool.status().retained_records, 0);
    assert!(spool.status().retained_bytes < retained_before);
    let second = spool.append(second_id, &vec![b'b'; 6000]).await.unwrap();
    let status = spool.status();
    assert_eq!(status.acknowledged_through, Some(first));
    assert_eq!(status.oldest_retained_cursor, Some(second));
    assert_eq!(status.retained_records, 1);
    assert_eq!(
        spool.read_batch(Some(first), 10).await.unwrap()[0].cursor,
        second
    );
    drop(spool);

    let spool = UsageSpool::open(options(directory.path(), gateway_id, max_bytes))
        .await
        .unwrap();
    assert_eq!(spool.status().acknowledged_through, Some(first));
    assert_eq!(spool.status().retained_records, 1);
    assert_eq!(
        spool.read_batch(Some(first), 10).await.unwrap()[0].cursor,
        second
    );
}

#[tokio::test]
async fn restart_reclaims_a_current_epoch_that_was_fully_acknowledged() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    let cursor = spool.append(Uuid::new_v4(), b"current").await.unwrap();
    let manifest = read_manifest(directory.path()).await;
    let file = manifest["epochs"][0]["file"].as_str().unwrap().to_string();
    let segment = spool_directory(directory.path()).join(file);
    let acknowledged = spool.acknowledge(cursor).await.unwrap();
    assert_eq!(acknowledged.reclaimed_bytes, 0);
    assert!(
        segment.exists(),
        "the live append segment cannot be removed"
    );
    drop(spool);

    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    assert!(!segment.exists());
    assert_eq!(spool.status().acknowledged_through, Some(cursor));
    assert_eq!(spool.status().retained_records, 0);
}

#[tokio::test]
async fn startup_finishes_a_committed_retiring_epoch() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let cursor = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"acknowledged").await.unwrap()
    };
    let mut manifest = read_manifest(directory.path()).await;
    let file = manifest["epochs"][0]["file"].as_str().unwrap().to_string();
    manifest["acknowledged_through"] = manifest_cursor(cursor);
    manifest["epochs"][0]["phase"] = serde_json::Value::String("gc".to_string());
    write_manifest(directory.path(), &manifest).await;
    let segment = spool_directory(directory.path()).join(file);
    assert!(segment.exists());

    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    assert!(!segment.exists());
    assert_eq!(spool.status().acknowledged_through, Some(cursor));
    assert_eq!(spool.status().retained_records, 0);
    assert!(spool.read_batch(Some(cursor), 10).await.unwrap().is_empty());
    let recovered = read_manifest(directory.path()).await;
    assert!(recovered["epochs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|epoch| epoch["phase"] == "ready"));
}

#[tokio::test]
async fn startup_finishes_retirement_after_the_segment_was_already_removed() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let cursor = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"acknowledged").await.unwrap()
    };
    let mut manifest = read_manifest(directory.path()).await;
    let file = manifest["epochs"][0]["file"].as_str().unwrap().to_string();
    manifest["acknowledged_through"] = manifest_cursor(cursor);
    manifest["epochs"][0]["phase"] = serde_json::Value::String("gc".to_string());
    write_manifest(directory.path(), &manifest).await;
    tokio::fs::remove_file(spool_directory(directory.path()).join(file))
        .await
        .unwrap();

    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    assert_eq!(spool.status().acknowledged_through, Some(cursor));
    assert_eq!(spool.status().retained_records, 0);
    assert!(spool.read_batch(Some(cursor), 10).await.unwrap().is_empty());
}

#[tokio::test]
async fn legacy_manifest_migrates_without_losing_retained_records() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let cursor = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"legacy").await.unwrap()
    };
    let mut manifest = read_manifest(directory.path()).await;
    manifest["schema"] =
        serde_json::Value::String("a3s.gateway.usage-spool-manifest.v1".to_string());
    manifest
        .as_object_mut()
        .unwrap()
        .remove("acknowledged_through");
    for epoch in manifest["epochs"].as_array_mut().unwrap() {
        epoch.as_object_mut().unwrap().remove("first_sequence");
        epoch
            .as_object_mut()
            .unwrap()
            .remove("compacted_last_sequence");
    }
    rewrite_segments_as_v1(directory.path(), &manifest).await;
    write_manifest(directory.path(), &manifest).await;

    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    assert_eq!(spool.status().acknowledged_through, None);
    assert_eq!(spool.status().oldest_retained_cursor, Some(cursor));
    assert_eq!(spool.read_batch(None, 10).await.unwrap()[0].cursor, cursor);
    let migrated = read_manifest(directory.path()).await;
    assert_eq!(migrated["schema"], "a3s.gateway.usage-spool-manifest.v3");
    assert_eq!(
        migrated["acknowledged_through"]["sequence"],
        "ffffffffffffffff"
    );
    assert_eq!(migrated["epochs"][0]["first_sequence"], "0000000000000001");
    assert_eq!(
        migrated["epochs"][0]["compacted_last_sequence"],
        "0000000000000000"
    );
}

#[tokio::test]
async fn v2_manifest_migrates_to_v3_without_losing_acknowledgement() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (first, second) = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        let first = spool.append(Uuid::new_v4(), b"acknowledged").await.unwrap();
        let second = spool.append(Uuid::new_v4(), b"retained").await.unwrap();
        spool.acknowledge(first).await.unwrap();
        (first, second)
    };
    let mut manifest = read_manifest(directory.path()).await;
    manifest["schema"] =
        serde_json::Value::String("a3s.gateway.usage-spool-manifest.v2".to_string());
    for epoch in manifest["epochs"].as_array_mut().unwrap() {
        epoch.as_object_mut().unwrap().remove("first_sequence");
        epoch
            .as_object_mut()
            .unwrap()
            .remove("compacted_last_sequence");
    }
    rewrite_segments_as_v1(directory.path(), &manifest).await;
    write_manifest(directory.path(), &manifest).await;

    let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap();
    assert_eq!(spool.status().acknowledged_through, Some(first));
    assert_eq!(spool.status().oldest_retained_cursor, Some(second));
    assert_eq!(
        spool.read_batch(Some(first), 10).await.unwrap()[0].cursor,
        second
    );
    let migrated = read_manifest(directory.path()).await;
    assert_eq!(migrated["schema"], "a3s.gateway.usage-spool-manifest.v3");
    assert_eq!(migrated["epochs"][0]["first_sequence"], "0000000000000002");
    assert_eq!(
        migrated["epochs"][0]["compacted_last_sequence"],
        "0000000000000002"
    );
}

#[tokio::test]
async fn acknowledgement_cursor_past_the_epoch_fails_closed_on_restart() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let cursor = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"retained").await.unwrap()
    };
    let mut manifest = read_manifest(directory.path()).await;
    manifest["acknowledged_through"] = manifest_cursor(UsageCursor {
        boot_epoch: cursor.boot_epoch,
        sequence: cursor.sequence + 1,
    });
    write_manifest(directory.path(), &manifest).await;

    let error = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(matches!(error, UsageSpoolError::Corrupt { .. }));
}

#[tokio::test]
async fn malformed_fixed_width_acknowledgement_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
            .await
            .unwrap();
        spool.append(Uuid::new_v4(), b"retained").await.unwrap();
    }
    let mut manifest = read_manifest(directory.path()).await;
    manifest["acknowledged_through"]["sequence"] =
        serde_json::Value::String("000000000000000g".to_string());
    write_manifest(directory.path(), &manifest).await;

    let error = UsageSpool::open(options(directory.path(), gateway_id, 1024 * 1024))
        .await
        .unwrap_err();
    assert!(matches!(error, UsageSpoolError::Corrupt { .. }));
}
