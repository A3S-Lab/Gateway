use super::{UsageCursor, UsageSpool, UsageSpoolError, UsageSpoolOptions};
use std::path::{Path, PathBuf};
use uuid::Uuid;

fn spool_directory(directory: &Path) -> PathBuf {
    directory.join("usage-spool")
}

fn options(directory: &Path, gateway_id: Uuid) -> UsageSpoolOptions {
    options_with_max(directory, gateway_id, 1024 * 1024)
}

fn options_with_max(directory: &Path, gateway_id: Uuid, max_bytes: u64) -> UsageSpoolOptions {
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

async fn write_private(path: &Path, bytes: &[u8]) {
    tokio::fs::write(path, bytes).await.unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();
    }
}

fn lines(bytes: &[u8]) -> Vec<&[u8]> {
    let lines = bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    assert!(lines.iter().all(|line| line.last() == Some(&b'\n')));
    lines
}

fn compacted_bytes(source: &[u8], first_sequence: u64) -> Vec<u8> {
    let source_lines = lines(source);
    let first_record = usize::try_from(first_sequence).unwrap();
    assert!(first_record < source_lines.len());
    let mut header: serde_json::Value =
        serde_json::from_slice(&source_lines[0][..source_lines[0].len() - 1]).unwrap();
    header["schema"] = serde_json::Value::String("a3s.gateway.usage-spool-segment.v2".to_string());
    header["first_sequence"] = serde_json::json!(first_sequence);
    let mut bytes = serde_json::to_vec(&header).unwrap();
    bytes.push(b'\n');
    for line in &source_lines[first_record..] {
        bytes.extend_from_slice(line);
    }
    bytes
}

fn manifest_cursor(cursor: UsageCursor) -> serde_json::Value {
    serde_json::json!({
        "boot_epoch": cursor.boot_epoch,
        "sequence": format!("{:016x}", cursor.sequence),
    })
}

async fn create_two_record_epoch(
    directory: &Path,
    gateway_id: Uuid,
) -> (UsageCursor, UsageCursor, PathBuf, Vec<u8>) {
    let (first, second) = {
        let spool = UsageSpool::open(options(directory, gateway_id))
            .await
            .unwrap();
        let first = spool
            .append(Uuid::new_v4(), &vec![b'a'; 4096])
            .await
            .unwrap();
        let second = spool
            .append(Uuid::new_v4(), &vec![b'b'; 4096])
            .await
            .unwrap();
        (first, second)
    };
    let manifest = read_manifest(directory).await;
    let file = manifest["epochs"][0]["file"].as_str().unwrap();
    let path = spool_directory(directory).join(file);
    let source = tokio::fs::read(&path).await.unwrap();
    (first, second, path, source)
}

#[tokio::test]
async fn partial_closed_epoch_is_compacted_without_reencoding_retained_records() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (first, second, segment, source) =
        create_two_record_epoch(directory.path(), gateway_id).await;
    let source_lines = lines(&source);
    let retained_line = source_lines[2].to_vec();

    let spool = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap();
    let retained_before = spool.status().retained_bytes;
    let acknowledged = spool.acknowledge(first).await.unwrap();
    assert_eq!(acknowledged.acknowledged_through, first);
    assert_eq!(acknowledged.newly_acknowledged_records, 1);
    assert!(acknowledged.reclaimed_bytes > 4096);
    assert!(!acknowledged.cleanup_pending);
    assert!(spool.status().retained_bytes < retained_before);
    assert_eq!(spool.status().oldest_retained_cursor, Some(second));
    assert_eq!(
        spool.read_batch(Some(first), 10).await.unwrap()[0].cursor,
        second
    );

    let compacted = tokio::fs::read(&segment).await.unwrap();
    assert!(compacted.len() < source.len());
    let compacted_lines = lines(&compacted);
    assert_eq!(compacted_lines.len(), 2);
    assert_eq!(compacted_lines[1], retained_line);
    let header: serde_json::Value =
        serde_json::from_slice(&compacted_lines[0][..compacted_lines[0].len() - 1]).unwrap();
    assert_eq!(header["schema"], "a3s.gateway.usage-spool-segment.v2");
    assert_eq!(header["first_sequence"], 2);
    let manifest = read_manifest(directory.path()).await;
    let descriptor = manifest["epochs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|epoch| epoch["boot_epoch"] == first.boot_epoch.to_string())
        .unwrap();
    assert_eq!(descriptor["first_sequence"], "0000000000000002");
    assert_eq!(descriptor["compacted_last_sequence"], "0000000000000002");
    assert_eq!(descriptor["phase"], "ready");
    drop(spool);

    let spool = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap();
    assert_eq!(spool.status().acknowledged_through, Some(first));
    assert_eq!(spool.status().oldest_retained_cursor, Some(second));
    assert_eq!(
        spool.read_batch(Some(first), 10).await.unwrap()[0].cursor,
        second
    );
    assert_eq!(
        lines(&tokio::fs::read(segment).await.unwrap())[1],
        retained_line
    );
}

#[tokio::test]
async fn partial_current_epoch_is_compacted_on_the_next_startup() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let spool = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap();
    let first = spool
        .append(Uuid::new_v4(), &vec![b'a'; 4096])
        .await
        .unwrap();
    let second = spool
        .append(Uuid::new_v4(), &vec![b'b'; 4096])
        .await
        .unwrap();
    let manifest = read_manifest(directory.path()).await;
    let segment =
        spool_directory(directory.path()).join(manifest["epochs"][0]["file"].as_str().unwrap());
    let source = tokio::fs::read(&segment).await.unwrap();
    let retained_line = lines(&source)[2].to_vec();

    let acknowledged = spool.acknowledge(first).await.unwrap();
    assert_eq!(acknowledged.reclaimed_bytes, 0);
    assert!(!acknowledged.cleanup_pending);
    assert_eq!(tokio::fs::read(&segment).await.unwrap(), source);
    drop(spool);

    let spool = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap();
    let compacted = tokio::fs::read(&segment).await.unwrap();
    assert!(compacted.len() < source.len());
    assert_eq!(lines(&compacted)[1], retained_line);
    assert_eq!(spool.status().acknowledged_through, Some(first));
    assert_eq!(spool.status().oldest_retained_cursor, Some(second));
    assert_eq!(
        spool.read_batch(Some(first), 10).await.unwrap()[0].cursor,
        second
    );
}

#[tokio::test]
async fn acknowledgement_can_compact_the_same_closed_epoch_more_than_once() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (first, second, third, segment) = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id))
            .await
            .unwrap();
        let first = spool
            .append(Uuid::new_v4(), &vec![b'a'; 4096])
            .await
            .unwrap();
        let second = spool
            .append(Uuid::new_v4(), &vec![b'b'; 4096])
            .await
            .unwrap();
        let third = spool
            .append(Uuid::new_v4(), &vec![b'c'; 4096])
            .await
            .unwrap();
        let manifest = read_manifest(directory.path()).await;
        let segment =
            spool_directory(directory.path()).join(manifest["epochs"][0]["file"].as_str().unwrap());
        (first, second, third, segment)
    };
    let source = tokio::fs::read(&segment).await.unwrap();
    let retained_line = lines(&source)[3].to_vec();

    let spool = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap();
    assert!(spool.acknowledge(first).await.unwrap().reclaimed_bytes > 4096);
    assert!(spool.acknowledge(second).await.unwrap().reclaimed_bytes > 4096);
    let compacted = tokio::fs::read(&segment).await.unwrap();
    let compacted_lines = lines(&compacted);
    assert_eq!(compacted_lines.len(), 2);
    assert_eq!(compacted_lines[1], retained_line);
    assert_eq!(spool.status().acknowledged_through, Some(second));
    assert_eq!(spool.status().oldest_retained_cursor, Some(third));
    assert_eq!(
        spool.read_batch(Some(second), 10).await.unwrap()[0].cursor,
        third
    );
    let manifest = read_manifest(directory.path()).await;
    let descriptor = manifest["epochs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|epoch| epoch["boot_epoch"] == first.boot_epoch.to_string())
        .unwrap();
    assert_eq!(descriptor["first_sequence"], "0000000000000003");
    assert_eq!(descriptor["compacted_last_sequence"], "0000000000000003");
}

#[tokio::test]
async fn partial_epoch_compaction_releases_capacity_for_new_records() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (first, _, _, _) = create_two_record_epoch(directory.path(), gateway_id).await;
    let retained_before = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id))
            .await
            .unwrap();
        spool.status().retained_bytes
    };
    let event_id = Uuid::new_v4();
    let payload = vec![b'c'; 4096];
    let encoded_bytes = super::record::encode(
        gateway_id,
        UsageCursor {
            boot_epoch: Uuid::new_v4(),
            sequence: 1,
        },
        event_id,
        &payload,
    )
    .unwrap()
    .0
    .len() as u64;
    let max_bytes = retained_before + encoded_bytes - 128;

    let spool = UsageSpool::open(options_with_max(directory.path(), gateway_id, max_bytes))
        .await
        .unwrap();
    assert!(matches!(
        spool.append(event_id, &payload).await.unwrap_err(),
        UsageSpoolError::Full { .. }
    ));
    assert!(spool.acknowledge(first).await.unwrap().reclaimed_bytes > 4096);
    spool.append(event_id, &payload).await.unwrap();
}

#[tokio::test]
async fn startup_finishes_retirement_of_a_previously_compacted_epoch() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (first, second, segment, _) = create_two_record_epoch(directory.path(), gateway_id).await;
    {
        let spool = UsageSpool::open(options(directory.path(), gateway_id))
            .await
            .unwrap();
        spool.acknowledge(first).await.unwrap();
    }
    let mut manifest = read_manifest(directory.path()).await;
    let descriptor = manifest["epochs"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|epoch| epoch["boot_epoch"] == first.boot_epoch.to_string())
        .unwrap();
    descriptor["phase"] = serde_json::Value::String("gc".to_string());
    manifest["acknowledged_through"] = manifest_cursor(second);
    write_manifest(directory.path(), &manifest).await;

    let spool = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap();
    assert!(!segment.exists());
    assert_eq!(spool.status().acknowledged_through, Some(second));
    assert_eq!(spool.status().retained_records, 0);
}

#[derive(Debug, Clone, Copy)]
enum CrashPoint {
    ManifestCommitted,
    OriginalRemoved,
    CompactPublished,
}

#[tokio::test]
async fn startup_recovers_every_compaction_publication_crash_point() {
    for crash_point in [
        CrashPoint::ManifestCommitted,
        CrashPoint::OriginalRemoved,
        CrashPoint::CompactPublished,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::new_v4();
        let (first, second, segment, source) =
            create_two_record_epoch(directory.path(), gateway_id).await;
        let retained_line = lines(&source)[2].to_vec();
        let file = segment.file_name().unwrap().to_string_lossy();
        let pending = spool_directory(directory.path()).join(format!(".{file}.compact"));
        write_private(&pending, &compacted_bytes(&source, 2)).await;

        let mut manifest = read_manifest(directory.path()).await;
        manifest["acknowledged_through"] = manifest_cursor(first);
        manifest["epochs"][0]["first_sequence"] =
            serde_json::Value::String("0000000000000002".to_string());
        manifest["epochs"][0]["compacted_last_sequence"] =
            serde_json::Value::String("0000000000000002".to_string());
        manifest["epochs"][0]["phase"] = serde_json::Value::String("cp".to_string());
        write_manifest(directory.path(), &manifest).await;
        match crash_point {
            CrashPoint::ManifestCommitted => {}
            CrashPoint::OriginalRemoved => {
                tokio::fs::remove_file(&segment).await.unwrap();
            }
            CrashPoint::CompactPublished => {
                tokio::fs::remove_file(&segment).await.unwrap();
                tokio::fs::rename(&pending, &segment).await.unwrap();
            }
        }

        let spool = UsageSpool::open(options(directory.path(), gateway_id))
            .await
            .unwrap_or_else(|error| panic!("failed to recover {crash_point:?}: {error}"));
        assert!(!pending.exists(), "staging file survived {crash_point:?}");
        let compacted = tokio::fs::read(&segment).await.unwrap();
        assert_eq!(lines(&compacted)[1], retained_line);
        assert_eq!(spool.status().acknowledged_through, Some(first));
        assert_eq!(spool.status().oldest_retained_cursor, Some(second));
        assert_eq!(
            spool.read_batch(Some(first), 10).await.unwrap()[0].cursor,
            second
        );
        let recovered = read_manifest(directory.path()).await;
        let descriptor = recovered["epochs"]
            .as_array()
            .unwrap()
            .iter()
            .find(|epoch| epoch["boot_epoch"] == first.boot_epoch.to_string())
            .unwrap();
        assert_eq!(descriptor["phase"], "ready");
        assert_eq!(descriptor["first_sequence"], "0000000000000002");
        assert_eq!(descriptor["compacted_last_sequence"], "0000000000000002");
    }
}

#[tokio::test]
async fn startup_discards_a_compaction_not_committed_to_the_manifest() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (first, second, segment, source) =
        create_two_record_epoch(directory.path(), gateway_id).await;
    let file = segment.file_name().unwrap().to_string_lossy();
    let pending = spool_directory(directory.path()).join(format!(".{file}.compact"));
    write_private(&pending, &compacted_bytes(&source, 2)).await;

    let spool = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap();
    assert!(!pending.exists());
    assert_eq!(tokio::fs::read(segment).await.unwrap(), source);
    let records = spool.read_batch(None, 10).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].cursor, first);
    assert_eq!(records[1].cursor, second);
}

#[tokio::test]
async fn compacted_prefix_without_a_matching_acknowledgement_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (_, _, segment, source) = create_two_record_epoch(directory.path(), gateway_id).await;
    write_private(&segment, &compacted_bytes(&source, 2)).await;
    let mut manifest = read_manifest(directory.path()).await;
    manifest["epochs"][0]["first_sequence"] =
        serde_json::Value::String("0000000000000002".to_string());
    manifest["epochs"][0]["compacted_last_sequence"] =
        serde_json::Value::String("0000000000000002".to_string());
    write_manifest(directory.path(), &manifest).await;

    let error = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap_err();
    assert!(matches!(error, UsageSpoolError::Corrupt { .. }));
}

#[tokio::test]
async fn invalid_compaction_staging_fails_before_the_original_is_removed() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (first, _, segment, source) = create_two_record_epoch(directory.path(), gateway_id).await;
    let file = segment.file_name().unwrap().to_string_lossy();
    let pending = spool_directory(directory.path()).join(format!(".{file}.compact"));
    let compacted = compacted_bytes(&source, 2);
    let compacted_lines = lines(&compacted);
    let mut header: serde_json::Value =
        serde_json::from_slice(&compacted_lines[0][..compacted_lines[0].len() - 1]).unwrap();
    header["first_sequence"] = serde_json::json!(3);
    let mut invalid = serde_json::to_vec(&header).unwrap();
    invalid.push(b'\n');
    invalid.extend_from_slice(compacted_lines[1]);
    write_private(&pending, &invalid).await;

    let mut manifest = read_manifest(directory.path()).await;
    manifest["acknowledged_through"] = manifest_cursor(first);
    manifest["epochs"][0]["first_sequence"] =
        serde_json::Value::String("0000000000000002".to_string());
    manifest["epochs"][0]["compacted_last_sequence"] =
        serde_json::Value::String("0000000000000002".to_string());
    manifest["epochs"][0]["phase"] = serde_json::Value::String("cp".to_string());
    write_manifest(directory.path(), &manifest).await;

    let error = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap_err();
    assert!(matches!(error, UsageSpoolError::Corrupt { .. }));
    assert!(segment.exists());
    assert_eq!(tokio::fs::read(segment).await.unwrap(), source);
}

#[tokio::test]
async fn truncated_compaction_staging_fails_before_the_original_is_removed() {
    let directory = tempfile::tempdir().unwrap();
    let gateway_id = Uuid::new_v4();
    let (first, segment, source) = {
        let spool = UsageSpool::open(options(directory.path(), gateway_id))
            .await
            .unwrap();
        let first = spool.append(Uuid::new_v4(), b"first").await.unwrap();
        spool.append(Uuid::new_v4(), b"second").await.unwrap();
        spool.append(Uuid::new_v4(), b"third").await.unwrap();
        let manifest = read_manifest(directory.path()).await;
        let segment =
            spool_directory(directory.path()).join(manifest["epochs"][0]["file"].as_str().unwrap());
        drop(spool);
        let source = tokio::fs::read(&segment).await.unwrap();
        (first, segment, source)
    };
    let file = segment.file_name().unwrap().to_string_lossy();
    let pending = spool_directory(directory.path()).join(format!(".{file}.compact"));
    let compacted = compacted_bytes(&source, 2);
    let compacted_lines = lines(&compacted);
    assert_eq!(compacted_lines.len(), 3);
    let mut truncated = compacted_lines[0].to_vec();
    truncated.extend_from_slice(compacted_lines[1]);
    write_private(&pending, &truncated).await;

    let mut manifest = read_manifest(directory.path()).await;
    manifest["acknowledged_through"] = manifest_cursor(first);
    manifest["epochs"][0]["first_sequence"] =
        serde_json::Value::String("0000000000000002".to_string());
    manifest["epochs"][0]["compacted_last_sequence"] =
        serde_json::Value::String("0000000000000003".to_string());
    manifest["epochs"][0]["phase"] = serde_json::Value::String("cp".to_string());
    write_manifest(directory.path(), &manifest).await;

    let error = UsageSpool::open(options(directory.path(), gateway_id))
        .await
        .unwrap_err();
    assert!(matches!(error, UsageSpoolError::Corrupt { .. }));
    assert!(segment.exists());
    assert_eq!(tokio::fs::read(segment).await.unwrap(), source);
}
