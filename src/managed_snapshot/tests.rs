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

#[test]
fn digest_is_over_exact_acl_bytes() {
    assert_ne!(digest_acl("mode {}"), digest_acl("mode {}\n"));
    assert_eq!(
        digest_acl(""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
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
    let store = ManagedSnapshotStore::new(Some(gateway_id));
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ConfigReloadCallback = {
        let calls = calls.clone();
        Arc::new(move |_| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(()) })
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
    let store = ManagedSnapshotStore::new(Some(gateway_id));
    let callback: ConfigReloadCallback = Arc::new(|_| Box::pin(async { Ok(()) }));
    let snapshot = snapshot(gateway_id, 1);
    let identity = snapshot.identity();
    let expires_at = snapshot.expires_at;

    assert!(store.apply(snapshot, Some(&callback)).await.status.ready);
    let expired = store.status(Some(identity), expires_at);
    assert_eq!(expired.state, ManagedSnapshotState::Expired);
    assert!(!expired.ready);
}

#[tokio::test]
async fn concurrent_applies_are_serialized_by_revision() {
    let gateway_id = Uuid::new_v4();
    let store = Arc::new(ManagedSnapshotStore::new(Some(gateway_id)));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let callback: ConfigReloadCallback = {
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
                Ok(())
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
