use super::*;

#[tokio::test]
async fn exact_bind_health_and_replay_use_the_real_gateway_route() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway = Gateway::with_managed_service_state(
        gateway_config(reserve_gateway_address()),
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();

    let request = request("bind-one", 7, backend.address, "/mcp");
    let first = gateway
        .bind_managed_service(request.clone(), deadline())
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");
    assert!(first
        .endpoint_ref()
        .starts_with("gateway:managed-services/"));
    assert!(!first.replayed());

    let response = reqwest::get(first.endpoint()).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "/mcp");
    assert_eq!(backend.next_service_path().await, "/mcp");

    let malformed = format!(
        "{}suffix/mcp",
        first.endpoint().strip_suffix("/mcp").unwrap()
    );
    assert_eq!(
        reqwest::get(malformed).await.unwrap().status(),
        reqwest::StatusCode::NOT_FOUND
    );

    let replay = gateway
        .bind_managed_service(request, deadline())
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");
    assert_eq!(replay.endpoint_ref(), first.endpoint_ref());
    assert_eq!(replay.endpoint(), first.endpoint());
    assert!(replay.replayed());

    let status = gateway
        .managed_service_status(first.identity())
        .unwrap()
        .expect("binding status");
    assert_eq!(status.phase(), ManagedServicePhase::Ready);
    assert!(status.ready());
    gateway.shutdown().await;
}

#[tokio::test]
async fn ordinary_base_reload_preserves_the_managed_service_overlay() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway_address = reserve_gateway_address();
    let gateway = Gateway::with_managed_service_state(
        gateway_config(gateway_address),
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();
    let binding = gateway
        .bind_managed_service(
            request("base-reload", 16, backend.address, "/mcp"),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");

    let mut reloaded = gateway_config(gateway_address);
    add_base_route(&mut reloaded, backend.address, "/base");
    gateway.reload(reloaded).await.unwrap();

    let base = reqwest::get(format!("http://{gateway_address}/base"))
        .await
        .unwrap();
    assert_eq!(base.status(), reqwest::StatusCode::OK);
    assert_eq!(base.text().await.unwrap(), "/base");
    assert_eq!(backend.next_service_path().await, "/base");

    let managed = reqwest::get(binding.endpoint()).await.unwrap();
    assert_eq!(managed.status(), reqwest::StatusCode::OK);
    assert_eq!(managed.text().await.unwrap(), "/mcp");
    assert_eq!(backend.next_service_path().await, "/mcp");
    gateway.shutdown().await;
}

#[tokio::test]
async fn base_reload_cannot_move_an_owned_managed_service_entrypoint() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway_address = reserve_gateway_address();
    let gateway = Gateway::with_managed_service_state(
        gateway_config(gateway_address),
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();
    let binding = gateway
        .bind_managed_service(
            request("entrypoint-fence", 18, backend.address, "/mcp"),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");

    let error = gateway
        .reload(gateway_config(reserve_gateway_address()))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cannot change"));

    let response = reqwest::get(binding.endpoint()).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "/mcp");
    assert_eq!(backend.next_service_path().await, "/mcp");
    gateway.shutdown().await;
}

#[tokio::test]
async fn managed_snapshot_reload_preserves_the_managed_service_overlay() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway_address = reserve_gateway_address();
    let management_address = reserve_gateway_address();
    let gateway_id = Uuid::new_v4();
    let bootstrap = GatewayConfig::from_acl(&cloud_managed_acl(
        gateway_id,
        gateway_address,
        management_address,
        None,
    ))
    .unwrap();
    let gateway = Gateway::with_managed_service_state(
        bootstrap,
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();
    let binding = gateway
        .bind_managed_service(
            request("snapshot-reload", 17, backend.address, "/mcp"),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");

    let now = Utc::now();
    let snapshot = ManagedSnapshot::new(
        gateway_id,
        1,
        None,
        now,
        now + ChronoDuration::hours(1),
        cloud_managed_acl(
            gateway_id,
            gateway_address,
            management_address,
            Some(backend.address),
        ),
    );
    let response = reqwest::Client::new()
        .post(format!(
            "http://{management_address}/api/gateway/snapshots/apply"
        ))
        .json(&snapshot)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let body = response.text().await.unwrap();
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");

    let base = reqwest::get(format!("http://{gateway_address}/base"))
        .await
        .unwrap();
    assert_eq!(base.status(), reqwest::StatusCode::OK);
    assert_eq!(base.text().await.unwrap(), "/base");
    assert_eq!(backend.next_service_path().await, "/base");

    let managed = reqwest::get(binding.endpoint()).await.unwrap();
    assert_eq!(managed.status(), reqwest::StatusCode::OK);
    assert_eq!(managed.text().await.unwrap(), "/mcp");
    assert_eq!(backend.next_service_path().await, "/mcp");
    assert!(gateway
        .managed_service_status(binding.identity())
        .unwrap()
        .unwrap()
        .ready());
    gateway.shutdown().await;
}

#[tokio::test]
async fn replay_with_changed_exact_identity_fails_without_replacing_the_route() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway = Gateway::with_managed_service_state(
        gateway_config(reserve_gateway_address()),
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();

    let original = request("same-key", 3, backend.address, "/one");
    let binding = gateway
        .bind_managed_service(original.clone(), deadline())
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");

    let changed = request("same-key", 4, backend.address, "/two");
    let error = gateway
        .bind_managed_service(changed, deadline())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("idempotency"));

    let response = reqwest::get(binding.endpoint()).await.unwrap();
    assert_eq!(response.text().await.unwrap(), "/one");
    assert_eq!(backend.next_service_path().await, "/one");
    gateway.shutdown().await;
}

#[tokio::test]
async fn drain_hides_then_waits_for_the_exact_admitted_stream() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway = Arc::new(
        Gateway::with_managed_service_state(
            gateway_config(reserve_gateway_address()),
            directory.path().join("managed-services.json"),
        )
        .unwrap(),
    );
    gateway.start().await.unwrap();
    let binding = gateway
        .bind_managed_service(request("stream", 9, backend.address, "/hold"), deadline())
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");

    let response = reqwest::get(binding.endpoint()).await.unwrap();
    assert_eq!(backend.next_service_path().await, "/hold");
    let identity = binding.identity().clone();
    let drain_gateway = gateway.clone();
    let drain = tokio::spawn(async move {
        drain_gateway
            .drain_managed_service(&identity, &digest("drain-stream"), deadline())
            .await
    });

    wait_until_hidden(binding.endpoint()).await;
    assert!(
        !drain.is_finished(),
        "drain ignored an admitted response body"
    );
    drop(response);
    drain.await.unwrap().unwrap();
    assert_eq!(
        gateway
            .managed_service_status(binding.identity())
            .unwrap()
            .unwrap()
            .phase(),
        ManagedServicePhase::Drained
    );
    let _ = backend.release_streams.send(true);
    gateway.shutdown().await;
}

#[tokio::test]
async fn health_verification_obeys_the_lifecycle_deadline() {
    let directory = tempfile::tempdir().unwrap();
    let backend = TestBackend::spawn_with_health_status(503).await;
    let gateway = Gateway::with_managed_service_state(
        gateway_config(reserve_gateway_address()),
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();

    let request = request("unhealthy", 13, backend.address, "/mcp");
    let identity = StoredManagedServiceBinding::new(request.clone())
        .unwrap()
        .identity();
    let started = tokio::time::Instant::now();
    let error = gateway
        .bind_managed_service(
            request,
            Some(tokio::time::Instant::now() + Duration::from_millis(80)),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("deadline"));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        gateway
            .managed_service_status(&identity)
            .unwrap()
            .unwrap()
            .phase(),
        ManagedServicePhase::Binding
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn shutdown_prevents_a_late_readiness_commit() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway = Arc::new(
        Gateway::with_managed_service_state(
            gateway_config(reserve_gateway_address()),
            directory.path().join("managed-services.json"),
        )
        .unwrap(),
    );
    gateway.start().await.unwrap();

    let request = ManagedServiceBindingRequest::new(
        digest("shutdown-readiness"),
        "plugins",
        target(19),
        backend.address,
        "/mcp",
        ManagedServiceHealthCheck::new("/held-health", 20, 2_000, 1, 2).unwrap(),
    )
    .unwrap();
    let identity = StoredManagedServiceBinding::new(request.clone())
        .unwrap()
        .identity();
    let bind_gateway = gateway.clone();
    let bind =
        tokio::spawn(async move { bind_gateway.bind_managed_service(request, deadline()).await });
    assert_eq!(backend.next_path().await, "/held-health");

    let shutdown_gateway = gateway.clone();
    let shutdown = tokio::spawn(async move { shutdown_gateway.shutdown().await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while gateway.state() != crate::GatewayState::Stopping {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown did not enter the stopping state");
    let _ = backend.release_streams.send(true);

    shutdown.await.unwrap();
    let error = bind.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("cannot commit readiness"));
    assert_eq!(
        gateway
            .managed_service_status(&identity)
            .unwrap()
            .unwrap()
            .phase(),
        ManagedServicePhase::Binding
    );
}

#[tokio::test]
async fn timed_out_drain_retains_the_admitted_generation_for_exact_replay() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway = Arc::new(
        Gateway::with_managed_service_state(
            gateway_config(reserve_gateway_address()),
            directory.path().join("managed-services.json"),
        )
        .unwrap(),
    );
    gateway.start().await.unwrap();
    let binding = gateway
        .bind_managed_service(
            request("drain-deadline", 14, backend.address, "/hold"),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");

    let response = reqwest::get(binding.endpoint()).await.unwrap();
    assert_eq!(backend.next_service_path().await, "/hold");
    let drain_key = digest("drain-deadline-operation");
    let error = gateway
        .drain_managed_service(
            binding.identity(),
            &drain_key,
            Some(tokio::time::Instant::now() + Duration::from_millis(50)),
        )
        .await
        .unwrap_err();
    assert!(error.to_string().contains("deadline"));
    assert_eq!(
        gateway
            .managed_service_status(binding.identity())
            .unwrap()
            .unwrap()
            .phase(),
        ManagedServicePhase::Draining
    );
    wait_until_hidden(binding.endpoint()).await;

    let conflicting = gateway
        .drain_managed_service(binding.identity(), &digest("different-drain"), deadline())
        .await
        .unwrap_err();
    assert!(conflicting.to_string().contains("operation key"));

    let retry_gateway = gateway.clone();
    let identity = binding.identity().clone();
    let retry = tokio::spawn(async move {
        retry_gateway
            .drain_managed_service(&identity, &drain_key, deadline())
            .await
    });
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(
        !retry.is_finished(),
        "drain replay forgot the still-admitted generation"
    );
    drop(response);
    retry.await.unwrap().unwrap();
    assert_eq!(
        gateway
            .managed_service_status(binding.identity())
            .unwrap()
            .unwrap()
            .phase(),
        ManagedServicePhase::Drained
    );
    let _ = backend.release_streams.send(true);
    gateway.shutdown().await;
}

#[tokio::test]
async fn stale_generation_cannot_remove_a_newer_binding() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway = Gateway::with_managed_service_state(
        gateway_config(reserve_gateway_address()),
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();

    let first = gateway
        .bind_managed_service(
            request("generation-one", 1, backend.address, "/one"),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");
    let second = gateway
        .bind_managed_service(
            request("generation-two", 2, backend.address, "/two"),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");

    let stale = ManagedServiceBindingIdentity::new(
        second.endpoint_ref().to_string(),
        first.identity().target().clone(),
    )
    .unwrap();
    let error = gateway
        .remove_managed_service(&stale, &digest("stale-remove"), deadline())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("exact generation"));

    gateway
        .drain_managed_service(first.identity(), &digest("drain-one"), deadline())
        .await
        .unwrap();
    gateway
        .remove_managed_service(first.identity(), &digest("remove-one"), deadline())
        .await
        .unwrap();
    gateway
        .remove_managed_service(first.identity(), &digest("remove-one"), deadline())
        .await
        .unwrap();

    let response = reqwest::get(second.endpoint()).await.unwrap();
    assert_eq!(response.text().await.unwrap(), "/two");
    assert_eq!(backend.next_service_path().await, "/two");
    gateway.shutdown().await;
}

#[tokio::test]
async fn restart_restores_the_route_and_replay_preserves_binding_identity() {
    let directory = tempfile::tempdir().unwrap();
    let mut backend = TestBackend::spawn().await;
    let gateway_address = reserve_gateway_address();
    let state_file = directory.path().join("managed-services.json");
    let request = request("restart", 11, backend.address, "/mcp");
    let first = {
        let gateway = Gateway::with_managed_service_state(
            gateway_config(gateway_address),
            state_file.clone(),
        )
        .unwrap();
        gateway.start().await.unwrap();
        let binding = gateway
            .bind_managed_service(request.clone(), deadline())
            .await
            .unwrap();
        assert_eq!(backend.next_path().await, "/healthz");
        gateway.shutdown().await;
        binding
    };

    let gateway =
        Gateway::with_managed_service_state(gateway_config(gateway_address), state_file).unwrap();
    gateway.start().await.unwrap();
    let response = reqwest::get(first.endpoint()).await.unwrap();
    assert_eq!(response.text().await.unwrap(), "/mcp");
    assert_eq!(backend.next_service_path().await, "/mcp");

    let replay = gateway
        .bind_managed_service(request, deadline())
        .await
        .unwrap();
    assert_eq!(backend.next_path().await, "/healthz");
    assert!(replay.replayed());
    assert_eq!(replay.identity(), first.identity());
    gateway.shutdown().await;
}
