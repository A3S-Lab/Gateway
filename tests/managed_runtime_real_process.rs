//! Cross-platform Managed Runtime Service qualification against a real OS process.
//!
//! Complements in-process lifecycle unit tests: bind health and private traffic
//! must reach a child upstream; drain must wait on admitted SSE / WebSocket /
//! gRPC streams before `Drained`; restart must restore the durable route and
//! replay must preserve the opaque binding identity. Runs on Windows and Unix
//! (no `cfg(unix)` gate).

use a3s_gateway::config::{EntrypointConfig, GatewayConfig, ManagedTargetConfig};
use a3s_gateway::managed_service::{
    ManagedServiceBindingRequest, ManagedServiceHealthCheck, ManagedServicePhase,
};
use a3s_gateway::Gateway;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use uuid::Uuid;

struct UpstreamProcess {
    child: Child,
    address: SocketAddr,
}

impl UpstreamProcess {
    async fn spawn_http() -> Self {
        Self::spawn_bin(env!("CARGO_BIN_EXE_managed-runtime-upstream")).await
    }

    async fn spawn_grpc() -> Self {
        Self::spawn_bin(env!("CARGO_BIN_EXE_managed-runtime-grpc-upstream")).await
    }

    async fn spawn_bin(binary: &str) -> Self {
        let mut child = Command::new(binary)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|error| panic!("spawn {binary}: {error}"));
        let stdout = child.stdout.take().expect("upstream stdout");
        let mut lines = BufReader::new(stdout).lines();
        let ready = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
            .await
            .expect("upstream READY timeout")
            .expect("upstream stdout closed")
            .expect("upstream READY line");
        let address = ready
            .strip_prefix("READY ")
            .unwrap_or_else(|| panic!("expected READY <addr>, got {ready}"))
            .parse::<SocketAddr>()
            .unwrap_or_else(|error| panic!("parse upstream addr from {ready}: {error}"));
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        Self { child, address }
    }

    async fn terminate(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            tokio::time::timeout(Duration::from_secs(3), self.child.kill())
                .await
                .expect("upstream kill timeout")
                .unwrap();
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), self.child.wait())
            .await
            .expect("upstream reap timeout");
    }
}

fn digest(label: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(label.as_bytes()))
}

fn reserve_gateway_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

fn gateway_config(address: SocketAddr) -> GatewayConfig {
    let mut config = GatewayConfig::default();
    config.entrypoints.clear();
    config.entrypoints.insert(
        "plugins".to_string(),
        EntrypointConfig::new(address.to_string()),
    );
    config.routers.clear();
    config.services.clear();
    config.middlewares.clear();
    config.observability.metrics_enabled = false;
    config.observability.access_log_enabled = false;
    config.observability.tracing_enabled = false;
    config
}

fn binding_request(
    label: &str,
    upstream: SocketAddr,
    service_path: &str,
) -> ManagedServiceBindingRequest {
    ManagedServiceBindingRequest::new(
        digest(label),
        "plugins",
        ManagedTargetConfig {
            target_id: Uuid::parse_str("018f0000-0000-7000-8000-0000000000aa").unwrap(),
            unit_id: "use:workspace-01:real-process:mcp".to_string(),
            generation: 1,
        },
        upstream,
        service_path,
        ManagedServiceHealthCheck::new("/healthz", 20, 250, 1, 2).unwrap(),
    )
    .unwrap()
}

fn deadline() -> Option<tokio::time::Instant> {
    Some(tokio::time::Instant::now() + Duration::from_secs(5))
}

async fn wait_until_hidden(endpoint: &str) {
    for _ in 0..100 {
        if reqwest::get(endpoint)
            .await
            .is_ok_and(|response| response.status() == reqwest::StatusCode::NOT_FOUND)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("managed route remained visible");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_os_process_upstream_survives_bind_health_traffic_drain_remove() {
    let directory = tempfile::tempdir().unwrap();
    let mut upstream = UpstreamProcess::spawn_http().await;
    let gateway = Gateway::with_managed_service_state(
        gateway_config(reserve_gateway_address()),
        directory.path().join("managed-services.json"),
    )
    .unwrap();
    gateway.start().await.unwrap();

    let binding = gateway
        .bind_managed_service(
            binding_request("real-process-bind", upstream.address, "/mcp"),
            deadline(),
        )
        .await
        .expect("bind against real OS-process upstream");
    assert!(!binding.replayed());
    assert!(binding
        .endpoint_ref()
        .starts_with("gateway:managed-services/"));

    let traffic = reqwest::get(binding.endpoint())
        .await
        .expect("private endpoint request");
    assert_eq!(traffic.status(), reqwest::StatusCode::OK);
    assert_eq!(traffic.text().await.unwrap(), "/mcp");

    let status = gateway
        .managed_service_status(binding.identity())
        .unwrap()
        .expect("ready status");
    assert_eq!(status.phase(), ManagedServicePhase::Ready);
    assert!(status.ready());

    gateway
        .drain_managed_service(
            binding.identity(),
            &digest("real-process-drain"),
            deadline(),
        )
        .await
        .unwrap();
    assert_eq!(
        gateway
            .managed_service_status(binding.identity())
            .unwrap()
            .unwrap()
            .phase(),
        ManagedServicePhase::Drained
    );

    wait_until_hidden(binding.endpoint()).await;
    assert_eq!(
        reqwest::get(binding.endpoint()).await.unwrap().status(),
        reqwest::StatusCode::NOT_FOUND,
        "drained route must stay hidden"
    );

    gateway
        .remove_managed_service(
            binding.identity(),
            &digest("real-process-remove"),
            deadline(),
        )
        .await
        .unwrap();
    assert!(gateway
        .managed_service_status(binding.identity())
        .unwrap()
        .is_none());

    gateway.shutdown().await;
    upstream.terminate().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_os_process_upstream_restart_restores_route_and_replay_preserves_identity() {
    let directory = tempfile::tempdir().unwrap();
    let mut upstream = UpstreamProcess::spawn_http().await;
    let gateway_address = reserve_gateway_address();
    let state_file = directory.path().join("managed-services.json");
    let request = binding_request("real-process-restart", upstream.address, "/mcp");

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
            .expect("bind against real OS-process upstream");
        assert!(!binding.replayed());
        let traffic = reqwest::get(binding.endpoint())
            .await
            .expect("private endpoint before restart");
        assert_eq!(traffic.status(), reqwest::StatusCode::OK);
        assert_eq!(traffic.text().await.unwrap(), "/mcp");
        gateway.shutdown().await;
        binding
    };

    // Upstream child stays up; Gateway reconstructs from durable state.
    let gateway =
        Gateway::with_managed_service_state(gateway_config(gateway_address), state_file).unwrap();
    gateway.start().await.unwrap();
    let restored = reqwest::get(first.endpoint())
        .await
        .expect("private endpoint after Gateway restart");
    assert_eq!(restored.status(), reqwest::StatusCode::OK);
    assert_eq!(
        restored.text().await.unwrap(),
        "/mcp",
        "restart must restore the route to the still-living OS-process upstream"
    );

    let replay = gateway
        .bind_managed_service(request, deadline())
        .await
        .expect("replay bind after restart");
    assert!(
        replay.replayed(),
        "exact-generation rebind after restart must be a replay"
    );
    assert_eq!(
        replay.identity(),
        first.identity(),
        "replay must preserve the opaque binding identity"
    );
    assert_eq!(replay.endpoint(), first.endpoint());

    gateway.shutdown().await;
    upstream.terminate().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_os_process_upstream_sse_drain_waits_for_admitted_stream() {
    let directory = tempfile::tempdir().unwrap();
    let mut upstream = UpstreamProcess::spawn_http().await;
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
            binding_request("real-process-sse", upstream.address, "/sse-hold"),
            deadline(),
        )
        .await
        .expect("bind SSE hold path against real OS-process upstream");

    let response = reqwest::Client::new()
        .get(binding.endpoint())
        .header(reqwest::header::ACCEPT, "text/event-stream")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .unwrap(),
        "text/event-stream"
    );

    let identity = binding.identity().clone();
    let drain_gateway = gateway.clone();
    let drain = tokio::spawn(async move {
        drain_gateway
            .drain_managed_service(&identity, &digest("real-process-sse-drain"), deadline())
            .await
    });

    wait_until_hidden(binding.endpoint()).await;
    assert!(
        !drain.is_finished(),
        "drain ignored an admitted SSE body against a real OS-process upstream"
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

    // Unblock the child hold so terminate does not hang on an open write.
    let _ = reqwest::Client::new()
        .post(format!("http://{}/release", upstream.address))
        .send()
        .await;

    gateway.shutdown().await;
    upstream.terminate().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_os_process_upstream_websocket_drain_waits_for_admitted_stream() {
    let directory = tempfile::tempdir().unwrap();
    let mut upstream = UpstreamProcess::spawn_http().await;
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
            binding_request("real-process-ws", upstream.address, "/ws-hold"),
            deadline(),
        )
        .await
        .expect("bind WebSocket hold path against real OS-process upstream");

    let ws_url = binding.endpoint().replacen("http://", "ws://", 1);
    let (websocket, response) = tokio_tungstenite::connect_async(ws_url).await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SWITCHING_PROTOCOLS);

    let identity = binding.identity().clone();
    let drain_gateway = gateway.clone();
    let drain = tokio::spawn(async move {
        drain_gateway
            .drain_managed_service(&identity, &digest("real-process-ws-drain"), deadline())
            .await
    });

    wait_until_hidden(binding.endpoint()).await;
    assert!(
        !drain.is_finished(),
        "drain ignored an admitted WebSocket against a real OS-process upstream"
    );
    drop(websocket);
    drain.await.unwrap().unwrap();
    assert_eq!(
        gateway
            .managed_service_status(binding.identity())
            .unwrap()
            .unwrap()
            .phase(),
        ManagedServicePhase::Drained
    );

    let _ = reqwest::Client::new()
        .post(format!("http://{}/release", upstream.address))
        .send()
        .await;

    gateway.shutdown().await;
    upstream.terminate().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_os_process_upstream_grpc_drain_waits_for_admitted_stream() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use std::convert::Infallible;

    let directory = tempfile::tempdir().unwrap();
    let mut upstream = UpstreamProcess::spawn_grpc().await;
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
            binding_request(
                "real-process-grpc",
                upstream.address,
                "/grpc.hold.Hold/Stream",
            ),
            deadline(),
        )
        .await
        .expect("bind gRPC hold path against real OS-process upstream");

    type RequestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>;
    let grpc_client: Client<HttpConnector, RequestBody> = Client::builder(TokioExecutor::new())
        .http2_only(true)
        .build_http();
    let request = http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri(binding.endpoint())
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers")
        .body(
            Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap();
    let response = grpc_client.request(request).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);

    let mut body = response.into_body();
    let first = body.frame().await.expect("first gRPC frame").unwrap();
    assert_eq!(first.into_data().unwrap().as_ref(), b"grpc-hold-first");

    let identity = binding.identity().clone();
    let drain_gateway = gateway.clone();
    let drain = tokio::spawn(async move {
        drain_gateway
            .drain_managed_service(&identity, &digest("real-process-grpc-drain"), deadline())
            .await
    });

    wait_until_hidden(binding.endpoint()).await;
    assert!(
        !drain.is_finished(),
        "drain ignored an admitted gRPC body against a real OS-process upstream"
    );
    drop(body);
    drain.await.unwrap().unwrap();
    assert_eq!(
        gateway
            .managed_service_status(binding.identity())
            .unwrap()
            .unwrap()
            .phase(),
        ManagedServicePhase::Drained
    );

    let _ = reqwest::Client::new()
        .post(format!("http://{}/release", upstream.address))
        .send()
        .await;

    gateway.shutdown().await;
    upstream.terminate().await;
}
