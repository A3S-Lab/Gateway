//! H0.3 local evidence: Cloud managed target generation replacement drains
//! in-flight work on the retired generation while new requests move to the
//! successor. This is Gateway-local; multi-replica joint gates remain open.

use a3s_gateway::managed_snapshot::{ManagedSnapshot, ManagedSnapshotState, ManagedSnapshotStatus};
use a3s_gateway::{config::GatewayConfig, Gateway};
use chrono::{Duration, Utc};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use uuid::Uuid;

async fn free_tcp_ports() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    (
        first.local_addr().unwrap().port(),
        second.local_addr().unwrap().port(),
    )
}

async fn start_bootstrap_gateway(gateway_id: Uuid) -> (Arc<Gateway>, u16, u16) {
    let mut last_bind_error = None;
    for _ in 0..10 {
        let (traffic_port, management_port) = free_tcp_ports().await;
        let gateway = Arc::new(
            Gateway::new(
                GatewayConfig::from_acl(&bootstrap_acl(gateway_id, traffic_port, management_port))
                    .unwrap(),
            )
            .unwrap(),
        );
        match gateway.start().await {
            Ok(()) => return (gateway, traffic_port, management_port),
            Err(error) if error.to_string().contains("Address already in use") => {
                last_bind_error = Some(error);
            }
            Err(error) => panic!("bootstrap Gateway failed: {error}"),
        }
    }
    panic!(
        "bootstrap Gateway could not reserve ports: {}",
        last_bind_error.unwrap()
    );
}

fn bootstrap_acl(gateway_id: Uuid, traffic_port: u16, management_port: u16) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}
entrypoints "web" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "http"
}}
management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
"#
    )
}

fn traffic_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: SocketAddr,
    target_id: Uuid,
    unit_id: &str,
    generation: u64,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}
entrypoints "web" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "http"
}}
routers "managed" {{
  rule        = "PathPrefix(`/`)"
  service     = "managed"
  entrypoints = ["web"]
}}
services "managed" {{
  load_balancer {{
    request_timeout = "5s"
    servers {{
      url = "http://{backend}"
      target {{
        target_id = "{target_id}"
        unit_id = "{unit_id}"
        generation = {generation}
      }}
    }}
  }}
}}
management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
"#
    )
}

fn snapshot(
    gateway_id: Uuid,
    revision: u64,
    expected_revision: Option<u64>,
    acl: String,
) -> ManagedSnapshot {
    let now = Utc::now();
    ManagedSnapshot::new(
        gateway_id,
        revision,
        expected_revision,
        now,
        now + Duration::hours(1),
        acl,
    )
}

async fn apply(
    client: &reqwest::Client,
    management_port: u16,
    snapshot: &ManagedSnapshot,
) -> ManagedSnapshotStatus {
    let response = client
        .post(format!(
            "http://127.0.0.1:{management_port}/api/gateway/snapshots/apply"
        ))
        .json(snapshot)
        .send()
        .await
        .unwrap();
    assert!(
        response.status().is_success(),
        "snapshot apply failed: {}",
        response.status()
    );
    let status = response.json::<ManagedSnapshotStatus>().await.unwrap();
    assert_eq!(status.state, ManagedSnapshotState::Applied);
    assert!(status.ready);
    status
}

async fn spawn_blocking_labeled_backend(
    label: &'static str,
) -> (SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await;
        let _ = started_tx.send(());
        let _ = release_rx.await;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            label.len(),
            label
        );
        let _ = stream.write_all(response.as_bytes()).await;
        let _ = stream.shutdown().await;
    });
    (address, started_rx, release_tx)
}

async fn spawn_echo_backend(label: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let label = label;
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    label.len(),
                    label
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

async fn write_chunk(stream: &mut tokio::net::TcpStream, payload: &[u8]) {
    let header = format!("{:x}\r\n", payload.len());
    stream.write_all(header.as_bytes()).await.unwrap();
    stream.write_all(payload).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
}

async fn spawn_blocking_sse_backend() -> (SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = stream.read(&mut request).await;
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/event-stream\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n",
            )
            .await
            .unwrap();
        write_chunk(&mut stream, b"data: generation-1-first\n\n").await;
        let _ = started_tx.send(());
        let _ = finish_rx.await;
        write_chunk(&mut stream, b"data: generation-1-done\n\n").await;
        stream.write_all(b"0\r\n\r\n").await.unwrap();
        let _ = stream.shutdown().await;
    });
    (address, started_rx, finish_tx)
}

async fn spawn_blocking_websocket_backend(
) -> (SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>) {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
        websocket
            .send(Message::Text("generation-1-first".into()))
            .await
            .unwrap();
        let _ = started_tx.send(());
        let _ = finish_rx.await;
        websocket
            .send(Message::Text("generation-1-done".into()))
            .await
            .unwrap();
        let _ = websocket.close(None).await;
        // Drain until the peer observes close.
        while let Some(Ok(message)) = websocket.next().await {
            if message.is_close() {
                break;
            }
        }
    });
    (address, started_rx, finish_tx)
}

#[tokio::test]
async fn generation_bump_keeps_inflight_on_retired_target_while_new_requests_use_successor() {
    let gateway_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let unit_id = "workload:unit";
    let (gateway, traffic_port, management_port) = start_bootstrap_gateway(gateway_id).await;
    let client = reqwest::Client::new();

    let (retired_backend, request_started, release_retired) =
        spawn_blocking_labeled_backend("generation-1").await;
    let first = snapshot(
        gateway_id,
        1,
        None,
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            retired_backend,
            target_id,
            unit_id,
            1,
        ),
    );
    apply(&client, management_port, &first).await;

    let in_flight = tokio::spawn(async move {
        reqwest::Client::new()
            .get(format!("http://127.0.0.1:{traffic_port}/"))
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    tokio::time::timeout(StdDuration::from_secs(2), request_started)
        .await
        .expect("retired generation did not accept the in-flight request")
        .unwrap();

    let successor_backend = spawn_echo_backend("generation-2").await;
    let second = snapshot(
        gateway_id,
        2,
        Some(1),
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            successor_backend,
            target_id,
            unit_id,
            2,
        ),
    );
    apply(&client, management_port, &second).await;

    let successor_body = client
        .get(format!("http://127.0.0.1:{traffic_port}/"))
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(
        successor_body, "generation-2",
        "new requests must use the successor managed generation"
    );

    release_retired.send(()).unwrap();
    let retired_body = tokio::time::timeout(StdDuration::from_secs(2), in_flight)
        .await
        .expect("retired generation in-flight work must finish")
        .unwrap();
    assert_eq!(
        retired_body, "generation-1",
        "in-flight work must complete on the retired generation"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn generation_bump_preserves_inflight_sse_on_retired_target() {
    let gateway_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let unit_id = "workload:sse-unit";
    let (gateway, traffic_port, management_port) = start_bootstrap_gateway(gateway_id).await;
    let client = reqwest::Client::new();

    let (retired_backend, stream_started, finish_retired) = spawn_blocking_sse_backend().await;
    let first = snapshot(
        gateway_id,
        1,
        None,
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            retired_backend,
            target_id,
            unit_id,
            1,
        ),
    );
    apply(&client, management_port, &first).await;

    let in_flight = tokio::spawn(async move {
        reqwest::Client::new()
            .get(format!("http://127.0.0.1:{traffic_port}/stream"))
            .header("accept", "text/event-stream")
            .header(reqwest::header::CONNECTION, "close")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    tokio::time::timeout(StdDuration::from_secs(2), stream_started)
        .await
        .expect("retired generation did not start SSE")
        .unwrap();

    let successor_backend = spawn_echo_backend("generation-2").await;
    let second = snapshot(
        gateway_id,
        2,
        Some(1),
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            successor_backend,
            target_id,
            unit_id,
            2,
        ),
    );
    apply(&client, management_port, &second).await;

    let successor_body = client
        .get(format!("http://127.0.0.1:{traffic_port}/"))
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(successor_body, "generation-2");

    finish_retired.send(()).unwrap();
    let retired_body = tokio::time::timeout(StdDuration::from_secs(2), in_flight)
        .await
        .expect("retired SSE must finish after generation bump")
        .unwrap();
    assert!(
        retired_body.contains("generation-1-first") && retired_body.contains("generation-1-done"),
        "SSE body incomplete after generation bump: {retired_body}"
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn generation_bump_preserves_inflight_websocket_on_retired_target() {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    let gateway_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let unit_id = "workload:ws-unit";
    let (gateway, traffic_port, management_port) = start_bootstrap_gateway(gateway_id).await;
    let client = reqwest::Client::new();

    let (retired_backend, stream_started, finish_retired) =
        spawn_blocking_websocket_backend().await;
    let first = snapshot(
        gateway_id,
        1,
        None,
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            retired_backend,
            target_id,
            unit_id,
            1,
        ),
    );
    apply(&client, management_port, &first).await;

    let in_flight = tokio::spawn(async move {
        let (mut websocket, response) =
            tokio_tungstenite::connect_async(format!("ws://127.0.0.1:{traffic_port}/socket"))
                .await
                .unwrap();
        assert_eq!(response.status(), 101);

        let first = websocket.next().await.unwrap().unwrap();
        assert_eq!(first, Message::Text("generation-1-first".into()));

        let done = websocket.next().await.unwrap().unwrap();
        assert_eq!(done, Message::Text("generation-1-done".into()));

        let close = websocket.next().await.unwrap().unwrap();
        assert!(close.is_close(), "expected close frame, got {close:?}");
        let _ = websocket.close(None).await;
    });
    tokio::time::timeout(StdDuration::from_secs(2), stream_started)
        .await
        .expect("retired generation did not start WebSocket")
        .unwrap();

    let successor_backend = spawn_echo_backend("generation-2").await;
    let second = snapshot(
        gateway_id,
        2,
        Some(1),
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            successor_backend,
            target_id,
            unit_id,
            2,
        ),
    );
    apply(&client, management_port, &second).await;

    let successor_body = client
        .get(format!("http://127.0.0.1:{traffic_port}/"))
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(successor_body, "generation-2");

    finish_retired.send(()).unwrap();
    tokio::time::timeout(StdDuration::from_secs(2), in_flight)
        .await
        .expect("retired WebSocket must finish after generation bump")
        .unwrap();

    gateway.shutdown().await;
}

async fn spawn_blocking_grpc_backend() -> (SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>) {
    use bytes::Bytes;
    use futures_util::stream;
    use http_body_util::StreamBody;
    use hyper::body::Frame;
    use hyper::service::service_fn;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let started_tx = Arc::new(Mutex::new(Some(started_tx)));
        let finish_rx = Arc::new(Mutex::new(Some(finish_rx)));
        let service = service_fn(move |_request| {
            let started_tx = started_tx.clone();
            let finish_rx = finish_rx.clone();
            async move {
                let response_stream = stream::unfold(
                    (0_u8, started_tx, finish_rx),
                    |(stage, started_tx, finish_rx)| async move {
                        match stage {
                            0 => {
                                if let Some(tx) = started_tx.lock().unwrap().take() {
                                    let _ = tx.send(());
                                }
                                Some((
                                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                                        b"generation-1-first",
                                    ))),
                                    (1, started_tx, finish_rx),
                                ))
                            }
                            1 => {
                                let finish = finish_rx.lock().unwrap().take().unwrap();
                                let _ = finish.await;
                                Some((
                                    Ok(Frame::data(Bytes::from_static(b"generation-1-done"))),
                                    (2, started_tx, finish_rx),
                                ))
                            }
                            2 => {
                                let mut trailers = http::HeaderMap::new();
                                trailers.insert("grpc-status", "0".parse().unwrap());
                                Some((Ok(Frame::trailers(trailers)), (3, started_tx, finish_rx)))
                            }
                            _ => None,
                        }
                    },
                );
                Ok::<_, Infallible>(
                    http::Response::builder()
                        .status(http::StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "application/grpc")
                        .body(StreamBody::new(response_stream))
                        .unwrap(),
                )
            }
        });
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    (address, started_rx, finish_tx)
}

#[tokio::test]
async fn generation_bump_preserves_inflight_grpc_on_retired_target() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper_util::client::legacy::connect::HttpConnector;
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;
    use std::convert::Infallible;

    let gateway_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let unit_id = "workload:grpc-unit";
    let (gateway, traffic_port, management_port) = start_bootstrap_gateway(gateway_id).await;
    let client = reqwest::Client::new();

    let (retired_backend, stream_started, finish_retired) = spawn_blocking_grpc_backend().await;
    let first = snapshot(
        gateway_id,
        1,
        None,
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            retired_backend,
            target_id,
            unit_id,
            1,
        ),
    );
    apply(&client, management_port, &first).await;

    let in_flight = tokio::spawn(async move {
        type RequestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>;
        let grpc_client: Client<HttpConnector, RequestBody> = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .build_http();
        let request = http::Request::builder()
            .method(http::Method::POST)
            .version(http::Version::HTTP_2)
            .uri(format!(
                "http://127.0.0.1:{traffic_port}/grpc.echo.Echo/Unary"
            ))
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
        let mut collected = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            if let Ok(data) = frame.into_data() {
                collected.extend_from_slice(&data);
            }
        }
        String::from_utf8(collected).unwrap()
    });
    tokio::time::timeout(StdDuration::from_secs(2), stream_started)
        .await
        .expect("retired generation did not start gRPC")
        .unwrap();

    let successor_backend = spawn_echo_backend("generation-2").await;
    let second = snapshot(
        gateway_id,
        2,
        Some(1),
        traffic_acl(
            gateway_id,
            traffic_port,
            management_port,
            successor_backend,
            target_id,
            unit_id,
            2,
        ),
    );
    apply(&client, management_port, &second).await;

    let successor_body = client
        .get(format!("http://127.0.0.1:{traffic_port}/"))
        .header(reqwest::header::CONNECTION, "close")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(successor_body, "generation-2");

    finish_retired.send(()).unwrap();
    let retired_body = tokio::time::timeout(StdDuration::from_secs(2), in_flight)
        .await
        .expect("retired gRPC must finish after generation bump")
        .unwrap();
    assert!(
        retired_body.contains("generation-1-first") && retired_body.contains("generation-1-done"),
        "gRPC body incomplete after generation bump: {retired_body}"
    );

    gateway.shutdown().await;
}

fn bootstrap_tcp_acl(gateway_id: Uuid, traffic_port: u16, management_port: u16) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}
entrypoints "tcp" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "tcp"
}}
management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
"#
    )
}

fn traffic_tcp_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: SocketAddr,
    target_id: Uuid,
    unit_id: &str,
    generation: u64,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}
entrypoints "tcp" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "tcp"
}}
routers "managed" {{
  rule        = "PathPrefix(`/`)"
  service     = "managed"
  entrypoints = ["tcp"]
}}
services "managed" {{
  load_balancer {{
    request_timeout = "5s"
    servers {{
      url = "tcp://{backend}"
      target {{
        target_id = "{target_id}"
        unit_id = "{unit_id}"
        generation = {generation}
      }}
    }}
  }}
}}
management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
"#
    )
}

async fn start_bootstrap_tcp_gateway(gateway_id: Uuid) -> (Arc<Gateway>, u16, u16) {
    let mut last_bind_error = None;
    for _ in 0..10 {
        let (traffic_port, management_port) = free_tcp_ports().await;
        let gateway = Arc::new(
            Gateway::new(
                GatewayConfig::from_acl(&bootstrap_tcp_acl(
                    gateway_id,
                    traffic_port,
                    management_port,
                ))
                .unwrap(),
            )
            .unwrap(),
        );
        match gateway.start().await {
            Ok(()) => return (gateway, traffic_port, management_port),
            Err(error) if error.to_string().contains("Address already in use") => {
                last_bind_error = Some(error);
            }
            Err(error) => panic!("bootstrap TCP Gateway failed: {error}"),
        }
    }
    panic!(
        "bootstrap TCP Gateway could not reserve ports: {}",
        last_bind_error.unwrap()
    );
}

async fn spawn_blocking_tcp_backend(
    label: &'static [u8],
) -> (SocketAddr, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (started_tx, started_rx) = oneshot::channel();
    let (finish_tx, finish_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0_u8; 16];
        let _ = stream.read(&mut buf).await;
        let _ = started_tx.send(());
        let _ = finish_rx.await;
        let _ = stream.write_all(label).await;
        let _ = stream.shutdown().await;
    });
    (address, started_rx, finish_tx)
}

async fn spawn_echo_tcp_backend(label: &'static [u8]) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0_u8; 16];
                let _ = stream.read(&mut buf).await;
                let _ = stream.write_all(label).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    address
}

#[tokio::test]
async fn generation_bump_preserves_inflight_tcp_on_retired_target() {
    use tokio::net::TcpStream;

    let gateway_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let unit_id = "workload:tcp-unit";
    let (gateway, traffic_port, management_port) = start_bootstrap_tcp_gateway(gateway_id).await;
    let client = reqwest::Client::new();

    let (retired_backend, stream_started, finish_retired) =
        spawn_blocking_tcp_backend(b"generation-1").await;
    let first = snapshot(
        gateway_id,
        1,
        None,
        traffic_tcp_acl(
            gateway_id,
            traffic_port,
            management_port,
            retired_backend,
            target_id,
            unit_id,
            1,
        ),
    );
    apply(&client, management_port, &first).await;

    let in_flight = tokio::spawn(async move {
        let mut stream = TcpStream::connect(format!("127.0.0.1:{traffic_port}"))
            .await
            .unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        buf
    });
    tokio::time::timeout(StdDuration::from_secs(2), stream_started)
        .await
        .expect("retired generation did not accept TCP")
        .unwrap();

    let successor_backend = spawn_echo_tcp_backend(b"generation-2").await;
    let second = snapshot(
        gateway_id,
        2,
        Some(1),
        traffic_tcp_acl(
            gateway_id,
            traffic_port,
            management_port,
            successor_backend,
            target_id,
            unit_id,
            2,
        ),
    );
    apply(&client, management_port, &second).await;

    let mut successor = TcpStream::connect(format!("127.0.0.1:{traffic_port}"))
        .await
        .unwrap();
    successor.write_all(b"y").await.unwrap();
    let mut successor_body = Vec::new();
    tokio::time::timeout(
        StdDuration::from_secs(2),
        successor.read_to_end(&mut successor_body),
    )
    .await
    .expect("successor TCP timed out")
    .unwrap();
    assert_eq!(
        successor_body, b"generation-2",
        "new TCP connections must use the successor managed generation"
    );

    finish_retired.send(()).unwrap();
    let retired_body = tokio::time::timeout(StdDuration::from_secs(2), in_flight)
        .await
        .expect("retired TCP must finish after generation bump")
        .unwrap();
    assert_eq!(
        retired_body, b"generation-1",
        "in-flight TCP must complete on the retired generation"
    );

    gateway.shutdown().await;
}

fn bootstrap_udp_acl(gateway_id: Uuid, traffic_port: u16, management_port: u16) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}
entrypoints "udp" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "udp"
  udp_session_timeout_secs = 30
  udp_max_sessions = 100
}}
management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
"#
    )
}

fn traffic_udp_acl(
    gateway_id: Uuid,
    traffic_port: u16,
    management_port: u16,
    backend: SocketAddr,
    target_id: Uuid,
    unit_id: &str,
    generation: u64,
) -> String {
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{gateway_id}" }}
shutdown_timeout_secs {{ shutdown_timeout_secs = 0 }}
entrypoints "udp" {{
  address  = "127.0.0.1:{traffic_port}"
  protocol = "udp"
  udp_session_timeout_secs = 30
  udp_max_sessions = 100
}}
routers "managed" {{
  rule        = "PathPrefix(`/`)"
  service     = "managed"
  entrypoints = ["udp"]
}}
services "managed" {{
  load_balancer {{
    request_timeout = "5s"
    servers {{
      url = "udp://{backend}"
      target {{
        target_id = "{target_id}"
        unit_id = "{unit_id}"
        generation = {generation}
      }}
    }}
  }}
}}
management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
"#
    )
}

async fn start_bootstrap_udp_gateway(gateway_id: Uuid) -> (Arc<Gateway>, u16, u16) {
    let mut last_bind_error = None;
    for _ in 0..10 {
        let (traffic_port, management_port) = free_tcp_ports().await;
        let gateway = Arc::new(
            Gateway::new(
                GatewayConfig::from_acl(&bootstrap_udp_acl(
                    gateway_id,
                    traffic_port,
                    management_port,
                ))
                .unwrap(),
            )
            .unwrap(),
        );
        match gateway.start().await {
            Ok(()) => return (gateway, traffic_port, management_port),
            Err(error) if error.to_string().contains("Address already in use") => {
                last_bind_error = Some(error);
            }
            Err(error) => panic!("bootstrap UDP Gateway failed: {error}"),
        }
    }
    panic!(
        "bootstrap UDP Gateway could not reserve ports: {}",
        last_bind_error.unwrap()
    );
}

async fn spawn_echo_udp_backend(label: &'static [u8]) -> SocketAddr {
    use tokio::net::UdpSocket;

    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0_u8; 64];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if n == 0 {
                continue;
            }
            let _ = socket.send_to(label, peer).await;
        }
    });
    address
}

#[tokio::test]
async fn generation_bump_preserves_inflight_udp_session_on_retired_target() {
    use tokio::net::UdpSocket;

    let gateway_id = Uuid::new_v4();
    let target_id = Uuid::new_v4();
    let unit_id = "workload:udp-unit";
    let (gateway, traffic_port, management_port) = start_bootstrap_udp_gateway(gateway_id).await;
    let client = reqwest::Client::new();

    let retired_backend = spawn_echo_udp_backend(b"generation-1").await;
    let first = snapshot(
        gateway_id,
        1,
        None,
        traffic_udp_acl(
            gateway_id,
            traffic_port,
            management_port,
            retired_backend,
            target_id,
            unit_id,
            1,
        ),
    );
    apply(&client, management_port, &first).await;

    let sticky = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let gateway_addr: SocketAddr = format!("127.0.0.1:{traffic_port}").parse().unwrap();
    sticky.send_to(b"ping", gateway_addr).await.unwrap();
    let mut buf = [0_u8; 64];
    let (n, _) = tokio::time::timeout(StdDuration::from_secs(2), sticky.recv_from(&mut buf))
        .await
        .expect("retired generation did not answer UDP")
        .unwrap();
    assert_eq!(&buf[..n], b"generation-1");

    let successor_backend = spawn_echo_udp_backend(b"generation-2").await;
    let second = snapshot(
        gateway_id,
        2,
        Some(1),
        traffic_udp_acl(
            gateway_id,
            traffic_port,
            management_port,
            successor_backend,
            target_id,
            unit_id,
            2,
        ),
    );
    apply(&client, management_port, &second).await;

    sticky.send_to(b"again", gateway_addr).await.unwrap();
    let (n, _) = tokio::time::timeout(StdDuration::from_secs(2), sticky.recv_from(&mut buf))
        .await
        .expect("sticky UDP session must finish on retired generation")
        .unwrap();
    assert_eq!(
        &buf[..n],
        b"generation-1",
        "established UDP session must stay on the retired generation"
    );

    let fresh = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    fresh.send_to(b"new", gateway_addr).await.unwrap();
    let (n, _) = tokio::time::timeout(StdDuration::from_secs(2), fresh.recv_from(&mut buf))
        .await
        .expect("successor UDP timed out")
        .unwrap();
    assert_eq!(
        &buf[..n],
        b"generation-2",
        "new UDP clients must use the successor managed generation"
    );

    gateway.shutdown().await;
}
