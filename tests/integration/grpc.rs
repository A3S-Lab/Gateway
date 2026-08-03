use bytes::{Bytes, BytesMut};
use futures_util::stream;
use http_body_util::{BodyExt as _, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use tokio::sync::{mpsc, oneshot};

type TestRequestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, Infallible>;

async fn spawn_full_duplex_grpc_backend() -> (
    SocketAddr,
    oneshot::Receiver<Bytes>,
    oneshot::Receiver<Bytes>,
    oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (first_request_tx, first_request_rx) = oneshot::channel();
    let (complete_request_tx, complete_request_rx) = oneshot::channel();
    let (continue_response_tx, continue_response_rx) = oneshot::channel();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let first_request_tx = Arc::new(std::sync::Mutex::new(Some(first_request_tx)));
        let complete_request_tx = Arc::new(std::sync::Mutex::new(Some(complete_request_tx)));
        let continue_response_rx = Arc::new(std::sync::Mutex::new(Some(continue_response_rx)));
        let service = service_fn(move |mut request: hyper::Request<hyper::body::Incoming>| {
            let first_request_tx = first_request_tx.clone();
            let complete_request_tx = complete_request_tx.clone();
            let continue_response_rx = continue_response_rx.clone();
            async move {
                assert_eq!(request.version(), http::Version::HTTP_2);
                assert_eq!(request.method(), http::Method::POST);

                let first = loop {
                    let frame = request.body_mut().frame().await.unwrap().unwrap();
                    if let Ok(data) = frame.into_data() {
                        break data;
                    }
                };
                first_request_tx
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(first.clone())
                    .unwrap();

                let complete_request_tx = complete_request_tx.lock().unwrap().take().unwrap();
                tokio::spawn(async move {
                    let mut complete = BytesMut::from(first.as_ref());
                    while let Some(frame) = request.body_mut().frame().await {
                        if let Ok(data) = frame.unwrap().into_data() {
                            complete.extend_from_slice(&data);
                        }
                    }
                    let _ = complete_request_tx.send(complete.freeze());
                });

                let continue_response = continue_response_rx.lock().unwrap().take().unwrap();
                let response_stream = stream::unfold(
                    (0_u8, Some(continue_response)),
                    |(stage, continue_response)| async move {
                        match stage {
                            0 => Some((
                                Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                                    b"response-first",
                                ))),
                                (1, continue_response),
                            )),
                            1 => {
                                let _ = continue_response.unwrap().await;
                                Some((
                                    Ok(Frame::data(Bytes::from_static(b"-second"))),
                                    (2, None),
                                ))
                            }
                            2 => {
                                let mut trailers = http::HeaderMap::new();
                                trailers.insert("grpc-status", "0".parse().unwrap());
                                trailers.insert("x-grpc-trailer", "preserved".parse().unwrap());
                                Some((Ok(Frame::trailers(trailers)), (3, None)))
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
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });

    (
        address,
        first_request_rx,
        complete_request_rx,
        continue_response_tx,
    )
}

async fn spawn_grpc_mirror_backend() -> (SocketAddr, oneshot::Receiver<Bytes>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (body_tx, body_rx) = oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = find_header_end(&request) {
                break header_end;
            }
        };
        let content_length = String::from_utf8_lossy(&request[..header_end])
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap();
        let body_start = header_end + 4;
        while request.len() - body_start < content_length {
            let read = stream.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..read]);
        }
        body_tx
            .send(Bytes::copy_from_slice(
                &request[body_start..body_start + content_length],
            ))
            .unwrap();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });

    (address, body_rx)
}

#[tokio::test]
async fn test_grpc_proxy_streams_bidirectionally_and_preserves_trailers() {
    let gateway_port = free_port().await;
    let (backend, mut first_request, complete_request, continue_response) =
        spawn_full_duplex_grpc_backend().await;
    let mut config = build_config(gateway_port, backend, "PathPrefix(`/`)").await;
    let shadow = config.services["test-svc"].clone();
    config.services.insert("disabled-shadow".to_string(), shadow);
    config.services.get_mut("test-svc").unwrap().mirror =
        Some(a3s_gateway::config::MirrorConfig {
            service: "disabled-shadow".to_string(),
            percentage: 0,
        });
    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();
    wait_ready(gateway_port).await;

    let client: Client<HttpConnector, TestRequestBody> =
        Client::builder(TokioExecutor::new()).http2_only(true).build_http();
    let (request_tx, request_rx) = mpsc::channel::<Bytes>(2);
    request_tx
        .send(Bytes::from_static(b"request-first"))
        .await
        .unwrap();
    let request_stream = stream::unfold(request_rx, |mut receiver| async move {
        receiver
            .recv()
            .await
            .map(|bytes| (Ok::<_, Infallible>(Frame::data(bytes)), receiver))
    });
    let request = http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri(format!(
            "http://127.0.0.1:{gateway_port}/grpc.echo.Echo/Bidi"
        ))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers")
        .body(StreamBody::new(request_stream).boxed_unsync())
        .unwrap();
    let response_task = tokio::spawn(async move { client.request(request).await.unwrap() });

    let first = tokio::time::timeout(Duration::from_secs(2), &mut first_request).await;
    if first.is_err() {
        request_tx
            .send(Bytes::from_static(b"-second"))
            .await
            .unwrap();
        drop(request_tx);
        let _ = continue_response.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), response_task).await;
        gateway.shutdown().await;
        panic!("gRPC request was buffered before reaching the upstream");
    }
    assert_eq!(first.unwrap().unwrap(), Bytes::from_static(b"request-first"));

    let response = tokio::time::timeout(Duration::from_secs(2), response_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(
        response.headers().get(http::header::CONTENT_TYPE).unwrap(),
        "application/grpc"
    );
    let mut response_body = response.into_body();
    let first_response = tokio::time::timeout(Duration::from_secs(2), response_body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert_eq!(first_response, Bytes::from_static(b"response-first"));

    request_tx
        .send(Bytes::from_static(b"-second"))
        .await
        .unwrap();
    drop(request_tx);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), complete_request)
            .await
            .unwrap()
            .unwrap(),
        Bytes::from_static(b"request-first-second")
    );
    continue_response.send(()).unwrap();

    let mut response_bytes = BytesMut::from(first_response.as_ref());
    let mut response_trailers = None;
    while let Some(frame) = response_body.frame().await {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref() {
            response_bytes.extend_from_slice(data);
        }
        if let Some(trailers) = frame.trailers_ref() {
            response_trailers = Some(trailers.clone());
        }
    }
    assert_eq!(response_bytes.freeze(), Bytes::from_static(b"response-first-second"));
    let trailers = response_trailers.expect("gRPC trailers must reach the downstream client");
    assert_eq!(trailers["grpc-status"], "0");
    assert_eq!(trailers["x-grpc-trailer"], "preserved");

    gateway.shutdown().await;
}

#[tokio::test]
async fn test_grpc_proxy_preserves_buffered_body_when_mirroring() {
    let gateway_port = free_port().await;
    let (primary, first_request, complete_request, continue_response) =
        spawn_full_duplex_grpc_backend().await;
    let (mirror, mirrored_body) = spawn_grpc_mirror_backend().await;
    let mut config = build_config(gateway_port, primary, "PathPrefix(`/`)").await;
    let mut shadow = config.services["test-svc"].clone();
    shadow.load_balancer.servers[0].url = format!("http://{mirror}");
    config.services.insert("shadow".to_string(), shadow);
    config.services.get_mut("test-svc").unwrap().mirror =
        Some(a3s_gateway::config::MirrorConfig {
            service: "shadow".to_string(),
            percentage: 100,
        });
    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();
    wait_ready(gateway_port).await;

    let client: Client<HttpConnector, TestRequestBody> =
        Client::builder(TokioExecutor::new()).http2_only(true).build_http();
    let request_body = Bytes::from_static(b"complete-unary-request");
    let request = http::Request::builder()
        .method(http::Method::POST)
        .version(http::Version::HTTP_2)
        .uri(format!(
            "http://127.0.0.1:{gateway_port}/grpc.echo.Echo/Unary"
        ))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers")
        .body(
            http_body_util::Full::new(request_body.clone())
                .map_err(|never| match never {})
                .boxed_unsync(),
        )
        .unwrap();
    let response_task = tokio::spawn(async move { client.request(request).await.unwrap() });

    assert!(!tokio::time::timeout(Duration::from_secs(2), first_request)
        .await
        .unwrap()
        .unwrap()
        .is_empty());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), complete_request)
            .await
            .unwrap()
            .unwrap(),
        request_body
    );
    continue_response.send(()).unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), response_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    let collected = response.into_body().collect().await.unwrap();
    assert_eq!(collected.to_bytes(), Bytes::from_static(b"response-first-second"));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), mirrored_body)
            .await
            .unwrap()
            .unwrap(),
        request_body
    );

    gateway.shutdown().await;
}

#[tokio::test]
async fn test_grpc_web_content_type_remains_regular_http() {
    let gateway_port = free_port().await;
    let backend = spawn_backend("regular-http").await;
    let config = build_config(gateway_port, backend, "PathPrefix(`/`)").await;
    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();
    wait_ready(gateway_port).await;

    let response = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{gateway_port}/grpc-web"))
        .header(http::header::CONTENT_TYPE, "application/grpc-web+proto")
        .body(Bytes::from_static(b"grpc-web-frame"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "regular-http");

    gateway.shutdown().await;
}
