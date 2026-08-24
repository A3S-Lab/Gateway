use super::*;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[test]
fn client_pool_shards_distribute_adjacent_connections() {
    let mut seen = [false; 4];
    for port in (40_000..40_128).step_by(2) {
        let context = ForwardedContext::new(
            SocketAddr::from(([127, 0, 0, 1], port)),
            ForwardedProto::Http,
        );
        seen[proxy_client_shard(Some(context), seen.len())] = true;
    }

    assert!(seen.into_iter().all(|was_selected| was_selected));
    assert_eq!(proxy_client_shard(None, 4), 0);
    assert_eq!(
        proxy_client_shard(
            Some(ForwardedContext::new(
                SocketAddr::from(([127, 0, 0, 1], 40_000)),
                ForwardedProto::Http,
            )),
            1,
        ),
        0
    );
}

#[test]
fn client_pool_shards_follow_the_active_tokio_runtime() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()
        .unwrap();
    let _runtime_guard = runtime.enter();

    assert_eq!(proxy_client_shard_count(), 2);
}

#[test]
fn client_pool_shard_reduction_matches_modulo() {
    for shard_count in [1, 2, 3, 4, 7, 16] {
        for hash in [0, 1, 7, 31, 1_000_003, u64::MAX] {
            let expected = if shard_count == 1 {
                0
            } else {
                (hash as usize) % shard_count
            };
            assert_eq!(proxy_client_shard_from_hash(hash, shard_count), expected);
        }
    }
}

#[test]
fn prepared_connection_reuses_client_pool_shard_hash() {
    let context = ForwardedContext::new(
        SocketAddr::from(([127, 0, 0, 1], 40_017)),
        ForwardedProto::Http,
    );
    let prepared = PreparedForwardedContext::new(context, 8080).unwrap();

    for shard_count in [1, 4, 16] {
        assert_eq!(
            prepared.client_shard(shard_count),
            proxy_client_shard(Some(context), shard_count)
        );
    }
}

/// Spawn a mock HTTP backend that returns a configurable response.
async fn spawn_mock_backend(status: u16, body: &'static str, delay_ms: u64) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let body = body.to_string();
            let status = status;
            let delay = delay_ms;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                if delay > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                let resp = format!(
                    "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                    status,
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// Spawn a backend that captures one raw HTTP request and returns 200 OK.
async fn spawn_capture_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = tx.send(request);

        let body = "ok";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (addr, rx)
}

fn captured_header(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

#[test]
fn test_hop_by_hop_headers() {
    assert!(is_hop_by_hop("Connection"));
    assert!(is_hop_by_hop("connection"));
    assert!(is_hop_by_hop("Keep-Alive"));
    assert!(is_hop_by_hop("Transfer-Encoding"));
    assert!(is_hop_by_hop("Upgrade"));
    assert!(is_hop_by_hop("Proxy-Authorization"));
    assert!(is_hop_by_hop("Proxy-Connection"));
    assert!(is_hop_by_hop("Trailer"));

    assert!(!is_hop_by_hop("Content-Type"));
    assert!(!is_hop_by_hop("Authorization"));
    assert!(!is_hop_by_hop("X-Custom-Header"));
    assert!(!is_hop_by_hop("Host"));
}

#[test]
fn builds_upstream_uri_by_reusing_the_request_path() {
    let backend = Backend::new("http://127.0.0.1:9000".to_string(), 1);
    let request_uri: http::Uri = "/v1/models?tenant=acme".parse().unwrap();

    let upstream = build_upstream_uri(&backend, &request_uri).unwrap();

    assert_eq!(upstream, "http://127.0.0.1:9000/v1/models?tenant=acme");
}

#[test]
fn builds_upstream_uri_with_a_configured_base_path() {
    let backend = Backend::new("http://127.0.0.1:9000/api".to_string(), 1);
    let request_uri: http::Uri = "/v1/models?tenant=acme".parse().unwrap();

    let upstream = build_upstream_uri(&backend, &request_uri).unwrap();

    assert_eq!(upstream, "http://127.0.0.1:9000/api/v1/models?tenant=acme");
}

#[test]
fn owned_request_builder_preserves_proxy_semantics() {
    let backend = Backend::new("http://127.0.0.1:9000".to_string(), 1);
    let method = http::Method::POST;
    let uri: http::Uri = "/v1/chat/completions?tenant=acme".parse().unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, "api.example.com:8443".parse().unwrap());
    headers.insert(http::header::CONNECTION, "x-hop".parse().unwrap());
    headers.insert("x-hop", "remove-me".parse().unwrap());
    headers.insert("x-forwarded-for", "192.0.2.1".parse().unwrap());
    let context =
        ForwardedContext::new("198.51.100.7:54321".parse().unwrap(), ForwardedProto::Https);

    let borrowed = build_upstream_request(
        &backend,
        &method,
        &uri,
        &headers,
        full_request_body(Bytes::new()),
        Some(context),
    )
    .unwrap();
    let owned = build_upstream_request_owned(
        &backend,
        method,
        uri,
        headers,
        full_request_body(Bytes::new()),
        Some(context),
        None,
    )
    .unwrap();

    assert_eq!(owned.method(), borrowed.method());
    assert_eq!(owned.uri(), borrowed.uri());
    assert_eq!(owned.headers(), borrowed.headers());
    assert!(!owned.headers().contains_key("x-hop"));
    assert_eq!(
        owned.headers()["x-forwarded-for"],
        "192.0.2.1, 198.51.100.7"
    );
    assert_eq!(owned.headers()["x-forwarded-port"], "8443");
}

#[test]
fn test_connection_nominated_headers_are_hop_by_hop() {
    let mut headers = http::HeaderMap::new();
    headers.append(
        http::header::CONNECTION,
        "keep-alive, X-First-Hop".parse().unwrap(),
    );
    headers.append(http::header::CONNECTION, "X-Second-Hop".parse().unwrap());
    headers.insert("X-First-Hop", "one".parse().unwrap());
    headers.insert("X-Second-Hop", "two".parse().unwrap());
    headers.insert("X-End-To-End", "preserved".parse().unwrap());
    headers.append(http::header::SET_COOKIE, "first=1".parse().unwrap());
    headers.append(http::header::SET_COOKIE, "second=2".parse().unwrap());

    assert!(is_hop_by_hop_header(
        &headers,
        &http::header::HeaderName::from_static("x-first-hop")
    ));
    assert!(is_hop_by_hop_header(
        &headers,
        &http::header::HeaderName::from_static("x-second-hop")
    ));

    let filtered = filter_hop_by_hop_headers(headers);
    assert!(!filtered.contains_key(http::header::CONNECTION));
    assert!(!filtered.contains_key("x-first-hop"));
    assert!(!filtered.contains_key("x-second-hop"));
    assert_eq!(filtered["x-end-to-end"], "preserved");
    assert_eq!(filtered.get_all(http::header::SET_COOKIE).iter().count(), 2);
}

#[test]
fn end_to_end_only_headers_pass_through_unchanged() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        "application/json".parse().unwrap(),
    );
    headers.append(http::header::SET_COOKIE, "first=1".parse().unwrap());
    headers.append(http::header::SET_COOKIE, "second=2".parse().unwrap());
    let expected = headers.clone();

    assert_eq!(filter_hop_by_hop_headers(headers), expected);
}

#[test]
fn test_forwarded_context_helpers() {
    let context =
        ForwardedContext::new("203.0.113.10:50123".parse().unwrap(), ForwardedProto::Https);
    assert_eq!(context.proto.as_str(), "https");
    assert_eq!(context.proto.default_port(), "443");
}

#[test]
fn prepared_forwarded_context_preserves_header_semantics() {
    let context =
        ForwardedContext::new("203.0.113.10:50123".parse().unwrap(), ForwardedProto::Https);
    let prepared = PreparedForwardedContext::new(context, 8443).unwrap();
    let mut headers = http::HeaderMap::new();
    headers.insert(http::header::HOST, "api.example.test:8443".parse().unwrap());

    prepared.apply(&mut headers).unwrap();
    assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
    assert_eq!(headers["x-forwarded-host"], "api.example.test:8443");
    assert_eq!(headers["x-forwarded-proto"], "https");
    assert_eq!(headers["x-forwarded-port"], "8443");

    headers.insert("x-forwarded-for", "192.0.2.1".parse().unwrap());
    headers.insert("x-forwarded-host", "edge.example.test".parse().unwrap());
    prepared.apply(&mut headers).unwrap();
    assert_eq!(headers["x-forwarded-for"], "192.0.2.1, 203.0.113.10");
    assert_eq!(
        headers["x-forwarded-host"],
        "edge.example.test, api.example.test:8443"
    );
}

#[test]
fn test_http_proxy_default() {
    let proxy = HttpProxy::default();
    assert_eq!(proxy.timeout, Duration::from_secs(30));
}

#[test]
fn test_http_proxy_custom_timeout() {
    let proxy = HttpProxy::with_timeout(Duration::from_secs(60));
    assert_eq!(proxy.timeout, Duration::from_secs(60));
}

#[tokio::test]
async fn test_forward_with_options_uses_request_timeout() {
    let backend_addr = spawn_mock_backend(200, "slow", 200).await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let uri: http::Uri = "/slow".parse().unwrap();
    let result = proxy
        .forward_streaming_response_with_options(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
            ForwardOptions {
                context: None,
                timeouts: Some(HttpTimeouts::new(
                    Duration::from_millis(50),
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )),
            },
        )
        .await;

    assert!(matches!(result, Err(GatewayError::UpstreamTimeout(50))));
}

#[test]
fn test_proxy_response_fields() {
    let resp = ProxyResponse {
        status: http::StatusCode::OK,
    };
    assert_eq!(resp.status, http::StatusCode::OK);
}

#[tokio::test]
async fn test_forward_success() {
    let backend_addr = spawn_mock_backend(200, "hello world", 0).await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let uri: http::Uri = "/test".parse().unwrap();
    let result = proxy
        .forward(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.status, http::StatusCode::OK);
}

#[tokio::test]
async fn owned_exchange_can_elide_unused_backend_accounting() {
    let backend_addr = spawn_mock_backend(200, "hello world", 0).await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let tracked = proxy
        .forward_buffered_exchange_owned(
            &backend,
            OwnedBufferedRequest {
                method: http::Method::GET,
                uri: "/tracked".parse().unwrap(),
                headers: http::HeaderMap::new(),
                body: Bytes::new(),
            },
            ForwardOptions::default(),
            None,
            BackendOperationTracking::Tracked,
        )
        .await
        .unwrap();
    assert_eq!(backend.connections(), 1);
    assert_eq!(
        tracked.body.collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"hello world")
    );
    assert_eq!(backend.connections(), 0);

    let untracked = proxy
        .forward_buffered_exchange_owned(
            &backend,
            OwnedBufferedRequest {
                method: http::Method::GET,
                uri: "/untracked".parse().unwrap(),
                headers: http::HeaderMap::new(),
                body: Bytes::new(),
            },
            ForwardOptions::default(),
            None,
            BackendOperationTracking::Untracked,
        )
        .await
        .unwrap();
    assert_eq!(backend.connections(), 0);
    assert_eq!(
        untracked.body.collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"hello world")
    );
    assert_eq!(backend.connections(), 0);
}

#[tokio::test]
async fn test_forward_404_response() {
    let backend_addr = spawn_mock_backend(404, "not found", 0).await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let uri: http::Uri = "/missing".parse().unwrap();
    let result = proxy
        .forward(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.status, http::StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_forward_500_response() {
    let backend_addr = spawn_mock_backend(500, "internal error", 0).await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let uri: http::Uri = "/error".parse().unwrap();
    let result = proxy
        .forward(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.status, http::StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_forward_connection_refused() {
    // Use a port that nothing is listening on
    let backend_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let uri: http::Uri = "/test".parse().unwrap();
    let result = proxy
        .forward(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;

    assert!(result.is_err());
}

#[tokio::test]
async fn test_forward_with_headers() {
    let backend_addr = spawn_mock_backend(200, "ok", 0).await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let mut headers = http::HeaderMap::new();
    headers.insert("X-Custom-Header", "custom-value".parse().unwrap());
    headers.insert("Authorization", "Bearer token".parse().unwrap());
    // Connection header should be filtered (hop-by-hop)
    headers.insert("Connection", "close".parse().unwrap());

    let uri: http::Uri = "/headers".parse().unwrap();
    let result = proxy
        .forward(&backend, &http::Method::GET, &uri, &headers, Bytes::new())
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_forward_with_options_adds_forwarded_headers() {
    let (backend_addr, captured) = spawn_capture_backend().await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let mut headers = http::HeaderMap::new();
    headers.insert("Host", "api.example.test:8443".parse().unwrap());
    headers.insert("Connection", "close".parse().unwrap());

    let context =
        ForwardedContext::new("203.0.113.42:53100".parse().unwrap(), ForwardedProto::Https);
    let uri: http::Uri = "/headers?debug=true".parse().unwrap();
    let result = proxy
        .forward_streaming_response_with_options(
            &backend,
            &http::Method::GET,
            &uri,
            &headers,
            Bytes::new(),
            ForwardOptions {
                context: Some(context),
                timeouts: None,
            },
        )
        .await;

    assert!(result.is_ok());
    let request = captured.await.unwrap();
    assert_eq!(
        captured_header(&request, "x-forwarded-for").as_deref(),
        Some("203.0.113.42")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-host").as_deref(),
        Some("api.example.test:8443")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-proto").as_deref(),
        Some("https")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-port").as_deref(),
        Some("8443")
    );
    assert!(captured_header(&request, "connection").is_none());
}

#[tokio::test]
async fn test_forward_with_options_appends_forwarded_for() {
    let (backend_addr, captured) = spawn_capture_backend().await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let mut headers = http::HeaderMap::new();
    headers.insert("Host", "api.example.test".parse().unwrap());
    headers.insert("X-Forwarded-For", "198.51.100.10".parse().unwrap());
    headers.insert("X-Forwarded-Proto", "https".parse().unwrap());

    let context = ForwardedContext::new("127.0.0.1:53101".parse().unwrap(), ForwardedProto::Http);
    let uri: http::Uri = "/chain".parse().unwrap();
    let result = proxy
        .forward_streaming_response_with_options(
            &backend,
            &http::Method::GET,
            &uri,
            &headers,
            Bytes::new(),
            ForwardOptions {
                context: Some(context),
                timeouts: None,
            },
        )
        .await;

    assert!(result.is_ok());
    let request = captured.await.unwrap();
    assert_eq!(
        captured_header(&request, "x-forwarded-for").as_deref(),
        Some("198.51.100.10, 127.0.0.1")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-proto").as_deref(),
        Some("http")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-port").as_deref(),
        Some("80")
    );
}

#[tokio::test]
async fn test_forward_with_body() {
    let backend_addr = spawn_mock_backend(200, "received", 0).await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let uri: http::Uri = "/upload".parse().unwrap();
    let body = Bytes::from("request body content");

    let result = proxy
        .forward(
            &backend,
            &http::Method::POST,
            &uri,
            &http::HeaderMap::new(),
            body,
        )
        .await;

    assert!(result.is_ok());
    let resp = result.unwrap();
    assert_eq!(resp.status, http::StatusCode::OK);
}

#[tokio::test]
async fn test_forward_path_and_query_preserved() {
    let backend_addr = spawn_mock_backend(200, "ok", 0).await;
    let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    // Test path and query string are preserved
    let uri: http::Uri = "/api/items?id=123&filter=name".parse().unwrap();
    let result = proxy
        .forward(
            &backend,
            &http::Method::GET,
            &uri,
            &http::HeaderMap::new(),
            Bytes::new(),
        )
        .await;

    assert!(result.is_ok());
}
