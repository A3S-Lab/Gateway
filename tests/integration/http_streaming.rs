async fn spawn_full_duplex_http_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0_u8; 4096];
        read_until_bytes(&mut stream, &mut request, b"first", &mut buf).await;

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/plain\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n\
                  5\r\nfirst\r\n",
            )
            .await
            .unwrap();

        read_until_bytes(&mut stream, &mut request, b"second", &mut buf).await;
        stream.write_all(b"6\r\nsecond\r\n0\r\n\r\n").await.unwrap();
        stream.shutdown().await.unwrap();
    });

    address
}

async fn read_until_bytes(
    stream: &mut tokio::net::TcpStream,
    received: &mut Vec<u8>,
    expected: &[u8],
    buf: &mut [u8],
) {
    while !received
        .windows(expected.len())
        .any(|window| window == expected)
    {
        let count = stream.read(buf).await.unwrap();
        assert!(count > 0, "HTTP exchange ended before the expected bytes");
        received.extend_from_slice(&buf[..count]);
    }
}

#[tokio::test]
async fn test_http_proxy_streams_request_and_response_concurrently() {
    let port = free_port().await;
    let backend = spawn_full_duplex_http_backend().await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gateway = Arc::new(Gateway::new(config).unwrap());
    gateway.start().await.unwrap();
    wait_ready(port).await;

    let mut client = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    client
        .write_all(
            b"POST /duplex HTTP/1.1\r\n\
              Host: localhost\r\n\
              Transfer-Encoding: chunked\r\n\
              Connection: close\r\n\r\n\
              5\r\nfirst\r\n",
        )
        .await
        .unwrap();

    let mut response = Vec::new();
    let mut buf = [0_u8; 1024];
    tokio::time::timeout(
        Duration::from_millis(500),
        read_until_bytes(&mut client, &mut response, b"first", &mut buf),
    )
    .await
    .expect("Gateway must relay a response before the request body completes");

    client
        .write_all(b"6\r\nsecond\r\n0\r\n\r\n")
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(1),
        read_until_bytes(&mut client, &mut response, b"second", &mut buf),
    )
    .await
    .expect("Gateway should complete the overlapping HTTP exchange");

    gateway.shutdown().await;
}
