//! Minimal loopback HTTP upstream for Managed Runtime Service real-process tests.
//!
//! Prints `READY <addr>` once listening, then serves:
//! - `/healthz` and other paths: echo path as body (idle bind/traffic)
//! - `/sse-hold`: SSE first event then block until `POST /release` (drain-wait)
//! - `/ws-hold`: WebSocket upgrade then block until `POST /release` (drain-wait)
//! - `/release`: unblocks held SSE/WebSocket streams

use futures_util::StreamExt;
use std::io::Write;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind managed-runtime upstream");
    let address = listener.local_addr().expect("local addr");
    println!("READY {address}");
    let _ = std::io::stdout().flush();

    let (release_tx, release_rx) = watch::channel(false);

    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            break;
        };
        let release_tx = release_tx.clone();
        let mut release_rx = release_rx.clone();
        tokio::spawn(async move {
            let mut bytes = Vec::new();
            let mut chunk = [0_u8; 1024];
            loop {
                let read = match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&bytes);
            let path = request
                .lines()
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .unwrap_or("/")
                .to_string();

            if path == "/release" {
                let _ = release_tx.send(true);
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                return;
            }

            if path == "/sse-hold" {
                // "data: sse-hold-first\n\n" is 22 bytes → chunk size 0x16
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\n\
                          Content-Type: text/event-stream\r\n\
                          Transfer-Encoding: chunked\r\n\
                          Connection: close\r\n\r\n\
                          16\r\ndata: sse-hold-first\n\n\r\n",
                    )
                    .await;
                while !*release_rx.borrow() {
                    if release_rx.changed().await.is_err() {
                        return;
                    }
                }
                let _ = stream.write_all(b"0\r\n\r\n").await;
                return;
            }

            if path == "/ws-hold" && is_websocket_upgrade(&request) {
                let Some(key) = websocket_key(&request) else {
                    return;
                };
                let accept = derive_accept_key(key.as_bytes());
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\n\
                     Upgrade: websocket\r\n\
                     Connection: Upgrade\r\n\
                     Sec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                let mut websocket =
                    WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
                while !*release_rx.borrow() {
                    tokio::select! {
                        changed = release_rx.changed() => {
                            if changed.is_err() {
                                return;
                            }
                        }
                        message = websocket.next() => {
                            match message {
                                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                                Some(Ok(_)) => {}
                            }
                        }
                    }
                }
                let _ = websocket.close(None).await;
                return;
            }

            let body = path.as_bytes();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(body).await;
        });
    }
}

fn is_websocket_upgrade(request: &str) -> bool {
    request.lines().any(|line| {
        let (name, value) = line.split_once(':').unwrap_or(("", ""));
        name.eq_ignore_ascii_case("upgrade") && value.trim().eq_ignore_ascii_case("websocket")
    })
}

fn websocket_key(request: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("sec-websocket-key")
            .then(|| value.trim().to_string())
    })
}
