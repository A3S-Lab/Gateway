//! Local protocol fixtures for the same-host proxy comparison.

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

type BoxError = Box<dyn Error + Send + Sync>;

const GRPC_ADDRESS: &str = "127.0.0.1:18090";
const TCP_ADDRESS: &str = "127.0.0.1:18091";
const UDP_ADDRESS: &str = "127.0.0.1:18092";
const WEBSOCKET_ADDRESS: &str = "127.0.0.1:18093";

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tokio::try_join!(
        serve_grpc(),
        serve_tcp_echo(),
        serve_udp_echo(),
        serve_websocket_echo(),
    )?;
    Ok(())
}

async fn serve_grpc() -> Result<(), BoxError> {
    let listener = TcpListener::bind(GRPC_ADDRESS).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let service = service_fn(|_request: Request<hyper::body::Incoming>| async move {
                let mut response = Response::new(Full::new(Bytes::from_static(&[0, 0, 0, 0, 0])));
                response.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/grpc"),
                );
                response
                    .headers_mut()
                    .insert("grpc-status", http::HeaderValue::from_static("0"));
                Ok::<_, Infallible>(response)
            });
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

async fn serve_tcp_echo() -> Result<(), BoxError> {
    let listener = TcpListener::bind(TCP_ADDRESS).await?;
    loop {
        let (mut stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let mut buffer = [0_u8; 16 * 1024];
            loop {
                let length = match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(length) => length,
                };
                if stream.write_all(&buffer[..length]).await.is_err() {
                    break;
                }
            }
        });
    }
}

async fn serve_udp_echo() -> Result<(), BoxError> {
    let socket = UdpSocket::bind(UDP_ADDRESS).await?;
    let mut buffer = [0_u8; 65_507];
    loop {
        let (length, peer) = socket.recv_from(&mut buffer).await?;
        socket.send_to(&buffer[..length], peer).await?;
    }
}

async fn serve_websocket_echo() -> Result<(), BoxError> {
    let listener = TcpListener::bind(WEBSOCKET_ADDRESS).await?;
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let Ok(mut websocket) = tokio_tungstenite::accept_async(stream).await else {
                return;
            };
            while let Some(Ok(message)) = websocket.next().await {
                if message.is_close() || websocket.send(message).await.is_err() {
                    break;
                }
            }
        });
    }
}
