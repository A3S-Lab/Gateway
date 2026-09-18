//! Dual-protocol (HTTP/1 + HTTP/2) loopback upstream for MRS gRPC real-process tests.
//!
//! Prints `READY <addr>` once listening. Serves `/healthz` immediately, holds
//! non-health responses as application/grpc streams until `POST /release`.

use bytes::Bytes;
use futures_util::stream;
use http_body_util::{Full, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use std::convert::Infallible;
use std::io::Write;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::watch;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind managed-runtime gRPC upstream");
    let address = listener.local_addr().expect("local addr");
    println!("READY {address}");
    let _ = std::io::stdout().flush();

    let (release_tx, release_rx) = watch::channel(false);
    let release_tx = Arc::new(release_tx);

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let release_tx = release_tx.clone();
        let release_rx = release_rx.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let release_tx = release_tx.clone();
                let release = release_rx.clone();
                async move {
                    let path = request.uri().path().to_string();
                    if path == "/release" {
                        let _ = release_tx.send(true);
                        return Ok::<_, Infallible>(
                            hyper::Response::builder()
                                .status(200)
                                .body(http_body_util::Either::Left(Full::new(Bytes::from_static(
                                    b"ok",
                                ))))
                                .unwrap(),
                        );
                    }
                    if path == "/healthz" {
                        return Ok(hyper::Response::builder()
                            .status(200)
                            .body(http_body_util::Either::Left(Full::new(Bytes::new())))
                            .unwrap());
                    }

                    let response_stream = stream::unfold(0_u8, move |stage| {
                        let mut release = release.clone();
                        async move {
                            match stage {
                                0 => Some((
                                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                                        b"grpc-hold-first",
                                    ))),
                                    1,
                                )),
                                1 => {
                                    while !*release.borrow() {
                                        if release.changed().await.is_err() {
                                            return None;
                                        }
                                    }
                                    Some((
                                        Ok(Frame::data(Bytes::from_static(b"grpc-hold-done"))),
                                        2,
                                    ))
                                }
                                2 => {
                                    let mut trailers = http::HeaderMap::new();
                                    trailers.insert("grpc-status", "0".parse().unwrap());
                                    Some((Ok(Frame::trailers(trailers)), 3))
                                }
                                _ => None,
                            }
                        }
                    });
                    Ok(hyper::Response::builder()
                        .status(200)
                        .header(http::header::CONTENT_TYPE, "application/grpc")
                        .body(http_body_util::Either::Right(StreamBody::new(
                            response_stream,
                        )))
                        .unwrap())
                }
            });
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
