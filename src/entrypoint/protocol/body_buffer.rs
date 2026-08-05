//! Bounded look-ahead buffering for response-body middleware.

use super::ResponseBody;
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use hyper::body::{Body, Frame, SizeHint};
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

pub(super) enum BufferedBody {
    Complete(Bytes),
    Streaming(ResponseBody),
}

/// Collect at most `limit` bytes without losing a prefix, trailer, or error.
///
/// A complete body is returned as bytes for middleware transformation. Once
/// the limit is crossed, or a non-DATA frame/error is observed, the consumed
/// prefix is replayed in front of the untouched remainder.
pub(super) async fn buffer_body_up_to(mut body: ResponseBody, limit: usize) -> BufferedBody {
    let mut buffered = BytesMut::new();
    loop {
        match body.frame().await {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if buffered.len().saturating_add(data.len()) > limit {
                        let mut prefix = VecDeque::new();
                        push_buffered_data(&mut prefix, buffered.freeze());
                        prefix.push_back(Ok(Frame::data(data)));
                        return BufferedBody::Streaming(replay_body(prefix, Some(body)));
                    }
                    buffered.extend_from_slice(&data);
                }
                Err(frame) => {
                    let mut prefix = VecDeque::new();
                    push_buffered_data(&mut prefix, buffered.freeze());
                    prefix.push_back(Ok(frame));
                    return BufferedBody::Streaming(replay_body(prefix, Some(body)));
                }
            },
            Some(Err(error)) => {
                let mut prefix = VecDeque::new();
                push_buffered_data(&mut prefix, buffered.freeze());
                prefix.push_back(Err(error));
                return BufferedBody::Streaming(replay_body(prefix, None));
            }
            None => return BufferedBody::Complete(buffered.freeze()),
        }
    }
}

fn push_buffered_data(prefix: &mut VecDeque<io::Result<Frame<Bytes>>>, buffered: Bytes) {
    if !buffered.is_empty() {
        prefix.push_back(Ok(Frame::data(buffered)));
    }
}

fn replay_body(
    prefix: VecDeque<io::Result<Frame<Bytes>>>,
    inner: Option<ResponseBody>,
) -> ResponseBody {
    ResponseBody::boxed(ReplayBody {
        prefix,
        inner: inner.map(Box::pin),
    })
}

struct ReplayBody {
    prefix: VecDeque<io::Result<Frame<Bytes>>>,
    inner: Option<Pin<Box<ResponseBody>>>,
}

impl Body for ReplayBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Self::Data>>>> {
        let this = self.get_mut();
        if let Some(frame) = this.prefix.pop_front() {
            return Poll::Ready(Some(frame));
        }
        let Some(inner) = this.inner.as_mut() else {
            return Poll::Ready(None);
        };
        let result = inner.as_mut().poll_frame(context);
        if result.is_ready() && inner.as_ref().get_ref().is_end_stream() {
            this.inner.take();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.is_empty()
            && self
                .inner
                .as_ref()
                .is_none_or(|inner| inner.as_ref().get_ref().is_end_stream())
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::stream;
    use http_body_util::{Full, StreamBody};

    #[tokio::test]
    async fn buffers_a_complete_body_within_the_limit() {
        let body = ResponseBody::from_boxed(
            Full::new(Bytes::from_static(b"hello"))
                .map_err(|never| match never {})
                .boxed_unsync(),
        );

        match buffer_body_up_to(body, 5).await {
            BufferedBody::Complete(bytes) => assert_eq!(bytes, "hello"),
            BufferedBody::Streaming(_) => panic!("body should fit in the buffer"),
        }
    }

    #[tokio::test]
    async fn replays_the_prefix_and_trailers_after_crossing_the_limit() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-checksum", "done".parse().unwrap());
        let frames = stream::iter([
            Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"abc"))),
            Ok(Frame::data(Bytes::from_static(b"def"))),
            Ok(Frame::trailers(trailers)),
        ]);
        let body = ResponseBody::from_boxed(StreamBody::new(frames).boxed_unsync());
        let BufferedBody::Streaming(mut body) = buffer_body_up_to(body, 4).await else {
            panic!("body should cross the buffer limit");
        };

        let mut data = BytesMut::new();
        let mut received_trailers = None;
        while let Some(frame) = body.frame().await {
            let frame = frame.unwrap();
            match frame.into_data() {
                Ok(bytes) => data.extend_from_slice(&bytes),
                Err(frame) => received_trailers = frame.into_trailers().ok(),
            }
        }
        assert_eq!(data.freeze(), "abcdef");
        assert_eq!(received_trailers.unwrap()["x-checksum"], "done");
    }

    #[tokio::test]
    async fn replays_an_error_after_the_consumed_prefix() {
        let frames = stream::iter([
            Ok(Frame::data(Bytes::from_static(b"abc"))),
            Err(io::Error::other("upstream failed")),
        ]);
        let body = ResponseBody::from_boxed(StreamBody::new(frames).boxed_unsync());
        let BufferedBody::Streaming(mut body) = buffer_body_up_to(body, 8).await else {
            panic!("an incomplete body cannot be transformed");
        };

        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            "abc"
        );
        assert_eq!(
            body.frame().await.unwrap().unwrap_err().to_string(),
            "upstream failed"
        );
        assert!(body.frame().await.is_none());
    }
}
