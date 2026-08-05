//! Unified downstream response body with allocation-free common variants.

use crate::proxy::http_proxy::ProxyResponseBody;
use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Frame, SizeHint};
use pin_project_lite::pin_project;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    #[project = ResponseBodyProj]
    pub(crate) enum ResponseBody {
        /// Ordinary HTTP proxy response: the dominant data-plane path.
        Proxy {
            #[pin]
            body: ProxyResponseBody,
        },
        /// Native and immediate byte responses.
        Full {
            #[pin]
            body: Full<Bytes>,
        },
        /// Less common streaming, replay, and instrumented bodies.
        Boxed {
            #[pin]
            body: UnsyncBoxBody<Bytes, io::Error>,
        },
    }
}

impl ResponseBody {
    pub(crate) fn proxy(body: ProxyResponseBody) -> Self {
        Self::Proxy { body }
    }

    pub(crate) fn full(bytes: impl Into<Bytes>) -> Self {
        Self::Full {
            body: Full::new(bytes.into()),
        }
    }

    pub(crate) fn boxed<B>(body: B) -> Self
    where
        B: Body<Data = Bytes, Error = io::Error> + Send + 'static,
    {
        Self::from_boxed(body.boxed_unsync())
    }

    pub(crate) fn from_boxed(body: UnsyncBoxBody<Bytes, io::Error>) -> Self {
        Self::Boxed { body }
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Self::Data>>>> {
        match self.project() {
            ResponseBodyProj::Proxy { body } => body.poll_frame(context),
            ResponseBodyProj::Full { body } => match body.poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(never))) => match never {},
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            },
            ResponseBodyProj::Boxed { body } => body.poll_frame(context),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Proxy { body } => body.is_end_stream(),
            Self::Full { body } => body.is_end_stream(),
            Self::Boxed { body } => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Proxy { body } => body.size_hint(),
            Self::Full { body } => body.size_hint(),
            Self::Boxed { body } => body.size_hint(),
        }
    }
}
