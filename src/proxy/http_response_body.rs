//! Bounded ordinary HTTP response-body relay.

use crate::error::Result;
use crate::proxy::http_proxy::filter_hop_by_hop_headers;
use crate::proxy::streaming::checked_deadline;
use crate::service::BackendConnectionGuard;
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use pin_project_lite::pin_project;
use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::Instant;

pin_project! {
    /// Ordinary upstream response body relayed without a per-response trait-object allocation.
    pub struct ProxyResponseBody {
        #[pin]
        inner: BoundedHttpBody<Incoming>,
    }
}

impl ProxyResponseBody {
    pub(crate) fn new(
        body: Incoming,
        connection: Option<BackendConnectionGuard>,
        operation_started_at: Instant,
        idle_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self> {
        Ok(Self {
            inner: BoundedHttpBody::new(
                body,
                connection,
                operation_started_at,
                idle_timeout,
                total_timeout,
            )?,
        })
    }
}

impl Body for ProxyResponseBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<io::Result<Frame<Self::Data>>>> {
        self.project().inner.poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

pin_project! {
    struct BoundedHttpBody<B> {
        #[pin]
        inner: B,
        connection: Option<BackendConnectionGuard>,
        idle_timeout: Duration,
        total_timeout: Duration,
        total_deadline: Instant,
        deadline: Instant,
        deadline_kind: DeadlineKind,
        deadline_sleep: Option<Pin<Box<tokio::time::Sleep>>>,
        finished: bool,
    }
}

#[derive(Clone, Copy)]
enum DeadlineKind {
    Idle,
    Total,
}

impl DeadlineKind {
    fn label(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Total => "total",
        }
    }
}

impl<B> BoundedHttpBody<B> {
    fn new(
        inner: B,
        connection: Option<BackendConnectionGuard>,
        operation_started_at: Instant,
        idle_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self> {
        let idle_deadline = checked_deadline(Instant::now(), idle_timeout, "stream_idle_timeout")?;
        let total_deadline =
            checked_deadline(operation_started_at, total_timeout, "stream_total_timeout")?;
        let (deadline, deadline_kind) = next_deadline(idle_deadline, total_deadline);
        Ok(Self {
            inner,
            connection,
            idle_timeout,
            total_timeout,
            total_deadline,
            deadline,
            deadline_kind,
            deadline_sleep: None,
            finished: false,
        })
    }
}

fn next_deadline(idle: Instant, total: Instant) -> (Instant, DeadlineKind) {
    if total <= idle {
        (total, DeadlineKind::Total)
    } else {
        (idle, DeadlineKind::Idle)
    }
}

fn timeout_error(kind: &str, timeout: Duration) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!(
            "upstream HTTP response {kind} timeout after {}ms",
            timeout.as_millis()
        ),
    )
}

fn refreshed_deadline(
    total_deadline: Instant,
    idle_timeout: Duration,
) -> io::Result<(Instant, DeadlineKind)> {
    let idle_deadline = Instant::now().checked_add(idle_timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "stream_idle_timeout exceeds the platform timer range",
        )
    })?;
    Ok(next_deadline(idle_deadline, total_deadline))
}

impl<B> Body for BoundedHttpBody<B>
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Error + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        if *this.finished {
            return Poll::Ready(None);
        }
        // Keep the operation-wide total deadline hard without polling the
        // Tokio timer first. Polling a Sleep registers it with the timer
        // driver; most small HTTP responses already have their only frame
        // ready on this first body poll and never need that registration.
        if matches!(*this.deadline_kind, DeadlineKind::Total)
            && Instant::now() >= *this.total_deadline
        {
            *this.finished = true;
            this.connection.take();
            return Poll::Ready(Some(Err(timeout_error("total", *this.total_timeout))));
        }
        // A buffered upstream frame wins a simultaneous idle deadline, while
        // the operation-wide total deadline remains a hard upper bound.
        match this.inner.as_mut().poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                // A body that reports end-of-stream after yielding this frame
                // cannot produce trailers or another data frame. Release its
                // accounting guard immediately and avoid resetting a timer that
                // will never be polled. Small one-frame HTTP responses take this
                // path, which keeps stream timeout enforcement off their tail.
                if this.inner.is_end_stream() {
                    *this.finished = true;
                    this.connection.take();
                    return Poll::Ready(Some(Ok(sanitize_http_frame(frame))));
                }
                let (deadline, kind) =
                    match refreshed_deadline(*this.total_deadline, *this.idle_timeout) {
                        Ok(next) => next,
                        Err(error) => {
                            *this.finished = true;
                            this.connection.take();
                            return Poll::Ready(Some(Err(error)));
                        }
                    };
                *this.deadline = deadline;
                *this.deadline_kind = kind;
                if let Some(sleep) = this.deadline_sleep.as_mut() {
                    sleep.as_mut().reset(deadline);
                }
                Poll::Ready(Some(Ok(sanitize_http_frame(frame))))
            }
            Poll::Ready(Some(Err(error))) => {
                *this.finished = true;
                this.connection.take();
                Poll::Ready(Some(Err(io::Error::other(error))))
            }
            Poll::Ready(None) => {
                *this.finished = true;
                this.connection.take();
                Poll::Ready(None)
            }
            Poll::Pending => {
                // Only responses that actually suspend allocate timer state.
                // Keeping Sleep behind a pinned pointer also keeps the common
                // inline ResponseBody variant compact.
                let deadline = *this.deadline;
                let deadline_sleep = this
                    .deadline_sleep
                    .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
                let deadline_elapsed = deadline_sleep.as_mut().poll(context).is_ready();
                if deadline_elapsed {
                    *this.finished = true;
                    this.connection.take();
                    let timeout = match *this.deadline_kind {
                        DeadlineKind::Idle => *this.idle_timeout,
                        DeadlineKind::Total => *this.total_timeout,
                    };
                    Poll::Ready(Some(Err(timeout_error(
                        (*this.deadline_kind).label(),
                        timeout,
                    ))))
                } else {
                    Poll::Pending
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn sanitize_http_frame(frame: Frame<Bytes>) -> Frame<Bytes> {
    match frame.into_trailers() {
        Ok(trailers) => Frame::trailers(filter_hop_by_hop_headers(trailers)),
        Err(frame) => frame,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::Backend;
    use futures_util::stream;
    use http_body_util::{BodyExt, Full, StreamBody};
    use std::sync::Arc;

    #[tokio::test]
    async fn final_frame_releases_connection_without_an_extra_poll() {
        let backend = Arc::new(Backend::new("http://backend".to_string(), 1));
        let connection = backend.track_connection();
        let body = BoundedHttpBody::new(
            Full::new(Bytes::from_static(b"complete")),
            Some(connection),
            Instant::now(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        tokio::pin!(body);

        assert!(body.as_ref().get_ref().deadline_sleep.is_none());
        assert_eq!(backend.connections(), 1);
        assert_eq!(
            body.as_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            Bytes::from_static(b"complete")
        );
        assert!(body.as_ref().get_ref().deadline_sleep.is_none());
        assert_eq!(backend.connections(), 0);
        assert!(body.as_mut().frame().await.is_none());
    }

    #[tokio::test]
    async fn relays_data_and_filters_response_trailers() {
        let backend = Arc::new(Backend::new("http://backend".to_string(), 1));
        let connection = backend.track_connection();
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-end-to-end", "kept".parse().unwrap());
        trailers.insert(http::header::CONNECTION, "x-hop".parse().unwrap());
        trailers.insert("x-hop", "removed".parse().unwrap());
        let frames = stream::iter([
            Ok::<_, io::Error>(Frame::data(Bytes::from_static(b"chunk"))),
            Ok(Frame::trailers(trailers)),
        ]);
        let body = BoundedHttpBody::new(
            StreamBody::new(frames),
            Some(connection),
            Instant::now(),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .unwrap();
        tokio::pin!(body);

        assert_eq!(backend.connections(), 1);
        assert_eq!(
            body.as_mut()
                .frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap(),
            Bytes::from_static(b"chunk")
        );
        let trailers = body
            .as_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_trailers()
            .unwrap();
        assert_eq!(trailers["x-end-to-end"], "kept");
        assert!(!trailers.contains_key("x-hop"));
        assert!(body.as_mut().frame().await.is_none());
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn idle_timeout_releases_the_backend_connection() {
        let backend = Arc::new(Backend::new("http://backend".to_string(), 1));
        let connection = backend.track_connection();
        let pending = stream::pending::<std::result::Result<Frame<Bytes>, io::Error>>();
        let body = BoundedHttpBody::new(
            StreamBody::new(pending),
            Some(connection),
            Instant::now(),
            Duration::from_millis(10),
            Duration::from_secs(1),
        )
        .unwrap();
        tokio::pin!(body);

        let error = body.as_mut().frame().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("idle"));
        assert!(body.as_ref().get_ref().deadline_sleep.is_some());
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn total_timeout_wins_over_a_longer_idle_timeout() {
        let backend = Arc::new(Backend::new("http://backend".to_string(), 1));
        let connection = backend.track_connection();
        let pending = stream::pending::<std::result::Result<Frame<Bytes>, io::Error>>();
        let body = BoundedHttpBody::new(
            StreamBody::new(pending),
            Some(connection),
            Instant::now(),
            Duration::from_secs(1),
            Duration::from_millis(10),
        )
        .unwrap();
        tokio::pin!(body);

        let error = body.as_mut().frame().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("total"));
        assert_eq!(backend.connections(), 0);
    }

    #[tokio::test]
    async fn expired_total_timeout_wins_over_a_ready_frame() {
        let backend = Arc::new(Backend::new("http://backend".to_string(), 1));
        let connection = backend.track_connection();
        let body = BoundedHttpBody::new(
            Full::new(Bytes::from_static(b"late")),
            Some(connection),
            Instant::now() - Duration::from_millis(20),
            Duration::from_secs(1),
            Duration::from_millis(10),
        )
        .unwrap();
        tokio::pin!(body);

        let error = body.as_mut().frame().await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("total"));
        assert_eq!(backend.connections(), 0);
    }
}
