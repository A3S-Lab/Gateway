//! Request buffer — holds requests during scale-from-zero

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Result of waiting in the request buffer
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BufferResult {
    /// A backend became ready
    Ready,
    /// Timed out waiting for a backend
    Timeout,
    /// Buffer is full, request rejected
    Overflow,
    /// Buffer has been shut down
    Shutdown,
}

/// Bounded async request buffer that holds requests while backends scale up
pub struct RequestBuffer {
    /// Service name (for logging)
    service: String,
    /// Maximum buffered requests
    capacity: usize,
    /// Timeout for buffered requests
    timeout: Duration,
    /// Current queue depth
    queue_depth: AtomicUsize,
    /// Whether a scale-up has been requested but not yet fulfilled
    scale_requested: AtomicBool,
    /// Notification that a backend is ready
    backend_ready: Arc<Notify>,
    /// Shutdown flag
    shutdown: AtomicBool,
}

impl RequestBuffer {
    /// Create a new request buffer
    pub fn new(service: impl Into<String>, capacity: usize, timeout_secs: u64) -> Self {
        Self {
            service: service.into(),
            capacity,
            timeout: Duration::from_secs(timeout_secs),
            queue_depth: AtomicUsize::new(0),
            scale_requested: AtomicBool::new(false),
            backend_ready: Arc::new(Notify::new()),
            shutdown: AtomicBool::new(false),
        }
    }

    /// Wait for a backend to become available.
    /// Returns `Ready` when signaled, `Timeout` on expiry, `Overflow` if buffer is full.
    pub async fn wait_for_backend(&self) -> BufferResult {
        if self.shutdown.load(Ordering::Relaxed) {
            return BufferResult::Shutdown;
        }

        // Check capacity before enqueueing
        let depth = self.queue_depth.fetch_add(1, Ordering::SeqCst);
        if depth >= self.capacity {
            self.queue_depth.fetch_sub(1, Ordering::SeqCst);
            return BufferResult::Overflow;
        }

        let notified = self.backend_ready.notified();
        let result = tokio::time::timeout(self.timeout, notified).await;

        self.queue_depth.fetch_sub(1, Ordering::SeqCst);

        if self.shutdown.load(Ordering::Relaxed) {
            return BufferResult::Shutdown;
        }

        match result {
            Ok(()) => BufferResult::Ready,
            Err(_) => BufferResult::Timeout,
        }
    }

    /// Signal all waiting requests that a backend is ready
    #[allow(dead_code)]
    pub fn signal_ready(&self) {
        self.scale_requested.store(false, Ordering::SeqCst);
        self.backend_ready.notify_waiters();
    }

    /// Check if a scale-up is needed. Returns true on the first call after
    /// construction or after `signal_ready()` resets the flag.
    pub fn needs_scale_up(&self) -> bool {
        self.scale_requested
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Current number of requests waiting in the buffer
    pub fn queue_depth(&self) -> usize {
        self.queue_depth.load(Ordering::SeqCst)
    }

    /// Service name
    #[allow(dead_code)]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Shut down the buffer, waking all waiters
    #[allow(dead_code)]
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.backend_ready.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ready_after_signal() {
        let buffer = Arc::new(RequestBuffer::new("svc", 10, 5));
        let buffer_clone = buffer.clone();

        let handle = tokio::spawn(async move { buffer_clone.wait_for_backend().await });

        // Small delay to let the waiter register
        tokio::time::sleep(Duration::from_millis(50)).await;
        buffer.signal_ready();

        let result = handle.await.unwrap();
        assert_eq!(result, BufferResult::Ready);
    }

    #[tokio::test]
    async fn test_timeout() {
        let buffer = RequestBuffer::new("svc", 10, 0);
        // timeout is 0 seconds, should time out immediately
        let result = buffer.wait_for_backend().await;
        assert_eq!(result, BufferResult::Timeout);
    }

    #[tokio::test]
    async fn test_overflow() {
        let buffer = RequestBuffer::new("svc", 1, 5);

        // Fill the buffer
        let buffer_arc = Arc::new(buffer);
        let b1 = buffer_arc.clone();
        let h1 = tokio::spawn(async move { b1.wait_for_backend().await });

        // Let it register
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Second request should overflow
        let result = buffer_arc.wait_for_backend().await;
        assert_eq!(result, BufferResult::Overflow);

        // Signal to release first waiter
        buffer_arc.signal_ready();
        let r1 = h1.await.unwrap();
        assert_eq!(r1, BufferResult::Ready);
    }

    #[tokio::test]
    async fn test_queue_depth_tracking() {
        let buffer = Arc::new(RequestBuffer::new("svc", 10, 5));
        assert_eq!(buffer.queue_depth(), 0);

        let b1 = buffer.clone();
        let h1 = tokio::spawn(async move { b1.wait_for_backend().await });

        let b2 = buffer.clone();
        let h2 = tokio::spawn(async move { b2.wait_for_backend().await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(buffer.queue_depth(), 2);

        buffer.signal_ready();
        let _ = h1.await;
        let _ = h2.await;
        assert_eq!(buffer.queue_depth(), 0);
    }

    #[tokio::test]
    async fn test_needs_scale_up_idempotent() {
        let buffer = RequestBuffer::new("svc", 10, 5);

        // First call returns true
        assert!(buffer.needs_scale_up());
        // Subsequent calls return false (scale already requested)
        assert!(!buffer.needs_scale_up());
        assert!(!buffer.needs_scale_up());

        // Reset via signal_ready
        buffer.signal_ready();
        assert!(buffer.needs_scale_up());
        assert!(!buffer.needs_scale_up());
    }

    #[tokio::test]
    async fn test_concurrent_waiters_all_notified() {
        let buffer = Arc::new(RequestBuffer::new("svc", 10, 5));
        let mut handles = Vec::new();

        for _ in 0..5 {
            let b = buffer.clone();
            handles.push(tokio::spawn(async move { b.wait_for_backend().await }));
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
        buffer.signal_ready();

        for h in handles {
            let result = h.await.unwrap();
            assert_eq!(result, BufferResult::Ready);
        }
    }

    #[test]
    fn test_service_name() {
        let buffer = RequestBuffer::new("my-service", 10, 5);
        assert_eq!(buffer.service(), "my-service");
    }

    #[tokio::test]
    async fn test_shutdown_wakes_waiters() {
        let buffer = Arc::new(RequestBuffer::new("svc", 10, 60));
        let b1 = buffer.clone();
        let h1 = tokio::spawn(async move { b1.wait_for_backend().await });

        tokio::time::sleep(Duration::from_millis(50)).await;
        buffer.shutdown();

        let result = h1.await.unwrap();
        assert_eq!(result, BufferResult::Shutdown);
    }

    #[tokio::test]
    async fn test_shutdown_immediate() {
        let buffer = RequestBuffer::new("svc", 10, 60);
        buffer.shutdown();
        let result = buffer.wait_for_backend().await;
        assert_eq!(result, BufferResult::Shutdown);
    }

    #[test]
    fn test_buffer_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RequestBuffer>();
    }

    #[tokio::test]
    async fn test_capacity_zero() {
        let buffer = RequestBuffer::new("svc", 0, 5);
        let result = buffer.wait_for_backend().await;
        assert_eq!(result, BufferResult::Overflow);
    }

    #[tokio::test]
    async fn test_depth_decremented_on_timeout() {
        let buffer = RequestBuffer::new("svc", 10, 0);
        let _ = buffer.wait_for_backend().await;
        assert_eq!(buffer.queue_depth(), 0);
    }
}
