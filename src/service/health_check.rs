//! Health checker — active HTTP health probes for backends

use super::LoadBalancer;
use crate::error::{GatewayError, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Default, PartialEq, Eq)]
struct ProbeCounters {
    consecutive_successes: u32,
    consecutive_failures: u32,
}

impl ProbeCounters {
    fn record(
        &mut self,
        currently_healthy: bool,
        succeeded: bool,
        unhealthy_threshold: u32,
        healthy_threshold: u32,
    ) -> Option<bool> {
        match (currently_healthy, succeeded) {
            (true, true) | (false, false) => {
                *self = Self::default();
                None
            }
            (false, true) => {
                self.consecutive_failures = 0;
                self.consecutive_successes = self
                    .consecutive_successes
                    .saturating_add(1)
                    .min(healthy_threshold);
                (self.consecutive_successes >= healthy_threshold).then_some(true)
            }
            (true, false) => {
                self.consecutive_successes = 0;
                self.consecutive_failures = self
                    .consecutive_failures
                    .saturating_add(1)
                    .min(unhealthy_threshold);
                (self.consecutive_failures >= unhealthy_threshold).then_some(false)
            }
        }
    }
}

/// Active health checker that periodically probes backends
pub struct HealthChecker {
    lb: Arc<LoadBalancer>,
    client: reqwest::Result<reqwest::Client>,
    path: String,
    interval: Duration,
    timeout: Duration,
    unhealthy_threshold: u32,
    healthy_threshold: u32,
}

/// Health checkers prepared during runtime construction but not yet started.
///
/// Keeping task creation separate from construction prevents rejected startup
/// and reload candidates from probing backends before the runtime commits.
pub(crate) struct PreparedHealthChecks {
    checkers: Vec<(String, HealthChecker)>,
}

impl PreparedHealthChecks {
    pub(crate) fn new(checkers: Vec<(String, HealthChecker)>) -> Self {
        Self { checkers }
    }

    pub(crate) fn start(self) -> HealthCheckTasks {
        let handles = self
            .checkers
            .into_iter()
            .map(|(service, checker)| {
                tracing::info!(service, "Started health checker");
                tokio::spawn(async move {
                    checker.run().await;
                })
            })
            .collect();
        HealthCheckTasks { handles }
    }
}

/// Owned health-check task set for one committed runtime snapshot.
#[derive(Default)]
pub(crate) struct HealthCheckTasks {
    handles: Vec<tokio::task::JoinHandle<()>>,
}

impl HealthCheckTasks {
    pub(crate) async fn shutdown(mut self) {
        for handle in &self.handles {
            handle.abort();
        }
        for handle in self.handles.drain(..) {
            let _ = handle.await;
        }
    }
}

impl Drop for HealthCheckTasks {
    fn drop(&mut self) {
        for handle in &self.handles {
            handle.abort();
        }
    }
}

impl HealthChecker {
    /// Create a new health checker while preserving the existing infallible API.
    ///
    /// Use [`Self::try_new`] when client initialization must fail synchronously.
    /// If initialization fails here, [`Self::run`] reports the error and returns
    /// without probing instead of substituting a client with different settings.
    pub fn new(
        lb: Arc<LoadBalancer>,
        path: String,
        interval: Duration,
        timeout: Duration,
        unhealthy_threshold: u32,
        healthy_threshold: u32,
    ) -> Self {
        Self::new_with_builder(
            lb,
            path,
            interval,
            timeout,
            unhealthy_threshold,
            healthy_threshold,
            reqwest::Client::builder(),
        )
    }

    /// Create a health checker and fail if its configured HTTP client cannot be built.
    pub fn try_new(
        lb: Arc<LoadBalancer>,
        path: String,
        interval: Duration,
        timeout: Duration,
        unhealthy_threshold: u32,
        healthy_threshold: u32,
    ) -> Result<Self> {
        Self::new(
            lb,
            path,
            interval,
            timeout,
            unhealthy_threshold,
            healthy_threshold,
        )
        .ensure_ready()
    }

    fn new_with_builder(
        lb: Arc<LoadBalancer>,
        path: String,
        interval: Duration,
        timeout: Duration,
        unhealthy_threshold: u32,
        healthy_threshold: u32,
        builder: reqwest::ClientBuilder,
    ) -> Self {
        let client = builder.timeout(timeout).build();
        Self {
            lb,
            client,
            path,
            interval,
            timeout,
            unhealthy_threshold,
            healthy_threshold,
        }
    }

    fn ensure_ready(self) -> Result<Self> {
        if let Err(error) = &self.client {
            return Err(GatewayError::Other(format!(
                "Failed to initialize active health-check HTTP client: {}",
                error_chain(error)
            )));
        }
        Ok(self)
    }

    /// Run the health check loop (call from a spawned task)
    pub async fn run(&self) {
        let client = match &self.client {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(
                    service = self.lb.name,
                    timeout_ms = self.timeout.as_millis(),
                    error = ?error,
                    "Active health-check HTTP client is unavailable"
                );
                return;
            }
        };

        let mut counters: Vec<ProbeCounters> = (0..self.lb.backends().len())
            .map(|_| ProbeCounters::default())
            .collect();

        loop {
            let mut probes = FuturesUnordered::new();
            for (i, backend) in self.lb.backends().iter().enumerate() {
                let url = format!("{}{}", backend.url.trim_end_matches('/'), self.path);
                let backend = backend.clone();
                let request = client.get(url).send();
                probes.push(async move {
                    let succeeded = matches!(
                        request.await,
                        Ok(response) if response.status().is_success()
                    );
                    (i, backend, succeeded)
                });
            }

            while let Some((i, backend, succeeded)) = probes.next().await {
                let was_healthy = backend.is_healthy();
                let Some(is_healthy) = counters[i].record(
                    was_healthy,
                    succeeded,
                    self.unhealthy_threshold,
                    self.healthy_threshold,
                ) else {
                    continue;
                };

                backend.set_healthy(is_healthy);
                if is_healthy {
                    tracing::info!(
                        service = self.lb.name,
                        backend = backend.url,
                        "Backend marked healthy"
                    );
                } else {
                    tracing::warn!(
                        service = self.lb.name,
                        backend = backend.url,
                        "Backend marked unhealthy"
                    );
                }
            }

            tokio::time::sleep(self.interval).await;
        }
    }
}

fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LoadBalancerConfig, ServerConfig, ServiceConfig, Strategy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn make_load_balancer_with_urls(urls: &[String]) -> Arc<LoadBalancer> {
        let config = ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers: urls
                    .iter()
                    .map(|url| ServerConfig {
                        url: url.clone(),
                        weight: 1,
                    })
                    .collect(),
                health_check: None,
                sticky: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        };
        let lb = LoadBalancer::new(
            "test".to_string(),
            Strategy::RoundRobin,
            &config.load_balancer.servers,
            None,
        );
        Arc::new(lb)
    }

    fn make_load_balancer() -> Arc<LoadBalancer> {
        make_load_balancer_with_urls(&["http://127.0.0.1:8080".to_string()])
    }

    async fn spawn_hanging_backend() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            std::future::pending::<()>().await;
        });
        (format!("http://{address}"), task)
    }

    async fn spawn_healthy_backend() -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
        });
        (format!("http://{address}"), task)
    }

    #[test]
    fn test_health_checker_new() {
        let lb = make_load_balancer();
        let checker = HealthChecker::new(
            lb,
            "/health".to_string(),
            Duration::from_secs(10),
            Duration::from_secs(5),
            3,
            2,
        );
        assert!(checker.client.is_ok());
        assert_eq!(checker.path, "/health");
        assert_eq!(checker.interval, Duration::from_secs(10));
        assert_eq!(checker.timeout, Duration::from_secs(5));
        assert_eq!(checker.unhealthy_threshold, 3);
        assert_eq!(checker.healthy_threshold, 2);
    }

    #[test]
    fn health_checker_try_new_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<HealthChecker>();

        let checker = HealthChecker::try_new(
            make_load_balancer(),
            "/health".to_string(),
            Duration::from_secs(10),
            Duration::from_secs(5),
            3,
            2,
        )
        .unwrap();
        assert!(checker.client.is_ok());
    }

    #[test]
    fn client_initialization_failure_is_explicit() {
        let checker = HealthChecker::new_with_builder(
            make_load_balancer(),
            "/health".to_string(),
            Duration::from_secs(10),
            Duration::from_secs(5),
            3,
            2,
            reqwest::Client::builder().use_preconfigured_tls(()),
        );

        let error = match checker.ensure_ready() {
            Ok(_) => panic!("an invalid HTTP client was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("Failed to initialize active health-check HTTP client"));
        assert!(error.contains("Unknown TLS backend"));
    }

    #[tokio::test]
    async fn client_initialization_failure_returns_without_probing() {
        let (backend_url, backend_task) = spawn_healthy_backend().await;
        let checker = HealthChecker::new_with_builder(
            make_load_balancer_with_urls(&[backend_url]),
            "/health".to_string(),
            Duration::from_secs(10),
            Duration::from_secs(5),
            3,
            2,
            reqwest::Client::builder().use_preconfigured_tls(()),
        );

        let run_returned = tokio::time::timeout(Duration::from_millis(100), checker.run()).await;
        tokio::time::sleep(Duration::from_millis(25)).await;
        let backend_was_probed = backend_task.is_finished();

        backend_task.abort();
        let _ = backend_task.await;

        assert!(
            run_returned.is_ok(),
            "a checker with no HTTP client remained active"
        );
        assert!(
            !backend_was_probed,
            "a checker with no HTTP client silently used a fallback client"
        );
    }

    #[test]
    fn probe_counters_track_only_pending_transitions() {
        let mut counters = ProbeCounters::default();

        assert_eq!(counters.record(true, false, 2, 2), None);
        assert_eq!(counters.consecutive_failures, 1);
        assert_eq!(counters.record(true, true, 2, 2), None);
        assert_eq!(counters, ProbeCounters::default());

        assert_eq!(counters.record(false, true, 2, 2), None);
        assert_eq!(counters.consecutive_successes, 1);
        assert_eq!(counters.record(false, false, 2, 2), None);
        assert_eq!(counters, ProbeCounters::default());
    }

    #[test]
    fn probe_counters_saturate_at_transition_thresholds() {
        let mut counters = ProbeCounters {
            consecutive_successes: u32::MAX,
            consecutive_failures: 0,
        };
        assert_eq!(counters.record(false, true, u32::MAX, u32::MAX), Some(true));
        assert_eq!(counters.consecutive_successes, u32::MAX);

        counters = ProbeCounters {
            consecutive_successes: 0,
            consecutive_failures: u32::MAX,
        };
        assert_eq!(
            counters.record(true, false, u32::MAX, u32::MAX),
            Some(false)
        );
        assert_eq!(counters.consecutive_failures, u32::MAX);
    }

    #[tokio::test]
    async fn slow_backend_does_not_delay_another_probe_result() {
        let (slow_url, slow_backend_task) = spawn_hanging_backend().await;
        let (healthy_url, healthy_backend_task) = spawn_healthy_backend().await;
        let lb = make_load_balancer_with_urls(&[slow_url, healthy_url]);
        lb.backends()[1].set_healthy(false);

        let checker = HealthChecker::new(
            lb.clone(),
            "/health".to_string(),
            Duration::from_secs(60),
            Duration::from_secs(5),
            1,
            1,
        );
        let checker_task = tokio::spawn(async move { checker.run().await });

        let recovered = tokio::time::timeout(Duration::from_millis(500), async {
            while !lb.backends()[1].is_healthy() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;

        checker_task.abort();
        let _ = checker_task.await;
        slow_backend_task.abort();
        healthy_backend_task.abort();
        let _ = slow_backend_task.await;
        let _ = healthy_backend_task.await;

        assert!(
            recovered.is_ok(),
            "a hanging first backend blocked a later healthy probe"
        );
    }
}
