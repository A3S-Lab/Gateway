//! Health checker — active HTTP health probes for backends

use super::LoadBalancer;
use std::sync::Arc;
use std::time::Duration;

/// Active health checker that periodically probes backends
pub struct HealthChecker {
    lb: Arc<LoadBalancer>,
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
    /// Create a new health checker
    pub fn new(
        lb: Arc<LoadBalancer>,
        path: String,
        interval: Duration,
        timeout: Duration,
        unhealthy_threshold: u32,
        healthy_threshold: u32,
    ) -> Self {
        Self {
            lb,
            path,
            interval,
            timeout,
            unhealthy_threshold,
            healthy_threshold,
        }
    }

    /// Run the health check loop (call from a spawned task)
    pub async fn run(&self) {
        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .unwrap_or_default();

        // Track consecutive successes/failures per backend
        let mut counters: Vec<(u32, u32)> = vec![(0, 0); self.lb.backends().len()];

        loop {
            for (i, backend) in self.lb.backends().iter().enumerate() {
                let url = format!("{}{}", backend.url.trim_end_matches('/'), self.path);
                let was_healthy = backend.is_healthy();

                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        counters[i].0 += 1; // successes
                        counters[i].1 = 0; // reset failures

                        if !was_healthy && counters[i].0 >= self.healthy_threshold {
                            backend.set_healthy(true);
                            tracing::info!(
                                service = self.lb.name,
                                backend = backend.url,
                                "Backend marked healthy"
                            );
                        }
                    }
                    _ => {
                        counters[i].1 += 1; // failures
                        counters[i].0 = 0; // reset successes

                        if was_healthy && counters[i].1 >= self.unhealthy_threshold {
                            backend.set_healthy(false);
                            tracing::warn!(
                                service = self.lb.name,
                                backend = backend.url,
                                "Backend marked unhealthy"
                            );
                        }
                    }
                }
            }

            tokio::time::sleep(self.interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LoadBalancerConfig, ServerConfig, ServiceConfig, Strategy};

    fn make_load_balancer() -> Arc<LoadBalancer> {
        let config = ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers: vec![ServerConfig {
                    url: "http://127.0.0.1:8080".to_string(),
                    weight: 1,
                }],
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
        assert_eq!(checker.path, "/health");
        assert_eq!(checker.interval, Duration::from_secs(10));
        assert_eq!(checker.timeout, Duration::from_secs(5));
        assert_eq!(checker.unhealthy_threshold, 3);
        assert_eq!(checker.healthy_threshold, 2);
    }
}
