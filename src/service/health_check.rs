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

impl HealthChecker {
    /// Create a new health checker
    pub fn new(
        lb: Arc<LoadBalancer>,
        path: String,
        interval: &str,
        timeout: &str,
        unhealthy_threshold: u32,
        healthy_threshold: u32,
    ) -> Self {
        Self {
            lb,
            path,
            interval: parse_duration(interval),
            timeout: parse_duration(timeout),
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

/// Parse a duration string like "10s", "500ms", "1m"
fn parse_duration(s: &str) -> Duration {
    let s = s.trim();
    if let Some(secs) = s.strip_suffix("ms") {
        Duration::from_millis(secs.parse().unwrap_or(1000))
    } else if let Some(secs) = s.strip_suffix('s') {
        Duration::from_secs(secs.parse().unwrap_or(10))
    } else if let Some(mins) = s.strip_suffix('m') {
        Duration::from_secs(mins.parse::<u64>().unwrap_or(1) * 60)
    } else {
        Duration::from_secs(s.parse().unwrap_or(10))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("10s"), Duration::from_secs(10));
        assert_eq!(parse_duration("5s"), Duration::from_secs(5));
        assert_eq!(parse_duration("0s"), Duration::from_secs(0));
    }

    #[test]
    fn test_parse_duration_milliseconds() {
        assert_eq!(parse_duration("500ms"), Duration::from_millis(500));
        assert_eq!(parse_duration("100ms"), Duration::from_millis(100));
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("1m"), Duration::from_secs(60));
        assert_eq!(parse_duration("5m"), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_duration_plain_number() {
        assert_eq!(parse_duration("30"), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_invalid() {
        // Falls back to default 10s
        assert_eq!(parse_duration("abc"), Duration::from_secs(10));
    }

    #[test]
    fn test_parse_duration_whitespace() {
        assert_eq!(parse_duration("  10s  "), Duration::from_secs(10));
    }
}
