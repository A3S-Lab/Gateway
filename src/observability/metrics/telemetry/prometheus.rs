use super::*;
use crate::observability::metrics::prometheus::escape_prometheus_label;

impl TelemetryTopology {
    pub(super) fn render_prometheus(&self, output: &mut String) {
        if self.services.is_empty() {
            return;
        }
        push_help_and_types(output);
        let observed_at = unix_millis();

        for (service, source) in &self.services {
            let service = escape_prometheus_label(service);
            output.push_str(&format!(
                "gateway_service_active_requests{{service=\"{service}\"}} {}\n",
                source.statistics.active_requests.load(Ordering::Relaxed)
            ));
            output.push_str(&format!(
                "gateway_service_queue_depth{{service=\"{service}\"}} {}\n",
                source
                    .queue
                    .as_ref()
                    .map(|queue| queue.queue_depth())
                    .unwrap_or(0)
            ));

            render_histogram(
                output,
                "gateway_service_request_duration_seconds",
                &service,
                &source.statistics.request_duration,
            );
            render_histogram(
                output,
                "gateway_service_ttft_seconds",
                &service,
                &source.statistics.ttft,
            );

            for (backend_id, backend) in &source.backends {
                let labels = format!("{{service=\"{service}\",backend_id=\"{backend_id}\"}}");
                output.push_str(&format!(
                    "gateway_backend_active_requests{labels} {}\n",
                    backend.connections()
                ));
                output.push_str(&format!(
                    "gateway_backend_healthy{labels} {}\n",
                    u8::from(backend.is_healthy())
                ));
            }

            render_observation(
                output,
                &service,
                "active_requests",
                observed_at,
                observed_at,
            );
            render_observation(output, &service, "queue_depth", observed_at, observed_at);
            render_observation(
                output,
                &service,
                "backend_pressure",
                observed_at,
                observed_at,
            );
            let latency_observed = source
                .statistics
                .request_duration
                .observed_at_unix_millis
                .load(Ordering::Acquire);
            if latency_observed != 0 {
                render_observation(
                    output,
                    &service,
                    "request_latency",
                    latency_observed,
                    observed_at,
                );
            }
            let ttft_observed = source
                .statistics
                .ttft
                .observed_at_unix_millis
                .load(Ordering::Acquire);
            if ttft_observed != 0 {
                render_observation(output, &service, "ttft", ttft_observed, observed_at);
            }
        }
    }
}

fn push_help_and_types(output: &mut String) {
    output.push_str(
        "# HELP gateway_service_active_requests Current accepted requests by configured service\n",
    );
    output.push_str("# TYPE gateway_service_active_requests gauge\n");
    output.push_str(
        "# HELP gateway_service_queue_depth Current cold-start queue depth by configured service\n",
    );
    output.push_str("# TYPE gateway_service_queue_depth gauge\n");
    output.push_str(
        "# HELP gateway_service_request_duration_seconds Gateway service operation duration\n",
    );
    output.push_str("# TYPE gateway_service_request_duration_seconds histogram\n");
    output.push_str(
        "# HELP gateway_service_ttft_seconds Time to the first non-empty streaming response chunk\n",
    );
    output.push_str("# TYPE gateway_service_ttft_seconds histogram\n");
    output.push_str(
        "# HELP gateway_backend_active_requests Current upstream operations by configured backend\n",
    );
    output.push_str("# TYPE gateway_backend_active_requests gauge\n");
    output.push_str("# HELP gateway_backend_healthy Current local backend health state\n");
    output.push_str("# TYPE gateway_backend_healthy gauge\n");
    output.push_str(
        "# HELP gateway_service_telemetry_observation_timestamp_seconds Unix time of the latest signal observation\n",
    );
    output.push_str("# TYPE gateway_service_telemetry_observation_timestamp_seconds gauge\n");
    output.push_str(
        "# HELP gateway_service_telemetry_age_seconds Age of the latest signal observation\n",
    );
    output.push_str("# TYPE gateway_service_telemetry_age_seconds gauge\n");
}

fn render_histogram(
    output: &mut String,
    metric: &str,
    service: &str,
    histogram: &DurationHistogram,
) {
    for ((_, label), count) in HISTOGRAM_BUCKETS.iter().zip(histogram.buckets.iter()) {
        output.push_str(&format!(
            "{metric}_bucket{{service=\"{service}\",le=\"{label}\"}} {}\n",
            count.load(Ordering::Relaxed)
        ));
    }
    output.push_str(&format!(
        "{metric}_bucket{{service=\"{service}\",le=\"+Inf\"}} {}\n",
        histogram.count.load(Ordering::Relaxed)
    ));
    output.push_str(&format!(
        "{metric}_sum{{service=\"{service}\"}} {}\n",
        seconds_from_microseconds(histogram.sum_microseconds.load(Ordering::Relaxed))
    ));
    output.push_str(&format!(
        "{metric}_count{{service=\"{service}\"}} {}\n",
        histogram.count.load(Ordering::Relaxed)
    ));
}

fn render_observation(
    output: &mut String,
    service: &str,
    signal: &str,
    signal_unix_millis: u64,
    now_unix_millis: u64,
) {
    let labels = format!("{{service=\"{service}\",signal=\"{signal}\"}}");
    output.push_str(&format!(
        "gateway_service_telemetry_observation_timestamp_seconds{labels} {}\n",
        seconds_from_milliseconds(signal_unix_millis)
    ));
    output.push_str(&format!(
        "gateway_service_telemetry_age_seconds{labels} {}\n",
        seconds_from_milliseconds(now_unix_millis.saturating_sub(signal_unix_millis))
    ));
}

fn seconds_from_microseconds(value: u64) -> String {
    format!("{}.{:06}", value / 1_000_000, value % 1_000_000)
}

fn seconds_from_milliseconds(value: u64) -> String {
    format!("{}.{:03}", value / 1_000, value % 1_000)
}
