use super::{GatewayMetrics, MetricsSnapshot};
use std::collections::HashMap;

impl GatewayMetrics {
    /// Render metrics in Prometheus text exposition format.
    pub fn render_prometheus(&self) -> String {
        let snapshot = self.snapshot();
        let mut output = String::new();

        output.push_str("# HELP gateway_requests_total Total number of requests\n");
        output.push_str("# TYPE gateway_requests_total counter\n");
        output.push_str(&format!(
            "gateway_requests_total {}\n",
            snapshot.total_requests
        ));

        output.push_str("# HELP gateway_responses_total Total responses by status class\n");
        output.push_str("# TYPE gateway_responses_total counter\n");
        for class in ["2xx", "3xx", "4xx", "5xx"] {
            let count = snapshot.status_classes.get(class).unwrap_or(&0);
            output.push_str(&format!(
                "gateway_responses_total{{status_class=\"{class}\"}} {count}\n"
            ));
        }

        output.push_str("# HELP gateway_response_bytes_total Total response bytes\n");
        output.push_str("# TYPE gateway_response_bytes_total counter\n");
        output.push_str(&format!(
            "gateway_response_bytes_total {}\n",
            snapshot.total_response_bytes
        ));

        output.push_str("# HELP gateway_active_connections Current active connections\n");
        output.push_str("# TYPE gateway_active_connections gauge\n");
        output.push_str(&format!(
            "gateway_active_connections {}\n",
            snapshot.active_connections
        ));

        render_map(
            &mut output,
            &snapshot,
            "gateway_router_requests_total",
            "Requests per router",
            "router",
            |snapshot| &snapshot.router_requests,
        );
        render_map(
            &mut output,
            &snapshot,
            "gateway_backend_requests_total",
            "Requests per backend",
            "backend_id",
            |snapshot| &snapshot.backend_requests,
        );
        render_map(
            &mut output,
            &snapshot,
            "gateway_service_requests_total",
            "Requests per service",
            "service",
            |snapshot| &snapshot.service_requests,
        );
        render_map(
            &mut output,
            &snapshot,
            "gateway_middleware_invocations_total",
            "Invocations per middleware",
            "middleware",
            |snapshot| &snapshot.middleware_invocations,
        );
        render_map(
            &mut output,
            &snapshot,
            "gateway_router_latency_microseconds_total",
            "Cumulative latency per router in microseconds",
            "router",
            |snapshot| &snapshot.router_latency_us,
        );
        render_map(
            &mut output,
            &snapshot,
            "gateway_router_errors_total",
            "Error responses (4xx+5xx) per router",
            "router",
            |snapshot| &snapshot.router_errors,
        );
        render_map(
            &mut output,
            &snapshot,
            "gateway_service_errors_total",
            "Error responses (4xx+5xx) per service",
            "service",
            |snapshot| &snapshot.service_errors,
        );

        self.telemetry.render_prometheus(&mut output);
        output
    }
}

fn render_map<'a>(
    output: &mut String,
    snapshot: &'a MetricsSnapshot,
    metric: &str,
    help: &str,
    label: &str,
    values: impl FnOnce(&'a MetricsSnapshot) -> &'a HashMap<String, u64>,
) {
    let values = values(snapshot);
    if values.is_empty() {
        return;
    }
    output.push_str(&format!("# HELP {metric} {help}\n"));
    output.push_str(&format!("# TYPE {metric} counter\n"));
    let mut values: Vec<_> = values.iter().collect();
    values.sort_unstable_by_key(|(value, _)| *value);
    for (value, count) in values {
        let value = escape_prometheus_label(value);
        output.push_str(&format!("{metric}{{{label}=\"{value}\"}} {count}\n"));
    }
}

pub(super) fn escape_prometheus_label(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            _ => escaped.push(character),
        }
    }
    escaped
}
