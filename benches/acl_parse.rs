use a3s_gateway::config::GatewayConfig;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

fn generate_acl(num_services: usize) -> String {
    let mut acl = String::new();
    acl.push_str("entrypoints \"web\" { address = \"0.0.0.0:80\" }\n\n");

    for i in 0..num_services {
        acl.push_str(&format!(
            r#"routers "router-{i}" {{
    rule    = "Host(`svc-{i}.example.com`) && PathPrefix(`/api/v{i}`)"
    service = "service-{i}"
    entrypoints = ["web"]
    middlewares = ["rate-limit"]
}}

services "service-{i}" {{
    load_balancer {{
        strategy        = "least-connections"
        request_timeout = "30s"
        servers = [
            {{ url = "http://10.0.{}.{}:8080" }},
            {{ url = "http://10.0.{}.{}:8080" }}
        ]
        health_check {{ path = "/health"; interval = "10s" }}
    }}
}}

"#,
            i / 256,
            i % 256,
            i / 256,
            (i + 1) % 256,
        ));
    }

    acl.push_str("middlewares \"rate-limit\" { type = \"rate-limit\"; rate = 100; burst = 20 }\n");
    acl
}

fn bench_acl_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("acl_parse");

    for num_services in [3, 30, 300] {
        let acl = generate_acl(num_services);

        group.bench_with_input(
            BenchmarkId::new("services", num_services),
            &acl,
            |b, acl| b.iter(|| black_box(GatewayConfig::from_acl(acl).unwrap())),
        );
    }

    group.finish();
}

criterion_group!(benches, bench_acl_parse);
criterion_main!(benches);
