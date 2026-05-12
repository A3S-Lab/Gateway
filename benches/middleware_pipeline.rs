use a3s_gateway::config::MiddlewareConfig;
use a3s_gateway::middleware::{Pipeline, RequestContext};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use http::Request;
use std::collections::HashMap;

fn make_middleware_configs(n: usize) -> HashMap<String, MiddlewareConfig> {
    let mut configs = HashMap::new();
    for i in 0..n {
        let config = match i % 5 {
            0 => MiddlewareConfig {
                middleware_type: "headers".to_string(),
                request_headers: [("X-Request-Id".to_string(), "bench".to_string())]
                    .into_iter()
                    .collect(),
                ..Default::default()
            },
            1 => MiddlewareConfig {
                middleware_type: "strip-prefix".to_string(),
                prefixes: vec![format!("/prefix-{i}")],
                ..Default::default()
            },
            2 => MiddlewareConfig {
                middleware_type: "cors".to_string(),
                allowed_origins: vec!["https://example.com".to_string()],
                allowed_methods: vec!["GET".to_string(), "POST".to_string()],
                ..Default::default()
            },
            3 => MiddlewareConfig {
                middleware_type: "rate-limit".to_string(),
                rate: Some(100_000),
                burst: Some(100_000),
                ..Default::default()
            },
            _ => MiddlewareConfig {
                middleware_type: "ip-allow".to_string(),
                allowed_ips: vec!["0.0.0.0/0".to_string()],
                ..Default::default()
            },
        };
        configs.insert(format!("mw-{i}"), config);
    }
    configs
}

fn bench_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("middleware_pipeline");

    for chain_len in [0, 3, 5, 10] {
        let configs = make_middleware_configs(chain_len);
        let mw_names: Vec<String> = (0..chain_len).map(|i| format!("mw-{i}")).collect();
        let pipeline = Pipeline::from_config(&mw_names, &configs).unwrap();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "bench".to_string(),
        };

        group.bench_with_input(
            BenchmarkId::new("process_request", chain_len),
            &chain_len,
            |b, _| {
                b.to_async(&rt).iter(|| async {
                    let (mut parts, _) = Request::builder()
                        .uri("http://example.com/prefix-1/api/users")
                        .header("Origin", "https://example.com")
                        .body(())
                        .unwrap()
                        .into_parts();
                    black_box(pipeline.process_request(&mut parts, &ctx).await.unwrap());
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
