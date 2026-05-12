use a3s_gateway::config::RouterConfig;
use a3s_gateway::router::RouterTable;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use http::HeaderMap;
use std::collections::HashMap;

fn build_router_table(n: usize) -> RouterTable {
    let mut routers = HashMap::new();
    for i in 0..n {
        routers.insert(
            format!("router-{i}"),
            RouterConfig {
                rule: format!("Host(`svc-{i}.example.com`) && PathPrefix(`/api/v{i}`)"),
                service: format!("service-{i}"),
                entrypoints: vec!["web".to_string()],
                middlewares: vec![],
                priority: i as i32,
            },
        );
    }
    RouterTable::from_config(&routers).unwrap()
}

fn bench_match_request(c: &mut Criterion) {
    let mut group = c.benchmark_group("router_match");

    for size in [10, 100, 1000] {
        let table = build_router_table(size);
        let headers = HeaderMap::new();

        group.bench_with_input(BenchmarkId::new("first_route", size), &size, |b, _| {
            b.iter(|| {
                black_box(table.match_request(
                    Some("svc-0.example.com"),
                    "/api/v0/users",
                    "GET",
                    &headers,
                    "web",
                ))
            })
        });

        group.bench_with_input(BenchmarkId::new("last_route", size), &size, |b, _| {
            b.iter(|| {
                black_box(table.match_request(
                    Some(&format!("svc-{}.example.com", size - 1)),
                    &format!("/api/v{}/users", size - 1),
                    "GET",
                    &headers,
                    "web",
                ))
            })
        });

        group.bench_with_input(BenchmarkId::new("no_match", size), &size, |b, _| {
            b.iter(|| {
                black_box(table.match_request(
                    Some("unknown.example.com"),
                    "/not/found",
                    "GET",
                    &headers,
                    "web",
                ))
            })
        });
    }

    group.finish();
}

criterion_group!(benches, bench_match_request);
criterion_main!(benches);
