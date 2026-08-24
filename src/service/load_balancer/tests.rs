use super::*;
use crate::config::ManagedTargetConfig;

fn make_servers(urls: Vec<&str>) -> Vec<ServerConfig> {
    urls.into_iter()
        .map(|url| ServerConfig {
            url: url.to_string(),
            weight: 1,
            target: None,
        })
        .collect()
}

fn make_weighted_servers() -> Vec<ServerConfig> {
    vec![
        ServerConfig {
            url: "http://a:8001".to_string(),
            weight: 3,
            target: None,
        },
        ServerConfig {
            url: "http://b:8002".to_string(),
            weight: 1,
            target: None,
        },
    ]
}

fn managed_server(
    url: &str,
    target_id: uuid::Uuid,
    unit_id: &str,
    generation: u64,
) -> ServerConfig {
    ServerConfig {
        url: url.to_string(),
        weight: 1,
        target: Some(ManagedTargetConfig {
            target_id,
            unit_id: unit_id.to_string(),
            generation,
        }),
    }
}

#[test]
fn managed_target_metric_identity_is_generation_bound_and_order_independent() {
    let first_target = uuid::Uuid::new_v4();
    let second_target = uuid::Uuid::new_v4();
    let first = managed_server("http://127.0.0.1:8001", first_target, "workload:first", 3);
    let second = managed_server("http://127.0.0.1:8002", second_target, "workload:second", 5);
    let ordered = LoadBalancer::new(
        "route-a".into(),
        Strategy::RoundRobin,
        &[first.clone(), second.clone()],
        None,
    );
    let reversed = LoadBalancer::new(
        "route-b".into(),
        Strategy::RoundRobin,
        &[second.clone(), first.clone()],
        None,
    );

    let ordered_first = ordered
        .backends()
        .iter()
        .find(|backend| backend.managed_target() == first.target.as_ref())
        .cloned()
        .unwrap();
    let reversed_first = reversed
        .backends()
        .iter()
        .find(|backend| backend.managed_target() == first.target.as_ref())
        .cloned()
        .unwrap();
    assert_eq!(ordered_first.metric_id(), reversed_first.metric_id());

    let next_generation = LoadBalancer::new(
        "route-a".into(),
        Strategy::RoundRobin,
        &[managed_server(
            "http://127.0.0.1:8001",
            first_target,
            "workload:first",
            4,
        )],
        None,
    );
    assert_ne!(
        ordered_first.metric_id(),
        next_generation.backends()[0].metric_id()
    );
    assert!(!ordered_first.metric_id().contains("workload"));
    assert!(!ordered_first
        .metric_id()
        .contains(&first_target.to_string()));
}

#[test]
fn test_round_robin_single() {
    let servers = make_servers(vec!["http://127.0.0.1:8001"]);
    let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

    let b = lb.next_backend().unwrap();
    assert_eq!(b.url, "http://127.0.0.1:8001");
    assert_eq!(lb.rr_counter.load(Ordering::Relaxed), 0);
}

#[test]
fn test_round_robin_cycles() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
    let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

    let urls: Vec<String> = (0..6)
        .map(|_| lb.next_backend().unwrap().url.clone())
        .collect();
    assert_eq!(urls[0], "http://a:8001");
    assert_eq!(urls[1], "http://b:8002");
    assert_eq!(urls[2], "http://c:8003");
    assert_eq!(urls[3], "http://a:8001");
    assert_eq!(urls[4], "http://b:8002");
    assert_eq!(urls[5], "http://c:8003");
}

#[test]
fn test_round_robin_skips_unhealthy() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
    let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

    lb.backends()[0].set_healthy(false);

    let b = lb.next_backend().unwrap();
    assert_eq!(b.url, "http://b:8002");
}

#[test]
fn test_all_unhealthy_returns_none() {
    let servers = make_servers(vec!["http://a:8001"]);
    let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

    lb.backends()[0].set_healthy(false);
    assert!(lb.next_backend().is_none());
}

#[test]
fn test_weighted_distribution() {
    let servers = make_weighted_servers();
    let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);

    let mut a_count = 0;
    let mut b_count = 0;
    for _ in 0..100 {
        let b = lb.next_backend().unwrap();
        if b.url.contains("a:") {
            a_count += 1;
        } else {
            b_count += 1;
        }
    }
    // Weight ratio is 3:1, so a should get ~75%
    assert!(a_count > b_count, "a={} should be > b={}", a_count, b_count);
}

#[test]
fn test_least_connections() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
    let lb = LoadBalancer::new("test".into(), Strategy::LeastConnections, &servers, None);

    // Add connections to first backend
    lb.backends()[0].inc_connections();
    lb.backends()[0].inc_connections();

    let b = lb.next_backend().unwrap();
    assert_eq!(b.url, "http://b:8002"); // fewer connections
}

#[test]
fn test_least_connections_all_unhealthy() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
    let lb = LoadBalancer::new("test".into(), Strategy::LeastConnections, &servers, None);
    for backend in lb.backends().iter() {
        backend.set_healthy(false);
    }

    assert!(lb.next_backend().is_none());
}

#[test]
fn test_random_returns_something() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
    let lb = LoadBalancer::new("test".into(), Strategy::Random, &servers, None);

    let b = lb.next_backend();
    assert!(b.is_some());
    assert_eq!(lb.rr_counter.load(Ordering::Relaxed), 0);
}

#[test]
fn test_mixed_counter_index_visits_every_slot() {
    for upper_bound in [2, 3, 4, 7] {
        let mut seen = vec![false; upper_bound];
        for counter in 0..(upper_bound * 16) {
            seen[mixed_counter_index(counter as u64, upper_bound)] = true;
        }
        assert!(seen.into_iter().all(|visited| visited));
    }
}

#[test]
fn test_backend_health() {
    let b = Backend::new("http://test:8001".to_string(), 1);
    assert!(b.is_healthy());
    b.set_healthy(false);
    assert!(!b.is_healthy());
    b.set_healthy(true);
    assert!(b.is_healthy());
}

#[test]
fn test_backend_connections() {
    let b = Backend::new("http://test:8001".to_string(), 1);
    assert_eq!(b.connections(), 0);
    b.inc_connections();
    b.inc_connections();
    assert_eq!(b.connections(), 2);
    b.dec_connections();
    assert_eq!(b.connections(), 1);
}

#[test]
fn test_backend_connection_guards_sum_shards() {
    let backend = Arc::new(Backend::new("http://test:8001".to_string(), 1));
    let first = backend.track_connection_on(1);
    let second = backend.track_connection_on(9);

    assert_eq!(backend.connections(), 2);
    drop(first);
    assert_eq!(backend.connections(), 1);
    drop(second);
    assert_eq!(backend.connections(), 0);
}

#[test]
fn test_healthy_count() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
    let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

    assert_eq!(lb.healthy_count(), 3);
    assert_eq!(lb.total_count(), 3);

    lb.backends()[1].set_healthy(false);
    assert_eq!(lb.healthy_count(), 2);
    assert_eq!(lb.total_count(), 3);
}

#[test]
fn test_sticky_cookie() {
    let servers = make_servers(vec!["http://a:8001"]);
    let lb = LoadBalancer::new(
        "test".into(),
        Strategy::RoundRobin,
        &servers,
        Some("session_id".to_string()),
    );
    assert_eq!(lb.sticky_cookie(), Some("session_id"));

    let lb2 = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);
    assert_eq!(lb2.sticky_cookie(), None);
}

#[test]
fn test_empty_backends() {
    let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &[], None);
    assert!(lb.next_backend().is_none());
    assert_eq!(lb.healthy_count(), 0);
    assert_eq!(lb.total_count(), 0);
}

#[test]
fn test_weighted_zero_total_weight() {
    // All backends with weight 0 should fall back to find()
    let servers = vec![
        ServerConfig {
            url: "http://a:8001".to_string(),
            weight: 0,
            target: None,
        },
        ServerConfig {
            url: "http://b:8002".to_string(),
            weight: 0,
            target: None,
        },
    ];
    let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);
    // Should return a healthy backend (first one found)
    let b = lb.next_backend();
    assert!(b.is_some());
    assert!(b.unwrap().url.starts_with("http://"));
}

#[test]
fn test_weighted_total_weight_does_not_overflow() {
    let servers = vec![
        ServerConfig {
            url: "http://a:8001".to_string(),
            weight: u32::MAX,
            target: None,
        },
        ServerConfig {
            url: "http://b:8002".to_string(),
            weight: u32::MAX,
            target: None,
        },
    ];
    let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);

    assert!(lb.next_backend().is_some());
}

#[test]
fn test_weighted_all_unhealthy() {
    let servers = vec![
        ServerConfig {
            url: "http://a:8001".to_string(),
            weight: 3,
            target: None,
        },
        ServerConfig {
            url: "http://b:8002".to_string(),
            weight: 1,
            target: None,
        },
    ];
    let lb = LoadBalancer::new("test".into(), Strategy::Weighted, &servers, None);
    lb.backends()[0].set_healthy(false);
    lb.backends()[1].set_healthy(false);
    assert!(lb.next_backend().is_none());
}

#[test]
fn dynamic_box_backends_replace_atomically_and_preserve_unchanged_state() {
    let lb = LoadBalancer::new(
        "api".to_string(),
        Strategy::RoundRobin,
        &make_servers(vec!["http://static:8000"]),
        None,
    );
    lb.replace_dynamic_backends(&[
        (0, "http://127.0.0.1:18080".to_string()),
        (1, "http://127.0.0.1:18081".to_string()),
    ])
    .unwrap();
    assert_eq!(lb.backends().len(), 3);

    let retained = lb.backends()[1].clone();
    let retained_metric_id = retained.metric_id().to_string();
    retained.set_healthy(false);
    lb.replace_dynamic_backends(&[(0, "http://127.0.0.1:18080".to_string())])
        .unwrap();
    let snapshot = lb.backends();
    assert_eq!(snapshot.len(), 2);
    assert!(Arc::ptr_eq(&snapshot[1], &retained));
    assert!(!snapshot[1].is_healthy());
    assert_eq!(snapshot[1].metric_id(), retained_metric_id);

    lb.replace_dynamic_backends(&[(0, "http://127.0.0.1:28080".to_string())])
        .unwrap();
    let replaced = lb.backends();
    assert!(!Arc::ptr_eq(&replaced[1], &retained));
    assert_eq!(replaced[1].metric_id(), retained_metric_id);

    lb.replace_dynamic_backends(&[]).unwrap();
    assert_eq!(lb.backends().len(), 1);
    assert_eq!(lb.backends()[0].url, "http://static:8000");
}

#[test]
fn dynamic_box_backends_reject_duplicate_slots_and_urls() {
    let lb = LoadBalancer::new("api".to_string(), Strategy::RoundRobin, &[], None);
    assert!(lb
        .replace_dynamic_backends(&[
            (0, "http://127.0.0.1:18080".to_string()),
            (0, "http://127.0.0.1:18081".to_string()),
        ])
        .is_err());
    assert!(lb
        .replace_dynamic_backends(&[
            (0, "http://127.0.0.1:18080".to_string()),
            (1, "http://127.0.0.1:18080".to_string()),
        ])
        .is_err());
    assert!(lb.backends().is_empty());
}

#[test]
fn test_round_robin_healthy_skips_all_unhealthy() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
    let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);

    // Mark all unhealthy
    for b in lb.backends().iter() {
        b.set_healthy(false);
    }
    assert!(lb.next_backend().is_none());
}

#[test]
fn test_random_skips_unhealthy() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002", "http://c:8003"]);
    let lb = LoadBalancer::new("test".into(), Strategy::Random, &servers, None);

    // Mark two unhealthy, only c remains
    lb.backends()[0].set_healthy(false);
    lb.backends()[1].set_healthy(false);

    // Run multiple times, should always get c
    for _ in 0..10 {
        let b = lb.next_backend().unwrap();
        assert_eq!(b.url, "http://c:8003");
    }
}

#[test]
fn test_random_all_unhealthy() {
    let servers = make_servers(vec!["http://a:8001", "http://b:8002"]);
    let lb = LoadBalancer::new("test".into(), Strategy::Random, &servers, None);

    lb.backends()[0].set_healthy(false);
    lb.backends()[1].set_healthy(false);
    assert!(lb.next_backend().is_none());
}
