//! CLI integration tests for configuration management commands.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::thread;
use tempfile::{tempdir, TempDir};

struct TestConfig {
    _dir: TempDir,
    path: PathBuf,
}

fn gateway_bin() -> &'static str {
    env!("CARGO_BIN_EXE_a3s-gateway")
}

fn write_config(extension: &str) -> TestConfig {
    let dir = tempdir().unwrap();
    let path = dir.path().join(format!("gateway.{extension}"));
    fs::write(
        &path,
        r#"
entrypoints "web" {
  address = "127.0.0.1:18080"
}

entrypoints "admin" {
  address = "127.0.0.1:18082"
}

routers "api" {
  rule        = "PathPrefix(`/api`)"
  service     = "backend"
  entrypoints = ["web"]
  middlewares = ["rate-limit"]
}

routers "admin" {
  rule        = "PathPrefix(`/admin`)"
  service     = "admin-svc"
  entrypoints = ["admin"]
}

services "backend" {
  load_balancer {
    strategy = "round-robin"
    servers = [
      { url = "http://127.0.0.1:18081" }
    ]
  }
}

services "admin-svc" {
  load_balancer {
    strategy = "least-connections"
    servers = [
      { url = "http://127.0.0.1:18083" },
      { url = "http://127.0.0.1:18084" }
    ]
  }
}

middlewares "rate-limit" {
  type  = "rate-limit"
  rate  = 100
  burst = 20
}

providers {
  file {
    watch = true
  }
  discovery {
    poll_interval_secs = 30
    timeout_secs       = 3
    seeds = [
      { url = "http://127.0.0.1:18085" }
    ]
  }
}

management {
  enabled     = true
  address     = "127.0.0.1:19090"
  path_prefix = "/api/gateway"
  auth_token_env = ""
  allowed_ips = ["127.0.0.1"]
}
"#,
    )
    .unwrap();
    TestConfig { _dir: dir, path }
}

fn run(args: &[&str]) -> Output {
    Command::new(gateway_bin()).args(args).output().unwrap()
}

fn spawn_events_api() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 2048];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);
        assert!(request.starts_with("GET /api/gateway/events?limit=2 "));

        let body = r#"[{
  "sequence": 7,
  "timestamp": "2026-05-09T00:00:00Z",
  "kind": "auth-rejected",
  "remote_addr": "127.0.0.1:50100",
  "path": "/api/gateway/health",
  "status": 401,
  "reason": "Bearer token is missing or invalid"
}]"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    format!("http://{}/api/gateway", addr)
}

fn spawn_mutation_api(expected_path: &'static str, response_body: &'static str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0_u8; 4096];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);
        assert!(request.starts_with(&format!("POST {expected_path} ")));
        assert!(request.contains("entrypoints"));

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        stream.write_all(response.as_bytes()).unwrap();
    });

    format!("http://{}/api/gateway", addr)
}

#[test]
fn validate_accepts_acl_config() {
    let config = write_config("acl");
    let output = run(&["validate", "--config", config.path.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "Gateway rejected valid ACL: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration is valid"));
    assert!(stdout.contains("Management:"));
}

#[test]
fn validate_accepts_complete_cloud_route_snapshot() {
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cloud-route-snapshot.acl");
    let output = run(&["validate", "--config", fixture.to_str().unwrap()]);

    assert!(
        output.status.success(),
        "Gateway rejected the Cloud route snapshot: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration is valid"));
    assert!(stdout.contains("Routers:     1"));
    assert!(stdout.contains("Services:    1"));
}

#[test]
fn config_summary_reports_management_listener() {
    let config = write_config("acl");
    let output = run(&[
        "config",
        "--config",
        config.path.to_str().unwrap(),
        "summary",
    ]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Configuration summary"));
    assert!(stdout.contains("Entrypoints: 2"));
    assert!(stdout.contains("Routers:     2"));
    assert!(stdout.contains("Services:    2"));
    assert!(stdout.contains("Middlewares: 1"));
    assert!(stdout.contains("Providers:   file, discovery"));
    assert!(stdout.contains("Management:  127.0.0.1:19090"));
}

#[test]
fn config_entrypoints_lists_stable_output() {
    let config = write_config("acl");
    let output = run(&[
        "config",
        "--config",
        config.path.to_str().unwrap(),
        "entrypoints",
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "admin\t127.0.0.1:18082\tHttp\nweb\t127.0.0.1:18080\tHttp\n"
    );
}

#[test]
fn config_routes_lists_stable_output() {
    let config = write_config("acl");
    let output = run(&[
        "config",
        "--config",
        config.path.to_str().unwrap(),
        "routes",
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "admin\tservice=admin-svc\trule=PathPrefix(`/admin`)\tentrypoints=admin\napi\tservice=backend\trule=PathPrefix(`/api`)\tentrypoints=web\n"
    );
}

#[test]
fn config_services_lists_stable_output() {
    let config = write_config("acl");
    let output = run(&[
        "config",
        "--config",
        config.path.to_str().unwrap(),
        "services",
    ]);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "admin-svc\tbase_backends=2\trevision_backends=0\tstrategy=LeastConnections\nbackend\tbase_backends=1\trevision_backends=0\tstrategy=RoundRobin\n"
    );
}

#[test]
fn config_middlewares_lists_stable_output() {
    let config = write_config("acl");
    let output = run(&[
        "config",
        "--config",
        config.path.to_str().unwrap(),
        "middlewares",
    ]);

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "rate-limit\n");
}

#[test]
fn config_providers_lists_enabled_sources() {
    let config = write_config("acl");
    let output = run(&[
        "config",
        "--config",
        config.path.to_str().unwrap(),
        "providers",
    ]);

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "file\ndiscovery\n");
}

#[test]
fn config_json_outputs_parsed_acl() {
    let config = write_config("acl");
    let output = run(&["config", "--config", config.path.to_str().unwrap(), "json"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"entrypoints\""));
    assert!(stdout.contains("\"backend\""));
    assert!(stdout.contains("\"rate-limit\""));
    assert!(stdout.contains("\"management\""));
}

#[test]
fn management_events_fetches_running_api() {
    let url = spawn_events_api();
    let output = run(&["management", "events", "--url", &url, "--limit", "2"]);

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("auth-rejected"));
    assert!(stdout.contains("Bearer token is missing or invalid"));
}

#[test]
fn management_validate_posts_acl_file() {
    let config = write_config("acl");
    let url = spawn_mutation_api(
        "/api/gateway/config/validate",
        r#"{"valid":true,"reloaded":false,"message":"Configuration is valid"}"#,
    );
    let output = run(&[
        "management",
        "validate",
        "--url",
        &url,
        "--file",
        config.path.to_str().unwrap(),
    ]);

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Configuration is valid"));
}

#[test]
fn management_reload_posts_acl_file() {
    let config = write_config("acl");
    let url = spawn_mutation_api(
        "/api/gateway/config/reload",
        r#"{"valid":true,"reloaded":true,"message":"Configuration reloaded"}"#,
    );
    let output = run(&[
        "management",
        "reload",
        "--url",
        &url,
        "--file",
        config.path.to_str().unwrap(),
    ]);

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Configuration reloaded"));
}

#[test]
fn validate_rejects_non_acl_extension() {
    let config = write_config("txt");
    let output = run(&["validate", "--config", config.path.to_str().unwrap()]);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(".acl"));
}
