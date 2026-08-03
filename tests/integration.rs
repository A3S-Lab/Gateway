//! Integration tests for A3S Gateway
//!
//! These tests spin up real TCP listeners and HTTP backends to verify
//! end-to-end request flow through the gateway.

use a3s_gateway::config::{
    DiscoveryConfig, DiscoverySeedConfig, EntrypointConfig, GatewayConfig, HealthCheckConfig,
    LoadBalancerConfig, ManagementConfig, ManagementTlsConfig, MiddlewareConfig, OperatingMode,
    Protocol, RevisionConfig, RouterConfig, ServerConfig, ServiceConfig, Strategy,
};
use a3s_gateway::provider::FileWatcher;
use a3s_gateway::Gateway;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find a free port on localhost
async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Spawn a minimal HTTP backend that returns a fixed body for any request.
/// Returns the address it's listening on.
async fn spawn_backend(body: impl Into<String>) -> SocketAddr {
    let body = body.into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    addr
}

async fn spawn_health_probe_backend() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (probe_tx, probe_rx) = tokio::sync::mpsc::unbounded_channel();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(_) => break,
            };
            let probe_tx = probe_tx.clone();
            tokio::spawn(async move {
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                let _ = probe_tx.send(());
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });

    (address, probe_rx)
}

fn enable_fast_health_checks(config: &mut GatewayConfig) {
    let service = config.services.get_mut("test-svc").unwrap();
    service.load_balancer.health_check = Some(HealthCheckConfig {
        path: "/health".to_string(),
        interval: "20ms".to_string(),
        timeout: "1s".to_string(),
        unhealthy_threshold: 1,
        healthy_threshold: 1,
    });
}

async fn wait_for_health_probe(rx: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("health probe timed out")
        .expect("health probe backend stopped");
}

fn drain_health_probes(rx: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
    while rx.try_recv().is_ok() {}
}

/// Spawn a minimal HTTP backend that waits before returning a fixed body.
async fn spawn_delayed_backend(body: &'static str, delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let body = body.to_string();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                tokio::time::sleep(delay).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    addr
}

/// Spawn one chunked backend response whose second chunk is released by the test.
async fn spawn_controlled_streaming_backend() -> (
    SocketAddr,
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (first_chunk_sent, first_chunk_received) = tokio::sync::oneshot::channel();
    let (release_second_chunk, continue_response) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0_u8; 4096];
        while find_header_end(&request).is_none() {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            request.extend_from_slice(&buf[..n]);
        }

        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\n\
                  Content-Type: text/plain\r\n\
                  Transfer-Encoding: chunked\r\n\
                  Connection: close\r\n\r\n\
                  5\r\nfirst\r\n",
            )
            .await
            .unwrap();
        let _ = first_chunk_sent.send(());
        let _ = continue_response.await;
        let _ = stream.write_all(b"6\r\nsecond\r\n0\r\n\r\n").await;
        let _ = stream.shutdown().await;
    });

    (addr, first_chunk_received, release_second_chunk)
}

/// Spawn a backend that returns the size of the request body it received.
async fn spawn_body_length_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = vec![0u8; 8192];
                let header_end = loop {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                    if let Some(pos) = find_header_end(&request) {
                        break pos;
                    }
                };

                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                let body_start = header_end + 4;

                while request.len().saturating_sub(body_start) < content_length {
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    request.extend_from_slice(&buf[..n]);
                }

                let body_len = request.len().saturating_sub(body_start).min(content_length);
                let body = body_len.to_string();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    addr
}

fn find_header_end(request: &[u8]) -> Option<usize> {
    request.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Spawn a backend that captures one raw HTTP request and returns 200 OK.
async fn spawn_capture_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]).to_string();
        let _ = tx.send(request);

        let body = "captured";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        let _ = stream.shutdown().await;
    });

    (addr, rx)
}

/// Capture one request and return a response with a Connection-nominated field.
async fn spawn_connection_header_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buf = [0_u8; 4096];
        while find_header_end(&request).is_none() {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            request.extend_from_slice(&buf[..n]);
        }
        let _ = tx.send(String::from_utf8_lossy(&request).to_string());

        let response = b"HTTP/1.1 200 OK\r\n\
                         Content-Length: 2\r\n\
                         Content-Type: text/plain\r\n\
                         Connection: close, X-Backend-Connection\r\n\
                         X-Backend-Connection: must-not-escape\r\n\
                         X-End-To-End-Response: preserved\r\n\r\n\
                         ok";
        stream.write_all(response).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    (addr, rx)
}

fn captured_header(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

/// Spawn a discovery seed that exposes service metadata, health, and backend traffic.
async fn spawn_discovery_seed(body: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let body = body.to_string();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let (content_type, response_body) = match path {
                    "/.well-known/a3s-service.json" => (
                        "application/json",
                        r#"{
  "name": "discovered-svc",
  "version": "1.0.0",
  "health_path": "/health",
  "routes": [
    { "rule": "PathPrefix(`/discovered`)" }
  ]
}"#
                        .to_string(),
                    ),
                    "/health" => ("text/plain", "ok".to_string()),
                    _ => ("text/plain", body),
                };

                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: {}\r\n\r\n{}",
                    response_body.len(),
                    content_type,
                    response_body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    addr
}

/// Build a minimal gateway config with one entrypoint, one router, one service.
async fn build_config(gateway_port: u16, backend_addr: SocketAddr, rule: &str) -> GatewayConfig {
    let mut entrypoints = HashMap::new();
    entrypoints.insert(
        "web".to_string(),
        EntrypointConfig {
            address: format!("127.0.0.1:{}", gateway_port),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let mut routers = HashMap::new();
    routers.insert(
        "test-router".to_string(),
        RouterConfig {
            rule: rule.to_string(),
            service: "test-svc".to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: vec![],
            priority: 0,
        },
    );

    let mut services = HashMap::new();
    services.insert(
        "test-svc".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers: vec![ServerConfig {
                    url: format!("http://{}", backend_addr),
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
        },
    );

    GatewayConfig {
        mode: Default::default(),
        managed: Default::default(),
        inference: None,
        entrypoints,
        routers,
        services,
        middlewares: HashMap::new(),
        providers: Default::default(),
        management: Default::default(),
        observability: Default::default(),
        shutdown_timeout_secs: 5,
    }
}

/// Wait briefly for the gateway to be ready to accept connections.
async fn wait_ready(port: u16) {
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("Gateway did not become ready on port {}", port);
}

fn gateway_acl(gateway_port: u16, backend_addr: SocketAddr, watch: bool) -> String {
    format!(
        r#"
entrypoints "web" {{
  address = "127.0.0.1:{gateway_port}"
}}

routers "test-router" {{
  rule        = "PathPrefix(`/`)"
  service     = "test-svc"
  entrypoints = ["web"]
}}

services "test-svc" {{
  load_balancer {{
    strategy = "round-robin"
    servers = [
      {{ url = "http://{backend_addr}" }}
    ]
  }}
}}

providers {{
  file {{
    watch = {watch}
  }}
}}
"#
    )
}

fn management_reload_acl(
    gateway_port: u16,
    management_port: u16,
    backend_addr: SocketAddr,
) -> String {
    format!(
        r#"
entrypoints "web" {{
  address = "127.0.0.1:{gateway_port}"
}}

routers "test-router" {{
  rule        = "PathPrefix(`/`)"
  service     = "test-svc"
  entrypoints = ["web"]
}}

services "test-svc" {{
  load_balancer {{
    servers = [
      {{ url = "http://{backend_addr}" }}
    ]
  }}
}}

management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}
"#
    )
}

async fn wait_for_file_reload(
    rx: std::sync::mpsc::Receiver<a3s_gateway::provider::file_watcher::ReloadEvent>,
) -> a3s_gateway::provider::file_watcher::ReloadEvent {
    tokio::task::spawn_blocking(move || rx.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("file watcher should emit a reload event")
}

async fn write_file(path: &Path, content: String) {
    tokio::fs::write(path, content).await.unwrap();
}

struct ManagementMtlsFixture {
    _dir: tempfile::TempDir,
    server_cert_file: String,
    server_key_file: String,
    client_ca_file: String,
    client_ca_pem: String,
    client_identity_pem: Vec<u8>,
}

fn management_mtls_fixture() -> ManagementMtlsFixture {
    const CA_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDKDCCAhCgAwIBAgIJANBtVGa0JSTzMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMMFkEzUyBNYW5hZ2VtZW50IFRlc3QgQ0EwHhcNMjYwNTA5MDI1MjE5WhcNMzYw
NTA2MDI1MjE5WjAhMR8wHQYDVQQDDBZBM1MgTWFuYWdlbWVudCBUZXN0IENBMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1q0SxFf4LqfO0vDKafgEt1/4
Z9DuGFa5ej/Xojb5M1FPKaRslgLpuvO3W8u1ZI1cLdVyhXx9tPc0f1HDRFNvnR/i
O47WJ5cLmxOJW9KLQZ6X+KJ/8FMrBNDHLNuegvn41phQH0JTida6SJAWivePbMVY
CjM7uztcQpbBi8ZgBN2TDZ1Br1sLAySrackuWvL/Rh8VdTLnHv7fTyPtu6Zabyzt
WYKb3Daq+ckAG9uEyKEiCFhhAUdumbhogemrlwptTBbk7e9hJ74U/4eWDrDt6rOg
Rc8aXblCAijT6KAGciEwEm0Z71uoTtVSdULlY/VtORf2T+ajulY9Sxou4wRR5QID
AQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4E
FgQUsZm5Ds2rV+rJYR7TWbQlS+iXlAYwHwYDVR0jBBgwFoAUsZm5Ds2rV+rJYR7T
WbQlS+iXlAYwDQYJKoZIhvcNAQELBQADggEBAFcG+fGUk3/Cvd6b8VXXLgdP7lWu
KZmtK8rbST78jy9MAbqkGNqu+u1YznYYpAXBDLYno3HhF1P47E4nLlYVV9X0tYyJ
ZGkK3TlIio1H+QiXjhJpqsDw79bA5rrabgCzurGbzyQXIpoIPqMVDBQ1JjG8eVRQ
h9anEP3NAjo5rie6jcdkvJTFrkH+VKsuFAuhiynVLR4730AeIU734NNAmo8wKGMZ
si5S/UaV9ZX+PvweODzyzn6Cy1J6joPCOu+9gLQ5qMo4Z4Mfr0DYGUDjOwGn0XAz
3NlucITXBSKukYflPG+CgC7EiLG8N5OIq7l4lgXFTgvwbO4WGS4sCOv3z/c=
-----END CERTIFICATE-----
"#;
    const SERVER_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIJAI9qpkA36BaSMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMMFkEzUyBNYW5hZ2VtZW50IFRlc3QgQ0EwHhcNMjYwNTA5MDI1MjE5WhcNMzYw
NTA2MDI1MjE5WjAlMSMwIQYDVQQDDBpBM1MgTWFuYWdlbWVudCBUZXN0IFNlcnZl
cjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALlaKzmM+2t38Xc/m1vy
wDSTMIWWeOOGAeUQU51rzj/mCGP40ro5q6eHu/tTsyN20L9W/1pJqWjlERBqUEQE
Tigct08oZ8GiaM2Lhmj1m0GXdVQYKewJfBwC3quii6vr+LEru5q3kGfIF8bevfX2
7dqkrSAcNp8FLDIc1KxW+GkrD8RcKneSz+BPKf/hehsGzEhdEQ2k1GfV7NZwc40i
lWwNNRjCVTRWJ0x5Z7bb2p94e9T18NQJLICJpSMtqn7FjKbMzoJgvwE+wT/2z+nE
MgSDgy0yL+EmL+jBbfbctf6UMXRCoTEMddWMDuf2v0qjTeYaPSzISKf45lH9zL9/
dE8CAwEAAaNOMEwwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAww
CgYIKwYBBQUHAwEwGgYDVR0RBBMwEYcEfwAAAYIJbG9jYWxob3N0MA0GCSqGSIb3
DQEBCwUAA4IBAQAov5QSOPux/nNPYlBC7SANB4NeB960Vg6TEPu4stUYosgj3hIs
OZ7cYNVNIA88XSbEOQUoAON9QD/h3jn93tZPdItDv+pRx0vKetTLt60OobZ4fbDJ
d18Y4uQjIH3La6l/oGa7kd+KVz6OS60YF1DsUZYzRh4C3BnYQ/zstbzGpmxgNQ72
n2P7azyAZSQOBlmg15SiO6+Vo9vrDiiXiTsQR388MqvdPN1QQQmfAnBWmR6u4zqn
bLJEK4LmXlm9M6T0BNk/huASMKQTpZ/nyW4iv59wcjTK71T0Saq/tmhvcgp/uD8M
nNE9Kucpm5cny/551/u1Rj82GlZ8AJwVi9tu
-----END CERTIFICATE-----
"#;
    const SERVER_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuVorOYz7a3fxdz+bW/LANJMwhZZ444YB5RBTnWvOP+YIY/jS
ujmrp4e7+1OzI3bQv1b/WkmpaOUREGpQRAROKBy3TyhnwaJozYuGaPWbQZd1VBgp
7Al8HALeq6KLq+v4sSu7mreQZ8gXxt699fbt2qStIBw2nwUsMhzUrFb4aSsPxFwq
d5LP4E8p/+F6GwbMSF0RDaTUZ9Xs1nBzjSKVbA01GMJVNFYnTHlnttvan3h71PXw
1AksgImlIy2qfsWMpszOgmC/AT7BP/bP6cQyBIODLTIv4SYv6MFt9ty1/pQxdEKh
MQx11YwO5/a/SqNN5ho9LMhIp/jmUf3Mv390TwIDAQABAoIBAF1MAc3qJPOnYCfC
IJVbz1unaxkS8K612WZPnYbzqNGJHFgV+xw5wymErR6Itvb264QkakwsH9Xo13oH
yXczI5QVQD/b+r4A3ff4byON3SRa9Hfr4c4pyArhduu12dAj6v5jIP9zvoA+u5ki
rUONk5Qmp+4txWCt3d0rnfFRpaBpbL3qoPES4UN+wPotPlXQzmjyRJ5edZtLcqeU
fiiLUZStuMTcSTaT4+nDcp6JoiJDrY0ttZPn6eizOUWO31gOfsd8zI7Fmt1jrUZN
YUR332c4TdAyNjLLD2x5Rw8ERtVrdFoll8nPGP7dBqwx3bpnM4rbKDB/ZRa60WOu
5kg9dOECgYEA6B7VO/Q/b/zlgMFeMTOIlcmxZ35rws7IKHj9O0eujoLePGvanV8Y
x2rXizbgfiPoiKHqYB16M2wdQrYHYKOASpa6qjW6QMojWvo+ahZ6yJHGg8q8n/oD
nAZwEyyp9ZtBhAdj0as/2T+OEu1US4gs2f5cueRP3SLB/YpuBVK9fIMCgYEAzGuj
r2BvsoidruL0Nco6OuOcz/P1xVCoFzj7mmK+ukTqsx9JBHPSmmm5O5CeQydNJmFd
bn4k86x8wla8hdZSFldApEmHiCgIOeYHjqF0xyt4E8Zpt3kdKMNdJ3Hb6fCDbhaH
UgaxTelKxO7NtZDR6s9CMSZT7w7ieamKzA6Ed0UCgYBkb3rqXyvXxAB17rVX6qlt
zoChfFUaTKjUwk0oCkMgTMXmNPC56TzqhHNRPGR0kAr8m7qy7e5DM8ORavvUN8q5
+3A3V9oIUK5tnhvFgYaNJG5V9jIZsm8/YpW55jiAGjaF70Ckp0mQMezCichQilKF
3Ia4tG5OC80ObIhga0WsCwKBgQCRkj2YUGZ6jwsrVXdvLrnU4e3zsNleUBfDodKa
mKMV5qn0MN1AjHJ3f75nCo+JZt1r7X4phy8tT7Hweu/5pywBuNTRqYMYlNl20baj
/Zo5k10JSAxUma0IMEeQJWbj62DM7sIiyZ1NzEpwf1aCa8TxH/MVKSQwYzsoRHIQ
6m2uuQKBgGTmCse+Wt/m3iIA71T1KRXkPRWMcBifQ1btcrFTY24hxMqsLNE6Z65Q
gH7rVKfHr3i4qsj/af/Y/JWBBgNsBBkCitf42fl9q3xtJzEmLHPyLIjPE4izAd6A
zUjs7uZSi9681jUf7Kd5V8XpmhwxRSTJP1khu5pBXJzWyiIwiF/h
-----END RSA PRIVATE KEY-----
"#;
    const CLIENT_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIC+zCCAeOgAwIBAgIJAI9qpkA36BaTMA0GCSqGSIb3DQEBCwUAMCExHzAdBgNV
BAMMFkEzUyBNYW5hZ2VtZW50IFRlc3QgQ0EwHhcNMjYwNTA5MDI1MjE5WhcNMzYw
NTA2MDI1MjE5WjAlMSMwIQYDVQQDDBpBM1MgTWFuYWdlbWVudCBUZXN0IENsaWVu
dDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALh6QBUvZCeuu+YPf9/F
8pC7GKuxNn+N0UxM/btAcA4eRIGtG3sa7X//Uzl7KUu3Q9S0PHTRkS5IaF0X6YEP
fyVYTgN4MfdtnHDI82WAn2VomRRGMoi7KtQ4vZO+PwUyj7W41aF3AEJE3ZFzADTY
c70an9gbh4/vAUX4r3aAWzmUY8H0Eh2A66WqKN3E2H0OD5z/wDnke3izu4Gks14X
tLuWsUQC+mFlv7rqRvtCXBELHZtEUr/XucZjUqEwoz+bKXk7x0cJHx/Q6UbDbUTB
5HorXJOWXm7IOqoZ+LA3/NP6uMZlictdGTq4ZZuZcsRn0TbFE0PUTCp4WOpiAhrF
fQkCAwEAAaMyMDAwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAww
CgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAFaeuLqaweykvl4AW4NLfJrK
oRy7ofpjDsf9aYHa3/YIDAyQ8IzmVj2LQsQTfmwOG3e4r62qtss3LXxHTfWjDC3F
VAIyWywybXFXggoRb6ieDWBmsUMRM86baP6yVqfQLpYyhlA8ModqXQnd2zTZ/wfO
FeDO1nY3zwqYJPMJoW9A1vroS9PF1kRPh1+5zMlhLLoH0EIJZKQzOxkM2WqyoJIm
O/suQzeFKT3gb+nPTRBiaL1kGxePZvyvconxGGiH/Pc2ovNbqFmxgZGYCz1U1E1Z
rC6LXKwR3iF+3qAttQ17cS+v9Fp6/0NSqpycTkz4CelUHLiPwSaWM0JVTmhzdNo=
-----END CERTIFICATE-----
"#;
    const CLIENT_KEY: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuHpAFS9kJ6675g9/38XykLsYq7E2f43RTEz9u0BwDh5Ega0b
exrtf/9TOXspS7dD1LQ8dNGRLkhoXRfpgQ9/JVhOA3gx922ccMjzZYCfZWiZFEYy
iLsq1Di9k74/BTKPtbjVoXcAQkTdkXMANNhzvRqf2BuHj+8BRfivdoBbOZRjwfQS
HYDrpaoo3cTYfQ4PnP/AOeR7eLO7gaSzXhe0u5axRAL6YWW/uupG+0JcEQsdm0RS
v9e5xmNSoTCjP5speTvHRwkfH9DpRsNtRMHkeitck5Zebsg6qhn4sDf80/q4xmWJ
y10ZOrhlm5lyxGfRNsUTQ9RMKnhY6mICGsV9CQIDAQABAoIBABTv2wIMhON0E2NC
8xJklukSMvSZgkPrxotQWaO85nrTuJa3HN1V6wqR4dIuRjuPqyUi55Gij0WfdijK
o/e/2IBWi1Qdeh5I1G6AgA9PD8gknOsOJIIcK/o2Dl4MQ37FhEXtmmFe7iqXQkZV
tPpKbqhRsz6FsVcGmzBjzxY17ySTn3SUDY5ozEM3zY8ZP1ba8MLesNT2D4tSNS8N
rSCzNkX4S9RljL+kpvWKCexB/sAAe4d2SguvFJZu5ZjtNw7KLA8cRVr9MB5C0bbz
TqxdfdhDLQhJGuA3BdeOCfxYBBLNcSFkca1JVttl6ykmvKxMf255L5Rg1hi8vhEo
cqTZ2DkCgYEA49dxe1jeBMv1hUIvWRMb2EfJbSXcGrbrWyMR3Ne2icwyLSai6BhE
e17oSlOva6vPInQYdga7dVT4pk03R/SI0K+xK47Ch+iApCucI2hP34yEZydbizCS
34MFrlmWq+rtOVoRY3LhQr995/c/wZZqdiPMv+H3h5eMfzn6+hrwjYMCgYEAz0bV
8cDE88p9nNSwmpm1YOqJJObG5dZxJOu53JHLaqLlhWYWTxhqNk9yAErsh0iOZL+3
rzk+ZoiQMARNnK/fp49dKSJDl7eFr/Jvt3V2JGUMCKV/EfnKCgtXskRjfLsEsGfM
2c9CWuVYsMAGnQtBlMs40qysJ0yK1Ul5sUpdMYMCgYEAqcM6M/zIGGzb+DmTS9xY
D/OVGrVt5Z3LiXF8+r7jrJKwBEJYeXSzefUCQXdPKnuub25vV2m2vTrdthOsj/md
A1kVOm45dciAKVKxGRS9BsUNVkrWA8TiepWGYx0vjdMShHwenqnXO8OwjWkFYTmx
A2uzQHme1LHPpnBOF5KBD/8CgYA4R/ChswkHdU0EP5AweloQlb5lYbBSChcwwjz2
UjQcoVyXCzA1i9iTJKE8yRtOZHodix0SHAYAi0Yzc4erauncsoXGPIKD+JX5P2fs
NZ29ph5NXrqRI/UjIw9N3VnyLUnJqHWsEqXeznV1kL569+p3v3KPaclY5mSwI0JC
zIFfhwKBgBa3wlNsEAtYQe9bWlflEiRR2A8yRDbVSWCWqD6oLyVS4bGSqOYdRYNv
M5sQHnB6Jj3oeUie71/yHfDsm2TZHAul6Hf2RrHXze3tQnxNzCgDHq1mxkZj8Hxa
t9BEZVkwW55sSbYRK2xucVrZd2EP6J8qW7x9e40zcTLVhaWyOAdt
-----END RSA PRIVATE KEY-----
"#;

    let dir = tempfile::tempdir().unwrap();
    let server_cert_file = dir.path().join("server.crt");
    let server_key_file = dir.path().join("server.key");
    let client_ca_file = dir.path().join("client-ca.crt");
    std::fs::write(&server_cert_file, SERVER_CERT).unwrap();
    std::fs::write(&server_key_file, SERVER_KEY).unwrap();
    std::fs::write(&client_ca_file, CA_CERT).unwrap();

    let mut client_identity_pem = CLIENT_CERT.as_bytes().to_vec();
    client_identity_pem.extend_from_slice(CLIENT_KEY.as_bytes());

    ManagementMtlsFixture {
        _dir: dir,
        server_cert_file: server_cert_file.to_str().unwrap().to_string(),
        server_key_file: server_key_file.to_str().unwrap().to_string(),
        client_ca_file: client_ca_file.to_str().unwrap().to_string(),
        client_ca_pem: CA_CERT.to_string(),
        client_identity_pem,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

include!("integration/traffic.rs");
include!("integration/http_streaming.rs");
include!("integration/grpc.rs");
include!("integration/reload.rs");
include!("integration/management.rs");
include!("integration/lifecycle.rs");
