//! Integration tests for A3S Gateway
//!
//! These tests spin up real TCP listeners and HTTP backends to verify
//! end-to-end request flow through the gateway.

use a3s_gateway::config::{
    DiscoveryConfig, DiscoverySeedConfig, EntrypointConfig, GatewayConfig, LoadBalancerConfig,
    ManagementConfig, ManagementTlsConfig, OperatingMode, Protocol, RevisionConfig, RouterConfig,
    ServerConfig, ServiceConfig, Strategy,
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
async fn spawn_backend(body: &'static str) -> SocketAddr {
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

#[tokio::test]
async fn test_gateway_lifecycle() {
    let port = free_port().await;
    let backend = spawn_backend("ok").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    assert!(gw.is_running());

    wait_ready(port).await;

    // Health check
    let health = gw.health();
    assert_eq!(health.state, a3s_gateway::GatewayState::Running);

    gw.shutdown().await;
    assert!(gw.is_shutdown());
}

#[tokio::test]
async fn test_http_proxy_round_trip() {
    let port = free_port().await;
    let backend = spawn_backend("hello from backend").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // Send a real HTTP request through the gateway
    let resp = reqwest::get(format!("http://127.0.0.1:{}/anything", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "hello from backend");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_http_proxy_forwards_client_context_headers() {
    let port = free_port().await;
    let (backend, captured) = spawn_capture_backend().await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/headers?trace=1", port))
        .header("Host", "public.example.test:8080")
        .header("X-Forwarded-For", "198.51.100.10")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "captured");

    let request = tokio::time::timeout(Duration::from_secs(2), captured)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        captured_header(&request, "x-forwarded-for").as_deref(),
        Some("198.51.100.10, 127.0.0.1")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-host").as_deref(),
        Some("public.example.test:8080")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-proto").as_deref(),
        Some("http")
    );
    assert_eq!(
        captured_header(&request, "x-forwarded-port").as_deref(),
        Some("8080")
    );

    gw.shutdown().await;
}

#[tokio::test]
async fn test_http_proxy_forwards_large_request_body() {
    let port = free_port().await;
    let backend = spawn_body_length_backend().await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let body = vec![b'a'; 1024 * 1024];
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{}/upload", port))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), (1024 * 1024).to_string());

    gw.shutdown().await;
}

#[tokio::test]
async fn test_path_prefix_routing() {
    let port = free_port().await;
    let backend_api = spawn_backend("api-response").await;
    let backend_web = spawn_backend("web-response").await;

    let mut config = build_config(port, backend_api, "PathPrefix(`/api`)").await;
    config.routers.insert(
        "web-router".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/web`)".to_string(),
            service: "web-svc".to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: vec![],
            priority: 0,
        },
    );
    config.services.insert(
        "web-svc".to_string(),
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers: vec![ServerConfig {
                    url: format!("http://{}", backend_web),
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

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // /api → api backend
    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/test", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "api-response");

    // /web → web backend
    let resp = reqwest::get(format!("http://127.0.0.1:{}/web/page", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "web-response");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_no_route_returns_404() {
    let port = free_port().await;
    let backend = spawn_backend("ok").await;
    // Only match /api prefix
    let config = build_config(port, backend, "PathPrefix(`/api`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // /unknown should get 404
    let resp = reqwest::get(format!("http://127.0.0.1:{}/unknown", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_backend_down_returns_503() {
    let port = free_port().await;
    // Point to a port that nothing is listening on
    let dead_port = free_port().await;
    let dead_addr: SocketAddr = format!("127.0.0.1:{}", dead_port).parse().unwrap();
    let config = build_config(port, dead_addr, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/test", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_http_proxy_respects_service_request_timeout() {
    let port = free_port().await;
    let backend = spawn_delayed_backend("too slow", Duration::from_millis(250)).await;
    let mut config = build_config(port, backend, "PathPrefix(`/`)").await;
    config
        .services
        .get_mut("test-svc")
        .unwrap()
        .load_balancer
        .request_timeout = "50ms".to_string();

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/slow", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::GATEWAY_TIMEOUT);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_reload_switches_backend() {
    let port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let config = build_config(port, backend_v1, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // Verify v1
    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "v1");

    // Reload with v2 backend on the same entrypoint. This should hot-swap the
    // runtime state without dropping or rebinding the traffic listener.
    let new_config = build_config(port, backend_v2, "PathPrefix(`/`)").await;
    gw.reload(new_config).await.unwrap();

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "v2");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_file_provider_reload_updates_live_traffic() {
    let port = free_port().await;
    let backend_v1 = spawn_backend("file-v1").await;
    let backend_v2 = spawn_backend("file-v2").await;
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("gateway.acl");

    write_file(&config_path, gateway_acl(port, backend_v1, true)).await;
    let watcher = FileWatcher::new(&config_path);
    let config = watcher.load_config().unwrap();

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "file-v1");

    let rx = watcher.watch().unwrap();
    tokio::time::sleep(Duration::from_millis(650)).await;
    write_file(&config_path, gateway_acl(port, backend_v2, true)).await;

    let event = wait_for_file_reload(rx).await;
    let new_config = event.config.unwrap();
    gw.reload(new_config).await.unwrap();

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.text().await.unwrap(), "file-v2");
    assert!(watcher.reload_count() >= 1);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_discovery_provider_reload_updates_live_traffic() {
    let gateway_port = free_port().await;
    let seed = spawn_discovery_seed("discovered-ok").await;

    let mut config = GatewayConfig::default();
    config.entrypoints.clear();
    config.entrypoints.insert(
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
    config.routers.clear();
    config.services.clear();
    config.providers.discovery = Some(DiscoveryConfig {
        seeds: vec![DiscoverySeedConfig {
            url: format!("http://{}", seed),
        }],
        poll_interval_secs: 1,
        timeout_secs: 1,
    });

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(gateway_port).await;

    let url = format!("http://127.0.0.1:{}/discovered", gateway_port);
    for _ in 0..50 {
        if let Ok(resp) = reqwest::get(&url).await {
            if resp.status() == 200 && resp.text().await.unwrap_or_default() == "discovered-ok" {
                gw.shutdown().await;
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    gw.shutdown().await;
    panic!("discovery provider did not update live traffic");
}

#[tokio::test]
async fn test_revision_only_service_routes_to_revision_backend() {
    let port = free_port().await;
    let backend = spawn_backend("revision-v1").await;
    let mut config = build_config(port, backend, "PathPrefix(`/`)").await;

    let service = config.services.get_mut("test-svc").unwrap();
    service.load_balancer.servers.clear();
    service.revisions = vec![RevisionConfig {
        name: "v1".to_string(),
        traffic_percent: 100,
        servers: vec![ServerConfig {
            url: format!("http://{}", backend),
            weight: 1,
        }],
        strategy: Strategy::RoundRobin,
    }];

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "revision-v1");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_invalid_config_rejected() {
    // Router references nonexistent service
    let mut config = GatewayConfig::default();
    config.routers.insert(
        "bad".to_string(),
        RouterConfig {
            rule: "PathPrefix(`/`)".to_string(),
            service: "nonexistent".to_string(),
            entrypoints: vec![],
            middlewares: vec![],
            priority: 0,
        },
    );
    assert!(Gateway::new(config).is_err());
}

#[tokio::test]
async fn test_multiple_entrypoints() {
    let port1 = free_port().await;
    let port2 = free_port().await;
    let backend = spawn_backend("multi-ep").await;

    let mut config = build_config(port1, backend, "PathPrefix(`/`)").await;
    // Router must list both entrypoints to accept traffic on both
    config.routers.get_mut("test-router").unwrap().entrypoints =
        vec!["web".to_string(), "web2".to_string()];
    config.entrypoints.insert(
        "web2".to_string(),
        EntrypointConfig {
            address: format!("127.0.0.1:{}", port2),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port1).await;
    wait_ready(port2).await;

    // Both entrypoints should proxy to the same backend
    let r1 = reqwest::get(format!("http://127.0.0.1:{}/", port1))
        .await
        .unwrap();
    assert_eq!(r1.text().await.unwrap(), "multi-ep");

    let r2 = reqwest::get(format!("http://127.0.0.1:{}/", port2))
        .await
        .unwrap();
    assert_eq!(r2.text().await.unwrap(), "multi-ep");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_api_gateway_path_is_regular_traffic() {
    let port = free_port().await;
    let backend = spawn_backend("regular-traffic").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/api/gateway/health", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "regular-traffic");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_management_api_uses_dedicated_listener() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let mut config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;
    config.mode = OperatingMode::CloudManaged;
    let token_env = format!("A3S_TEST_GATEWAY_ADMIN_TOKEN_{}", management_port);
    std::env::set_var(&token_env, "secret-token");
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;

    let client = reqwest::Client::new();
    let management_url = format!("http://127.0.0.1:{}/api/gateway/health", management_port);
    let unauthorized = client.get(&management_url).send().await.unwrap();
    assert_eq!(unauthorized.status(), 401);

    let management_resp = client
        .get(&management_url)
        .bearer_auth("secret-token")
        .send()
        .await
        .unwrap();
    assert_eq!(management_resp.status(), 200);
    let management_health: serde_json::Value = management_resp.json().await.unwrap();
    assert_eq!(management_health["state"], "Running");
    assert_eq!(management_health["mode"], "cloud-managed");

    let events_url = format!("http://127.0.0.1:{}/api/gateway/events", management_port);
    let events_resp = client
        .get(events_url)
        .bearer_auth("secret-token")
        .send()
        .await
        .unwrap();
    assert_eq!(events_resp.status(), 200);
    assert!(events_resp.text().await.unwrap().contains("auth-rejected"));

    let traffic_resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/gateway/health",
        traffic_port
    ))
    .await
    .unwrap();
    assert_eq!(traffic_resp.status(), 200);
    assert_eq!(traffic_resp.text().await.unwrap(), "traffic-ok");

    gw.shutdown().await;
    std::env::remove_var(token_env);
}

#[tokio::test]
async fn test_management_api_rejects_disallowed_ip() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let mut config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: None,
        allowed_ips: vec!["10.0.0.1".to_string()],
        tls: None,
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(management_port).await;

    let management_url = format!("http://127.0.0.1:{}/api/gateway/health", management_port);
    let resp = reqwest::get(management_url).await.unwrap();
    assert_eq!(resp.status(), 403);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_management_api_validates_and_reloads_acl_payload() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_backend("mgmt-v1").await;
    let backend_v2 = spawn_backend("mgmt-v2").await;
    let acl_v1 = management_reload_acl(traffic_port, management_port, backend_v1);
    let acl_v2 = management_reload_acl(traffic_port, management_port, backend_v2);
    let config = GatewayConfig::from_acl(&acl_v1).unwrap();

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;

    let client = reqwest::Client::new();
    let validate_url = format!(
        "http://127.0.0.1:{}/api/gateway/config/validate",
        management_port
    );
    let validate_resp = client
        .post(validate_url)
        .body(acl_v1)
        .header("Content-Type", "text/plain")
        .send()
        .await
        .unwrap();
    assert_eq!(validate_resp.status(), 200);
    assert!(validate_resp.text().await.unwrap().contains("valid"));

    let reload_url = format!(
        "http://127.0.0.1:{}/api/gateway/config/reload",
        management_port
    );
    let reload_resp = client
        .post(reload_url)
        .body(acl_v2)
        .header("Content-Type", "text/plain")
        .send()
        .await
        .unwrap();
    assert_eq!(reload_resp.status(), 200);
    assert!(reload_resp.text().await.unwrap().contains("reloaded"));

    let traffic_resp = reqwest::get(format!("http://127.0.0.1:{}/", traffic_port))
        .await
        .unwrap();
    assert_eq!(traffic_resp.text().await.unwrap(), "mgmt-v2");

    let events_resp = client
        .get(format!(
            "http://127.0.0.1:{}/api/gateway/events",
            management_port
        ))
        .send()
        .await
        .unwrap();
    let events_body = events_resp.text().await.unwrap();
    assert!(events_body.contains("config-validated"));
    assert!(events_body.contains("config-reloaded"));

    gw.shutdown().await;
}

#[tokio::test]
async fn test_management_api_requires_valid_client_certificate() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let fixture = management_mtls_fixture();
    let mut config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: None,
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: Some(ManagementTlsConfig {
            cert_file: fixture.server_cert_file.clone(),
            key_file: fixture.server_key_file.clone(),
            client_ca_file: Some(fixture.client_ca_file.clone()),
            require_client_cert: true,
            min_version: "1.2".to_string(),
        }),
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(management_port).await;

    let ca_cert = reqwest::Certificate::from_pem(fixture.client_ca_pem.as_bytes()).unwrap();
    let no_cert_client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .build()
        .unwrap();
    let management_url = format!("https://127.0.0.1:{}/api/gateway/health", management_port);
    let no_cert_result = no_cert_client.get(&management_url).send().await;
    assert!(no_cert_result.is_err());

    let ca_cert = reqwest::Certificate::from_pem(fixture.client_ca_pem.as_bytes()).unwrap();
    let identity = reqwest::Identity::from_pem(&fixture.client_identity_pem).unwrap();
    let mtls_client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .build()
        .unwrap();
    let resp = mtls_client.get(management_url).send().await.unwrap();
    assert_eq!(resp.status(), 200);
    assert!(resp.text().await.unwrap().contains("Running"));

    gw.shutdown().await;
}

#[tokio::test]
async fn test_reload_enables_management_api_on_dedicated_listener() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend = spawn_backend("traffic-ok").await;
    let config = build_config(traffic_port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config.clone()).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;

    let token_env = format!("A3S_TEST_GATEWAY_RELOAD_ADMIN_TOKEN_{}", management_port);
    std::env::set_var(&token_env, "reload-secret");
    let mut new_config = config;
    new_config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    gw.reload(new_config).await.unwrap();
    wait_ready(management_port).await;

    let management_url = format!("http://127.0.0.1:{}/api/gateway/health", management_port);
    let resp = reqwest::Client::new()
        .get(management_url)
        .bearer_auth("reload-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let traffic_resp = reqwest::get(format!(
        "http://127.0.0.1:{}/api/gateway/health",
        traffic_port
    ))
    .await
    .unwrap();
    assert_eq!(traffic_resp.status(), 200);
    assert_eq!(traffic_resp.text().await.unwrap(), "traffic-ok");

    gw.shutdown().await;
    std::env::remove_var(token_env);
}

#[tokio::test]
async fn test_failed_management_reload_keeps_old_runtime_and_listener() {
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let mut config = build_config(traffic_port, backend_v1, "PathPrefix(`/`)").await;

    let token_env = format!("A3S_TEST_GATEWAY_OLD_ADMIN_TOKEN_{}", management_port);
    let missing_token_env = format!("A3S_TEST_GATEWAY_MISSING_ADMIN_TOKEN_{}", management_port);
    std::env::set_var(&token_env, "old-secret");
    std::env::remove_var(&missing_token_env);
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(management_port).await;

    let mut new_config = build_config(traffic_port, backend_v2, "PathPrefix(`/`)").await;
    new_config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(missing_token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let err = gw.reload(new_config).await.unwrap_err();
    assert!(err.to_string().contains(&missing_token_env));

    let traffic_resp = reqwest::get(format!("http://127.0.0.1:{}/", traffic_port))
        .await
        .unwrap();
    assert_eq!(traffic_resp.status(), 200);
    assert_eq!(traffic_resp.text().await.unwrap(), "v1");

    let management_url = format!("http://127.0.0.1:{}/api/gateway/health", management_port);
    let management_resp = reqwest::Client::new()
        .get(management_url)
        .bearer_auth("old-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(management_resp.status(), 200);

    gw.shutdown().await;
    std::env::remove_var(token_env);
    std::env::remove_var(missing_token_env);
}

#[tokio::test]
async fn test_failed_entrypoint_reload_keeps_old_listener_and_runtime() {
    let port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let config = build_config(port, backend_v1, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    let mut new_config = build_config(port, backend_v2, "PathPrefix(`/`)").await;
    new_config.entrypoints.insert(
        "admin".to_string(),
        EntrypointConfig {
            address: format!("127.0.0.1:{}", port),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let err = gw.reload(new_config).await.unwrap_err();
    assert!(err.to_string().contains("Failed to bind"));

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "v1");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_failed_entrypoint_reload_does_not_switch_management_listener() {
    let traffic_port = free_port().await;
    let old_management_port = free_port().await;
    let new_management_port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let mut config = build_config(traffic_port, backend_v1, "PathPrefix(`/`)").await;

    let old_token_env = format!("A3S_TEST_GATEWAY_OLD_MGMT_TOKEN_{}", old_management_port);
    let new_token_env = format!("A3S_TEST_GATEWAY_NEW_MGMT_TOKEN_{}", new_management_port);
    std::env::set_var(&old_token_env, "old-token");
    std::env::set_var(&new_token_env, "new-token");
    config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", old_management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(old_token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(traffic_port).await;
    wait_ready(old_management_port).await;

    let mut new_config = build_config(traffic_port, backend_v2, "PathPrefix(`/`)").await;
    new_config.management = ManagementConfig {
        enabled: true,
        address: format!("127.0.0.1:{}", new_management_port),
        path_prefix: "/api/gateway".to_string(),
        auth_token_env: Some(new_token_env.clone()),
        allowed_ips: vec!["127.0.0.1".to_string()],
        tls: None,
    };
    new_config.entrypoints.insert(
        "admin".to_string(),
        EntrypointConfig {
            address: format!("127.0.0.1:{}", traffic_port),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
        },
    );

    let err = gw.reload(new_config).await.unwrap_err();
    assert!(err.to_string().contains("Failed to bind"));

    let old_management_url = format!(
        "http://127.0.0.1:{}/api/gateway/health",
        old_management_port
    );
    let old_management_resp = reqwest::Client::new()
        .get(old_management_url)
        .bearer_auth("old-token")
        .send()
        .await
        .unwrap();
    assert_eq!(old_management_resp.status(), 200);

    let new_management_connect = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        tokio::net::TcpStream::connect(format!("127.0.0.1:{}", new_management_port)),
    )
    .await;
    assert!(!matches!(new_management_connect, Ok(Ok(_))));

    let traffic_resp = reqwest::get(format!("http://127.0.0.1:{}/", traffic_port))
        .await
        .unwrap();
    assert_eq!(traffic_resp.status(), 200);
    assert_eq!(traffic_resp.text().await.unwrap(), "v1");

    gw.shutdown().await;
    std::env::remove_var(old_token_env);
    std::env::remove_var(new_token_env);
}

#[tokio::test]
async fn test_entrypoint_address_change_restarts_only_changed_listener() {
    let old_port = free_port().await;
    let new_port = free_port().await;
    let backend_v1 = spawn_backend("v1").await;
    let backend_v2 = spawn_backend("v2").await;
    let config = build_config(old_port, backend_v1, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(old_port).await;

    let mut new_config = build_config(new_port, backend_v2, "PathPrefix(`/`)").await;
    new_config
        .routers
        .get_mut("test-router")
        .unwrap()
        .entrypoints = vec!["web".to_string()];

    gw.reload(new_config).await.unwrap();
    wait_ready(new_port).await;

    let resp = reqwest::get(format!("http://127.0.0.1:{}/", new_port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "v2");

    gw.shutdown().await;
}

#[tokio::test]
async fn test_concurrent_requests() {
    let port = free_port().await;
    let backend = spawn_backend("concurrent-ok").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // Fire 20 concurrent requests
    let mut handles = Vec::new();
    for _ in 0..20 {
        let url = format!("http://127.0.0.1:{}/", port);
        handles.push(tokio::spawn(async move {
            reqwest::get(&url).await.unwrap().text().await.unwrap()
        }));
    }

    for h in handles {
        let body = h.await.unwrap();
        assert_eq!(body, "concurrent-ok");
    }

    // Verify metrics recorded requests
    let snapshot = gw.metrics().snapshot();
    assert!(snapshot.total_requests >= 20);

    gw.shutdown().await;
}

#[tokio::test]
async fn test_graceful_shutdown_completes() {
    let port = free_port().await;
    let backend = spawn_backend("shutdown-test").await;
    let config = build_config(port, backend, "PathPrefix(`/`)").await;

    let gw = Arc::new(Gateway::new(config).unwrap());
    gw.start().await.unwrap();
    wait_ready(port).await;

    // Verify it's working
    let resp = reqwest::get(format!("http://127.0.0.1:{}/", port))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // Shutdown should complete without hanging
    let gw_clone = gw.clone();
    let shutdown = tokio::spawn(async move {
        gw_clone.shutdown().await;
    });

    tokio::time::timeout(std::time::Duration::from_secs(5), shutdown)
        .await
        .expect("Shutdown should complete within 5 seconds")
        .unwrap();

    assert_eq!(gw.state(), a3s_gateway::GatewayState::Stopped);
}
