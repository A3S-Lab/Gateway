use reqwest::Client;
use serde_json::{json, Value};
use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::process::{Child, Command};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const SANDBOX_BODY: &str = "a3s-box-sandbox-ready";
const DEFAULT_SANDBOX_IMAGE: &str = "docker.io/library/alpine@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc";

struct ProcessGuard {
    name: &'static str,
    child: Child,
}

impl ProcessGuard {
    fn spawn(name: &'static str, command: &mut Command) -> TestResult<Self> {
        command
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        Ok(Self {
            name,
            child: command.spawn()?,
        })
    }

    fn ensure_running(&mut self) -> TestResult {
        if let Some(status) = self.child.try_wait()? {
            return Err(format!("{} exited unexpectedly with {status}", self.name).into());
        }
        Ok(())
    }

    async fn stop(mut self) -> TestResult {
        if self.child.try_wait()?.is_none() {
            self.child.start_kill()?;
        }
        tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .map_err(|_| format!("{} did not stop within 10 seconds", self.name))??;
        Ok(())
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

async fn free_ports() -> TestResult<[u16; 3]> {
    let mut listeners = Vec::with_capacity(3);
    for _ in 0..3 {
        listeners.push(TcpListener::bind("127.0.0.1:0").await?);
    }
    let ports = [
        listeners[0].local_addr()?.port(),
        listeners[1].local_addr()?.port(),
        listeners[2].local_addr()?.port(),
    ];
    drop(listeners);
    Ok(ports)
}

fn sandbox_catalog(image: &str) -> String {
    format!(
        r#"
service "api" {{
  image   = "{image}"
  command = ["/bin/sh", "-c", "mkdir -p /www && printf '%s' '{SANDBOX_BODY}' > /www/ready && exec httpd -f -p 8080 -h /www"]
  ports   = ["0:8080"]
}}
"#,
    )
}

fn gateway_config(traffic_port: u16, management_port: u16, box_port: u16) -> String {
    format!(
        r#"
mode {{ kind = "standalone" }}

entrypoints "web" {{
  address = "127.0.0.1:{traffic_port}"
}}

routers "api" {{
  rule        = "PathPrefix(`/`)"
  service     = "api"
  entrypoints = ["web"]
}}

services "api" {{
  load_balancer {{
    strategy = "round-robin"
  }}

  scaling {{
    min_replicas          = 0
    max_replicas          = 1
    container_concurrency = 1
    target_utilization    = 1.0
    scale_down_delay_secs = 300
    buffer_enabled        = true
    buffer_timeout_secs   = 90
    buffer_size           = 4
    executor              = "box"
    executor_endpoint     = "http://127.0.0.1:{box_port}"
  }}
}}

management {{
  enabled        = true
  address        = "127.0.0.1:{management_port}"
  path_prefix    = "/api/gateway"
  auth_token_env = ""
  allowed_ips    = ["127.0.0.1"]
}}

observability {{
  metrics_enabled    = false
  access_log_enabled = false
  tracing_enabled    = false
}}
"#,
    )
}

fn start_box(
    binary: &Path,
    address: SocketAddr,
    catalog: &Path,
    state: &Path,
) -> TestResult<ProcessGuard> {
    let mut command = Command::new(binary);
    command
        .arg("scale-api")
        .arg("--address")
        .arg(address.to_string())
        .arg("--state")
        .arg(state)
        .arg("--services")
        .arg(catalog)
        .arg("--isolation")
        .arg("sandbox")
        .arg("--endpoint-bind-address")
        .arg("127.0.0.1")
        .arg("--endpoint-drain-timeout-secs")
        .arg("1");
    ProcessGuard::spawn("A3S Box scale API", &mut command)
}

fn start_gateway(config: &Path) -> TestResult<ProcessGuard> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_a3s-gateway"));
    command
        .arg("--config")
        .arg(config)
        .arg("--log-level")
        .arg("info");
    ProcessGuard::spawn("A3S Gateway", &mut command)
}

async fn wait_for_health(process: &mut ProcessGuard, client: &Client, url: &str) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        process.ensure_running()?;
        if let Ok(response) = client.get(url).send().await {
            if response.status().is_success() {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("{} did not become healthy at {url}", process.name).into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_observation(
    process: &mut ProcessGuard,
    client: &Client,
    url: &str,
    replicas: u64,
    ready_replicas: u64,
) -> TestResult<Value> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        process.ensure_running()?;
        if let Ok(response) = client.get(url).send().await {
            if response.status().is_success() {
                let observation: Value = response.json().await?;
                if observation["replicas"].as_u64() == Some(replicas)
                    && observation["ready_replicas"].as_u64() == Some(ready_replicas)
                {
                    return Ok(observation);
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} did not report replicas={replicas}, ready_replicas={ready_replicas}",
                process.name
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_endpoint_retirement(client: &Client, endpoint: &str) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match client.get(endpoint).send().await {
            Ok(response) if response.status().is_success() => {}
            Ok(_) | Err(_) => return Ok(()),
        }
        if Instant::now() >= deadline {
            return Err(
                format!("retired Box endpoint still accepted traffic at {endpoint}").into(),
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn required_path(name: &str) -> TestResult<PathBuf> {
    let path = PathBuf::from(env::var(name).map_err(|_| format!("{name} must be set"))?);
    if !path.is_file() {
        return Err(format!("{name} does not name a file: {}", path.display()).into());
    }
    Ok(path)
}

#[test]
fn generated_gateway_acl_validates() {
    let config = a3s_gateway::config::GatewayConfig::from_acl(&gateway_config(18080, 18081, 19090))
        .expect("Box Sandbox conformance ACL should parse");
    config
        .validate()
        .expect("Box Sandbox conformance ACL should validate");
}

#[tokio::test]
#[ignore = "requires the pinned A3S Box and OCI Runtime on a privileged Linux host"]
async fn real_box_sandbox_endpoint_relay_scales_from_zero_and_retires() -> TestResult {
    if env::var("A3S_GATEWAY_TEST_BOX_SANDBOX").as_deref() != Ok("1") {
        return Err("set A3S_GATEWAY_TEST_BOX_SANDBOX=1 to run this destructive gate".into());
    }
    if !cfg!(target_os = "linux") {
        return Err("real Box Sandbox conformance requires Linux".into());
    }
    for name in [
        "A3S_HOME",
        "A3S_BOX_OCI_RUNTIME_PATH",
        "A3S_BOX_OCI_AGENT_PATH",
        "A3S_BOX_OCI_HOST_ROOT",
    ] {
        env::var(name).map_err(|_| format!("{name} must be set"))?;
    }

    let box_binary = required_path("A3S_GATEWAY_BOX_BINARY")?;
    let image = env::var("A3S_GATEWAY_BOX_SANDBOX_IMAGE")
        .unwrap_or_else(|_| DEFAULT_SANDBOX_IMAGE.to_string());
    let directory = tempfile::tempdir()?;
    let catalog = directory.path().join("services.acl");
    let box_state = directory.path().join("scale-authority.json");
    let gateway_acl = directory.path().join("gateway.acl");
    tokio::fs::write(&catalog, sandbox_catalog(&image)).await?;

    let [box_port, traffic_port, management_port] = free_ports().await?;
    let box_address = SocketAddr::from(([127, 0, 0, 1], box_port));
    let box_url = format!("http://{box_address}/v1/scale/api");
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;

    let mut box_process = start_box(&box_binary, box_address, &catalog, &box_state)?;
    wait_for_observation(&mut box_process, &client, &box_url, 0, 0).await?;

    tokio::fs::write(
        &gateway_acl,
        gateway_config(traffic_port, management_port, box_port),
    )
    .await?;
    let mut gateway = start_gateway(&gateway_acl)?;
    wait_for_health(
        &mut gateway,
        &client,
        &format!("http://127.0.0.1:{management_port}/api/gateway/health"),
    )
    .await?;

    let traffic_client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(120))
        .build()?;
    let response = traffic_client
        .get(format!("http://127.0.0.1:{traffic_port}/ready"))
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await?;
    if !status.is_success() {
        return Err(format!("Gateway returned {status} after Sandbox scale-up: {body}").into());
    }
    if body != SANDBOX_BODY {
        return Err(format!("unexpected Sandbox response body: {body:?}").into());
    }

    let observation = wait_for_observation(&mut box_process, &client, &box_url, 1, 1).await?;
    let endpoints = observation["endpoints"]
        .as_array()
        .ok_or("Box observation omitted endpoints")?;
    if endpoints.len() != 1 {
        return Err(format!(
            "Box published {} endpoints for one replica",
            endpoints.len()
        )
        .into());
    }
    let endpoint_origin = endpoints[0]["url"]
        .as_str()
        .ok_or("Box endpoint omitted its URL")?;
    if !endpoint_origin.starts_with("http://127.0.0.1:") {
        return Err(format!("Box published a non-loopback endpoint: {endpoint_origin}").into());
    }
    let endpoint = format!("{}/ready", endpoint_origin.trim_end_matches('/'));
    let direct = traffic_client.get(&endpoint).send().await?;
    if direct.text().await? != SANDBOX_BODY {
        return Err("direct Box relay did not reach the Sandbox workload".into());
    }

    let revision = observation["revision"]
        .as_str()
        .ok_or("Box observation omitted its post-scale revision")?
        .to_string();
    let cleanup = client
        .post(&box_url)
        .json(&json!({
            "schema_version": 1,
            "operation_id": "gateway-linux-sandbox-conformance-cleanup",
            "service": "api",
            "expected_revision": revision,
            "direction": "Down",
            "current_replicas": 1,
            "desired_replicas": 0,
            "reason": "conformance cleanup"
        }))
        .timeout(Duration::from_secs(90))
        .send()
        .await?;
    let cleanup_status = cleanup.status();
    let cleanup_body = cleanup.text().await?;
    if !cleanup_status.is_success() {
        return Err(format!("Box cleanup returned {cleanup_status}: {cleanup_body}").into());
    }
    wait_for_observation(&mut box_process, &client, &box_url, 0, 0).await?;
    wait_for_endpoint_retirement(&client, &endpoint).await?;

    gateway.stop().await?;
    box_process.stop().await?;
    Ok(())
}
