use bytes::Bytes;
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

const SCALE_PATH: &str = "/v1/scale/api";

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: Method,
    path: String,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ScaleSnapshot {
    replicas: u32,
    get_count: usize,
    post_count: usize,
    requests: Vec<RecordedRequest>,
}

struct ScaleState {
    replicas: u32,
    revision: u64,
    endpoint_url: String,
    fail_next_post_after_apply: bool,
    get_count: usize,
    post_count: usize,
    requests: Vec<RecordedRequest>,
}

struct BoxScaleApi {
    address: SocketAddr,
    state: Arc<Mutex<ScaleState>>,
    server: JoinHandle<()>,
}

impl BoxScaleApi {
    async fn start(endpoint_url: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(ScaleState {
            replicas: 0,
            revision: 0,
            endpoint_url,
            fail_next_post_after_apply: true,
            get_count: 0,
            post_count: 0,
            requests: Vec::new(),
        }));
        let server_state = state.clone();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let connection_state = server_state.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request| {
                        handle_scale_request(request, connection_state.clone())
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            address,
            state,
            server,
        }
    }

    fn snapshot(&self) -> ScaleSnapshot {
        let state = self.state.lock().unwrap();
        ScaleSnapshot {
            replicas: state.replicas,
            get_count: state.get_count,
            post_count: state.post_count,
            requests: state.requests.clone(),
        }
    }

    async fn wait_for<F>(&self, predicate: F) -> ScaleSnapshot
    where
        F: Fn(&ScaleSnapshot) -> bool,
    {
        for _ in 0..600 {
            let snapshot = self.snapshot();
            if predicate(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "Box Scale API did not reach the expected state: {:?}",
            self.snapshot()
        );
    }
}

impl Drop for BoxScaleApi {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn handle_scale_request(
    request: Request<Incoming>,
    state: Arc<Mutex<ScaleState>>,
) -> io::Result<Response<Full<Bytes>>> {
    let (parts, body) = request.into_parts();
    let body = body
        .collect()
        .await
        .map_err(|error| io::Error::other(error.to_string()))?
        .to_bytes()
        .to_vec();
    let method = parts.method;
    let path = parts.uri.path().to_string();
    let mut state = state.lock().unwrap();
    state.requests.push(RecordedRequest {
        method: method.clone(),
        path: path.clone(),
        body: body.clone(),
    });

    if path != SCALE_PATH {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            json!({ "error": format!("unexpected fixture path {path}") }),
        ));
    }

    match method {
        Method::GET => {
            state.get_count += 1;
            Ok(observation_response(&state))
        }
        Method::POST => {
            let operation: Value = serde_json::from_slice(&body)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let desired = operation["desired_replicas"]
                .as_u64()
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "scale operation is missing desired_replicas",
                    )
                })?;
            let expected_revision = operation["expected_revision"]
                .as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "scale operation is missing expected_revision",
                    )
                })?;
            if expected_revision != state.revision {
                return Ok(json_response(
                    StatusCode::CONFLICT,
                    json!({ "error": "stale revision" }),
                ));
            }
            state.post_count += 1;
            state.replicas = desired;
            state.revision += 1;
            if state.fail_next_post_after_apply {
                state.fail_next_post_after_apply = false;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "fixture dropped the response after persisting desired replicas",
                ));
            }
            Ok(json_response(
                StatusCode::OK,
                json!({
                    "accepted": true,
                    "actual_replicas": desired,
                    "revision": state.revision.to_string(),
                    "message": "accepted"
                }),
            ))
        }
        _ => Ok(json_response(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({ "error": "only GET and POST are supported" }),
        )),
    }
}

fn observation_response(state: &ScaleState) -> Response<Full<Bytes>> {
    let endpoints = if state.replicas == 0 {
        Vec::new()
    } else {
        vec![json!({
            "instance_id": "scale-api-0",
            "slot": 0,
            "url": state.endpoint_url
        })]
    };
    json_response(
        StatusCode::OK,
        json!({
            "replicas": state.replicas,
            "revision": state.revision.to_string(),
            "ready_replicas": state.replicas,
            "endpoints": endpoints
        }),
    )
}

fn json_response(status: StatusCode, body: Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CONNECTION, "close")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

struct Upstream {
    address: SocketAddr,
    server: JoinHandle<()>,
}

impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let service = service_fn(|_request: Request<Incoming>| async {
                        Ok::<_, io::Error>(Response::new(Full::new(Bytes::from_static(
                            b"box-endpoint-ready",
                        ))))
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self { address, server }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct GatewayProcess {
    child: Child,
}

impl GatewayProcess {
    fn start(config_path: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_a3s-gateway"));
        command
            .arg("--config")
            .arg(config_path)
            .arg("--log-level")
            .arg("error")
            .env("NO_PROXY", "127.0.0.1,localhost")
            .env("no_proxy", "127.0.0.1,localhost")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);
        Self {
            child: command.spawn().expect("failed to start Gateway binary"),
        }
    }

    async fn wait_for_management(&mut self, management_port: u16) {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .unwrap();
        for _ in 0..240 {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("Gateway exited before management became ready: {status}");
            }
            if let Ok(response) = client
                .get(format!(
                    "http://127.0.0.1:{management_port}/api/gateway/health"
                ))
                .send()
                .await
            {
                if response.status().is_success() {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("Gateway node API listener did not become ready");
    }

    async fn stop(mut self) {
        if self.child.try_wait().unwrap().is_none() {
            tokio::time::timeout(Duration::from_secs(3), self.child.kill())
                .await
                .expect("Gateway process termination timed out")
                .unwrap();
        }
        let _ = tokio::time::timeout(Duration::from_secs(3), self.child.wait())
            .await
            .expect("Gateway process reap timed out");
    }
}

async fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_ports_released(ports: &[u16]) {
    for _ in 0..200 {
        let mut listeners = Vec::with_capacity(ports.len());
        let mut all_available = true;
        for port in ports {
            match TcpListener::bind(("127.0.0.1", *port)).await {
                Ok(listener) => listeners.push(listener),
                Err(_) => {
                    all_available = false;
                    break;
                }
            }
        }
        if all_available {
            return;
        }
        drop(listeners);
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("Gateway listener ports were not released");
}

fn gateway_acl(traffic_port: u16, management_port: u16, box_address: SocketAddr) -> String {
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
    buffer_timeout_secs   = 15
    buffer_size           = 4
    executor              = "box"
    executor_endpoint     = "http://{box_address}"
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

async fn request_until_ready(traffic_port: u16) -> reqwest::Response {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    client
        .get(format!("http://127.0.0.1:{traffic_port}/ready"))
        .send()
        .await
        .expect("buffered Gateway request failed")
}

#[tokio::test]
async fn real_gateway_recovers_box_scale_from_zero_and_dynamic_endpoint_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let upstream = Upstream::start().await;
    let api = BoxScaleApi::start(upstream.url()).await;
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let config_path = directory.path().join("gateway.acl");
    tokio::fs::write(
        &config_path,
        gateway_acl(traffic_port, management_port, api.address),
    )
    .await
    .unwrap();

    let mut first = GatewayProcess::start(&config_path);
    first.wait_for_management(management_port).await;
    let buffered_request = tokio::spawn(request_until_ready(traffic_port));
    let recovered = api
        .wait_for(|snapshot| {
            snapshot.replicas == 1 && snapshot.post_count == 1 && snapshot.get_count >= 2
        })
        .await;
    assert_eq!(recovered.post_count, 1);
    let response = tokio::time::timeout(Duration::from_secs(20), buffered_request)
        .await
        .expect("buffered request did not resume")
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "box-endpoint-ready");

    first.stop().await;
    wait_for_ports_released(&[traffic_port, management_port]).await;

    let gets_before_restart = api.snapshot().get_count;
    let mut restarted = GatewayProcess::start(&config_path);
    restarted.wait_for_management(management_port).await;
    api.wait_for(|snapshot| snapshot.get_count > gets_before_restart)
        .await;
    let response = request_until_ready(traffic_port).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await.unwrap(), "box-endpoint-ready");
    tokio::time::sleep(Duration::from_millis(2250)).await;

    let final_state = api.snapshot();
    assert_eq!(final_state.replicas, 1);
    assert_eq!(
        final_state.post_count, 1,
        "ambiguous mutation recovery or Gateway restart issued a duplicate scale operation"
    );
    assert!(final_state.get_count >= 3);
    assert!(final_state
        .requests
        .iter()
        .all(|request| request.path == SCALE_PATH));
    assert_eq!(final_state.requests[0].method, Method::GET);
    let mutation = final_state
        .requests
        .iter()
        .find(|request| request.method == Method::POST)
        .expect("one Box scale mutation");
    let operation: Value = serde_json::from_slice(&mutation.body).unwrap();
    assert_eq!(operation["schema_version"], 1);
    assert_eq!(operation["service"], "api");
    assert_eq!(operation["current_replicas"], 0);
    assert_eq!(operation["desired_replicas"], 1);
    assert_eq!(operation["expected_revision"], "0");
    assert!(operation["operation_id"]
        .as_str()
        .unwrap()
        .starts_with("scale-v1-"));

    restarted.stop().await;
    wait_for_ports_released(&[traffic_port, management_port]).await;
}
