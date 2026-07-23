#![cfg(feature = "kube")]

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
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

const SCALE_PATH: &str = "/apis/apps/v1/namespaces/default/deployments/api/scale";

#[derive(Clone, Debug)]
struct RecordedRequest {
    method: Method,
    path: String,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ScaleSnapshot {
    replicas: i32,
    get_count: usize,
    patch_count: usize,
    requests: Vec<RecordedRequest>,
}

struct ScaleState {
    replicas: i32,
    resource_version: u64,
    fail_next_patch_after_apply: bool,
    get_count: usize,
    patch_count: usize,
    requests: Vec<RecordedRequest>,
}

struct KubernetesScaleApi {
    address: SocketAddr,
    state: Arc<Mutex<ScaleState>>,
    server: JoinHandle<()>,
}

impl KubernetesScaleApi {
    async fn start(initial_replicas: i32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(ScaleState {
            replicas: initial_replicas,
            resource_version: 1,
            fail_next_patch_after_apply: true,
            get_count: 0,
            patch_count: 0,
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
            patch_count: state.patch_count,
            requests: state.requests.clone(),
        }
    }

    async fn wait_for<F>(&self, predicate: F) -> ScaleSnapshot
    where
        F: Fn(&ScaleSnapshot) -> bool,
    {
        for _ in 0..400 {
            let snapshot = self.snapshot();
            if predicate(&snapshot) {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!(
            "Kubernetes Scale API did not reach the expected state: {:?}",
            self.snapshot()
        );
    }

    fn kubeconfig(&self) -> String {
        format!(
            r#"apiVersion: v1
kind: Config
clusters:
  - name: fixture
    cluster:
      server: http://{}
contexts:
  - name: fixture
    context:
      cluster: fixture
      namespace: default
current-context: fixture
users: []
"#,
            self.address
        )
    }
}

impl Drop for KubernetesScaleApi {
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
        return Ok(kubernetes_error(
            StatusCode::NOT_FOUND,
            &format!("unexpected fixture path {path}"),
        ));
    }

    match method {
        Method::GET => {
            state.get_count += 1;
            Ok(scale_response(state.replicas, state.resource_version))
        }
        Method::PATCH => {
            let patch: Value = serde_json::from_slice(&body)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let desired = patch
                .pointer("/spec/replicas")
                .and_then(Value::as_i64)
                .and_then(|replicas| i32::try_from(replicas).ok())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Scale patch is missing an int32 spec.replicas",
                    )
                })?;
            state.patch_count += 1;
            state.replicas = desired;
            state.resource_version += 1;

            if state.fail_next_patch_after_apply {
                state.fail_next_patch_after_apply = false;
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "fixture dropped the response after applying the Scale patch",
                ));
            }

            Ok(scale_response(state.replicas, state.resource_version))
        }
        _ => Ok(kubernetes_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "only GET and PATCH are supported",
        )),
    }
}

fn scale_response(replicas: i32, resource_version: u64) -> Response<Full<Bytes>> {
    json_response(
        StatusCode::OK,
        json!({
            "apiVersion": "autoscaling/v1",
            "kind": "Scale",
            "metadata": {
                "name": "api",
                "namespace": "default",
                "resourceVersion": resource_version.to_string()
            },
            "spec": {
                "replicas": replicas
            },
            "status": {
                "replicas": replicas,
                "selector": "app=api"
            }
        }),
    )
}

fn kubernetes_error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json_response(
        status,
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "message": message,
            "reason": status.canonical_reason().unwrap_or("Error"),
            "code": status.as_u16()
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

struct GatewayProcess {
    child: Child,
}

impl GatewayProcess {
    fn start(config_path: &Path, kubeconfig_path: &Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_a3s-gateway"));
        command
            .arg("--config")
            .arg(config_path)
            .arg("--log-level")
            .arg("error")
            .env("KUBECONFIG", kubeconfig_path)
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
        panic!("Gateway management listener did not become ready");
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

fn gateway_acl(traffic_port: u16, management_port: u16) -> String {
    format!(
        r#"
mode {{ kind = "standalone" }}

entrypoints "web" {{
  address = "127.0.0.1:{traffic_port}"
}}

services "api" {{
  load_balancer {{
    servers = [
      {{ url = "http://127.0.0.1:9" }}
    ]
  }}

  scaling {{
    min_replicas          = 1
    max_replicas          = 3
    container_concurrency = 1
    target_utilization    = 1.0
    scale_down_delay_secs = 0
    buffer_enabled        = false
    executor              = "k8s"
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
"#
    )
}

async fn write_fixture_files(
    directory: &Path,
    api: &KubernetesScaleApi,
    traffic_port: u16,
    management_port: u16,
) -> (PathBuf, PathBuf) {
    let config_path = directory.join("gateway.acl");
    let kubeconfig_path = directory.join("kubeconfig.yaml");
    tokio::fs::write(&config_path, gateway_acl(traffic_port, management_port))
        .await
        .unwrap();
    tokio::fs::write(&kubeconfig_path, api.kubeconfig())
        .await
        .unwrap();
    (config_path, kubeconfig_path)
}

#[tokio::test]
async fn real_gateway_reconciles_ambiguous_kubernetes_scale_across_process_restart() {
    let directory = tempfile::tempdir().unwrap();
    let api = KubernetesScaleApi::start(0).await;
    let traffic_port = free_port().await;
    let management_port = free_port().await;
    let (config_path, kubeconfig_path) =
        write_fixture_files(directory.path(), &api, traffic_port, management_port).await;

    let mut first = GatewayProcess::start(&config_path, &kubeconfig_path);
    first.wait_for_management(management_port).await;
    let recovered = api
        .wait_for(|snapshot| {
            snapshot.replicas == 1 && snapshot.patch_count == 1 && snapshot.get_count >= 2
        })
        .await;
    assert_eq!(recovered.patch_count, 1);
    first.stop().await;
    wait_for_ports_released(&[traffic_port, management_port]).await;

    let gets_before_restart = api.snapshot().get_count;
    let mut restarted = GatewayProcess::start(&config_path, &kubeconfig_path);
    restarted.wait_for_management(management_port).await;
    api.wait_for(|snapshot| snapshot.get_count > gets_before_restart)
        .await;
    tokio::time::sleep(Duration::from_millis(2250)).await;

    let final_state = api.snapshot();
    assert_eq!(final_state.replicas, 1);
    assert_eq!(
        final_state.patch_count, 1,
        "reconciliation or process restart issued a duplicate Scale patch"
    );
    assert!(final_state.get_count >= 3);
    assert!(final_state
        .requests
        .iter()
        .all(|request| request.path == SCALE_PATH));
    assert_eq!(final_state.requests[0].method, Method::GET);
    assert_eq!(final_state.requests[1].method, Method::PATCH);
    assert_eq!(
        serde_json::from_slice::<Value>(&final_state.requests[1].body).unwrap(),
        json!({ "spec": { "replicas": 1 } })
    );
    assert!(final_state.requests[2..]
        .iter()
        .all(|request| request.method == Method::GET));

    restarted.stop().await;
    wait_for_ports_released(&[traffic_port, management_port]).await;
}
