//! Kubernetes Scale subresource executor.

use async_trait::async_trait;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::autoscaling::v1::Scale;
use kube::api::{Api, Patch, PatchParams};

use crate::error::{GatewayError, Result};
use crate::scaling::executor::{ScaleDecision, ScaleExecutor, ScaleResult};

/// Scale executor backed by Kubernetes Deployments.
pub struct K8sScaleExecutor {
    client: kube::Client,
    namespace: String,
}

impl K8sScaleExecutor {
    /// Create a Kubernetes scale executor from the active kubeconfig or
    /// in-cluster service account.
    pub async fn new(namespace: impl Into<String>) -> Result<Self> {
        // Gateway enables both rustls providers through its dependency graph.
        // Select ring before kube builds its TLS client so programmatic use is
        // panic-free even when the CLI entrypoint did not run first.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = kube::Client::try_default().await.map_err(|error| {
            GatewayError::Scaling(format!("Failed to create Kubernetes client: {error}"))
        })?;
        Ok(Self {
            client,
            namespace: namespace.into(),
        })
    }

    #[cfg(test)]
    fn with_client(client: kube::Client, namespace: impl Into<String>) -> Self {
        Self {
            client,
            namespace: namespace.into(),
        }
    }
}

fn requested_replicas(service: &str, replicas: u32) -> Result<i32> {
    i32::try_from(replicas).map_err(|_| {
        GatewayError::Scaling(format!(
            "Requested replica count {replicas} for Deployment '{service}' exceeds Kubernetes int32 limit"
        ))
    })
}

fn response_replicas(service: &str, scale: &Scale) -> Result<u32> {
    let replicas = scale
        .spec
        .as_ref()
        .and_then(|spec| spec.replicas)
        .ok_or_else(|| {
            GatewayError::Scaling(format!(
                "Kubernetes Scale response for Deployment '{service}' does not contain spec.replicas"
            ))
        })?;

    u32::try_from(replicas).map_err(|_| {
        GatewayError::Scaling(format!(
            "Kubernetes Scale response for Deployment '{service}' contains negative replica count {replicas}"
        ))
    })
}

#[async_trait]
impl ScaleExecutor for K8sScaleExecutor {
    async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        let desired_replicas = requested_replicas(&decision.service, decision.desired_replicas)?;
        let patch = serde_json::json!({
            "spec": {
                "replicas": desired_replicas
            }
        });

        let scale = deployments
            .patch_scale(
                &decision.service,
                &PatchParams::default(),
                &Patch::Merge(&patch),
            )
            .await
            .map_err(|error| {
                GatewayError::Scaling(format!(
                    "Failed to patch Kubernetes Scale subresource for Deployment '{}' in namespace '{}': {error}",
                    decision.service, self.namespace
                ))
            })?;
        let actual_replicas = response_replicas(&decision.service, &scale)?;
        if actual_replicas != decision.desired_replicas {
            return Err(GatewayError::Scaling(format!(
                "Kubernetes Scale subresource for Deployment '{}' returned {} replicas after requesting {}",
                decision.service, actual_replicas, decision.desired_replicas
            )));
        }

        Ok(ScaleResult {
            accepted: true,
            actual_replicas,
            message: format!(
                "Kubernetes Scale subresource accepted Deployment '{}' at {} replicas",
                decision.service, actual_replicas
            ),
        })
    }

    async fn current_replicas(&self, service: &str) -> Result<u32> {
        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        let scale = deployments.get_scale(service).await.map_err(|error| {
            GatewayError::Scaling(format!(
                "Failed to get Kubernetes Scale subresource for Deployment '{service}' in namespace '{}': {error}",
                self.namespace
            ))
        })?;

        response_replicas(service, &scale)
    }

    fn name(&self) -> &str {
        "k8s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScalingConfig;
    use crate::scaling::autoscaler::{Autoscaler, ServiceMetricsSnapshot};
    use bytes::Bytes;
    use http::{Method, StatusCode};
    use http_body_util::{BodyExt, Full};
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper::{Request, Response};
    use hyper_util::rt::TokioIo;
    use serde_json::{json, Value};
    use std::collections::{HashMap, VecDeque};
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        method: Method,
        path: String,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    struct FixtureResponse {
        status: StatusCode,
        body: String,
    }

    impl FixtureResponse {
        fn json(status: StatusCode, body: Value) -> Self {
            Self {
                status,
                body: body.to_string(),
            }
        }

        fn scale(spec_replicas: Option<i32>, status_replicas: i32) -> Self {
            let mut body = json!({
                "apiVersion": "autoscaling/v1",
                "kind": "Scale",
                "metadata": {
                    "name": "api",
                    "namespace": "team-a",
                    "resourceVersion": "17"
                },
                "status": {
                    "replicas": status_replicas,
                    "selector": "app=api"
                }
            });
            if let Some(replicas) = spec_replicas {
                body["spec"] = json!({ "replicas": replicas });
            }
            Self::json(StatusCode::OK, body)
        }

        fn kube_error(status: StatusCode, message: &str) -> Self {
            Self::json(
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
    }

    struct FakeKubeApi {
        uri: http::Uri,
        requests: Arc<Mutex<Vec<RecordedRequest>>>,
        server: JoinHandle<()>,
    }

    impl FakeKubeApi {
        async fn start(responses: Vec<FixtureResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let queued_responses = Arc::new(Mutex::new(VecDeque::from(responses)));
            let server_requests = requests.clone();

            let server = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let connection_requests = server_requests.clone();
                    let connection_responses = queued_responses.clone();
                    tokio::spawn(async move {
                        let service = service_fn(move |request: Request<Incoming>| {
                            let request_log = connection_requests.clone();
                            let responses = connection_responses.clone();
                            async move {
                                let (parts, body) = request.into_parts();
                                let body = body.collect().await.unwrap().to_bytes().to_vec();
                                request_log.lock().unwrap().push(RecordedRequest {
                                    method: parts.method,
                                    path: parts.uri.path().to_string(),
                                    content_type: parts
                                        .headers
                                        .get(http::header::CONTENT_TYPE)
                                        .and_then(|value| value.to_str().ok())
                                        .map(str::to_string),
                                    body,
                                });

                                let response =
                                    responses.lock().unwrap().pop_front().unwrap_or_else(|| {
                                        FixtureResponse::kube_error(
                                            StatusCode::INTERNAL_SERVER_ERROR,
                                            "fixture response queue exhausted",
                                        )
                                    });
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(response.status)
                                        .header(http::header::CONTENT_TYPE, "application/json")
                                        .header(http::header::CONNECTION, "close")
                                        .body(Full::new(Bytes::from(response.body)))
                                        .unwrap(),
                                )
                            }
                        });
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });

            Self {
                uri: format!("http://{address}").parse().unwrap(),
                requests,
                server,
            }
        }

        fn executor(&self) -> K8sScaleExecutor {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let config = kube::Config::new(self.uri.clone());
            let client = kube::Client::try_from(config).unwrap();
            K8sScaleExecutor::with_client(client, "team-a")
        }

        fn requests(&self) -> Vec<RecordedRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for FakeKubeApi {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn decision(desired_replicas: u32) -> ScaleDecision {
        ScaleDecision {
            service: "api".to_string(),
            direction: crate::scaling::executor::ScaleDirection::Up,
            current_replicas: 1,
            desired_replicas,
            reason: "fixture load".to_string(),
        }
    }

    #[tokio::test]
    async fn current_replicas_reads_desired_count_from_scale_subresource() {
        let api = FakeKubeApi::start(vec![FixtureResponse::scale(Some(4), 2)]).await;

        let replicas = api.executor().current_replicas("api").await.unwrap();

        assert_eq!(replicas, 4);
        let requests = api.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(
            requests[0].path,
            "/apis/apps/v1/namespaces/team-a/deployments/api/scale"
        );
        assert!(requests[0].body.is_empty());
    }

    #[tokio::test]
    async fn execute_patches_scale_subresource_and_validates_response() {
        let api = FakeKubeApi::start(vec![FixtureResponse::scale(Some(5), 3)]).await;

        let result = api.executor().execute(&decision(5)).await.unwrap();

        assert!(result.accepted);
        assert_eq!(result.actual_replicas, 5);
        let requests = api.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::PATCH);
        assert_eq!(
            requests[0].path,
            "/apis/apps/v1/namespaces/team-a/deployments/api/scale"
        );
        assert_eq!(
            requests[0].content_type.as_deref(),
            Some("application/merge-patch+json")
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
            json!({ "spec": { "replicas": 5 } })
        );
    }

    #[tokio::test]
    async fn current_replicas_rejects_missing_spec_count() {
        let api = FakeKubeApi::start(vec![FixtureResponse::scale(None, 3)]).await;

        let error = api.executor().current_replicas("api").await.unwrap_err();

        assert!(error.to_string().contains("does not contain spec.replicas"));
    }

    #[tokio::test]
    async fn current_replicas_rejects_negative_spec_count() {
        let api = FakeKubeApi::start(vec![FixtureResponse::scale(Some(-1), 0)]).await;

        let error = api.executor().current_replicas("api").await.unwrap_err();

        assert!(error.to_string().contains("negative replica count"));
    }

    #[tokio::test]
    async fn execute_rejects_replica_counts_larger_than_kubernetes_int32() {
        let api = FakeKubeApi::start(Vec::new()).await;

        let error = api
            .executor()
            .execute(&decision(u32::MAX))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("exceeds Kubernetes int32"));
        assert!(api.requests().is_empty());
    }

    #[tokio::test]
    async fn execute_rejects_success_response_with_different_replica_count() {
        let api = FakeKubeApi::start(vec![FixtureResponse::scale(Some(2), 2)]).await;

        let error = api.executor().execute(&decision(3)).await.unwrap_err();

        assert!(error
            .to_string()
            .contains("returned 2 replicas after requesting 3"));
    }

    #[tokio::test]
    async fn execute_surfaces_kubernetes_api_errors_with_service_context() {
        let api = FakeKubeApi::start(vec![FixtureResponse::kube_error(
            StatusCode::FORBIDDEN,
            "deployments/scale is forbidden",
        )])
        .await;

        let error = api.executor().execute(&decision(2)).await.unwrap_err();
        let message = error.to_string();

        assert!(message.contains("api"));
        assert!(message.contains("403"));
        assert!(message.contains("deployments/scale is forbidden"));
    }

    #[tokio::test]
    async fn recreated_controller_reconciles_after_ambiguous_patch_failure() {
        let api = FakeKubeApi::start(vec![
            FixtureResponse::scale(Some(1), 1),
            FixtureResponse::kube_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "response lost after applying scale",
            ),
            FixtureResponse::scale(Some(2), 1),
        ])
        .await;
        let scaling = ScalingConfig {
            container_concurrency: 1,
            target_utilization: 1.0,
            min_replicas: 0,
            max_replicas: 5,
            scale_down_delay_secs: 0,
            ..ScalingConfig::default()
        };
        let mut configs = HashMap::new();
        configs.insert("api".to_string(), scaling);
        let recreated_configs = configs.clone();
        let mut autoscaler = Autoscaler::new(Arc::new(api.executor()), configs);
        let snapshot = ServiceMetricsSnapshot {
            service: "api".to_string(),
            healthy_backends: 1,
            in_flight: 2,
            queue_depth: 0,
        };

        let first = autoscaler.tick(|_| Some(snapshot.clone())).await;
        assert_eq!(first.len(), 1);
        assert!(first[0].is_err());

        drop(autoscaler);
        let mut recreated = Autoscaler::new(Arc::new(api.executor()), recreated_configs);
        let second = recreated.tick(|_| Some(snapshot.clone())).await;
        assert!(second.is_empty());

        let requests = api.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[1].method, Method::PATCH);
        assert_eq!(requests[2].method, Method::GET);
        assert!(requests
            .iter()
            .all(|request| request.path.ends_with("/deployments/api/scale")));
    }
}
