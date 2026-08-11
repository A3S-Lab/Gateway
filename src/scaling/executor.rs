//! Scale executor — trait and implementations for executing scaling decisions
//!
//! Provides the `ScaleExecutor` async trait with three implementations:
//! - `BoxScaleExecutor` — calls the A3S Box Scale API over HTTP (always compiled)
//! - `MockScaleExecutor` — records decisions in memory (for tests)
//! - `K8sScaleExecutor` — updates Kubernetes Scale subresources (feature-gated behind `kube`)

#![allow(dead_code)]
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

use crate::error::{GatewayError, Result};

/// Direction of a scaling operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScaleDirection {
    Up,
    Down,
}

impl std::fmt::Display for ScaleDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Up => write!(f, "up"),
            Self::Down => write!(f, "down"),
        }
    }
}

/// A scaling decision emitted by the autoscaler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaleDecision {
    /// Version of the scale-operation contract.
    pub schema_version: u32,
    /// Stable idempotency identity for this observed-state transition.
    pub operation_id: String,
    /// Service being scaled
    pub service: String,
    /// Executor revision observed before making the decision, when available.
    pub expected_revision: Option<String>,
    /// Direction of scaling
    pub direction: ScaleDirection,
    /// Current replica count
    pub current_replicas: u32,
    /// Desired replica count
    pub desired_replicas: u32,
    /// Human-readable reason for the decision
    pub reason: String,
}

/// Result of executing a scaling decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScaleResult {
    /// Whether the executor accepted the decision
    pub accepted: bool,
    /// Actual replica count after execution
    pub actual_replicas: u32,
    /// Executor revision after the operation, when available.
    #[serde(default)]
    pub revision: Option<String>,
    /// Optional message from the executor
    pub message: String,
}

/// Authoritative replica state observed from an executor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicaState {
    /// Desired replica count reported by the orchestrator.
    pub replicas: u32,
    /// Opaque concurrency revision used for conditional mutation.
    pub revision: Option<String>,
}

/// Async trait for executing scaling decisions against a backend orchestrator
#[async_trait]
pub trait ScaleExecutor: Send + Sync {
    /// Execute a scaling decision
    async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult>;

    /// Query the current replica count for a service
    async fn current_replicas(&self, service: &str) -> Result<ReplicaState>;

    /// Executor name (for logging)
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// BoxScaleExecutor — calls A3S Box Scale API over HTTP
// ---------------------------------------------------------------------------

/// Scale executor that calls the A3S Box Scale API
pub struct BoxScaleExecutor {
    /// Base URL of the Box Scale API (e.g., "http://localhost:9090")
    base_url: String,
    /// HTTP client
    client: reqwest::Client,
}

impl BoxScaleExecutor {
    /// Create a new Box scale executor
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl ScaleExecutor for BoxScaleExecutor {
    async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
        let url = format!("{}/v1/scale/{}", self.base_url, decision.service);
        let resp = self
            .client
            .post(&url)
            .json(decision)
            .send()
            .await
            .map_err(|e| {
                GatewayError::Scaling(format!(
                    "Box scale API request failed for '{}': {}",
                    decision.service, e
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Scaling(format!(
                "Box scale API returned {} for '{}': {}",
                status, decision.service, body
            )));
        }

        resp.json::<ScaleResult>().await.map_err(|e| {
            GatewayError::Scaling(format!(
                "Failed to parse Box scale API response for '{}': {}",
                decision.service, e
            ))
        })
    }

    async fn current_replicas(&self, service: &str) -> Result<ReplicaState> {
        let url = format!("{}/v1/scale/{}", self.base_url, service);
        let resp = self.client.get(&url).send().await.map_err(|e| {
            GatewayError::Scaling(format!(
                "Box scale API query failed for '{}': {}",
                service, e
            ))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Scaling(format!(
                "Box scale API returned {} for '{}': {}",
                status, service, body
            )));
        }

        #[derive(Deserialize)]
        struct ReplicaResponse {
            replicas: u32,
            #[serde(default)]
            revision: Option<String>,
        }

        let result = resp.json::<ReplicaResponse>().await.map_err(|e| {
            GatewayError::Scaling(format!(
                "Failed to parse replica response for '{}': {}",
                service, e
            ))
        })?;

        Ok(ReplicaState {
            replicas: result.replicas,
            revision: result.revision,
        })
    }

    fn name(&self) -> &str {
        "box"
    }
}

// ---------------------------------------------------------------------------
// MockScaleExecutor — records decisions for testing
// ---------------------------------------------------------------------------

/// Mock scale executor that records decisions in memory (test-only)
pub(crate) struct MockScaleExecutor {
    /// Recorded decisions
    decisions: Arc<Mutex<Vec<ScaleDecision>>>,
    /// Simulated current replicas per service
    replicas: Arc<Mutex<std::collections::HashMap<String, u32>>>,
}

impl MockScaleExecutor {
    /// Create a new mock executor
    pub(crate) fn new() -> Self {
        Self {
            decisions: Arc::new(Mutex::new(Vec::new())),
            replicas: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Get all recorded decisions
    pub(crate) fn decisions(&self) -> Vec<ScaleDecision> {
        self.decisions.lock().unwrap().clone()
    }

    /// Set the simulated replica count for a service
    pub(crate) fn set_replicas(&self, service: &str, count: u32) {
        self.replicas
            .lock()
            .unwrap()
            .insert(service.to_string(), count);
    }
}

impl Default for MockScaleExecutor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ScaleExecutor for MockScaleExecutor {
    async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
        self.decisions.lock().unwrap().push(decision.clone());
        self.replicas
            .lock()
            .unwrap()
            .insert(decision.service.clone(), decision.desired_replicas);

        Ok(ScaleResult {
            accepted: true,
            actual_replicas: decision.desired_replicas,
            revision: decision.expected_revision.clone(),
            message: format!(
                "Mock: scaled '{}' to {} replicas",
                decision.service, decision.desired_replicas
            ),
        })
    }

    async fn current_replicas(&self, service: &str) -> Result<ReplicaState> {
        Ok(ReplicaState {
            replicas: *self.replicas.lock().unwrap().get(service).unwrap_or(&0),
            revision: None,
        })
    }

    fn name(&self) -> &str {
        "mock"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_http_request(stream: &mut tokio::net::TcpStream) -> String {
        use tokio::io::AsyncReadExt;

        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(read > 0, "client closed before completing HTTP request");
            bytes.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&bytes);
            let Some(header_end) = text.find("\r\n\r\n") else {
                continue;
            };
            let content_length = text[..header_end]
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= header_end + 4 + content_length {
                return String::from_utf8(bytes).unwrap();
            }
        }
    }

    async fn write_json_response(stream: &mut tokio::net::TcpStream, body: &str) {
        use tokio::io::AsyncWriteExt;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    #[test]
    fn test_scale_direction_display() {
        assert_eq!(ScaleDirection::Up.to_string(), "up");
        assert_eq!(ScaleDirection::Down.to_string(), "down");
    }

    #[test]
    fn test_scale_decision_serialization() {
        let decision = ScaleDecision {
            schema_version: 1,
            operation_id: "scale-v1-test".into(),
            service: "api".into(),
            expected_revision: Some("7".into()),
            direction: ScaleDirection::Up,
            current_replicas: 1,
            desired_replicas: 3,
            reason: "high load".into(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: ScaleDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, 1);
        assert_eq!(parsed.operation_id, "scale-v1-test");
        assert_eq!(parsed.service, "api");
        assert_eq!(parsed.expected_revision.as_deref(), Some("7"));
        assert_eq!(parsed.direction, ScaleDirection::Up);
        assert_eq!(parsed.current_replicas, 1);
        assert_eq!(parsed.desired_replicas, 3);
        assert_eq!(parsed.reason, "high load");
    }

    #[test]
    fn test_scale_result_serialization() {
        let result = ScaleResult {
            accepted: true,
            actual_replicas: 5,
            revision: Some("8".into()),
            message: "ok".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ScaleResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.accepted);
        assert_eq!(parsed.actual_replicas, 5);
        assert_eq!(parsed.revision.as_deref(), Some("8"));
    }

    #[tokio::test]
    async fn test_mock_records_decisions() {
        let mock = MockScaleExecutor::new();
        let decision = ScaleDecision {
            schema_version: 1,
            operation_id: "scale-v1-test".into(),
            service: "api".into(),
            expected_revision: None,
            direction: ScaleDirection::Up,
            current_replicas: 1,
            desired_replicas: 3,
            reason: "test".into(),
        };

        let result = mock.execute(&decision).await.unwrap();
        assert!(result.accepted);
        assert_eq!(result.actual_replicas, 3);

        let decisions = mock.decisions();
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].service, "api");
    }

    #[tokio::test]
    async fn test_mock_returns_replicas() {
        let mock = MockScaleExecutor::new();
        assert_eq!(mock.current_replicas("api").await.unwrap().replicas, 0);

        mock.set_replicas("api", 5);
        assert_eq!(mock.current_replicas("api").await.unwrap().replicas, 5);
    }

    #[tokio::test]
    async fn test_mock_execute_updates_replicas() {
        let mock = MockScaleExecutor::new();
        let decision = ScaleDecision {
            schema_version: 1,
            operation_id: "scale-v1-test".into(),
            service: "web".into(),
            expected_revision: None,
            direction: ScaleDirection::Up,
            current_replicas: 0,
            desired_replicas: 2,
            reason: "scale up".into(),
        };

        mock.execute(&decision).await.unwrap();
        assert_eq!(mock.current_replicas("web").await.unwrap().replicas, 2);
    }

    #[test]
    fn test_mock_executor_name() {
        let mock = MockScaleExecutor::new();
        assert_eq!(mock.name(), "mock");
    }

    #[test]
    fn test_box_executor_name() {
        let executor = BoxScaleExecutor::new("http://localhost:9090");
        assert_eq!(executor.name(), "box");
    }

    #[tokio::test]
    async fn box_executor_matches_box_scale_v1_wire_contract() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut mutation, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut mutation).await;
            assert!(request.starts_with("POST /v1/scale/api HTTP/1.1"));
            let body = request.split_once("\r\n\r\n").unwrap().1;
            let operation: serde_json::Value = serde_json::from_str(body).unwrap();
            assert_eq!(operation["schema_version"], 1);
            assert_eq!(operation["operation_id"], "scale-v1-contract");
            assert_eq!(operation["service"], "api");
            assert_eq!(operation["expected_revision"], "0");
            assert_eq!(operation["direction"], "Up");
            assert_eq!(operation["current_replicas"], 0);
            assert_eq!(operation["desired_replicas"], 2);
            write_json_response(
                &mut mutation,
                r#"{"accepted":true,"actual_replicas":2,"revision":"1","message":"accepted"}"#,
            )
            .await;

            let (mut observation, _) = listener.accept().await.unwrap();
            let request = read_http_request(&mut observation).await;
            assert!(request.starts_with("GET /v1/scale/api HTTP/1.1"));
            write_json_response(&mut observation, r#"{"replicas":2,"revision":"1"}"#).await;
        });

        let executor = BoxScaleExecutor::new(format!("http://{address}/"));
        let result = executor
            .execute(&ScaleDecision {
                schema_version: 1,
                operation_id: "scale-v1-contract".into(),
                service: "api".into(),
                expected_revision: Some("0".into()),
                direction: ScaleDirection::Up,
                current_replicas: 0,
                desired_replicas: 2,
                reason: "contract test".into(),
            })
            .await
            .unwrap();
        assert_eq!(result.actual_replicas, 2);
        assert_eq!(result.revision.as_deref(), Some("1"));
        assert_eq!(executor.current_replicas("api").await.unwrap().replicas, 2);
        server.await.unwrap();
    }

    #[test]
    fn test_executor_trait_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<MockScaleExecutor>();
        assert_send_sync::<BoxScaleExecutor>();
    }

    #[test]
    fn test_mock_default() {
        let mock = MockScaleExecutor::default();
        assert!(mock.decisions().is_empty());
    }

    #[tokio::test]
    async fn test_mock_multiple_services() {
        let mock = MockScaleExecutor::new();
        mock.set_replicas("api", 3);
        mock.set_replicas("web", 5);

        assert_eq!(mock.current_replicas("api").await.unwrap().replicas, 3);
        assert_eq!(mock.current_replicas("web").await.unwrap().replicas, 5);
        assert_eq!(mock.current_replicas("unknown").await.unwrap().replicas, 0);
    }

    #[tokio::test]
    async fn test_mock_records_multiple_decisions() {
        let mock = MockScaleExecutor::new();

        for i in 0..3 {
            let decision = ScaleDecision {
                schema_version: 1,
                operation_id: format!("scale-v1-test-{i}"),
                service: format!("svc-{}", i),
                expected_revision: None,
                direction: ScaleDirection::Up,
                current_replicas: 0,
                desired_replicas: i + 1,
                reason: "test".into(),
            };
            mock.execute(&decision).await.unwrap();
        }

        assert_eq!(mock.decisions().len(), 3);
    }

    #[test]
    fn test_scale_direction_eq() {
        assert_eq!(ScaleDirection::Up, ScaleDirection::Up);
        assert_ne!(ScaleDirection::Up, ScaleDirection::Down);
    }
}
