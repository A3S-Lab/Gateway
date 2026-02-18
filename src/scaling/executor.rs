//! Scale executor — trait and implementations for executing scaling decisions
//!
//! Provides the `ScaleExecutor` async trait with three implementations:
//! - `BoxScaleExecutor` — calls the A3S Box Scale API over HTTP (always compiled)
//! - `MockScaleExecutor` — records decisions in memory (for tests)
//! - `K8sScaleExecutor` — patches Kubernetes deployments (feature-gated behind `kube`)

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
    /// Service being scaled
    pub service: String,
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
    /// Optional message from the executor
    pub message: String,
}

/// Async trait for executing scaling decisions against a backend orchestrator
#[async_trait]
pub trait ScaleExecutor: Send + Sync {
    /// Execute a scaling decision
    async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult>;

    /// Query the current replica count for a service
    async fn current_replicas(&self, service: &str) -> Result<u32>;

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
            base_url: base_url.into(),
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

    async fn current_replicas(&self, service: &str) -> Result<u32> {
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
        }

        let result = resp.json::<ReplicaResponse>().await.map_err(|e| {
            GatewayError::Scaling(format!(
                "Failed to parse replica response for '{}': {}",
                service, e
            ))
        })?;

        Ok(result.replicas)
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
            message: format!(
                "Mock: scaled '{}' to {} replicas",
                decision.service, decision.desired_replicas
            ),
        })
    }

    async fn current_replicas(&self, service: &str) -> Result<u32> {
        Ok(*self
            .replicas
            .lock()
            .unwrap()
            .get(service)
            .unwrap_or(&0))
    }

    fn name(&self) -> &str {
        "mock"
    }
}

// ---------------------------------------------------------------------------
// K8sScaleExecutor — patches Kubernetes deployments (feature-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "kube")]
pub struct K8sScaleExecutor {
    client: kube::Client,
    namespace: String,
}

#[cfg(feature = "kube")]
impl K8sScaleExecutor {
    /// Create a new K8s scale executor
    pub async fn new(namespace: impl Into<String>) -> Result<Self> {
        let client = kube::Client::try_default().await.map_err(|e| {
            GatewayError::Scaling(format!("Failed to create Kubernetes client: {}", e))
        })?;
        Ok(Self {
            client,
            namespace: namespace.into(),
        })
    }
}

#[cfg(feature = "kube")]
#[async_trait]
impl ScaleExecutor for K8sScaleExecutor {
    async fn execute(&self, decision: &ScaleDecision) -> Result<ScaleResult> {
        use k8s_openapi::api::apps::v1::Deployment;
        use kube::api::{Api, Patch, PatchParams};

        let deployments: Api<Deployment> =
            Api::namespaced(self.client.clone(), &self.namespace);

        let patch = serde_json::json!({
            "spec": {
                "replicas": decision.desired_replicas
            }
        });

        deployments
            .patch(
                &decision.service,
                &PatchParams::apply("a3s-gateway"),
                &Patch::Merge(&patch),
            )
            .await
            .map_err(|e| {
                GatewayError::Scaling(format!(
                    "Failed to patch deployment '{}': {}",
                    decision.service, e
                ))
            })?;

        Ok(ScaleResult {
            accepted: true,
            actual_replicas: decision.desired_replicas,
            message: format!(
                "K8s: scaled deployment '{}' to {} replicas",
                decision.service, decision.desired_replicas
            ),
        })
    }

    async fn current_replicas(&self, service: &str) -> Result<u32> {
        use k8s_openapi::api::apps::v1::Deployment;
        use kube::api::Api;

        let deployments: Api<Deployment> =
            Api::namespaced(self.client.clone(), &self.namespace);

        let deploy = deployments.get(service).await.map_err(|e| {
            GatewayError::Scaling(format!(
                "Failed to get deployment '{}': {}",
                service, e
            ))
        })?;

        Ok(deploy
            .spec
            .and_then(|s| s.replicas)
            .unwrap_or(0) as u32)
    }

    fn name(&self) -> &str {
        "k8s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scale_direction_display() {
        assert_eq!(ScaleDirection::Up.to_string(), "up");
        assert_eq!(ScaleDirection::Down.to_string(), "down");
    }

    #[test]
    fn test_scale_decision_serialization() {
        let decision = ScaleDecision {
            service: "api".into(),
            direction: ScaleDirection::Up,
            current_replicas: 1,
            desired_replicas: 3,
            reason: "high load".into(),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let parsed: ScaleDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.service, "api");
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
            message: "ok".into(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ScaleResult = serde_json::from_str(&json).unwrap();
        assert!(parsed.accepted);
        assert_eq!(parsed.actual_replicas, 5);
    }

    #[tokio::test]
    async fn test_mock_records_decisions() {
        let mock = MockScaleExecutor::new();
        let decision = ScaleDecision {
            service: "api".into(),
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
        assert_eq!(mock.current_replicas("api").await.unwrap(), 0);

        mock.set_replicas("api", 5);
        assert_eq!(mock.current_replicas("api").await.unwrap(), 5);
    }

    #[tokio::test]
    async fn test_mock_execute_updates_replicas() {
        let mock = MockScaleExecutor::new();
        let decision = ScaleDecision {
            service: "web".into(),
            direction: ScaleDirection::Up,
            current_replicas: 0,
            desired_replicas: 2,
            reason: "scale up".into(),
        };

        mock.execute(&decision).await.unwrap();
        assert_eq!(mock.current_replicas("web").await.unwrap(), 2);
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

        assert_eq!(mock.current_replicas("api").await.unwrap(), 3);
        assert_eq!(mock.current_replicas("web").await.unwrap(), 5);
        assert_eq!(mock.current_replicas("unknown").await.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_mock_records_multiple_decisions() {
        let mock = MockScaleExecutor::new();

        for i in 0..3 {
            let decision = ScaleDecision {
                service: format!("svc-{}", i),
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
