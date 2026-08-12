//! Real-cluster conformance for the Kubernetes Scale executor.
//!
//! The ordinary unit suite uses an in-process API fixture. This ignored gate
//! exercises the same controller against an actual Kubernetes API server and
//! is enabled only by the dedicated CI job.

use super::autoscaler::{Autoscaler, ServiceMetricsSnapshot};
use super::executor::{ScaleDecision, ScaleDirection, ScaleExecutor};
use super::kubernetes_executor::K8sScaleExecutor;
use crate::config::ScalingConfig;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, DeleteParams, PostParams};
use kube::Client;
use serde_json::json;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::sync::Arc;
use uuid::Uuid;

const ENABLE_ENV: &str = "A3S_GATEWAY_TEST_KUBERNETES";
const DEPLOYMENT_NAME: &str = "a3s-scale-conformance";

type ConformanceResult<T = ()> = std::result::Result<T, Box<dyn Error + Send + Sync + 'static>>;

#[tokio::test]
#[ignore = "requires a real Kubernetes cluster and an active kubeconfig"]
async fn real_cluster_enforces_scale_cas_and_recovers_controller_state() {
    assert_eq!(
        std::env::var(ENABLE_ENV).as_deref(),
        Ok("1"),
        "set {ENABLE_ENV}=1 only in the dedicated real-cluster gate"
    );

    let client = Client::try_default()
        .await
        .expect("real-cluster gate requires an active kubeconfig");
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let namespace = format!("a3s-gateway-scale-{}", Uuid::new_v4().simple());
    let namespace_resource =
        namespace_fixture(&namespace).expect("namespace fixture must match the Kubernetes schema");
    namespaces
        .create(&PostParams::default(), &namespace_resource)
        .await
        .expect("create isolated Kubernetes conformance namespace");

    let result = exercise_scale_contract(client, &namespace).await;
    let cleanup = namespaces
        .delete(&namespace, &DeleteParams::background())
        .await;

    if let Err(error) = cleanup {
        if result.is_ok() {
            panic!("delete Kubernetes conformance namespace {namespace}: {error}");
        }
        eprintln!(
            "Kubernetes conformance failed and namespace cleanup also failed for {namespace}: {error}"
        );
    }

    if let Err(error) = result {
        panic!("real Kubernetes Scale conformance failed: {error}");
    }
}

async fn exercise_scale_contract(client: Client, namespace: &str) -> ConformanceResult {
    let deployments: Api<Deployment> = Api::namespaced(client, namespace);
    deployments
        .create(&PostParams::default(), &deployment_fixture()?)
        .await?;

    let executor = Arc::new(K8sScaleExecutor::new(namespace).await?);
    let initial = executor.current_replicas(DEPLOYMENT_NAME).await?;
    require(
        initial.replicas == 1,
        format!(
            "initial Scale replica count was {}, expected 1",
            initial.replicas
        ),
    )?;
    let initial_revision = initial.revision.clone().ok_or_else(|| {
        conformance_error("initial Kubernetes Scale response omitted resourceVersion")
    })?;

    let config = ScalingConfig {
        min_replicas: 1,
        max_replicas: 4,
        container_concurrency: 1,
        target_utilization: 1.0,
        scale_down_delay_secs: 0,
        ..ScalingConfig::default()
    };
    let mut configs = HashMap::new();
    configs.insert(DEPLOYMENT_NAME.to_string(), config.clone());
    let mut autoscaler = Autoscaler::new(executor.clone(), configs);

    let scale_up = autoscaler.tick(|service| Some(metrics(service, 3))).await;
    require_one_success(&scale_up, "scale from one to three")?;

    let scaled = executor.current_replicas(DEPLOYMENT_NAME).await?;
    require(
        scaled.replicas == 3,
        format!("scaled replica count was {}, expected 3", scaled.replicas),
    )?;
    require(
        scaled.revision.as_deref() != Some(initial_revision.as_str()),
        "Kubernetes Scale resourceVersion did not advance after mutation",
    )?;

    let stale = ScaleDecision {
        schema_version: 1,
        operation_id: "real-cluster-stale-scale".to_string(),
        service: DEPLOYMENT_NAME.to_string(),
        expected_revision: Some(initial_revision),
        direction: ScaleDirection::Down,
        current_replicas: 3,
        desired_replicas: 2,
        reason: "prove stale Kubernetes resourceVersion rejection".to_string(),
    };
    let stale_error = match executor.execute(&stale).await {
        Ok(result) => {
            return Err(conformance_error(format!(
                "stale Kubernetes resourceVersion unexpectedly changed Scale state: {result:?}"
            )));
        }
        Err(error) => error,
    };
    let stale_message = stale_error.to_string();
    require(
        stale_message.contains("409") || stale_message.contains("Conflict"),
        format!("stale Scale mutation did not surface a conflict: {stale_message}"),
    )?;
    require(
        executor.current_replicas(DEPLOYMENT_NAME).await?.replicas == 3,
        "stale Scale mutation changed the Deployment replica count",
    )?;

    let mut recreated_configs = HashMap::new();
    recreated_configs.insert(DEPLOYMENT_NAME.to_string(), config);
    let mut recreated = Autoscaler::new(executor.clone(), recreated_configs);
    let recovered = recreated.tick(|service| Some(metrics(service, 3))).await;
    require(
        recovered.is_empty(),
        format!(
            "recreated autoscaler emitted a duplicate mutation: {} result(s)",
            recovered.len()
        ),
    )?;

    let scale_down = recreated.tick(|service| Some(metrics(service, 1))).await;
    require_one_success(&scale_down, "scale from three to one")?;
    require(
        executor.current_replicas(DEPLOYMENT_NAME).await?.replicas == 1,
        "Kubernetes Scale adapter did not converge back to one replica",
    )?;

    Ok(())
}

fn namespace_fixture(name: &str) -> ConformanceResult<Namespace> {
    Ok(serde_json::from_value(json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": { "name": name }
    }))?)
}

fn deployment_fixture() -> ConformanceResult<Deployment> {
    Ok(serde_json::from_value(json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": { "name": DEPLOYMENT_NAME },
        "spec": {
            "replicas": 1,
            "selector": { "matchLabels": { "app": DEPLOYMENT_NAME } },
            "template": {
                "metadata": { "labels": { "app": DEPLOYMENT_NAME } },
                "spec": {
                    "containers": [{
                        "name": "pause",
                        "image": "registry.k8s.io/pause:3.10",
                        "imagePullPolicy": "IfNotPresent"
                    }]
                }
            }
        }
    }))?)
}

fn metrics(service: &str, in_flight: usize) -> ServiceMetricsSnapshot {
    ServiceMetricsSnapshot {
        service: service.to_string(),
        healthy_backends: 1,
        in_flight,
        queue_depth: 0,
    }
}

fn require_one_success(results: &[crate::error::Result<()>], operation: &str) -> ConformanceResult {
    require(
        results.len() == 1,
        format!(
            "{operation} produced {} controller result(s), expected one",
            results.len()
        ),
    )?;
    if let Err(error) = &results[0] {
        return Err(conformance_error(format!("{operation} failed: {error}")));
    }
    Ok(())
}

fn require(condition: bool, message: impl Into<String>) -> ConformanceResult {
    if condition {
        Ok(())
    } else {
        Err(conformance_error(message))
    }
}

fn conformance_error(message: impl Into<String>) -> Box<dyn Error + Send + Sync + 'static> {
    Box::new(io::Error::other(message.into()))
}
