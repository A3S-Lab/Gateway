//! Drop-safe cleanup for Power distributed-serving executions.

use super::client::{PowerClientError, PowerDistributedClient};
use super::contract::{AbortExecutionRequest, ProtocolBinding, DISTRIBUTED_SERVING_SCHEMA};
use super::orchestrator::{DistributedServingError, DistributedWorkerEndpoint};
use std::time::Duration;
use tokio::time::Instant;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct CleanupTarget {
    url: String,
    binding: ProtocolBinding,
}

pub(super) struct ExecutionCleanup {
    client: PowerDistributedClient,
    api_key_env: String,
    prefill: CleanupTarget,
    decode: CleanupTarget,
    armed: bool,
}

impl ExecutionCleanup {
    pub(super) fn new(
        client: PowerDistributedClient,
        api_key_env: String,
        prefill: DistributedWorkerEndpoint,
        decode: DistributedWorkerEndpoint,
    ) -> Self {
        Self {
            client,
            api_key_env,
            prefill: CleanupTarget {
                url: prefill.url,
                binding: prefill.binding,
            },
            decode: CleanupTarget {
                url: decode.url,
                binding: decode.binding,
            },
            armed: true,
        }
    }

    pub(super) async fn fail<T>(
        mut self,
        error: DistributedServingError,
    ) -> Result<T, DistributedServingError> {
        self.abort_all().await;
        Err(error)
    }

    pub(super) async fn finish(mut self) {
        self.abort_all().await;
    }

    async fn abort_all(&mut self) {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let prefill = abort_target(&self.client, &self.api_key_env, deadline, &self.prefill);
        let decode = abort_target(&self.client, &self.api_key_env, deadline, &self.decode);
        let _ = tokio::join!(prefill, decode);
        self.armed = false;
    }

    fn spawn_abort(&self) {
        let client = self.client.clone();
        let api_key_env = self.api_key_env.clone();
        let prefill = self.prefill.clone();
        let decode = self.decode.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let deadline = Instant::now() + CLEANUP_TIMEOUT;
                let _ = tokio::join!(
                    abort_target(&client, &api_key_env, deadline, &prefill),
                    abort_target(&client, &api_key_env, deadline, &decode)
                );
            });
        }
    }
}

impl Drop for ExecutionCleanup {
    fn drop(&mut self) {
        if self.armed {
            self.spawn_abort();
        }
    }
}

async fn abort_target(
    client: &PowerDistributedClient,
    api_key_env: &str,
    deadline: Instant,
    target: &CleanupTarget,
) -> Result<(), PowerClientError> {
    client
        .abort(
            &target.url,
            api_key_env,
            deadline,
            &AbortExecutionRequest {
                schema: DISTRIBUTED_SERVING_SCHEMA,
                execution_id: target.binding.execution_id,
                worker_epoch: target.binding.worker_epoch,
                execution_profile_sha256: target.binding.execution_profile_sha256.clone(),
            },
            &target.binding,
        )
        .await
}
