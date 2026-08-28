//! Gateway-owned prefill/decode orchestration over Power's internal protocol.

mod cleanup;
mod client;
mod contract;
mod orchestrator;
mod response;

pub(crate) use contract::ProtocolBinding;
pub(crate) use orchestrator::{
    DistributedExecutionRequest, DistributedInferenceResponse, DistributedServingError,
    DistributedServingOrchestrator, DistributedWorkerEndpoint,
};

#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod contract_tests;
#[cfg(test)]
mod orchestrator_tests;
#[cfg(test)]
mod response_tests;
