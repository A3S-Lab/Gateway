//! Native inference request handling.

mod access_error;
mod authorization;
mod distributed_serving;
mod identity;
mod limits;
mod openai_request;
mod scheduling;

pub(crate) use access_error::InferenceAccessError;
pub(crate) use authorization::{
    AuthenticatedInference, InferenceAdmissionGuard, InferenceAuthorizer, InferenceDispatchTarget,
};
pub(crate) use distributed_serving::{
    DistributedExecutionRequest, DistributedInferenceResponse, DistributedServingError,
    DistributedServingOrchestrator, DistributedWorkerEndpoint, ProtocolBinding,
};
pub(crate) use identity::{InferenceAttemptIdentity, InferenceRequestIdentity};
#[cfg(test)]
pub(crate) use identity::{ATTEMPT_ID_HEADER, REQUEST_ID_HEADER};
pub(crate) use openai_request::{
    collect_json_body, collect_proxy_json_body, models_response, valid_model_alias,
    OpenAiJsonRequest, OpenAiRequestProfile,
};
pub(crate) use scheduling::{
    InferenceWorkerCandidate, InferenceWorkerPairSelection, InferenceWorkerPairSelectionRequest,
    InferenceWorkerSelection, InferenceWorkerSelectionRequest,
};
