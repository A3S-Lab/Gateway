//! Native inference request handling.

mod access_error;
mod authorization;
mod distributed_serving;
mod identity;
mod limits;
mod openai_request;
mod scheduling;
mod token_reconcile;
mod tokenizer;

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
    OpenAiJsonRequest, OpenAiRequestError, OpenAiRequestProfile, OPENAI_REQUEST_BODY_LIMIT,
};
pub(crate) use scheduling::{
    InferenceWorkerCandidate, InferenceWorkerPairSelection, InferenceWorkerPairSelectionRequest,
    InferenceWorkerSelection, InferenceWorkerSelectionRequest,
};
pub(crate) use token_reconcile::track_token_budget_response;
