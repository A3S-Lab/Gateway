//! Native inference request handling.

mod access_error;
mod authorization;
mod identity;
mod limits;
mod openai_request;

pub(crate) use access_error::InferenceAccessError;
pub(crate) use authorization::{
    AuthenticatedInference, InferenceAuthorizer, InferenceDispatchTarget,
};
pub(crate) use identity::{InferenceAttemptIdentity, InferenceRequestIdentity};
#[cfg(test)]
pub(crate) use identity::{ATTEMPT_ID_HEADER, REQUEST_ID_HEADER};
pub(crate) use limits::InferenceAdmissionGuard;
pub(crate) use openai_request::{
    collect_json_body, models_response, valid_model_alias, OpenAiRequestProfile,
};
