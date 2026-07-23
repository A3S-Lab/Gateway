//! Native inference request handling.

mod openai_request;

pub(crate) use openai_request::{collect_json_body, valid_model_alias, OpenAiRequestProfile};
