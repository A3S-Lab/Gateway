//! Native modern MCP request handling.

mod access_error;
mod authorization;
mod dispatch;
mod limits;
pub(crate) mod request;

pub(crate) use access_error::McpAccessError;
pub(crate) use authorization::McpAuthorizer;
pub(crate) use dispatch::{dispatch_once, validate_response_head, McpResponseKind};
pub(crate) use limits::McpAdmissionGuard;
