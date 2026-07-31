use std::process::{ExitStatus, Stdio};

use tokio::process::Command;

use super::AgentCommand;
use crate::{GatewayError, Result};

/// Executes resolved agent commands with inherited terminal streams.
#[derive(Clone, Copy, Debug, Default)]
pub struct AgentRuntime;

impl AgentRuntime {
    /// Spawn a native coding-agent command and wait for its exit status.
    pub async fn execute(&self, invocation: &AgentCommand) -> Result<ExitStatus> {
        if !invocation.workspace().is_dir() {
            return Err(GatewayError::Agent(format!(
                "workspace `{}` is not a directory",
                invocation.workspace().display()
            )));
        }

        Command::new(invocation.program())
            .args(invocation.arguments())
            .current_dir(invocation.workspace())
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .map_err(|error| {
                GatewayError::Agent(format!(
                    "failed to start `{}` in `{}`: {error}",
                    invocation.program().to_string_lossy(),
                    invocation.workspace().display()
                ))
            })
    }
}
