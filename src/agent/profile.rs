use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::{GatewayError, Result};

/// A native coding-agent CLI contract.
///
/// `base_args` are present for every invocation. `task_args` select the
/// agent's non-interactive task mode and are followed by the task prompt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentProfile {
    id: String,
    display_name: String,
    command: OsString,
    base_args: Vec<OsString>,
    task_args: Vec<OsString>,
    skill_roots: Vec<PathBuf>,
}

impl AgentProfile {
    /// Create a validated coding-agent profile.
    pub fn new(
        id: impl Into<String>,
        display_name: impl Into<String>,
        command: impl Into<OsString>,
        base_args: impl IntoIterator<Item = impl Into<OsString>>,
        task_args: impl IntoIterator<Item = impl Into<OsString>>,
        skill_roots: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Result<Self> {
        let id = id.into();
        if !valid_profile_id(&id) {
            return Err(GatewayError::Agent(format!(
                "invalid profile id `{id}`; use lowercase letters, digits, `-`, or `_`"
            )));
        }
        let display_name = display_name.into();
        if display_name.trim().is_empty() {
            return Err(GatewayError::Agent(format!(
                "profile `{id}` has an empty display name"
            )));
        }
        let command = command.into();
        if command.is_empty() {
            return Err(GatewayError::Agent(format!(
                "profile `{id}` has an empty command"
            )));
        }

        Ok(Self {
            id,
            display_name,
            command,
            base_args: base_args.into_iter().map(Into::into).collect(),
            task_args: task_args.into_iter().map(Into::into).collect(),
            skill_roots: skill_roots.into_iter().map(Into::into).collect(),
        })
    }

    /// Create a profile for an arbitrary native CLI.
    pub fn custom(id: impl Into<String>, command: impl Into<OsString>) -> Result<Self> {
        let id = id.into();
        Self::new(
            id.clone(),
            id,
            command,
            std::iter::empty::<OsString>(),
            std::iter::empty::<OsString>(),
            [PathBuf::from(".agents/skills")],
        )
    }

    /// Stable profile identifier used by the CLI and registry.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Human-readable agent name.
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// Native executable name or path.
    pub fn command(&self) -> &OsStr {
        &self.command
    }

    /// Arguments applied to every invocation.
    pub fn base_args(&self) -> &[OsString] {
        &self.base_args
    }

    /// Arguments selecting the non-interactive task operation.
    pub fn task_args(&self) -> &[OsString] {
        &self.task_args
    }

    /// Agent-specific Skill roots, relative to a workspace or user home.
    pub fn skill_roots(&self) -> &[PathBuf] {
        &self.skill_roots
    }

    /// Override only the executable while preserving the profile contract.
    pub fn with_command(mut self, command: impl Into<OsString>) -> Result<Self> {
        let command = command.into();
        if command.is_empty() {
            return Err(GatewayError::Agent(format!(
                "profile `{}` has an empty command override",
                self.id
            )));
        }
        self.command = command;
        Ok(self)
    }

    /// Build a native passthrough invocation.
    pub fn native_command(
        &self,
        workspace: impl Into<PathBuf>,
        arguments: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> AgentCommand {
        let mut args = self.base_args.clone();
        args.extend(arguments.into_iter().map(Into::into));
        AgentCommand::new(self.command.clone(), args, workspace.into())
    }

    /// Build a non-interactive task invocation.
    pub fn task_command(
        &self,
        workspace: impl Into<PathBuf>,
        prompt: impl Into<OsString>,
    ) -> AgentCommand {
        let mut args = self.base_args.clone();
        args.extend(self.task_args.iter().cloned());
        args.push(prompt.into());
        AgentCommand::new(self.command.clone(), args, workspace.into())
    }
}

/// A fully resolved process invocation that never passes through a shell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentCommand {
    program: OsString,
    arguments: Vec<OsString>,
    workspace: PathBuf,
}

impl AgentCommand {
    pub(crate) fn new(program: OsString, arguments: Vec<OsString>, workspace: PathBuf) -> Self {
        Self {
            program,
            arguments,
            workspace,
        }
    }

    /// Executable to spawn.
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// Exact native arguments passed to the executable.
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// Child process working directory.
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

fn valid_profile_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_".contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_command_preserves_each_argument() {
        let profile = AgentProfile::new(
            "example",
            "Example",
            "example-agent",
            ["code"],
            ["exec"],
            [".example/skills"],
        )
        .unwrap();
        let command = profile.native_command("/workspace", ["--flag", "two words"]);

        assert_eq!(command.program(), "example-agent");
        assert_eq!(
            command.arguments(),
            [
                OsString::from("code"),
                OsString::from("--flag"),
                OsString::from("two words")
            ]
        );
    }

    #[test]
    fn task_command_uses_profile_task_contract() {
        let profile = AgentProfile::new(
            "example",
            "Example",
            "example-agent",
            ["code"],
            ["exec"],
            [".example/skills"],
        )
        .unwrap();
        let command = profile.task_command("/workspace", "review this");

        assert_eq!(
            command.arguments(),
            [
                OsString::from("code"),
                OsString::from("exec"),
                OsString::from("review this")
            ]
        );
    }

    #[test]
    fn profile_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AgentProfile>();
        assert_send_sync::<AgentCommand>();
    }
}
