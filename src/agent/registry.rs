use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use super::AgentProfile;
use crate::{GatewayError, Result};

/// Extensible registry of native coding-agent CLI profiles.
#[derive(Clone, Debug)]
pub struct AgentRegistry {
    profiles: BTreeMap<String, AgentProfile>,
}

impl AgentRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            profiles: BTreeMap::new(),
        }
    }

    /// Create the registry shipped by the Gateway CLI.
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        for profile in builtin_profiles() {
            registry.register(profile);
        }
        registry
    }

    /// Add or replace one typed profile.
    pub fn register(&mut self, profile: AgentProfile) -> Option<AgentProfile> {
        self.profiles.insert(profile.id().to_string(), profile)
    }

    /// Resolve a registered profile by its stable identifier.
    pub fn get(&self, id: &str) -> Option<&AgentProfile> {
        self.profiles.get(id)
    }

    /// Return profiles in stable identifier order.
    pub fn profiles(&self) -> impl Iterator<Item = &AgentProfile> {
        self.profiles.values()
    }

    /// Resolve a profile and apply an optional executable override.
    ///
    /// An unknown identifier is accepted only when an explicit command is
    /// supplied, which creates a custom passthrough profile.
    pub fn resolve(&self, id: &str, command: Option<OsString>) -> Result<AgentProfile> {
        match (self.get(id), command) {
            (Some(profile), Some(command)) => profile.clone().with_command(command),
            (Some(profile), None) => Ok(profile.clone()),
            (None, Some(command)) => AgentProfile::custom(id, command),
            (None, None) => Err(GatewayError::Agent(format!(
                "unknown agent profile `{id}`; use `agent list` or pass `--command`"
            ))),
        }
    }
}

impl Default for AgentRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}

/// Resolve an executable using the current process `PATH` without invoking a shell.
pub fn find_executable(command: &OsStr) -> Option<PathBuf> {
    let candidate = Path::new(command);
    if candidate.components().count() > 1 {
        return executable_file(candidate).then(|| candidate.to_path_buf());
    }

    let search_path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&search_path) {
        let candidate = directory.join(command);
        if executable_file(&candidate) {
            return Some(candidate);
        }
        #[cfg(windows)]
        for extension in windows_executable_extensions() {
            let candidate = directory.join(format!(
                "{}{}",
                command.to_string_lossy(),
                extension.to_string_lossy()
            ));
            if executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = path.metadata() else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(windows)]
fn windows_executable_extensions() -> Vec<OsString> {
    std::env::var_os("PATHEXT")
        .map(|extensions| {
            extensions
                .to_string_lossy()
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(OsString::from)
                .collect()
        })
        .unwrap_or_else(|| {
            [".COM", ".EXE", ".BAT", ".CMD"]
                .map(OsString::from)
                .to_vec()
        })
}

fn builtin_profiles() -> Vec<AgentProfile> {
    vec![
        AgentProfile::new(
            "a3s",
            "A3S Code",
            "a3s",
            ["code"],
            ["exec"],
            [".a3s/skills"],
        ),
        AgentProfile::new(
            "claude",
            "Claude Code",
            "claude",
            std::iter::empty::<&str>(),
            ["--print"],
            [".claude/skills"],
        ),
        AgentProfile::new(
            "codex",
            "OpenAI Codex",
            "codex",
            std::iter::empty::<&str>(),
            ["exec"],
            [".codex/skills"],
        ),
        AgentProfile::new(
            "gemini",
            "Gemini CLI",
            "gemini",
            std::iter::empty::<&str>(),
            ["--prompt"],
            [".gemini/skills"],
        ),
        AgentProfile::new(
            "opencode",
            "OpenCode",
            "opencode",
            std::iter::empty::<&str>(),
            ["run"],
            [".opencode/skills"],
        ),
    ]
    .into_iter()
    .map(|profile| profile.expect("built-in agent profiles must be valid"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_have_unique_stable_ids() {
        let registry = AgentRegistry::with_builtins();
        assert_eq!(
            registry
                .profiles()
                .map(AgentProfile::id)
                .collect::<Vec<_>>(),
            ["a3s", "claude", "codex", "gemini", "opencode"]
        );
    }

    #[test]
    fn unknown_profile_requires_an_explicit_command() {
        let registry = AgentRegistry::new();
        assert!(registry.resolve("custom", None).is_err());
        let profile = registry
            .resolve("custom", Some(OsString::from("my-agent")))
            .unwrap();
        assert_eq!(profile.command(), "my-agent");
    }
}
