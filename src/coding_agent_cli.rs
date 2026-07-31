//! CLI presentation for the coding-agent control plane.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Subcommand)]
pub(crate) enum AgentCommands {
    /// List built-in coding-agent profiles and local availability
    List {
        /// Print stable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Inspect one coding-agent profile
    Inspect {
        /// Built-in profile identifier.
        agent: String,
        /// Print stable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Execute a native agent CLI with exact argument passthrough
    Exec {
        /// Built-in profile identifier, or a custom identifier with --command.
        agent: String,
        /// Override the native executable; required for custom profiles.
        #[arg(long, value_name = "PATH")]
        command: Option<PathBuf>,
        /// Run the agent in this workspace.
        #[arg(short = 'C', long, default_value = ".", value_name = "PATH")]
        workspace: PathBuf,
        /// Arguments passed to the native CLI after `--`.
        #[arg(last = true, allow_hyphen_values = true)]
        arguments: Vec<OsString>,
    },
}

#[derive(Subcommand)]
pub(crate) enum SkillCommands {
    /// List discoverable Agent Skills
    List {
        #[command(flatten)]
        search: SkillSearchArgs,
        /// Print stable JSON output.
        #[arg(long)]
        json: bool,
    },
    /// Print a complete SKILL.md definition
    Show {
        /// Skill name from YAML frontmatter.
        name: String,
        #[command(flatten)]
        search: SkillSearchArgs,
    },
    /// Print the resolved SKILL.md path
    Path {
        /// Skill name from YAML frontmatter.
        name: String,
        #[command(flatten)]
        search: SkillSearchArgs,
    },
    /// Run a coding-agent task with one selected Skill
    Run {
        /// Skill name from YAML frontmatter.
        name: String,
        /// Coding-agent profile. Defaults to Codex.
        #[arg(long, default_value = "codex")]
        agent: String,
        /// Override the native executable; required for custom profiles.
        #[arg(long, value_name = "PATH")]
        command: Option<PathBuf>,
        /// Run the agent and discover project Skills in this workspace.
        #[arg(short = 'C', long, default_value = ".", value_name = "PATH")]
        workspace: PathBuf,
        /// Add a highest-precedence Skill root. May be repeated.
        #[arg(long = "skill-dir", value_name = "PATH")]
        skill_dirs: Vec<PathBuf>,
        /// Task passed to the coding agent after the Skill instruction.
        #[arg(long)]
        task: String,
    },
}

#[derive(Args, Clone)]
pub(crate) struct SkillSearchArgs {
    /// Discover project Skills in this workspace.
    #[arg(short = 'C', long, default_value = ".", value_name = "PATH")]
    workspace: PathBuf,
    /// Restrict agent-specific roots to one built-in profile.
    #[arg(long)]
    agent: Option<String>,
    /// Add a highest-precedence Skill root. May be repeated.
    #[arg(long = "skill-dir", value_name = "PATH")]
    skill_dirs: Vec<PathBuf>,
}

pub(crate) async fn operate_agent(command: &AgentCommands) -> a3s_gateway::Result<()> {
    use a3s_gateway::agent::{find_executable, AgentRegistry, AgentRuntime};

    let registry = AgentRegistry::with_builtins();
    match command {
        AgentCommands::List { json } => {
            if *json {
                let profiles: Vec<_> = registry
                    .profiles()
                    .map(|profile| {
                        serde_json::json!({
                            "id": profile.id(),
                            "name": profile.display_name(),
                            "command": profile.command().to_string_lossy(),
                            "available": find_executable(profile.command()).is_some(),
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&profiles)
                        .map_err(|error| a3s_gateway::GatewayError::Other(error.to_string()))?
                );
            } else {
                for profile in registry.profiles() {
                    let status = if find_executable(profile.command()).is_some() {
                        "ready"
                    } else {
                        "missing"
                    };
                    println!(
                        "{}\t{}\t{}\t{}",
                        profile.id(),
                        profile.display_name(),
                        profile.command().to_string_lossy(),
                        status
                    );
                }
            }
        }
        AgentCommands::Inspect { agent, json } => {
            let profile = registry.resolve(agent, None)?;
            if *json {
                let body = serde_json::json!({
                    "id": profile.id(),
                    "name": profile.display_name(),
                    "command": profile.command().to_string_lossy(),
                    "available": find_executable(profile.command()).is_some(),
                    "baseArgs": strings_for_json(profile.base_args()),
                    "taskArgs": strings_for_json(profile.task_args()),
                    "skillRoots": profile.skill_roots().iter().map(|path| path.to_string_lossy()).collect::<Vec<_>>(),
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body)
                        .map_err(|error| a3s_gateway::GatewayError::Other(error.to_string()))?
                );
            } else {
                println!("Agent:       {} ({})", profile.display_name(), profile.id());
                println!("Command:     {}", profile.command().to_string_lossy());
                println!(
                    "Available:   {}",
                    if find_executable(profile.command()).is_some() {
                        "yes"
                    } else {
                        "no"
                    }
                );
                println!("Base args:   {}", join_arguments(profile.base_args()));
                println!("Task args:   {}", join_arguments(profile.task_args()));
                println!(
                    "Skill roots: {}",
                    profile
                        .skill_roots()
                        .iter()
                        .map(|path| path.to_string_lossy())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        AgentCommands::Exec {
            agent,
            command,
            workspace,
            arguments,
        } => {
            let profile = registry.resolve(
                agent,
                command.as_ref().map(|path| path.as_os_str().to_os_string()),
            )?;
            let invocation = profile.native_command(workspace, arguments.iter().cloned());
            let status = AgentRuntime.execute(&invocation).await?;
            require_agent_success(profile.id(), status)?;
        }
    }
    Ok(())
}

pub(crate) async fn operate_skill(command: &SkillCommands) -> a3s_gateway::Result<()> {
    use a3s_gateway::agent::{AgentRegistry, AgentRuntime, SkillCatalog, SkillDiscovery};

    let registry = AgentRegistry::with_builtins();
    match command {
        SkillCommands::List { search, json } => {
            let catalog = discover_skills(search, &registry)?;
            if *json {
                let skills: Vec<_> = catalog
                    .skills()
                    .map(|skill| {
                        serde_json::json!({
                            "name": skill.name(),
                            "description": skill.description(),
                            "path": skill.path().to_string_lossy(),
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&skills)
                        .map_err(|error| a3s_gateway::GatewayError::Other(error.to_string()))?
                );
            } else {
                for skill in catalog.skills() {
                    println!(
                        "{}\t{}\t{}",
                        skill.name(),
                        skill.description(),
                        skill.path().display()
                    );
                }
            }
        }
        SkillCommands::Show { name, search } => {
            let catalog = discover_skills(search, &registry)?;
            let content = catalog.require(name)?.read()?;
            print!("{content}");
            if !content.ends_with('\n') {
                println!();
            }
        }
        SkillCommands::Path { name, search } => {
            let catalog = discover_skills(search, &registry)?;
            println!("{}", catalog.require(name)?.path().display());
        }
        SkillCommands::Run {
            name,
            agent,
            command,
            workspace,
            skill_dirs,
            task,
        } => {
            if task.trim().is_empty() {
                return Err(a3s_gateway::GatewayError::Skill(
                    "--task must not be empty".to_string(),
                ));
            }
            let profile = registry.resolve(
                agent,
                command.as_ref().map(|path| path.as_os_str().to_os_string()),
            )?;
            let catalog = SkillCatalog::discover(
                SkillDiscovery::new(workspace)
                    .with_profile(&profile)
                    .with_explicit_roots(skill_dirs),
            );
            let prompt = catalog.require(name)?.task_prompt(task);
            let invocation = profile.task_command(workspace, prompt);
            let status = AgentRuntime.execute(&invocation).await?;
            require_agent_success(profile.id(), status)?;
        }
    }
    Ok(())
}

fn discover_skills(
    search: &SkillSearchArgs,
    registry: &a3s_gateway::agent::AgentRegistry,
) -> a3s_gateway::Result<a3s_gateway::agent::SkillCatalog> {
    use a3s_gateway::agent::{SkillCatalog, SkillDiscovery};

    let mut discovery = SkillDiscovery::new(&search.workspace)
        .with_explicit_roots(search.skill_dirs.iter().cloned());
    if let Some(agent) = search.agent.as_deref() {
        let profile = registry.resolve(agent, None)?;
        discovery = discovery.with_profile(&profile);
    }
    Ok(SkillCatalog::discover(discovery))
}

fn strings_for_json(arguments: &[OsString]) -> Vec<String> {
    arguments
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
}

fn join_arguments(arguments: &[OsString]) -> String {
    let joined = strings_for_json(arguments).join(" ");
    if joined.is_empty() {
        "(none)".to_string()
    } else {
        joined
    }
}

fn require_agent_success(agent: &str, status: std::process::ExitStatus) -> a3s_gateway::Result<()> {
    if status.success() {
        Ok(())
    } else {
        Err(a3s_gateway::GatewayError::Agent(format!(
            "agent `{agent}` exited with {}",
            status
                .code()
                .map(|code| format!("status {code}"))
                .unwrap_or_else(|| "a signal".to_string())
        )))
    }
}
