//! Portable coding-agent CLI and `SKILL.md` operations.
//!
//! The module is intentionally separate from the gateway data plane. Agent
//! profiles describe native CLI contracts, [`AgentRegistry`] owns extension,
//! [`AgentRuntime`] owns process execution, and [`SkillCatalog`] owns read-only
//! Skill discovery. No command is evaluated through a shell.

mod profile;
mod registry;
mod runtime;
mod skill;

pub use profile::{AgentCommand, AgentProfile};
pub use registry::{find_executable, AgentRegistry};
pub use runtime::AgentRuntime;
pub use skill::{Skill, SkillCatalog, SkillDiscovery};
