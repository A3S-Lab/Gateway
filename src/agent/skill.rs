use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use super::AgentProfile;
use crate::{GatewayError, Result};

const MAX_SKILL_BYTES: u64 = 256 * 1024;
const STANDARD_SKILL_ROOTS: &[&str] = &[
    ".agents/skills",
    ".a3s/skills",
    ".claude/skills",
    ".codex/skills",
    ".gemini/skills",
    ".opencode/skills",
    ".cursor/skills",
];

/// Metadata for one validated Agent Skill package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skill {
    name: String,
    description: String,
    path: PathBuf,
}

impl Skill {
    /// Skill name from YAML frontmatter.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Skill description from YAML frontmatter.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Absolute or workspace-qualified `SKILL.md` path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the complete bounded Skill definition.
    pub fn read(&self) -> Result<String> {
        read_bounded(&self.path)
    }

    /// Build a provider-neutral task prompt that identifies the selected Skill.
    pub fn task_prompt(&self, task: &str) -> String {
        format!(
            "Use the coding-agent Skill `{}` for this task. Read and follow the instructions in `{}`.\n\nTask:\n{}",
            self.name,
            self.path.display(),
            task
        )
    }
}

/// Inputs for deterministic Skill discovery.
#[derive(Clone, Debug)]
pub struct SkillDiscovery {
    workspace: PathBuf,
    home: Option<PathBuf>,
    profile_roots: Option<Vec<PathBuf>>,
    explicit_roots: Vec<PathBuf>,
}

impl SkillDiscovery {
    /// Discover project and user Skills for one workspace.
    pub fn new(workspace: impl Into<PathBuf>) -> Self {
        Self {
            workspace: workspace.into(),
            home: user_home_directory(),
            profile_roots: None,
            explicit_roots: Vec::new(),
        }
    }

    /// Restrict agent-specific roots while retaining the shared `.agents/skills` root.
    pub fn with_profile(mut self, profile: &AgentProfile) -> Self {
        self.profile_roots = Some(profile.skill_roots().to_vec());
        self
    }

    /// Add highest-precedence Skill roots.
    pub fn with_explicit_roots(
        mut self,
        roots: impl IntoIterator<Item = impl Into<PathBuf>>,
    ) -> Self {
        self.explicit_roots
            .extend(roots.into_iter().map(Into::into));
        self
    }

    /// Override home discovery, primarily for embedding and deterministic tests.
    pub fn with_home(mut self, home: Option<PathBuf>) -> Self {
        self.home = home;
        self
    }

    fn roots(&self) -> Vec<PathBuf> {
        let relative_roots: Vec<PathBuf> = match &self.profile_roots {
            Some(profile_roots) => std::iter::once(PathBuf::from(".agents/skills"))
                .chain(profile_roots.iter().cloned())
                .collect(),
            None => STANDARD_SKILL_ROOTS.iter().map(PathBuf::from).collect(),
        };

        let mut roots = self.explicit_roots.clone();
        roots.extend(
            relative_roots
                .iter()
                .map(|relative| self.workspace.join(relative)),
        );
        if let Some(home) = &self.home {
            roots.extend(relative_roots.iter().map(|relative| home.join(relative)));
        }

        let mut seen = BTreeSet::new();
        roots
            .into_iter()
            .filter(|root| seen.insert(root.clone()))
            .collect()
    }
}

/// Read-only inventory of validated Agent Skills.
#[derive(Clone, Debug, Default)]
pub struct SkillCatalog {
    skills: BTreeMap<String, Skill>,
}

impl SkillCatalog {
    /// Discover valid `<name>/SKILL.md` packages in precedence order.
    ///
    /// The first occurrence of a Skill name wins. Unreadable or malformed
    /// packages are ignored so one third-party package cannot break the entire
    /// inventory.
    pub fn discover(discovery: SkillDiscovery) -> Self {
        let mut skills = BTreeMap::new();
        for root in discovery.roots() {
            discover_root(&root, &mut skills);
        }
        Self { skills }
    }

    /// Return Skills in stable name order.
    pub fn skills(&self) -> impl Iterator<Item = &Skill> {
        self.skills.values()
    }

    /// Find one Skill by its frontmatter name.
    pub fn get(&self, name: &str) -> Option<&Skill> {
        self.skills.get(name)
    }

    /// Resolve one Skill or return a contextual error.
    pub fn require(&self, name: &str) -> Result<&Skill> {
        self.get(name).ok_or_else(|| {
            GatewayError::Skill(format!(
                "Skill `{name}` was not found in the selected workspace and user roots"
            ))
        })
    }
}

fn discover_root(root: &Path, skills: &mut BTreeMap<String, Skill>) {
    if root.join("SKILL.md").is_file() {
        if let Ok(skill) = load_skill(&root.join("SKILL.md")) {
            skills.entry(skill.name.clone()).or_insert(skill);
        }
        return;
    }

    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let mut paths: Vec<_> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        let skill_file = path.join("SKILL.md");
        if !skill_file.is_file() {
            continue;
        }
        if let Ok(skill) = load_skill(&skill_file) {
            skills.entry(skill.name.clone()).or_insert(skill);
        }
    }
}

fn load_skill(path: &Path) -> Result<Skill> {
    let content = read_bounded(path)?;
    let (name, description) = parse_frontmatter(&content).ok_or_else(|| {
        GatewayError::Skill(format!(
            "`{}` must contain YAML frontmatter with a non-empty `name`",
            path.display()
        ))
    })?;
    let path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    Ok(Skill {
        name,
        description,
        path,
    })
}

fn read_bounded(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path).map_err(|error| {
        GatewayError::Skill(format!("failed to inspect `{}`: {error}", path.display()))
    })?;
    if metadata.len() > MAX_SKILL_BYTES {
        return Err(GatewayError::Skill(format!(
            "`{}` exceeds the {} byte Skill limit",
            path.display(),
            MAX_SKILL_BYTES
        )));
    }
    fs::read_to_string(path).map_err(|error| {
        GatewayError::Skill(format!(
            "failed to read `{}` as UTF-8: {error}",
            path.display()
        ))
    })
}

fn parse_frontmatter(content: &str) -> Option<(String, String)> {
    let mut lines = content.trim_start_matches('\u{feff}').lines();
    if lines.next()?.trim_end_matches('\r') != "---" {
        return None;
    }

    let mut name: Option<String> = None;
    let mut description = String::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line == "---" {
            let name = name?;
            return (!name.is_empty()).then_some((name, description));
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().trim_matches(['\'', '"']).to_string();
        match key.trim() {
            "name" => name = Some(value),
            "description" => description = value,
            _ => {}
        }
    }
    None
}

fn user_home_directory() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .filter(|value| !value.is_empty())
                .map(PathBuf::from)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_skill(root: &Path, name: &str, description: &str) -> PathBuf {
        let directory = root.join(name);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("SKILL.md");
        fs::write(
            &path,
            format!("---\nname: {name}\ndescription: {description}\n---\n\n# Body\n"),
        )
        .unwrap();
        path
    }

    #[test]
    fn explicit_skill_root_has_precedence() {
        let workspace = tempdir().unwrap();
        let project_root = workspace.path().join(".agents/skills");
        write_skill(&project_root, "review", "project");
        let explicit = tempdir().unwrap();
        let explicit_path = write_skill(explicit.path(), "review", "explicit");

        let catalog = SkillCatalog::discover(
            SkillDiscovery::new(workspace.path())
                .with_home(None)
                .with_explicit_roots([explicit.path()]),
        );
        let skill = catalog.require("review").unwrap();
        assert_eq!(skill.description(), "explicit");
        assert_eq!(skill.path(), explicit_path.canonicalize().unwrap());
    }

    #[test]
    fn malformed_skill_does_not_hide_valid_inventory() {
        let workspace = tempdir().unwrap();
        let root = workspace.path().join(".agents/skills");
        write_skill(&root, "valid", "works");
        fs::create_dir_all(root.join("broken")).unwrap();
        fs::write(root.join("broken/SKILL.md"), "# no frontmatter").unwrap();

        let catalog = SkillCatalog::discover(SkillDiscovery::new(workspace.path()).with_home(None));
        assert!(catalog.get("valid").is_some());
        assert_eq!(catalog.skills().count(), 1);
    }

    #[test]
    fn task_prompt_names_the_skill_path_and_task() {
        let workspace = tempdir().unwrap();
        let root = workspace.path().join(".agents/skills");
        let path = write_skill(&root, "review", "works");
        let catalog = SkillCatalog::discover(SkillDiscovery::new(workspace.path()).with_home(None));
        let prompt = catalog
            .require("review")
            .unwrap()
            .task_prompt("inspect parser");

        assert!(prompt.contains("`review`"));
        assert!(prompt.contains(path.canonicalize().unwrap().to_str().unwrap()));
        assert!(prompt.contains("inspect parser"));
    }
}
