//! Agent health probe — checks AI agent availability and model loading status
//!
//! Extends standard HTTP health checks with AI-specific probes that verify
//! model readiness, GPU memory, and inference capability.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Agent readiness state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    /// Agent is starting up (loading model, warming up)
    Loading,
    /// Agent is ready to accept requests
    Ready,
    /// Agent is busy (all inference slots occupied)
    Busy,
    /// Agent is in an error state
    Error,
    /// Agent is unreachable
    Unreachable,
}

impl Default for AgentStatus {
    fn default() -> Self {
        Self::Unreachable
    }
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loading => write!(f, "loading"),
            Self::Ready => write!(f, "ready"),
            Self::Busy => write!(f, "busy"),
            Self::Error => write!(f, "error"),
            Self::Unreachable => write!(f, "unreachable"),
        }
    }
}

impl AgentStatus {
    /// Whether this status means the agent can accept new requests
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether this status means the agent is alive (but maybe not ready)
    pub fn is_alive(&self) -> bool {
        matches!(self, Self::Loading | Self::Ready | Self::Busy)
    }
}

/// Health probe configuration for an AI agent backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeConfig {
    /// Health endpoint path (e.g., "/health" or "/v1/models")
    #[serde(default = "default_health_path")]
    pub health_path: String,
    /// Probe interval in seconds
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,
    /// Probe timeout in seconds
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Number of consecutive failures before marking unreachable
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// Number of consecutive successes before marking ready
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
}

fn default_health_path() -> String {
    "/health".to_string()
}

fn default_interval_secs() -> u64 {
    5
}

fn default_timeout_secs() -> u64 {
    3
}

fn default_failure_threshold() -> u32 {
    3
}

fn default_success_threshold() -> u32 {
    1
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            health_path: default_health_path(),
            interval_secs: default_interval_secs(),
            timeout_secs: default_timeout_secs(),
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
        }
    }
}

/// Snapshot of an agent's health state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHealthSnapshot {
    /// Current status
    pub status: AgentStatus,
    /// Backend URL
    pub backend_url: String,
    /// Consecutive failure count
    pub consecutive_failures: u32,
    /// Consecutive success count
    pub consecutive_successes: u32,
    /// Last known model name (if reported)
    pub model_name: Option<String>,
    /// Last probe response time in milliseconds
    pub last_latency_ms: Option<u64>,
}

/// Internal mutable state for a single agent
#[derive(Debug)]
struct AgentState {
    status: AgentStatus,
    backend_url: String,
    consecutive_failures: u32,
    consecutive_successes: u32,
    model_name: Option<String>,
    last_latency_ms: Option<u64>,
    config: ProbeConfig,
}

impl AgentState {
    fn new(backend_url: String, config: ProbeConfig) -> Self {
        Self {
            status: AgentStatus::Unreachable,
            backend_url,
            consecutive_failures: 0,
            consecutive_successes: 0,
            model_name: None,
            last_latency_ms: None,
            config,
        }
    }

    fn snapshot(&self) -> AgentHealthSnapshot {
        AgentHealthSnapshot {
            status: self.status,
            backend_url: self.backend_url.clone(),
            consecutive_failures: self.consecutive_failures,
            consecutive_successes: self.consecutive_successes,
            model_name: self.model_name.clone(),
            last_latency_ms: self.last_latency_ms,
        }
    }
}

/// Agent health probe manager — tracks health of AI agent backends
pub struct AgentHealthProbe {
    agents: Arc<RwLock<HashMap<String, AgentState>>>,
}

impl AgentHealthProbe {
    /// Create a new health probe manager
    pub fn new() -> Self {
        Self {
            agents: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register an agent backend for health probing
    pub fn register(&self, agent_id: &str, backend_url: &str, config: ProbeConfig) {
        let state = AgentState::new(backend_url.to_string(), config);
        let mut agents = self.agents.write().unwrap();
        agents.insert(agent_id.to_string(), state);
    }

    /// Unregister an agent backend
    pub fn unregister(&self, agent_id: &str) {
        let mut agents = self.agents.write().unwrap();
        agents.remove(agent_id);
    }

    /// Record a successful probe result
    pub fn record_success(&self, agent_id: &str, latency_ms: u64, model_name: Option<String>) {
        let mut agents = self.agents.write().unwrap();
        if let Some(state) = agents.get_mut(agent_id) {
            state.consecutive_failures = 0;
            state.consecutive_successes += 1;
            state.last_latency_ms = Some(latency_ms);
            if let Some(name) = model_name {
                state.model_name = Some(name);
            }
            if state.consecutive_successes >= state.config.success_threshold {
                state.status = AgentStatus::Ready;
            }
        }
    }

    /// Record a failed probe result
    pub fn record_failure(&self, agent_id: &str) {
        let mut agents = self.agents.write().unwrap();
        if let Some(state) = agents.get_mut(agent_id) {
            state.consecutive_successes = 0;
            state.consecutive_failures += 1;
            state.last_latency_ms = None;
            if state.consecutive_failures >= state.config.failure_threshold {
                state.status = AgentStatus::Unreachable;
            } else {
                state.status = AgentStatus::Error;
            }
        }
    }

    /// Manually set an agent's status (e.g., from a status endpoint response)
    pub fn set_status(&self, agent_id: &str, status: AgentStatus) {
        let mut agents = self.agents.write().unwrap();
        if let Some(state) = agents.get_mut(agent_id) {
            state.status = status;
        }
    }

    /// Get the current status of an agent
    pub fn get_status(&self, agent_id: &str) -> Option<AgentStatus> {
        let agents = self.agents.read().unwrap();
        agents.get(agent_id).map(|s| s.status)
    }

    /// Get a full health snapshot for an agent
    pub fn get_snapshot(&self, agent_id: &str) -> Option<AgentHealthSnapshot> {
        let agents = self.agents.read().unwrap();
        agents.get(agent_id).map(|s| s.snapshot())
    }

    /// Get all available (ready) agent IDs
    pub fn available_agents(&self) -> Vec<String> {
        let agents = self.agents.read().unwrap();
        agents
            .iter()
            .filter(|(_, s)| s.status.is_available())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Get all registered agent IDs
    pub fn all_agents(&self) -> Vec<String> {
        let agents = self.agents.read().unwrap();
        agents.keys().cloned().collect()
    }

    /// Get the probe interval for an agent
    pub fn probe_interval(&self, agent_id: &str) -> Option<Duration> {
        let agents = self.agents.read().unwrap();
        agents
            .get(agent_id)
            .map(|s| Duration::from_secs(s.config.interval_secs))
    }

    /// Get the probe timeout for an agent
    pub fn probe_timeout(&self, agent_id: &str) -> Option<Duration> {
        let agents = self.agents.read().unwrap();
        agents
            .get(agent_id)
            .map(|s| Duration::from_secs(s.config.timeout_secs))
    }
}

impl Default for AgentHealthProbe {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> AgentHealthProbe {
        AgentHealthProbe::new()
    }

    // --- AgentStatus tests ---

    #[test]
    fn test_agent_status_default() {
        assert_eq!(AgentStatus::default(), AgentStatus::Unreachable);
    }

    #[test]
    fn test_agent_status_display() {
        assert_eq!(AgentStatus::Loading.to_string(), "loading");
        assert_eq!(AgentStatus::Ready.to_string(), "ready");
        assert_eq!(AgentStatus::Busy.to_string(), "busy");
        assert_eq!(AgentStatus::Error.to_string(), "error");
        assert_eq!(AgentStatus::Unreachable.to_string(), "unreachable");
    }

    #[test]
    fn test_agent_status_is_available() {
        assert!(!AgentStatus::Loading.is_available());
        assert!(AgentStatus::Ready.is_available());
        assert!(!AgentStatus::Busy.is_available());
        assert!(!AgentStatus::Error.is_available());
        assert!(!AgentStatus::Unreachable.is_available());
    }

    #[test]
    fn test_agent_status_is_alive() {
        assert!(AgentStatus::Loading.is_alive());
        assert!(AgentStatus::Ready.is_alive());
        assert!(AgentStatus::Busy.is_alive());
        assert!(!AgentStatus::Error.is_alive());
        assert!(!AgentStatus::Unreachable.is_alive());
    }

    #[test]
    fn test_agent_status_serialization() {
        let json = serde_json::to_string(&AgentStatus::Ready).unwrap();
        assert_eq!(json, "\"ready\"");
        let parsed: AgentStatus = serde_json::from_str("\"busy\"").unwrap();
        assert_eq!(parsed, AgentStatus::Busy);
    }

    // --- ProbeConfig tests ---

    #[test]
    fn test_probe_config_default() {
        let config = ProbeConfig::default();
        assert_eq!(config.health_path, "/health");
        assert_eq!(config.interval_secs, 5);
        assert_eq!(config.timeout_secs, 3);
        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 1);
    }

    #[test]
    fn test_probe_config_serialization() {
        let config = ProbeConfig {
            health_path: "/v1/models".to_string(),
            interval_secs: 10,
            timeout_secs: 5,
            failure_threshold: 5,
            success_threshold: 2,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ProbeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.health_path, "/v1/models");
        assert_eq!(parsed.interval_secs, 10);
        assert_eq!(parsed.failure_threshold, 5);
    }

    // --- Register / unregister tests ---

    #[test]
    fn test_register_agent() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        assert_eq!(p.get_status("agent-1"), Some(AgentStatus::Unreachable));
    }

    #[test]
    fn test_unregister_agent() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.unregister("agent-1");
        assert_eq!(p.get_status("agent-1"), None);
    }

    #[test]
    fn test_unregister_nonexistent() {
        let p = probe();
        p.unregister("nope"); // Should not panic
    }

    // --- Success recording tests ---

    #[test]
    fn test_record_success_transitions_to_ready() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.record_success("agent-1", 50, None);
        // Default success_threshold is 1, so one success → Ready
        assert_eq!(p.get_status("agent-1"), Some(AgentStatus::Ready));
    }

    #[test]
    fn test_record_success_with_higher_threshold() {
        let config = ProbeConfig {
            success_threshold: 3,
            ..Default::default()
        };
        let p = probe();
        p.register("agent-1", "http://localhost:8080", config);
        p.record_success("agent-1", 50, None);
        assert_ne!(p.get_status("agent-1"), Some(AgentStatus::Ready));
        p.record_success("agent-1", 45, None);
        assert_ne!(p.get_status("agent-1"), Some(AgentStatus::Ready));
        p.record_success("agent-1", 40, None);
        assert_eq!(p.get_status("agent-1"), Some(AgentStatus::Ready));
    }

    #[test]
    fn test_record_success_resets_failure_count() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.record_failure("agent-1");
        p.record_failure("agent-1");
        p.record_success("agent-1", 50, None);
        let snap = p.get_snapshot("agent-1").unwrap();
        assert_eq!(snap.consecutive_failures, 0);
        assert_eq!(snap.consecutive_successes, 1);
    }

    #[test]
    fn test_record_success_with_model_name() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.record_success("agent-1", 50, Some("llama-3.1-8b".to_string()));
        let snap = p.get_snapshot("agent-1").unwrap();
        assert_eq!(snap.model_name, Some("llama-3.1-8b".to_string()));
    }

    #[test]
    fn test_record_success_latency() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.record_success("agent-1", 123, None);
        let snap = p.get_snapshot("agent-1").unwrap();
        assert_eq!(snap.last_latency_ms, Some(123));
    }

    // --- Failure recording tests ---

    #[test]
    fn test_record_failure_transitions_to_error() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.record_failure("agent-1");
        assert_eq!(p.get_status("agent-1"), Some(AgentStatus::Error));
    }

    #[test]
    fn test_record_failure_transitions_to_unreachable() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        // Default failure_threshold is 3
        p.record_failure("agent-1");
        p.record_failure("agent-1");
        assert_eq!(p.get_status("agent-1"), Some(AgentStatus::Error));
        p.record_failure("agent-1");
        assert_eq!(p.get_status("agent-1"), Some(AgentStatus::Unreachable));
    }

    #[test]
    fn test_record_failure_resets_success_count() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.record_success("agent-1", 50, None);
        p.record_failure("agent-1");
        let snap = p.get_snapshot("agent-1").unwrap();
        assert_eq!(snap.consecutive_successes, 0);
        assert_eq!(snap.consecutive_failures, 1);
    }

    #[test]
    fn test_record_failure_clears_latency() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.record_success("agent-1", 50, None);
        p.record_failure("agent-1");
        let snap = p.get_snapshot("agent-1").unwrap();
        assert_eq!(snap.last_latency_ms, None);
    }

    // --- Manual status set ---

    #[test]
    fn test_set_status() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.set_status("agent-1", AgentStatus::Busy);
        assert_eq!(p.get_status("agent-1"), Some(AgentStatus::Busy));
    }

    #[test]
    fn test_set_status_nonexistent() {
        let p = probe();
        p.set_status("nope", AgentStatus::Ready); // Should not panic
    }

    // --- Available agents ---

    #[test]
    fn test_available_agents_empty() {
        let p = probe();
        assert!(p.available_agents().is_empty());
    }

    #[test]
    fn test_available_agents() {
        let p = probe();
        p.register("agent-1", "http://b1:8080", ProbeConfig::default());
        p.register("agent-2", "http://b2:8080", ProbeConfig::default());
        p.register("agent-3", "http://b3:8080", ProbeConfig::default());
        p.record_success("agent-1", 50, None);
        p.record_success("agent-3", 50, None);
        // agent-2 is still Unreachable
        let available = p.available_agents();
        assert_eq!(available.len(), 2);
        assert!(available.contains(&"agent-1".to_string()));
        assert!(available.contains(&"agent-3".to_string()));
    }

    // --- All agents ---

    #[test]
    fn test_all_agents() {
        let p = probe();
        p.register("a", "http://a:8080", ProbeConfig::default());
        p.register("b", "http://b:8080", ProbeConfig::default());
        let all = p.all_agents();
        assert_eq!(all.len(), 2);
    }

    // --- Probe interval/timeout ---

    #[test]
    fn test_probe_interval() {
        let p = probe();
        let config = ProbeConfig {
            interval_secs: 10,
            ..Default::default()
        };
        p.register("agent-1", "http://b:8080", config);
        assert_eq!(p.probe_interval("agent-1"), Some(Duration::from_secs(10)));
    }

    #[test]
    fn test_probe_timeout() {
        let p = probe();
        let config = ProbeConfig {
            timeout_secs: 7,
            ..Default::default()
        };
        p.register("agent-1", "http://b:8080", config);
        assert_eq!(p.probe_timeout("agent-1"), Some(Duration::from_secs(7)));
    }

    #[test]
    fn test_probe_interval_nonexistent() {
        let p = probe();
        assert_eq!(p.probe_interval("nope"), None);
    }

    // --- Snapshot tests ---

    #[test]
    fn test_snapshot() {
        let p = probe();
        p.register("agent-1", "http://localhost:8080", ProbeConfig::default());
        p.record_success("agent-1", 42, Some("gpt-4".to_string()));
        let snap = p.get_snapshot("agent-1").unwrap();
        assert_eq!(snap.status, AgentStatus::Ready);
        assert_eq!(snap.backend_url, "http://localhost:8080");
        assert_eq!(snap.consecutive_failures, 0);
        assert_eq!(snap.consecutive_successes, 1);
        assert_eq!(snap.model_name, Some("gpt-4".to_string()));
        assert_eq!(snap.last_latency_ms, Some(42));
    }

    #[test]
    fn test_snapshot_nonexistent() {
        let p = probe();
        assert!(p.get_snapshot("nope").is_none());
    }

    #[test]
    fn test_snapshot_serialization() {
        let snap = AgentHealthSnapshot {
            status: AgentStatus::Ready,
            backend_url: "http://localhost:8080".to_string(),
            consecutive_failures: 0,
            consecutive_successes: 5,
            model_name: Some("llama".to_string()),
            last_latency_ms: Some(100),
        };
        let json = serde_json::to_string(&snap).unwrap();
        let parsed: AgentHealthSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.status, AgentStatus::Ready);
        assert_eq!(parsed.consecutive_successes, 5);
    }

    // --- Default impl ---

    #[test]
    fn test_default_impl() {
        let p = AgentHealthProbe::default();
        assert!(p.all_agents().is_empty());
    }
}
