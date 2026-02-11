//! Request priority — classifies and queues requests by priority level
//!
//! Assigns priority to incoming requests based on message type, user tier,
//! and other factors. Higher priority requests are processed first when
//! agent backends are busy.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Priority levels for agent requests (lower value = higher priority)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    /// Critical system messages (health checks, admin commands)
    Critical = 0,
    /// High priority (paid users, urgent messages)
    High = 1,
    /// Normal priority (regular user messages)
    Normal = 2,
    /// Low priority (batch processing, background tasks)
    Low = 3,
    /// Best effort (analytics, non-essential processing)
    BestEffort = 4,
}

impl Default for Priority {
    fn default() -> Self {
        Self::Normal
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Critical => write!(f, "critical"),
            Self::High => write!(f, "high"),
            Self::Normal => write!(f, "normal"),
            Self::Low => write!(f, "low"),
            Self::BestEffort => write!(f, "best-effort"),
        }
    }
}

impl Priority {
    /// Parse from a string value
    pub fn from_str_value(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" | "0" => Some(Self::Critical),
            "high" | "1" => Some(Self::High),
            "normal" | "2" => Some(Self::Normal),
            "low" | "3" => Some(Self::Low),
            "best-effort" | "besteffort" | "4" => Some(Self::BestEffort),
            _ => None,
        }
    }

    /// Get the numeric value
    pub fn value(&self) -> u8 {
        *self as u8
    }
}

/// Priority classification rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityConfig {
    /// Header to read explicit priority from
    #[serde(default = "default_priority_header")]
    pub priority_header: String,
    /// Default priority for unclassified requests
    #[serde(default)]
    pub default_priority: Priority,
    /// User tiers: map of user_id/group → priority
    #[serde(default)]
    pub user_tiers: HashMap<String, Priority>,
    /// Path patterns that get elevated priority
    #[serde(default)]
    pub high_priority_paths: Vec<String>,
    /// Path patterns that get lowered priority
    #[serde(default)]
    pub low_priority_paths: Vec<String>,
}

fn default_priority_header() -> String {
    "X-Request-Priority".to_string()
}

impl Default for PriorityConfig {
    fn default() -> Self {
        Self {
            priority_header: default_priority_header(),
            default_priority: Priority::Normal,
            user_tiers: HashMap::new(),
            high_priority_paths: Vec::new(),
            low_priority_paths: Vec::new(),
        }
    }
}

/// Request priority classifier
pub struct RequestPriority {
    config: PriorityConfig,
}

impl RequestPriority {
    /// Create a new priority classifier
    pub fn new(config: PriorityConfig) -> Self {
        Self { config }
    }

    /// Classify a request's priority based on headers, path, and user
    pub fn classify(
        &self,
        headers: &HashMap<String, String>,
        path: &str,
        user_id: Option<&str>,
    ) -> Priority {
        // 1. Explicit header takes highest precedence
        if let Some(header_value) = headers.get(&self.config.priority_header) {
            if let Some(priority) = Priority::from_str_value(header_value) {
                return priority;
            }
        }

        // 2. User tier mapping
        if let Some(uid) = user_id {
            if let Some(priority) = self.config.user_tiers.get(uid) {
                return *priority;
            }
        }

        // 3. Path-based classification
        for pattern in &self.config.high_priority_paths {
            if path.starts_with(pattern) {
                return Priority::High;
            }
        }
        for pattern in &self.config.low_priority_paths {
            if path.starts_with(pattern) {
                return Priority::Low;
            }
        }

        // 4. Default
        self.config.default_priority
    }

    /// Get the priority header name
    pub fn header_name(&self) -> &str {
        &self.config.priority_header
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_classifier() -> RequestPriority {
        RequestPriority::new(PriorityConfig::default())
    }

    // --- Priority level tests ---

    #[test]
    fn test_priority_default() {
        assert_eq!(Priority::default(), Priority::Normal);
    }

    #[test]
    fn test_priority_display() {
        assert_eq!(Priority::Critical.to_string(), "critical");
        assert_eq!(Priority::High.to_string(), "high");
        assert_eq!(Priority::Normal.to_string(), "normal");
        assert_eq!(Priority::Low.to_string(), "low");
        assert_eq!(Priority::BestEffort.to_string(), "best-effort");
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical < Priority::High);
        assert!(Priority::High < Priority::Normal);
        assert!(Priority::Normal < Priority::Low);
        assert!(Priority::Low < Priority::BestEffort);
    }

    #[test]
    fn test_priority_values() {
        assert_eq!(Priority::Critical.value(), 0);
        assert_eq!(Priority::High.value(), 1);
        assert_eq!(Priority::Normal.value(), 2);
        assert_eq!(Priority::Low.value(), 3);
        assert_eq!(Priority::BestEffort.value(), 4);
    }

    #[test]
    fn test_priority_serialization() {
        let json = serde_json::to_string(&Priority::High).unwrap();
        assert_eq!(json, "\"high\"");
        let parsed: Priority = serde_json::from_str("\"low\"").unwrap();
        assert_eq!(parsed, Priority::Low);
    }

    // --- from_str_value tests ---

    #[test]
    fn test_from_str_value_names() {
        assert_eq!(Priority::from_str_value("critical"), Some(Priority::Critical));
        assert_eq!(Priority::from_str_value("high"), Some(Priority::High));
        assert_eq!(Priority::from_str_value("normal"), Some(Priority::Normal));
        assert_eq!(Priority::from_str_value("low"), Some(Priority::Low));
        assert_eq!(Priority::from_str_value("best-effort"), Some(Priority::BestEffort));
        assert_eq!(Priority::from_str_value("besteffort"), Some(Priority::BestEffort));
    }

    #[test]
    fn test_from_str_value_numbers() {
        assert_eq!(Priority::from_str_value("0"), Some(Priority::Critical));
        assert_eq!(Priority::from_str_value("1"), Some(Priority::High));
        assert_eq!(Priority::from_str_value("2"), Some(Priority::Normal));
        assert_eq!(Priority::from_str_value("3"), Some(Priority::Low));
        assert_eq!(Priority::from_str_value("4"), Some(Priority::BestEffort));
    }

    #[test]
    fn test_from_str_value_case_insensitive() {
        assert_eq!(Priority::from_str_value("HIGH"), Some(Priority::High));
        assert_eq!(Priority::from_str_value("Critical"), Some(Priority::Critical));
    }

    #[test]
    fn test_from_str_value_invalid() {
        assert_eq!(Priority::from_str_value("unknown"), None);
        assert_eq!(Priority::from_str_value("5"), None);
        assert_eq!(Priority::from_str_value(""), None);
    }

    // --- Classification tests ---

    #[test]
    fn test_classify_default_priority() {
        let classifier = default_classifier();
        let headers = HashMap::new();
        assert_eq!(classifier.classify(&headers, "/api/data", None), Priority::Normal);
    }

    #[test]
    fn test_classify_from_header() {
        let classifier = default_classifier();
        let mut headers = HashMap::new();
        headers.insert("X-Request-Priority".to_string(), "high".to_string());
        assert_eq!(classifier.classify(&headers, "/api/data", None), Priority::High);
    }

    #[test]
    fn test_classify_from_header_numeric() {
        let classifier = default_classifier();
        let mut headers = HashMap::new();
        headers.insert("X-Request-Priority".to_string(), "0".to_string());
        assert_eq!(classifier.classify(&headers, "/api/data", None), Priority::Critical);
    }

    #[test]
    fn test_classify_invalid_header_falls_through() {
        let classifier = default_classifier();
        let mut headers = HashMap::new();
        headers.insert("X-Request-Priority".to_string(), "invalid".to_string());
        assert_eq!(classifier.classify(&headers, "/api/data", None), Priority::Normal);
    }

    #[test]
    fn test_classify_user_tier() {
        let config = PriorityConfig {
            user_tiers: {
                let mut m = HashMap::new();
                m.insert("vip-user".to_string(), Priority::High);
                m.insert("bot-user".to_string(), Priority::Low);
                m
            },
            ..Default::default()
        };
        let classifier = RequestPriority::new(config);
        let headers = HashMap::new();
        assert_eq!(
            classifier.classify(&headers, "/api", Some("vip-user")),
            Priority::High
        );
        assert_eq!(
            classifier.classify(&headers, "/api", Some("bot-user")),
            Priority::Low
        );
        assert_eq!(
            classifier.classify(&headers, "/api", Some("regular")),
            Priority::Normal
        );
    }

    #[test]
    fn test_classify_high_priority_path() {
        let config = PriorityConfig {
            high_priority_paths: vec!["/admin".to_string(), "/health".to_string()],
            ..Default::default()
        };
        let classifier = RequestPriority::new(config);
        let headers = HashMap::new();
        assert_eq!(
            classifier.classify(&headers, "/admin/settings", None),
            Priority::High
        );
        assert_eq!(
            classifier.classify(&headers, "/health", None),
            Priority::High
        );
        assert_eq!(
            classifier.classify(&headers, "/api/data", None),
            Priority::Normal
        );
    }

    #[test]
    fn test_classify_low_priority_path() {
        let config = PriorityConfig {
            low_priority_paths: vec!["/batch".to_string(), "/analytics".to_string()],
            ..Default::default()
        };
        let classifier = RequestPriority::new(config);
        let headers = HashMap::new();
        assert_eq!(
            classifier.classify(&headers, "/batch/process", None),
            Priority::Low
        );
        assert_eq!(
            classifier.classify(&headers, "/analytics/report", None),
            Priority::Low
        );
    }

    // --- Precedence tests ---

    #[test]
    fn test_header_takes_precedence_over_user_tier() {
        let config = PriorityConfig {
            user_tiers: {
                let mut m = HashMap::new();
                m.insert("user-1".to_string(), Priority::Low);
                m
            },
            ..Default::default()
        };
        let classifier = RequestPriority::new(config);
        let mut headers = HashMap::new();
        headers.insert("X-Request-Priority".to_string(), "critical".to_string());
        assert_eq!(
            classifier.classify(&headers, "/api", Some("user-1")),
            Priority::Critical
        );
    }

    #[test]
    fn test_user_tier_takes_precedence_over_path() {
        let config = PriorityConfig {
            user_tiers: {
                let mut m = HashMap::new();
                m.insert("user-1".to_string(), Priority::Critical);
                m
            },
            low_priority_paths: vec!["/batch".to_string()],
            ..Default::default()
        };
        let classifier = RequestPriority::new(config);
        let headers = HashMap::new();
        assert_eq!(
            classifier.classify(&headers, "/batch/job", Some("user-1")),
            Priority::Critical
        );
    }

    // --- Config tests ---

    #[test]
    fn test_config_default() {
        let config = PriorityConfig::default();
        assert_eq!(config.priority_header, "X-Request-Priority");
        assert_eq!(config.default_priority, Priority::Normal);
        assert!(config.user_tiers.is_empty());
        assert!(config.high_priority_paths.is_empty());
        assert!(config.low_priority_paths.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = PriorityConfig {
            default_priority: Priority::High,
            high_priority_paths: vec!["/urgent".to_string()],
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PriorityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.default_priority, Priority::High);
        assert_eq!(parsed.high_priority_paths, vec!["/urgent"]);
    }

    #[test]
    fn test_custom_default_priority() {
        let config = PriorityConfig {
            default_priority: Priority::BestEffort,
            ..Default::default()
        };
        let classifier = RequestPriority::new(config);
        let headers = HashMap::new();
        assert_eq!(
            classifier.classify(&headers, "/api", None),
            Priority::BestEffort
        );
    }

    #[test]
    fn test_header_name() {
        let classifier = default_classifier();
        assert_eq!(classifier.header_name(), "X-Request-Priority");
    }
}
