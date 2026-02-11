//! Privacy-aware routing — classifies content sensitivity and routes accordingly
//!
//! Determines whether a request should be routed to a local backend or a
//! Trusted Execution Environment (TEE) based on content sensitivity analysis.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Privacy classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PrivacyLevel {
    /// Public data — can be processed anywhere
    Public,
    /// Internal data — prefer local processing
    Internal,
    /// Confidential data — must use TEE
    Confidential,
    /// Restricted data — TEE only, with audit logging
    Restricted,
}

impl Default for PrivacyLevel {
    fn default() -> Self {
        Self::Public
    }
}

impl std::fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Internal => write!(f, "internal"),
            Self::Confidential => write!(f, "confidential"),
            Self::Restricted => write!(f, "restricted"),
        }
    }
}

/// Routing decision based on privacy classification
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteTarget {
    /// Route to a standard local backend
    Local,
    /// Route to a TEE-protected backend
    Tee,
}

/// Configuration for the privacy router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyRouterConfig {
    /// Minimum privacy level that triggers TEE routing
    #[serde(default = "default_tee_threshold")]
    pub tee_threshold: PrivacyLevel,
    /// Custom sensitive keywords (in addition to built-in patterns)
    #[serde(default)]
    pub sensitive_keywords: Vec<String>,
    /// Header name to read explicit privacy level from
    #[serde(default = "default_privacy_header")]
    pub privacy_header: String,
}

fn default_tee_threshold() -> PrivacyLevel {
    PrivacyLevel::Confidential
}

fn default_privacy_header() -> String {
    "X-Privacy-Level".to_string()
}

impl Default for PrivacyRouterConfig {
    fn default() -> Self {
        Self {
            tee_threshold: default_tee_threshold(),
            sensitive_keywords: Vec::new(),
            privacy_header: default_privacy_header(),
        }
    }
}

/// Privacy-aware router — classifies and routes based on content sensitivity
pub struct PrivacyRouter {
    config: PrivacyRouterConfig,
    /// Built-in PII patterns (lowercased for matching)
    builtin_patterns: HashSet<&'static str>,
}

impl PrivacyRouter {
    /// Create a new privacy router with the given configuration
    pub fn new(config: PrivacyRouterConfig) -> Self {
        let builtin_patterns = HashSet::from([
            "ssn",
            "social security",
            "credit card",
            "card number",
            "passport",
            "driver license",
            "bank account",
            "routing number",
            "medical record",
            "health record",
            "diagnosis",
            "prescription",
            "password",
            "secret key",
            "private key",
            "api key",
            "access token",
            "refresh token",
        ]);
        Self {
            config,
            builtin_patterns,
        }
    }

    /// Classify the privacy level of content
    pub fn classify(&self, content: &str) -> PrivacyLevel {
        let lower = content.to_lowercase();

        // Check for restricted-level patterns (PII identifiers)
        if self.contains_pii_pattern(&lower) {
            return PrivacyLevel::Restricted;
        }

        // Check for confidential-level patterns (sensitive keywords)
        if self.contains_sensitive_keyword(&lower) {
            return PrivacyLevel::Confidential;
        }

        // Check for internal-level patterns (personal context)
        if self.contains_personal_context(&lower) {
            return PrivacyLevel::Internal;
        }

        PrivacyLevel::Public
    }

    /// Parse an explicit privacy level from a header value
    pub fn parse_header_level(value: &str) -> Option<PrivacyLevel> {
        match value.to_lowercase().as_str() {
            "public" => Some(PrivacyLevel::Public),
            "internal" => Some(PrivacyLevel::Internal),
            "confidential" => Some(PrivacyLevel::Confidential),
            "restricted" => Some(PrivacyLevel::Restricted),
            _ => None,
        }
    }

    /// Determine the route target based on privacy level
    pub fn route(&self, level: PrivacyLevel) -> RouteTarget {
        if level >= self.config.tee_threshold {
            RouteTarget::Tee
        } else {
            RouteTarget::Local
        }
    }

    /// Classify content and determine route in one step
    pub fn classify_and_route(&self, content: &str) -> (PrivacyLevel, RouteTarget) {
        let level = self.classify(content);
        let target = self.route(level);
        (level, target)
    }

    /// Check if content contains PII patterns (restricted level)
    fn contains_pii_pattern(&self, lower_content: &str) -> bool {
        for pattern in &self.builtin_patterns {
            if lower_content.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Check if content contains user-defined sensitive keywords (confidential level)
    fn contains_sensitive_keyword(&self, lower_content: &str) -> bool {
        for keyword in &self.config.sensitive_keywords {
            if lower_content.contains(&keyword.to_lowercase()) {
                return true;
            }
        }
        false
    }

    /// Check if content contains personal context indicators (internal level)
    fn contains_personal_context(&self, lower_content: &str) -> bool {
        let personal_indicators = [
            "my name is",
            "my address",
            "my phone",
            "my email",
            "date of birth",
            "born on",
            "i live at",
            "contact me at",
        ];
        for indicator in &personal_indicators {
            if lower_content.contains(indicator) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_router() -> PrivacyRouter {
        PrivacyRouter::new(PrivacyRouterConfig::default())
    }

    // --- PrivacyLevel tests ---

    #[test]
    fn test_privacy_level_default() {
        assert_eq!(PrivacyLevel::default(), PrivacyLevel::Public);
    }

    #[test]
    fn test_privacy_level_display() {
        assert_eq!(PrivacyLevel::Public.to_string(), "public");
        assert_eq!(PrivacyLevel::Internal.to_string(), "internal");
        assert_eq!(PrivacyLevel::Confidential.to_string(), "confidential");
        assert_eq!(PrivacyLevel::Restricted.to_string(), "restricted");
    }

    #[test]
    fn test_privacy_level_ordering() {
        assert!(PrivacyLevel::Public < PrivacyLevel::Internal);
        assert!(PrivacyLevel::Internal < PrivacyLevel::Confidential);
        assert!(PrivacyLevel::Confidential < PrivacyLevel::Restricted);
    }

    #[test]
    fn test_privacy_level_serialization() {
        let json = serde_json::to_string(&PrivacyLevel::Confidential).unwrap();
        assert_eq!(json, "\"confidential\"");
        let parsed: PrivacyLevel = serde_json::from_str("\"restricted\"").unwrap();
        assert_eq!(parsed, PrivacyLevel::Restricted);
    }

    // --- Classification tests ---

    #[test]
    fn test_classify_public() {
        let router = default_router();
        assert_eq!(router.classify("What is the weather today?"), PrivacyLevel::Public);
    }

    #[test]
    fn test_classify_public_general_question() {
        let router = default_router();
        assert_eq!(router.classify("How do I write a for loop in Rust?"), PrivacyLevel::Public);
    }

    #[test]
    fn test_classify_internal_personal_context() {
        let router = default_router();
        assert_eq!(router.classify("My name is Alice and I need help"), PrivacyLevel::Internal);
    }

    #[test]
    fn test_classify_internal_address() {
        let router = default_router();
        assert_eq!(router.classify("I live at 123 Main Street"), PrivacyLevel::Internal);
    }

    #[test]
    fn test_classify_internal_phone() {
        let router = default_router();
        assert_eq!(router.classify("my phone number is important"), PrivacyLevel::Internal);
    }

    #[test]
    fn test_classify_confidential_custom_keyword() {
        let config = PrivacyRouterConfig {
            sensitive_keywords: vec!["project-alpha".to_string()],
            ..Default::default()
        };
        let router = PrivacyRouter::new(config);
        assert_eq!(
            router.classify("Tell me about Project-Alpha status"),
            PrivacyLevel::Confidential
        );
    }

    #[test]
    fn test_classify_restricted_ssn() {
        let router = default_router();
        assert_eq!(
            router.classify("My SSN is 123-45-6789"),
            PrivacyLevel::Restricted
        );
    }

    #[test]
    fn test_classify_restricted_credit_card() {
        let router = default_router();
        assert_eq!(
            router.classify("My credit card number is 4111-1111-1111-1111"),
            PrivacyLevel::Restricted
        );
    }

    #[test]
    fn test_classify_restricted_password() {
        let router = default_router();
        assert_eq!(
            router.classify("My password is hunter2"),
            PrivacyLevel::Restricted
        );
    }

    #[test]
    fn test_classify_restricted_api_key() {
        let router = default_router();
        assert_eq!(
            router.classify("The api key is sk-abc123"),
            PrivacyLevel::Restricted
        );
    }

    #[test]
    fn test_classify_restricted_medical() {
        let router = default_router();
        assert_eq!(
            router.classify("My medical record shows a diagnosis"),
            PrivacyLevel::Restricted
        );
    }

    #[test]
    fn test_classify_case_insensitive() {
        let router = default_router();
        assert_eq!(
            router.classify("MY SOCIAL SECURITY number"),
            PrivacyLevel::Restricted
        );
    }

    // --- Routing tests ---

    #[test]
    fn test_route_public_to_local() {
        let router = default_router();
        assert_eq!(router.route(PrivacyLevel::Public), RouteTarget::Local);
    }

    #[test]
    fn test_route_internal_to_local() {
        let router = default_router();
        assert_eq!(router.route(PrivacyLevel::Internal), RouteTarget::Local);
    }

    #[test]
    fn test_route_confidential_to_tee() {
        let router = default_router();
        assert_eq!(router.route(PrivacyLevel::Confidential), RouteTarget::Tee);
    }

    #[test]
    fn test_route_restricted_to_tee() {
        let router = default_router();
        assert_eq!(router.route(PrivacyLevel::Restricted), RouteTarget::Tee);
    }

    #[test]
    fn test_route_custom_threshold() {
        let config = PrivacyRouterConfig {
            tee_threshold: PrivacyLevel::Internal,
            ..Default::default()
        };
        let router = PrivacyRouter::new(config);
        assert_eq!(router.route(PrivacyLevel::Public), RouteTarget::Local);
        assert_eq!(router.route(PrivacyLevel::Internal), RouteTarget::Tee);
        assert_eq!(router.route(PrivacyLevel::Confidential), RouteTarget::Tee);
    }

    // --- Combined classify_and_route tests ---

    #[test]
    fn test_classify_and_route_public() {
        let router = default_router();
        let (level, target) = router.classify_and_route("Hello world");
        assert_eq!(level, PrivacyLevel::Public);
        assert_eq!(target, RouteTarget::Local);
    }

    #[test]
    fn test_classify_and_route_restricted() {
        let router = default_router();
        let (level, target) = router.classify_and_route("Store my passport number");
        assert_eq!(level, PrivacyLevel::Restricted);
        assert_eq!(target, RouteTarget::Tee);
    }

    // --- Header parsing tests ---

    #[test]
    fn test_parse_header_level_valid() {
        assert_eq!(PrivacyRouter::parse_header_level("public"), Some(PrivacyLevel::Public));
        assert_eq!(PrivacyRouter::parse_header_level("internal"), Some(PrivacyLevel::Internal));
        assert_eq!(PrivacyRouter::parse_header_level("confidential"), Some(PrivacyLevel::Confidential));
        assert_eq!(PrivacyRouter::parse_header_level("restricted"), Some(PrivacyLevel::Restricted));
    }

    #[test]
    fn test_parse_header_level_case_insensitive() {
        assert_eq!(PrivacyRouter::parse_header_level("Confidential"), Some(PrivacyLevel::Confidential));
        assert_eq!(PrivacyRouter::parse_header_level("RESTRICTED"), Some(PrivacyLevel::Restricted));
    }

    #[test]
    fn test_parse_header_level_invalid() {
        assert_eq!(PrivacyRouter::parse_header_level("unknown"), None);
        assert_eq!(PrivacyRouter::parse_header_level(""), None);
    }

    // --- Config tests ---

    #[test]
    fn test_config_default() {
        let config = PrivacyRouterConfig::default();
        assert_eq!(config.tee_threshold, PrivacyLevel::Confidential);
        assert!(config.sensitive_keywords.is_empty());
        assert_eq!(config.privacy_header, "X-Privacy-Level");
    }

    #[test]
    fn test_config_serialization() {
        let config = PrivacyRouterConfig {
            tee_threshold: PrivacyLevel::Internal,
            sensitive_keywords: vec!["secret-project".to_string()],
            privacy_header: "X-Custom-Privacy".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: PrivacyRouterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tee_threshold, PrivacyLevel::Internal);
        assert_eq!(parsed.sensitive_keywords, vec!["secret-project"]);
        assert_eq!(parsed.privacy_header, "X-Custom-Privacy");
    }

    // --- Multiple custom keywords ---

    #[test]
    fn test_multiple_sensitive_keywords() {
        let config = PrivacyRouterConfig {
            sensitive_keywords: vec![
                "project-x".to_string(),
                "classified".to_string(),
            ],
            ..Default::default()
        };
        let router = PrivacyRouter::new(config);
        assert_eq!(router.classify("Info about project-x"), PrivacyLevel::Confidential);
        assert_eq!(router.classify("This is classified info"), PrivacyLevel::Confidential);
        assert_eq!(router.classify("Normal question"), PrivacyLevel::Public);
    }

    // --- Priority: restricted > confidential > internal > public ---

    #[test]
    fn test_classification_priority() {
        let config = PrivacyRouterConfig {
            sensitive_keywords: vec!["sensitive-topic".to_string()],
            ..Default::default()
        };
        let router = PrivacyRouter::new(config);
        // Content with both PII and custom keyword → restricted wins
        assert_eq!(
            router.classify("My SSN and sensitive-topic"),
            PrivacyLevel::Restricted
        );
    }
}
