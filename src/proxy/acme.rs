//! ACME/Let's Encrypt — automatic TLS certificate management
//!
//! Provides automatic certificate issuance and renewal via the ACME protocol.
//! Supports HTTP-01 challenge validation for domain verification.

#![allow(dead_code)]
use crate::error::{GatewayError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// ACME directory URLs
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
pub const LETS_ENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

/// Default renewal threshold (30 days before expiry)
const DEFAULT_RENEWAL_DAYS: u64 = 30;

/// ACME challenge type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ChallengeType {
    /// HTTP-01: serve a token at /.well-known/acme-challenge/<token>
    #[serde(rename = "http-01")]
    #[default]
    Http01,
    /// DNS-01: create a TXT record at _acme-challenge.<domain>
    #[serde(rename = "dns-01")]
    Dns01,
}

/// ACME configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// ACME directory URL
    #[serde(default = "default_directory")]
    pub directory_url: String,
    /// Contact email for the ACME account
    pub email: String,
    /// Domains to obtain certificates for
    pub domains: Vec<String>,
    /// Storage path for certificates and account keys
    #[serde(default = "default_storage_path")]
    pub storage_path: PathBuf,
    /// Use staging environment (for testing)
    #[serde(default)]
    pub staging: bool,
    /// Days before expiry to trigger renewal
    #[serde(default = "default_renewal_days")]
    pub renewal_days: u64,
    /// Challenge type (default: http-01)
    #[serde(default)]
    pub challenge_type: ChallengeType,
    /// DNS provider configuration (required when challenge_type is dns-01)
    #[serde(default)]
    pub dns_provider: Option<crate::proxy::acme_dns::DnsProviderConfig>,
}

fn default_directory() -> String {
    LETS_ENCRYPT_PRODUCTION.to_string()
}

fn default_storage_path() -> PathBuf {
    PathBuf::from("/etc/gateway/acme")
}

fn default_renewal_days() -> u64 {
    DEFAULT_RENEWAL_DAYS
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            directory_url: default_directory(),
            email: String::new(),
            domains: Vec::new(),
            storage_path: default_storage_path(),
            staging: false,
            renewal_days: DEFAULT_RENEWAL_DAYS,
            challenge_type: ChallengeType::default(),
            dns_provider: None,
        }
    }
}

impl AcmeConfig {
    /// Get the effective directory URL (staging or production)
    pub fn effective_directory(&self) -> &str {
        if self.staging {
            LETS_ENCRYPT_STAGING
        } else {
            &self.directory_url
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.email.is_empty() {
            return Err(GatewayError::Config("ACME email is required".to_string()));
        }
        if self.domains.is_empty() {
            return Err(GatewayError::Config(
                "ACME requires at least one domain".to_string(),
            ));
        }
        for domain in &self.domains {
            if domain.is_empty() || domain.contains(' ') {
                return Err(GatewayError::Config(format!(
                    "Invalid ACME domain: '{}'",
                    domain
                )));
            }
        }
        if self.challenge_type == ChallengeType::Dns01 {
            match &self.dns_provider {
                Some(dns_config) => dns_config.validate()?,
                None => {
                    return Err(GatewayError::Config(
                        "DNS provider configuration is required for DNS-01 challenge".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Certificate status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CertStatus {
    /// No certificate exists
    Missing,
    /// Certificate is valid
    Valid,
    /// Certificate is expiring soon (within renewal window)
    ExpiringSoon,
    /// Certificate has expired
    Expired,
    /// Certificate issuance/renewal is in progress
    Pending,
    /// Certificate issuance/renewal failed
    Failed(String),
}

impl std::fmt::Display for CertStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "missing"),
            Self::Valid => write!(f, "valid"),
            Self::ExpiringSoon => write!(f, "expiring-soon"),
            Self::Expired => write!(f, "expired"),
            Self::Pending => write!(f, "pending"),
            Self::Failed(msg) => write!(f, "failed: {}", msg),
        }
    }
}

/// Stored certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    /// Domain name
    pub domain: String,
    /// Certificate PEM data
    pub cert_pem: String,
    /// Private key PEM data
    pub key_pem: String,
    /// Expiry timestamp (seconds since epoch)
    pub expires_at: u64,
    /// Issuance timestamp (seconds since epoch)
    pub issued_at: u64,
}

impl CertInfo {
    /// Check if the certificate has expired
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now >= self.expires_at
    }

    /// Check if the certificate is expiring within the given number of days
    pub fn is_expiring_within(&self, days: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let threshold = self.expires_at.saturating_sub(days * 86400);
        now >= threshold
    }

    /// Get the remaining validity duration
    pub fn remaining(&self) -> Duration {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now >= self.expires_at {
            Duration::ZERO
        } else {
            Duration::from_secs(self.expires_at - now)
        }
    }

    /// Get the status based on renewal threshold
    pub fn status(&self, renewal_days: u64) -> CertStatus {
        if self.is_expired() {
            CertStatus::Expired
        } else if self.is_expiring_within(renewal_days) {
            CertStatus::ExpiringSoon
        } else {
            CertStatus::Valid
        }
    }
}

/// HTTP-01 challenge token store
///
/// When the ACME server sends an HTTP-01 challenge, the gateway must serve
/// the challenge response at `/.well-known/acme-challenge/<token>`.
pub struct ChallengeStore {
    /// token → key_authorization mapping
    challenges: Arc<RwLock<HashMap<String, String>>>,
}

impl ChallengeStore {
    /// Create a new challenge store
    pub fn new() -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a challenge token and its key authorization
    pub fn add(&self, token: String, key_authorization: String) {
        let mut challenges = self.challenges.write().unwrap();
        challenges.insert(token, key_authorization);
    }

    /// Get the key authorization for a token
    pub fn get(&self, token: &str) -> Option<String> {
        let challenges = self.challenges.read().unwrap();
        challenges.get(token).cloned()
    }

    /// Remove a challenge token
    pub fn remove(&self, token: &str) {
        let mut challenges = self.challenges.write().unwrap();
        challenges.remove(token);
    }

    /// Clear all challenges
    pub fn clear(&self) {
        let mut challenges = self.challenges.write().unwrap();
        challenges.clear();
    }

    /// Number of active challenges
    pub fn len(&self) -> usize {
        let challenges = self.challenges.read().unwrap();
        challenges.len()
    }

    /// Check if there are no active challenges
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if a request path is an ACME challenge path
    pub fn is_challenge_path(path: &str) -> bool {
        path.starts_with("/.well-known/acme-challenge/")
    }

    /// Extract the token from an ACME challenge path
    pub fn extract_token(path: &str) -> Option<&str> {
        path.strip_prefix("/.well-known/acme-challenge/")
            .filter(|t| !t.is_empty())
    }
}

impl Default for ChallengeStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Certificate storage — persists certificates to disk
pub struct CertStorage {
    base_path: PathBuf,
}

impl CertStorage {
    /// Create a new certificate storage
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }

    /// Get the base storage path
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Get the certificate file path for a domain
    pub fn cert_path(&self, domain: &str) -> PathBuf {
        self.base_path
            .join(format!("{}.crt", sanitize_domain(domain)))
    }

    /// Get the key file path for a domain
    pub fn key_path(&self, domain: &str) -> PathBuf {
        self.base_path
            .join(format!("{}.key", sanitize_domain(domain)))
    }

    /// Get the metadata file path for a domain
    pub fn meta_path(&self, domain: &str) -> PathBuf {
        self.base_path
            .join(format!("{}.json", sanitize_domain(domain)))
    }

    /// Save certificate info to disk
    pub fn save(&self, info: &CertInfo) -> Result<()> {
        std::fs::create_dir_all(&self.base_path).map_err(|e| {
            GatewayError::Other(format!(
                "Failed to create ACME storage directory {}: {}",
                self.base_path.display(),
                e
            ))
        })?;

        // Write cert PEM
        std::fs::write(self.cert_path(&info.domain), &info.cert_pem)
            .map_err(|e| GatewayError::Other(format!("Failed to write certificate: {}", e)))?;

        // Write key PEM
        std::fs::write(self.key_path(&info.domain), &info.key_pem)
            .map_err(|e| GatewayError::Other(format!("Failed to write private key: {}", e)))?;

        // Write metadata
        let meta = serde_json::to_string_pretty(info).map_err(|e| {
            GatewayError::Other(format!("Failed to serialize cert metadata: {}", e))
        })?;
        std::fs::write(self.meta_path(&info.domain), meta)
            .map_err(|e| GatewayError::Other(format!("Failed to write cert metadata: {}", e)))?;

        Ok(())
    }

    /// Load certificate info from disk
    pub fn load(&self, domain: &str) -> Result<CertInfo> {
        let meta_path = self.meta_path(domain);
        let content = std::fs::read_to_string(&meta_path).map_err(|e| {
            GatewayError::Other(format!(
                "Failed to read cert metadata {}: {}",
                meta_path.display(),
                e
            ))
        })?;
        let info: CertInfo = serde_json::from_str(&content)
            .map_err(|e| GatewayError::Other(format!("Failed to parse cert metadata: {}", e)))?;
        Ok(info)
    }

    /// Check if a certificate exists on disk
    pub fn exists(&self, domain: &str) -> bool {
        self.cert_path(domain).exists() && self.key_path(domain).exists()
    }
}

/// Sanitize a domain name for use as a filename
fn sanitize_domain(domain: &str) -> String {
    domain
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- AcmeConfig ---

    #[test]
    fn test_config_default() {
        let config = AcmeConfig::default();
        assert_eq!(config.directory_url, LETS_ENCRYPT_PRODUCTION);
        assert!(config.email.is_empty());
        assert!(config.domains.is_empty());
        assert!(!config.staging);
        assert_eq!(config.renewal_days, 30);
    }

    #[test]
    fn test_config_effective_directory_production() {
        let config = AcmeConfig {
            staging: false,
            ..Default::default()
        };
        assert_eq!(config.effective_directory(), LETS_ENCRYPT_PRODUCTION);
    }

    #[test]
    fn test_config_effective_directory_staging() {
        let config = AcmeConfig {
            staging: true,
            ..Default::default()
        };
        assert_eq!(config.effective_directory(), LETS_ENCRYPT_STAGING);
    }

    #[test]
    fn test_config_validate_ok() {
        let config = AcmeConfig {
            email: "admin@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_missing_email() {
        let config = AcmeConfig {
            domains: vec!["example.com".to_string()],
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("email"));
    }

    #[test]
    fn test_config_validate_missing_domains() {
        let config = AcmeConfig {
            email: "admin@example.com".to_string(),
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("domain"));
    }

    #[test]
    fn test_config_validate_invalid_domain() {
        let config = AcmeConfig {
            email: "admin@example.com".to_string(),
            domains: vec!["invalid domain".to_string()],
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("Invalid ACME domain"));
    }

    #[test]
    fn test_config_validate_empty_domain() {
        let config = AcmeConfig {
            email: "admin@example.com".to_string(),
            domains: vec!["".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string(), "www.example.com".to_string()],
            staging: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AcmeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.email, "test@example.com");
        assert_eq!(parsed.domains.len(), 2);
        assert!(parsed.staging);
    }

    // --- CertStatus ---

    #[test]
    fn test_cert_status_display() {
        assert_eq!(CertStatus::Missing.to_string(), "missing");
        assert_eq!(CertStatus::Valid.to_string(), "valid");
        assert_eq!(CertStatus::ExpiringSoon.to_string(), "expiring-soon");
        assert_eq!(CertStatus::Expired.to_string(), "expired");
        assert_eq!(CertStatus::Pending.to_string(), "pending");
        assert_eq!(
            CertStatus::Failed("timeout".to_string()).to_string(),
            "failed: timeout"
        );
    }

    #[test]
    fn test_cert_status_equality() {
        assert_eq!(CertStatus::Valid, CertStatus::Valid);
        assert_ne!(CertStatus::Valid, CertStatus::Expired);
    }

    // --- CertInfo ---

    #[test]
    fn test_cert_info_expired() {
        let info = CertInfo {
            domain: "example.com".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            expires_at: 1000, // Long expired
            issued_at: 0,
        };
        assert!(info.is_expired());
        assert_eq!(info.remaining(), Duration::ZERO);
        assert_eq!(info.status(30), CertStatus::Expired);
    }

    #[test]
    fn test_cert_info_valid() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = CertInfo {
            domain: "example.com".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            expires_at: now + 90 * 86400, // 90 days from now
            issued_at: now,
        };
        assert!(!info.is_expired());
        assert!(info.remaining() > Duration::ZERO);
        assert_eq!(info.status(30), CertStatus::Valid);
    }

    #[test]
    fn test_cert_info_expiring_soon() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = CertInfo {
            domain: "example.com".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            expires_at: now + 15 * 86400, // 15 days from now
            issued_at: now,
        };
        assert!(!info.is_expired());
        assert!(info.is_expiring_within(30));
        assert_eq!(info.status(30), CertStatus::ExpiringSoon);
    }

    #[test]
    fn test_cert_info_serialization() {
        let info = CertInfo {
            domain: "example.com".to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            expires_at: 1700000000,
            issued_at: 1690000000,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: CertInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.expires_at, 1700000000);
    }

    // --- ChallengeStore ---

    #[test]
    fn test_challenge_store_new() {
        let store = ChallengeStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_challenge_store_add_get() {
        let store = ChallengeStore::new();
        store.add("token123".to_string(), "auth456".to_string());
        assert_eq!(store.get("token123"), Some("auth456".to_string()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_challenge_store_get_missing() {
        let store = ChallengeStore::new();
        assert_eq!(store.get("nonexistent"), None);
    }

    #[test]
    fn test_challenge_store_remove() {
        let store = ChallengeStore::new();
        store.add("token123".to_string(), "auth456".to_string());
        store.remove("token123");
        assert!(store.is_empty());
        assert_eq!(store.get("token123"), None);
    }

    #[test]
    fn test_challenge_store_clear() {
        let store = ChallengeStore::new();
        store.add("t1".to_string(), "a1".to_string());
        store.add("t2".to_string(), "a2".to_string());
        assert_eq!(store.len(), 2);
        store.clear();
        assert!(store.is_empty());
    }

    #[test]
    fn test_is_challenge_path() {
        assert!(ChallengeStore::is_challenge_path(
            "/.well-known/acme-challenge/abc123"
        ));
        assert!(!ChallengeStore::is_challenge_path("/api/data"));
        assert!(!ChallengeStore::is_challenge_path("/.well-known/other"));
    }

    #[test]
    fn test_extract_token() {
        assert_eq!(
            ChallengeStore::extract_token("/.well-known/acme-challenge/abc123"),
            Some("abc123")
        );
        assert_eq!(
            ChallengeStore::extract_token("/.well-known/acme-challenge/"),
            None
        );
        assert_eq!(ChallengeStore::extract_token("/other/path"), None);
    }

    // --- CertStorage ---

    #[test]
    fn test_cert_storage_paths() {
        let storage = CertStorage::new("/etc/acme");
        assert_eq!(storage.base_path(), Path::new("/etc/acme"));
        assert_eq!(
            storage.cert_path("example.com"),
            PathBuf::from("/etc/acme/example.com.crt")
        );
        assert_eq!(
            storage.key_path("example.com"),
            PathBuf::from("/etc/acme/example.com.key")
        );
        assert_eq!(
            storage.meta_path("example.com"),
            PathBuf::from("/etc/acme/example.com.json")
        );
    }

    #[test]
    fn test_cert_storage_save_load() {
        let dir = tempfile::tempdir().unwrap();
        let storage = CertStorage::new(dir.path());

        let info = CertInfo {
            domain: "test.example.com".to_string(),
            cert_pem: "cert-data".to_string(),
            key_pem: "key-data".to_string(),
            expires_at: 1700000000,
            issued_at: 1690000000,
        };

        storage.save(&info).unwrap();
        assert!(storage.exists("test.example.com"));

        let loaded = storage.load("test.example.com").unwrap();
        assert_eq!(loaded.domain, "test.example.com");
        assert_eq!(loaded.cert_pem, "cert-data");
        assert_eq!(loaded.key_pem, "key-data");
    }

    #[test]
    fn test_cert_storage_not_exists() {
        let dir = tempfile::tempdir().unwrap();
        let storage = CertStorage::new(dir.path());
        assert!(!storage.exists("nonexistent.com"));
    }

    #[test]
    fn test_cert_storage_load_missing() {
        let dir = tempfile::tempdir().unwrap();
        let storage = CertStorage::new(dir.path());
        let result = storage.load("nonexistent.com");
        assert!(result.is_err());
    }

    // --- sanitize_domain ---

    #[test]
    fn test_sanitize_domain() {
        assert_eq!(sanitize_domain("example.com"), "example.com");
        assert_eq!(sanitize_domain("sub.example.com"), "sub.example.com");
        assert_eq!(sanitize_domain("my-domain.com"), "my-domain.com");
        assert_eq!(sanitize_domain("*.example.com"), "_.example.com");
    }

    // --- Constants ---

    #[test]
    fn test_lets_encrypt_urls() {
        assert!(LETS_ENCRYPT_PRODUCTION.contains("acme-v02"));
        assert!(LETS_ENCRYPT_STAGING.contains("staging"));
    }

    // --- ChallengeType ---

    #[test]
    fn test_challenge_type_default() {
        assert_eq!(ChallengeType::default(), ChallengeType::Http01);
    }

    #[test]
    fn test_challenge_type_serialization() {
        let json = serde_json::to_string(&ChallengeType::Http01).unwrap();
        assert_eq!(json, "\"http-01\"");
        let json = serde_json::to_string(&ChallengeType::Dns01).unwrap();
        assert_eq!(json, "\"dns-01\"");
    }

    #[test]
    fn test_challenge_type_deserialization() {
        let parsed: ChallengeType = serde_json::from_str("\"http-01\"").unwrap();
        assert_eq!(parsed, ChallengeType::Http01);
        let parsed: ChallengeType = serde_json::from_str("\"dns-01\"").unwrap();
        assert_eq!(parsed, ChallengeType::Dns01);
    }

    // --- DNS-01 validation ---

    #[test]
    fn test_config_validate_dns01_missing_provider() {
        let config = AcmeConfig {
            email: "admin@example.com".to_string(),
            domains: vec!["*.example.com".to_string()],
            challenge_type: ChallengeType::Dns01,
            dns_provider: None,
            ..Default::default()
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("DNS provider"));
    }

    #[test]
    fn test_config_validate_dns01_with_provider() {
        let config = AcmeConfig {
            email: "admin@example.com".to_string(),
            domains: vec!["*.example.com".to_string()],
            challenge_type: ChallengeType::Dns01,
            dns_provider: Some(crate::proxy::acme_dns::DnsProviderConfig {
                provider: crate::proxy::acme_dns::DnsProvider::Cloudflare,
                api_token: "tok".to_string(),
                zone_id: "z1".to_string(),
                propagation_wait_secs: 60,
            }),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_dns01_invalid_provider() {
        let config = AcmeConfig {
            email: "admin@example.com".to_string(),
            domains: vec!["*.example.com".to_string()],
            challenge_type: ChallengeType::Dns01,
            dns_provider: Some(crate::proxy::acme_dns::DnsProviderConfig {
                provider: crate::proxy::acme_dns::DnsProvider::Cloudflare,
                api_token: String::new(), // invalid
                zone_id: "z1".to_string(),
                propagation_wait_secs: 60,
            }),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_http01_ignores_dns_provider() {
        // HTTP-01 should not require dns_provider
        let config = AcmeConfig {
            email: "admin@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            challenge_type: ChallengeType::Http01,
            dns_provider: None,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }
}
