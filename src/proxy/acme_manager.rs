//! ACME certificate manager — automatic issuance and renewal
//!
//! Wraps `AcmeClient` with a periodic check-and-renew loop that
//! monitors certificate expiry and triggers re-issuance as needed.

#![allow(dead_code)]
use crate::error::Result;
use crate::proxy::acme::{AcmeConfig, ChallengeStore};
use crate::proxy::acme_client::AcmeClient;
use std::sync::Arc;
use std::time::Duration;

/// ACME certificate manager — automatic issuance and renewal
pub struct AcmeManager {
    client: AcmeClient,
    /// How often to check certificate status (default: 12 hours)
    check_interval: Duration,
}

impl AcmeManager {
    /// Create a new ACME manager
    pub fn new(config: AcmeConfig, challenges: Arc<ChallengeStore>) -> Result<Self> {
        let check_interval = Duration::from_secs(12 * 3600);
        let client = AcmeClient::new(config, challenges)?;
        Ok(Self {
            client,
            check_interval,
        })
    }

    /// Set the check interval
    pub fn with_check_interval(mut self, interval: Duration) -> Self {
        self.check_interval = interval;
        self
    }

    /// Get a reference to the inner client
    pub fn client(&self) -> &AcmeClient {
        &self.client
    }

    /// Get a mutable reference to the inner client
    pub fn client_mut(&mut self) -> &mut AcmeClient {
        &mut self.client
    }

    /// Check all domains and issue/renew certificates as needed.
    /// Returns the list of domains that were issued or renewed.
    pub async fn check_and_renew(&mut self) -> Result<Vec<String>> {
        let mut renewed = Vec::new();
        let renewal_days = self.client.config.renewal_days;
        let domains = self.client.config.domains.clone();

        for domain in &domains {
            let needs_action = if self.client.storage.exists(domain) {
                match self.client.storage.load(domain) {
                    Ok(info) => {
                        let status = info.status(renewal_days);
                        matches!(
                            status,
                            crate::proxy::acme::CertStatus::Expired
                                | crate::proxy::acme::CertStatus::ExpiringSoon
                        )
                    }
                    Err(_) => true, // Corrupted metadata, re-issue
                }
            } else {
                true // Missing certificate
            };

            if needs_action {
                tracing::info!(domain = domain, "Certificate needs issuance/renewal");
                renewed.push(domain.clone());
            }
        }

        if !renewed.is_empty() {
            // Issue a single certificate covering all domains
            self.client.issue_certificate().await?;
        }

        Ok(renewed)
    }

    /// Run the renewal loop (blocking — spawn in a tokio task)
    pub async fn run(mut self) {
        tracing::info!(
            interval_hours = self.check_interval.as_secs() / 3600,
            domains = ?self.client.config.domains,
            "ACME manager started"
        );

        loop {
            match self.check_and_renew().await {
                Ok(renewed) => {
                    if !renewed.is_empty() {
                        tracing::info!(
                            domains = ?renewed,
                            "Certificates issued/renewed"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(error = %e, "ACME renewal check failed");
                }
            }

            tokio::time::sleep(self.check_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::acme::{AcmeConfig, CertInfo, CertStorage, ChallengeStore};
    use std::time::SystemTime;

    fn test_config() -> AcmeConfig {
        AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            staging: true,
            storage_path: std::path::PathBuf::from("/tmp/acme-test"),
            ..Default::default()
        }
    }

    #[test]
    fn test_manager_new() {
        let challenges = Arc::new(ChallengeStore::new());
        let manager = AcmeManager::new(test_config(), challenges).unwrap();
        assert_eq!(manager.check_interval, Duration::from_secs(12 * 3600));
    }

    #[test]
    fn test_manager_with_check_interval() {
        let challenges = Arc::new(ChallengeStore::new());
        let manager = AcmeManager::new(test_config(), challenges)
            .unwrap()
            .with_check_interval(Duration::from_secs(3600));
        assert_eq!(manager.check_interval, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn test_manager_check_and_renew_missing_cert() {
        let dir = tempfile::tempdir().unwrap();
        let challenges = Arc::new(ChallengeStore::new());
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            storage_path: dir.path().to_path_buf(),
            staging: true,
            ..Default::default()
        };
        let mut manager = AcmeManager::new(config, challenges).unwrap();

        // check_and_renew will detect missing cert and try to issue,
        // which will fail because we can't reach the ACME server in tests.
        // That's expected — we're testing the detection logic.
        let result = manager.check_and_renew().await;
        assert!(result.is_err()); // Can't reach ACME server
    }

    #[tokio::test]
    async fn test_manager_check_valid_cert_no_renewal() {
        let dir = tempfile::tempdir().unwrap();
        let challenges = Arc::new(ChallengeStore::new());
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["test.example.com".to_string()],
            storage_path: dir.path().to_path_buf(),
            staging: true,
            ..Default::default()
        };

        // Pre-populate a valid certificate
        let storage = CertStorage::new(dir.path());
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let cert_info = CertInfo {
            domain: "test.example.com".to_string(),
            cert_pem: "cert-data".to_string(),
            key_pem: "key-data".to_string(),
            expires_at: now + 60 * 86400, // 60 days from now
            issued_at: now,
        };
        storage.save(&cert_info).unwrap();

        let mut manager = AcmeManager::new(config, challenges).unwrap();
        let renewed = manager.check_and_renew().await.unwrap();
        assert!(renewed.is_empty()); // No renewal needed
    }
}
