//! ACME certificate manager — automatic issuance and renewal
//!
//! Wraps `AcmeClient` with a periodic check-and-renew loop that
//! monitors certificate expiry and triggers re-issuance as needed.

#![allow(dead_code)]
use crate::config::{GatewayConfig, Protocol};
use crate::error::{GatewayError, Result};
use crate::proxy::acme::{AcmeConfig, CertInfo, CertStorage, ChallengeStore};
use crate::proxy::acme_client::AcmeClient;
use crate::proxy::tls::build_tls_acceptor_from_pem;
use std::sync::Arc;
use std::time::Duration;

/// Comparable ACME activation surface for reload restart decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AcmeActivationFingerprint {
    email: String,
    domains: Vec<String>,
    staging: bool,
    storage_path: String,
}

/// Installs ACME-issued PEMs onto live HTTPS listeners.
pub(crate) type AcmeCertificateSink = Arc<dyn Fn(&CertInfo) -> Result<()> + Send + Sync>;

/// ACME certificate manager — automatic issuance and renewal
pub struct AcmeManager {
    client: AcmeClient,
    /// How often to check certificate status (default: 12 hours)
    check_interval: Duration,
    /// Optional sink that hot-swaps listener TLS after issue / stored activate.
    certificate_sink: Option<AcmeCertificateSink>,
    /// TLS min_version used when probing / installing stored PEMs.
    tls_min_version: String,
}

impl AcmeManager {
    /// Create a new ACME manager
    pub fn new(config: AcmeConfig, challenges: Arc<ChallengeStore>) -> Result<Self> {
        let check_interval = Duration::from_secs(12 * 3600);
        let client = AcmeClient::new(config, challenges)?;
        Ok(Self {
            client,
            check_interval,
            certificate_sink: None,
            tls_min_version: "1.2".to_string(),
        })
    }

    /// Attach a sink that installs issued/stored PEMs onto live HTTPS entrypoints.
    pub(crate) fn with_certificate_sink(mut self, sink: AcmeCertificateSink) -> Self {
        self.certificate_sink = Some(sink);
        self
    }

    /// Match entrypoint TLS min_version for stored-PEM probe and install.
    pub(crate) fn with_tls_min_version(mut self, min_version: impl Into<String>) -> Self {
        self.tls_min_version = min_version.into();
        self
    }

    /// Build the ACME manager when any entrypoint enables ACME (same checks as start).
    pub(crate) fn try_from_gateway_config(config: &GatewayConfig) -> Result<Option<Self>> {
        let acme_tls = config
            .entrypoints
            .values()
            .find_map(|entrypoint| entrypoint.tls.as_ref().filter(|tls| tls.acme));
        let Some(tls) = acme_tls else {
            return Ok(None);
        };
        let email = tls.acme_email.clone().unwrap_or_default();
        if email.trim().is_empty() {
            return Err(GatewayError::Config(
                "ACME enabled but acme_email is not set".to_string(),
            ));
        }

        let domains = crate::config::resolve_acme_domains(tls, &config.routers);
        if domains.is_empty() {
            return Err(GatewayError::Config(
                "ACME requires acme_domains or at least one Host(`...`) router".to_string(),
            ));
        }
        let storage_path = tls
            .acme_storage_path
            .as_deref()
            .unwrap_or("/etc/gateway/acme");
        let storage_path = std::path::PathBuf::from(storage_path);
        // Same create/write surface as ensure_account_key / CertStorage::save,
        // plus PKCS#8 parse of a present account.key — fail before spawn so
        // validate ≡ activate instead of warn-loop forever on corrupt material.
        CertStorage::probe_activation(&storage_path)?;
        // Same rustls PEM → acceptor surface as activate_stored_certificate /
        // certificate sink install — present but unusable domain PEMs must not
        // soft-open validate while start only forever-warns under Valid expiry.
        CertStorage::probe_existing_domain_certificates(&storage_path, &domains, &tls.min_version)?;
        let acme_config = AcmeConfig {
            email,
            domains,
            staging: tls.acme_staging,
            storage_path,
            ..Default::default()
        };
        let challenges = Arc::new(ChallengeStore::new());
        Ok(Some(
            Self::new(acme_config, challenges)?.with_tls_min_version(tls.min_version.clone()),
        ))
    }

    /// Fail closed when ACME is configured but the manager/client cannot activate.
    pub(crate) fn validate_activation(config: &GatewayConfig) -> Result<()> {
        let _ = Self::try_from_gateway_config(config)?;
        Ok(())
    }

    /// Identity of the ACME activation surface used to decide reload restarts.
    pub(crate) fn activation_fingerprint(
        config: &GatewayConfig,
    ) -> Option<AcmeActivationFingerprint> {
        let tls = config
            .entrypoints
            .values()
            .find_map(|entrypoint| entrypoint.tls.as_ref().filter(|tls| tls.acme))?;
        let email = tls.acme_email.clone().unwrap_or_default();
        let domains = crate::config::resolve_acme_domains(tls, &config.routers);
        let storage_path = tls
            .acme_storage_path
            .clone()
            .unwrap_or_else(|| "/etc/gateway/acme".to_string());
        Some(AcmeActivationFingerprint {
            email,
            domains,
            staging: tls.acme_staging,
            storage_path,
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

    /// Shared HTTP-01 challenge store (same Arc the data plane must serve).
    pub fn challenges(&self) -> Arc<ChallengeStore> {
        Arc::clone(self.client.challenges())
    }

    /// Get a mutable reference to the inner client
    pub fn client_mut(&mut self) -> &mut AcmeClient {
        &mut self.client
    }

    /// Install a certificate through the configured sink (no-op without a sink).
    pub(crate) fn activate_certificate(&self, info: &CertInfo) -> Result<()> {
        let Some(sink) = &self.certificate_sink else {
            return Ok(());
        };
        sink(info)
    }

    /// Activate the best stored certificate onto listeners when present.
    ///
    /// Called at manager start so a prior issuance cannot soft-open Running
    /// while the live acceptor still serves only bootstrap PEMs.
    pub(crate) fn activate_stored_certificate(&self) -> Result<()> {
        let Some(domain) = self.client.config.domains.first() else {
            return Ok(());
        };
        if !self.client.storage.exists(domain) {
            return Ok(());
        }
        let info = self.client.storage.load(domain)?;
        self.activate_certificate(&info)
    }

    /// Check all domains and issue/renew certificates as needed.
    /// Returns the list of domains that were issued or renewed.
    pub async fn check_and_renew(&mut self) -> Result<Vec<String>> {
        let mut renewed = Vec::new();
        let renewal_days = self.client.config.renewal_days;
        let domains = self.client.config.domains.clone();
        let min_version = self.tls_min_version.clone();

        for domain in &domains {
            let needs_action = if self.client.storage.exists(domain) {
                match self.client.storage.load(domain) {
                    Ok(info) => {
                        let status = info.status(renewal_days);
                        let expiry_needs = matches!(
                            status,
                            crate::proxy::acme::CertStatus::Expired
                                | crate::proxy::acme::CertStatus::ExpiringSoon
                        );
                        if expiry_needs {
                            true
                        } else {
                            // Valid expiry with unusable PEMs must not soft-open
                            // a forever skip of re-issue (timestamp-only gate).
                            build_tls_acceptor_from_pem(&info.cert_pem, &info.key_pem, &min_version)
                                .is_err()
                        }
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
            // Issue a single certificate covering all domains, then install it
            // onto live HTTPS listeners (same PEM → rustls surface as cold start).
            let cert_info = self.client.issue_certificate().await?;
            self.activate_certificate(&cert_info)?;
        }

        Ok(renewed)
    }

    /// Run the renewal loop (blocking — spawn in a tokio task).
    ///
    /// Callers must fail-closed `activate_stored_certificate` before spawn so
    /// unusable stored PEMs cannot soft-open a forever-warn task under Running.
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

/// Build a certificate sink that hot-swaps ACME PEMs onto matching HTTP entrypoints.
pub(crate) fn gateway_certificate_sink(
    handles: Arc<std::sync::RwLock<crate::entrypoint::EntryPointHandles>>,
    config: &GatewayConfig,
) -> Option<AcmeCertificateSink> {
    let mut entrypoint_names = Vec::new();
    let mut min_version = "1.2".to_string();
    for (name, entrypoint) in &config.entrypoints {
        let Some(tls) = entrypoint.tls.as_ref().filter(|tls| tls.acme) else {
            continue;
        };
        if entrypoint.protocol != Protocol::Http {
            continue;
        }
        min_version = tls.min_version.clone();
        entrypoint_names.push(name.clone());
    }
    if entrypoint_names.is_empty() {
        return None;
    }

    Some(Arc::new(move |info: &CertInfo| -> Result<()> {
        let acceptor = build_tls_acceptor_from_pem(&info.cert_pem, &info.key_pem, &min_version)?;
        let handles = handles
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for name in &entrypoint_names {
            let Some(handle) = handles.get(name) else {
                continue;
            };
            handle.install_http_tls_acceptor(acceptor.clone())?;
            tracing::info!(
                entrypoint = %name,
                domain = %info.domain,
                "ACME certificate installed on live HTTPS listener"
            );
        }
        Ok(())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::acme::{AcmeConfig, CertInfo, CertStorage, ChallengeStore};
    use std::sync::atomic::{AtomicBool, Ordering};
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

    #[test]
    fn activate_certificate_invokes_sink() {
        let challenges = Arc::new(ChallengeStore::new());
        let called = Arc::new(AtomicBool::new(false));
        let flag = called.clone();
        let manager = AcmeManager::new(test_config(), challenges)
            .unwrap()
            .with_certificate_sink(Arc::new(move |_info| {
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }));
        let info = CertInfo {
            domain: "example.com".to_string(),
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            expires_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 86400,
            issued_at: 0,
        };
        manager.activate_certificate(&info).unwrap();
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn activate_stored_certificate_loads_from_storage() {
        let dir = tempfile::tempdir().unwrap();
        let storage = CertStorage::new(dir.path());
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = CertInfo {
            domain: "example.com".to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----".to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----".to_string(),
            expires_at: now + 86400,
            issued_at: now,
        };
        storage.save(&info).unwrap();

        let mut config = test_config();
        config.storage_path = dir.path().to_path_buf();
        let challenges = Arc::new(ChallengeStore::new());
        let called = Arc::new(AtomicBool::new(false));
        let flag = called.clone();
        let manager = AcmeManager::new(config, challenges)
            .unwrap()
            .with_certificate_sink(Arc::new(move |loaded| {
                assert_eq!(loaded.domain, "example.com");
                assert!(loaded.cert_pem.contains("BEGIN CERTIFICATE"));
                flag.store(true, Ordering::SeqCst);
                Ok(())
            }));
        manager.activate_stored_certificate().unwrap();
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn activate_stored_certificate_fails_closed_when_sink_rejects_unusable_pem() {
        let dir = tempfile::tempdir().unwrap();
        let storage = CertStorage::new(dir.path());
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let info = CertInfo {
            domain: "example.com".to_string(),
            cert_pem: "-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n"
                .to_string(),
            key_pem: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n"
                .to_string(),
            expires_at: now + 90 * 86400,
            issued_at: now,
        };
        storage.save(&info).unwrap();

        let mut config = test_config();
        config.storage_path = dir.path().to_path_buf();
        let challenges = Arc::new(ChallengeStore::new());
        let manager = AcmeManager::new(config, challenges)
            .unwrap()
            .with_certificate_sink(Arc::new(|loaded| {
                build_tls_acceptor_from_pem(&loaded.cert_pem, &loaded.key_pem, "1.2")?;
                Ok(())
            }));
        let error = manager.activate_stored_certificate().unwrap_err();
        assert!(
            error.to_string().contains("certificate")
                || error.to_string().contains("TLS")
                || error.to_string().contains("PEM")
                || error.to_string().contains("private key"),
            "unusable stored PEM must fail activate: {error}"
        );
    }

    #[test]
    fn test_manager_client_access() {
        let challenges = Arc::new(ChallengeStore::new());
        let mut manager = AcmeManager::new(test_config(), challenges).unwrap();
        assert_eq!(manager.client().config.email, "test@example.com");
        assert_eq!(manager.client_mut().config.domains, vec!["example.com"]);
    }
}
