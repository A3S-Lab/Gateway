//! ACME DNS-01 challenge solver
//!
//! Supports DNS-based domain validation for wildcard certificates.
//! Implements the Cloudflare DNS API for TXT record management.

#![allow(dead_code)]
use crate::error::{GatewayError, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// DNS provider type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DnsProvider {
    /// Cloudflare DNS API
    #[default]
    Cloudflare,
    /// AWS Route53 (placeholder for future implementation)
    Route53,
}


/// DNS provider configuration for ACME DNS-01 challenges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    /// DNS provider type
    #[serde(default)]
    pub provider: DnsProvider,
    /// API token for authentication
    pub api_token: String,
    /// Zone ID (Cloudflare) or Hosted Zone ID (Route53)
    #[serde(default)]
    pub zone_id: String,
    /// Propagation wait time in seconds (default: 60)
    #[serde(default = "default_propagation_wait")]
    pub propagation_wait_secs: u64,
}

fn default_propagation_wait() -> u64 {
    60
}

impl DnsProviderConfig {
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.api_token.is_empty() {
            return Err(GatewayError::Config(
                "DNS provider api_token is required".to_string(),
            ));
        }
        match self.provider {
            DnsProvider::Cloudflare => {
                if self.zone_id.is_empty() {
                    return Err(GatewayError::Config(
                        "Cloudflare zone_id is required".to_string(),
                    ));
                }
            }
            DnsProvider::Route53 => {
                // Route53 uses hosted_zone_id from zone_id field
                if self.zone_id.is_empty() {
                    return Err(GatewayError::Config(
                        "Route53 zone_id (hosted zone ID) is required".to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// DNS-01 challenge solver trait
#[async_trait::async_trait]
pub trait DnsSolver: Send + Sync {
    /// Create a TXT record for the ACME challenge
    /// Record name: `_acme-challenge.<domain>`
    /// Record value: the key authorization digest
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String>;

    /// Delete a TXT record by ID after challenge validation
    async fn delete_txt_record(&self, record_id: &str) -> Result<()>;

    /// Wait for DNS propagation
    async fn wait_for_propagation(&self);
}

/// Cloudflare DNS solver
pub struct CloudflareSolver {
    http: reqwest::Client,
    api_token: String,
    zone_id: String,
    propagation_wait: Duration,
}

/// Cloudflare API response wrapper
#[derive(Debug, Deserialize)]
struct CfResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<T>,
}

/// Cloudflare API error
#[derive(Debug, Deserialize)]
struct CfError {
    #[serde(default)]
    message: String,
}

/// Cloudflare DNS record
#[derive(Debug, Deserialize)]
struct CfDnsRecord {
    id: String,
}

impl CloudflareSolver {
    /// Create a new Cloudflare DNS solver
    pub fn new(config: &DnsProviderConfig) -> Result<Self> {
        config.validate()?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| GatewayError::Other(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            http,
            api_token: config.api_token.clone(),
            zone_id: config.zone_id.clone(),
            propagation_wait: Duration::from_secs(config.propagation_wait_secs),
        })
    }

    /// Get the Cloudflare API base URL for DNS records
    fn api_url(&self) -> String {
        format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            self.zone_id
        )
    }
}

#[async_trait::async_trait]
impl DnsSolver for CloudflareSolver {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        let record_name = format!("_acme-challenge.{}", domain);
        let body = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120,
        });

        let resp = self
            .http
            .post(self.api_url())
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                GatewayError::Other(format!("Cloudflare API request failed: {}", e))
            })?;

        let status = resp.status();
        let cf_resp: CfResponse<CfDnsRecord> = resp.json().await.map_err(|e| {
            GatewayError::Other(format!("Failed to parse Cloudflare response: {}", e))
        })?;

        if !cf_resp.success {
            let errors: Vec<String> = cf_resp.errors.iter().map(|e| e.message.clone()).collect();
            return Err(GatewayError::Other(format!(
                "Cloudflare DNS record creation failed (HTTP {}): {}",
                status,
                errors.join(", ")
            )));
        }

        let record = cf_resp.result.ok_or_else(|| {
            GatewayError::Other("Cloudflare returned success but no record".to_string())
        })?;

        tracing::info!(
            domain = domain,
            record_name = record_name,
            record_id = record.id,
            "DNS-01 TXT record created"
        );

        Ok(record.id)
    }

    async fn delete_txt_record(&self, record_id: &str) -> Result<()> {
        let url = format!("{}/{}", self.api_url(), record_id);

        let resp = self
            .http
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| {
                GatewayError::Other(format!("Cloudflare delete request failed: {}", e))
            })?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Other(format!(
                "Cloudflare DNS record deletion failed: {}",
                body
            )));
        }

        tracing::debug!(record_id = record_id, "DNS-01 TXT record deleted");
        Ok(())
    }

    async fn wait_for_propagation(&self) {
        tracing::info!(
            wait_secs = self.propagation_wait.as_secs(),
            "Waiting for DNS propagation"
        );
        tokio::time::sleep(self.propagation_wait).await;
    }
}

/// Create a DNS solver from configuration
pub fn create_solver(config: &DnsProviderConfig) -> Result<Box<dyn DnsSolver>> {
    match config.provider {
        DnsProvider::Cloudflare => Ok(Box::new(CloudflareSolver::new(config)?)),
        DnsProvider::Route53 => Err(GatewayError::Config(
            "Route53 DNS solver is not yet implemented".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- DnsProvider ---

    #[test]
    fn test_dns_provider_default() {
        assert_eq!(DnsProvider::default(), DnsProvider::Cloudflare);
    }

    #[test]
    fn test_dns_provider_serialization() {
        let json = serde_json::to_string(&DnsProvider::Cloudflare).unwrap();
        assert_eq!(json, "\"cloudflare\"");
        let json = serde_json::to_string(&DnsProvider::Route53).unwrap();
        assert_eq!(json, "\"route53\"");
    }

    #[test]
    fn test_dns_provider_deserialization() {
        let parsed: DnsProvider = serde_json::from_str("\"cloudflare\"").unwrap();
        assert_eq!(parsed, DnsProvider::Cloudflare);
        let parsed: DnsProvider = serde_json::from_str("\"route53\"").unwrap();
        assert_eq!(parsed, DnsProvider::Route53);
    }

    // --- DnsProviderConfig ---

    #[test]
    fn test_config_validate_ok() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Cloudflare,
            api_token: "test-token".to_string(),
            zone_id: "zone123".to_string(),
            propagation_wait_secs: 60,
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validate_missing_token() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Cloudflare,
            api_token: String::new(),
            zone_id: "zone123".to_string(),
            propagation_wait_secs: 60,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("api_token"));
    }

    #[test]
    fn test_config_validate_cloudflare_missing_zone() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Cloudflare,
            api_token: "test-token".to_string(),
            zone_id: String::new(),
            propagation_wait_secs: 60,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("zone_id"));
    }

    #[test]
    fn test_config_validate_route53_missing_zone() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Route53,
            api_token: "test-token".to_string(),
            zone_id: String::new(),
            propagation_wait_secs: 60,
        };
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("zone_id"));
    }

    #[test]
    fn test_config_serialization() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Cloudflare,
            api_token: "my-token".to_string(),
            zone_id: "zone-abc".to_string(),
            propagation_wait_secs: 120,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DnsProviderConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.provider, DnsProvider::Cloudflare);
        assert_eq!(parsed.api_token, "my-token");
        assert_eq!(parsed.zone_id, "zone-abc");
        assert_eq!(parsed.propagation_wait_secs, 120);
    }

    #[test]
    fn test_config_deserialization_defaults() {
        let json = r#"{"api_token": "tok", "zone_id": "z1"}"#;
        let config: DnsProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.provider, DnsProvider::Cloudflare); // default
        assert_eq!(config.propagation_wait_secs, 60); // default
    }

    // --- CloudflareSolver ---

    #[test]
    fn test_cloudflare_solver_new() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Cloudflare,
            api_token: "test-token".to_string(),
            zone_id: "zone123".to_string(),
            propagation_wait_secs: 30,
        };
        let solver = CloudflareSolver::new(&config).unwrap();
        assert_eq!(solver.api_token, "test-token");
        assert_eq!(solver.zone_id, "zone123");
        assert_eq!(solver.propagation_wait, Duration::from_secs(30));
    }

    #[test]
    fn test_cloudflare_solver_api_url() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Cloudflare,
            api_token: "tok".to_string(),
            zone_id: "abc123".to_string(),
            propagation_wait_secs: 60,
        };
        let solver = CloudflareSolver::new(&config).unwrap();
        assert_eq!(
            solver.api_url(),
            "https://api.cloudflare.com/client/v4/zones/abc123/dns_records"
        );
    }

    #[test]
    fn test_cloudflare_solver_invalid_config() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Cloudflare,
            api_token: String::new(),
            zone_id: "zone123".to_string(),
            propagation_wait_secs: 60,
        };
        assert!(CloudflareSolver::new(&config).is_err());
    }

    // --- create_solver ---

    #[test]
    fn test_create_solver_cloudflare() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Cloudflare,
            api_token: "tok".to_string(),
            zone_id: "z1".to_string(),
            propagation_wait_secs: 60,
        };
        assert!(create_solver(&config).is_ok());
    }

    #[test]
    fn test_create_solver_route53_not_implemented() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Route53,
            api_token: "tok".to_string(),
            zone_id: "z1".to_string(),
            propagation_wait_secs: 60,
        };
        let result = create_solver(&config);
        assert!(result.is_err());
    }
}
