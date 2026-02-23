//! ACME DNS-01 challenge solver
//!
//! Supports DNS-based domain validation for wildcard certificates.
//! Implements the Cloudflare and AWS Route53 DNS APIs for TXT record management.

use crate::error::{GatewayError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// DNS provider type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DnsProvider {
    /// Cloudflare DNS API
    #[default]
    Cloudflare,
    /// AWS Route53
    Route53,
}

/// DNS provider configuration for ACME DNS-01 challenges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    /// DNS provider type
    #[serde(default)]
    pub provider: DnsProvider,
    /// API token for authentication.
    /// - Cloudflare: Bearer API token
    /// - Route53: "ACCESS_KEY_ID:SECRET_ACCESS_KEY"
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
    /// Create a TXT record for the ACME challenge.
    /// Record name: `_acme-challenge.<domain>`
    /// Record value: the key authorization digest.
    /// Returns an opaque record ID used for deletion.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String>;

    /// Delete a TXT record by the ID returned from `create_txt_record`
    async fn delete_txt_record(&self, record_id: &str) -> Result<()>;

    /// Wait for DNS propagation
    async fn wait_for_propagation(&self);
}

// ---------------------------------------------------------------------------
// Cloudflare solver
// ---------------------------------------------------------------------------

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
            .map_err(|e| GatewayError::Other(format!("Cloudflare API request failed: {}", e)))?;

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
            .map_err(|e| GatewayError::Other(format!("Cloudflare delete request failed: {}", e)))?;

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

// ---------------------------------------------------------------------------
// AWS Route53 solver
// ---------------------------------------------------------------------------

const ROUTE53_REGION: &str = "us-east-1";
const ROUTE53_SERVICE: &str = "route53";
const ROUTE53_HOST: &str = "route53.amazonaws.com";

/// Hex-encode bytes as a lowercase string
fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// SHA-256 hash of `data`, returned as a lowercase hex string
fn sha256_hex(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    hex_lower(digest.as_ref())
}

/// HMAC-SHA256 of `data` with `key`
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let k = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key);
    ring::hmac::sign(&k, data).as_ref().to_vec()
}

/// Parse AWS credentials from the `"ACCESS_KEY_ID:SECRET_ACCESS_KEY"` format.
///
/// The split is on the first colon only, so secret keys that contain slashes
/// or other characters (but not colons) are handled correctly.
fn parse_aws_credentials(api_token: &str) -> Result<(String, String)> {
    match api_token.split_once(':') {
        Some((key_id, secret)) if !key_id.is_empty() && !secret.is_empty() => {
            Ok((key_id.to_string(), secret.to_string()))
        }
        _ => Err(GatewayError::Config(
            "Route53 api_token must be 'ACCESS_KEY_ID:SECRET_ACCESS_KEY'".to_string(),
        )),
    }
}

/// Generate AWS Signature Version 4 signed headers for a Route53 API call.
///
/// Returns a map of header names → values that must be added to the HTTP
/// request.  The `Host` header is included in the signature but intentionally
/// omitted from the returned map because `reqwest` sets it automatically.
fn sigv4_sign(
    method: &str,
    path: &str,
    body: &str,
    access_key_id: &str,
    secret_access_key: &str,
    now: &chrono::DateTime<chrono::Utc>,
) -> HashMap<String, String> {
    let datetime = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();

    let content_type = "application/xml";
    let payload_hash = sha256_hex(body.as_bytes());

    // Canonical headers must be sorted alphabetically by header name.
    let canonical_headers =
        format!("content-type:{content_type}\nhost:{ROUTE53_HOST}\nx-amz-date:{datetime}\n");
    let signed_headers = "content-type;host;x-amz-date";

    // An empty query string is represented as an empty line.
    let canonical_request =
        format!("{method}\n{path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}");

    let credential_scope = format!("{date}/{ROUTE53_REGION}/{ROUTE53_SERVICE}/aws4_request");

    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{datetime}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    // Derive the signing key via the HMAC key-derivation chain.
    let k_date = hmac_sha256(
        format!("AWS4{secret_access_key}").as_bytes(),
        date.as_bytes(),
    );
    let k_region = hmac_sha256(&k_date, ROUTE53_REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, ROUTE53_SERVICE.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");

    let signature = hex_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    );

    HashMap::from([
        ("Authorization".to_string(), authorization),
        ("X-Amz-Date".to_string(), datetime),
        ("Content-Type".to_string(), content_type.to_string()),
    ])
}

/// AWS Route53 DNS solver using SigV4 authentication.
///
/// Configure `api_token` as `"ACCESS_KEY_ID:SECRET_ACCESS_KEY"`.
/// The IAM principal needs `route53:ChangeResourceRecordSets` on the hosted zone.
pub struct Route53Solver {
    http: reqwest::Client,
    access_key_id: String,
    secret_access_key: String,
    hosted_zone_id: String,
    propagation_wait: Duration,
}

impl Route53Solver {
    /// Create a new Route53 DNS solver from configuration
    pub fn new(config: &DnsProviderConfig) -> Result<Self> {
        config.validate()?;
        let (access_key_id, secret_access_key) = parse_aws_credentials(&config.api_token)?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| GatewayError::Other(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            http,
            access_key_id,
            secret_access_key,
            hosted_zone_id: config.zone_id.clone(),
            propagation_wait: Duration::from_secs(config.propagation_wait_secs),
        })
    }

    fn api_path(&self) -> String {
        format!("/2013-04-01/hostedzone/{}/rrset/", self.hosted_zone_id)
    }

    fn api_url(&self) -> String {
        format!("https://{}{}", ROUTE53_HOST, self.api_path())
    }

    /// Build a `ChangeResourceRecordSets` XML body for CREATE or DELETE.
    ///
    /// Route53 requires the TXT record value to be wrapped in double quotes
    /// inside the XML `<Value>` element.
    fn change_xml(&self, action: &str, domain: &str, value: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?><ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ChangeBatch><Changes><Change><Action>{action}</Action><ResourceRecordSet><Name>_acme-challenge.{domain}.</Name><Type>TXT</Type><TTL>120</TTL><ResourceRecords><ResourceRecord><Value>"{value}"</Value></ResourceRecord></ResourceRecords></ResourceRecordSet></Change></Changes></ChangeBatch></ChangeResourceRecordSetsRequest>"#
        )
    }

    /// Send a `ChangeResourceRecordSets` POST request to Route53
    async fn change_record(&self, action: &str, domain: &str, value: &str) -> Result<()> {
        let body = self.change_xml(action, domain, value);
        let path = self.api_path();
        let url = self.api_url();
        let now = chrono::Utc::now();

        let signed = sigv4_sign(
            "POST",
            &path,
            &body,
            &self.access_key_id,
            &self.secret_access_key,
            &now,
        );

        let mut req = self.http.post(&url).body(body);
        for (k, v) in &signed {
            req = req.header(k.as_str(), v.as_str());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| GatewayError::Other(format!("Route53 API request failed: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Other(format!(
                "Route53 ChangeResourceRecordSets {} failed (HTTP {}): {}",
                action, status, text
            )));
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsSolver for Route53Solver {
    /// Create a `_acme-challenge.<domain>` TXT record.
    ///
    /// Returns `"<domain>|<value>"` as the record ID, which encodes the
    /// information needed to issue the corresponding DELETE later.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String> {
        self.change_record("CREATE", domain, value).await?;

        let record_id = format!("{}|{}", domain, value);
        tracing::info!(
            domain = domain,
            record_name = format!("_acme-challenge.{}", domain),
            "Route53 DNS-01 TXT record created"
        );

        Ok(record_id)
    }

    /// Delete the TXT record identified by `record_id` (format: `"domain|value"`)
    async fn delete_txt_record(&self, record_id: &str) -> Result<()> {
        let (domain, value) = record_id.split_once('|').ok_or_else(|| {
            GatewayError::Other(format!(
                "Invalid Route53 record_id (expected 'domain|value'): {}",
                record_id
            ))
        })?;

        self.change_record("DELETE", domain, value).await?;

        tracing::debug!(record_id = record_id, "Route53 DNS-01 TXT record deleted");
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

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Create a DNS solver from configuration
pub fn create_solver(config: &DnsProviderConfig) -> Result<Box<dyn DnsSolver>> {
    match config.provider {
        DnsProvider::Cloudflare => Ok(Box::new(CloudflareSolver::new(config)?)),
        DnsProvider::Route53 => Ok(Box::new(Route53Solver::new(config)?)),
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

    // --- AWS credential parsing ---

    #[test]
    fn test_parse_aws_credentials_valid() {
        let (key_id, secret) = parse_aws_credentials("AKID:SECRET").unwrap();
        assert_eq!(key_id, "AKID");
        assert_eq!(secret, "SECRET");
    }

    #[test]
    fn test_parse_aws_credentials_secret_with_slash() {
        // AWS secret keys can contain slashes and other base64 characters
        let (key_id, secret) =
            parse_aws_credentials("AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCY").unwrap();
        assert_eq!(key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(secret, "wJalrXUtnFEMI/K7MDENG/bPxRfiCY");
    }

    #[test]
    fn test_parse_aws_credentials_missing_separator() {
        assert!(parse_aws_credentials("NODIVIDER").is_err());
    }

    #[test]
    fn test_parse_aws_credentials_empty_key_id() {
        assert!(parse_aws_credentials(":SECRET").is_err());
    }

    #[test]
    fn test_parse_aws_credentials_empty_secret() {
        assert!(parse_aws_credentials("AKID:").is_err());
    }

    // --- Route53Solver ---

    fn route53_config() -> DnsProviderConfig {
        DnsProviderConfig {
            provider: DnsProvider::Route53,
            api_token: "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG".to_string(),
            zone_id: "Z1234567890ABC".to_string(),
            propagation_wait_secs: 120,
        }
    }

    #[test]
    fn test_route53_solver_new() {
        let solver = Route53Solver::new(&route53_config()).unwrap();
        assert_eq!(solver.access_key_id, "AKIAIOSFODNN7EXAMPLE");
        assert_eq!(solver.secret_access_key, "wJalrXUtnFEMI/K7MDENG");
        assert_eq!(solver.hosted_zone_id, "Z1234567890ABC");
        assert_eq!(solver.propagation_wait, Duration::from_secs(120));
    }

    #[test]
    fn test_route53_solver_invalid_credentials() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Route53,
            api_token: "no-colon-separator".to_string(),
            zone_id: "Z1234567890ABC".to_string(),
            propagation_wait_secs: 60,
        };
        assert!(Route53Solver::new(&config).is_err());
    }

    #[test]
    fn test_route53_solver_api_path() {
        let solver = Route53Solver::new(&route53_config()).unwrap();
        assert_eq!(
            solver.api_path(),
            "/2013-04-01/hostedzone/Z1234567890ABC/rrset/"
        );
    }

    #[test]
    fn test_route53_solver_api_url() {
        let solver = Route53Solver::new(&route53_config()).unwrap();
        assert_eq!(
            solver.api_url(),
            "https://route53.amazonaws.com/2013-04-01/hostedzone/Z1234567890ABC/rrset/"
        );
    }

    #[test]
    fn test_route53_solver_change_xml_create() {
        let solver = Route53Solver::new(&route53_config()).unwrap();
        let xml = solver.change_xml("CREATE", "example.com", "challenge-value");
        assert!(xml.contains("<Action>CREATE</Action>"));
        assert!(xml.contains("<Name>_acme-challenge.example.com.</Name>"));
        assert!(xml.contains("<Type>TXT</Type>"));
        assert!(xml.contains("<TTL>120</TTL>"));
        assert!(xml.contains(r#"<Value>"challenge-value"</Value>"#));
    }

    #[test]
    fn test_route53_solver_change_xml_delete() {
        let solver = Route53Solver::new(&route53_config()).unwrap();
        let xml = solver.change_xml("DELETE", "example.com", "challenge-value");
        assert!(xml.contains("<Action>DELETE</Action>"));
        assert!(xml.contains("<Name>_acme-challenge.example.com.</Name>"));
        assert!(xml.contains(r#"<Value>"challenge-value"</Value>"#));
    }

    // --- SigV4 signing ---

    #[test]
    fn test_sigv4_sign_produces_required_headers() {
        let now = chrono::DateTime::parse_from_rfc3339("2024-01-15T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        let headers = sigv4_sign(
            "POST",
            "/2013-04-01/hostedzone/Z123/rrset/",
            "<xml/>",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            &now,
        );

        assert!(headers.contains_key("Authorization"));
        assert!(headers.contains_key("X-Amz-Date"));
        assert!(headers.contains_key("Content-Type"));

        let auth = &headers["Authorization"];
        assert!(auth.starts_with("AWS4-HMAC-SHA256 "));
        assert!(auth
            .contains("Credential=AKIAIOSFODNN7EXAMPLE/20240115/us-east-1/route53/aws4_request"));
        assert!(auth.contains("SignedHeaders=content-type;host;x-amz-date"));
        assert!(auth.contains("Signature="));

        assert_eq!(headers["X-Amz-Date"], "20240115T120000Z");
        assert_eq!(headers["Content-Type"], "application/xml");
    }

    #[test]
    fn test_sigv4_sign_is_deterministic() {
        let now = chrono::DateTime::parse_from_rfc3339("2024-06-01T08:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let headers1 = sigv4_sign("POST", "/path/", "body", "KEY", "SECRET", &now);
        let headers2 = sigv4_sign("POST", "/path/", "body", "KEY", "SECRET", &now);
        assert_eq!(headers1["Authorization"], headers2["Authorization"]);
    }

    #[test]
    fn test_sigv4_sign_different_bodies_produce_different_signatures() {
        let now = chrono::DateTime::parse_from_rfc3339("2024-06-01T08:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let h1 = sigv4_sign("POST", "/path/", "body-a", "KEY", "SECRET", &now);
        let h2 = sigv4_sign("POST", "/path/", "body-b", "KEY", "SECRET", &now);
        assert_ne!(h1["Authorization"], h2["Authorization"]);
    }

    #[test]
    fn test_sigv4_sign_different_keys_produce_different_signatures() {
        let now = chrono::DateTime::parse_from_rfc3339("2024-06-01T08:30:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let h1 = sigv4_sign("POST", "/path/", "body", "KEY1", "SECRET1", &now);
        let h2 = sigv4_sign("POST", "/path/", "body", "KEY2", "SECRET2", &now);
        assert_ne!(h1["Authorization"], h2["Authorization"]);
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
    fn test_create_solver_route53() {
        assert!(create_solver(&route53_config()).is_ok());
    }

    #[test]
    fn test_create_solver_route53_invalid_credentials() {
        let config = DnsProviderConfig {
            provider: DnsProvider::Route53,
            api_token: "no-colon".to_string(),
            zone_id: "Z1234567890ABC".to_string(),
            propagation_wait_secs: 60,
        };
        assert!(create_solver(&config).is_err());
    }
}
