//! ACME v2 protocol client (RFC 8555)
//!
//! Implements the full ACME certificate issuance flow:
//! 1. Fetch directory → 2. Create account → 3. Create order →
//! 4. Solve HTTP-01 challenge → 5. Finalize order → 6. Download certificate

#![allow(dead_code)]
use crate::error::{GatewayError, Result};
use crate::proxy::acme::{AcmeConfig, CertInfo, CertStorage, ChallengeStore, ChallengeType};
use crate::proxy::acme_dns;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// ACME directory endpoints (cached from the ACME server)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    #[serde(default)]
    pub revoke_cert: String,
}

/// ACME order object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeOrder {
    pub status: String,
    #[serde(default)]
    pub authorizations: Vec<String>,
    #[serde(default)]
    pub finalize: String,
    #[serde(default)]
    pub certificate: Option<String>,
}

/// ACME authorization object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAuthorization {
    pub status: String,
    pub identifier: AcmeIdentifier,
    #[serde(default)]
    pub challenges: Vec<AcmeChallenge>,
}

/// ACME identifier (domain)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeIdentifier {
    #[serde(rename = "type")]
    pub id_type: String,
    pub value: String,
}

/// ACME challenge object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeChallenge {
    #[serde(rename = "type")]
    pub challenge_type: String,
    pub url: String,
    pub token: String,
    pub status: String,
}

/// ACME account key — ECDSA P-256
pub struct AccountKey {
    key_pair: EcdsaKeyPair,
    /// PKCS#8 DER bytes for persistence
    pkcs8_der: Vec<u8>,
}

impl AccountKey {
    /// Generate a new ECDSA P-256 key pair
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| GatewayError::Other(format!("Failed to generate ECDSA key: {}", e)))?;
        let pkcs8_der = pkcs8.as_ref().to_vec();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &pkcs8_der, &rng)
            .map_err(|e| GatewayError::Other(format!("Failed to parse generated key: {}", e)))?;
        Ok(Self {
            key_pair,
            pkcs8_der,
        })
    }

    /// Load from PKCS#8 DER bytes
    pub fn from_pkcs8(der: &[u8]) -> Result<Self> {
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der, &rng)
            .map_err(|e| {
                GatewayError::Other(format!("Failed to load ECDSA key from PKCS#8: {}", e))
            })?;
        Ok(Self {
            key_pair,
            pkcs8_der: der.to_vec(),
        })
    }

    /// Get the JWK (JSON Web Key) thumbprint for key authorization
    pub fn jwk_thumbprint(&self) -> String {
        let public_key = self.key_pair.public_key().as_ref();
        // P-256 uncompressed point: 0x04 || x (32 bytes) || y (32 bytes)
        let x = &public_key[1..33];
        let y = &public_key[33..65];
        let x_b64 = URL_SAFE_NO_PAD.encode(x);
        let y_b64 = URL_SAFE_NO_PAD.encode(y);

        // JWK thumbprint per RFC 7638 — lexicographic order of required members
        let jwk_json = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            x_b64, y_b64
        );
        let digest = ring::digest::digest(&ring::digest::SHA256, jwk_json.as_bytes());
        URL_SAFE_NO_PAD.encode(digest.as_ref())
    }

    /// Get the JWK public key for the protected header
    pub fn jwk(&self) -> serde_json::Value {
        let public_key = self.key_pair.public_key().as_ref();
        let x = &public_key[1..33];
        let y = &public_key[33..65];
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": URL_SAFE_NO_PAD.encode(x),
            "y": URL_SAFE_NO_PAD.encode(y),
        })
    }

    /// Sign data with the account key
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let sig = self
            .key_pair
            .sign(&rng, data)
            .map_err(|e| GatewayError::Other(format!("ECDSA signing failed: {}", e)))?;
        Ok(sig.as_ref().to_vec())
    }

    /// Get the PKCS#8 DER bytes for persistence
    pub fn pkcs8_der(&self) -> &[u8] {
        &self.pkcs8_der
    }
}

/// ACME v2 protocol client
pub struct AcmeClient {
    pub(crate) config: AcmeConfig,
    http: reqwest::Client,
    pub(crate) storage: CertStorage,
    challenges: Arc<ChallengeStore>,
    /// Cached ACME directory endpoints
    directory: Option<AcmeDirectory>,
    /// Account key pair
    account_key: Option<AccountKey>,
    /// Account URL (returned by ACME server after registration)
    account_url: Option<String>,
}

impl AcmeClient {
    /// Create a new ACME client
    pub fn new(config: AcmeConfig, challenges: Arc<ChallengeStore>) -> Result<Self> {
        config.validate()?;
        let storage = CertStorage::new(&config.storage_path);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| GatewayError::Other(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self {
            config,
            http,
            storage,
            challenges,
            directory: None,
            account_key: None,
            account_url: None,
        })
    }

    /// Get the challenge store
    pub fn challenges(&self) -> &Arc<ChallengeStore> {
        &self.challenges
    }

    /// Get the certificate storage
    pub fn storage(&self) -> &CertStorage {
        &self.storage
    }

    /// Load or generate the account key
    pub fn ensure_account_key(&mut self) -> Result<()> {
        if self.account_key.is_some() {
            return Ok(());
        }

        let key_path = self.config.storage_path.join("account.key");
        if key_path.exists() {
            let der = std::fs::read(&key_path).map_err(|e| {
                GatewayError::Other(format!(
                    "Failed to read account key {}: {}",
                    key_path.display(),
                    e
                ))
            })?;
            self.account_key = Some(AccountKey::from_pkcs8(&der)?);
            tracing::info!("Loaded existing ACME account key");
        } else {
            let key = AccountKey::generate()?;
            std::fs::create_dir_all(&self.config.storage_path).map_err(|e| {
                GatewayError::Other(format!(
                    "Failed to create ACME storage dir {}: {}",
                    self.config.storage_path.display(),
                    e
                ))
            })?;
            std::fs::write(&key_path, key.pkcs8_der())
                .map_err(|e| GatewayError::Other(format!("Failed to write account key: {}", e)))?;
            self.account_key = Some(key);
            tracing::info!("Generated new ACME account key");
        }
        Ok(())
    }

    /// Fetch the ACME directory from the server
    pub async fn fetch_directory(&mut self) -> Result<&AcmeDirectory> {
        let url = self.config.effective_directory();
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|e| GatewayError::Other(format!("ACME directory fetch failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(GatewayError::Other(format!(
                "ACME directory returned HTTP {}",
                resp.status()
            )));
        }

        let dir: AcmeDirectory = resp
            .json()
            .await
            .map_err(|e| GatewayError::Other(format!("ACME directory parse failed: {}", e)))?;

        tracing::debug!(
            new_account = dir.new_account,
            new_order = dir.new_order,
            "ACME directory fetched"
        );

        self.directory = Some(dir);
        Ok(self.directory.as_ref().unwrap())
    }

    /// Get a fresh replay nonce from the ACME server
    pub async fn get_nonce(&self) -> Result<String> {
        let dir = self
            .directory
            .as_ref()
            .ok_or_else(|| GatewayError::Other("ACME directory not fetched".to_string()))?;

        let resp = self
            .http
            .head(&dir.new_nonce)
            .send()
            .await
            .map_err(|e| GatewayError::Other(format!("ACME nonce request failed: {}", e)))?;

        resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| GatewayError::Other("No replay-nonce header in response".to_string()))
    }

    /// Build a JWS (JSON Web Signature) request body
    fn build_jws(&self, url: &str, payload: &str, nonce: &str) -> Result<String> {
        let key = self
            .account_key
            .as_ref()
            .ok_or_else(|| GatewayError::Other("Account key not loaded".to_string()))?;

        let header = if let Some(ref account_url) = self.account_url {
            // Use kid (account URL) for authenticated requests
            serde_json::json!({
                "alg": "ES256",
                "kid": account_url,
                "nonce": nonce,
                "url": url,
            })
        } else {
            // Use jwk for account creation
            serde_json::json!({
                "alg": "ES256",
                "jwk": key.jwk(),
                "nonce": nonce,
                "url": url,
            })
        };

        let protected = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
        let payload_b64 = if payload.is_empty() {
            String::new() // POST-as-GET
        } else {
            URL_SAFE_NO_PAD.encode(payload.as_bytes())
        };

        let signing_input = format!("{}.{}", protected, payload_b64);
        let signature = key.sign(signing_input.as_bytes())?;
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        let jws = serde_json::json!({
            "protected": protected,
            "payload": payload_b64,
            "signature": sig_b64,
        });

        Ok(jws.to_string())
    }

    /// POST a JWS-signed request to an ACME endpoint
    async fn acme_post(
        &self,
        url: &str,
        payload: &str,
        nonce: &str,
    ) -> Result<(reqwest::Response, Option<String>)> {
        let body = self.build_jws(url, payload, nonce)?;

        let resp = self
            .http
            .post(url)
            .header("Content-Type", "application/jose+json")
            .body(body)
            .send()
            .await
            .map_err(|e| GatewayError::Other(format!("ACME POST to {} failed: {}", url, e)))?;

        let new_nonce = resp
            .headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        Ok((resp, new_nonce))
    }

    /// Register an ACME account (or retrieve existing one)
    pub async fn register_account(&mut self) -> Result<()> {
        self.ensure_account_key()?;
        let dir = self
            .directory
            .as_ref()
            .ok_or_else(|| GatewayError::Other("ACME directory not fetched".to_string()))?
            .clone();

        let nonce = self.get_nonce().await?;
        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{}", self.config.email)],
        });

        let (resp, _) = self
            .acme_post(&dir.new_account, &payload.to_string(), &nonce)
            .await?;

        let status = resp.status();
        if status == 200 || status == 201 {
            // Account URL is in the Location header
            let account_url = resp
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    GatewayError::Other("No Location header in account response".to_string())
                })?;

            tracing::info!(
                account_url = account_url,
                status = status.as_u16(),
                "ACME account registered"
            );
            self.account_url = Some(account_url);
            Ok(())
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(GatewayError::Other(format!(
                "ACME account registration failed (HTTP {}): {}",
                status, body
            )))
        }
    }

    /// Create a new certificate order for the configured domains
    pub async fn create_order(&self) -> Result<(AcmeOrder, String)> {
        let dir = self
            .directory
            .as_ref()
            .ok_or_else(|| GatewayError::Other("ACME directory not fetched".to_string()))?
            .clone();

        let identifiers: Vec<serde_json::Value> = self
            .config
            .domains
            .iter()
            .map(|d| {
                serde_json::json!({
                    "type": "dns",
                    "value": d,
                })
            })
            .collect();

        let payload = serde_json::json!({
            "identifiers": identifiers,
        });

        let nonce = self.get_nonce().await?;
        let (resp, _) = self
            .acme_post(&dir.new_order, &payload.to_string(), &nonce)
            .await?;

        let status = resp.status();
        let order_url = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();

        if status == 201 || status == 200 {
            let order: AcmeOrder = resp
                .json()
                .await
                .map_err(|e| GatewayError::Other(format!("Failed to parse ACME order: {}", e)))?;
            tracing::info!(
                status = order.status,
                authorizations = order.authorizations.len(),
                "ACME order created"
            );
            Ok((order, order_url))
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(GatewayError::Other(format!(
                "ACME order creation failed (HTTP {}): {}",
                status, body
            )))
        }
    }

    /// Solve an HTTP-01 challenge for an authorization URL
    pub async fn solve_http01_challenge(&self, auth_url: &str) -> Result<()> {
        let nonce = self.get_nonce().await?;
        // POST-as-GET to fetch authorization
        let (resp, _) = self.acme_post(auth_url, "", &nonce).await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Other(format!(
                "Failed to fetch authorization {}: {}",
                auth_url, body
            )));
        }

        let auth: AcmeAuthorization = resp
            .json()
            .await
            .map_err(|e| GatewayError::Other(format!("Failed to parse authorization: {}", e)))?;

        // Find the HTTP-01 challenge
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.challenge_type == "http-01")
            .ok_or_else(|| {
                GatewayError::Other(format!(
                    "No HTTP-01 challenge for domain {}",
                    auth.identifier.value
                ))
            })?;

        if challenge.status == "valid" {
            tracing::debug!(
                domain = auth.identifier.value,
                "Challenge already valid, skipping"
            );
            return Ok(());
        }

        // Compute key authorization: token.thumbprint
        let key = self
            .account_key
            .as_ref()
            .ok_or_else(|| GatewayError::Other("Account key not loaded".to_string()))?;
        let key_auth = format!("{}.{}", challenge.token, key.jwk_thumbprint());

        // Store the challenge response for the HTTP server to serve
        self.challenges.add(challenge.token.clone(), key_auth);

        tracing::info!(
            domain = auth.identifier.value,
            token = challenge.token,
            "HTTP-01 challenge token stored, notifying ACME server"
        );

        // Notify the ACME server that we're ready
        let nonce = self.get_nonce().await?;
        let (resp, _) = self.acme_post(&challenge.url, "{}", &nonce).await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Other(format!(
                "Failed to respond to challenge: {}",
                body
            )));
        }

        // Poll until challenge is valid (or fails)
        for attempt in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let nonce = self.get_nonce().await?;
            let (resp, _) = self.acme_post(auth_url, "", &nonce).await?;
            if !resp.status().is_success() {
                continue;
            }

            let auth: AcmeAuthorization = match resp.json().await {
                Ok(a) => a,
                Err(_) => continue,
            };

            match auth.status.as_str() {
                "valid" => {
                    tracing::info!(
                        domain = auth.identifier.value,
                        attempts = attempt + 1,
                        "HTTP-01 challenge validated"
                    );
                    // Clean up challenge token
                    self.challenges.remove(&challenge.token);
                    return Ok(());
                }
                "invalid" => {
                    self.challenges.remove(&challenge.token);
                    return Err(GatewayError::Other(format!(
                        "Challenge validation failed for domain {}",
                        auth.identifier.value
                    )));
                }
                _ => continue, // "pending" or "processing"
            }
        }

        self.challenges.remove(&challenge.token);
        Err(GatewayError::Other(format!(
            "Challenge validation timed out for authorization {}",
            auth_url
        )))
    }

    /// Solve a DNS-01 challenge for an authorization URL
    ///
    /// Creates a TXT record via the configured DNS provider, waits for propagation,
    /// then notifies the ACME server. Used for wildcard certificates.
    pub async fn solve_dns01_challenge(
        &self,
        auth_url: &str,
        dns_solver: &dyn acme_dns::DnsSolver,
    ) -> Result<()> {
        let nonce = self.get_nonce().await?;
        let (resp, _) = self.acme_post(auth_url, "", &nonce).await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Other(format!(
                "Failed to fetch authorization {}: {}",
                auth_url, body
            )));
        }

        let auth: AcmeAuthorization = resp
            .json()
            .await
            .map_err(|e| GatewayError::Other(format!("Failed to parse authorization: {}", e)))?;

        // Find the DNS-01 challenge
        let challenge = auth
            .challenges
            .iter()
            .find(|c| c.challenge_type == "dns-01")
            .ok_or_else(|| {
                GatewayError::Other(format!(
                    "No DNS-01 challenge for domain {}",
                    auth.identifier.value
                ))
            })?;

        if challenge.status == "valid" {
            tracing::debug!(
                domain = auth.identifier.value,
                "DNS-01 challenge already valid, skipping"
            );
            return Ok(());
        }

        // Compute key authorization digest for DNS-01:
        // base64url(SHA-256(token.thumbprint))
        let key = self
            .account_key
            .as_ref()
            .ok_or_else(|| GatewayError::Other("Account key not loaded".to_string()))?;
        let key_auth = format!("{}.{}", challenge.token, key.jwk_thumbprint());
        let digest = ring::digest::digest(&ring::digest::SHA256, key_auth.as_bytes());
        let dns_value = URL_SAFE_NO_PAD.encode(digest.as_ref());

        // Strip wildcard prefix for the DNS record domain
        let domain = auth
            .identifier
            .value
            .strip_prefix("*.")
            .unwrap_or(&auth.identifier.value);

        // Create TXT record
        let record_id = dns_solver.create_txt_record(domain, &dns_value).await?;

        tracing::info!(
            domain = domain,
            record_id = record_id,
            "DNS-01 TXT record created, waiting for propagation"
        );

        // Wait for DNS propagation
        dns_solver.wait_for_propagation().await;

        // Notify the ACME server that we're ready
        let nonce = self.get_nonce().await?;
        let (resp, _) = self.acme_post(&challenge.url, "{}", &nonce).await?;

        if !resp.status().is_success() {
            // Clean up the DNS record before returning error
            let _ = dns_solver.delete_txt_record(&record_id).await;
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Other(format!(
                "Failed to respond to DNS-01 challenge: {}",
                body
            )));
        }

        // Poll until challenge is valid (or fails)
        let challenge_url = challenge.url.clone();
        for attempt in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let nonce = self.get_nonce().await?;
            let (resp, _) = self.acme_post(auth_url, "", &nonce).await?;
            if !resp.status().is_success() {
                continue;
            }

            let auth: AcmeAuthorization = match resp.json().await {
                Ok(a) => a,
                Err(_) => continue,
            };

            match auth.status.as_str() {
                "valid" => {
                    tracing::info!(
                        domain = auth.identifier.value,
                        attempts = attempt + 1,
                        "DNS-01 challenge validated"
                    );
                    // Clean up the DNS record
                    if let Err(e) = dns_solver.delete_txt_record(&record_id).await {
                        tracing::warn!(
                            record_id = record_id,
                            error = %e,
                            "Failed to clean up DNS TXT record"
                        );
                    }
                    return Ok(());
                }
                "invalid" => {
                    let _ = dns_solver.delete_txt_record(&record_id).await;
                    return Err(GatewayError::Other(format!(
                        "DNS-01 challenge validation failed for domain {}",
                        auth.identifier.value
                    )));
                }
                _ => continue,
            }
        }

        let _ = dns_solver.delete_txt_record(&record_id).await;
        Err(GatewayError::Other(format!(
            "DNS-01 challenge validation timed out for {}",
            challenge_url
        )))
    }

    /// Poll an order until it reaches "ready" or "valid" status
    pub async fn poll_order_ready(&self, order_url: &str) -> Result<AcmeOrder> {
        for attempt in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;

            let nonce = self.get_nonce().await?;
            let (resp, _) = self.acme_post(order_url, "", &nonce).await?;

            if !resp.status().is_success() {
                continue;
            }

            let order: AcmeOrder = match resp.json().await {
                Ok(o) => o,
                Err(_) => continue,
            };

            match order.status.as_str() {
                "ready" | "valid" => {
                    tracing::debug!(
                        status = order.status,
                        attempts = attempt + 1,
                        "Order is ready"
                    );
                    return Ok(order);
                }
                "invalid" => {
                    return Err(GatewayError::Other("ACME order became invalid".to_string()));
                }
                _ => continue, // "pending" or "processing"
            }
        }

        Err(GatewayError::Other(
            "Timed out waiting for ACME order to become ready".to_string(),
        ))
    }

    /// Finalize an order by submitting a CSR
    pub async fn finalize_order(
        &self,
        finalize_url: &str,
        domains: &[String],
    ) -> Result<AcmeOrder> {
        // Generate a CSR key pair (separate from account key)
        let rng = SystemRandom::new();
        let csr_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|e| GatewayError::Other(format!("Failed to generate CSR key: {}", e)))?;
        let csr_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, csr_pkcs8.as_ref(), &rng)
                .map_err(|e| GatewayError::Other(format!("Failed to parse CSR key: {}", e)))?;

        // Build a minimal DER-encoded CSR
        let csr_der = build_csr(&csr_key, domains, &rng)?;
        let csr_b64 = URL_SAFE_NO_PAD.encode(&csr_der);

        let payload = serde_json::json!({ "csr": csr_b64 });
        let nonce = self.get_nonce().await?;
        let (resp, _) = self
            .acme_post(finalize_url, &payload.to_string(), &nonce)
            .await?;

        let status = resp.status();
        if status.is_success() {
            let order: AcmeOrder = resp.json().await.map_err(|e| {
                GatewayError::Other(format!("Failed to parse finalize response: {}", e))
            })?;

            // Store the CSR private key for later use as the cert's key
            let key_pem = pem_encode("EC PRIVATE KEY", csr_pkcs8.as_ref());
            let key_path = self.config.storage_path.join("csr.key.pem");
            std::fs::write(&key_path, &key_pem)
                .map_err(|e| GatewayError::Other(format!("Failed to write CSR key: {}", e)))?;

            tracing::info!(status = order.status, "Order finalized");
            Ok(order)
        } else {
            let body = resp.text().await.unwrap_or_default();
            Err(GatewayError::Other(format!(
                "ACME finalize failed (HTTP {}): {}",
                status, body
            )))
        }
    }

    /// Download the issued certificate
    pub async fn download_certificate(&self, cert_url: &str) -> Result<String> {
        let nonce = self.get_nonce().await?;
        let (resp, _) = self.acme_post(cert_url, "", &nonce).await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Other(format!(
                "Certificate download failed: {}",
                body
            )));
        }

        let cert_pem = resp
            .text()
            .await
            .map_err(|e| GatewayError::Other(format!("Failed to read certificate body: {}", e)))?;

        tracing::info!(bytes = cert_pem.len(), "Certificate downloaded");
        Ok(cert_pem)
    }

    /// Full certificate issuance flow for all configured domains
    pub async fn issue_certificate(&mut self) -> Result<CertInfo> {
        // 1. Fetch directory
        self.fetch_directory().await?;

        // 2. Register account
        self.register_account().await?;

        // 3. Create order
        let (order, order_url) = self.create_order().await?;

        // 4. Solve challenges based on configured challenge type
        match self.config.challenge_type {
            ChallengeType::Http01 => {
                for auth_url in &order.authorizations {
                    self.solve_http01_challenge(auth_url).await?;
                }
            }
            ChallengeType::Dns01 => {
                let dns_config = self.config.dns_provider.as_ref().ok_or_else(|| {
                    GatewayError::Other(
                        "DNS provider configuration required for DNS-01 challenge".to_string(),
                    )
                })?;
                let solver = acme_dns::create_solver(dns_config)?;
                for auth_url in &order.authorizations {
                    self.solve_dns01_challenge(auth_url, solver.as_ref())
                        .await?;
                }
            }
        }

        // 5. Poll until order is ready
        let order = self.poll_order_ready(&order_url).await?;

        // 6. Finalize with CSR
        let order = if order.status == "ready" {
            self.finalize_order(&order.finalize, &self.config.domains.clone())
                .await?
        } else {
            order
        };

        // 7. Poll until order is valid (certificate issued)
        let order = if order.certificate.is_none() {
            self.poll_order_ready(&order_url).await?
        } else {
            order
        };

        // 8. Download certificate
        let cert_url = order.certificate.ok_or_else(|| {
            GatewayError::Other("Order completed but no certificate URL".to_string())
        })?;
        let cert_pem = self.download_certificate(&cert_url).await?;

        // 9. Read the CSR private key
        let key_path = self.config.storage_path.join("csr.key.pem");
        let key_pem = std::fs::read_to_string(&key_path)
            .map_err(|e| GatewayError::Other(format!("Failed to read CSR key: {}", e)))?;

        // 10. Build CertInfo and save
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cert_info = CertInfo {
            domain: self.config.domains.first().cloned().unwrap_or_default(),
            cert_pem,
            key_pem,
            expires_at: now + 90 * 86400, // Let's Encrypt certs are valid for 90 days
            issued_at: now,
        };

        self.storage.save(&cert_info)?;
        tracing::info!(
            domain = cert_info.domain,
            expires_in_days = 90,
            "Certificate issued and saved"
        );

        Ok(cert_info)
    }
}

/// Build a minimal DER-encoded PKCS#10 CSR for the given domains
fn build_csr(key: &EcdsaKeyPair, domains: &[String], rng: &SystemRandom) -> Result<Vec<u8>> {
    // Build Subject Alternative Names extension
    let mut san_bytes = Vec::new();
    for domain in domains {
        // GeneralName: dNSName [2] IA5String
        let domain_bytes = domain.as_bytes();
        san_bytes.push(0x82); // context tag [2]
        encode_der_length(domain_bytes.len(), &mut san_bytes);
        san_bytes.extend_from_slice(domain_bytes);
    }

    // Wrap SAN in SEQUENCE
    let mut san_seq = vec![0x30]; // SEQUENCE
    encode_der_length(san_bytes.len(), &mut san_seq);
    san_seq.extend_from_slice(&san_bytes);

    // Extension: subjectAltName (OID 2.5.29.17)
    let san_oid = &[0x55, 0x1d, 0x11]; // 2.5.29.17
    let mut ext = Vec::new();
    // OID
    ext.push(0x06); // OID tag
    encode_der_length(san_oid.len(), &mut ext);
    ext.extend_from_slice(san_oid);
    // OCTET STRING wrapping the SAN SEQUENCE
    ext.push(0x04); // OCTET STRING
    encode_der_length(san_seq.len(), &mut ext);
    ext.extend_from_slice(&san_seq);

    // Wrap extension in SEQUENCE
    let mut ext_seq = vec![0x30];
    encode_der_length(ext.len(), &mut ext_seq);
    ext_seq.extend_from_slice(&ext);

    // Extensions SEQUENCE
    let mut exts_seq = vec![0x30];
    encode_der_length(ext_seq.len(), &mut exts_seq);
    exts_seq.extend_from_slice(&ext_seq);

    // Wrap in SET for extensionRequest attribute
    let mut exts_set = vec![0x31];
    encode_der_length(exts_seq.len(), &mut exts_set);
    exts_set.extend_from_slice(&exts_seq);

    // extensionRequest OID: 1.2.840.113549.1.9.14
    let ext_req_oid = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
    let mut attr = Vec::new();
    attr.push(0x06);
    encode_der_length(ext_req_oid.len(), &mut attr);
    attr.extend_from_slice(ext_req_oid);
    attr.extend_from_slice(&exts_set);

    let mut attr_seq = vec![0x30];
    encode_der_length(attr.len(), &mut attr_seq);
    attr_seq.extend_from_slice(&attr);

    // Attributes [0] IMPLICIT
    let mut attrs = vec![0xa0];
    encode_der_length(attr_seq.len(), &mut attrs);
    attrs.extend_from_slice(&attr_seq);

    // CertificationRequestInfo
    let mut cri = Vec::new();
    // Version: INTEGER 0
    cri.extend_from_slice(&[0x02, 0x01, 0x00]);
    // Subject: empty SEQUENCE (Let's Encrypt ignores subject, uses SAN)
    cri.extend_from_slice(&[0x30, 0x00]);
    // SubjectPublicKeyInfo
    let spki = build_ec_spki(key);
    cri.extend_from_slice(&spki);
    // Attributes
    cri.extend_from_slice(&attrs);

    let mut cri_seq = vec![0x30];
    encode_der_length(cri.len(), &mut cri_seq);
    cri_seq.extend_from_slice(&cri);

    // Sign the CertificationRequestInfo
    let sig = key
        .sign(rng, &cri_seq)
        .map_err(|e| GatewayError::Other(format!("CSR signing failed: {}", e)))?;
    let sig_bytes = sig.as_ref();

    // Build CertificationRequest
    let mut cr = Vec::new();
    cr.extend_from_slice(&cri_seq);
    // SignatureAlgorithm: ecdsaWithSHA256 (1.2.840.10045.4.3.2)
    let sig_alg_oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    let mut sig_alg = vec![0x30];
    let mut sig_alg_inner = vec![0x06];
    encode_der_length(sig_alg_oid.len(), &mut sig_alg_inner);
    sig_alg_inner.extend_from_slice(sig_alg_oid);
    encode_der_length(sig_alg_inner.len(), &mut sig_alg);
    sig_alg.extend_from_slice(&sig_alg_inner);
    cr.extend_from_slice(&sig_alg);
    // Signature: BIT STRING
    let mut sig_bits = vec![0x03];
    encode_der_length(sig_bytes.len() + 1, &mut sig_bits);
    sig_bits.push(0x00); // no unused bits
    sig_bits.extend_from_slice(sig_bytes);
    cr.extend_from_slice(&sig_bits);

    let mut csr = vec![0x30];
    encode_der_length(cr.len(), &mut csr);
    csr.extend_from_slice(&cr);

    Ok(csr)
}

/// Build EC SubjectPublicKeyInfo DER for P-256
fn build_ec_spki(key: &EcdsaKeyPair) -> Vec<u8> {
    let pub_key = key.public_key().as_ref(); // 65 bytes uncompressed point

    // AlgorithmIdentifier: ecPublicKey + P-256
    let ec_oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
    let p256_oid = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7

    let mut alg_id = Vec::new();
    alg_id.push(0x06);
    encode_der_length(ec_oid.len(), &mut alg_id);
    alg_id.extend_from_slice(ec_oid);
    alg_id.push(0x06);
    encode_der_length(p256_oid.len(), &mut alg_id);
    alg_id.extend_from_slice(p256_oid);

    let mut alg_seq = vec![0x30];
    encode_der_length(alg_id.len(), &mut alg_seq);
    alg_seq.extend_from_slice(&alg_id);

    // BIT STRING wrapping the public key
    let mut bit_str = vec![0x03];
    encode_der_length(pub_key.len() + 1, &mut bit_str);
    bit_str.push(0x00); // no unused bits
    bit_str.extend_from_slice(pub_key);

    // SEQUENCE { algorithmIdentifier, subjectPublicKey }
    let mut spki = Vec::new();
    spki.extend_from_slice(&alg_seq);
    spki.extend_from_slice(&bit_str);

    let mut spki_seq = vec![0x30];
    encode_der_length(spki.len(), &mut spki_seq);
    spki_seq.extend_from_slice(&spki);

    spki_seq
}

/// Encode a DER length field
fn encode_der_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len < 0x100 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

/// PEM-encode DER data
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    let b64 = STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_config() -> AcmeConfig {
        AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            staging: true,
            storage_path: PathBuf::from("/tmp/acme-test"),
            ..Default::default()
        }
    }

    // --- AccountKey ---

    #[test]
    fn test_account_key_generate() {
        let key = AccountKey::generate().unwrap();
        assert!(!key.pkcs8_der().is_empty());
    }

    #[test]
    fn test_account_key_roundtrip() {
        let key = AccountKey::generate().unwrap();
        let der = key.pkcs8_der().to_vec();
        let key2 = AccountKey::from_pkcs8(&der).unwrap();
        assert_eq!(key.pkcs8_der(), key2.pkcs8_der());
    }

    #[test]
    fn test_account_key_jwk_thumbprint() {
        let key = AccountKey::generate().unwrap();
        let thumbprint = key.jwk_thumbprint();
        // Base64url-encoded SHA-256 is always 43 chars
        assert_eq!(thumbprint.len(), 43);
        assert!(!thumbprint.contains('+'));
        assert!(!thumbprint.contains('/'));
        assert!(!thumbprint.contains('='));
    }

    #[test]
    fn test_account_key_jwk() {
        let key = AccountKey::generate().unwrap();
        let jwk = key.jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string());
        assert!(jwk["y"].is_string());
    }

    #[test]
    fn test_account_key_sign() {
        let key = AccountKey::generate().unwrap();
        let sig = key.sign(b"test data").unwrap();
        assert!(!sig.is_empty());
    }

    #[test]
    fn test_account_key_from_invalid_pkcs8() {
        let result = AccountKey::from_pkcs8(b"not valid pkcs8");
        assert!(result.is_err());
    }

    // --- AcmeDirectory ---

    #[test]
    fn test_directory_deserialize() {
        let json = r#"{
            "newNonce": "https://acme.example/nonce",
            "newAccount": "https://acme.example/account",
            "newOrder": "https://acme.example/order",
            "revokeCert": "https://acme.example/revoke"
        }"#;
        let dir: AcmeDirectory = serde_json::from_str(json).unwrap();
        assert_eq!(dir.new_nonce, "https://acme.example/nonce");
        assert_eq!(dir.new_account, "https://acme.example/account");
        assert_eq!(dir.new_order, "https://acme.example/order");
        assert_eq!(dir.revoke_cert, "https://acme.example/revoke");
    }

    #[test]
    fn test_directory_deserialize_minimal() {
        let json = r#"{
            "newNonce": "https://acme.example/nonce",
            "newAccount": "https://acme.example/account",
            "newOrder": "https://acme.example/order"
        }"#;
        let dir: AcmeDirectory = serde_json::from_str(json).unwrap();
        assert!(dir.revoke_cert.is_empty());
    }

    // --- AcmeOrder ---

    #[test]
    fn test_order_deserialize() {
        let json = r#"{
            "status": "pending",
            "authorizations": ["https://acme.example/auth/1"],
            "finalize": "https://acme.example/finalize/1"
        }"#;
        let order: AcmeOrder = serde_json::from_str(json).unwrap();
        assert_eq!(order.status, "pending");
        assert_eq!(order.authorizations.len(), 1);
        assert_eq!(order.finalize, "https://acme.example/finalize/1");
        assert!(order.certificate.is_none());
    }

    #[test]
    fn test_order_with_certificate() {
        let json = r#"{
            "status": "valid",
            "authorizations": [],
            "finalize": "",
            "certificate": "https://acme.example/cert/1"
        }"#;
        let order: AcmeOrder = serde_json::from_str(json).unwrap();
        assert_eq!(
            order.certificate,
            Some("https://acme.example/cert/1".to_string())
        );
    }

    // --- AcmeChallenge ---

    #[test]
    fn test_challenge_deserialize() {
        let json = r#"{
            "type": "http-01",
            "url": "https://acme.example/chall/1",
            "token": "abc123",
            "status": "pending"
        }"#;
        let ch: AcmeChallenge = serde_json::from_str(json).unwrap();
        assert_eq!(ch.challenge_type, "http-01");
        assert_eq!(ch.token, "abc123");
        assert_eq!(ch.status, "pending");
    }

    // --- AcmeClient construction ---

    #[test]
    fn test_client_new() {
        let challenges = Arc::new(ChallengeStore::new());
        let client = AcmeClient::new(test_config(), challenges).unwrap();
        assert!(client.challenges().is_empty());
    }

    #[test]
    fn test_client_new_invalid_config() {
        let challenges = Arc::new(ChallengeStore::new());
        let config = AcmeConfig::default(); // missing email + domains
        let result = AcmeClient::new(config, challenges);
        assert!(result.is_err());
    }

    #[test]
    fn test_client_ensure_account_key() {
        let dir = tempfile::tempdir().unwrap();
        let challenges = Arc::new(ChallengeStore::new());
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            storage_path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let mut client = AcmeClient::new(config, challenges).unwrap();
        client.ensure_account_key().unwrap();

        // Key file should exist
        assert!(dir.path().join("account.key").exists());

        // Loading again should reuse the same key
        client.account_key = None;
        client.ensure_account_key().unwrap();
    }

    // --- JWS building ---

    #[test]
    fn test_build_jws_without_account() {
        let dir = tempfile::tempdir().unwrap();
        let challenges = Arc::new(ChallengeStore::new());
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            storage_path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let mut client = AcmeClient::new(config, challenges).unwrap();
        client.ensure_account_key().unwrap();

        let jws = client
            .build_jws(
                "https://acme.example/new-acct",
                r#"{"test":true}"#,
                "nonce123",
            )
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();
        assert!(parsed["protected"].is_string());
        assert!(parsed["payload"].is_string());
        assert!(parsed["signature"].is_string());

        // Decode protected header — should contain jwk (not kid)
        let protected = URL_SAFE_NO_PAD
            .decode(parsed["protected"].as_str().unwrap())
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&protected).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert!(header["jwk"].is_object());
        assert!(header.get("kid").is_none());
    }

    #[test]
    fn test_build_jws_with_account() {
        let dir = tempfile::tempdir().unwrap();
        let challenges = Arc::new(ChallengeStore::new());
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            storage_path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let mut client = AcmeClient::new(config, challenges).unwrap();
        client.ensure_account_key().unwrap();
        client.account_url = Some("https://acme.example/acct/1".to_string());

        let jws = client
            .build_jws("https://acme.example/order", r#"{"test":true}"#, "nonce456")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();

        let protected = URL_SAFE_NO_PAD
            .decode(parsed["protected"].as_str().unwrap())
            .unwrap();
        let header: serde_json::Value = serde_json::from_slice(&protected).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "https://acme.example/acct/1");
        assert!(header.get("jwk").is_none());
    }

    #[test]
    fn test_build_jws_post_as_get() {
        let dir = tempfile::tempdir().unwrap();
        let challenges = Arc::new(ChallengeStore::new());
        let config = AcmeConfig {
            email: "test@example.com".to_string(),
            domains: vec!["example.com".to_string()],
            storage_path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let mut client = AcmeClient::new(config, challenges).unwrap();
        client.ensure_account_key().unwrap();

        // Empty payload = POST-as-GET
        let jws = client
            .build_jws("https://acme.example/auth", "", "nonce789")
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&jws).unwrap();
        assert_eq!(parsed["payload"], "");
    }

    #[test]
    fn test_build_jws_no_key_fails() {
        let challenges = Arc::new(ChallengeStore::new());
        let client = AcmeClient::new(test_config(), challenges).unwrap();
        let result = client.build_jws("https://acme.example/test", "{}", "nonce");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Account key"));
    }

    // --- DER helpers ---

    #[test]
    fn test_encode_der_length_short() {
        let mut out = Vec::new();
        encode_der_length(42, &mut out);
        assert_eq!(out, vec![42]);
    }

    #[test]
    fn test_encode_der_length_medium() {
        let mut out = Vec::new();
        encode_der_length(200, &mut out);
        assert_eq!(out, vec![0x81, 200]);
    }

    #[test]
    fn test_encode_der_length_long() {
        let mut out = Vec::new();
        encode_der_length(300, &mut out);
        assert_eq!(out, vec![0x82, 0x01, 0x2c]);
    }

    #[test]
    fn test_pem_encode() {
        let pem = pem_encode("TEST", &[1, 2, 3, 4]);
        assert!(pem.starts_with("-----BEGIN TEST-----\n"));
        assert!(pem.ends_with("-----END TEST-----\n"));
    }

    // --- CSR builder ---

    #[test]
    fn test_build_csr() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let csr = build_csr(&key, &["example.com".to_string()], &rng).unwrap();
        // CSR should start with SEQUENCE tag
        assert_eq!(csr[0], 0x30);
        assert!(csr.len() > 100);
    }

    #[test]
    fn test_build_csr_multiple_domains() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let domains = vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
            "api.example.com".to_string(),
        ];
        let csr = build_csr(&key, &domains, &rng).unwrap();
        assert_eq!(csr[0], 0x30);
        // Multi-domain CSR should be larger
        assert!(csr.len() > 150);
    }
}
