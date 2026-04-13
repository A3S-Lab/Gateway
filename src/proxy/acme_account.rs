//! ACME account key management

use crate::error::{GatewayError, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};

#[cfg(test)]
mod tests {
    use super::*;

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
