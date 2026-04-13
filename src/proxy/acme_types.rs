//! ACME protocol types (RFC 8555)

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_acme_directory_deserialize() {
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
    fn test_acme_directory_deserialize_minimal() {
        let json = r#"{
            "newNonce": "https://acme.example/nonce",
            "newAccount": "https://acme.example/account",
            "newOrder": "https://acme.example/order"
        }"#;
        let dir: AcmeDirectory = serde_json::from_str(json).unwrap();
        assert!(dir.revoke_cert.is_empty());
    }

    #[test]
    fn test_acme_order_deserialize() {
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
    fn test_acme_order_with_certificate() {
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

    #[test]
    fn test_acme_challenge_deserialize() {
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

    #[test]
    fn test_acme_identifier_deserialize() {
        let json = r#"{
            "type": "dns",
            "value": "example.com"
        }"#;
        let id: AcmeIdentifier = serde_json::from_str(json).unwrap();
        assert_eq!(id.id_type, "dns");
        assert_eq!(id.value, "example.com");
    }

    #[test]
    fn test_acme_authorization_deserialize() {
        let json = r#"{
            "status": "pending",
            "identifier": {
                "type": "dns",
                "value": "example.com"
            },
            "challenges": []
        }"#;
        let auth: AcmeAuthorization = serde_json::from_str(json).unwrap();
        assert_eq!(auth.status, "pending");
        assert_eq!(auth.identifier.value, "example.com");
        assert!(auth.challenges.is_empty());
    }
}

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
