//! Read-only digest-bound object authority port.
//!
//! Gateway may `HEAD`/`GET` by digest only. List, write, delete, restore, and
//! "current release" discovery are out of scope for the data plane.

use super::StaticObjectError;
use async_trait::async_trait;
use bytes::Bytes;

/// Metadata returned by a digest-bound `HEAD`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticObjectMeta {
    pub digest: String,
    pub size: u64,
}

/// Bytes returned by a digest-bound `GET` after local size/digest checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticObjectBytes {
    pub digest: String,
    pub body: Bytes,
}

/// Closed object-authority surface used by static bundle serving.
#[async_trait]
pub trait ReadOnlyObjectPort: Send + Sync {
    async fn head(&self, digest: &str) -> Result<StaticObjectMeta, StaticObjectError>;
    async fn get(&self, digest: &str) -> Result<StaticObjectBytes, StaticObjectError>;
}

/// Admit object bytes into a local cache only when size and digest match.
pub fn admit_object_bytes(
    expected_digest: &str,
    expected_size: u64,
    body: Bytes,
) -> Result<StaticObjectBytes, StaticObjectError> {
    if body.len() as u64 != expected_size {
        return Err(StaticObjectError::Integrity(format!(
            "static object size mismatch: expected {expected_size}, got {}",
            body.len()
        )));
    }
    let actual = sha256_hex(&body);
    if actual != expected_digest {
        return Err(StaticObjectError::Integrity(format!(
            "static object digest mismatch for {expected_digest}"
        )));
    }
    Ok(StaticObjectBytes {
        digest: actual,
        body,
    })
}

pub(crate) fn sha256_hex(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admits_only_exact_size_and_digest() {
        let body = Bytes::from_static(b"hello-static");
        let digest = sha256_hex(&body);
        let admitted = admit_object_bytes(&digest, body.len() as u64, body.clone()).unwrap();
        assert_eq!(admitted.digest, digest);

        assert!(admit_object_bytes(&digest, 1, body.clone()).is_err());
        assert!(admit_object_bytes(&format!("{:064x}", 1), body.len() as u64, body).is_err());
    }
}
