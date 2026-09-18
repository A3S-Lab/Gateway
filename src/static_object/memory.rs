//! In-memory read-only object authority for Gateway-local WEB0.4 tests.
//!
//! This is not S3 and not a production cache. It only proves digest-bound
//! HEAD/GET semantics without inventing list/write/delete APIs.

use super::port::{sha256_hex, ReadOnlyObjectPort, StaticObjectBytes, StaticObjectMeta};
use super::StaticObjectError;
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Default)]
pub struct MemoryObjectAuthority {
    objects: Mutex<HashMap<String, Bytes>>,
}

impl MemoryObjectAuthority {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert bytes under their content digest. Overwriting a digest with
    /// different bytes fails closed.
    pub fn insert(&self, body: impl Into<Bytes>) -> Result<String, StaticObjectError> {
        let body = body.into();
        let digest = sha256_hex(&body);
        let mut objects = self.objects.lock().expect("memory object authority lock");
        match objects.get(&digest) {
            Some(existing) if existing.as_ref() != body.as_ref() => {
                Err(StaticObjectError::Integrity(format!(
                    "memory object authority refuses conflicting bytes for {digest}"
                )))
            }
            Some(_) => Ok(digest),
            None => {
                objects.insert(digest.clone(), body);
                Ok(digest)
            }
        }
    }
}

#[async_trait]
impl ReadOnlyObjectPort for MemoryObjectAuthority {
    async fn head(&self, digest: &str) -> Result<StaticObjectMeta, StaticObjectError> {
        let objects = self.objects.lock().expect("memory object authority lock");
        let body = objects
            .get(digest)
            .ok_or_else(|| StaticObjectError::NotFound(format!("object digest {digest}")))?;
        Ok(StaticObjectMeta {
            digest: digest.to_owned(),
            size: body.len() as u64,
        })
    }

    async fn get(&self, digest: &str) -> Result<StaticObjectBytes, StaticObjectError> {
        let objects = self.objects.lock().expect("memory object authority lock");
        let body = objects
            .get(digest)
            .ok_or_else(|| StaticObjectError::NotFound(format!("object digest {digest}")))?
            .clone();
        Ok(StaticObjectBytes {
            digest: digest.to_owned(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serves_digest_bound_head_and_get_only() {
        let authority = MemoryObjectAuthority::new();
        let digest = authority.insert(&b"bundle"[..]).unwrap();
        let meta = authority.head(&digest).await.unwrap();
        assert_eq!(meta.size, 6);
        let bytes = authority.get(&digest).await.unwrap();
        assert_eq!(bytes.body.as_ref(), b"bundle");
        assert!(authority
            .head(&format!("{:064x}", 9))
            .await
            .unwrap_err()
            .to_string()
            .contains("not found"));
    }
}
