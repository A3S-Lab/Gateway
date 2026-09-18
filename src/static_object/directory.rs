//! Read-only digest-addressed directory for standalone static fixtures.
//!
//! Files are named by lowercase SHA-256 hex. This is not an S3 client and does
//! not list, write, or discover a "current" release.

use super::port::{ReadOnlyObjectPort, StaticObjectBytes, StaticObjectMeta};
use super::StaticObjectError;
use async_trait::async_trait;
use bytes::Bytes;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct DirectoryObjectAuthority {
    root: PathBuf,
}

impl DirectoryObjectAuthority {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn object_path(&self, digest: &str) -> Result<PathBuf, StaticObjectError> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StaticObjectError::Contract(
                "object digest must be lowercase sha256 hex".into(),
            ));
        }
        let path = self.root.join(digest);
        if path.parent() != Some(self.root.as_path()) && path.parent() != Some(Path::new("")) {
            // join of a plain digest should stay under root; defend against
            // future API drift that accepts path separators.
            return Err(StaticObjectError::InvalidPath(
                "object digest path escaped the digest store".into(),
            ));
        }
        Ok(path)
    }
}

#[async_trait]
impl ReadOnlyObjectPort for DirectoryObjectAuthority {
    async fn head(&self, digest: &str) -> Result<StaticObjectMeta, StaticObjectError> {
        let path = self.object_path(digest)?;
        let meta = tokio::fs::metadata(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StaticObjectError::NotFound(format!("object digest {digest}"))
            } else {
                StaticObjectError::Contract(format!("object digest store head failed: {error}"))
            }
        })?;
        Ok(StaticObjectMeta {
            digest: digest.to_owned(),
            size: meta.len(),
        })
    }

    async fn get(&self, digest: &str) -> Result<StaticObjectBytes, StaticObjectError> {
        let path = self.object_path(digest)?;
        let body = tokio::fs::read(&path).await.map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StaticObjectError::NotFound(format!("object digest {digest}"))
            } else {
                StaticObjectError::Contract(format!("object digest store get failed: {error}"))
            }
        })?;
        Ok(StaticObjectBytes {
            digest: digest.to_owned(),
            body: Bytes::from(body),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::static_object::port::sha256_hex;

    #[tokio::test]
    async fn reads_digest_named_files_only() {
        let directory = tempfile::tempdir().unwrap();
        let body = b"static-bytes";
        let digest = sha256_hex(body);
        tokio::fs::write(directory.path().join(&digest), body)
            .await
            .unwrap();
        let authority = DirectoryObjectAuthority::new(directory.path());
        assert_eq!(
            authority.head(&digest).await.unwrap().size,
            body.len() as u64
        );
        assert_eq!(
            authority.get(&digest).await.unwrap().body.as_ref(),
            body.as_slice()
        );
        assert!(authority
            .get(&format!("{:064x}", 1))
            .await
            .unwrap_err()
            .to_string()
            .contains("not found"));
    }
}
