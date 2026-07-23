//! Durable write-ahead journal for managed snapshots.

use super::ManagedSnapshot;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

pub(super) const MANAGED_SNAPSHOT_JOURNAL_SCHEMA: &str = "a3s.gateway.managed-snapshot-journal.v1";

const MAX_JOURNAL_BYTES: u64 = super::MAX_ACL_BYTES as u64 * 6 + 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum JournalPhase {
    Prepared,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedSnapshotJournal {
    pub schema: String,
    pub gateway_id: Uuid,
    pub phase: JournalPhase,
    pub snapshot: ManagedSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied_at: Option<DateTime<Utc>>,
}

impl ManagedSnapshotJournal {
    pub(super) fn prepared(snapshot: ManagedSnapshot) -> Self {
        Self {
            schema: MANAGED_SNAPSHOT_JOURNAL_SCHEMA.to_string(),
            gateway_id: snapshot.gateway_id,
            phase: JournalPhase::Prepared,
            snapshot,
            applied_at: None,
        }
    }

    pub(super) fn applied(snapshot: ManagedSnapshot, applied_at: DateTime<Utc>) -> Self {
        Self {
            schema: MANAGED_SNAPSHOT_JOURNAL_SCHEMA.to_string(),
            gateway_id: snapshot.gateway_id,
            phase: JournalPhase::Applied,
            snapshot,
            applied_at: Some(applied_at),
        }
    }

    pub(super) fn validate_shape(&self) -> std::result::Result<(), String> {
        if self.schema != MANAGED_SNAPSHOT_JOURNAL_SCHEMA {
            return Err(format!(
                "unsupported managed snapshot journal schema {:?}",
                self.schema
            ));
        }
        if self.gateway_id != self.snapshot.gateway_id {
            return Err(
                "managed snapshot journal identity does not match its snapshot".to_string(),
            );
        }
        match (self.phase, self.applied_at) {
            (JournalPhase::Prepared, None) | (JournalPhase::Applied, Some(_)) => Ok(()),
            (JournalPhase::Prepared, Some(_)) => {
                Err("prepared managed snapshot journal must not contain applied_at".to_string())
            }
            (JournalPhase::Applied, None) => {
                Err("applied managed snapshot journal requires applied_at".to_string())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct ManagedSnapshotPersistence {
    path: PathBuf,
}

impl ManagedSnapshotPersistence {
    pub(super) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) async fn read(
        &self,
    ) -> std::result::Result<Option<ManagedSnapshotJournal>, PersistenceError> {
        let metadata = match tokio::fs::symlink_metadata(&self.path).await {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(PersistenceError::before("inspect journal", error)),
        };
        if metadata.file_type().is_symlink() {
            return Err(PersistenceError::invalid(format!(
                "managed snapshot journal {} must not be a symbolic link",
                self.path.display()
            )));
        }
        if !metadata.is_file() {
            return Err(PersistenceError::invalid(format!(
                "managed snapshot journal {} is not a regular file",
                self.path.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(PersistenceError::invalid(format!(
                    "managed snapshot journal {} must not be accessible by group or other users",
                    self.path.display()
                )));
            }
        }
        if metadata.len() > MAX_JOURNAL_BYTES {
            return Err(PersistenceError::invalid(format!(
                "managed snapshot journal exceeds {MAX_JOURNAL_BYTES} bytes"
            )));
        }

        let file = tokio::fs::File::open(&self.path)
            .await
            .map_err(|error| PersistenceError::before("open journal", error))?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_JOURNAL_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|error| PersistenceError::before("read journal", error))?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(PersistenceError::invalid(format!(
                "managed snapshot journal exceeds {MAX_JOURNAL_BYTES} bytes"
            )));
        }
        let journal = serde_json::from_slice(&bytes).map_err(|error| {
            PersistenceError::invalid(format!(
                "managed snapshot journal {} is invalid JSON: {error}",
                self.path.display()
            ))
        })?;
        Ok(Some(journal))
    }

    pub(super) async fn write(
        &self,
        journal: &ManagedSnapshotJournal,
    ) -> std::result::Result<(), PersistenceError> {
        let bytes = serde_json::to_vec(journal).map_err(|error| {
            PersistenceError::invalid(format!(
                "could not encode managed snapshot journal: {error}"
            ))
        })?;
        if bytes.len() as u64 > MAX_JOURNAL_BYTES {
            return Err(PersistenceError::invalid(format!(
                "managed snapshot journal exceeds {MAX_JOURNAL_BYTES} bytes"
            )));
        }

        let parent = self.path.parent().ok_or_else(|| {
            PersistenceError::invalid("managed snapshot journal path has no parent directory")
        })?;
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|error| PersistenceError::before("create journal directory", error))?;
        reject_existing_non_file(&self.path).await?;

        let file_name = self.path.file_name().ok_or_else(|| {
            PersistenceError::invalid("managed snapshot journal path does not identify a file")
        })?;
        let temporary_path = parent.join(format!(
            ".{}.{}.tmp",
            file_name.to_string_lossy(),
            Uuid::new_v4()
        ));

        let mut options = tokio::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let mut temporary = options
            .open(&temporary_path)
            .await
            .map_err(|error| PersistenceError::before("create journal staging file", error))?;

        let staging_result = async {
            temporary.write_all(&bytes).await?;
            temporary.sync_all().await?;
            drop(temporary);
            tokio::fs::rename(&temporary_path, &self.path).await
        }
        .await;
        if let Err(error) = staging_result {
            let _ = tokio::fs::remove_file(&temporary_path).await;
            return Err(PersistenceError::before("publish journal", error));
        }

        sync_parent(parent)
            .await
            .map_err(|error| PersistenceError::after("sync journal directory", error))
    }

    pub(super) async fn restore(
        &self,
        journal: Option<&ManagedSnapshotJournal>,
    ) -> std::result::Result<(), PersistenceError> {
        match journal {
            Some(journal) => self.write(journal).await,
            None => self.remove().await,
        }
    }

    async fn remove(&self) -> std::result::Result<(), PersistenceError> {
        match tokio::fs::symlink_metadata(&self.path).await {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PersistenceError::invalid(format!(
                    "managed snapshot journal {} must not be a symbolic link",
                    self.path.display()
                )));
            }
            Ok(metadata) if !metadata.is_file() => {
                return Err(PersistenceError::invalid(format!(
                    "managed snapshot journal {} is not a regular file",
                    self.path.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(PersistenceError::before("inspect journal", error)),
        }

        tokio::fs::remove_file(&self.path)
            .await
            .map_err(|error| PersistenceError::before("remove journal", error))?;
        let parent = self.path.parent().ok_or_else(|| {
            PersistenceError::invalid("managed snapshot journal path has no parent directory")
        })?;
        sync_parent(parent)
            .await
            .map_err(|error| PersistenceError::after("sync journal directory", error))
    }
}

async fn reject_existing_non_file(path: &Path) -> std::result::Result<(), PersistenceError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(PersistenceError::invalid(format!(
                "managed snapshot journal {} must not be a symbolic link",
                path.display()
            )))
        }
        Ok(metadata) if !metadata.is_file() => Err(PersistenceError::invalid(format!(
            "managed snapshot journal {} is not a regular file",
            path.display()
        ))),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PersistenceError::before("inspect journal", error)),
    }
}

#[cfg(unix)]
async fn sync_parent(parent: &Path) -> std::io::Result<()> {
    tokio::fs::File::open(parent).await?.sync_all().await
}

#[cfg(not(unix))]
async fn sync_parent(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

#[derive(Debug)]
pub(super) struct PersistenceError {
    message: String,
    published: bool,
}

impl PersistenceError {
    fn before(action: &str, error: std::io::Error) -> Self {
        Self {
            message: format!("could not {action}: {error}"),
            published: false,
        }
    }

    fn after(action: &str, error: std::io::Error) -> Self {
        Self {
            message: format!("could not {action}: {error}"),
            published: true,
        }
    }

    fn invalid(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            published: false,
        }
    }

    pub(super) const fn published(&self) -> bool {
        self.published
    }
}

impl fmt::Display for PersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PersistenceError {}
