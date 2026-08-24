use super::model::{StoredManagedServiceBinding, STATE_SCHEMA};
use crate::error::{GatewayError, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const MAX_STATE_BYTES: u64 = 4 * 1024 * 1024;

pub(super) async fn acquire_lock(path: &Path) -> Result<std::fs::File> {
    let parent = path.parent().ok_or_else(|| {
        state_error("Managed Service state path has no parent directory".to_string())
    })?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|error| io_error(path, "create parent directory for", error))?;
    let file_name = path.file_name().ok_or_else(|| {
        state_error("Managed Service state path does not identify a file".to_string())
    })?;
    let lock_path = parent.join(format!(".{}.lock", file_name.to_string_lossy()));
    match tokio::fs::symlink_metadata(&lock_path).await {
        Ok(metadata) => validate_existing_file(&lock_path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(&lock_path, "inspect", error)),
    }
    let open_path = lock_path.clone();
    let file = tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(open_path)
    })
    .await
    .map_err(|error| {
        state_error(format!(
            "Could not join Managed Service state lock task: {error}"
        ))
    })?
    .map_err(|error| io_error(&lock_path, "open", error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_error(&lock_path, "inspect", error))?;
    validate_existing_file(&lock_path, &metadata)?;
    file.try_lock_exclusive().map_err(|error| {
        if lock_is_contended(&error) {
            state_error(format!(
                "Managed Service state {} is already owned by another Gateway",
                path.display()
            ))
        } else {
            io_error(&lock_path, "lock", error)
        }
    })?;
    Ok(file)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StateFile {
    schema: String,
    bindings: Vec<StoredManagedServiceBinding>,
}

pub(super) async fn read(path: &Path) -> Result<Vec<StoredManagedServiceBinding>> {
    let metadata = match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(io_error(path, "inspect", error)),
    };
    validate_existing_file(path, &metadata)?;
    if metadata.len() > MAX_STATE_BYTES {
        return Err(state_error(format!(
            "Managed Service state {} exceeds {MAX_STATE_BYTES} bytes",
            path.display()
        )));
    }
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|error| io_error(path, "open", error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| io_error(path, "read", error))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(state_error(format!(
            "Managed Service state {} exceeds {MAX_STATE_BYTES} bytes",
            path.display()
        )));
    }
    let state: StateFile = serde_json::from_slice(&bytes).map_err(|error| {
        state_error(format!(
            "Managed Service state {} is invalid JSON: {error}",
            path.display()
        ))
    })?;
    if state.schema != STATE_SCHEMA {
        return Err(state_error(format!(
            "Managed Service state {} uses unsupported schema {:?}",
            path.display(),
            state.schema
        )));
    }
    Ok(state.bindings)
}

pub(super) async fn write(path: &Path, bindings: Vec<StoredManagedServiceBinding>) -> Result<()> {
    let state = StateFile {
        schema: STATE_SCHEMA.to_string(),
        bindings,
    };
    let bytes = serde_json::to_vec(&state)
        .map_err(|error| state_error(format!("Could not encode Managed Service state: {error}")))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(state_error(format!(
            "Managed Service state exceeds {MAX_STATE_BYTES} bytes"
        )));
    }
    let parent = path.parent().ok_or_else(|| {
        state_error("Managed Service state path has no parent directory".to_string())
    })?;
    tokio::fs::create_dir_all(parent)
        .await
        .map_err(|error| io_error(path, "create parent directory for", error))?;
    match tokio::fs::symlink_metadata(path).await {
        Ok(metadata) => validate_existing_file(path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(io_error(path, "inspect", error)),
    }
    let file_name = path.file_name().ok_or_else(|| {
        state_error("Managed Service state path does not identify a file".to_string())
    })?;
    let temporary = parent.join(format!(
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
    let mut file = options
        .open(&temporary)
        .await
        .map_err(|error| io_error(&temporary, "create", error))?;
    let publication = async {
        file.write_all(&bytes).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temporary, path).await
    }
    .await;
    if let Err(error) = publication {
        let _ = tokio::fs::remove_file(&temporary).await;
        return Err(io_error(path, "publish", error));
    }
    sync_parent(parent)
        .await
        .map_err(|error| io_error(path, "sync parent directory for", error))
}

fn validate_existing_file(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(state_error(format!(
            "Managed Service state {} must be a regular non-symlink file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(state_error(format!(
                "Managed Service state {} must not be accessible by group or other users",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn sync_parent(parent: &Path) -> std::io::Result<()> {
    tokio::fs::File::open(parent).await?.sync_all().await
}

#[cfg(not(unix))]
async fn sync_parent(_parent: &Path) -> std::io::Result<()> {
    Ok(())
}

fn io_error(path: &Path, action: &str, error: std::io::Error) -> GatewayError {
    state_error(format!(
        "Could not {action} Managed Service state {}: {error}",
        path.display()
    ))
}

fn state_error(message: String) -> GatewayError {
    GatewayError::Other(message)
}

fn lock_is_contended(error: &std::io::Error) -> bool {
    let expected = fs2::lock_contended_error();
    match (error.raw_os_error(), expected.raw_os_error()) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => error.kind() == expected.kind(),
    }
}

pub(super) fn validate_path(path: PathBuf) -> Result<PathBuf> {
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(GatewayError::Config(
            "Managed Service state must use an absolute normalized file path".to_string(),
        ));
    }
    Ok(path)
}
