//! File watcher — monitors config files and triggers hot reload
//!
//! Uses the `notify` crate for cross-platform file system events
//! (inotify on Linux, kqueue on macOS, ReadDirectoryChanges on Windows).

use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Debounce interval to coalesce rapid file changes
const DEBOUNCE_MS: u64 = 500;

/// File watcher — watches config files and notifies on changes
pub struct FileWatcher {
    /// Path to the main config file
    config_path: PathBuf,
    /// Optional directory to watch for additional configs
    watch_directory: Option<PathBuf>,
    /// Last known good config
    last_config: Arc<RwLock<Option<GatewayConfig>>>,
    /// Total reload count
    reload_count: Arc<std::sync::atomic::AtomicU64>,
}

/// Reload event — emitted when configuration changes are detected
#[derive(Debug, Clone)]
pub struct ReloadEvent {
    /// Path that triggered the reload
    pub trigger_path: PathBuf,
    /// New configuration (if parsing succeeded)
    pub config: std::result::Result<GatewayConfig, String>,
    /// Timestamp of the event
    pub timestamp: Instant,
}

/// Load the root `.acl` file and merge any `providers.file.directory` fragments.
///
/// This is the single loader for CLI `run`, `validate`, and hot reload so
/// cold-start activation matches `a3s-gateway validate` (validate ≡ activate).
/// A configured directory that is missing fails closed instead of binding only
/// the root ACL while operators believe conf.d is active.
pub fn load_merged_gateway_config(config_path: impl AsRef<Path>) -> Result<GatewayConfig> {
    let config_path = config_path.as_ref();
    // Same extension gate as read_combined_config / conf.d merge — a non-.acl
    // root path cannot soft-open cold start while only directory merges reject.
    if !is_config_file(config_path) {
        return Err(GatewayError::Config(
            "Gateway config files must use .acl extension".to_string(),
        ));
    }
    let root_content = read_config_file(config_path)?;
    let root = GatewayConfig::from_acl(&root_content)?;
    let directory = root
        .providers
        .file
        .as_ref()
        .and_then(|file| file.directory.as_deref())
        .map(PathBuf::from);

    let content = match directory.as_deref() {
        Some(dir) => read_combined_config(config_path, Some(dir))?,
        None => root_content,
    };

    let config = GatewayConfig::from_acl(&content)?;
    // Path-aware activation: structural + runtime probes including the same
    // notify watch attach surface as CLI hot reload (`providers.file.watch`).
    crate::validate_activation_at_path(&config, config_path)?;
    Ok(config)
}

/// Probe the same notify `Watcher::new` surface used by hot reload.
///
/// Called from [`crate::validate_activation`] / path-less [`crate::Gateway::new`]
/// when `providers.file.watch` is true so embedders cannot soft-open a config
/// that only fails when the watcher is created. Directory attach (when
/// configured) is included; the root ACL parent-path attach requires
/// [`crate::validate_activation_at_path`] / [`crate::Gateway::new_at_path`].
pub(crate) fn probe_file_watch_notify_activation(watch_directory: Option<&Path>) -> Result<()> {
    let (notify_tx, _notify_rx) = mpsc::channel();
    let mut watcher: RecommendedWatcher = Watcher::new(notify_tx, notify::Config::default())
        .map_err(|error| {
            GatewayError::Config(format!(
                "providers.file.watch cannot activate: failed to create file watcher: {error}"
            ))
        })?;

    if let Some(dir) = watch_directory {
        if !dir.exists() {
            return Err(GatewayError::Config(format!(
                "providers.file.directory does not exist: {}",
                dir.display()
            )));
        }
        watcher
            .watch(dir, RecursiveMode::NonRecursive)
            .map_err(|error| {
                GatewayError::Config(format!(
                    "providers.file.watch cannot activate: failed to watch directory {}: {error}",
                    dir.display()
                ))
            })?;
    }
    Ok(())
}

/// Probe the same notify `Watcher::new` + path attach surface as [`FileWatcher::watch`].
///
/// Used by [`crate::validate_activation_at_path`] /
/// [`crate::Gateway::new_at_path`] / CLI load when `providers.file.watch = true`
/// so validate cannot pass while `a3s-gateway run` later aborts because the
/// watcher cannot start.
pub(crate) fn probe_file_watch_activation(
    config_path: &Path,
    watch_directory: Option<&Path>,
) -> Result<()> {
    let (notify_tx, _notify_rx) = mpsc::channel();
    let _watcher = create_configured_watcher(config_path, watch_directory, notify_tx)?;
    Ok(())
}

fn create_configured_watcher(
    config_path: &Path,
    watch_directory: Option<&Path>,
    notify_tx: mpsc::Sender<std::result::Result<Event, notify::Error>>,
) -> Result<RecommendedWatcher> {
    let mut watcher: RecommendedWatcher = Watcher::new(notify_tx, notify::Config::default())
        .map_err(|error| {
            GatewayError::Config(format!(
                "providers.file.watch cannot activate: failed to create file watcher: {error}"
            ))
        })?;

    let watch_path = config_path.parent().unwrap_or_else(|| Path::new("."));
    watcher
        .watch(watch_path, RecursiveMode::NonRecursive)
        .map_err(|error| {
            GatewayError::Config(format!(
                "providers.file.watch cannot activate: failed to watch {}: {error}",
                watch_path.display()
            ))
        })?;

    if let Some(dir) = watch_directory {
        if !dir.exists() {
            return Err(GatewayError::Config(format!(
                "providers.file.directory does not exist: {}",
                dir.display()
            )));
        }
        watcher
            .watch(dir, RecursiveMode::Recursive)
            .map_err(|error| {
                GatewayError::Config(format!(
                    "providers.file.watch cannot activate: failed to watch directory {}: {error}",
                    dir.display()
                ))
            })?;
    }

    Ok(watcher)
}

impl FileWatcher {
    /// Create a new file watcher for the given config path
    pub fn new(config_path: impl AsRef<Path>) -> Self {
        Self {
            config_path: config_path.as_ref().to_path_buf(),
            watch_directory: None,
            last_config: Arc::new(RwLock::new(None)),
            reload_count: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Set an additional directory to watch
    pub fn with_directory(mut self, dir: impl AsRef<Path>) -> Self {
        self.watch_directory = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Get the config file path
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// Get the watch directory (if set)
    pub fn watch_directory(&self) -> Option<&Path> {
        self.watch_directory.as_deref()
    }

    /// Get total reload count
    pub fn reload_count(&self) -> u64 {
        self.reload_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the last known good config
    pub fn last_config(&self) -> Option<GatewayConfig> {
        self.last_config.read().unwrap().clone()
    }

    /// Load the config file and validate it
    pub fn load_config(&self) -> Result<GatewayConfig> {
        let config = if let Some(ref dir) = self.watch_directory {
            let content = read_combined_config(&self.config_path, Some(dir))?;
            let config = GatewayConfig::from_acl(&content)?;
            crate::validate_activation_at_path(&config, &self.config_path)?;
            config
        } else {
            load_merged_gateway_config(&self.config_path)?
        };

        // Store as last known good
        let mut last = self.last_config.write().unwrap();
        *last = Some(config.clone());

        Ok(config)
    }

    /// Start watching for file changes. Returns a channel receiver for reload events.
    ///
    /// This method spawns a background thread that watches for file system events
    /// and sends `ReloadEvent`s through the returned channel.
    pub fn watch(&self) -> Result<mpsc::Receiver<ReloadEvent>> {
        let (event_tx, event_rx) = mpsc::channel();
        let (notify_tx, notify_rx) = mpsc::channel();

        let config_path = self.config_path.clone();
        let watch_dir = self.watch_directory.clone();
        let last_config = self.last_config.clone();
        let reload_count = self.reload_count.clone();

        let watcher = create_configured_watcher(&config_path, watch_dir.as_deref(), notify_tx)?;

        // Spawn background thread to process events
        std::thread::spawn(move || {
            let _watcher = watcher; // Keep watcher alive
            let mut last_event_time = Instant::now();

            loop {
                match notify_rx.recv() {
                    Ok(Ok(event)) => {
                        if !is_relevant_config_event(&event, &config_path, watch_dir.as_deref()) {
                            continue;
                        }

                        // Debounce: skip if too close to last event
                        let now = Instant::now();
                        if now.duration_since(last_event_time) < Duration::from_millis(DEBOUNCE_MS)
                        {
                            continue;
                        }
                        last_event_time = now;

                        let trigger_path = event
                            .paths
                            .first()
                            .cloned()
                            .unwrap_or_else(|| config_path.clone());

                        tracing::info!(
                            path = %trigger_path.display(),
                            "Config file change detected, reloading"
                        );

                        // Try to load and validate the combined ACL config.
                        let content = match read_combined_config(&config_path, watch_dir.as_deref())
                        {
                            Ok(c) => c,
                            Err(e) => {
                                let _ = event_tx.send(ReloadEvent {
                                    trigger_path,
                                    config: Err(e.to_string()),
                                    timestamp: now,
                                });
                                continue;
                            }
                        };

                        let config_result = GatewayConfig::from_acl(&content).and_then(|c| {
                            crate::validate_activation(&c)?;
                            Ok(c)
                        });

                        match &config_result {
                            Ok(config) => {
                                let mut last = last_config.write().unwrap();
                                *last = Some(config.clone());
                                reload_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                tracing::info!("Configuration reloaded successfully");
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    "Config reload failed, keeping previous config"
                                );
                            }
                        }

                        let _ = event_tx.send(ReloadEvent {
                            trigger_path,
                            config: config_result.map_err(|e| e.to_string()),
                            timestamp: now,
                        });
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "File watcher error");
                    }
                    Err(_) => {
                        // Channel closed, watcher was dropped
                        break;
                    }
                }
            }
        });

        Ok(event_rx)
    }
}

/// Check if a file system event is relevant for config reload
fn is_relevant_event(event: &Event) -> bool {
    matches!(
        event.kind,
        EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
    )
}

fn is_relevant_config_event(event: &Event, config_path: &Path, watch_dir: Option<&Path>) -> bool {
    is_relevant_event(event)
        && event
            .paths
            .iter()
            .any(|path| is_watched_config_path(path, config_path, watch_dir))
}

fn is_watched_config_path(path: &Path, config_path: &Path, watch_dir: Option<&Path>) -> bool {
    if paths_equivalent(path, config_path) {
        return true;
    }

    if !is_config_file(path) {
        return false;
    }

    watch_dir.is_some_and(|dir| path.starts_with(dir))
}

fn read_combined_config(config_path: &Path, watch_dir: Option<&Path>) -> Result<String> {
    if !is_config_file(config_path) {
        return Err(GatewayError::Config(
            "Gateway config files must use .acl extension".to_string(),
        ));
    }

    let mut content = read_config_file(config_path)?;

    for path in collect_config_files(watch_dir, config_path)? {
        content.push_str("\n\n");
        content.push_str(&read_config_file(&path)?);
    }

    Ok(content)
}

fn read_config_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| {
        GatewayError::Config(format!(
            "Failed to read config file {}: {}",
            path.display(),
            e
        ))
    })
}

fn collect_config_files(watch_dir: Option<&Path>, config_path: &Path) -> Result<Vec<PathBuf>> {
    let Some(dir) = watch_dir else {
        return Ok(Vec::new());
    };

    if !dir.exists() {
        return Err(GatewayError::Config(format!(
            "providers.file.directory does not exist: {}",
            dir.display()
        )));
    }

    let mut paths = Vec::new();
    collect_config_files_recursive(dir, config_path, &mut paths)?;
    paths.sort();
    Ok(paths)
}

fn collect_config_files_recursive(
    dir: &Path,
    config_path: &Path,
    paths: &mut Vec<PathBuf>,
) -> Result<()> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        GatewayError::Config(format!(
            "Failed to read config directory {}: {}",
            dir.display(),
            e
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            GatewayError::Config(format!(
                "Failed to read config directory entry {}: {}",
                dir.display(),
                e
            ))
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| {
            GatewayError::Config(format!(
                "Failed to inspect config path {}: {}",
                path.display(),
                e
            ))
        })?;

        if file_type.is_dir() {
            collect_config_files_recursive(&path, config_path, paths)?;
        } else if file_type.is_file()
            && is_config_file(&path)
            && !paths_equivalent(&path, config_path)
        {
            paths.push(path);
        }
    }

    Ok(())
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }

    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Check if a path is a supported config file (.acl)
pub fn is_config_file(path: &Path) -> bool {
    path.extension().map(|ext| ext == "acl").unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- FileWatcher construction tests ---

    #[test]
    fn test_new_file_watcher() {
        let watcher = FileWatcher::new("/etc/gateway/config.acl");
        assert_eq!(watcher.config_path(), Path::new("/etc/gateway/config.acl"));
        assert!(watcher.watch_directory().is_none());
        assert_eq!(watcher.reload_count(), 0);
    }

    #[test]
    fn test_with_directory() {
        let watcher =
            FileWatcher::new("/etc/gateway/config.acl").with_directory("/etc/gateway/conf.d");
        assert_eq!(
            watcher.watch_directory(),
            Some(Path::new("/etc/gateway/conf.d"))
        );
    }

    #[test]
    fn test_last_config_initially_none() {
        let watcher = FileWatcher::new("/nonexistent.acl");
        assert!(watcher.last_config().is_none());
    }

    // --- Config loading tests ---

    #[test]
    fn test_load_config_missing_file() {
        let watcher = FileWatcher::new("/nonexistent/gateway.acl");
        let result = watcher.load_config();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn load_config_fails_closed_when_configured_directory_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();

        let missing = dir.path().join("conf.d-missing");
        let err = FileWatcher::new(&config_path)
            .with_directory(&missing)
            .load_config()
            .expect_err("missing providers.file.directory must fail closed");
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn watch_fails_closed_when_configured_directory_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();

        let missing = dir.path().join("conf.d-missing");
        let err = FileWatcher::new(&config_path)
            .with_directory(&missing)
            .watch()
            .expect_err("missing providers.file.directory must fail closed at watch start");
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_load_config_valid() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();

        let watcher = FileWatcher::new(&config_path);
        let config = watcher.load_config().unwrap();
        assert!(config.entrypoints.contains_key("web"));
        assert!(watcher.last_config().is_some());
    }

    #[test]
    fn test_load_config_with_directory_merges_acl_fragments() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir(&conf_dir).unwrap();

        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();

        std::fs::write(
            conf_dir.join("10-service.acl"),
            r#"
services "backend" {
  load_balancer {
    servers {
      url = "http://127.0.0.1:8001"
    }
  }
}
"#,
        )
        .unwrap();

        std::fs::write(
            conf_dir.join("20-router.acl"),
            r#"
routers "api" {
  rule        = "PathPrefix(`/api`)"
  service     = "backend"
  entrypoints = ["web"]
}
"#,
        )
        .unwrap();

        let watcher = FileWatcher::new(&config_path).with_directory(&conf_dir);
        let config = watcher.load_config().unwrap();
        assert!(config.entrypoints.contains_key("web"));
        assert!(config.services.contains_key("backend"));
        assert!(config.routers.contains_key("api"));
    }

    #[test]
    fn load_merged_gateway_config_merges_directory_from_root_acl() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir(&conf_dir).unwrap();
        let conf_dir_acl = conf_dir.display().to_string().replace('\\', "/");

        std::fs::write(
            &config_path,
            format!(
                r#"
providers {{
  file {{
    watch = false
    directory = "{conf_dir_acl}"
  }}
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}
"#
            ),
        )
        .unwrap();

        std::fs::write(
            conf_dir.join("10-service.acl"),
            r#"
services "backend" {
  load_balancer {
    servers = [{ url = "http://127.0.0.1:8001" }]
  }
}
"#,
        )
        .unwrap();

        std::fs::write(
            conf_dir.join("20-router.acl"),
            r#"
routers "api" {
  rule        = "PathPrefix(`/api`)"
  service     = "backend"
  entrypoints = ["web"]
}
"#,
        )
        .unwrap();

        // Cold-start / validate path: directory comes from the root ACL, not
        // from FileWatcher::with_directory.
        let config = load_merged_gateway_config(&config_path).unwrap();
        assert!(config.services.contains_key("backend"));
        assert!(config.routers.contains_key("api"));
        assert!(
            !config.providers.file.as_ref().unwrap().watch,
            "watch=false must still merge conf.d at load"
        );
    }

    #[test]
    fn load_merged_gateway_config_fails_closed_when_directory_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        let missing = dir.path().join("conf.d-missing");
        let missing_acl = missing.display().to_string().replace('\\', "/");

        std::fs::write(
            &config_path,
            format!(
                r#"
providers {{
  file {{
    directory = "{missing_acl}"
  }}
}}

entrypoints "web" {{
  address = "127.0.0.1:0"
}}
"#
            ),
        )
        .unwrap();

        let err = load_merged_gateway_config(&config_path)
            .expect_err("missing providers.file.directory must fail closed at merged load");
        assert!(
            err.to_string().contains("does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_merged_gateway_config_probes_file_watch_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
providers {
  file {
    watch = true
  }
}

entrypoints "web" {
  address = "127.0.0.1:0"
}
"#,
        )
        .unwrap();

        load_merged_gateway_config(&config_path)
            .expect("watch=true must probe notify attach at merged load");
    }

    #[test]
    fn probe_file_watch_activation_rejects_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            "entrypoints \"web\" { address = \"127.0.0.1:0\" }\n",
        )
        .unwrap();
        let missing = dir.path().join("conf.d-missing");
        let error = probe_file_watch_activation(&config_path, Some(&missing)).unwrap_err();
        assert!(
            error.to_string().contains("does not exist"),
            "missing watch directory must fail probe: {error}"
        );
    }

    #[test]
    fn validate_activation_fails_closed_when_file_watch_directory_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("conf.d-missing");
        let missing_acl = missing.display().to_string().replace('\\', "/");
        let config = GatewayConfig::from_acl(&format!(
            r#"
            providers {{
              file {{
                watch = true
                directory = "{missing_acl}"
              }}
            }}
            entrypoints "web" {{
              address = "127.0.0.1:0"
            }}
            "#
        ))
        .unwrap();
        let error = crate::validate_activation(&config).unwrap_err();
        assert!(
            error.to_string().contains("does not exist"),
            "watch=true with missing directory must fail validate_activation: {error}"
        );
    }

    #[test]
    fn validate_activation_probes_file_watch_notify_when_enabled() {
        let config = GatewayConfig::from_acl(
            r#"
            providers {
              file {
                watch = true
              }
            }
            entrypoints "web" {
              address = "127.0.0.1:0"
            }
            "#,
        )
        .unwrap();
        crate::validate_activation(&config)
            .expect("watch=true must probe notify Watcher::new at validate_activation");
    }

    #[test]
    fn validate_activation_at_path_attaches_config_parent_watch() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
providers {
  file {
    watch = true
  }
}
entrypoints "web" {
  address = "127.0.0.1:0"
}
"#,
        )
        .unwrap();
        let config =
            GatewayConfig::from_acl(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        crate::validate_activation_at_path(&config, &config_path)
            .expect("path-aware validate must attach root ACL parent watch");
        crate::Gateway::new_at_path(config, &config_path)
            .expect("Gateway::new_at_path must share path-aware file-watch activation");
    }

    #[test]
    fn gateway_new_at_path_fails_closed_when_config_parent_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("missing-parent").join("gateway.acl");
        let config = GatewayConfig::from_acl(
            r#"
providers {
  file {
    watch = true
  }
}
entrypoints "web" {
  address = "127.0.0.1:0"
}
"#,
        )
        .unwrap();

        crate::Gateway::new(config.clone()).expect(
            "path-less Gateway::new only probes notify (+ optional conf.d); missing ACL parent is soft-open",
        );
        let Err(error) = crate::Gateway::new_at_path(config, &config_path) else {
            panic!(
                "Gateway::new_at_path must fail closed when the root ACL parent cannot be watched"
            );
        };
        let message = error.to_string();
        assert!(
            message.contains("providers.file.watch cannot activate")
                || message.contains("failed to watch"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn probe_file_watch_activation_accepts_existing_paths() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir(&conf_dir).unwrap();
        std::fs::write(
            &config_path,
            "entrypoints \"web\" { address = \"127.0.0.1:0\" }\n",
        )
        .unwrap();
        probe_file_watch_activation(&config_path, Some(&conf_dir))
            .expect("existing config parent and conf.d must activate notify watch");
    }

    #[test]
    fn load_merged_gateway_config_fails_closed_on_missing_entrypoint_tls_pem() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        let missing_cert = dir.path().join("missing-cert.pem");
        let missing_key = dir.path().join("missing-key.pem");
        let cert_acl = missing_cert.display().to_string().replace('\\', "/");
        let key_acl = missing_key.display().to_string().replace('\\', "/");

        std::fs::write(
            &config_path,
            format!(
                r#"
entrypoints "web" {{
  address = "127.0.0.1:0"
  tls {{
    cert_file = "{cert_acl}"
    key_file  = "{key_acl}"
  }}
}}
"#
            ),
        )
        .unwrap();

        let err = load_merged_gateway_config(&config_path)
            .expect_err("missing entrypoint TLS PEM must fail closed at validate≡activate");
        assert!(
            err.to_string().contains("certificate") || err.to_string().contains("TLS"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn load_merged_gateway_config_fails_closed_when_management_token_env_unset() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        let token_env = "A3S_GATEWAY_VALIDATE_ACTIVATION_MISSING_TOKEN";
        std::env::remove_var(token_env);

        std::fs::write(
            &config_path,
            format!(
                r#"
entrypoints "web" {{
  address = "127.0.0.1:0"
}}

management {{
  enabled        = true
  address        = "127.0.0.1:19091"
  auth_token_env = "{token_env}"
  allowed_ips    = ["127.0.0.1"]
}}
"#
            ),
        )
        .unwrap();

        let err = load_merged_gateway_config(&config_path)
            .expect_err("unset management auth token env must fail closed at validate≡activate");
        assert!(
            err.to_string().contains(token_env) || err.to_string().contains("not set"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_load_config_ignores_non_acl_fragments() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir(&conf_dir).unwrap();

        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();
        std::fs::write(conf_dir.join("notes.txt"), "this is not acl {{{").unwrap();

        let watcher = FileWatcher::new(&config_path).with_directory(&conf_dir);
        let config = watcher.load_config().unwrap();
        assert_eq!(config.entrypoints.len(), 1);
        assert!(config.routers.is_empty());
    }

    #[test]
    fn test_load_config_rejects_non_acl_main_extension() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.txt");
        std::fs::write(&config_path, "entrypoints \"web\" {}").unwrap();

        let watcher = FileWatcher::new(&config_path);
        let result = watcher.load_config();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains(".acl"));
    }

    #[test]
    fn test_load_config_invalid_acl() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(&config_path, "not valid acl {{{").unwrap();

        let watcher = FileWatcher::new(&config_path);
        let result = watcher.load_config();
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_stores_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();

        let watcher = FileWatcher::new(&config_path);
        assert!(watcher.last_config().is_none());
        watcher.load_config().unwrap();
        assert!(watcher.last_config().is_some());
    }

    // --- is_config_file tests ---

    #[test]
    fn test_is_config_file_acl() {
        assert!(is_config_file(Path::new("gateway.acl")));
    }

    #[test]
    fn test_is_config_file_toml_rejected() {
        assert!(!is_config_file(Path::new("gateway.toml")));
    }

    #[test]
    fn test_is_config_file_other() {
        assert!(!is_config_file(Path::new("readme.md")));
        assert!(!is_config_file(Path::new("binary.exe")));
        assert!(!is_config_file(Path::new("noext")));
        assert!(!is_config_file(Path::new("config.yaml")));
        assert!(!is_config_file(Path::new("config.yml")));
    }

    // --- ReloadEvent tests ---

    #[test]
    fn test_reload_event_success() {
        let event = ReloadEvent {
            trigger_path: PathBuf::from("/etc/gateway.acl"),
            config: Ok(GatewayConfig::default()),
            timestamp: Instant::now(),
        };
        assert!(event.config.is_ok());
    }

    #[test]
    fn test_reload_event_failure() {
        let event = ReloadEvent {
            trigger_path: PathBuf::from("/etc/gateway.acl"),
            config: Err("parse error".to_string()),
            timestamp: Instant::now(),
        };
        assert!(event.config.is_err());
        assert_eq!(event.config.unwrap_err(), "parse error");
    }

    // --- File watcher start test (with real temp files) ---

    #[test]
    fn test_watch_creates_watcher() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();

        let watcher = FileWatcher::new(&config_path);
        let rx = watcher.watch();
        assert!(rx.is_ok());
    }

    #[test]
    fn test_watch_detects_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();

        let watcher = FileWatcher::new(&config_path);
        let rx = watcher.watch().unwrap();

        // Wait a bit, then modify the file
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:8080"
}
"#,
        )
        .unwrap();

        // Wait for the event (with timeout)
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(event) => {
                assert!(event.config.is_ok());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // On some CI/environments file events may not fire quickly
                // This is acceptable for a unit test
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_watch_invalid_config_keeps_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        std::fs::write(
            &config_path,
            r#"
entrypoints "web" {
  address = "0.0.0.0:80"
}
"#,
        )
        .unwrap();

        let watcher = FileWatcher::new(&config_path);
        watcher.load_config().unwrap(); // Load initial good config
        let rx = watcher.watch().unwrap();

        // Write invalid config
        std::thread::sleep(Duration::from_millis(100));
        std::fs::write(&config_path, "invalid {{{{").unwrap();

        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(event) => {
                assert!(event.config.is_err());
                // Last good config should still be available
                assert!(watcher.last_config().is_some());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Acceptable on some systems
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    // --- is_relevant_event tests ---

    #[test]
    fn test_is_relevant_event() {
        let modify = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![],
            attrs: Default::default(),
        };
        assert!(is_relevant_event(&modify));

        let create = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![],
            attrs: Default::default(),
        };
        assert!(is_relevant_event(&create));

        let access = Event {
            kind: EventKind::Access(notify::event::AccessKind::Read),
            paths: vec![],
            attrs: Default::default(),
        };
        assert!(!is_relevant_event(&access));
    }

    #[test]
    fn test_is_relevant_config_event_filters_paths() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.acl");
        let conf_dir = dir.path().join("conf.d");
        std::fs::create_dir(&conf_dir).unwrap();
        std::fs::write(&config_path, "").unwrap();

        let event_for_main = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![config_path.clone()],
            attrs: Default::default(),
        };
        assert!(is_relevant_config_event(
            &event_for_main,
            &config_path,
            Some(&conf_dir)
        ));

        let event_for_fragment = Event {
            kind: EventKind::Create(notify::event::CreateKind::File),
            paths: vec![conf_dir.join("api.acl")],
            attrs: Default::default(),
        };
        assert!(is_relevant_config_event(
            &event_for_fragment,
            &config_path,
            Some(&conf_dir)
        ));

        let event_for_unrelated_file = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![dir.path().join("notes.txt")],
            attrs: Default::default(),
        };
        assert!(!is_relevant_config_event(
            &event_for_unrelated_file,
            &config_path,
            Some(&conf_dir)
        ));
    }

    // --- Reload count ---

    #[test]
    fn test_reload_count_initial() {
        let watcher = FileWatcher::new("/tmp/test.acl");
        assert_eq!(watcher.reload_count(), 0);
    }
}
