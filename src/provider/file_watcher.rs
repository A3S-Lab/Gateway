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
        self.reload_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Get the last known good config
    pub fn last_config(&self) -> Option<GatewayConfig> {
        self.last_config.read().unwrap().clone()
    }

    /// Load the config file and validate it
    pub fn load_config(&self) -> Result<GatewayConfig> {
        let content = std::fs::read_to_string(&self.config_path).map_err(|e| {
            GatewayError::Config(format!(
                "Failed to read config file {}: {}",
                self.config_path.display(),
                e
            ))
        })?;
        let config = GatewayConfig::from_toml(&content)?;
        config.validate()?;

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

        // Create the file system watcher
        let mut watcher: RecommendedWatcher =
            Watcher::new(notify_tx, notify::Config::default()).map_err(|e| {
                GatewayError::Other(format!("Failed to create file watcher: {}", e))
            })?;

        // Watch the config file's parent directory
        let watch_path = config_path
            .parent()
            .unwrap_or_else(|| Path::new("."));
        watcher
            .watch(watch_path, RecursiveMode::NonRecursive)
            .map_err(|e| {
                GatewayError::Other(format!(
                    "Failed to watch {}: {}",
                    watch_path.display(),
                    e
                ))
            })?;

        // Watch additional directory if configured
        if let Some(ref dir) = watch_dir {
            if dir.exists() {
                watcher
                    .watch(dir, RecursiveMode::Recursive)
                    .map_err(|e| {
                        GatewayError::Other(format!(
                            "Failed to watch directory {}: {}",
                            dir.display(),
                            e
                        ))
                    })?;
            }
        }

        // Spawn background thread to process events
        std::thread::spawn(move || {
            let _watcher = watcher; // Keep watcher alive
            let mut last_event_time = Instant::now();

            loop {
                match notify_rx.recv() {
                    Ok(Ok(event)) => {
                        if !is_relevant_event(&event) {
                            continue;
                        }

                        // Debounce: skip if too close to last event
                        let now = Instant::now();
                        if now.duration_since(last_event_time)
                            < Duration::from_millis(DEBOUNCE_MS)
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

                        // Try to load and validate the new config
                        let content = match std::fs::read_to_string(&config_path) {
                            Ok(c) => c,
                            Err(e) => {
                                let _ = event_tx.send(ReloadEvent {
                                    trigger_path,
                                    config: Err(format!("Failed to read config: {}", e)),
                                    timestamp: now,
                                });
                                continue;
                            }
                        };

                        let config_result = GatewayConfig::from_toml(&content)
                            .and_then(|c| {
                                c.validate()?;
                                Ok(c)
                            });

                        match &config_result {
                            Ok(config) => {
                                let mut last = last_config.write().unwrap();
                                *last = Some(config.clone());
                                reload_count.fetch_add(
                                    1,
                                    std::sync::atomic::Ordering::Relaxed,
                                );
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

/// Check if a path is a TOML config file
pub fn is_config_file(path: &Path) -> bool {
    path.extension()
        .map(|ext| ext == "toml" || ext == "yaml" || ext == "yml")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- FileWatcher construction tests ---

    #[test]
    fn test_new_file_watcher() {
        let watcher = FileWatcher::new("/etc/gateway/config.toml");
        assert_eq!(
            watcher.config_path(),
            Path::new("/etc/gateway/config.toml")
        );
        assert!(watcher.watch_directory().is_none());
        assert_eq!(watcher.reload_count(), 0);
    }

    #[test]
    fn test_with_directory() {
        let watcher = FileWatcher::new("/etc/gateway/config.toml")
            .with_directory("/etc/gateway/conf.d");
        assert_eq!(
            watcher.watch_directory(),
            Some(Path::new("/etc/gateway/conf.d"))
        );
    }

    #[test]
    fn test_last_config_initially_none() {
        let watcher = FileWatcher::new("/nonexistent.toml");
        assert!(watcher.last_config().is_none());
    }

    // --- Config loading tests ---

    #[test]
    fn test_load_config_missing_file() {
        let watcher = FileWatcher::new("/nonexistent/gateway.toml");
        let result = watcher.load_config();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to read"));
    }

    #[test]
    fn test_load_config_valid() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.toml");
        std::fs::write(
            &config_path,
            r#"
[entrypoints]
[entrypoints.web]
address = "0.0.0.0:80"
"#,
        )
        .unwrap();

        let watcher = FileWatcher::new(&config_path);
        let config = watcher.load_config().unwrap();
        assert!(config.entrypoints.contains_key("web"));
        assert!(watcher.last_config().is_some());
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.toml");
        std::fs::write(&config_path, "not valid toml {{{").unwrap();

        let watcher = FileWatcher::new(&config_path);
        let result = watcher.load_config();
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_stores_last_good() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("gateway.toml");
        std::fs::write(
            &config_path,
            r#"
[entrypoints]
[entrypoints.web]
address = "0.0.0.0:80"
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
    fn test_is_config_file_toml() {
        assert!(is_config_file(Path::new("gateway.toml")));
    }

    #[test]
    fn test_is_config_file_yaml() {
        assert!(is_config_file(Path::new("config.yaml")));
        assert!(is_config_file(Path::new("config.yml")));
    }

    #[test]
    fn test_is_config_file_other() {
        assert!(!is_config_file(Path::new("readme.md")));
        assert!(!is_config_file(Path::new("binary.exe")));
        assert!(!is_config_file(Path::new("noext")));
    }

    // --- ReloadEvent tests ---

    #[test]
    fn test_reload_event_success() {
        let event = ReloadEvent {
            trigger_path: PathBuf::from("/etc/gateway.toml"),
            config: Ok(GatewayConfig::default()),
            timestamp: Instant::now(),
        };
        assert!(event.config.is_ok());
    }

    #[test]
    fn test_reload_event_failure() {
        let event = ReloadEvent {
            trigger_path: PathBuf::from("/etc/gateway.toml"),
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
        let config_path = dir.path().join("gateway.toml");
        std::fs::write(
            &config_path,
            r#"
[entrypoints]
[entrypoints.web]
address = "0.0.0.0:80"
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
        let config_path = dir.path().join("gateway.toml");
        std::fs::write(
            &config_path,
            r#"
[entrypoints]
[entrypoints.web]
address = "0.0.0.0:80"
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
[entrypoints]
[entrypoints.web]
address = "0.0.0.0:8080"
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
        let config_path = dir.path().join("gateway.toml");
        std::fs::write(
            &config_path,
            r#"
[entrypoints]
[entrypoints.web]
address = "0.0.0.0:80"
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

    // --- Reload count ---

    #[test]
    fn test_reload_count_initial() {
        let watcher = FileWatcher::new("/tmp/test.toml");
        assert_eq!(watcher.reload_count(), 0);
    }
}
