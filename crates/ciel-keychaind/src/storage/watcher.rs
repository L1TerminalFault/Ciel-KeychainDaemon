//! ============================================================================
//! ciel-keychaind - Vault Storage Watcher
//!
//! Monitors the vault storage directory (`$XDG_DATA_HOME/keyrings`) for external
//! modifications, updates, or deletions executed by external tools:
//! - Tracks filesystem modification timestamps (`mtime`) on keyring files.
//! - Emits [`DaemonEvent::VaultExternallyModified`] when on-disk changes occur.
//!
//! ============================================================================

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::task::JoinHandle;
use tracing::debug;

use crate::core::events::{DaemonEvent, EventBus};

/// Filesystem monitor watching for vault updates.
pub struct VaultWatcher {
    vault_dir: PathBuf,
    event_bus: EventBus,
    poll_interval: Duration,
}

impl VaultWatcher {
    /// Instantiates a new watcher for the target directory.
    pub fn new(vault_dir: PathBuf, event_bus: EventBus) -> Self {
        Self {
            vault_dir,
            event_bus,
            poll_interval: Duration::from_secs(5),
        }
    }

    /// Spawns the background monitoring loop.
    pub fn spawn(self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut known_mtimes: HashMap<PathBuf, SystemTime> = HashMap::new();
            let mut interval = tokio::time::interval(self.poll_interval);

            loop {
                interval.tick().await;

                if !self.vault_dir.exists() {
                    continue;
                }

                let entries = match std::fs::read_dir(&self.vault_dir) {
                    Ok(rd) => rd,
                    Err(_) => continue,
                };

                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|s| s.to_str()) == Some("keyring") {
                        if let Ok(metadata) = entry.metadata() {
                            if let Ok(mtime) = metadata.modified() {
                                if let Some(&prev_time) = known_mtimes.get(&path) {
                                    if mtime > prev_time {
                                        debug!("External modification detected on {:?}", path);
                                        known_mtimes.insert(path.clone(), mtime);
                                        if let Some(stem) =
                                            path.file_stem().and_then(|s| s.to_str())
                                        {
                                            self.event_bus.publish(
                                                DaemonEvent::VaultExternallyModified(
                                                    stem.to_string(),
                                                ),
                                            );
                                        }
                                    }
                                } else {
                                    known_mtimes.insert(path, mtime);
                                }
                            }
                        }
                    }
                }
            }
        })
    }
}
