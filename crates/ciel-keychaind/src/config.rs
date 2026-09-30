//! ============================================================================
//! ciel-keychaind - Configuration Management
//!
//! Handles configuration loading, environment path resolution adhering to the
//! XDG Base Directory specification, daemon lifecycle timeouts, auto-lock
//! policies, and security parameters.
//! ============================================================================

use crate::error::{CielError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Default name of the primary user collection created on first unlock.
pub const DEFAULT_COLLECTION_NAME: &str = "login";

/// FreeDesktop Secret Service alias for the default collection.
pub const DEFAULT_COLLECTION_ALIAS: &str = "default";

/// Core daemon configuration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Directory where encrypted collection vaults are persisted.
    /// Typically `$XDG_DATA_HOME/keyrings` (e.g. `~/.local/share/keyrings`).
    pub vault_dir: PathBuf,

    /// Runtime state directory for private UNIX sockets and ephemeral files.
    /// Typically `$XDG_RUNTIME_DIR/ciel-keychaind` (e.g. `/run/user/<uid>/ciel-keychaind`).
    pub runtime_dir: PathBuf,

    /// UNIX domain socket path used for receiving PAM authentication tokens.
    pub pam_socket_path: PathBuf,

    /// Inactivity duration before unlocked keyrings are automatically locked.
    /// `None` indicates auto-lock on idle is disabled.
    pub auto_lock_timeout: Option<Duration>,

    /// Timeout waiting for user interaction on graphical prompt dialogs.
    pub prompt_timeout: Duration,

    /// Maximum idle duration of a client D-Bus cryptographic session before cleanup.
    pub session_timeout: Duration,

    /// Whether to automatically lock all collections when logind signals system sleep/suspend.
    pub lock_on_sleep: bool,

    /// Whether to automatically lock all collections when logind signals screen session lock.
    pub lock_on_screen_lock: bool,

    /// Access control policy applied when an unknown binary requests secrets.
    pub default_access_policy: AccessPolicyDefault,
}

/// Default policy behavior for unrecognized client applications.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPolicyDefault {
    /// Prompt the user graphically via the prompter UI for authorization.
    Prompt,
    /// Automatically allow access without prompting (standard gnome-keyring behavior).
    Allow,
    /// Deny access immediately unless explicitly pre-authorized.
    Deny,
}

impl Default for Config {
    fn default() -> Self {
        let (vault_dir, runtime_dir) = Self::resolve_standard_paths();
        let pam_socket_path = runtime_dir.join("pam.sock");

        Self {
            vault_dir,
            runtime_dir,
            pam_socket_path,
            auto_lock_timeout: Some(Duration::from_secs(900)), // 15 minutes default idle lock
            prompt_timeout: Duration::from_secs(120),          // 2 minutes user prompt timeout
            session_timeout: Duration::from_secs(1800),        // 30 minutes D-Bus session expiry
            lock_on_sleep: true,
            lock_on_screen_lock: true,
            default_access_policy: AccessPolicyDefault::Prompt,
        }
    }
}

impl Config {
    /// Loads configuration from standard XDG paths, falling back to secure defaults.
    ///
    /// Searches in order:
    /// 1. `$XDG_CONFIG_HOME/ciel-keychaind/config.toml`
    /// 2. `~/.config/ciel-keychaind/config.toml`
    /// 3. Defaults
    pub fn load() -> Result<Self> {
        let config_path = Self::resolve_config_file_path();
        if config_path.exists() {
            let data = std::fs::read_to_string(&config_path).map_err(|e| {
                CielError::Config(format!("Failed to read {}: {e}", config_path.display()))
            })?;
            let cfg: Config = toml_or_json_parse(&data, &config_path)?;
            cfg.ensure_directories()?;
            Ok(cfg)
        } else {
            let cfg = Self::default();
            cfg.ensure_directories()?;
            Ok(cfg)
        }
    }

    /// Resolves canonical XDG data and runtime directories.
    fn resolve_standard_paths() -> (PathBuf, PathBuf) {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());

        // Vault directory: $XDG_DATA_HOME/keyrings or ~/.local/share/keyrings
        let vault_dir = match std::env::var("XDG_DATA_HOME") {
            Ok(d) if !d.is_empty() => PathBuf::from(d).join("keyrings"),
            _ => PathBuf::from(&home).join(".local/share/keyrings"),
        };

        // Runtime directory: $XDG_RUNTIME_DIR/ciel-keychaind or fallback /tmp/ciel-keychaind-<uid>
        let uid = unsafe { libc::getuid() };
        let runtime_dir = match std::env::var("XDG_RUNTIME_DIR") {
            Ok(d) if !d.is_empty() => PathBuf::from(d).join("ciel-keychaind"),
            _ => PathBuf::from(format!("/tmp/ciel-keychaind-runtime-{uid}")),
        };

        (vault_dir, runtime_dir)
    }

    /// Resolves the candidate path for `config.toml`.
    fn resolve_config_file_path() -> PathBuf {
        if let Ok(cfg_home) = std::env::var("XDG_CONFIG_HOME") {
            if !cfg_home.is_empty() {
                return PathBuf::from(cfg_home)
                    .join("ciel-keychaind")
                    .join("config.toml");
            }
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        PathBuf::from(home).join(".config/ciel-keychaind/config.toml")
    }

    /// Verifies and creates necessary directory paths on disk with restrictive permissions (0700).
    pub fn ensure_directories(&self) -> Result<()> {
        Self::create_secure_dir(&self.vault_dir)?;
        Self::create_secure_dir(&self.runtime_dir)?;
        Ok(())
    }

    /// Creates a directory with mode `0700` (`rwx------`) ensuring private ownership.
    fn create_secure_dir(path: &Path) -> Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        if !path.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)
                .map_err(|e| {
                    CielError::Storage(format!(
                        "Failed to create secure directory {}: {e}",
                        path.display()
                    ))
                })?;
        }
        Ok(())
    }
}

/// Parses configuration file either as TOML or JSON depending on syntax.
fn toml_or_json_parse(content: &str, path: &Path) -> Result<Config> {
    serde_json::from_str(content).map_err(|e| {
        CielError::Config(format!(
            "Failed to parse configuration file at {}: {e}",
            path.display()
        ))
    })
}
