//! ============================================================================
//! ciel-keychaind - Error Handling Architecture
//!
//! Defines a unified crate-wide error type representing all failure modes
//! across cryptographic operations, storage I/O, IPC messaging, access
//! policies, and FreeDesktop Secret Service D-Bus specification errors.
//! ============================================================================

use zbus::DBusError;

/// Crate-wide Result type alias using [`CielError`].
pub type Result<T> = std::result::Result<T, CielError>;

/// Unified error type for the `ciel-keychaind` daemon.
///
/// Encapsulates domain-specific errors and maps directly into standard
/// FreeDesktop Secret Service D-Bus errors (`org.freedesktop.Secret.Error.*`)
/// or standard system D-Bus errors.
#[derive(Debug, thiserror::Error)]
pub enum CielError {
    /// The requested collection or item is currently locked.
    /// Maps to D-Bus `org.freedesktop.Secret.Error.IsLocked`.
    #[error("Object is locked: {0}")]
    IsLocked(String),

    /// The session specified by the caller does not exist or has expired.
    /// Maps to D-Bus `org.freedesktop.Secret.Error.NoSession`.
    #[error("No such session: {0}")]
    NoSession(String),

    /// The requested object path does not reference any known collection or item.
    /// Maps to D-Bus `org.freedesktop.Secret.Error.NoSuchObject`.
    #[error("No such object: {0}")]
    NoSuchObject(String),

    /// A collection or item with the given identifier or alias already exists.
    /// Maps to D-Bus `org.freedesktop.Secret.Error.AlreadyExists`.
    #[error("Object already exists: {0}")]
    AlreadyExists(String),

    /// The secret provided is malformed, uses an unsupported algorithm, or cannot be decrypted.
    /// Maps to D-Bus `org.freedesktop.Secret.Error.InvalidSecret`.
    #[error("Invalid secret parameter: {0}")]
    InvalidSecret(String),

    /// Access was denied by security policy or rejected by the user in a prompt.
    #[error("Access denied by policy: {0}")]
    PolicyDenied(String),

    /// The prompt dialog was dismissed or cancelled by the user.
    #[error("Operation cancelled by user")]
    PromptDismissed,

    /// Cryptographic operation failed (e.g., MAC verification, KDF derivation, DH exchange).
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Storage encoding, decoding, or disk integrity failure.
    #[error("Vault storage error: {0}")]
    Storage(String),

    /// Standard I/O error occurred during file or socket operations.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal D-Bus messaging or serialization error.
    #[error("D-Bus transport error: {0}")]
    Dbus(#[from] zbus::Error),

    /// PAM or IPC communication failure.
    #[error("IPC communication error: {0}")]
    Ipc(String),

    /// Process hardening failure (e.g., mlock, prctl, seccomp).
    #[error("Security hardening failed: {0}")]
    Hardening(String),

    /// Configuration validation or parsing error.
    #[error("Configuration error: {0}")]
    Config(String),
}

/// D-Bus error mapping compliant with the FreeDesktop Secret Service specification.
#[derive(Debug, DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum SecretServiceDbusError {
    #[zbus(error)]
    ZBus(zbus::Error),

    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
    AlreadyExists(String),
    InvalidSecret(String),
    Failed(String),
}

impl From<zbus::names::Error> for CielError {
    fn from(err: zbus::names::Error) -> Self {
        CielError::PolicyDenied(format!("Invalid D-Bus bus name: {err}"))
    }
}

impl From<CielError> for zbus::fdo::Error {
    fn from(err: CielError) -> Self {
        match err {
            CielError::IsLocked(msg) => {
                zbus::fdo::Error::Failed(format!("org.freedesktop.Secret.Error.IsLocked: {msg}"))
            }
            CielError::NoSession(msg) => {
                zbus::fdo::Error::Failed(format!("org.freedesktop.Secret.Error.NoSession: {msg}"))
            }
            CielError::NoSuchObject(msg) => zbus::fdo::Error::UnknownObject(msg),
            CielError::AlreadyExists(msg) => zbus::fdo::Error::Failed(format!(
                "org.freedesktop.Secret.Error.AlreadyExists: {msg}"
            )),
            CielError::InvalidSecret(msg) => zbus::fdo::Error::InvalidArgs(msg),
            CielError::PolicyDenied(msg) => zbus::fdo::Error::AccessDenied(msg),
            CielError::PromptDismissed => {
                zbus::fdo::Error::Failed("Operation cancelled by user".to_string())
            }
            CielError::Dbus(e) => zbus::fdo::Error::Failed(e.to_string()),
            other => zbus::fdo::Error::Failed(other.to_string()),
        }
    }
}
