//! ============================================================================
//! ciel-keychaind - Persistent Vault Storage Architecture
//!
//! Manages durable, encrypted disk persistence for keyrings and items:
//! - `format`: On-disk header parsing, Argon2 parameter descriptors, binary framing.
//! - `vault`: Atomic write strategies (write-to-temp + rename + parent dir fsync),
//!   safe reads, and serialization.
//! - `watcher`: Optional inotify-based file system watcher for detecting external changes.
//!
//! ============================================================================

pub mod format;
pub mod vault;
pub mod watcher;

pub use format::{StoredItem, VaultHeader, VaultPayload, VAULT_FORMAT_VERSION, VAULT_MAGIC};
pub use vault::VaultStorage;
pub use watcher::VaultWatcher;
