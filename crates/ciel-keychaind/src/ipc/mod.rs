//! ============================================================================
//! ciel-keychaind - Private PAM IPC Subsystem
//!
//! Exposes a private, permission-restricted UNIX domain socket specifically
//! designed for PAM module authentication handoffs (`pam_ciel_keychaind.so`):
//! - Path: `$XDG_RUNTIME_DIR/ciel-keychaind/pam.sock` (mode `0600`).
//! - Security: Strictly validates peer socket credentials via `SO_PEERCRED`
//!   to ensure only root (UID 0) or the session owner's UID may communicate.
//! - Protocol: One-shot structured message passing for login unlocks and password changes.
//!
//! ============================================================================

pub mod server;

pub use server::start_pam_server;
