//! ============================================================================
//! ciel-keychaind - GUI Prompter Client Subsystem
//!
//! Bridges the daemon with the independent `secretd-prompter` UI process:
//! - Dispatches graphical modal dialogs for passphrase unlocks.
//! - Prompts user when unknown applications request access to secrets.
//! - Connects via session D-Bus interface `org.freedesktop.secrets.Prompter`.
//!
//! ============================================================================

pub mod client;

pub use client::PrompterClient;
