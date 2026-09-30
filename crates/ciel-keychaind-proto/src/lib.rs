//! ============================================================================
//! ciel-keychaind-proto - Shared Protocol & IPC Wire Types
//!
//! Minimal shared crate defining:
//! - PAM <-> daemon IPC wire messages (`pam_ciel_keychaind.so` to `ciel-keychaind`).
//! - D-Bus interface and method constants for the GUI prompter companion.
//! - Access control decision representations.
//! - Zeroizing password containers.
//!
//! ============================================================================

use serde::{Deserialize, Serialize};
// use zeroize::{Zeroize, Zeroizing};

/// Standard UNIX socket filename used for PAM communication.
pub const PAM_SOCKET_FILENAME: &str = "pam.sock";

/// Well-known bus name reserved for the UI prompter front-end.
pub const PROMPTER_BUS_NAME: &str = "org.freedesktop.secrets.Prompter";

/// Object path where the prompter interface is mounted.
pub const PROMPTER_OBJECT_PATH: &str = "/org/freedesktop/secrets/prompter";

/// Interface name exposed by the prompter.
pub const PROMPTER_INTERFACE: &str = "org.freedesktop.secrets.Prompter";

/// Messages sent from the PAM module (`pam_ciel_keychaind.so`) to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PamMessage {
    /// Command to unlock a specific keyring (default: "login").
    Unlock {
        collection_id: String,
        password: Vec<u8>,
    },
    /// Notification that the user changed their login password.
    ChangePassword {
        username: String,
        old_password: Vec<u8>,
        new_password: Vec<u8>,
    },
}

impl PamMessage {
    /// Serializes the PAM message into length-prefixed binary wire format.
    pub fn encode(&self) -> Vec<u8> {
        let payload = match self {
            PamMessage::Unlock {
                collection_id,
                password,
            } => {
                let mut buf = Vec::with_capacity(1 + collection_id.len() + 1 + password.len());
                buf.push(1u8); // Opcode 1: Unlock
                buf.extend_from_slice(collection_id.as_bytes());
                buf.push(0u8); // Null delimiter
                buf.extend_from_slice(password);
                buf
            }
            PamMessage::ChangePassword {
                username,
                old_password,
                new_password,
            } => {
                let mut buf = Vec::new();
                buf.push(2u8); // Opcode 2: ChangePassword
                buf.extend_from_slice(username.as_bytes());
                buf.push(0u8);
                buf.extend_from_slice(old_password);
                buf.push(0u8);
                buf.extend_from_slice(new_password);
                buf
            }
        };

        let len = (payload.len() as u32).to_be_bytes();
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&len);
        out.extend_from_slice(&payload);
        out
    }
}

/// Access authorization choices returned by interactive prompts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum PromptDecision {
    /// Explicitly deny access.
    Deny = 0,
    /// Permit access for this single invocation only.
    AllowOnce = 1,
    /// Permanently remember authorization for this application binary.
    AllowAlways = 2,
}
