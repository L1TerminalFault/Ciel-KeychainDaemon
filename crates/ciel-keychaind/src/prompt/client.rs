//! ============================================================================
//! ciel-keychaind - Prompter D-Bus Client Implementation
//!
//! Invokes remote UI dialogs on `ciel-keychaind-prompter`:
//! - Requests passphrase prompts to unlock keyrings.
//! - Queries user authorization when untrusted applications request access.
//! - Uses zeroized strings for received passphrases.
//! ============================================================================

use std::time::Duration;
use tracing::{info, warn};
use zbus::Connection;
use zeroize::Zeroizing;

use crate::core::policy::AccessDecision;
use crate::error::{Result, CielError};

/// D-Bus service name for the GUI prompter companion daemon.
pub const PROMPTER_SERVICE_NAME: &str = "org.freedesktop.secrets.Prompter";

/// D-Bus object path for the GUI prompter.
pub const PROMPTER_OBJECT_PATH: &str = "/org/freedesktop/secrets/prompter";

/// Client used by the daemon to request interactive dialogs from the prompter.
#[derive(Clone)]
pub struct PrompterClient {
    prompt_timeout: Duration,
}

impl PrompterClient {
    /// Creates a new prompter client with configured timeout.
    pub fn new(prompt_timeout: Duration) -> Self {
        Self { prompt_timeout }
    }

    /// Requests the user to enter a passphrase to unlock a specific collection.
    pub async fn prompt_unlock(
        &self,
        connection: &Connection,
        collection_label: &str,
        window_id: &str,
    ) -> Result<Zeroizing<String>> {
        info!("Requesting prompter unlock dialog for '{}'", collection_label);

        let reply: std::result::Result<(bool, String), zbus::Error> = connection
            .call_method(
                Some(PROMPTER_SERVICE_NAME),
                PROMPTER_OBJECT_PATH,
                Some("org.freedesktop.secrets.Prompter"),
                "PromptUnlock",
                &(collection_label, window_id),
            )
            .await
            .and_then(|r| r.body().deserialize());

        match reply {
            Ok((true, password)) => Ok(Zeroizing::new(password)),
            Ok((false, _)) => Err(CielError::PromptDismissed),
            Err(e) => {
                warn!("Prompter service unavailable or timed out: {e}");
                Err(CielError::PromptDismissed)
            }
        }
    }

    /// Requests user authorization when an unrecognized application accesses secrets.
    pub async fn prompt_authorize(
        &self,
        connection: &Connection,
        app_label: &str,
        binary_path: &str,
        window_id: &str,
    ) -> Result<AccessDecision> {
        info!("Requesting authorization dialog for app: '{}' ({})", app_label, binary_path);

        let reply: std::result::Result<u32, zbus::Error> = connection
            .call_method(
                Some(PROMPTER_SERVICE_NAME),
                PROMPTER_OBJECT_PATH,
                Some("org.freedesktop.secrets.Prompter"),
                "PromptAuthorize",
                &(app_label, binary_path, window_id),
            )
            .await
            .and_then(|r| r.body().deserialize());

        match reply {
            Ok(0) => Ok(AccessDecision::Deny),
            Ok(1) => Ok(AccessDecision::AllowOnce),
            Ok(2) => Ok(AccessDecision::Allow),
            _ => Err(CielError::PromptDismissed),
        }
    }
}
