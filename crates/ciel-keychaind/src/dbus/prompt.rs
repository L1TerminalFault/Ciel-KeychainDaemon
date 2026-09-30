//! ============================================================================
//! ciel-keychaind - FreeDesktop Secret Service Prompt Object
//!
//! Implements `org.freedesktop.Secret.Prompt` representing asynchronous user
//! confirmation requests (e.g. passphrase entry to unlock vaults, or prompting
//! whether an untrusted application should be permitted access to secrets).
//!
//! Lifecycle:
//! 1. Created dynamically when an action (Unlock, CreateCollection) requires user consent.
//! 2. Client calls `Prompt(window_id)` to display the dialog.
//! 3. Propt asynchronously queries the prompter UI.
//! 4. Propt emits `Completed(dismissed, result)` signal with the outcome.
//! ============================================================================

use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::{debug, info};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, Value};

use crate::error::Result;

/// Prompt completion callback closure type.
pub type PromptHandler = Box<
    dyn FnOnce(
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Value<'static>>> + Send>,
        > + Send,
>;

/// D-Bus interface `org.freedesktop.Secret.Prompt`.
pub struct PromptDbus {
    prompt_path: ObjectPath<'static>,
    handler: Arc<Mutex<Option<PromptHandler>>>,
}

impl PromptDbus {
    /// Creates a new Prompt D-Bus object.
    pub fn new(prompt_path: ObjectPath<'static>, handler: PromptHandler) -> Self {
        Self {
            prompt_path,
            handler: Arc::new(Mutex::new(Some(handler))),
        }
    }

    /// Path to this prompt instance.
    pub fn path(&self) -> &ObjectPath<'static> {
        &self.prompt_path
    }
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptDbus {
    /// Performs the prompt action, requesting the prompter to present UI attached
    /// to the given caller `window_id` (e.g., X11 window id or Wayland surface handle).
    async fn prompt(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        window_id: &str,
    ) -> zbus::fdo::Result<()> {
        info!(
            "Executing Prompt at '{}' for window: '{}'",
            self.prompt_path, window_id
        );

        let handler = {
            let mut guard = self.handler.lock().await;
            guard.take()
        };

        if let Some(f) = handler {
            let result = f(window_id.to_string()).await;

            match result {
                Ok(val) => {
                    // Completed signal: dismissed = false, result = value
                    Self::completed(&emitter, false, &val).await?;
                }
                Err(e) => {
                    debug!("Prompt dismissed or cancelled: {e}");

                    // Completed signal: dismissed = true, result = empty
                    Self::completed(&emitter, true, &Value::from("")).await?;
                }
            }
        } else {
            // Already prompted or dismissed
            Self::completed(&emitter, true, &Value::from("")).await?;
        }

        Ok(())
    }

    /// Dismisses the prompt without performing the action.
    async fn dismiss(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        info!("Dismissing prompt at '{}'", self.prompt_path);

        {
            let mut guard = self.handler.lock().await;
            let _ = guard.take();
        }

        Self::completed(&emitter, true, &Value::from("")).await?;

        Ok(())
    }

    /// Signal emitted when the prompt completes or is dismissed by the user.
    #[zbus(signal)]
    pub async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: &Value<'_>,
    ) -> zbus::Result<()>;
}
