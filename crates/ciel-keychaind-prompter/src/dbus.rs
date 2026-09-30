//! ============================================================================
//! ciel-keychaind-prompter - D-Bus Prompter Mediator Interface
//!
//! Exposes the `org.freedesktop.secrets.Prompter` interface over the session bus.
//! Acts as a pure D-Bus mediator without embedded UI toolkits:
//! - When `ciel-keychaind` requests a prompt, this service emits D-Bus signals
//!   (`UnlockPromptRequested`, `AuthorizePromptRequested`).
//! - External desktop UI engines (GNOME Shell, KDE, custom UI apps) listen
//!   for these signals, display the appropriate modal dialogs, and submit
//!   responses back via D-Bus method calls (`SubmitUnlock`, `SubmitAuthorize`).
//! ============================================================================

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{oneshot, RwLock};
use zbus::{interface, object_server::SignalEmitter};
use zeroize::Zeroizing;

/// Active pending prompt response channels.
type PendingUnlockMap = Arc<RwLock<HashMap<u64, oneshot::Sender<(bool, Zeroizing<String>)>>>>;
type PendingAuthMap = Arc<RwLock<HashMap<u64, oneshot::Sender<u32>>>>;

/// D-Bus interface handler for `org.freedesktop.secrets.Prompter`.
pub struct PrompterService {
    prompt_counter: AtomicU64,
    pending_unlocks: PendingUnlockMap,
    pending_auths: PendingAuthMap,
}

impl PrompterService {
    pub fn new() -> Self {
        Self {
            prompt_counter: AtomicU64::new(1),
            pending_unlocks: Arc::new(RwLock::new(HashMap::new())),
            pending_auths: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for PrompterService {
    fn default() -> Self {
        Self::new()
    }
}

#[interface(name = "org.freedesktop.secrets.Prompter")]
impl PrompterService {
    // ------------------------------------------------------------------------
    // Methods invoked by ciel-keychaind daemon
    // ------------------------------------------------------------------------

    /// Called by `ciel-keychaind` to request an interactive unlock passphrase dialog.
    /// Emits `UnlockPromptRequested` signal to notify external UI engines.
    async fn prompt_unlock(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        collection_label: &str,
        window_id: &str,
    ) -> zbus::fdo::Result<(bool, String)> {
        let prompt_id = self.prompt_counter.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        {
            let mut map = self.pending_unlocks.write().await;
            map.insert(prompt_id, tx);
        }

        // Emit signal for external UI engine
        Self::unlock_prompt_requested(&emitter, prompt_id, collection_label, window_id).await?;

        // Await external UI engine response
        match rx.await {
            Ok((success, pass)) => Ok((success, pass.to_string())),
            Err(_) => Ok((false, String::new())),
        }
    }

    /// Called by `ciel-keychaind` to request interactive application authorization.
    /// Emits `AuthorizePromptRequested` signal to notify external UI engines.
    async fn prompt_authorize(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        app_label: &str,
        binary_path: &str,
        window_id: &str,
    ) -> zbus::fdo::Result<u32> {
        let prompt_id = self.prompt_counter.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();

        {
            let mut map = self.pending_auths.write().await;
            map.insert(prompt_id, tx);
        }

        // Emit signal for external UI engine
        Self::authorize_prompt_requested(&emitter, prompt_id, app_label, binary_path, window_id)
            .await?;

        // Await external UI engine response
        match rx.await {
            Ok(decision) => Ok(decision),
            Err(_) => Ok(0), // Default to Deny
        }
    }

    // ------------------------------------------------------------------------
    // Signals received by external UI engine
    // ------------------------------------------------------------------------

    /// Signal emitted when an unlock prompt must be rendered by the UI engine.
    #[zbus(signal)]
    pub async fn unlock_prompt_requested(
        emitter: &SignalEmitter<'_>,
        prompt_id: u64,
        collection_label: &str,
        window_id: &str,
    ) -> zbus::Result<()>;

    /// Signal emitted when an application authorization dialog must be rendered by the UI engine.
    #[zbus(signal)]
    pub async fn authorize_prompt_requested(
        emitter: &SignalEmitter<'_>,
        prompt_id: u64,
        app_label: &str,
        binary_path: &str,
        window_id: &str,
    ) -> zbus::Result<()>;

    // ------------------------------------------------------------------------
    // Methods invoked by external UI engine to return user responses
    // ------------------------------------------------------------------------

    /// Called by external UI engine after user enters a passphrase or cancels.
    async fn submit_unlock(
        &self,
        prompt_id: u64,
        success: bool,
        passphrase: String,
    ) -> zbus::fdo::Result<()> {
        let mut map = self.pending_unlocks.write().await;
        if let Some(tx) = map.remove(&prompt_id) {
            let _ = tx.send((success, Zeroizing::new(passphrase)));
        }
        Ok(())
    }

    /// Called by external UI engine after user chooses an authorization decision.
    async fn submit_authorize(&self, prompt_id: u64, decision: u32) -> zbus::fdo::Result<()> {
        let mut map = self.pending_auths.write().await;
        if let Some(tx) = map.remove(&prompt_id) {
            let _ = tx.send(decision);
        }
        Ok(())
    }
}
