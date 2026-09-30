//! ============================================================================
//! ciel-keychaind - Internal Event Bus Subsystem
//!
//! Provides a decoupled, asynchronous pub/sub event channel across the daemon.
//! Subsystems (logind monitor, PAM socket listener, D-Bus service, auto-lock
//! timers) publish and subscribe to lifecycle changes without tight coupling.
//! ============================================================================

use tokio::sync::broadcast::{self, Receiver, Sender};
use tracing::debug;

/// Maximum number of buffered daemon events before slow consumers lag.
const EVENT_CHANNEL_CAPACITY: usize = 128;

/// Internal daemon events broadcast across subsystems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonEvent {
    /// An individual collection was unlocked.
    CollectionUnlocked(String),

    /// An individual collection was locked.
    CollectionLocked(String),

    /// Global command to immediately lock all collections and scrub memory.
    LockAllKeyrings,

    /// System is preparing to sleep/suspend (triggered by logind).
    PrepareForSleep,

    /// User session screen was locked (triggered by logind).
    ScreenLocked,

    /// An item was modified or deleted within a collection.
    ItemChanged {
        collection_id: String,
        item_id: String,
    },

    /// Vault ciphertext on disk was modified externally.
    VaultExternallyModified(String),
}

/// Daemon-wide asynchronous event bus.
#[derive(Clone)]
pub struct EventBus {
    sender: Sender<DaemonEvent>,
}

impl EventBus {
    /// Instantiates a new event bus with default buffer capacity.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self { sender }
    }

    /// Broadcasts an event to all active subscribers.
    pub fn publish(&self, event: DaemonEvent) {
        debug!("Publishing daemon event: {:?}", event);
        // Ignore SendError if there are currently no active receivers
        let _ = self.sender.send(event);
    }

    /// Subscribes to daemon events, returning a broadcast `Receiver`.
    pub fn subscribe(&self) -> Receiver<DaemonEvent> {
        self.sender.subscribe()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}
