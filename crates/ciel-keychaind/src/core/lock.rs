//! ============================================================================
//! ciel-keychaind - Lock State & Inactivity Auto-Lock Coordination
//!
//! Manages the lock lifecycle of collections and items:
//! - Tracks state transitions (Locked <-> Unlocked).
//! - Records access activity timestamps.
//! - Runs an asynchronous inactivity watchdog that automatically relocks vaults
//!   when idle beyond the configured threshold (`auto_lock_timeout`).
//! ============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::core::events::{DaemonEvent, EventBus};

/// The lock state of an individual collection vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// The collection is locked; secrets are encrypted and inaccessible.
    Locked,
    /// The collection is unlocked; decryption keys are in memory.
    Unlocked {
        /// Time when the collection was initially unlocked.
        unlocked_at: Instant,
        /// Time when the collection was last queried or updated.
        last_activity: Instant,
    },
}

impl LockState {
    pub fn is_locked(&self) -> bool {
        matches!(self, LockState::Locked)
    }
}

/// Central manager tracking collection lock states and inactivity timers.
pub struct LockManager {
    states: Arc<RwLock<HashMap<String, LockState>>>,
    auto_lock_timeout: Option<Duration>,
    event_bus: EventBus,
}

impl LockManager {
    /// Creates a new LockManager instance.
    pub fn new(auto_lock_timeout: Option<Duration>, event_bus: EventBus) -> Self {
        let manager = Self {
            states: Arc::new(RwLock::new(HashMap::new())),
            auto_lock_timeout,
            event_bus,
        };

        if let Some(timeout) = auto_lock_timeout {
            manager.spawn_watchdog(timeout);
        }

        manager
    }

    /// Returns `true` if the specified collection is locked or unknown.
    pub async fn is_locked(&self, collection_id: &str) -> bool {
        let guard = self.states.read().await;
        match guard.get(collection_id) {
            Some(state) => state.is_locked(),
            None => true, // Unknown collections default to locked
        }
    }

    /// Marks a collection as unlocked and records current timestamp as activity.
    pub async fn unlock(&self, collection_id: &str) {
        let mut guard = self.states.write().await;
        let now = Instant::now();
        guard.insert(
            collection_id.to_string(),
            LockState::Unlocked {
                unlocked_at: now,
                last_activity: now,
            },
        );
        info!("Collection '{}' transitioned to UNLOCKED", collection_id);
        self.event_bus
            .publish(DaemonEvent::CollectionUnlocked(collection_id.to_string()));
    }

    /// Transitions a collection to the locked state.
    pub async fn lock(&self, collection_id: &str) {
        let mut guard = self.states.write().await;
        guard.insert(collection_id.to_string(), LockState::Locked);
        info!("Collection '{}' transitioned to LOCKED", collection_id);
        self.event_bus
            .publish(DaemonEvent::CollectionLocked(collection_id.to_string()));
    }

    /// Immediately transitions all managed collections to the locked state.
    pub async fn lock_all(&self) {
        let mut guard = self.states.write().await;
        for (id, state) in guard.iter_mut() {
            if !state.is_locked() {
                *state = LockState::Locked;
                info!("Collection '{}' relocked by global lock", id);
                self.event_bus
                    .publish(DaemonEvent::CollectionLocked(id.clone()));
            }
        }
        self.event_bus.publish(DaemonEvent::LockAllKeyrings);
    }

    /// Updates the last activity timestamp for an unlocked collection to prevent premature idle lock.
    pub async fn touch_activity(&self, collection_id: &str) {
        let mut guard = self.states.write().await;
        if let Some(LockState::Unlocked {
            ref mut last_activity,
            ..
        }) = guard.get_mut(collection_id)
        {
            *last_activity = Instant::now();
            debug!("Touched activity for collection '{}'", collection_id);
        }
    }

pub async fn register_unlocked(&self, collection_id: &str) {
    let mut guard = self.states.write().await;

    if !guard.contains_key(collection_id) {
        let now = Instant::now();
        guard.insert(
            collection_id.to_string(),
            LockState::Unlocked {
                unlocked_at: now,
                last_activity: now,
            },
        );
    }
}

    /// Spawns the background inactivity timer task.
    fn spawn_watchdog(&self, timeout: Duration) {
        let states = Arc::clone(&self.states);
        let event_bus = self.event_bus.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(15));
            loop {
                interval.tick().await;
                let now = Instant::now();
                let mut to_lock = Vec::new();

                {
                    let mut guard = states.write().await;
                    for (id, state) in guard.iter_mut() {
                        if let LockState::Unlocked { last_activity, .. } = state {
                            if now.duration_since(*last_activity) >= timeout {
                                *state = LockState::Locked;
                                to_lock.push(id.clone());
                            }
                        }
                    }
                }

                for id in to_lock {
                    info!(
                        "Collection '{}' locked due to inactivity timeout ({:?})",
                        id, timeout
                    );
                    event_bus.publish(DaemonEvent::CollectionLocked(id));
                }
            }
        });
    }
}
