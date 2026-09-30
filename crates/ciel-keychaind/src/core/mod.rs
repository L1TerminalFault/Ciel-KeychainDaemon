//! ============================================================================
//! ciel-keychaind - Core Domain & Business Logic Architecture
//!
//! Encapsulates pure business logic independent of D-Bus protocols or direct
//! disk I/O, maintaining strong architectural separation:
//!
//! Submodules:
//! - `keyring`: In-memory collections and items, alias resolutions, vault lifetime.
//! - `lock`: Lock/unlock state machine and inactivity auto-lock timers.
//! - `policy`: Per-application permission rules and authorization decisions.
//! - `search`: FreeDesktop attribute pattern matching and filtering engine.
//! - `events`: Internal event bus for lock, sleep, session change, and sync broadcasts.
//!
//! ============================================================================

pub mod events;
pub mod keyring;
pub mod lock;
pub mod policy;
pub mod search;

pub use events::{DaemonEvent, EventBus};
pub use keyring::KeyringManager;
pub use lock::LockManager;
pub use policy::{AccessDecision, PolicyEngine};
pub use search::AttributeFilter;
