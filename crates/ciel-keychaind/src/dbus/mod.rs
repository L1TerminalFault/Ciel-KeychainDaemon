//! ============================================================================
//! ciel-keychaind - FreeDesktop Secret Service D-Bus Implementation
//!
//! Exposes the standard `org.freedesktop.secrets` bus hierarchy using `zbus`:
//! - `/org/freedesktop/secrets`: Root service interface (`org.freedesktop.Secret.Service`)
//! - `/org/freedesktop/secrets/collection/*`: Collection interface (`org.freedesktop.Secret.Collection`)
//! - `/org/freedesktop/secrets/collection/*/*`: Item interface (`org.freedesktop.Secret.Item`)
//! - `/org/freedesktop/secrets/session/*`: Session interface (`org.freedesktop.Secret.Session`)
//! - `/org/freedesktop/secrets/prompt/*`: Prompt interface (`org.freedesktop.Secret.Prompt`)
//! ============================================================================

pub mod caller;
pub mod collection;
pub mod item;
pub mod prompt;
pub mod service;
pub mod session;

use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{info, warn};
use zbus::connection::Builder;

use crate::config::Config;
use crate::core::keyring::KeyringManager;
use crate::dbus::service::SecretService;
use crate::error::{CielError, Result};

/// The primary well-known bus name specified by FreeDesktop Secret Service.
pub const SECRET_SERVICE_BUS_NAME: &str = "org.freedesktop.secrets";

/// Standard object path for the root Secret Service.
pub const SECRET_SERVICE_OBJECT_PATH: &str = "/org/freedesktop/secrets";

/// Prefix for all dynamically allocated collection object paths.
pub const COLLECTION_PATH_PREFIX: &str = "/org/freedesktop/secrets/collection";

/// Prefix for all dynamically created cryptographic session object paths.
pub const SESSION_PATH_PREFIX: &str = "/org/freedesktop/secrets/session";

/// Prefix for all interactive user confirmation prompt object paths.
pub const PROMPT_PATH_PREFIX: &str = "/org/freedesktop/secrets/prompt";

/// Prefix for standard collection alias symlinks (e.g. `/org/freedesktop/secrets/aliases/default`).
pub const ALIASES_PATH_PREFIX: &str = "/org/freedesktop/secrets/aliases";

/// Initializes the D-Bus connection, mounts the root Secret Service interface,
/// requests the `org.freedesktop.secrets` bus name, and returns a runner task handle.
pub async fn init_dbus_service(
    keyring_manager: Arc<KeyringManager>,
    config: &Config,
) -> Result<JoinHandle<Result<()>>> {
    info!("Initializing D-Bus connection to session bus...");
    let service = SecretService::new(Arc::clone(&keyring_manager), config.clone());

    // Get the shared sessions map to pass to collections/items
    let sessions = service.sessions();

    let sessions_for_gc = service.sessions();

    // Build session bus connection and register the primary service object
    let connection = Builder::session()?
        .name(SECRET_SERVICE_BUS_NAME)?
        .serve_at(SECRET_SERVICE_OBJECT_PATH, service)?
        .build()
        .await?;

    info!("Acquired D-Bus bus name '{}'", SECRET_SERVICE_BUS_NAME);

    // ============================================================
    // FIX: Register the default collection and its alias on D-Bus
    // ============================================================
    let collection_dbus = crate::dbus::collection::CollectionDbus::new(
        crate::config::DEFAULT_COLLECTION_NAME.to_string(),
        Arc::clone(&keyring_manager),
        Arc::clone(&sessions),
    );

    let collection_path = zbus::zvariant::OwnedObjectPath::try_from(format!(
        "{}/{}",
        COLLECTION_PATH_PREFIX,
        crate::config::DEFAULT_COLLECTION_NAME
    ))
    .map_err(|e| crate::error::CielError::Config(e.to_string()))?;

    connection
        .object_server()
        .at(&collection_path, collection_dbus)
        .await?;

    let alias_path = zbus::zvariant::OwnedObjectPath::try_from(format!(
        "{}/{}",
        ALIASES_PATH_PREFIX,
        crate::config::DEFAULT_COLLECTION_ALIAS
    ))
    .map_err(|e| crate::error::CielError::Config(e.to_string()))?;

    let alias_dbus = crate::dbus::collection::CollectionDbus::new(
        crate::config::DEFAULT_COLLECTION_NAME.to_string(),
        Arc::clone(&keyring_manager),
        Arc::clone(&sessions),
    );
    connection
        .object_server()
        .at(&alias_path, alias_dbus)
        .await?;

    info!(
        "Registered default collection '{}' and alias '{}'",
        crate::config::DEFAULT_COLLECTION_NAME,
        crate::config::DEFAULT_COLLECTION_ALIAS
    );

    // Spawn an event loop task to monitor connection health
    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            if connection.is_closed() {
                warn!("Session D-Bus connection closed by broker");
                return Err(CielError::Dbus(zbus::Error::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "Session D-Bus disconnected",
                ))));
            }
        }
    });

    // Session Garbage Collection (Phase 2)
    // let sessions_for_gc = service.sessions();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300)); // 5 minutes
        loop {
            interval.tick().await;
            let mut map = sessions_for_gc.write().await;
            let now = std::time::Instant::now();
            map.retain(|path, session| {
                let keep =
                    now.duration_since(session.last_accessed) < std::time::Duration::from_secs(600); // 10 min TTL
                if !keep {
                    info!("Garbage collecting expired session: {}", path);
                }
                keep
            });
        }
    });

    // FIX: Ensure we actually return the handle wrapped in Ok()
    Ok(handle)
}
