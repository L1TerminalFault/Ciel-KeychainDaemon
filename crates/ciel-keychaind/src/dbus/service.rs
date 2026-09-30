//! ============================================================================
//! ciel-keychaind - FreeDesktop Secret Service Root Service Interface
//!
//! Implements `org.freedesktop.Secret.Service` mounted at `/org/freedesktop/secrets`.
//! Provides the primary gateway for clients:
//! - Establishing transport encryption (`OpenSession`)
//! - Global item discovery across all keyrings (`SearchItems`)
//! - Unlocking and locking collections/items (`Unlock`, `Lock`)
//! - Bulk secret extraction (`GetSecrets`)
//! - Managing collections and alias mappings (`CreateCollection`, `ReadAlias`, `SetAlias`)
//!
//! ============================================================================

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::config::Config;
use crate::core::keyring::KeyringManager;
use crate::dbus::caller::resolve_caller;
use crate::dbus::collection::CollectionDbus;
use crate::dbus::item::SecretWire;
use crate::dbus::session::{negotiate_session, Session, SessionDbus};

/// Main Secret Service D-Bus object.
pub struct SecretService {
    keyring_manager: Arc<KeyringManager>,
    config: Config,
    sessions: Arc<RwLock<HashMap<OwnedObjectPath, Session>>>,
    session_counter: AtomicU64,
}

impl SecretService {
    /// Creates a new `SecretService` instance.
    pub fn new(keyring_manager: Arc<KeyringManager>, config: Config) -> Self {
        Self {
            keyring_manager,
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            session_counter: AtomicU64::new(1),
        }
    }

    /// Returns a clone of the sessions map for garbage collection.
    pub fn sessions(&self) -> Arc<RwLock<HashMap<OwnedObjectPath, Session>>> {
        Arc::clone(&self.sessions)
    }
}

// impl SecretService {
//     pub fn sessions(&self) -> Arc<RwLock<HashMap<OwnedObjectPath, Session>>> {
//         Arc::clone(&self.sessions)
//     }
// }

#[interface(name = "org.freedesktop.Secret.Service")]
impl SecretService {
    /// Opens a new cryptographic or plain session for transferring secrets.
    async fn open_session(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        algorithm: &str,
        input: Value<'_>,
    ) -> zbus::fdo::Result<(Value<'static>, OwnedObjectPath)> {
        let sender = hdr
            .sender()
            .and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller_name = sender
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".into());

        debug!(
            "OpenSession called with algorithm: '{}' by {}",
            algorithm, caller_name
        );

        let id = self.session_counter.fetch_add(1, Ordering::SeqCst);

        let (session, output_val) = negotiate_session(algorithm, &input, id, caller_name)?;

        let session_path = session.path.clone();

        let session_dbus = SessionDbus::new(session_path.clone(), Arc::clone(&self.sessions));

        connection
            .object_server()
            .at(&session_path, session_dbus)
            .await?;

        {
            let mut map = self.sessions.write().await;
            map.insert(session_path.clone(), session);
        }

        info!(
            "Session opened at '{}' using algorithm '{}'",
            session_path, algorithm
        );

        Ok((output_val, session_path))
    }

    /// Creates a new persistent encrypted collection vault.
    async fn create_collection(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        properties: HashMap<String, Value<'_>>,
        alias: &str,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let sender = hdr
            .sender()
            .and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        info!(
            "CreateCollection requested by {}: alias='{}'",
            caller.display_label(),
            alias
        );

        let (collection_path, prompt_path) = self
            .keyring_manager
            .create_collection(properties, alias, &caller)
            .await?;

        // Register the newly-created collection object.
        let collection_id = collection_path
            .as_str()
            .rsplit('/')
            .next()
            .ok_or_else(|| zbus::fdo::Error::Failed("Invalid collection object path".into()))?
            .to_string();

        let collection_dbus = CollectionDbus::new(
            collection_id.clone(),
            Arc::clone(&self.keyring_manager),
            Arc::clone(&self.sessions),
        );

        connection
            .object_server()
            .at(&collection_path, collection_dbus)
            .await?;

        if !alias.is_empty() {
            let alias_path =
                OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/aliases/{alias}"))
                    .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;

            let alias_collection_dbus = CollectionDbus::new(
                collection_id,
                Arc::clone(&self.keyring_manager),
                Arc::clone(&self.sessions),
            );

            connection
                .object_server()
                .at(&alias_path, alias_collection_dbus)
                .await?;
        }

        if prompt_path.as_str() == "/" {
            Self::collection_created(&emitter, &collection_path).await?;
        }

        Ok((collection_path, prompt_path))
    }

    /// Searches for items matching attributes across all collections.
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        debug!("SearchItems with {} attributes", attributes.len());

        let (unlocked, locked) = self
            .keyring_manager
            .search_items_global(&attributes)
            .await?;

        Ok((unlocked, locked))
    }

    /// Unlocks the specified collection or item objects.
    async fn unlock(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let sender = hdr
            .sender()
            .and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        debug!(
            "Unlock requested for {} objects by {}",
            objects.len(),
            caller.display_label()
        );

        let (unlocked, prompt) = self
            .keyring_manager
            .unlock_objects(objects, &caller)
            .await?;

        Ok((unlocked, prompt))
    }

    /// Locks the specified collection or item objects.
    async fn lock(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let sender = hdr
            .sender()
            .and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        debug!(
            "Lock requested for {} objects by {}",
            objects.len(),
            caller.display_label()
        );

        let (locked, prompt) = self.keyring_manager.lock_objects(objects, &caller).await?;

        Ok((locked, prompt))
    }

    /// Bulk secret retrieval for multiple items encoded for a specific session.
    async fn get_secrets(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> zbus::fdo::Result<HashMap<OwnedObjectPath, SecretWire>> {
        let sender = hdr
            .sender()
            .and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        debug!(
            "GetSecrets requested for {} items by {}",
            items.len(),
            caller.display_label()
        );

        let sessions_guard = self.sessions.read().await;

        let active_session = sessions_guard
            .get(&session)
            .ok_or_else(|| zbus::fdo::Error::Failed("Session not found".into()))?;

        let secrets = self
            .keyring_manager
            .get_multiple_secrets(items, active_session, &caller)
            .await?;

        Ok(secrets)
    }

    /// Reads the object path associated with a well-known collection alias.
    async fn read_alias(&self, name: &str) -> zbus::fdo::Result<OwnedObjectPath> {
        let path = self.keyring_manager.resolve_alias(name).await?;
        Ok(path)
    }

    /// Links a well-known alias name to an existing collection path.
    async fn set_alias(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        name: &str,
        collection: OwnedObjectPath,
    ) -> zbus::fdo::Result<()> {
        let sender = hdr
            .sender()
            .and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        info!(
            "SetAlias '{}' -> '{}' by {}",
            name,
            collection,
            caller.display_label()
        );

        self.keyring_manager
            .set_alias(name, &collection, &caller)
            .await?;

        Ok(())
    }

    /// Signal emitted when a new collection is created.
    #[zbus(signal)]
    pub async fn collection_created(
        emitter: &SignalEmitter<'_>,
        collection: &OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// Signal emitted when a collection is deleted.
    #[zbus(signal)]
    pub async fn collection_deleted(
        emitter: &SignalEmitter<'_>,
        collection: &OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// Signal emitted when collection properties change.
    #[zbus(signal)]
    pub async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: &OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// Property: `Collections` (paths of all existing collections).
    #[zbus(property)]
    async fn collections(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let paths = self.keyring_manager.list_all_collections().await?;

        Ok(paths)
    }
}
