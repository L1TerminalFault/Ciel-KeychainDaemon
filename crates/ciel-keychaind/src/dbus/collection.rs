//! ============================================================================
//! ciel-keychaind - FreeDesktop Secret Service Collection Interface
//!
//! Implements `org.freedesktop.Secret.Collection` representing a named vault
//! collection (e.g. "login", "default") containing items, managing item creation,
//! search queries, and lifecycle signals (`ItemCreated`, `ItemDeleted`, `ItemChanged`).
//! ============================================================================

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info};
use zbus::interface;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{OwnedObjectPath, Value};

use crate::core::keyring::KeyringManager;
use crate::dbus::caller::resolve_caller;
use crate::dbus::item::SecretWire;

use tokio::sync::RwLock;

use crate::dbus::session::Session;

/// D-Bus interface `org.freedesktop.Secret.Collection`.
pub struct CollectionDbus {
    collection_id: String,
    keyring_manager: Arc<KeyringManager>,
    sessions_map: Arc<RwLock<HashMap<OwnedObjectPath, Session>>>,
}

impl CollectionDbus {
    pub fn new(
        collection_id: String,
        keyring_manager: Arc<KeyringManager>,
        sessions_map: Arc<RwLock<HashMap<OwnedObjectPath, Session>>>,
    ) -> Self {
        Self {
            collection_id,
            keyring_manager,
            sessions_map,
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionDbus {
    /// Deletes this collection and all contained items.
    ///
    /// Returns `/` if deleted immediately without requiring a prompt.
    async fn delete(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let sender = hdr
            .sender()
            .and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        info!(
            "Delete collection '{}' requested by {}",
            self.collection_id,
            caller.display_label()
        );

        self.keyring_manager
            .delete_collection(&self.collection_id, &caller)
            .await?;

        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    /// Searches for items within this collection matching the specified
    /// attribute map.
    async fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let matches = self
            .keyring_manager
            .search_items_in_collection(&self.collection_id, &attributes)
            .await?;

        Ok(matches)
    }

    /// Creates a new item within this collection.
    ///
    /// Parameters:
    /// - `properties`: Initial item properties.
    /// - `secret`: Secret value and session payload.
    /// - `replace`: Whether to replace an existing item matching the same
    ///   attributes.
    ///
    /// Returns `(item_path, prompt_path)`: `prompt_path` is `/` if created
    /// immediately.
    async fn create_item(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        properties: HashMap<String, Value<'_>>,
        secret: SecretWire,
        replace: bool,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let sender = hdr
            .sender()
            .and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        debug!(
            "CreateItem in '{}' by {}",
            self.collection_id,
            caller.display_label()
        );

        let sessions = self.sessions_map.read().await;

        let session_obj = sessions
            .get(&secret.session)
            .ok_or_else(|| zbus::fdo::Error::Failed("Unknown session".into()))?;

        let plaintext = session_obj.decrypt(&secret.parameters, &secret.value)?;

        let secret = SecretWire {
            session: secret.session.clone(),
            parameters: Vec::new(),
            value: plaintext.to_vec(),
            content_type: secret.content_type,
        };

        drop(sessions);

        let (item_path, prompt_path) = self
            .keyring_manager
            .create_item(&self.collection_id, properties, secret, replace, &caller)
            .await?;

        let item_id = item_path
            .as_str()
            .rsplit('/')
            .next()
            .ok_or_else(|| zbus::fdo::Error::Failed("Invalid item object path".into()))?
            .to_string();

        let item_dbus = crate::dbus::item::ItemDbus::new(
            self.collection_id.clone(),
            item_id,
            Arc::clone(&self.keyring_manager),
            Arc::clone(&self.sessions_map),
        );

        connection.object_server().at(&item_path, item_dbus).await?;

        if prompt_path.as_str() == "/" {
            Self::item_created(&emitter, &item_path).await?;
        }

        Ok((item_path, prompt_path))
    }

    /// Signal emitted when a new item is created within this collection.
    #[zbus(signal)]
    pub async fn item_created(
        emitter: &SignalEmitter<'_>,
        item: &OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// Signal emitted when an item in this collection is deleted.
    #[zbus(signal)]
    pub async fn item_deleted(
        emitter: &SignalEmitter<'_>,
        item: &OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// Signal emitted when an item in this collection changes.
    #[zbus(signal)]
    pub async fn item_changed(
        emitter: &SignalEmitter<'_>,
        item: &OwnedObjectPath,
    ) -> zbus::Result<()>;

    /// Property: `Items` (object paths of all items contained in this
    /// collection).
    #[zbus(property)]
    async fn items(&self) -> zbus::fdo::Result<Vec<OwnedObjectPath>> {
        let paths = self.keyring_manager.list_items(&self.collection_id).await?;

        Ok(paths)
    }

    /// Property: `Label` (display name of this collection).
    #[zbus(property)]
    async fn label(&self) -> zbus::fdo::Result<String> {
        let label = self
            .keyring_manager
            .get_collection_label(&self.collection_id)
            .await?;

        Ok(label)
    }

    /// Property: `Label` setter.
    #[zbus(property)]
    async fn set_label(&self, label: String) -> zbus::fdo::Result<()> {
        self.keyring_manager
            .set_collection_label(&self.collection_id, label)
            .await?;

        Ok(())
    }

    /// Property: `Locked` (whether this collection is currently locked).
    #[zbus(property)]
    async fn locked(&self) -> zbus::fdo::Result<bool> {
        let is_locked = self
            .keyring_manager
            .is_collection_locked(&self.collection_id)
            .await;

        Ok(is_locked)
    }

    /// Property: `Created` (UNIX epoch timestamp in seconds).
    #[zbus(property)]
    async fn created(&self) -> zbus::fdo::Result<u64> {
        let created = self
            .keyring_manager
            .get_collection_created(&self.collection_id)
            .await?;

        Ok(created)
    }

    /// Property: `Modified` (UNIX epoch timestamp in seconds).
    #[zbus(property)]
    async fn modified(&self) -> zbus::fdo::Result<u64> {
        let modified = self
            .keyring_manager
            .get_collection_modified(&self.collection_id)
            .await?;

        Ok(modified)
    }
}
