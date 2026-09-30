//! ============================================================================
//! ciel-keychaind - FreeDesktop Secret Service Item Interface
//!
//! Implements `org.freedesktop.Secret.Item` representing an individual stored
//! credential record, containing attributes, labels, timestamps, and the
//! encrypted secret payload itself.
//! ============================================================================

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::debug;
use zbus::interface;
use zbus::zvariant::{OwnedObjectPath, Type};

use crate::core::keyring::KeyringManager;
use crate::dbus::caller::resolve_caller;

use tokio::sync::RwLock;

use crate::dbus::session::Session;

/// The Secret Service wire representation of a secret payload.
///
/// Transferred across D-Bus as `(oayays)`:
/// 1. `session`: Object path of the session used to encode the secret.
/// 2. `parameters`: Algorithm-specific encryption parameters.
/// 3. `value`: Encrypted (or plain) secret bytes.
/// 4. `content_type`: MIME type of the secret.
#[derive(Debug, Clone, Serialize, Deserialize, Type)]
pub struct SecretWire {
    /// The session used to encrypt this secret.
    pub session: OwnedObjectPath,

    /// Parameters such as initialization vector (IV).
    pub parameters: Vec<u8>,

    /// The secret value itself.
    pub value: Vec<u8>,

    /// Content type of the value.
    pub content_type: String,
}

/// D-Bus interface `org.freedesktop.Secret.Item`.
pub struct ItemDbus {
    collection_id: String,
    item_id: String,
    keyring_manager: Arc<KeyringManager>,
    sessions_map: Arc<RwLock<HashMap<OwnedObjectPath, Session>>>,
}
// pub struct ItemDbus {
//     collection_id: String,
//     item_id: String,
//     keyring_manager: Arc<KeyringManager>,
// }

impl ItemDbus {
pub fn new(
    collection_id: String,
    item_id: String,
    keyring_manager: Arc<KeyringManager>,
    sessions_map: Arc<RwLock<HashMap<OwnedObjectPath, Session>>>,
) -> Self {
    Self {
        collection_id,
        item_id,
        keyring_manager,
        sessions_map,
    }
}
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ItemDbus {
    /// Deletes this item from its parent collection.
    ///
    /// Returns `/` if deleted immediately without requiring a prompt.
    async fn delete(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let sender = hdr.sender();

        let sender = sender.and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        debug!(
            "Delete item requested by caller: {:?}",
            caller.display_label()
        );

        self.keyring_manager
            .delete_item(&self.collection_id, &self.item_id, &caller)
            .await?;

        Ok(OwnedObjectPath::try_from("/").unwrap())
    }

    /// Retrieves the secret value for this item, encrypted with the specified session.
    async fn get_secret(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        session: OwnedObjectPath,
    ) -> zbus::fdo::Result<(SecretWire,)> {
        let sender = hdr.sender();

        let sender = sender.and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        debug!(
            "GetSecret requested for item {} by {}",
            self.item_id,
            caller.display_label()
        );

let secret_wire = self
    .keyring_manager
    .get_item_secret(&self.collection_id, &self.item_id, &session, &caller)
    .await?;

let sessions = self.sessions_map.read().await;

let session_obj = sessions
    .get(&session)
    .ok_or_else(|| zbus::fdo::Error::Failed("Unknown session".into()))?;

let (parameters, value) = session_obj.encrypt(&secret_wire.value)?;

let result = SecretWire {
    session,
    parameters,
    value,
    content_type: secret_wire.content_type,
};

Ok((result,))
        // let secret_wire = self
        //     .keyring_manager
        //     .get_item_secret(&self.collection_id, &self.item_id, &session, &caller)
        //     .await?;
        //
        // Ok((secret_wire,))
    }

    /// Sets the secret value of this item.
    async fn set_secret(
        &self,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        secret: SecretWire,
    ) -> zbus::fdo::Result<()> {
        let sender = hdr.sender();

        let sender = sender.and_then(|s| zbus::names::BusName::try_from(s.as_str()).ok());

        let caller = resolve_caller(connection, sender.as_ref()).await?;

        debug!(
            "SetSecret requested for item {} by {}",
            self.item_id,
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

        self.keyring_manager
            .set_item_secret(&self.collection_id, &self.item_id, secret, &caller)
            .await?;

        Ok(())
    }

    /// Property: `Locked`.
    #[zbus(property)]
    async fn locked(&self) -> zbus::fdo::Result<bool> {
        let is_locked = self
            .keyring_manager
            .is_collection_locked(&self.collection_id)
            .await;

        Ok(is_locked)
    }

    /// Property: `Attributes`.
    #[zbus(property)]
    async fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>> {
        let attrs = self
            .keyring_manager
            .get_item_attributes(&self.collection_id, &self.item_id)
            .await?;

        Ok(attrs)
    }

    /// Property: `Attributes` setter.
    #[zbus(property)]
    async fn set_attributes(&self, attributes: HashMap<String, String>) -> zbus::fdo::Result<()> {
        self.keyring_manager
            .set_item_attributes(&self.collection_id, &self.item_id, attributes)
            .await?;

        Ok(())
    }

    /// Property: `Label`.
    #[zbus(property)]
    async fn label(&self) -> zbus::fdo::Result<String> {
        let label = self
            .keyring_manager
            .get_item_label(&self.collection_id, &self.item_id)
            .await?;

        Ok(label)
    }

    /// Property: `Label` setter.
    #[zbus(property)]
    async fn set_label(&self, label: String) -> zbus::fdo::Result<()> {
        self.keyring_manager
            .set_item_label(&self.collection_id, &self.item_id, label)
            .await?;

        Ok(())
    }

    /// Property: `Created`.
    #[zbus(property)]
    async fn created(&self) -> zbus::fdo::Result<u64> {
        let created = self
            .keyring_manager
            .get_item_created(&self.collection_id, &self.item_id)
            .await?;

        Ok(created)
    }

    /// Property: `Modified`.
    #[zbus(property)]
    async fn modified(&self) -> zbus::fdo::Result<u64> {
        let modified = self
            .keyring_manager
            .get_item_modified(&self.collection_id, &self.item_id)
            .await?;

        Ok(modified)
    }
}
