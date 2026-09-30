use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;
use tracing::{error, info, warn};
use zbus::zvariant::{OwnedObjectPath, Value};
use zeroize::Zeroizing;

use crate::config::{Config, DEFAULT_COLLECTION_ALIAS, DEFAULT_COLLECTION_NAME};
use crate::core::events::EventBus;
use crate::core::lock::LockManager;
use crate::core::policy::{AccessDecision, PolicyEngine};
use crate::core::search::matches_attributes;
use crate::crypto::kdf::{derive_master_key, KdfParams};
use crate::dbus::caller::CallerIdentity;
use crate::dbus::item::SecretWire;
use crate::dbus::session::Session;
use crate::error::{CielError, Result};
use crate::storage::{StoredItem, VaultPayload, VaultStorage};

/// Current UNIX timestamp in seconds.
fn current_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// In-memory representation of an individual stored item.
#[derive(Debug, Clone)]
pub struct ItemData {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Zeroizing<Vec<u8>>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

/// In-memory representation of a collection vault.
pub struct CollectionData {
    pub id: String,
    pub label: String,
    pub created: u64,
    pub modified: u64,
    pub items: HashMap<String, ItemData>,
    /// Cached 256-bit AEAD key. Present only while the collection is unlocked.
    pub master_key: Option<Zeroizing<[u8; 32]>>,
    /// KDF parameters (including salt) that `master_key` was derived with.
    /// Must be written back unchanged on every persist.
    pub kdf_params: Option<KdfParams>,
}

/// Central orchestrator managing keyrings, items, aliases, and lifecycle operations.
pub struct KeyringManager {
    config: Config,
    collections: Arc<RwLock<HashMap<String, CollectionData>>>,
    aliases: Arc<RwLock<HashMap<String, String>>>,
    lock_manager: Arc<LockManager>,
    policy_engine: Arc<PolicyEngine>,
    event_bus: EventBus,
    item_counter: AtomicU64,
    vault_storage: Arc<VaultStorage>,
}

impl KeyringManager {
    /// Initializes a new KeyringManager with vault persistence.
    pub async fn new(config: Config, vault_storage: Arc<VaultStorage>) -> Result<Self> {
        let event_bus = EventBus::new();
        let lock_manager = Arc::new(LockManager::new(
            config.auto_lock_timeout,
            event_bus.clone(),
        ));
        let policy_engine = Arc::new(PolicyEngine::new(config.default_access_policy));
        let mut initial_aliases = HashMap::new();
        initial_aliases.insert(
            DEFAULT_COLLECTION_ALIAS.to_string(),
            DEFAULT_COLLECTION_NAME.to_string(),
        );

        let manager = Self {
            config,
            collections: Arc::new(RwLock::new(HashMap::new())),
            aliases: Arc::new(RwLock::new(initial_aliases)),
            lock_manager,
            policy_engine,
            event_bus,
            item_counter: AtomicU64::new(1),
            vault_storage,
        };

        // Do NOT auto-create the default vault with a dummy passphrase.
        // That sealed the file with a password the PAM emulator never sent, and
        // every later persist then rewrote the Argon2 salt, bricking unlock.
        // The vault is created on the first successful `unlock_with_passphrase`.
        let vault_path = manager
            .vault_storage
            .vault_file_path(DEFAULT_COLLECTION_NAME);
        if vault_path.exists() {
            info!(
                "Found existing default vault at {} (locked until PAM unlock)",
                vault_path.display()
            );
        } else {
            info!(
                "No default vault yet; it will be created on first PAM unlock at {}",
                vault_path.display()
            );
        }

        Ok(manager)
    }

    /// Access the internal lock manager.
    pub fn lock_manager(&self) -> &Arc<LockManager> {
        &self.lock_manager
    }

    /// Access the internal policy engine.
    pub fn policy_engine(&self) -> &Arc<PolicyEngine> {
        &self.policy_engine
    }

    /// Returns `true` if the specified collection is locked.
    pub async fn is_collection_locked(&self, collection_id: &str) -> bool {
        self.lock_manager.is_locked(collection_id).await
    }

    /// Creates a new collection given properties and an optional alias.
    pub async fn create_collection(
        &self,
        properties: HashMap<String, Value<'_>>,
        alias: &str,
        _caller: &CallerIdentity,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        let label = properties
            .get("org.freedesktop.Secret.Collection.Label")
            .and_then(|v| match v {
                Value::Str(s) => Some(s.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "New Collection".to_string());

        let collection_id = label.to_lowercase().replace(' ', "_");
        let now = current_timestamp_secs();

        {
            let mut cols = self.collections.write().await;
            if cols.contains_key(&collection_id) {
                return Err(CielError::AlreadyExists(format!(
                    "Collection '{collection_id}' already exists"
                )));
            }

            cols.insert(
                collection_id.clone(),
                CollectionData {
                    id: collection_id.clone(),
                    label,
                    created: now,
                    modified: now,
                    items: HashMap::new(),
                    master_key: None,
                    kdf_params: None,
                },
            );
        }

        self.lock_manager.register_unlocked(&collection_id).await;

        if !alias.is_empty() {
            let mut aliases = self.aliases.write().await;
            aliases.insert(alias.to_string(), collection_id.clone());
        }

        let collection_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/collection/{collection_id}"
        ))
        .map_err(|e| CielError::Config(e.to_string()))?;
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();

        self.persist_collection(&collection_id).await?;

        Ok((collection_path, prompt_path))
    }

    /// Deletes a collection and purges all contained items.
    pub async fn delete_collection(
        &self,
        collection_id: &str,
        _caller: &CallerIdentity,
    ) -> Result<()> {
        self.vault_storage.delete_vault(collection_id)?;

        let mut cols = self.collections.write().await;
        if cols.remove(collection_id).is_none() {
            return Err(CielError::NoSuchObject(format!(
                "No collection '{collection_id}'"
            )));
        }

        self.lock_manager.lock(collection_id).await;
        Ok(())
    }

    /// Lists all known collections.
    pub async fn list_all_collections(&self) -> Result<Vec<OwnedObjectPath>> {
        let cols = self.collections.read().await;
        let mut paths = Vec::with_capacity(cols.len());
        for id in cols.keys() {
            if let Ok(p) =
                OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{id}"))
            {
                paths.push(p);
            }
        }
        Ok(paths)
    }

    /// Lists all item object paths in a collection.
    pub async fn list_items(&self, collection_id: &str) -> Result<Vec<OwnedObjectPath>> {
        let cols = self.collections.read().await;
        let col = cols
            .get(collection_id)
            .ok_or_else(|| CielError::NoSuchObject(format!("No collection '{collection_id}'")))?;

        let mut paths = Vec::with_capacity(col.items.len());
        for item_id in col.items.keys() {
            if let Ok(p) = OwnedObjectPath::try_from(format!(
                "/org/freedesktop/secrets/collection/{collection_id}/{item_id}"
            )) {
                paths.push(p);
            }
        }
        Ok(paths)
    }

    /// Creates a new secret item inside a collection.
    pub async fn create_item(
        &self,
        collection_id: &str,
        properties: HashMap<String, Value<'_>>,
        secret_wire: SecretWire,
        replace: bool,
        _caller: &CallerIdentity,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath)> {
        if self.is_collection_locked(collection_id).await {
            return Err(CielError::IsLocked(format!(
                "Collection '{collection_id}' is locked"
            )));
        }

        let label = properties
            .get("org.freedesktop.Secret.Item.Label")
            .and_then(|v| match v {
                Value::Str(s) => Some(s.to_string()),
                _ => None,
            })
            .unwrap_or_else(|| "New Secret".to_string());

        let mut attributes = HashMap::new();
        if let Some(Value::Dict(dict)) = properties.get("org.freedesktop.Secret.Item.Attributes") {
            for (k, v) in dict.iter() {
                if let (Value::Str(ks), Value::Str(vs)) = (k, v) {
                    attributes.insert(ks.to_string(), vs.to_string());
                }
            }
        }

        let item_id = format!("i{}", self.item_counter.fetch_add(1, Ordering::SeqCst));
        let now = current_timestamp_secs();

        let item_data = ItemData {
            id: item_id.clone(),
            label,
            attributes,
            secret: Zeroizing::new(secret_wire.value),
            content_type: secret_wire.content_type,
            created: now,
            modified: now,
        };

        {
            let mut cols = self.collections.write().await;
            let col = cols.get_mut(collection_id).ok_or_else(|| {
                CielError::NoSuchObject(format!("No collection '{collection_id}'"))
            })?;

            if replace {
                col.items
                    .retain(|_, it| !matches_attributes(&item_data.attributes, &it.attributes));
            }

            col.items.insert(item_id.clone(), item_data);
            col.modified = now;
        }

        self.lock_manager.touch_activity(collection_id).await;
        let item_path = OwnedObjectPath::try_from(format!(
            "/org/freedesktop/secrets/collection/{collection_id}/{item_id}"
        ))
        .map_err(|e| CielError::Config(e.to_string()))?;
        let prompt_path = OwnedObjectPath::try_from("/").unwrap();

        self.persist_collection(collection_id).await?;

        Ok((item_path, prompt_path))
    }

    /// Deletes an item from a collection.
    pub async fn delete_item(
        &self,
        collection_id: &str,
        item_id: &str,
        _caller: &CallerIdentity,
    ) -> Result<()> {
        if self.is_collection_locked(collection_id).await {
            return Err(CielError::IsLocked(format!(
                "Collection '{collection_id}' is locked"
            )));
        }

        {
            let mut cols = self.collections.write().await;
            let col = cols.get_mut(collection_id).ok_or_else(|| {
                CielError::NoSuchObject(format!("No collection '{collection_id}'"))
            })?;

            if col.items.remove(item_id).is_none() {
                return Err(CielError::NoSuchObject(format!(
                    "No item '{item_id}' in '{collection_id}'"
                )));
            }

            col.modified = current_timestamp_secs();
        }

        self.persist_collection(collection_id).await?;

        Ok(())
    }

    /// Reads and encrypts an item's secret for the caller's session.
    pub async fn get_item_secret(
        &self,
        collection_id: &str,
        item_id: &str,
        session_path: &OwnedObjectPath,
        caller: &CallerIdentity,
    ) -> Result<SecretWire> {
        if self.is_collection_locked(collection_id).await {
            return Err(CielError::IsLocked(format!(
                "Collection '{collection_id}' is locked"
            )));
        }

        let decision = self.policy_engine.evaluate_access(caller).await;
        if decision == AccessDecision::Deny {
            return Err(CielError::PolicyDenied(format!(
                "Access denied to caller {:?}",
                caller.display_label()
            )));
        }

        let cols = self.collections.read().await;
        let col = cols
            .get(collection_id)
            .ok_or_else(|| CielError::NoSuchObject(format!("No collection '{collection_id}'")))?;

        let item = col
            .items
            .get(item_id)
            .ok_or_else(|| CielError::NoSuchObject(format!("No item '{item_id}'")))?;

        self.lock_manager.touch_activity(collection_id).await;

        Ok(SecretWire {
            session: session_path.clone(),
            parameters: Vec::new(),
            value: item.secret.to_vec(),
            content_type: item.content_type.clone(),
        })
    }

    /// Updates an item's secret value.
    pub async fn set_item_secret(
        &self,
        collection_id: &str,
        item_id: &str,
        secret_wire: SecretWire,
        _caller: &CallerIdentity,
    ) -> Result<()> {
        if self.is_collection_locked(collection_id).await {
            return Err(CielError::IsLocked(format!(
                "Collection '{collection_id}' is locked"
            )));
        }

        {
            let mut cols = self.collections.write().await;
            let col = cols.get_mut(collection_id).ok_or_else(|| {
                CielError::NoSuchObject(format!("No collection '{collection_id}'"))
            })?;

            let item = col
                .items
                .get_mut(item_id)
                .ok_or_else(|| CielError::NoSuchObject(format!("No item '{item_id}'")))?;

            item.secret = Zeroizing::new(secret_wire.value);
            item.content_type = secret_wire.content_type;
            item.modified = current_timestamp_secs();
        }

        self.lock_manager.touch_activity(collection_id).await;
        self.persist_collection(collection_id).await?;

        Ok(())
    }

    /// Performs attribute search within a single collection.
    pub async fn search_items_in_collection(
        &self,
        collection_id: &str,
        attributes: &HashMap<String, String>,
    ) -> Result<Vec<OwnedObjectPath>> {
        let cols = self.collections.read().await;
        let col = cols
            .get(collection_id)
            .ok_or_else(|| CielError::NoSuchObject(format!("No collection '{collection_id}'")))?;

        let mut results = Vec::new();
        for (item_id, item) in &col.items {
            if matches_attributes(attributes, &item.attributes) {
                if let Ok(p) = OwnedObjectPath::try_from(format!(
                    "/org/freedesktop/secrets/collection/{collection_id}/{item_id}"
                )) {
                    results.push(p);
                }
            }
        }

        Ok(results)
    }

    /// Performs global attribute search across all collections, returning unlocked and locked items.
    pub async fn search_items_global(
        &self,
        attributes: &HashMap<String, String>,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let cols = self.collections.read().await;
        let mut unlocked = Vec::new();
        let mut locked = Vec::new();

        for (col_id, col) in cols.iter() {
            let is_locked = self.lock_manager.is_locked(col_id).await;
            for (item_id, item) in &col.items {
                if matches_attributes(attributes, &item.attributes) {
                    if let Ok(path) = OwnedObjectPath::try_from(format!(
                        "/org/freedesktop/secrets/collection/{col_id}/{item_id}"
                    )) {
                        if is_locked {
                            locked.push(path);
                        } else {
                            unlocked.push(path);
                        }
                    }
                }
            }
        }

        Ok((unlocked, locked))
    }

    /// Unlocks objects (collections or items).
    pub async fn unlock_objects(
        &self,
        objects: Vec<OwnedObjectPath>,
        _caller: &CallerIdentity,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let mut unlocked = Vec::new();
        let mut needs_prompt = false;
        let mut prompt_col_id = String::new();

        for obj in objects {
            let path_str = obj.as_str();
            if let Some(col_id) = path_str.strip_prefix("/org/freedesktop/secrets/collection/") {
                let actual_col_id = col_id.split('/').next().unwrap_or(col_id);

                let in_memory = {
                    let cols = self.collections.read().await;
                    cols.get(actual_col_id)
                        .is_some_and(|c| c.master_key.is_some())
                };

                // Presence in the HashMap is not enough: a locked collection stays
                // in memory with secrets zeroized and no master key.
                if in_memory && !self.lock_manager.is_locked(actual_col_id).await {
                    unlocked.push(obj.clone());
                } else {
                    needs_prompt = true;
                    prompt_col_id = actual_col_id.to_string();
                }
            }
        }

        if needs_prompt {
            warn!(
                "Collection '{}' is locked and requires a passphrase (PAM or GUI prompter).",
                prompt_col_id
            );
            let prompt_path =
                OwnedObjectPath::try_from("/org/freedesktop/secrets/prompt/p1").unwrap();
            return Ok((unlocked, prompt_path));
        }

        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((unlocked, prompt_path))
    }

    /// Locks objects (collections or items).
    pub async fn lock_objects(
        &self,
        objects: Vec<OwnedObjectPath>,
        _caller: &CallerIdentity,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        let mut locked = Vec::new();

        for obj in objects {
            let path_str = obj.as_str();
            if let Some(col_id) = path_str.strip_prefix("/org/freedesktop/secrets/collection/") {
                let actual_col_id = col_id.split('/').next().unwrap_or(col_id);
                self.lock_collection(actual_col_id).await?;
                if let Ok(p) = OwnedObjectPath::try_from(path_str) {
                    locked.push(p);
                }
            }
        }

        let prompt_path = OwnedObjectPath::try_from("/").unwrap();
        Ok((locked, prompt_path))
    }

    /// Locks all collections immediately.
    pub async fn lock_all(&self) {
        let cols = self.collections.read().await;
        let ids: Vec<String> = cols.keys().cloned().collect();
        drop(cols);
        for id in ids {
            let _ = self.lock_collection(&id).await;
        }
    }

    /// Unlocks a collection directly with a raw passphrase (invoked by PAM module).
    ///
    /// If the vault file does not exist, a new empty vault is created using this
    /// passphrase. The KDF salt generated at creation is cached and reused on
    /// every subsequent persist so the header always matches the master key.
    pub async fn unlock_with_passphrase(
        &self,
        collection_id: &str,
        passphrase: &[u8],
    ) -> Result<()> {
        info!(
            "unlock_with_passphrase for collection '{}' (passphrase {} bytes)",
            collection_id,
            passphrase.len()
        );

        let path = self.vault_storage.vault_file_path(collection_id);
        let (payload, master_key, kdf_params) = if path.exists() {
            info!("Loading existing vault from {}", path.display());
            match self
                .vault_storage
                .load_vault_with_passphrase(collection_id, passphrase)
            {
                Ok(v) => v,
                Err(e) => {
                    error!(
                        "Failed to decrypt vault '{}': {e}. Wrong passphrase, or the file was written with a mismatched KDF salt.",
                        collection_id
                    );
                    return Err(e);
                }
            }
        } else {
            info!("Vault file does not exist — creating a new empty vault");
            let kdf_params = KdfParams::generate();
            let master_key = derive_master_key(passphrase, &kdf_params)?;

            let now = current_timestamp_secs();
            let new_payload = VaultPayload {
                collection_id: collection_id.to_string(),
                label: if collection_id == DEFAULT_COLLECTION_NAME {
                    "Login Keyring".to_string()
                } else {
                    collection_id.to_string()
                },
                created: now,
                modified: now,
                items: Vec::new(),
            };

            self.vault_storage.save_vault_with_key(
                collection_id,
                &new_payload,
                &master_key,
                &kdf_params,
            )?;
            info!("New vault written successfully");
            (new_payload, master_key, kdf_params)
        };

        let items = payload
            .items
            .into_iter()
            .map(|stored| {
                let id = stored.id.clone();
                let item = ItemData {
                    id: stored.id,
                    label: stored.label,
                    attributes: stored.attributes,
                    secret: Zeroizing::new(stored.secret),
                    content_type: stored.content_type,
                    created: stored.created,
                    modified: stored.modified,
                };
                (id, item)
            })
            .collect();

        let collection = CollectionData {
            id: payload.collection_id,
            label: payload.label,
            created: payload.created,
            modified: payload.modified,
            items,
            master_key: Some(master_key),
            kdf_params: Some(kdf_params),
        };

        {
            let mut cols = self.collections.write().await;
            cols.insert(collection_id.to_string(), collection);
        }

        self.lock_manager.unlock(collection_id).await;
        info!("Collection '{}' successfully unlocked", collection_id);
        Ok(())
    }

    /// Locks a collection and zeroizes secrets from memory.
    pub async fn lock_collection(&self, collection_id: &str) -> Result<()> {
        let mut cols = self.collections.write().await;
        let col = cols
            .get_mut(collection_id)
            .ok_or_else(|| CielError::NoSuchObject(format!("No collection '{collection_id}'")))?;

        for item in col.items.values_mut() {
            item.secret = Zeroizing::new(vec![]);
        }

        col.master_key = None;
        col.kdf_params = None;

        self.lock_manager.lock(collection_id).await;
        info!("Collection '{}' locked and secrets zeroized", collection_id);
        Ok(())
    }

    /// Persists a collection to disk using its cached master key AND the KDF
    /// parameters that key was derived with. Never generates a new salt here.
    pub async fn persist_collection(&self, collection_id: &str) -> Result<()> {
        let cols = self.collections.read().await;
        let col = cols
            .get(collection_id)
            .ok_or_else(|| CielError::NoSuchObject(format!("No collection '{collection_id}'")))?;

        let payload = VaultPayload {
            collection_id: col.id.clone(),
            label: col.label.clone(),
            created: col.created,
            modified: col.modified,
            items: col
                .items
                .values()
                .map(|item| StoredItem {
                    id: item.id.clone(),
                    label: item.label.clone(),
                    attributes: item.attributes.clone(),
                    secret: item.secret.to_vec(),
                    content_type: item.content_type.clone(),
                    created: item.created,
                    modified: item.modified,
                })
                .collect(),
        };

        match (&col.master_key, &col.kdf_params) {
            (Some(master_key), Some(kdf_params)) => {
                self.vault_storage.save_vault_with_key(
                    collection_id,
                    &payload,
                    master_key,
                    kdf_params,
                )?;
            }
            _ => {
                warn!(
                    "Skipped persist for collection '{}' (locked or missing cached KDF params)",
                    collection_id
                );
            }
        }
        Ok(())
    }

    /// Resolves an alias name (e.g., `default`) to its target collection object path.
    pub async fn resolve_alias(&self, name: &str) -> Result<OwnedObjectPath> {
        let aliases = self.aliases.read().await;
        let col_id = aliases.get(name).ok_or_else(|| {
            CielError::NoSuchObject(format!("Alias '{name}' does not point to any collection"))
        })?;

        OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/collection/{col_id}"))
            .map_err(|e| CielError::Config(e.to_string()))
    }

    /// Sets or updates an alias.
    pub async fn set_alias(
        &self,
        name: &str,
        collection_path: &OwnedObjectPath,
        _caller: &CallerIdentity,
    ) -> Result<()> {
        let path_str = collection_path.as_str();
        if path_str == "/" {
            let mut aliases = self.aliases.write().await;
            aliases.remove(name);
            return Ok(());
        }

        let col_id = path_str
            .strip_prefix("/org/freedesktop/secrets/collection/")
            .ok_or_else(|| CielError::NoSuchObject("Invalid collection path for alias".into()))?;

        let mut aliases = self.aliases.write().await;
        aliases.insert(name.to_string(), col_id.to_string());
        Ok(())
    }

    /// Bulk retrieves secrets for multiple items for a given session.
    pub async fn get_multiple_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: &Session,
        caller: &CallerIdentity,
    ) -> Result<HashMap<OwnedObjectPath, SecretWire>> {
        let mut map = HashMap::new();
        for item_path in items {
            let path_str = item_path.as_str();
            if let Some(rest) = path_str.strip_prefix("/org/freedesktop/secrets/collection/") {
                let mut parts = rest.split('/');
                if let (Some(col_id), Some(item_id)) = (parts.next(), parts.next()) {
                    let session_path = OwnedObjectPath::try_from(session.path.as_str())
                        .map_err(|e| CielError::Config(e.to_string()))?;

                    if let Ok(wire) = self
                        .get_item_secret(col_id, item_id, &session_path, caller)
                        .await
                    {
                        let (parameters, value) = session.encrypt(&wire.value)?;

                        let encrypted_wire = SecretWire {
                            session: session.path.clone(),
                            parameters,
                            value,
                            content_type: wire.content_type,
                        };

                        if let Ok(owned_path) = OwnedObjectPath::try_from(path_str) {
                            map.insert(owned_path, encrypted_wire);
                        }
                    }
                }
            }
        }
        Ok(map)
    }

    pub async fn get_collection_label(&self, id: &str) -> Result<String> {
        let cols = self.collections.read().await;
        let col = cols
            .get(id)
            .ok_or_else(|| CielError::NoSuchObject(id.into()))?;
        Ok(col.label.clone())
    }

    pub async fn set_collection_label(&self, id: &str, label: String) -> Result<()> {
        {
            let mut cols = self.collections.write().await;
            let col = cols
                .get_mut(id)
                .ok_or_else(|| CielError::NoSuchObject(id.into()))?;
            col.label = label;
            col.modified = current_timestamp_secs();
        }
        self.persist_collection(id).await?;
        Ok(())
    }

    pub async fn get_collection_created(&self, id: &str) -> Result<u64> {
        let cols = self.collections.read().await;
        let col = cols
            .get(id)
            .ok_or_else(|| CielError::NoSuchObject(id.into()))?;
        Ok(col.created)
    }

    pub async fn get_collection_modified(&self, id: &str) -> Result<u64> {
        let cols = self.collections.read().await;
        let col = cols
            .get(id)
            .ok_or_else(|| CielError::NoSuchObject(id.into()))?;
        Ok(col.modified)
    }

    pub async fn get_item_label(&self, col_id: &str, item_id: &str) -> Result<String> {
        let cols = self.collections.read().await;
        let col = cols
            .get(col_id)
            .ok_or_else(|| CielError::NoSuchObject(col_id.into()))?;
        let item = col
            .items
            .get(item_id)
            .ok_or_else(|| CielError::NoSuchObject(item_id.into()))?;
        Ok(item.label.clone())
    }

    pub async fn set_item_label(&self, col_id: &str, item_id: &str, label: String) -> Result<()> {
        {
            let mut cols = self.collections.write().await;
            let col = cols
                .get_mut(col_id)
                .ok_or_else(|| CielError::NoSuchObject(col_id.into()))?;
            let item = col
                .items
                .get_mut(item_id)
                .ok_or_else(|| CielError::NoSuchObject(item_id.into()))?;
            item.label = label;
            item.modified = current_timestamp_secs();
        }
        self.persist_collection(col_id).await?;
        Ok(())
    }

    pub async fn get_item_attributes(
        &self,
        col_id: &str,
        item_id: &str,
    ) -> Result<HashMap<String, String>> {
        let cols = self.collections.read().await;
        let col = cols
            .get(col_id)
            .ok_or_else(|| CielError::NoSuchObject(col_id.into()))?;
        let item = col
            .items
            .get(item_id)
            .ok_or_else(|| CielError::NoSuchObject(item_id.into()))?;
        Ok(item.attributes.clone())
    }

    pub async fn set_item_attributes(
        &self,
        col_id: &str,
        item_id: &str,
        attributes: HashMap<String, String>,
    ) -> Result<()> {
        {
            let mut cols = self.collections.write().await;
            let col = cols
                .get_mut(col_id)
                .ok_or_else(|| CielError::NoSuchObject(col_id.into()))?;
            let item = col
                .items
                .get_mut(item_id)
                .ok_or_else(|| CielError::NoSuchObject(item_id.into()))?;
            item.attributes = attributes;
            item.modified = current_timestamp_secs();
        }
        self.persist_collection(col_id).await?;
        Ok(())
    }

    pub async fn get_item_created(&self, col_id: &str, item_id: &str) -> Result<u64> {
        let cols = self.collections.read().await;
        let col = cols
            .get(col_id)
            .ok_or_else(|| CielError::NoSuchObject(col_id.into()))?;
        let item = col
            .items
            .get(item_id)
            .ok_or_else(|| CielError::NoSuchObject(item_id.into()))?;
        Ok(item.created)
    }

    pub async fn get_item_modified(&self, col_id: &str, item_id: &str) -> Result<u64> {
        let cols = self.collections.read().await;
        let col = cols
            .get(col_id)
            .ok_or_else(|| CielError::NoSuchObject(col_id.into()))?;
        let item = col
            .items
            .get(item_id)
            .ok_or_else(|| CielError::NoSuchObject(item_id.into()))?;
        Ok(item.modified)
    }
}
