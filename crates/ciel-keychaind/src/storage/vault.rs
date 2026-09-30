//! ============================================================================
//! ciel-keychaind - Atomic Vault Persistence & Storage Operations
//!
//! Provides durable and atomic disk persistence:
//! - File writes strictly adhere to the crash-safe pattern:
//!   1. Write new encrypted content to an ephemeral temp file (`.tmp.<pid>.<rand>`).
//!   2. Set restrictive POSIX permissions `0600` (`-rw-------`).
//!   3. Execute `File::sync_all()` to flush buffers and filesystem journals.
//!   4. Atomically replace target via `std::fs::rename()`.
//!   5. Invoke `fsync()` on the parent directory to commit directory entry changes.
//! - Prevents partial writes, power-loss corruption, or permission race windows.
//! ============================================================================

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};
use zeroize::Zeroizing;

use crate::crypto::aead::{decrypt_payload, encrypt_payload};
use crate::crypto::kdf::{derive_master_key, KdfParams};
use crate::error::{CielError, Result};
use crate::storage::format::{
    decode_vault_file, encode_vault_file, VaultHeader, VaultPayload, VAULT_FORMAT_VERSION,
};

/// High-level disk storage coordinator for encrypted vault files.
pub struct VaultStorage {
    vault_dir: PathBuf,
}

impl VaultStorage {
    /// Creates a new storage coordinator bound to the given directory.
    pub fn new(vault_dir: PathBuf) -> Self {
        Self { vault_dir }
    }

    pub fn vault_dir(&self) -> &Path {
        &self.vault_dir
    }

    /// Derives the canonical path for a collection's on-disk vault file.
    pub fn vault_file_path(&self, collection_id: &str) -> PathBuf {
        self.vault_dir.join(format!("{collection_id}.keyring"))
    }

    /// Reads KDF parameters from an existing vault header, if the file is present.
    ///
    /// The on-disk salt is the source of truth: the cached master key was derived
    /// with it, so every subsequent save MUST write the same salt back.
    pub fn read_existing_kdf(&self, collection_id: &str) -> Result<Option<KdfParams>> {
        let path = self.vault_file_path(collection_id);
        if !path.exists() {
            return Ok(None);
        }

        let raw_data = std::fs::read(&path)
            .map_err(|e| CielError::Storage(format!("Failed to read {}: {e}", path.display())))?;
        let (header, _) = decode_vault_file(&raw_data)?;
        Ok(Some(header.kdf))
    }

    /// Reads, verifies, and decrypts a vault file using the provided passphrase.
    pub fn load_vault(&self, collection_id: &str, passphrase: &[u8]) -> Result<VaultPayload> {
        let (payload, _key, _kdf) = self.load_vault_with_passphrase(collection_id, passphrase)?;
        Ok(payload)
    }

    /// Decrypts a vault and also returns the derived master key plus the on-disk
    /// KDF parameters so callers can cache both for later `save_vault_with_key`.
    pub fn load_vault_with_passphrase(
        &self,
        collection_id: &str,
        passphrase: &[u8],
    ) -> Result<(VaultPayload, Zeroizing<[u8; 32]>, KdfParams)> {
        let path = self.vault_file_path(collection_id);
        if !path.exists() {
            return Err(CielError::NoSuchObject(format!(
                "Vault file does not exist at {}",
                path.display()
            )));
        }

        let raw_data = std::fs::read(&path)
            .map_err(|e| CielError::Storage(format!("Failed to read {}: {e}", path.display())))?;

        let (header, encrypted_body) = decode_vault_file(&raw_data)?;
        let kdf = header.kdf;

        let master_key = derive_master_key(passphrase, &kdf)?;
        let aad = collection_id.as_bytes();
        let decrypted_bytes = decrypt_payload(&master_key, encrypted_body, aad)?;

        let payload: VaultPayload = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| CielError::Storage(format!("Corrupt vault payload JSON: {e}")))?;

        info!("Successfully decrypted vault '{}' from disk", collection_id);
        Ok((payload, master_key, kdf))
    }

    /// Encrypts and atomically saves a vault payload to disk, deriving a fresh
    /// master key from the passphrase. A new salt is generated only when no
    /// vault file exists yet.
    pub fn save_vault(
        &self,
        collection_id: &str,
        payload: &VaultPayload,
        passphrase: &[u8],
        kdf_params: Option<KdfParams>,
    ) -> Result<()> {
        let kdf = match self.read_existing_kdf(collection_id)? {
            Some(existing) => existing,
            None => kdf_params.unwrap_or_else(KdfParams::generate),
        };
        let master_key = derive_master_key(passphrase, &kdf)?;
        self.save_vault_with_key(collection_id, payload, &master_key, &kdf)
    }

    /// Encrypts and saves a vault using a pre-derived master key (avoids expensive
    /// KDF re-derivation).
    ///
    /// If a vault file already exists, its on-disk KDF parameters (especially the
    /// salt) are reused. Writing a *new* salt while encrypting with a key derived
    /// from the *old* salt makes the file permanently undecryptable.
    pub fn save_vault_with_key(
        &self,
        collection_id: &str,
        payload: &VaultPayload,
        master_key: &[u8; 32],
        kdf_params: &KdfParams,
    ) -> Result<()> {
        let kdf = match self.read_existing_kdf(collection_id)? {
            Some(existing) => {
                if existing != *kdf_params {
                    warn!(
                        "Reusing on-disk KDF salt for '{}' instead of caller-supplied params (salt mismatch would brick the vault)",
                        collection_id
                    );
                }
                existing
            }
            None => kdf_params.clone(),
        };

        let plaintext_json = serde_json::to_vec(payload)
            .map_err(|e| CielError::Storage(format!("Failed to serialize payload: {e}")))?;

        let aad = collection_id.as_bytes();
        let encrypted_body = encrypt_payload(master_key, &plaintext_json, aad)?;

        let header = VaultHeader {
            version: VAULT_FORMAT_VERSION,
            kdf,
        };

        let file_bytes = encode_vault_file(&header, &encrypted_body)?;
        let target_path = self.vault_file_path(collection_id);
        self.atomic_write(&target_path, &file_bytes)?;

        info!(
            "Persisted vault '{}' to {} (using cached master key)",
            collection_id,
            target_path.display()
        );
        Ok(())
    }

    /// Reads, verifies, and decrypts a vault file using a pre-derived master key.
    pub fn load_vault_with_key(
        &self,
        collection_id: &str,
        master_key: &[u8; 32],
    ) -> Result<VaultPayload> {
        let path = self.vault_file_path(collection_id);
        if !path.exists() {
            return Err(CielError::NoSuchObject(format!(
                "Vault file does not exist at {}",
                path.display()
            )));
        }

        let raw_data = std::fs::read(&path)
            .map_err(|e| CielError::Storage(format!("Failed to read {}: {e}", path.display())))?;
        let (_, encrypted_body) = decode_vault_file(&raw_data)?;

        let aad = collection_id.as_bytes();
        let decrypted_bytes = decrypt_payload(master_key, encrypted_body, aad)?;
        let payload: VaultPayload = serde_json::from_slice(&decrypted_bytes)
            .map_err(|e| CielError::Storage(format!("Corrupt vault payload JSON: {e}")))?;

        info!("Successfully decrypted vault '{}' from disk", collection_id);
        Ok(payload)
    }

    /// Lists all collection IDs that have a vault file on disk.
    pub fn list_vaults(&self) -> Result<Vec<String>> {
        let mut vaults = Vec::new();
        if self.vault_dir.exists() {
            for entry in std::fs::read_dir(&self.vault_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("keyring") {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        vaults.push(stem.to_string());
                    }
                }
            }
        }
        Ok(vaults)
    }

    /// Deletes a vault file from disk.
    pub fn delete_vault(&self, collection_id: &str) -> Result<()> {
        let path = self.vault_file_path(collection_id);
        if path.exists() {
            std::fs::remove_file(&path)
                .map_err(|e| CielError::Storage(format!("Failed to delete vault file: {e}")))?;
        }
        Ok(())
    }

    /// Executes an atomic write sequence with fsync and directory barrier.
    fn atomic_write(&self, target_path: &Path, content: &[u8]) -> Result<()> {
        let parent = target_path.parent().ok_or_else(|| {
            CielError::Storage("Target vault path has no parent directory".into())
        })?;

        if !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }

        let rand_suffix: u64 = rand::random();
        let pid = std::process::id();
        let temp_filename = format!(".vault-tmp-{pid}-{rand_suffix}.tmp");
        let temp_path = parent.join(temp_filename);

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .map_err(|e| {
                CielError::Storage(format!(
                    "Failed to open temp file {}: {e}",
                    temp_path.display()
                ))
            })?;

        file.write_all(content)
            .map_err(|e| CielError::Storage(format!("Failed to write to temp file: {e}")))?;

        file.sync_all()
            .map_err(|e| CielError::Storage(format!("Failed to fsync temp file: {e}")))?;

        drop(file);

        std::fs::rename(&temp_path, target_path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            CielError::Storage(format!("Failed to rename temp file to target: {e}"))
        })?;

        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }

        debug!("Atomic write verified for {}", target_path.display());
        Ok(())
    }
}
