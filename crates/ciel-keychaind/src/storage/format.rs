//! ============================================================================
//! ciel-keychaind - Vault Storage Format & Serialization
//!
//! Defines the cryptographic on-disk file layout for encrypted vaults:
//! - File Header:
//!   - Magic bytes: `SECRETD_VAULT\0` (14 bytes)
//!   - Format version: `1` (u32 little-endian)
//!   - Header metadata (Argon2id salt and cost parameters)
//! - Ciphertext Body:
//!   - Encrypted via XChaCha20-Poly1305 with random 192-bit nonce.
//!   - Decrypts to a structured [`VaultPayload`] containing collections and items.
//!
//! ============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::crypto::kdf::KdfParams;
use crate::error::{CielError, Result};

/// 14-byte magic signature at the beginning of all ciel-keychaind vault files.
pub const VAULT_MAGIC: &[u8; 21] = b"CIEL_KEYCHAIND_VAULT\0";

/// Current on-disk vault file format version.
pub const VAULT_FORMAT_VERSION: u32 = 1;

/// File header located at offset 0 of each `.keyring` or vault file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Format version number.
    pub version: u32,
    /// Argon2id KDF parameters used to derive the AEAD master key.
    pub kdf: KdfParams,
}

/// Plaintext vault payload stored inside the authenticated AEAD ciphertext envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultPayload {
    /// Canonical collection identifier (e.g. `login`).
    pub collection_id: String,
    /// Human-friendly display label.
    pub label: String,
    /// Creation timestamp (UNIX epoch in seconds).
    pub created: u64,
    /// Modification timestamp (UNIX epoch in seconds).
    pub modified: u64,
    /// All credential items stored inside this collection.
    pub items: Vec<StoredItem>,
}

/// Persistent representation of a stored secret item.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredItem {
    pub id: String,
    pub label: String,
    pub attributes: HashMap<String, String>,
    pub secret: Vec<u8>,
    pub content_type: String,
    pub created: u64,
    pub modified: u64,
}

/// Encodes complete file bytes given a header and the encrypted payload blob.
pub fn encode_vault_file(header: &VaultHeader, encrypted_body: &[u8]) -> Result<Vec<u8>> {
    let header_json = serde_json::to_vec(header)
        .map_err(|e| CielError::Storage(format!("Failed to serialize header: {e}")))?;

    let header_len = header_json.len() as u32;

    let mut file_bytes =
        Vec::with_capacity(VAULT_MAGIC.len() + 4 + header_json.len() + encrypted_body.len());
    file_bytes.extend_from_slice(VAULT_MAGIC);
    file_bytes.extend_from_slice(&header_len.to_le_bytes());
    file_bytes.extend_from_slice(&header_json);
    file_bytes.extend_from_slice(encrypted_body);

    Ok(file_bytes)
}

/// Decodes and validates header and encrypted payload from raw vault file bytes.
pub fn decode_vault_file(data: &[u8]) -> Result<(VaultHeader, &[u8])> {
    if data.len() < VAULT_MAGIC.len() + 4 {
        return Err(CielError::Storage(
            "Vault file too small to contain valid header".into(),
        ));
    }

    let (magic, rest) = data.split_at(VAULT_MAGIC.len());
    if magic != VAULT_MAGIC {
        return Err(CielError::Storage(
            "Invalid vault file magic identifier".into(),
        ));
    }

    let (len_bytes, rest) = rest.split_at(4);
    let header_len = u32::from_le_bytes(len_bytes.try_into().unwrap()) as usize;

    if rest.len() < header_len {
        return Err(CielError::Storage(
            "Vault file truncated in header section".into(),
        ));
    }

    let (header_bytes, encrypted_body) = rest.split_at(header_len);
    let header: VaultHeader = serde_json::from_slice(header_bytes)
        .map_err(|e| CielError::Storage(format!("Malformed vault header JSON: {e}")))?;

    if header.version != VAULT_FORMAT_VERSION {
        return Err(CielError::Storage(format!(
            "Unsupported vault version: {} (supported: {})",
            header.version, VAULT_FORMAT_VERSION
        )));
    }

    Ok((header, encrypted_body))
}
