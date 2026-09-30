//! ============================================================================
//! ciel-keychaind - Key Derivation Function (Argon2id)
//!
//! Implements memory-hard password hashing and symmetric key derivation using
//! the Argon2id variant specified in RFC 9106:
//! - Provides resistance against GPU and ASIC brute-force attacks.
//! - Default parameters: 64 MiB RAM, 3 iterations, 4 parallel threads.
//! - Key material is held exclusively within zeroized memory buffers.
//! ============================================================================

use argon2::{Algorithm, Argon2, Params, Version};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{CielError, Result};

/// Default memory cost for Argon2id in KiB (64 MiB).
pub const DEFAULT_MEMORY_COST_KIB: u32 = 64 * 1024;

/// Default time cost (iterations) for Argon2id.
pub const DEFAULT_TIME_COST: u32 = 3;

/// Default degree of parallelism (threads/lanes) for Argon2id.
pub const DEFAULT_PARALLELISM: u32 = 4;

/// Salt length in bytes (128 bits).
pub const SALT_LENGTH_BYTES: usize = 16;

/// Output master key length in bytes (256 bits for XChaCha20-Poly1305).
pub const KEY_LENGTH_BYTES: usize = 32;

/// Serialization parameters for the Argon2id key derivation configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory consumption in KiB.
    pub memory_cost_kib: u32,
    /// Number of iterations.
    pub time_cost: u32,
    /// Thread parallelism count.
    pub parallelism: u32,
    /// Cryptographic salt bytes.
    pub salt: Vec<u8>,
}

impl KdfParams {
    /// Generate parameters with a fresh random salt.
    ///
    /// Call this **only** when creating a brand-new vault. Re-saving an existing
    /// vault MUST reuse the salt that the cached master key was derived with.
    /// `Default` also generates a new salt — never use it in `persist_collection`.
    pub fn generate() -> Self {
        Self::default()
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        let mut salt = vec![0u8; SALT_LENGTH_BYTES];
        rand::rng().fill_bytes(&mut salt);

        Self {
            memory_cost_kib: DEFAULT_MEMORY_COST_KIB,
            time_cost: DEFAULT_TIME_COST,
            parallelism: DEFAULT_PARALLELISM,
            salt,
        }
    }
}

/// Derives a 256-bit symmetric encryption key from a passphrase and KDF parameters.
///
/// Returns a zeroizing 32-byte array that scrubs itself when dropped.
pub fn derive_master_key(
    passphrase: &[u8],
    params: &KdfParams,
) -> Result<Zeroizing<[u8; KEY_LENGTH_BYTES]>> {
    if params.salt.len() < SALT_LENGTH_BYTES {
        return Err(CielError::Crypto(format!(
            "Argon2id salt too short: {} bytes (expected at least {SALT_LENGTH_BYTES})",
            params.salt.len()
        )));
    }

    let argon2_params = Params::new(
        params.memory_cost_kib,
        params.time_cost,
        params.parallelism,
        Some(KEY_LENGTH_BYTES),
    )
    .map_err(|e| CielError::Crypto(format!("Invalid Argon2 parameters: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut output_key = Zeroizing::new([0u8; KEY_LENGTH_BYTES]);

    argon2
        .hash_password_into(passphrase, &params.salt, output_key.as_mut())
        .map_err(|e| CielError::Crypto(format!("Argon2id key derivation failed: {e}")))?;

    Ok(output_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id_derivation() {
        let params = KdfParams {
            memory_cost_kib: 1024, // 1 MiB for fast unit test
            time_cost: 1,
            parallelism: 1,
            salt: vec![0x42; 16],
        };

        let pass = b"correct horse battery staple";
        let key1 = derive_master_key(pass, &params).unwrap();
        let key2 = derive_master_key(pass, &params).unwrap();

        assert_eq!(key1.as_ref(), key2.as_ref());
        assert_ne!(key1.as_ref(), &[0u8; 32]);
    }

    #[test]
    fn default_kdf_params_use_unique_salts() {
        let a = KdfParams::generate();
        let b = KdfParams::generate();
        assert_ne!(
            a.salt, b.salt,
            "each generate()/Default must mint a unique salt — never reuse Default when persisting"
        );
    }
}
