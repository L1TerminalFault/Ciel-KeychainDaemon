//! ============================================================================
//! ciel-keychaind - Authenticated Encryption (XChaCha20-Poly1305)
//!
//! Provides symmetric AEAD confidentiality and integrity guarantees for
//! collection vaults stored on disk:
//! - Cipher: XChaCha20-Poly1305 (256-bit key, 192-bit nonce, 128-bit MAC).
//! - Nonces are 192 bits, eliminating nonce reuse vulnerabilities across
//!   random generations.
//! - Output payload structure: `[ 24-byte Nonce || Ciphertext || 16-byte Poly1305 Tag ]`.
//! ============================================================================

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::Rng;
use zeroize::Zeroizing;

use crate::error::{CielError, Result};

/// Nonce length in bytes for XChaCha20 (192 bits).
pub const NONCE_LENGTH_BYTES: usize = 24;

/// Authentication tag length in bytes for Poly1305 (128 bits).
pub const TAG_LENGTH_BYTES: usize = 16;

/// Minimum payload length (must include nonce and authentication tag).
pub const MIN_PAYLOAD_LENGTH: usize = NONCE_LENGTH_BYTES + TAG_LENGTH_BYTES;

/// Encrypts plaintext bytes using XChaCha20-Poly1305 with optional Associated Data (AAD).
///
/// Returns a contiguous byte buffer structured as `[Nonce (24B) || Ciphertext + Tag]`.
pub fn encrypt_payload(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; NONCE_LENGTH_BYTES];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::try_from(nonce_bytes)
        .map_err(|_| CielError::Crypto("Invalid nonce length".into()))?;

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let mut ciphertext = cipher
        .encrypt(&nonce, payload)
        .map_err(|e| CielError::Crypto(format!("XChaCha20-Poly1305 encryption failed: {e}")))?;

    let mut output = Vec::with_capacity(NONCE_LENGTH_BYTES + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.append(&mut ciphertext);

    Ok(output)
}

/// Decrypts and authenticates a payload previously encrypted with [`encrypt_payload`].
///
/// Returns a [`Zeroizing`] buffer containing the verified plaintext.
pub fn decrypt_payload(
    key: &[u8; 32],
    encrypted_blob: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if encrypted_blob.len() < MIN_PAYLOAD_LENGTH {
        return Err(CielError::Crypto(format!(
            "Encrypted payload too short: {} bytes (minimum {MIN_PAYLOAD_LENGTH})",
            encrypted_blob.len()
        )));
    }

    let (nonce_bytes, ciphertext_with_tag) = encrypted_blob.split_at(NONCE_LENGTH_BYTES);
    let nonce = XNonce::try_from(nonce_bytes)
        .map_err(|_| CielError::Crypto("Invalid nonce length".into()))?;

    let cipher = XChaCha20Poly1305::new(key.into());
    let payload = Payload {
        msg: ciphertext_with_tag,
        aad,
    };

    let plaintext = cipher.decrypt(&nonce, payload).map_err(|_| {
        CielError::Crypto("Authentication tag verification or decryption failed".into())
    })?;

    Ok(Zeroizing::new(plaintext))
}

/// High-level wrapper around an active AEAD vault key.
pub struct AeadCipher {
    key: Zeroizing<[u8; 32]>,
}

impl AeadCipher {
    /// Instantiates a cipher from a zeroized 256-bit key.
    pub fn new(key: Zeroizing<[u8; 32]>) -> Self {
        Self { key }
    }

    /// Encrypts plaintext with associated data.
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        encrypt_payload(&self.key, plaintext, aad)
    }

    /// Decrypts ciphertext with associated data.
    pub fn decrypt(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        decrypt_payload(&self.key, ciphertext, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_roundtrip() {
        let key = [0x5au8; 32];
        let plaintext = b"Top secret classified credential";
        let aad = b"header-v1-metadata";

        let ciphertext = encrypt_payload(&key, plaintext, aad).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        let decrypted = decrypt_payload(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_aead_tamper_detection() {
        let key = [0x7bu8; 32];
        let plaintext = b"Sensitive payload";
        let aad = b"vault-id-login";

        let mut ciphertext = encrypt_payload(&key, plaintext, aad).unwrap();

        // Tamper with one byte in the ciphertext payload
        let last_idx = ciphertext.len() - 1;
        ciphertext[last_idx] ^= 0x01;

        let result = decrypt_payload(&key, &ciphertext, aad);
        assert!(result.is_err());
    }
}
