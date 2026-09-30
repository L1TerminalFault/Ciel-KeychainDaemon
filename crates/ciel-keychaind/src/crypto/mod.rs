//! ============================================================================
//! ciel-keychaind - Cryptographic Subsystem Architecture
//!
//! Provides memory-safe, zeroized cryptographic implementations:
//! - `kdf`: Key derivation using Argon2id (RFC 9106) with memory/time cost parameters.
//! - `aead`: Authenticated Encryption with Associated Data (AEAD) using
//!   XChaCha20-Poly1305 with random 192-bit nonces.
//! - `secret`: Zeroizing, heap-locked secret wrappers (`ProtectedMemory`, `SecureVec`).
//! - `session`: Transport encryption protocols (DH-IETF1024-SHA256-AES128-CBC and Plain).
//!
//! ============================================================================

pub mod aead;
pub mod kdf;
pub mod secret;
pub mod session;

pub use aead::{decrypt_payload, encrypt_payload, AeadCipher};
pub use kdf::{derive_master_key, KdfParams};
pub use secret::{ProtectedSecret, SecureBuffer};
