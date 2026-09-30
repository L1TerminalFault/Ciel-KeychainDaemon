//! ============================================================================
//! ciel-keychaind - D-Bus Session & Transport Encryption
//!
//! Implements the `org.freedesktop.Secret.Session` interface and cryptographic
//! transport encryption between the daemon and client applications:
//!
//! Supported Algorithms:
//! 1. `plain`: Secrets are transferred unencrypted (standard for local trusted IPC)
//! 2. `dh-ietf1024-sha256-aes128-cbc-pkcs7`:
//!    - Diffie-Hellman Key Exchange using RFC 2409 1024-bit MODP Group 2
//!    - Shared secret derived via SHA-256
//!    - AES-128-CBC encryption/decryption with PKCS#7 padding
//!
//! ============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use tokio::sync::RwLock;
use zbus::interface;
use zbus::zvariant::{OwnedObjectPath, Value};
use zeroize::Zeroizing;

use crate::error::{CielError, Result};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// RFC 2409 / RFC 3526 1024-bit MODP Group 2 Prime (hex representation).
const DH_PRIME_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381\
FFFFFFFFFFFFFFFF";
// const DH_PRIME_HEX: &str = "\
// FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
// 29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
// EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
// E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
// EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
// C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
// 83655D23DCA3AD961C62F356208552BB9ED529077096966D\
// 670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
// E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9D\
// E2BCBF6955817183995497CEA956AE515D2261898FA051015\
// 728E5A8AACAA68FFFFFFFFFFFFFFFF";

const DH_GENERATOR: u32 = 2;

/// Supported session transport encryption algorithms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionAlgorithm {
    /// Plaintext transport over local D-Bus.
    Plain,

    /// DH-IETF1024 ephemeral key agreement + AES-128-CBC.
    DhIetf1024Aes128CbcPkcs7 {
        /// Derived 128-bit symmetric key for this session (zeroized on drop).
        symmetric_key: Zeroizing<[u8; 16]>,
    },
}

/// Active Secret Service client session.
pub struct Session {
    /// Path uniquely identifying this session object on D-Bus.
    pub path: OwnedObjectPath,

    /// The negotiated transport encryption mode.
    pub algorithm: SessionAlgorithm,

    /// Time when this session was opened or last used.
    pub last_accessed: Instant,

    /// Owner D-Bus connection name that instantiated this session.
    pub owner_bus_name: String,
}

impl Session {
    /// Encrypts raw secret bytes into transport format according to the
    /// session algorithm.
    pub fn encrypt(&self, secret_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match &self.algorithm {
            SessionAlgorithm::Plain => {
                // Plain format uses empty parameter / IV.
                Ok((Vec::new(), secret_bytes.to_vec()))
            }

            SessionAlgorithm::DhIetf1024Aes128CbcPkcs7 { symmetric_key } => {
                let mut iv = [0u8; 16];
                rand::fill(&mut iv);

                // Convert key slice reference into a fixed-size 16-byte array reference
                let key_arr: &[u8; 16] = (&**symmetric_key).try_into().map_err(|_| {
                    CielError::Crypto("Invalid symmetric key length for AES-128".into())
                })?;

                let encryptor = Aes128CbcEnc::new(key_arr.into(), (&iv).into());
                let ciphertext = encryptor.encrypt_padded_vec::<Pkcs7>(secret_bytes);

                Ok((iv.to_vec(), ciphertext))
            }
        }
    }

    /// Decrypts incoming client secret bytes from transport format.
    pub fn decrypt(&self, parameters: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match &self.algorithm {
            SessionAlgorithm::Plain => Ok(Zeroizing::new(ciphertext.to_vec())),

            SessionAlgorithm::DhIetf1024Aes128CbcPkcs7 { symmetric_key } => {
                if parameters.len() != 16 {
                    return Err(CielError::InvalidSecret(
                        "AES-128-CBC transport requires a 16-byte IV in parameters".into(),
                    ));
                }

                let iv: &[u8; 16] = parameters.try_into().map_err(|_| {
                    CielError::InvalidSecret("AES-128-CBC transport requires a 16-byte IV".into())
                })?;

                // Convert key slice reference into a fixed-size 16-byte array reference
                let key_arr: &[u8; 16] = (&**symmetric_key).try_into().map_err(|_| {
                    CielError::Crypto("Invalid symmetric key length for AES-128".into())
                })?;

                let decryptor = Aes128CbcDec::new(key_arr.into(), iv.into());
                let plaintext = decryptor
                    .decrypt_padded_vec::<Pkcs7>(ciphertext)
                    .map_err(|e| {
                        CielError::InvalidSecret(format!("Decryption/unpadding failed: {e}"))
                    })?;

                Ok(Zeroizing::new(plaintext))
            }
        }
    }
}

/// D-Bus interface `org.freedesktop.Secret.Session`.
pub struct SessionDbus {
    session_path: OwnedObjectPath,
    sessions_map: Arc<RwLock<HashMap<OwnedObjectPath, Session>>>,
}

impl SessionDbus {
    pub fn new(
        session_path: OwnedObjectPath,
        sessions_map: Arc<RwLock<HashMap<OwnedObjectPath, Session>>>,
    ) -> Self {
        Self {
            session_path,
            sessions_map,
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl SessionDbus {
    /// Closes the session and purges negotiated transport cryptographic keys.
    async fn close(&self) -> zbus::fdo::Result<()> {
        let mut map = self.sessions_map.write().await;
        map.remove(&self.session_path);
        Ok(())
    }
}

/// Negotiates a new session given an algorithm and client input parameters.
pub fn negotiate_session(
    algorithm: &str,
    input: &Value<'_>,
    session_id: u64,
    owner_bus_name: String,
) -> Result<(Session, Value<'static>)> {
    let session_path =
        OwnedObjectPath::try_from(format!("/org/freedesktop/secrets/session/s{session_id}"))
            .map_err(|e| CielError::Config(e.to_string()))?;

    match algorithm {
        "plain" => {
            let session = Session {
                path: session_path,
                algorithm: SessionAlgorithm::Plain,
                last_accessed: Instant::now(),
                owner_bus_name,
            };

            // Output parameter for plain is an empty string.
            Ok((session, Value::from("")))
        }

        "dh-ietf1024-sha256-aes128-cbc-pkcs7" => {
            let client_pub_bytes: Vec<u8> = match input {
                Value::Array(arr) => {
                    let mut bytes = Vec::with_capacity(arr.len());

                    for value in arr.iter() {
                        if let Value::U8(byte) = value {
                            bytes.push(*byte);
                        } else {
                            return Err(CielError::InvalidSecret(
                                "DH public key array must contain u8 elements".into(),
                            ));
                        }
                    }

                    bytes
                }

                _ => {
                    return Err(CielError::InvalidSecret(
                        "DH input must be a byte array".into(),
                    ));
                }
            };

            let prime = BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16)
                .ok_or_else(|| CielError::Crypto("Failed to parse DH prime".into()))?;

            let generator = BigUint::from(DH_GENERATOR);
            let client_pub = BigUint::from_bytes_be(&client_pub_bytes);

            // Generate private exponent (random integer less than prime).
let mut private_bytes = [0u8; 128];
rand::fill(&mut private_bytes);

let priv_exp = BigUint::from_bytes_be(&private_bytes);

// Compute daemon public key: g^priv mod p.
let daemon_pub = generator.modpow(&priv_exp, &prime);

let daemon_pub_raw = daemon_pub.to_bytes_be();
let mut daemon_pub_bytes = vec![0u8; 128];
let daemon_offset = 128 - daemon_pub_raw.len();
daemon_pub_bytes[daemon_offset..].copy_from_slice(&daemon_pub_raw);

// Compute shared secret: client_pub^priv mod p.
let shared_secret = client_pub.modpow(&priv_exp, &prime);

let shared_secret_raw = shared_secret.to_bytes_be();
let mut shared_secret_bytes = [0u8; 128];
let shared_offset = 128 - shared_secret_raw.len();
shared_secret_bytes[shared_offset..].copy_from_slice(&shared_secret_raw);

            // let shared_secret_bytes = shared_secret.to_bytes_be();
            //
            // // Hash shared secret with SHA-256 and truncate to 16 bytes
            // // for AES-128.
            // let mut hasher = Sha256::new();
            // hasher.update(&shared_secret_bytes);
            // let hash_result = hasher.finalize();
            //
            // let mut symmetric_key = [0u8; 16];
            // symmetric_key.copy_from_slice(&hash_result[..16]);

// let shared_secret_vec = shared_secret.to_bytes_be();

let hkdf = Hkdf::<Sha256>::new(None, &shared_secret_bytes);

let mut symmetric_key = [0u8; 16];
hkdf.expand(&[], &mut symmetric_key)
    .map_err(|_| CielError::Crypto("HKDF key derivation failed".into()))?;

            let session = Session {
                path: session_path,
                algorithm: SessionAlgorithm::DhIetf1024Aes128CbcPkcs7 {
                    symmetric_key: Zeroizing::new(symmetric_key),
                },
                last_accessed: Instant::now(),
                owner_bus_name,
            };

            // Explicitly cast daemon_pub_bytes to Value<'static> to satisfy return type bounds
            let output_val = Value::from(daemon_pub_bytes).to_owned();

            Ok((session, output_val))
        }

        unsupported => Err(CielError::InvalidSecret(format!(
            "Unsupported session algorithm: '{unsupported}'"
        ))),
    }
}
