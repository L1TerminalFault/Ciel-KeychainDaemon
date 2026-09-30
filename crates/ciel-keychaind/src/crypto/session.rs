//! ============================================================================
//! ciel-keychaind - Transport Session Cryptography (DH-1024 & AES-128-CBC)
//!
//! Provides the mathematical and cryptographic primitives for FreeDesktop
//! Secret Service session transport encryption:
//! - Diffie-Hellman Key Agreement: RFC 2409 / RFC 3526 1024-bit MODP Group 2.
//! - Key Derivation: SHA-256 truncated to 128 bits.
//! - Symmetric Cipher: AES-128 in CBC mode with PKCS#7 block padding.
//! ============================================================================

use aes::cipher::{block_padding::Pkcs7, BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use num_bigint::{BigRng010, BigUint};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CielError, Result};

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

/// RFC 2409 1024-bit MODP Group 2 Prime.
const DH_PRIME_HEX: &str = "\
FFFFFFFFFFFFFFFFC90FDAA22168C244C4797449394FFC83\
437489C78483CD49790ACCFBCFF777025E244506554E43CA\
613A8BA94A308DEB1D2BE88B3F11E5FFD0ECE1D4DCF1697E\
35DE6DEC8032649779E7B2F686C0153049F5BAF462E52FF8\
62A477432BBCB52F7CA71226526D5CE6279CD0D876305531\
FFD4A22F9FB527961A0CE2CA356B273BF92B7BE88478441A\
E4797823460A2612767F065551B307544654D19058CE0F07\
931B651A08543E78CD0EC69FCD0F84B24C4A37A09BB9F27F\
FF594360CE620211E016C3611C8407B0F0B63A52B533FA8B\
A47DA394FF40E867B44265A7495062955877617E319A7264\
7A0864590A09472303E8FFBFB0CA9FAB42507FAC723FB89E\
AC6A4BD67E144964965B728E2AC47E3E57473E9617145B98\
76420398D2D6818C82B57B4F7FBF6F01FFEBFBC452C7B7FB\
C43478E564E0257B7B8F4A1F77AC64F2E75C3349C0796976\
2F64E0ECB5150842273577326E3914199E123230E73BAFDC\
B4EA49DA36423D7B22C42C99CE37A08B4E0AAC6FE04E0C05\
660F02A3ED8B1FE44A7E83F6597B010857907C48361C2C30\
D57A02056474AC4C2E057A9E583E4774E0FEFFBE0D73C32B\
42E9497535D2EB4C20B02A0B647000B0E12363DD47393437\
7C7F602B8833E43D5337E5D474B2FB420B855222221BEFD5\
A78D55CE62DA741F3E64019185EEB58546CC80E747F24C34\
6F7366C60B00A0C9EE0B6C13C056ACC35F3D14E7BB8D00C7";

const DH_GENERATOR: u32 = 2;

/// Ephemeral Diffie-Hellman Key Pair.
pub struct DhKeyPair {
    private_exp: BigUint,
    public_key: Vec<u8>,
}

impl DhKeyPair {
    /// Generates a new ephemeral Diffie-Hellman keypair using MODP Group 2.
    pub fn generate() -> Result<Self> {
        let prime = BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16)
            .ok_or_else(|| CielError::Crypto("Failed to parse Group 2 DH prime".into()))?;
        let generator = BigUint::from(DH_GENERATOR);

        let mut rng = rand::rng();
        let private_exp = rng.random_biguint_below(&prime);
        let public_num = generator.modpow(&private_exp, &prime);
        let public_key = public_num.to_bytes_be();

        Ok(Self {
            private_exp,
            public_key,
        })
    }

    /// Exposes the generated public key bytes to return to the client.
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Computes the 128-bit shared session key from the client's public key.
    pub fn compute_shared_key(&self, client_pub_bytes: &[u8]) -> Result<Zeroizing<[u8; 16]>> {
        let prime = BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16)
            .ok_or_else(|| CielError::Crypto("Failed to parse Group 2 DH prime".into()))?;

        let client_pub = BigUint::from_bytes_be(client_pub_bytes);
        let shared_secret = client_pub.modpow(&self.private_exp, &prime);
        let shared_bytes = shared_secret.to_bytes_be();

        // Hash shared secret with SHA-256 and truncate to 128 bits
        let mut hasher = Sha256::new();
        hasher.update(&shared_bytes);
        let digest = hasher.finalize();

        let mut key = [0u8; 16];
        key.copy_from_slice(&digest[..16]);

        Ok(Zeroizing::new(key))
    }
}

/// Encrypts plaintext bytes using AES-128-CBC with PKCS#7 padding.
pub fn aes128_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128CbcEnc::new(key.into(), iv.into());
    cipher.encrypt_padded_vec::<Pkcs7>(plaintext)
}

/// Decrypts ciphertext bytes using AES-128-CBC with PKCS#7 unpadding.
pub fn aes128_cbc_decrypt(
    key: &[u8; 16],
    iv: &[u8; 16],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes128CbcDec::new(key.into(), iv.into());
    let plaintext = cipher
        .decrypt_padded_vec::<Pkcs7>(ciphertext)
        .map_err(|e| CielError::InvalidSecret(format!("AES-128-CBC unpadding failed: {e}")))?;

    Ok(Zeroizing::new(plaintext))
}
