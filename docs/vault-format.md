# ciel-keychaind Vault Format Specification (v1)

Each collection (e.g. `login.keyring` or custom collections) is stored under:
`$XDG_DATA_HOME/keyrings/<collection-id>.keyring`

## File Header (Unencrypted)

| Field                       | Type       | Size     | Description                                 |
| --------------------------- | ---------- | -------- | ------------------------------------------- |
| Magic bytes                 | `[u8; 8]`  | 8 bytes  | `b"SECRETD1"`                               |
| Version                     | `u32` (BE) | 4 bytes  | `0x00000001`                                |
| KDF Algorithm ID            | `u8`       | 1 byte   | `1` = Argon2id                              |
| Argon2 Memory (m_cost)      | `u32` (BE) | 4 bytes  | 65536 KiB (64 MiB)                          |
| Argon2 Time (t_cost)        | `u32` (BE) | 4 bytes  | 3 passes                                    |
| Argon2 Parallelism (p_cost) | `u32` (BE) | 4 bytes  | 4 lanes                                     |
| Salt                        | `[u8; 32]` | 32 bytes | Cryptographically secure random salt        |
| Master Key Nonce            | `[u8; 24]` | 24 bytes | XChaCha20 nonce for Master Key encryption   |
| Encrypted Master Key        | `[u8; 48]` | 48 bytes | 32-byte Master Key + 16-byte Poly1305 MAC   |
| Payload Nonce               | `[u8; 24]` | 24 bytes | XChaCha20 nonce for Payload encryption      |
| Payload Length              | `u64` (BE) | 8 bytes  | Length of following encrypted payload + MAC |

Total Header Size: 157 bytes.

## Encrypted Payload

Encrypted with XChaCha20-Poly1305 using the 32-byte Master Key.
Decrypted payload contains collection metadata and item entries with their attributes and zeroizable secret values.
