//! ============================================================================
//! ciel-keychaind - Private PAM IPC Socket Server
//!
//! Listens for incoming authentication tokens delivered by `pam_ciel_keychaind.so`:
//! - Binds to `$XDG_RUNTIME_DIR/ciel-keychaind/pam.sock` with POSIX permissions `0600`.
//! - Peer Authentication: Queries `SO_PEERCRED` on the UNIX domain socket.
//!   Accepts connections ONLY from `UID 0` (display managers / PAM auth stacks)
//!   or the current process's own `UID`.
//! - Enforces memory zeroization on incoming password buffers immediately upon handling.
//! ============================================================================

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::core::keyring::KeyringManager;
use crate::error::{CielError, Result};

/// Message type identifier sent over the wire by `pam_ciel_keychaind.so`.
#[repr(u8)]
pub enum PamOpcode {
    Unlock = 1,
    ChangePassword = 2,
}

/// Starts the PAM IPC server on the specified UNIX domain socket path.
pub async fn start_pam_server(
    socket_path: PathBuf,
    keyring_manager: Arc<KeyringManager>,
) -> Result<()> {
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    if let Some(parent) = socket_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let listener = UnixListener::bind(&socket_path).map_err(|e| {
        CielError::Ipc(format!(
            "Failed to bind PAM socket at {}: {e}",
            socket_path.display()
        ))
    })?;

    // Set socket permissions strictly to 0600 (read/write by owner only)
    if let Ok(metadata) = std::fs::metadata(&socket_path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o600);
        let _ = std::fs::set_permissions(&socket_path, permissions);
    }

    info!("PAM IPC listener active at {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let km = Arc::clone(&keyring_manager);
                tokio::spawn(async move {
                    if let Err(e) = handle_pam_connection(stream, km).await {
                        warn!("PAM IPC client transaction error: {e}");
                    }
                });
            }
            Err(e) => {
                error!("Error accepting PAM socket connection: {e}");
            }
        }
    }
}

/// Handles an individual incoming PAM IPC connection.
async fn handle_pam_connection(
    mut stream: UnixStream,
    keyring_manager: Arc<KeyringManager>,
) -> Result<()> {
    // Verify peer credentials via SO_PEERCRED
    verify_peer_credentials(&stream)?;

    // Read 4-byte payload length prefix (big-endian)
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let payload_len = u32::from_be_bytes(len_buf) as usize;

    if payload_len == 0 || payload_len > 8192 {
        return Err(CielError::Ipc(format!(
            "Invalid PAM message size: {payload_len} bytes"
        )));
    }

    // Read payload directly into zeroizing buffer
    let mut payload = Zeroizing::new(vec![0u8; payload_len]);
    stream.read_exact(&mut payload).await?;

    let opcode = payload[0];
    let body = &payload[1..];

    let success = match opcode {
        1 => {
            // Opcode 1: Unlock collection (body format: [collection_id\0][password])
            if let Some(null_pos) = body.iter().position(|&b| b == 0) {
                let collection_id = String::from_utf8_lossy(&body[..null_pos]).to_string();
                let password = &body[null_pos + 1..];
                debug!(
                    "Received PAM unlock request for collection '{}'",
                    collection_id
                );
                keyring_manager
                    .unlock_with_passphrase(&collection_id, password)
                    .await
                    .is_ok()
            } else {
                false
            }
        }
        2 => {
            // Opcode 2: Password change notification
            info!("Received PAM password change event");
            true
        }
        _ => {
            warn!("Unknown PAM opcode: {opcode}");
            false
        }
    };

    // Send single-byte response: 1 for success, 0 for failure
    let resp = [if success { 1u8 } else { 0u8 }];
    stream.write_all(&resp).await?;
    stream.flush().await?;

    Ok(())
}

/// Validates caller's POSIX credentials over the UNIX socket via `SO_PEERCRED`.
fn verify_peer_credentials(stream: &UnixStream) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let mut ucred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;

        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut ucred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };

        if ret != 0 {
            return Err(CielError::Ipc(format!(
                "Failed to query SO_PEERCRED: {}",
                std::io::Error::last_os_error()
            )));
        }

        let my_uid = unsafe { libc::getuid() };
        // Permit peer if peer is root (UID 0) or matches daemon UID
        if ucred.uid != 0 && ucred.uid != my_uid {
            return Err(CielError::PolicyDenied(format!(
                "Unauthorized PAM peer UID: {} (expected 0 or {})",
                ucred.uid, my_uid
            )));
        }
    }

    Ok(())
}
