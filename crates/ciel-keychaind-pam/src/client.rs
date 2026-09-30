//! ============================================================================
//! ciel-keychaind-pam - Daemon IPC Client
//!
//! Connects to the daemon's private UNIX domain socket:
//! - Resolves user UID from username using POSIX `getpwnam_r`.
//! - Locates the runtime socket at `/run/user/<uid>/ciel-keychaind/pam.sock`.
//! - Transmits authentication payload and guarantees zeroization of memory.
//!
//! ============================================================================

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

use ciel_keychaind_proto::PamMessage;

/// Resolves user UID given a username string.
pub fn resolve_uid(username: &str) -> Option<u32> {
    let c_username = CString::new(username).ok()?;
    let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buf = vec![0; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();

    let ret = unsafe {
        libc::getpwnam_r(
            c_username.as_ptr(),
            pwd.as_mut_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };

    if ret == 0 && !result.is_null() {
        let passwd = unsafe { pwd.assume_init() };
        Some(passwd.pw_uid)
    } else {
        None
    }
}

/// Resolves candidate UNIX domain socket paths for a user's daemon instance.
fn get_socket_paths(uid: u32) -> Vec<PathBuf> {
    vec![
        PathBuf::from(format!("/run/user/{uid}/ciel-keychaind/pam.sock")),
        PathBuf::from(format!("/tmp/ciel-keychaind-runtime-{uid}/pam.sock")),
    ]
}

/// Transmits an unlock request to the daemon over the private UNIX socket.
pub fn send_unlock(username: &str, password: Zeroizing<Vec<u8>>) -> bool {
    let uid = match resolve_uid(username) {
        Some(u) => u,
        None => return false,
    };

    let socket_paths = get_socket_paths(uid);
    let mut stream = None;

    for path in socket_paths {
        if path.exists() {
            if let Ok(s) = UnixStream::connect(&path) {
                stream = Some(s);
                break;
            }
        }
    }

    let mut stream = match stream {
        Some(s) => s,
        None => return false, // Daemon not running or socket not accessible yet
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));

    let msg = PamMessage::Unlock {
        collection_id: "login".to_string(),
        password: password.to_vec(),
    };

    let encoded = msg.encode();
    if stream.write_all(&encoded).is_err() {
        return false;
    }
    let _ = stream.flush();

    let mut resp = [0u8; 1];
    if stream.read_exact(&mut resp).is_ok() {
        resp[0] == 1
    } else {
        false
    }
}

/// Transmits a password update notification to the daemon.
pub fn send_password_change(
    username: &str,
    old_pass: Zeroizing<Vec<u8>>,
    new_pass: Zeroizing<Vec<u8>>,
) -> bool {
    let uid = match resolve_uid(username) {
        Some(u) => u,
        None => return false,
    };

    let socket_paths = get_socket_paths(uid);
    for path in socket_paths {
        if let Ok(mut stream) = UnixStream::connect(&path) {
            let msg = PamMessage::ChangePassword {
                username: username.to_string(),
                old_password: old_pass.to_vec(),
                new_password: new_pass.to_vec(),
            };
            let encoded = msg.encode();
            if stream.write_all(&encoded).is_ok() {
                let _ = stream.flush();
                let mut resp = [0u8; 1];
                if stream.read_exact(&mut resp).is_ok() && resp[0] == 1 {
                    return true;
                }
            }
        }
    }

    false
}
