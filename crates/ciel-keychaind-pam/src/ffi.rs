//! ============================================================================
//! ciel-keychaind-pam - Linux PAM C-FFI Bindings
//!
//! Encapsulates unsafe PAM C API declarations and constant values:
//! - Item identifiers (`PAM_AUTHTOK`, `PAM_OLDAUTHTOK`, `PAM_USER`).
//! - Status return codes (`PAM_SUCCESS`, `PAM_AUTH_ERR`, `PAM_IGNORE`).
//! - Function prototypes for `pam_get_item`, `pam_get_user`.
//!
//! ============================================================================

use libc::{c_char, c_int, c_void};
use std::ffi::CStr;

/// Opaque PAM transaction handle.
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

// PAM Return Codes
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_AUTH_ERR: c_int = 7;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_IGNORE: c_int = 25;
pub const PAM_SERVICE_ERR: c_int = 3;

// PAM Item Types
pub const PAM_SERVICE: c_int = 1;
pub const PAM_USER: c_int = 2;
pub const PAM_TTY: c_int = 3;
pub const PAM_RHOST: c_int = 4;
pub const PAM_CONV: c_int = 5;
pub const PAM_AUTHTOK: c_int = 6;
pub const PAM_OLDAUTHTOK: c_int = 7;
pub const PAM_RUSER: c_int = 8;
pub const PAM_USER_PROMPT: c_int = 9;

// PAM Flags
pub const PAM_SILENT: c_int = 0x8000;
pub const PAM_PRELIM_CHECK: c_int = 0x4000;
pub const PAM_UPDATE_AUTHTOK: c_int = 0x2000;

extern "C" {
    pub fn pam_get_item(
        pamh: *const PamHandle,
        item_type: c_int,
        item: *mut *const c_void,
    ) -> c_int;

    pub fn pam_get_user(
        pamh: *const PamHandle,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

/// Safely retrieves the target username for the current PAM transaction.
pub fn get_user(pamh: *const PamHandle) -> Result<String, c_int> {
    let mut user_ptr: *const c_char = std::ptr::null();
    let status = unsafe { pam_get_user(pamh, &mut user_ptr, std::ptr::null()) };
    if status != PAM_SUCCESS || user_ptr.is_null() {
        return Err(status);
    }
    let username = unsafe { CStr::from_ptr(user_ptr) }
        .to_string_lossy()
        .into_owned();
    Ok(username)
}

/// Safely retrieves the authentication token (passphrase) from the PAM transaction.
pub fn get_auth_token(pamh: *const PamHandle, item_type: c_int) -> Result<Vec<u8>, c_int> {
    let mut item_ptr: *const c_void = std::ptr::null();
    let status = unsafe { pam_get_item(pamh, item_type, &mut item_ptr) };
    if status != PAM_SUCCESS || item_ptr.is_null() {
        return Err(status);
    }
    let pass_cstr = unsafe { CStr::from_ptr(item_ptr as *const c_char) };
    Ok(pass_cstr.to_bytes().to_vec())
}
