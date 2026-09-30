//! ============================================================================
//! ciel-keychaind-pam - Pluggable Authentication Module (PAM)
//!
//! Shared object library (`pam_ciel_keychaind.so`) integrated into `/etc/pam.d/*`:
//! - Intercepts user passphrases at login (`pam_sm_open_session`).
//! - Automatically unlocks the primary `login` keyring in the background.
//! - Propagates password modifications (`pam_sm_chauthtok`).
//! - Guaranteed zeroization: plaintext credentials are scrubbed immediately.
//!
//! ============================================================================

pub mod client;
pub mod ffi;

use libc::{c_char, c_int};
use zeroize::Zeroizing;

use crate::ffi::*;

/// PAM authentication hook: captures authentication tokens if required.
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// PAM credential management hook: no-op.
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// PAM session opening hook: forwards login credentials to unlock `ciel-keychaind`.
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(
    pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    let username = match ffi::get_user(pamh) {
        Ok(u) => u,
        Err(_) => return PAM_SUCCESS,
    };

    let password = match ffi::get_auth_token(pamh, PAM_AUTHTOK) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => return PAM_SUCCESS,
    };

    if !password.is_empty() {
        let _ = client::send_unlock(&username, password);
    }

    // Always succeed so a secret daemon failure does not block login
    PAM_SUCCESS
}

/// PAM session closing hook: no-op.
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(
    _pamh: *const PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// PAM password changing hook: synchronizes new passwords with the daemon.
/// # Safety
#[no_mangle]
pub unsafe extern "C" fn pam_sm_chauthtok(
    pamh: *const PamHandle,
    flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    if (flags & PAM_PRELIM_CHECK) != 0 {
        return PAM_SUCCESS;
    }

    let username = match ffi::get_user(pamh) {
        Ok(u) => u,
        Err(_) => return PAM_SUCCESS,
    };

    let old_pass = match ffi::get_auth_token(pamh, PAM_OLDAUTHTOK) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => Zeroizing::new(Vec::new()),
    };

    let new_pass = match ffi::get_auth_token(pamh, PAM_AUTHTOK) {
        Ok(p) => Zeroizing::new(p),
        Err(_) => return PAM_SUCCESS,
    };

    if !new_pass.is_empty() {
        let _ = client::send_password_change(&username, old_pass, new_pass);
    }

    PAM_SUCCESS
}
