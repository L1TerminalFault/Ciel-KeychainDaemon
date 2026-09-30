# secretd PAM Authentication & Session Flow

1. **Authentication (`pam_sm_authenticate`)**:
   - Grabs user password via `pam_get_item(pamh, PAM_AUTHTOK)`.
   - Stores it temporarily in zeroizing memory inside the PAM handle.

2. **Session Open (`pam_sm_open_session`)**:
   - Triggered after user login session and `$XDG_RUNTIME_DIR` are established.
   - Connects to `$XDG_RUNTIME_DIR/secretd/pam.sock`.
   - Sends `PamMessage::UnlockLoginKeyring { password }`.
   - The daemon unlocks the `login` collection.
   - Clears password from PAM handle memory.

3. **Password Change (`pam_sm_chauthtok`)**:
   - Captures both old and new password.
   - Sends `PamMessage::ChangePassword { old_password, new_password }`.
   - The daemon re-encrypts the vault master key under the new password.
