# secretd Threat Model & Hardening

1. **Unprivileged Co-tenant Processes (same UID)**:
   - `prctl(PR_SET_DUMPABLE, 0)`: Disables ptrace and /proc/$PID/mem access from non-root.
   - `mlockall(MCL_CURRENT | MCL_FUTURE)`: Prevents unlocked secrets from swapping to disk.
   - Zeroization: Drops zero memory holding keys and secrets immediately.
   - Socket security: `SO_PEERCRED` checks on Unix sockets enforce same-UID communication.

2. **D-Bus Eavesdropping**:
   - Implements Secret Service transport encryption (`dh-ietf1024-sha256-aes128-cbc-pkcs7`).
   - Secrets are never transmitted in plaintext over the session bus unless explicitly requested under the plain transport algorithm.

3. **Storage At Rest**:
   - Master key protected via Argon2id with 64 MiB memory cost.
   - Atomicity: File replacement uses temporary file write + `rename` + parent directory `fsync`.
