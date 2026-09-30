//! ============================================================================
//! ciel-keychaind - Process & Memory Hardening Subsystem
//!
//! Enforces OS-level defense-in-depth mitigations:
//! - Disabling core dumps and ptrace memory attachment (`PR_SET_DUMPABLE = 0`)
//! - Preventing memory from swapping to disk (`mlockall(MCL_CURRENT | MCL_FUTURE)`)
//! - Dropping ability to acquire new privileges (`PR_SET_NO_NEW_PRIVS = 1`)
//! - Zeroing core dump resource limits (`RLIMIT_CORE = 0`)
//! ============================================================================

use crate::error::{CielError, Result};
use nix::sys::mman::{mlockall, MlockAllFlags};
use nix::sys::resource::{setrlimit, Resource};
use tracing::{info, warn};

/// Applies kernel and memory isolation guarantees to the running daemon process.
///
/// This function MUST be invoked at the very beginning of process execution
/// before any cryptographic key material or vault passphrases are allocated.
pub fn apply_process_hardening() -> Result<()> {
    // 1. Disable core dumps via rlimit (Resource::RLIMIT_CORE)
    disable_core_dumps()?;

    // 2. Prevent process tracing, ptrace attachments, and /proc/pid/mem access
    disable_dumpable()?;

    // 3. Prevent privilege escalation via execve
    disable_new_privs()?;

    // 4. Lock process virtual address space into RAM to prevent swapping secrets to disk
    lock_process_memory()?;

    info!("Process hardening policies successfully applied");
    Ok(())
}

/// Sets RLIMIT_CORE to 0 to prevent writing unencrypted memory to disk upon crash.
fn disable_core_dumps() -> Result<()> {
    setrlimit(Resource::RLIMIT_CORE, 0, 0)
        .map_err(|e| CielError::Hardening(format!("Failed to set RLIMIT_CORE to 0: {e}")))
}

/// Sets Linux `prctl(PR_SET_DUMPABLE, 0)` to disable ptrace attachment and core dumping.
fn disable_dumpable() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
        if ret != 0 {
            return Err(CielError::Hardening(format!(
                "prctl(PR_SET_DUMPABLE, 0) failed with errno: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Enforces `prctl(PR_SET_NO_NEW_PRIVS, 1)` to prevent child processes or exec transitions
/// from gaining higher privileges.
fn disable_new_privs() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            return Err(CielError::Hardening(format!(
                "prctl(PR_SET_NO_NEW_PRIVS, 1) failed with errno: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Invokes `mlockall(MCL_CURRENT | MCL_FUTURE)` to lock all current and future
/// memory allocations in physical RAM, prohibiting swap-to-disk.
///
/// If `RLIMIT_MEMLOCK` is insufficient, a warning is logged rather than terminating,
/// accommodating non-root user sessions that lack CAP_IPC_LOCK.
fn lock_process_memory() -> Result<()> {
    let flags = MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE;
    match mlockall(flags) {
        Ok(_) => {
            info!(
                "Successfully locked process memory pages with mlockall(MCL_CURRENT | MCL_FUTURE)"
            );
        }
        Err(err) => {
            // In unprivileged user sessions without elevated memlock rlimit, mlockall can return ENOMEM/EPERM
            warn!(
                "mlockall failed ({}). Secret pages will rely on heap-level memguard and zeroization.",
                err
            );
        }
    }
    Ok(())
}
