//! ============================================================================
//! ciel-keychaind - D-Bus Client Identification & Caller Inspection
//!
//! Inspects incoming D-Bus message headers and queries the session bus broker
//! (`org.freedesktop.DBus`) to resolve caller process identity:
//! - Unique connection name (e.g., `:1.56`)
//! - Process ID (PID)
//! - User ID (UID)
//! - Executable binary path (`/proc/<pid>/exe`)
//! - Desktop Application ID / Command line
//!
//! This information is critical for enforcing granular per-application
//! access control policies.
//! ============================================================================

use crate::error::{CielError, Result};
use std::path::PathBuf;
use tracing::debug;
use zbus::fdo::DBusProxy;
use zbus::names::BusName;
use zbus::Connection;

/// Resolved client identity associated with an incoming D-Bus message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIdentity {
    /// Unique D-Bus connection name assigned by the bus broker (e.g., `:1.42`).
    pub bus_name: String,

    /// UNIX Process ID of the peer process.
    pub pid: u32,

    /// UNIX User ID of the peer process.
    pub uid: u32,

    /// Full canonical path to the executable binary on disk (read from `/proc/<pid>/exe`).
    pub binary_path: Option<PathBuf>,

    /// Command line arguments of the process (from `/proc/<pid>/cmdline`).
    pub cmdline: Option<String>,

    /// Identified desktop application name or executable basename.
    pub app_name: String,
}

impl CallerIdentity {
    /// Returns a human-friendly representation for logging and authorization dialogs.
    pub fn display_label(&self) -> String {
        if let Some(ref path) = self.binary_path {
            if let Some(file_name) = path.file_name() {
                return file_name.to_string_lossy().to_string();
            }
        }
        self.app_name.clone()
    }
}

/// Resolves a D-Bus sender unique name into a concrete [`CallerIdentity`].
///
/// Queries `org.freedesktop.DBus` over the active connection to look up the
/// PID and UID of the sender, then inspects `/proc` on Linux to extract the
/// executable path and process metadata.
pub async fn resolve_caller(
    connection: &Connection,
    sender: Option<&BusName<'_>>,
) -> Result<CallerIdentity> {
    let bus_name = match sender {
        Some(name) => name.to_string(),
        None => {
            return Err(CielError::PolicyDenied(
                "Missing D-Bus sender bus name".into(),
            ))
        }
    };

    let dbus_proxy = DBusProxy::new(connection).await?;

    // Query D-Bus broker for Unix PID
    let pid = dbus_proxy
        .get_connection_unix_process_id(bus_name.as_str().try_into()?)
        .await
        .map_err(|e| CielError::PolicyDenied(format!("Failed to resolve caller PID: {e}")))?;

    // Query D-Bus broker for Unix UID
    let uid = dbus_proxy
        .get_connection_unix_user(bus_name.as_str().try_into()?)
        .await
        .map_err(|e| CielError::PolicyDenied(format!("Failed to resolve caller UID: {e}")))?;

    // Extract executable path from /proc/<pid>/exe
    let exe_path = match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => Some(path),
        Err(e) => {
            debug!("Could not inspect /proc/{pid}/exe: {e}");
            None
        }
    };

    // Extract command line from /proc/<pid>/cmdline
    let cmdline = match std::fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(bytes) => {
            let s = bytes
                .split(|&b| b == 0)
                .filter(|slice| !slice.is_empty())
                .map(|slice| String::from_utf8_lossy(slice))
                .collect::<Vec<_>>()
                .join(" ");
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        Err(_) => None,
    };

    // Derive display application name
    let app_name = exe_path
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| format!("process-{pid}"));

    Ok(CallerIdentity {
        bus_name,
        pid,
        uid,
        binary_path: exe_path,
        cmdline,
        app_name,
    })
}
