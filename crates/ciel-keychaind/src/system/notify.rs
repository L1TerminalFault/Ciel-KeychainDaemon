//! ============================================================================
//! ciel-keychaind - Systemd Readiness Notification (sd_notify)
//!
//! Implements the systemd service readiness protocol over a UNIX datagram socket:
//! - Inspects the `$NOTIFY_SOCKET` environment variable provided by systemd.
//! - Emits `READY=1` when initialization and D-Bus name acquisition are complete.
//! - Emits `STOPPING=1` during graceful shutdown.
//! - Pure-Rust implementation using standard UNIX datagram sockets without libsystemd.
//! ============================================================================

use std::os::unix::net::UnixDatagram;
use tracing::debug;

/// Signals systemd that the daemon has completed startup and is ready to process requests.
pub fn sd_notify_ready() {
    notify("READY=1\nSTATUS=Ready and serving org.freedesktop.secrets\n");
}

/// Signals systemd that the daemon has begun graceful shutdown.
pub fn sd_notify_stopping() {
    notify("STOPPING=1\nSTATUS=Shutting down and locking keyrings\n");
}

/// Sends a status update message to systemd.
pub fn sd_notify_status(status: &str) {
    notify(&format!("STATUS={status}\n"));
}

/// Transmits a notification payload string to the socket specified in `$NOTIFY_SOCKET`.
fn notify(msg: &str) {
    if let Ok(socket_path) = std::env::var("NOTIFY_SOCKET") {
        if socket_path.is_empty() {
            return;
        }

        let socket_addr = if let Some(abstract_path) = socket_path.strip_prefix('@') {
            // Linux abstract socket namespace begins with a null byte
            format!("\0{abstract_path}")
        } else {
            socket_path
        };

        match UnixDatagram::unbound() {
            Ok(sock) => {
                if let Err(e) = sock.send_to(msg.as_bytes(), &socket_addr) {
                    debug!("Failed to send sd_notify state: {e}");
                } else {
                    debug!("Sent sd_notify: {:?}", msg.trim());
                }
            }
            Err(e) => {
                debug!("Failed to create datagram socket for sd_notify: {e}");
            }
        }
    }
}
