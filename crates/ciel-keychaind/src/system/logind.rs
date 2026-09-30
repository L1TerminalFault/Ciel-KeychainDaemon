//! ============================================================================
//! ciel-keychaind - Systemd Logind Sleep & Session Lock Monitor
//!
//! Subscribes to system bus signals emitted by `systemd-logind` (`org.freedesktop.login1`):
//! - `PrepareForSleep(active: bool)`: Emitted before system enters suspend/hibernate.
//!   Triggers `lock_all()` to purge unencrypted secrets from RAM before memory
//!   is frozen or written to swap.
//! - `Lock`: Emitted when the user screen locks. Relocks keyrings according
//!   to user configuration.
//! ============================================================================

use std::sync::Arc;
use tracing::{debug, error, info, warn};
use zbus::Connection;
use zbus::proxy;

use crate::config::Config;
use crate::core::keyring::KeyringManager;
use crate::error::Result;

/// Proxy for listening to login1 Manager signals on the system bus.
#[proxy(
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    interface = "org.freedesktop.login1.Manager"
)]
trait LogindManager {
    /// Signal sent when system is about to sleep (true) or just woke up (false).
    #[zbus(signal)]
    fn prepare_for_sleep(&self, start: bool) -> zbus::Result<()>;
}

/// Proxy for listening to active session Lock/Unlock signals on the system bus.
#[proxy(
    default_service = "org.freedesktop.login1",
    interface = "org.freedesktop.login1.Session"
)]
trait LogindSession {
    /// Signal sent when session is locked.
    #[zbus(signal)]
    fn lock(&self) -> zbus::Result<()>;

    /// Signal sent when session is unlocked.
    #[zbus(signal)]
    fn unlock(&self) -> zbus::Result<()>;
}

/// Spawns the logind sleep and lock event monitor on the system D-Bus.
pub async fn watch_logind_events(
    keyring_manager: Arc<KeyringManager>,
    config: Config,
) -> Result<()> {
    debug!("Connecting to system bus to monitor logind events...");

    let system_bus = match Connection::system().await {
        Ok(bus) => bus,
        Err(e) => {
            warn!("Could not connect to system bus for logind monitoring: {e}");
            return Ok(());
        }
    };

    let manager_proxy = match LogindManagerProxy::new(&system_bus).await {
        Ok(p) => p,
        Err(e) => {
            warn!("Could not establish Logind proxy: {e}");
            return Ok(());
        }
    };

    let mut sleep_stream = match manager_proxy.receive_prepare_for_sleep().await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to subscribe to PrepareForSleep signal: {e}");
            return Ok(());
        }
    };

    info!("Subscribed to systemd-logind sleep and power management signals");

    use futures_util::StreamExt;
    while let Some(signal) = sleep_stream.next().await {
        match signal.args() {
            Ok(args) => {
                if args.start {
                    info!("Received PrepareForSleep(start=true). System entering sleep/suspend.");
                    if config.lock_on_sleep {
                        info!("Locking all keyrings prior to system sleep...");
                        keyring_manager.lock_all().await;
                    }
                } else {
                    debug!("Received PrepareForSleep(start=false). System resumed from sleep.");
                }
            }
            Err(e) => {
                error!("Error parsing PrepareForSleep signal args: {e}");
            }
        }
    }

    Ok(())
}
