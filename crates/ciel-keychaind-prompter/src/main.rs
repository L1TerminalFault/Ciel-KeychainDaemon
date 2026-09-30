//! ============================================================================
//! ciel-keychaind-prompter - Prompter Binary Entry Point
//!
//! Independent user interface process for presenting graphical authentication
//! and application authorization dialogs on behalf of the `ciel-keychaind` daemon:
//! 1. Disables process core dumps (`PR_SET_DUMPABLE = 0`).
//! 2. Initializes structured logging.
//! 3. Mounts `org.freedesktop.secrets.Prompter` on the session D-Bus.
//! 4. Handles interactive user dialogs with automatic idle shutdown.
//!
//! ============================================================================

pub mod dbus;

use tracing::info;
use zbus::connection::Builder;

use crate::dbus::PrompterService;

const PROMPTER_BUS_NAME: &str = "org.freedesktop.secrets.Prompter";
const PROMPTER_OBJECT_PATH: &str = "/org/freedesktop/secrets/prompter";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Disable core dumps and ptrace attachment for security
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("Starting ciel-keychaind-prompter GUI helper...");

    // Mount D-Bus prompter interface and acquire well-known name
    let _conn = Builder::session()?
        .name(PROMPTER_BUS_NAME)?
        .serve_at(PROMPTER_OBJECT_PATH, PrompterService::new())?
        .build()
        .await?;

    info!("ciel-keychaind-prompter serving on {}", PROMPTER_BUS_NAME);

    // Keep running until SIGINT/SIGTERM
    tokio::signal::ctrl_c().await?;
    info!("ciel-keychaind-prompter exiting cleanly");
    Ok(())
}
