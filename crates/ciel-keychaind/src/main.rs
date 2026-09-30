//! ============================================================================
//! ciel-keychaind - Secure Secret Service Daemon
//!
//! A hardened, modern replacement for gnome-keyring-daemon adhering strictly to
//! the FreeDesktop Secret Service specification (org.freedesktop.secrets).
//!
//! Startup Sequence:
//! 1. Apply OS-level process hardening (prctl PR_SET_DUMPABLE, mlockall)
//! 2. Initialize tracing and structured logging
//! 3. Load configuration and ensure secure directory permissions (0700)
//! 4. Initialize in-memory core keyring state and auto-lock coordinator
//! 5. Spawn background PAM IPC socket listener for password unlock
//! 6. Spawn systemd-logind sleep/lock monitor
//! 7. Establish D-Bus session bus connection and acquire `org.freedesktop.secrets`
//! 8. Signal readiness via sd_notify (READY=1)
//! 9. Graceful shutdown on SIGTERM / SIGINT with zeroization of memory
//!
//! ============================================================================

pub mod config;
pub mod core;
pub mod crypto;
pub mod dbus;
pub mod error;
pub mod hardening;
pub mod ipc;
pub mod prompt;
pub mod storage;
pub mod system;

use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing::{error, info, warn};

use crate::config::Config;
use crate::core::keyring::KeyringManager;
use crate::error::Result;

// use crate::storage::VaultStorage;
// use std::path::PathBuf;

// #[tokio::main]
// async fn main() -> Result<()> {
//     // Step 1: Enforce kernel-level process and memory hardening immediately.
//     // Disables ptrace/core dumps and locks memory to prevent paging secrets to swap.
//     if let Err(e) = hardening::apply_process_hardening() {
//         eprintln!("[ciel-keychaind FATAL] Failed to enforce process hardening: {e}");
//         std::process::exit(1);
//     }
//
//     // Step 2: Initialize structured logging with environment filter support.
//     tracing_subscriber::fmt()
//         .with_env_filter(
//             tracing_subscriber::EnvFilter::try_from_default_env()
//                 .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
//         )
//         .with_target(false)
//         .init();
//
//     info!("Starting ciel-keychaind daemon (FreeDesktop Secret Service)");
//
//     // Step 3: Load configuration settings and verify runtime/storage directories.
//     let config = match Config::load() {
//         Ok(cfg) => cfg,
//         Err(e) => {
//             error!("Failed to load configuration: {e}");
//             std::process::exit(1);
//         }
//     };
//     info!("Vault storage path: {}", config.vault_dir.display());
//     info!("PAM IPC socket path: {}", config.pam_socket_path.display());
//
//     // Step 3.5: Initialize Vault Storage
//     let vault_storage = Arc::new(crate::storage::VaultStorage::new(config.vault_dir.clone()));
//
//     // Step 4: Initialize the core in-memory keyring manager with persistence.
//     let keyring_manager = Arc::new(
//         KeyringManager::new(config.clone(), vault_storage).await?
//     );
//
//     // Step 5: Spawn background PAM IPC listener on private UNIX domain socket.
//     let pam_keyring_manager = Arc::clone(&keyring_manager);
//     let pam_socket_path = config.pam_socket_path.clone();
//     tokio::spawn(async move {
//         if let Err(e) = ipc::server::start_pam_server(pam_socket_path, pam_keyring_manager).await {
//             error!("PAM IPC server error: {e}");
//         }
//     });
//
//     // Step 6: Spawn systemd-logind sleep/lock monitor.
//     let logind_keyring_manager = Arc::clone(&keyring_manager);
//     let logind_config = config.clone();
//     tokio::spawn(async move {
//         if let Err(e) =
//             system::logind::watch_logind_events(logind_keyring_manager, logind_config).await
//         {
//             warn!("Logind event monitor error: {e}");
//         }
//     });
//
//     // Step 7: Establish D-Bus connection, export Secret Service interfaces,
//     // and acquire the well-known bus name `org.freedesktop.secrets`.
//     let dbus_keyring_manager = Arc::clone(&keyring_manager);
//     let dbus_handle = dbus::init_dbus_service(dbus_keyring_manager, &config).await?;
//
//     // Step 8: Notify systemd that the daemon is ready to service client requests.
//     system::notify::sd_notify_ready();
//     info!("ciel-keychaind successfully initialized and serving org.freedesktop.secrets");
//
//     // Step 9: Listen for termination signals (SIGINT / SIGTERM) for graceful cleanup.
//     let mut sigint = signal(SignalKind::interrupt())?;
//     let mut sigterm = signal(SignalKind::terminate())?;
//
//     tokio::select! {
//         _ = sigint.recv() => {
//             info!("Received SIGINT, initiating graceful shutdown...");
//         }
//         _ = sigterm.recv() => {
//             info!("Received SIGTERM, initiating graceful shutdown...");
//         }
//         res = dbus_handle => {
//             if let Err(e) = res {
//                 error!("D-Bus service terminated unexpectedly: {e}");
//             }
//         }
//     }
//
//     // Step 10: Perform graceful shutdown, locking all vaults and cleaning runtime socket.
//     info!("Locking all keyrings and clearing cryptographic material...");
//     keyring_manager.lock_all().await;
//
//     if config.pam_socket_path.exists() {
//         let _ = std::fs::remove_file(&config.pam_socket_path);
//     }
//
//     info!("ciel-keychaind daemon stopped cleanly.");
//     Ok(())
// }

// use std::sync::Arc;
// use tokio::signal::unix::{signal, SignalKind};
// use tracing::{error, info, warn};

// use ciel_keychaind::config::Config;
// use ciel_keychaind::core::keyring::KeyringManager;
// use ciel_keychaind::dbus;
// use ciel_keychaind::hardening;
// use ciel_keychaind::ipc;
use crate::storage::vault::VaultStorage;
// use ciel_keychaind::system;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Step 1: Enforce kernel-level process and memory hardening immediately.
    // Disables ptrace/core dumps and locks memory to prevent paging secrets to swap.
    if let Err(e) = hardening::apply_process_hardening() {
        eprintln!("[ciel-keychaind FATAL] Failed to enforce process hardening: {e}");
        std::process::exit(1);
    }
    // Step 2: Initialize structured logging with environment filter support.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    info!("Starting ciel-keychaind daemon (FreeDesktop Secret Service)");

    // Step 3: Load configuration settings and verify runtime/storage directories.
    let config = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to load configuration: {e}");
            std::process::exit(1);
        }
    };
    info!("Vault storage path: {}", config.vault_dir.display());
    info!("PAM IPC socket path: {}", config.pam_socket_path.display());

    // Step 3.5: Initialize Vault Storage
    let vault_storage = Arc::new(VaultStorage::new(config.vault_dir.clone()));

    // Step 4: Initialize the core in-memory keyring manager with persistence.
    let keyring_manager = Arc::new(KeyringManager::new(config.clone(), vault_storage).await?);

    // Step 5: Spawn background PAM IPC listener on private UNIX domain socket.
    let pam_keyring_manager = Arc::clone(&keyring_manager);
    let pam_socket_path = config.pam_socket_path.clone();
    tokio::spawn(async move {
        if let Err(e) = ipc::server::start_pam_server(pam_socket_path, pam_keyring_manager).await {
            error!("PAM IPC server error: {e}");
        }
    });

    // Step 6: Spawn systemd-logind sleep/lock monitor.
    let logind_keyring_manager = Arc::clone(&keyring_manager);
    let logind_config = config.clone();
    tokio::spawn(async move {
        if let Err(e) =
            system::logind::watch_logind_events(logind_keyring_manager, logind_config).await
        {
            warn!("Logind event monitor error: {e}");
        }
    });

    // Step 7: Establish D-Bus connection, export Secret Service interfaces,
    // and acquire the well-known bus name `org.freedesktop.secrets`.
    let dbus_keyring_manager = Arc::clone(&keyring_manager);
    let dbus_handle = dbus::init_dbus_service(dbus_keyring_manager, &config).await?;

    // Step 8: Notify systemd that the daemon is ready to service client requests.
    system::notify::sd_notify_ready();
    info!("ciel-keychaind successfully initialized and serving org.freedesktop.secrets");

    // Step 9: Listen for termination signals (SIGINT / SIGTERM) for graceful cleanup.
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT, initiating graceful shutdown...");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, initiating graceful shutdown...");
        }
        res = dbus_handle => {
            if let Err(e) = res {
                error!("D-Bus service terminated unexpectedly: {e}");
            }
        }
    }

    // Step 10: Perform graceful shutdown, locking all vaults and clearing cryptographic material.
    info!("Locking all keyrings and clearing cryptographic material...");
    keyring_manager.lock_all().await;

    if config.pam_socket_path.exists() {
        let _ = std::fs::remove_file(&config.pam_socket_path);
    }

    info!("ciel-keychaind daemon stopped cleanly.");
    Ok(())
}
