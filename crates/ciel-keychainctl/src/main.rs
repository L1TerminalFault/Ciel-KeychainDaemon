//! ============================================================================
//! ciel-keychainctl - Command-Line Administrative Tool for ciel-keychaind
//!
//! Provides CLI management of collections and credentials over session D-Bus:
//! - `list`: Enumerate collections and their current lock status.
//! - `lock [COLLECTION]`: Lock an individual collection or all collections.
//! - `unlock [COLLECTION]`: Unlock a collection via password or prompter.
//! - `search [KEY=VALUE...]`: Query stored items by attributes.
//!
//! ============================================================================

use std::collections::HashMap;
use std::env;
use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

/// D-Bus proxy for root Secret Service interface.
#[proxy(
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets",
    interface = "org.freedesktop.Secret.Service"
)]
trait SecretServiceProxy {
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)>;

    fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;

    fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;

    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    #[zbus(property)]
    fn collections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

/// D-Bus proxy for an individual Collection.
#[proxy(
    default_service = "org.freedesktop.secrets",
    interface = "org.freedesktop.Secret.Collection"
)]
trait CollectionProxy {
    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;

    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;

    #[zbus(property)]
    fn items(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let connection = Connection::session().await?;
    let service = SecretServiceProxyProxy::new(&connection).await?;

    match args[1].as_str() {
        "list" => {
            cmd_list(&connection, &service).await?;
        }
        "lock" => {
            let target = args.get(2).map(|s| s.as_str());
            cmd_lock(&service, target).await?;
        }
        "unlock" => {
            let target = args.get(2).map(|s| s.as_str()).unwrap_or("default");
            cmd_unlock(&service, target).await?;
        }
        "search" => {
            let pairs = &args[2..];
            cmd_search(&service, pairs).await?;
        }
        "help" | "--help" | "-h" => {
            print_usage();
        }
        unknown => {
            eprintln!("Unknown command: '{unknown}'");
            print_usage();
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_usage() {
    println!(
        "ciel-keychainctl - Command-line management for ciel-keychaind\n\n\
        USAGE:\n\
            ciel-keychainctl <COMMAND> [OPTIONS]\n\n\
        COMMANDS:\n\
            list                 List all collections and their lock states\n\
            lock [COLLECTION]    Lock a specific collection (or all if omitted)\n\
            unlock [COLLECTION]  Unlock a collection (default: 'default')\n\
            search [K=V ...]     Search for items matching attribute key-value pairs\n\
            help                 Show this help message"
    );
}

async fn cmd_list(
    connection: &Connection,
    service: &SecretServiceProxyProxy<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let collections = service.collections().await?;
    println!("Collections ({} total):", collections.len());

    for col_path in collections {
        let col = CollectionProxyProxy::builder(connection)
            .path(col_path.clone())?
            .build()
            .await?;

        let label = col.label().await.unwrap_or_else(|_| "Unknown".into());
        let locked = col.locked().await.unwrap_or(true);
        let items = col.items().await.unwrap_or_default();

        let status = if locked { "[LOCKED]" } else { "[UNLOCKED]" };
        println!(
            "  • {:<12} {:<24} ({} items) - {}",
            status,
            label,
            items.len(),
            col_path
        );
    }

    Ok(())
}

async fn cmd_lock(
    service: &SecretServiceProxyProxy<'_>,
    target: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let objects = match target {
        Some(name) => {
            let path = if name.starts_with('/') {
                OwnedObjectPath::try_from(name)?
            } else {
                service.read_alias(name).await?
            };
            vec![path]
        }
        None => service.collections().await?,
    };

    let (locked, _) = service.lock(objects).await?;
    println!("Successfully locked {} collection(s).", locked.len());
    Ok(())
}

async fn cmd_unlock(
    service: &SecretServiceProxyProxy<'_>,
    target: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = if target.starts_with('/') {
        OwnedObjectPath::try_from(target)?
    } else {
        service.read_alias(target).await?
    };

    println!("Requesting unlock for '{}'...", path);
    let (unlocked, _) = service.unlock(vec![path]).await?;
    if unlocked.is_empty() {
        println!("Unlock operation pending prompt or was cancelled.");
    } else {
        println!("Successfully unlocked collection.");
    }

    Ok(())
}

async fn cmd_search(
    service: &SecretServiceProxyProxy<'_>,
    pairs: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut attributes = HashMap::new();
    for pair in pairs {
        if let Some((k, v)) = pair.split_once('=') {
            attributes.insert(k.to_string(), v.to_string());
        }
    }

    let (unlocked_items, locked_items) = service.search_items(attributes).await?;
    println!(
        "Search results: {} unlocked, {} locked",
        unlocked_items.len(),
        locked_items.len()
    );

    for item in unlocked_items {
        println!("  [Unlocked] {}", item);
    }
    for item in locked_items {
        println!("  [Locked]   {}", item);
    }

    Ok(())
}
