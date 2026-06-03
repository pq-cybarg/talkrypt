//! Linux **Secret Service** backend for the `OsKeystore` custody tier.
//!
//! Stores a secret as a Secret Service item (the desktop standard, served by
//! gnome-keyring / KWallet over D-Bus) keyed by `service=talkrypt-helper,
//! account=<name>`. The keyring is encrypted at rest by the desktop and unlocked
//! at login — so, like the macOS Keychain tier, there is no app-held passphrase.
//!
//! Uses the pure-Rust `zbus`/`secret-service` backend (no system libdbus), and
//! the session-encrypted (`EncryptionType::Dh`) transport so the secret is not
//! sent in cleartext over the bus. Validated in a Linux container with a
//! `gnome-keyring` daemon (emulators give no fidelity here — this is real Linux).

use std::collections::HashMap;

use secret_service::{EncryptionType, SecretService};

use crate::error::{HelperError, Result};

const SERVICE: &str = "talkrypt-helper";
const CONTENT_TYPE: &str = "application/octet-stream";

fn attrs(name: &str) -> HashMap<&str, &str> {
    HashMap::from([("service", SERVICE), ("account", name)])
}

async fn service() -> Result<SecretService<'static>> {
    SecretService::connect(EncryptionType::Dh)
        .await
        .map_err(|_| HelperError::Keychain)
}

/// Store (or replace) `secret` for `name` in the default collection.
pub async fn set(name: &str, secret: &[u8]) -> Result<()> {
    let ss = service().await?;
    let collection = ss
        .get_default_collection()
        .await
        .map_err(|_| HelperError::Keychain)?;
    collection
        .create_item(
            &format!("{SERVICE}:{name}"),
            attrs(name),
            secret,
            true, // replace an existing item with the same attributes
            CONTENT_TYPE,
        )
        .await
        .map_err(|_| HelperError::Keychain)?;
    Ok(())
}

/// Fetch the secret for `name`. `NotFound` if no matching item.
pub async fn get(name: &str) -> Result<Vec<u8>> {
    let ss = service().await?;
    let found = ss
        .search_items(attrs(name))
        .await
        .map_err(|_| HelperError::Keychain)?;
    // Prefer an already-unlocked item; otherwise unlock a locked match.
    if let Some(item) = found.unlocked.into_iter().next() {
        return item.get_secret().await.map_err(|_| HelperError::Keychain);
    }
    if let Some(item) = found.locked.into_iter().next() {
        item.unlock().await.map_err(|_| HelperError::Keychain)?;
        return item.get_secret().await.map_err(|_| HelperError::Keychain);
    }
    Err(HelperError::NotFound)
}

/// Delete every item matching `name` (no error if none).
pub async fn delete(name: &str) -> Result<()> {
    let ss = service().await?;
    let found = ss
        .search_items(attrs(name))
        .await
        .map_err(|_| HelperError::Keychain)?;
    for item in found.unlocked.into_iter().chain(found.locked) {
        item.delete().await.map_err(|_| HelperError::Keychain)?;
    }
    Ok(())
}

// Note: tests run inside the Linux container harness (`docs/` Docker recipe),
// not in the host `cargo test`, because they need a live Secret Service daemon.
