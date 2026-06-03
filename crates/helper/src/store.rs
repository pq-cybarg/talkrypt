//! On-disk custody of **already-sealed** key blobs.
//!
//! The store persists opaque ciphertext only — sealing/unsealing happens in the
//! [`crate::server`] dispatch via `talkrypt_server::keystore` (Argon2id +
//! AES-256-GCM). The store never sees a passphrase or plaintext. Files live in
//! an owner-only directory; each file is written owner-read/write.

use std::path::{Path, PathBuf};

use crate::custody::CustodyTier;
use crate::error::{HelperError, Result};

/// Tiered custody of key material. Each key has a one-byte `<name>.tier` marker
/// recording its [`CustodyTier`]; the bytes live in a sealed file
/// (`<name>.sealed`, `SoftwareSealed`) or the OS keychain (`OsKeystore`).
#[derive(Clone)]
pub struct KeyStore {
    dir: PathBuf,
}

impl KeyStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Create the store directory (owner-only on Unix) if needed.
    pub async fn ensure_dir(&self) -> Result<()> {
        tokio::fs::create_dir_all(&self.dir).await?;
        set_owner_only_dir(&self.dir)?;
        Ok(())
    }

    fn sealed_path(&self, name: &str) -> Result<PathBuf> {
        if !valid_name(name) {
            return Err(HelperError::InvalidName);
        }
        Ok(self.dir.join(format!("{name}.sealed")))
    }

    fn tier_path(&self, name: &str) -> Result<PathBuf> {
        if !valid_name(name) {
            return Err(HelperError::InvalidName);
        }
        Ok(self.dir.join(format!("{name}.tier")))
    }

    /// Store `blob` under `name` at `tier`, replacing any existing key.
    ///
    /// For `SoftwareSealed`, `blob` is the already-sealed ciphertext (written to
    /// a file). For `OsKeystore`, `blob` is the secret itself, handed to the OS
    /// keychain (which encrypts at rest). `HardwareBacked` is not yet a backend.
    pub async fn put(&self, name: &str, tier: CustodyTier, blob: &[u8]) -> Result<()> {
        match tier {
            CustodyTier::SoftwareSealed => {
                let path = self.sealed_path(name)?;
                tokio::fs::write(&path, blob).await?;
                set_owner_only_file(&path)?;
            }
            CustodyTier::OsKeystore => keychain_set(name, blob)?,
            CustodyTier::HardwareBacked => {
                return Err(HelperError::Unsupported("hardware-backed custody"))
            }
        }
        let tpath = self.tier_path(name)?;
        tokio::fs::write(&tpath, [tier.tag()]).await?;
        set_owner_only_file(&tpath)?;
        Ok(())
    }

    /// Load `name`, returning its custody tier and the stored bytes (the sealed
    /// ciphertext for `SoftwareSealed`, the secret for `OsKeystore`).
    pub async fn get(&self, name: &str) -> Result<(CustodyTier, Vec<u8>)> {
        let tier = self.tier_of(name).await?;
        let bytes = match tier {
            CustodyTier::SoftwareSealed => match tokio::fs::read(&self.sealed_path(name)?).await {
                Ok(b) => b,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(HelperError::NotFound)
                }
                Err(e) => return Err(e.into()),
            },
            CustodyTier::OsKeystore => keychain_get(name)?,
            CustodyTier::HardwareBacked => {
                return Err(HelperError::Unsupported("hardware-backed custody"))
            }
        };
        Ok((tier, bytes))
    }

    /// The custody tier `name` is stored at, or `NotFound`.
    pub async fn tier_of(&self, name: &str) -> Result<CustodyTier> {
        match tokio::fs::read(&self.tier_path(name)?).await {
            Ok(b) if b.len() == 1 => CustodyTier::from_tag(b[0]),
            Ok(_) => Err(HelperError::NotFound),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(HelperError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete `name` from every backend (no error if absent).
    pub async fn delete(&self, name: &str) -> Result<()> {
        // Best-effort across backends so no copy is left behind.
        remove_if_present(&self.sealed_path(name)?).await?;
        let _ = keychain_delete(name);
        remove_if_present(&self.tier_path(name)?).await?;
        Ok(())
    }
}

async fn remove_if_present(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

// ----- OS keychain routing (macOS today) -----

#[cfg(target_os = "macos")]
fn keychain_set(name: &str, secret: &[u8]) -> Result<()> {
    crate::keychain::set(name, secret)
}
#[cfg(target_os = "macos")]
fn keychain_get(name: &str) -> Result<Vec<u8>> {
    crate::keychain::get(name)
}
#[cfg(target_os = "macos")]
fn keychain_delete(name: &str) -> Result<()> {
    crate::keychain::delete(name)
}

#[cfg(not(target_os = "macos"))]
fn keychain_set(_name: &str, _secret: &[u8]) -> Result<()> {
    Err(HelperError::Unsupported("OS keychain custody on this platform"))
}
#[cfg(not(target_os = "macos"))]
fn keychain_get(_name: &str) -> Result<Vec<u8>> {
    Err(HelperError::Unsupported("OS keychain custody on this platform"))
}
#[cfg(not(target_os = "macos"))]
fn keychain_delete(_name: &str) -> Result<()> {
    Ok(())
}

/// A name must be a single safe path component — no separators, no `.`/`..`,
/// only `[A-Za-z0-9._-]` — so a request can never escape the store directory.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(unix)]
fn set_owner_only_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

// On non-Unix, directory/file confidentiality relies on the per-user profile
// location and (for the IPC channel) the Named-Pipe ACL; see `endpoint`.
#[cfg(not(unix))]
fn set_owner_only_dir(_path: &Path) -> Result<()> {
    Ok(())
}
#[cfg(not(unix))]
fn set_owner_only_file(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> PathBuf {
        // Unique-enough temp dir without external rng: nanos since boot via the
        // monotonic clock is unavailable in tests deterministically, so derive
        // from a static counter + process id.
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("talkrypt-helper-test-{}-{n}", std::process::id()))
    }

    #[tokio::test]
    async fn software_sealed_put_get_delete_roundtrip() {
        let dir = tmp();
        let store = KeyStore::new(&dir);
        store.ensure_dir().await.unwrap();

        assert!(matches!(store.get("k").await, Err(HelperError::NotFound)));
        store
            .put("k", CustodyTier::SoftwareSealed, b"sealed-bytes")
            .await
            .unwrap();
        assert_eq!(
            store.get("k").await.unwrap(),
            (CustodyTier::SoftwareSealed, b"sealed-bytes".to_vec())
        );
        assert_eq!(store.tier_of("k").await.unwrap(), CustodyTier::SoftwareSealed);
        store.delete("k").await.unwrap();
        assert!(matches!(store.get("k").await, Err(HelperError::NotFound)));
        // delete is idempotent
        store.delete("k").await.unwrap();

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn os_keystore_tier_uses_the_real_keychain() {
        let dir = tmp();
        let store = KeyStore::new(&dir);
        store.ensure_dir().await.unwrap();
        let name = format!("osk{}", std::process::id());

        store
            .put(&name, CustodyTier::OsKeystore, b"in-the-keychain")
            .await
            .unwrap();
        // The tier marker is on disk; the secret is in the keychain (NOT in a
        // sealed file — the OS holds it).
        assert_eq!(store.tier_of(&name).await.unwrap(), CustodyTier::OsKeystore);
        assert!(!store.dir.join(format!("{name}.sealed")).exists());
        assert_eq!(
            store.get(&name).await.unwrap(),
            (CustodyTier::OsKeystore, b"in-the-keychain".to_vec())
        );
        store.delete(&name).await.unwrap();
        assert!(matches!(store.get(&name).await, Err(HelperError::NotFound)));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn name_validation_blocks_traversal() {
        assert!(valid_name("identity"));
        assert!(valid_name("my-key_1.v2"));
        assert!(!valid_name(""));
        assert!(!valid_name("."));
        assert!(!valid_name(".."));
        assert!(!valid_name("a/b"));
        assert!(!valid_name("../escape"));
        assert!(!valid_name("a\\b"));
        assert!(!valid_name("space key"));
    }

    #[tokio::test]
    async fn invalid_name_is_rejected_not_written() {
        let dir = tmp();
        let store = KeyStore::new(&dir);
        store.ensure_dir().await.unwrap();
        assert!(matches!(
            store
                .put("../escape", CustodyTier::SoftwareSealed, b"x")
                .await,
            Err(HelperError::InvalidName)
        ));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
