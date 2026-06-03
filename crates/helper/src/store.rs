//! On-disk custody of **already-sealed** key blobs.
//!
//! The store persists opaque ciphertext only — sealing/unsealing happens in the
//! [`crate::server`] dispatch via `talkrypt_server::keystore` (Argon2id +
//! AES-256-GCM). The store never sees a passphrase or plaintext. Files live in
//! an owner-only directory; each file is written owner-read/write.

use std::path::{Path, PathBuf};

use crate::error::{HelperError, Result};

/// A directory of sealed key blobs, one file (`<name>.sealed`) per stored key.
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

    fn path(&self, name: &str) -> Result<PathBuf> {
        if !valid_name(name) {
            return Err(HelperError::InvalidName);
        }
        Ok(self.dir.join(format!("{name}.sealed")))
    }

    /// Persist a sealed blob under `name`, replacing any existing one.
    pub async fn put(&self, name: &str, sealed: &[u8]) -> Result<()> {
        let path = self.path(name)?;
        tokio::fs::write(&path, sealed).await?;
        set_owner_only_file(&path)?;
        Ok(())
    }

    /// Load the sealed blob stored under `name`.
    pub async fn get(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.path(name)?;
        match tokio::fs::read(&path).await {
            Ok(b) => Ok(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(HelperError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete `name` (no error if it doesn't exist).
    pub async fn delete(&self, name: &str) -> Result<()> {
        let path = self.path(name)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
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
    async fn put_get_delete_roundtrip() {
        let dir = tmp();
        let store = KeyStore::new(&dir);
        store.ensure_dir().await.unwrap();

        assert!(matches!(store.get("k").await, Err(HelperError::NotFound)));
        store.put("k", b"sealed-bytes").await.unwrap();
        assert_eq!(store.get("k").await.unwrap(), b"sealed-bytes");
        store.delete("k").await.unwrap();
        assert!(matches!(store.get("k").await, Err(HelperError::NotFound)));
        // delete is idempotent
        store.delete("k").await.unwrap();

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
            store.put("../escape", b"x").await,
            Err(HelperError::InvalidName)
        ));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
