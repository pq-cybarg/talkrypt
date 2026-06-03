//! The local IPC endpoint: an owner-only Unix socket (macOS/Linux) or an
//! ACL'd Named Pipe (Windows). Default locations match `docs/ROADMAP.md`.
//!
//! The endpoint *is* the confidentiality boundary for in-flight secrets, so its
//! access control matters: on Unix the socket is bound in an owner-only
//! directory and `chmod 0600`; on Windows it must carry an SDDL ACL restricting
//! access to the current user's SID (see the Windows note below).

use std::path::PathBuf;
#[cfg(unix)]
use std::path::Path;

use crate::error::Result;

/// Default base directory for the helper's runtime + stored keys.
pub fn default_base_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join("Library/Application Support/talkrypt");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        // Prefer the per-user, 0700 runtime dir; fall back to a private temp dir.
        if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR") {
            return PathBuf::from(xdg).join("talkrypt");
        }
    }
    #[cfg(windows)]
    {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local).join("talkrypt");
        }
    }
    std::env::temp_dir().join("talkrypt")
}

/// Default socket path (Unix) — `<base>/helper.sock`.
pub fn default_socket_path() -> PathBuf {
    default_base_dir().join("helper.sock")
}

/// Default key-store directory — `<base>/keys`.
pub fn default_store_dir() -> PathBuf {
    default_base_dir().join("keys")
}

#[cfg(unix)]
mod imp {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::{UnixListener, UnixStream};

    /// Bind an owner-only listening socket at `path`, creating its parent dir
    /// (0700) and removing any stale socket first.
    pub async fn bind(path: &Path) -> Result<UnixListener> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        // Remove a stale socket from a previous run (ignore if absent).
        match tokio::fs::remove_file(path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(listener)
    }

    pub async fn connect(path: &Path) -> Result<UnixStream> {
        Ok(UnixStream::connect(path).await?)
    }
}

#[cfg(unix)]
pub use imp::{bind, connect};

// ----- Windows: Named Pipe with an SDDL ACL bound to the current SID -----
//
// See `winpipe`. The pipe is created with a security descriptor granting access
// only to the current user's SID + SYSTEM, so it is NOT the insecure default
// pipe. The ACL's *enforcement* must still be validated on real Windows (Wine
// does not faithfully enforce security descriptors).
#[cfg(windows)]
pub fn default_pipe_name() -> Result<String> {
    Ok(crate::sddl::pipe_name_for_sid(&crate::winpipe::current_user_sid()?))
}

#[cfg(windows)]
pub async fn connect(
    name: &str,
) -> Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    crate::winpipe::connect(name).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_under_a_talkrypt_dir() {
        let sock = default_socket_path();
        assert!(sock.ends_with("helper.sock"));
        assert!(default_store_dir().ends_with("keys"));
        // base dir component is "talkrypt"
        assert!(default_base_dir()
            .components()
            .any(|c| c.as_os_str() == "talkrypt"));
    }
}
