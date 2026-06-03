//! `talkrypt-helper` — run the key-custody helper, listening on the default
//! per-user IPC endpoint until terminated.

use talkrypt_helper::{endpoint, Helper, KeyStore, Result};

#[tokio::main]
async fn main() -> Result<()> {
    let store = KeyStore::new(endpoint::default_store_dir());
    store.ensure_dir().await?;

    #[cfg(unix)]
    {
        let sock = endpoint::default_socket_path();
        let listener = endpoint::bind(&sock).await?;
        eprintln!(
            "talkrypt-helper: listening at {} (owner-only). Reuses the audited \
             talkrypt core; NOT certified or audited.",
            sock.display()
        );
        Helper::new(store).serve(listener).await
    }

    #[cfg(not(unix))]
    {
        let _ = store;
        Err(talkrypt_helper::HelperError::Unsupported(
            "talkrypt-helper currently supports the Unix-socket transport only; \
             the Windows Named-Pipe transport awaits SDDL/SID ACL hardening",
        ))
    }
}
