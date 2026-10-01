//! `talkrypt-helper` — run the key-custody helper, listening on the default
//! per-user IPC endpoint until terminated.

use talkrypt_helper::{endpoint, harden, Helper, HelperError, KeyStore, Result};

#[tokio::main]
async fn main() -> Result<()> {
    // Baseline, like the CLI: run the power-on self-test (FIPS POST) and apply
    // RAM-capture hardening before touching any key material.
    talkrypt_crypto::ensure_self_tested();
    talkrypt_crypto::ensure_hardened();

    // Opt-in permissive-security hardening (for a host running with SIP/AMFI
    // relaxed): anti-debug + injection-env scan + optional PQ self-attestation.
    // Refuse to start if the posture is unacceptable (loader-injection env set,
    // or a requested self-attestation failed).
    if std::env::var_os(harden::HARDEN_ENV).is_some() {
        let posture = harden::from_env();
        eprintln!("talkrypt-helper: hardening posture: {posture:?}");
        if !posture.is_acceptable() {
            return Err(HelperError::Unsupported(
                "hardening posture unacceptable (loader-injection env set, or \
                 self-attestation failed) — refusing to start",
            ));
        }
    }

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

    #[cfg(windows)]
    {
        let name = endpoint::default_pipe_name()?;
        eprintln!(
            "talkrypt-helper: listening on {name} (ACL: current SID + SYSTEM). \
             Reuses the audited talkrypt core; NOT certified or audited. \
             ACL enforcement must be validated on real Windows.",
        );
        Helper::new(store).serve_pipe(name).await
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = store;
        Err(talkrypt_helper::HelperError::Unsupported(
            "talkrypt-helper supports the Unix-socket and Windows Named-Pipe transports only",
        ))
    }
}
