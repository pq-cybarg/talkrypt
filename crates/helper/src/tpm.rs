//! **TPM 2.0** hardware-backed sealing for the `HardwareBacked` custody tier
//! (gated by the `tpm` feature).
//!
//! A secret is sealed to the TPM with `tpm2_create` under the owner-hierarchy
//! primary (SRK). The resulting `(public, private)` blobs are **bound to this
//! TPM** — they can only be loaded and unsealed by the same TPM, so an
//! attacker who copies the stored blob to another machine cannot recover the
//! secret. (A PQ identity key can't live *in* a TPM — the TPM has no ML-DSA —
//! so, like the Secure Enclave, the TPM provides hardware-bound *at-rest*
//! protection of the key blob, not native PQ operations.)
//!
//! We shell out to `tpm2-tools` rather than link `libtss2`: it's faithful (real
//! TPM2 commands), needs no C build dep, and the secret crosses via an
//! owner-only file, never argv. The TCTI (which TPM) comes from the process
//! environment (`TPM2TOOLS_TCTI`) — e.g. `swtpm:...` in tests, the system
//! resource manager in production.
//!
//! Validated in Docker against **swtpm** (a spec-faithful software TPM 2.0);
//! see `docs/linux-tpm-test.sh`.

use std::path::Path;
use std::process::Stdio;

use tokio::process::Command;

use crate::error::{HelperError, Result};

async fn tpm2(args: &[&str], cwd: &Path) -> Result<()> {
    let status = Command::new(args[0])
        .args(&args[1..])
        .current_dir(cwd)
        .status()
        .await
        .map_err(|_| HelperError::Unsupported("tpm2-tools not found (install tpm2-tools)"))?;
    if !status.success() {
        return Err(HelperError::Keychain); // reuse the "os keystore error" class
    }
    Ok(())
}

/// Run a tpm2 command as a *probe* — failure is expected/normal, and its output
/// is silenced. Returns whether it succeeded.
async fn tpm2_probe(args: &[&str], cwd: &Path) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .current_dir(cwd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// A private, owner-only scratch directory removed on drop.
struct Scratch {
    dir: std::path::PathBuf,
}
impl Scratch {
    async fn new() -> Result<Scratch> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("tk-helper-tpm-{}-{n}", std::process::id()));
        tokio::fs::create_dir_all(&dir).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Scratch { dir })
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Conventional persistent SRK handle.
const SRK_HANDLE: &str = "0x81000001";

/// Ensure the owner-hierarchy SRK is **persistent** at [`SRK_HANDLE`]. A
/// persistent parent is referenced by handle and consumes no transient object
/// slot — a TPM has only ~3 (swtpm included), and referencing a *transient*
/// primary via a saved context would re-load it on every `tpm2_load`, exhausting
/// them ("out of memory for object contexts"). The SRK is deterministic
/// (default template + the TPM's fixed owner seed), so seal and unseal agree,
/// and it persists across helper restarts.
async fn ensure_srk(cwd: &Path) -> Result<()> {
    // Probe (silently — a miss on first run is normal) whether the SRK is
    // already persisted.
    if tpm2_probe(&["tpm2_readpublic", "-c", SRK_HANDLE], cwd).await {
        return Ok(());
    }
    let _ = tpm2(&["tpm2_flushcontext", "-t"], cwd).await; // best-effort
    tpm2(&["tpm2_createprimary", "-C", "o", "-c", "primary.ctx", "-Q"], cwd).await?;
    tpm2(
        &["tpm2_evictcontrol", "-C", "o", "-c", "primary.ctx", SRK_HANDLE, "-Q"],
        cwd,
    )
    .await?;
    let _ = tpm2(&["tpm2_flushcontext", "-t"], cwd).await;
    Ok(())
}

/// Seal `secret` to the TPM. Returns `bytes(pub) ‖ bytes(priv)` — TPM-bound.
pub async fn seal(secret: &[u8]) -> Result<Vec<u8>> {
    let scratch = Scratch::new().await?;
    let cwd = &scratch.dir;
    tokio::fs::write(cwd.join("secret.bin"), secret).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(cwd.join("secret.bin"), std::fs::Permissions::from_mode(0o600))?;
    }
    ensure_srk(cwd).await?;
    tpm2(
        &[
            "tpm2_create", "-C", SRK_HANDLE, "-i", "secret.bin", "-u", "seal.pub", "-r",
            "seal.priv", "-Q",
        ],
        cwd,
    )
    .await?;
    let _ = tpm2(&["tpm2_flushcontext", "-t"], cwd).await;
    let pubk = tokio::fs::read(cwd.join("seal.pub")).await?;
    let privk = tokio::fs::read(cwd.join("seal.priv")).await?;
    let mut w = talkrypt_wire::Writer::new();
    w.put_bytes(&pubk);
    w.put_bytes(&privk);
    Ok(w.into_vec())
}

/// Unseal a blob produced by [`seal`] on this TPM.
pub async fn unseal(blob: &[u8]) -> Result<Vec<u8>> {
    let mut r = talkrypt_wire::Reader::new(blob);
    let pubk = r.get_vec()?;
    let privk = r.get_vec()?;
    r.finish()?;

    let scratch = Scratch::new().await?;
    let cwd = &scratch.dir;
    tokio::fs::write(cwd.join("seal.pub"), &pubk).await?;
    tokio::fs::write(cwd.join("seal.priv"), &privk).await?;
    ensure_srk(cwd).await?;
    tpm2(
        &[
            "tpm2_load", "-C", SRK_HANDLE, "-u", "seal.pub", "-r", "seal.priv", "-c", "seal.ctx",
            "-Q",
        ],
        cwd,
    )
    .await?;
    tpm2(&["tpm2_unseal", "-c", "seal.ctx", "-o", "out.bin", "-Q"], cwd).await?;
    let out = tokio::fs::read(cwd.join("out.bin")).await?;
    let _ = tpm2(&["tpm2_flushcontext", "-t"], cwd).await;
    Ok(out)
}
