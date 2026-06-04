//! TPM 2.0 HardwareBacked custody-tier test. Runs only on Linux with the `tpm`
//! feature and needs a TPM (or swtpm) reachable via `TPM2TOOLS_TCTI` plus
//! `tpm2-tools`. See `docs/linux-tpm-test.sh` for the swtpm Docker harness. This
//! is a real TPM2 seal/unseal, not an emulation of the API.

#![cfg(all(target_os = "linux", feature = "tpm"))]

use talkrypt_helper::{CustodyTier, KeyStore};

#[tokio::test]
async fn hardware_backed_tier_seals_to_the_tpm() {
    let dir = std::env::temp_dir().join(format!("tk-helper-tpm-it-{}", std::process::id()));
    let store = KeyStore::new(&dir);
    store.ensure_dir().await.unwrap();
    let name = format!("tpm-{}", std::process::id());

    // Put at HardwareBacked → the secret is TPM-sealed; the TPM-bound blob is on
    // disk, the secret is not.
    store
        .put(&name, CustodyTier::HardwareBacked, b"tpm-sealed-secret")
        .await
        .expect("TPM seal");
    assert_eq!(
        store.tier_of(&name).await.unwrap(),
        CustodyTier::HardwareBacked
    );
    // The on-disk blob must NOT contain the plaintext (it's TPM-sealed).
    let on_disk = tokio::fs::read(dir.join(format!("{name}.sealed"))).await.unwrap();
    assert!(
        on_disk.windows(b"tpm-sealed-secret".len()).all(|w| w != b"tpm-sealed-secret"),
        "plaintext must not appear in the TPM-sealed blob"
    );

    // Get → the TPM unseals it back.
    assert_eq!(
        store.get(&name).await.expect("TPM unseal"),
        (CustodyTier::HardwareBacked, b"tpm-sealed-secret".to_vec())
    );

    store.delete(&name).await.unwrap();
    assert!(store.get(&name).await.is_err());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}
