//! Linux Secret Service custody-tier test. Runs only on Linux and needs a live
//! Secret Service daemon (gnome-keyring) on a session D-Bus — see
//! `docs/linux-secretservice-test.md` for the Docker harness. It is a real
//! Secret Service round-trip, not an emulation.

#![cfg(target_os = "linux")]

use talkrypt_helper::{CustodyTier, KeyStore};

#[tokio::test]
async fn os_keystore_tier_round_trips_through_secret_service() {
    let dir = std::env::temp_dir().join(format!("tk-helper-ss-{}", std::process::id()));
    let store = KeyStore::new(&dir);
    store.ensure_dir().await.unwrap();
    let name = format!("ss-test-{}", std::process::id());

    // Put at the OsKeystore tier → the secret goes to the Secret Service, the
    // tier marker to disk, and NOT to a sealed file.
    store
        .put(&name, CustodyTier::OsKeystore, b"secret-service-held")
        .await
        .expect("put into secret service");
    assert_eq!(store.tier_of(&name).await.unwrap(), CustodyTier::OsKeystore);
    assert!(!dir.join(format!("{name}.sealed")).exists());

    assert_eq!(
        store.get(&name).await.expect("get from secret service"),
        (CustodyTier::OsKeystore, b"secret-service-held".to_vec())
    );

    store.delete(&name).await.unwrap();
    assert!(store.get(&name).await.is_err());

    let _ = tokio::fs::remove_dir_all(&dir).await;
}
