//! End-to-end IPC test over a real Unix socket: bind a helper, connect a
//! client, and exercise the protocol the way a desktop app would.

#![cfg(unix)]

use std::time::Duration;

use talkrypt_helper::{endpoint, Client, Helper, KeyStore, Request, Response};

fn tmp_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("tk-helper-ipc-{tag}-{}-{n}", std::process::id()))
}

#[tokio::test]
async fn end_to_end_over_unix_socket() {
    let base = tmp_dir("e2e");
    let sock = base.join("helper.sock");
    let store = KeyStore::new(base.join("keys"));
    store.ensure_dir().await.unwrap();

    let listener = endpoint::bind(&sock).await.unwrap();
    let server = tokio::spawn(Helper::new(store).serve(listener));

    // The socket must be owner-only.
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "helper socket must be chmod 0600");
    }

    let mut client = Client::connect(&sock).await.unwrap();
    assert_eq!(client.ping().await.unwrap(), talkrypt_helper::PROTOCOL_VERSION);

    // Platform capabilities (PQ + custody tiers) report over the wire.
    match client.request(Request::Capabilities).await.unwrap() {
        Response::Capabilities(b) => {
            let caps = talkrypt_helper::Capabilities::decode(&b).unwrap();
            assert!(caps.pq_identity, "identities are post-quantum");
            assert_eq!(
                caps.strongest(),
                Some(talkrypt_helper::CustodyTier::SoftwareSealed),
                "desktop helper holds keys software-sealed today"
            );
        }
        other => panic!("expected Capabilities, got {other:?}"),
    }

    // Generate an identity through the helper, then recover its fingerprint.
    let fp = match client
        .request(Request::GenerateIdentity {
            name: "primary".into(),
            passphrase: b"correct horse".to_vec(),
        })
        .await
        .unwrap()
    {
        Response::Fingerprint(fp) => fp,
        other => panic!("expected Fingerprint, got {other:?}"),
    };
    assert_eq!(fp.len(), 48);

    assert_eq!(
        client
            .request(Request::IdentityFingerprint {
                name: "primary".into(),
                passphrase: b"correct horse".to_vec(),
            })
            .await
            .unwrap(),
        Response::Fingerprint(fp)
    );

    // Wrong passphrase is rejected (uniform error).
    assert!(matches!(
        client
            .request(Request::IdentityFingerprint {
                name: "primary".into(),
                passphrase: b"WRONG".to_vec(),
            })
            .await
            .unwrap(),
        Response::Error(_)
    ));

    // A second client on the same socket works concurrently; seal → unseal
    // round-trips, and two seals of the same secret differ (random salt/nonce).
    let mut c2 = Client::connect(&sock).await.unwrap();
    let seal_req = Request::Seal {
        passphrase: b"pw".to_vec(),
        secret: b"hello".to_vec(),
    };
    let a = match c2.request(seal_req.clone()).await.unwrap() {
        Response::Sealed(b) => b,
        other => panic!("expected Sealed, got {other:?}"),
    };
    let b = match c2.request(seal_req).await.unwrap() {
        Response::Sealed(b) => b,
        other => panic!("expected Sealed, got {other:?}"),
    };
    assert_ne!(a, b, "independent salts/nonces must differ");
    assert_eq!(
        c2.request(Request::Unseal {
            passphrase: b"pw".to_vec(),
            blob: a,
        })
        .await
        .unwrap(),
        Response::Unsealed(b"hello".to_vec())
    );

    server.abort();
    tokio::time::timeout(Duration::from_secs(1), async {})
        .await
        .ok();
    let _ = tokio::fs::remove_dir_all(&base).await;
}
