//! The helper server: accept connections and dispatch requests.
//!
//! Every privileged operation **reuses the audited talkrypt Rust core** — there
//! is no re-implemented crypto here. Sealing is `talkrypt_server::keystore`
//! (Argon2id + AES-256-GCM); identities are `talkrypt_crypto::IdentityKeyPair`
//! (ML-DSA-87); invite parsing is `talkrypt_core::ChatDescriptor`.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroize;

use talkrypt_core::ChatDescriptor;
use talkrypt_crypto::IdentityKeyPair;
use talkrypt_server::keystore;

use crate::custody::CustodyTier;
use crate::error::{HelperError, Result};
use crate::frame::{read_frame, write_frame};
use crate::protocol::{Request, Response, PROTOCOL_VERSION};
use crate::store::KeyStore;

/// The helper service over a key store.
pub struct Helper {
    store: KeyStore,
}

impl Helper {
    pub fn new(store: KeyStore) -> Self {
        Self { store }
    }

    /// Dispatch one request, turning any error into a `Response::Error` so the
    /// connection survives a bad request.
    pub async fn dispatch(&self, req: Request) -> Response {
        match self.handle(req).await {
            Ok(resp) => resp,
            Err(e) => Response::Error(e.to_string()),
        }
    }

    async fn handle(&self, req: Request) -> Result<Response> {
        Ok(match req {
            Request::Ping => Response::Pong {
                version: PROTOCOL_VERSION,
            },

            Request::Seal { passphrase, secret } => {
                let mut secret = secret;
                let blob = keystore::seal(&passphrase, &secret)?;
                secret.zeroize();
                Response::Sealed(blob)
            }
            Request::Unseal { passphrase, blob } => {
                Response::Unsealed(keystore::unseal(&passphrase, &blob)?)
            }

            Request::Put {
                name,
                tier,
                passphrase,
                secret,
            } => {
                let tier = CustodyTier::from_tag(tier)?;
                let mut secret = secret;
                match tier {
                    CustodyTier::SoftwareSealed => {
                        let sealed = keystore::seal(&passphrase, &secret)?;
                        secret.zeroize();
                        self.store.put(&name, tier, &sealed).await?;
                    }
                    // OsKeystore / HardwareBacked: the backend protects at rest,
                    // so the secret is handed over directly (no app passphrase).
                    _ => {
                        self.store.put(&name, tier, &secret).await?;
                        secret.zeroize();
                    }
                }
                Response::Ok
            }
            Request::Get { name, passphrase } => {
                let (tier, bytes) = self.store.get(&name).await?;
                let secret = match tier {
                    CustodyTier::SoftwareSealed => keystore::unseal(&passphrase, &bytes)?,
                    _ => bytes,
                };
                Response::Secret(secret)
            }
            Request::Delete { name } => {
                self.store.delete(&name).await?;
                Response::Ok
            }

            Request::GenerateIdentity { name, passphrase } => {
                // Identities are software-sealed today (a PQ identity seed can't
                // live in an EC-only Secure Enclave; OS-keystore custody of the
                // seed is a future option).
                let id = IdentityKeyPair::generate();
                let mut seed = id.export_secret();
                let sealed = keystore::seal(&passphrase, &seed)?;
                seed.zeroize();
                self.store
                    .put(&name, CustodyTier::SoftwareSealed, &sealed)
                    .await?;
                Response::Fingerprint(id.public().fingerprint().to_vec())
            }
            Request::IdentityFingerprint { name, passphrase } => {
                let (tier, bytes) = self.store.get(&name).await?;
                let mut seed = match tier {
                    CustodyTier::SoftwareSealed => keystore::unseal(&passphrase, &bytes)?,
                    _ => bytes,
                };
                let mut seed32: [u8; 32] = seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| HelperError::Protocol("stored identity seed length"))?;
                seed.zeroize();
                let id = IdentityKeyPair::from_secret_bytes(seed32);
                seed32.zeroize();
                Response::Fingerprint(id.public().fingerprint().to_vec())
            }

            Request::ValidateInvite { uri } => {
                let desc = ChatDescriptor::from_uri(&uri)
                    .map_err(|_| HelperError::InvalidInvite("malformed talkrypt:// URI"))?;
                Response::Invite {
                    suite_id: desc.resolved_suite_id().to_string(),
                    scheme: desc.scheme_hash().to_vec(),
                }
            }

            Request::Capabilities => Response::Capabilities(crate::custody::encode_capabilities()),
        })
    }

    /// Serve one connection until the peer hangs up.
    pub async fn handle_conn<S>(&self, mut stream: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let frame = match read_frame(&mut stream).await {
                Ok(f) => f,
                Err(HelperError::Closed) => return Ok(()),
                Err(e) => return Err(e),
            };
            let resp = match Request::decode(&frame) {
                Ok(req) => self.dispatch(req).await,
                Err(e) => Response::Error(e.to_string()),
            };
            write_frame(&mut stream, &resp.encode()).await?;
        }
    }

    /// Accept loop over a bound Unix listener (one task per connection).
    #[cfg(unix)]
    pub async fn serve(self, listener: tokio::net::UnixListener) -> Result<()> {
        let helper = Arc::new(self);
        loop {
            let (stream, _addr) = listener.accept().await?;
            let h = helper.clone();
            tokio::spawn(async move {
                let _ = h.handle_conn(stream).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn helper() -> (Helper, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("tk-helper-srv-{}-{n}", std::process::id()));
        let store = KeyStore::new(&dir);
        store.ensure_dir().await.unwrap();
        (Helper::new(store), dir)
    }

    #[tokio::test]
    async fn dispatch_seal_unseal_and_named_store() {
        let (h, dir) = helper().await;
        assert_eq!(h.dispatch(Request::Ping).await, Response::Pong { version: 1 });

        // Stateless seal → unseal.
        let sealed = match h
            .dispatch(Request::Seal {
                passphrase: b"pw".to_vec(),
                secret: b"top secret".to_vec(),
            })
            .await
        {
            Response::Sealed(b) => b,
            other => panic!("expected Sealed, got {other:?}"),
        };
        assert_eq!(
            h.dispatch(Request::Unseal {
                passphrase: b"pw".to_vec(),
                blob: sealed,
            })
            .await,
            Response::Unsealed(b"top secret".to_vec())
        );

        // Named put → get; wrong passphrase fails.
        assert_eq!(
            h.dispatch(Request::Put {
                name: "k".into(),
                tier: CustodyTier::SoftwareSealed.tag(),
                passphrase: b"pw".to_vec(),
                secret: b"v".to_vec(),
            })
            .await,
            Response::Ok
        );
        assert_eq!(
            h.dispatch(Request::Get {
                name: "k".into(),
                passphrase: b"pw".to_vec(),
            })
            .await,
            Response::Secret(b"v".to_vec())
        );
        assert!(matches!(
            h.dispatch(Request::Get {
                name: "k".into(),
                passphrase: b"WRONG".to_vec(),
            })
            .await,
            Response::Error(_)
        ));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn generate_identity_is_recoverable_and_stable() {
        let (h, dir) = helper().await;
        let fp = match h
            .dispatch(Request::GenerateIdentity {
                name: "id".into(),
                passphrase: b"pw".to_vec(),
            })
            .await
        {
            Response::Fingerprint(fp) => fp,
            other => panic!("expected Fingerprint, got {other:?}"),
        };
        assert_eq!(fp.len(), 48);
        // Re-deriving the fingerprint from the sealed identity matches.
        assert_eq!(
            h.dispatch(Request::IdentityFingerprint {
                name: "id".into(),
                passphrase: b"pw".to_vec(),
            })
            .await,
            Response::Fingerprint(fp)
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn validate_invite_reports_scheme() {
        let (h, dir) = helper().await;
        let desc = ChatDescriptor::new(
            talkrypt_core::TopologyKind::P2P,
            talkrypt_core::Persistence::Ephemeral,
            talkrypt_crypto::DEFAULT_SUITE_ID,
            vec!["x".into()],
            "#c",
        );
        match h.dispatch(Request::ValidateInvite { uri: desc.to_uri() }).await {
            Response::Invite { suite_id, scheme } => {
                assert_eq!(suite_id, talkrypt_crypto::DEFAULT_SUITE_ID);
                assert_eq!(scheme, desc.scheme_hash().to_vec());
            }
            other => panic!("expected Invite, got {other:?}"),
        }
        assert!(matches!(
            h.dispatch(Request::ValidateInvite {
                uri: "http://nope".into(),
            })
            .await,
            Response::Error(_)
        ));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
