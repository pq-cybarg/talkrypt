//! Device **linking** — a primary device that holds the account key certifies a
//! new device's key, so the new device resolves as the *same account* to
//! friends. This is the opt-in multi-device path of the identity model
//! (`docs/identity-accounts.md`): the account private key never leaves the
//! primary; only a short ML-DSA-87 **device certificate** crosses the wire.
//!
//! Flow (over an authenticated, AEAD-encrypted session whose handshake root is a
//! **one-time linking descriptor** shared in person — e.g. a QR):
//!
//! ```text
//!   new device ──LinkRequest{ device_pubkey, label }──► primary (holds account key)
//!   new device ◄─LinkGrant{ chain: account→device, account_pubkey, username }── primary
//! ```
//!
//! The new device stores the returned [`IdentityChain`] and thereafter presents
//! it (see `Core::present_identity`) — friends who pinned the account accept the
//! new device automatically, because the chain is signed by the account key.
//!
//! Security: linking runs inside the encrypted session, so the device cert and
//! account key are confidential and tamper-evident. MITM is defeated by the
//! in-person channel that carries the one-time descriptor plus an out-of-band
//! comparison of the **account safety number** the grant returns. The account
//! key is never transmitted. Pure post-quantum (ML-DSA-87); no EC is load-bearing.

use std::sync::Arc;

use talkrypt_crypto::suite::SessionHandle;
use talkrypt_crypto::{CryptoSuite, IdentityChain, IdentityKeyPair, IdentityPublic};
use talkrypt_transport::{Endpoint, Stream, Transport};
use talkrypt_wire::{Reader, Writer};

use crate::descriptor::ChatDescriptor;
use crate::error::{CoreError, Result};
use crate::handshake;

/// A new device's request to be certified under an account.
struct LinkRequest {
    device: IdentityPublic,
    label: String,
}

/// The primary's reply.
enum LinkReply {
    /// The account certified the device: a 1-link `account → device` chain, the
    /// account public key (for safety-number verification), and the account's
    /// self-asserted username (if any).
    Grant {
        chain: IdentityChain,
        account: IdentityPublic,
        username: Option<String>,
    },
    /// The primary declined (e.g. user rejected the pairing).
    Denied(String),
}

fn put_pub(w: &mut Writer, p: &IdentityPublic) {
    w.put_bytes(&p.sig_vk);
}
fn get_pub(r: &mut Reader) -> Result<IdentityPublic> {
    Ok(IdentityPublic {
        sig_vk: r.get_vec()?,
    })
}

impl LinkRequest {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        put_pub(&mut w, &self.device);
        w.put_bytes(self.label.as_bytes());
        w.into_vec()
    }
    fn decode(bytes: &[u8]) -> Result<LinkRequest> {
        let mut r = Reader::new(bytes);
        let device = get_pub(&mut r)?;
        let label = String::from_utf8(r.get_vec()?)
            .map_err(|_| CoreError::Malformed("link label utf-8"))?;
        Ok(LinkRequest { device, label })
    }
}

impl LinkReply {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            LinkReply::Grant {
                chain,
                account,
                username,
            } => {
                w.put_u8(0);
                w.put_bytes(&chain.encode());
                put_pub(&mut w, account);
                match username {
                    Some(u) => {
                        w.put_u8(1);
                        w.put_bytes(u.as_bytes());
                    }
                    None => w.put_u8(0),
                }
            }
            LinkReply::Denied(msg) => {
                w.put_u8(1);
                w.put_bytes(msg.as_bytes());
            }
        }
        w.into_vec()
    }
    fn decode(bytes: &[u8]) -> Result<LinkReply> {
        let mut r = Reader::new(bytes);
        let reply = match r.get_u8()? {
            0 => {
                let chain = IdentityChain::decode(r.get_bytes()?)?;
                let account = get_pub(&mut r)?;
                let username = match r.get_u8()? {
                    0 => None,
                    1 => Some(
                        String::from_utf8(r.get_vec()?)
                            .map_err(|_| CoreError::Malformed("link username utf-8"))?,
                    ),
                    _ => return Err(CoreError::Malformed("link username tag")),
                };
                LinkReply::Grant {
                    chain,
                    account,
                    username,
                }
            }
            1 => LinkReply::Denied(
                String::from_utf8(r.get_vec()?)
                    .map_err(|_| CoreError::Malformed("link denied utf-8"))?,
            ),
            _ => return Err(CoreError::Malformed("link reply tag")),
        };
        Ok(reply)
    }
}

/// How long a freshly-issued device certificate is valid (seconds). The caller
/// supplies `now`; `0` expiry would mean "never", but linked devices should be
/// revocable, so we bound them. ~10 years.
pub const LINK_CERT_TTL: u64 = 10 * 365 * 24 * 3600;

/// The **primary** side of linking: holds the account key and certifies new
/// devices that connect with the shared one-time descriptor.
pub struct LinkHost {
    /// The account keypair (certifies device keys). Never transmitted.
    account: IdentityKeyPair,
    /// This primary's own device identity, for the session handshake.
    device_identity: IdentityKeyPair,
    suite: Arc<dyn CryptoSuite>,
    transport: Arc<dyn Transport>,
    root0: [u8; 32],
    username: Option<String>,
    now: u64,
}

impl LinkHost {
    pub fn new(
        account: IdentityKeyPair,
        device_identity: IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: &ChatDescriptor,
        username: Option<String>,
        now: u64,
    ) -> LinkHost {
        LinkHost {
            account,
            device_identity,
            suite,
            transport,
            root0: descriptor.derive_root(),
            username,
            now,
        }
    }

    /// Start accepting link requests (spawns a background accept loop). Each new
    /// device that connects is certified under the account.
    pub async fn run(&self) -> Result<Endpoint> {
        let listener = self.transport.listen().await?;
        let endpoint = listener.endpoint();
        let mut listener = listener;
        let suite = self.suite.clone();
        let root0 = self.root0;
        let dev_seed = self.device_identity.export_secret();
        let acct_seed = self.account.export_secret();
        let username = self.username.clone();
        let now = self.now;

        tokio::spawn(async move {
            while let Ok(mut stream) = listener.accept().await {
                let device_identity = IdentityKeyPair::from_secret_bytes(dev_seed);
                let hs =
                    handshake::respond(stream.as_mut(), &device_identity, suite.as_ref(), root0)
                        .await;
                let Ok(hs) = hs else { continue };
                let account = IdentityKeyPair::from_secret_bytes(acct_seed);
                tokio::spawn(grant_loop(stream, hs.session, account, username.clone(), now));
            }
        });
        Ok(endpoint)
    }
}

/// Per-connection: receive one LinkRequest, certify the device, send the grant.
async fn grant_loop(
    stream: Box<dyn Stream>,
    session: Box<dyn SessionHandle>,
    account: IdentityKeyPair,
    username: Option<String>,
    now: u64,
) {
    let mut stream = stream;
    let mut session = session;
    let frame = match stream.recv_frame().await {
        Ok(f) => f,
        Err(_) => return,
    };
    let pt = match session.decrypt(&frame) {
        Ok(pt) => pt,
        Err(_) => return,
    };
    let reply = match LinkRequest::decode(&pt) {
        Ok(req) => {
            // Certify the new device under the account: account → device.
            let chain = IdentityChain::device(
                &account,
                &req.device,
                format!("device:{}", req.label),
                now,
                now.saturating_add(LINK_CERT_TTL),
            );
            LinkReply::Grant {
                chain,
                account: account.public().clone(),
                username,
            }
        }
        Err(_) => LinkReply::Denied("malformed link request".into()),
    };
    if let Ok(ct) = session.encrypt(&reply.encode()) {
        let _ = stream.send_frame(&ct).await;
    }
}

/// The result of a successful link: the chain to present, plus the account it
/// roots at (verify its safety number out of band before trusting).
#[derive(Clone, Debug)]
pub struct Linked {
    pub chain: IdentityChain,
    pub account: IdentityPublic,
    pub username: Option<String>,
}

/// The **new device** side of linking: connect to a primary and obtain a device
/// certificate for our `device_identity`.
pub struct LinkClient;

impl LinkClient {
    /// Connect to a primary's linking endpoint, send our device key, and return
    /// the certified chain. Verifies the returned chain actually certifies *our*
    /// device and roots at the returned account (so a faulty/hostile primary
    /// can't hand us a chain for someone else's key).
    pub async fn request(
        device_identity: &IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: &ChatDescriptor,
        endpoint: &str,
        label: impl Into<String>,
        now: u64,
    ) -> Result<Linked> {
        let mut stream = transport.dial(&endpoint.to_string()).await?;
        let hs = handshake::initiate(
            stream.as_mut(),
            device_identity,
            suite.as_ref(),
            descriptor.derive_root(),
        )
        .await?;
        let mut session = hs.session;

        let req = LinkRequest {
            device: device_identity.public().clone(),
            label: label.into(),
        };
        let ct = session.encrypt(&req.encode())?;
        stream.send_frame(&ct).await?;

        let frame = stream.recv_frame().await?;
        let pt = session.decrypt(&frame)?;
        match LinkReply::decode(&pt)? {
            LinkReply::Grant {
                chain,
                account,
                username,
            } => {
                // The chain must root at `account` and certify OUR device key.
                chain
                    .verify(&account, device_identity.public(), now)
                    .map_err(|_| CoreError::Handshake("link grant did not certify our device"))?;
                Ok(Linked {
                    chain,
                    account,
                    username,
                })
            }
            LinkReply::Denied(msg) => Err(CoreError::Registry(format!("link denied: {msg}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{Persistence, TopologyKind};
    use crate::contacts::{resolve_chain, ContactStore};
    use talkrypt_crypto::{SuiteRegistry, DEFAULT_SUITE_ID};
    use talkrypt_transport::LoopbackFabric;

    const NOW: u64 = 1_700_000_000;

    fn suite() -> Arc<dyn CryptoSuite> {
        SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID).unwrap()
    }

    fn link_desc() -> ChatDescriptor {
        ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec![],
            "#link",
        )
    }

    #[tokio::test]
    async fn link_certifies_new_device_under_account() {
        let fabric = LoopbackFabric::new();
        let desc = link_desc();

        let account = IdentityKeyPair::generate();
        let primary_device = IdentityKeyPair::generate();
        let host = LinkHost::new(
            // primary holds the account key
            IdentityKeyPair::from_secret_bytes(account.export_secret()),
            primary_device,
            suite(),
            Arc::new(fabric.transport("primary")),
            &desc,
            Some("alice".into()),
            NOW,
        );
        // Leak so the accept loop lives for the test.
        let host = Box::leak(Box::new(host));
        host.run().await.unwrap();

        // New device requests certification.
        let new_device = IdentityKeyPair::generate();
        let linked = LinkClient::request(
            &new_device,
            suite(),
            Arc::new(fabric.transport("newdev")),
            &desc,
            "primary",
            "laptop",
            NOW,
        )
        .await
        .unwrap();

        // The grant certifies our device under Alice's account.
        assert_eq!(linked.account, account.public().clone());
        assert_eq!(linked.username.as_deref(), Some("alice"));
        assert_eq!(linked.chain.leaf(), Some(new_device.public()));

        // A friend who pinned Alice's account now resolves the NEW device as a
        // friend — exactly the multi-device goal.
        let mut store = ContactStore::new();
        store.add(account.public().clone(), Some("alice".into()), true);
        let res = resolve_chain(&store, &linked.chain, new_device.public().fingerprint(), NOW)
            .expect("chain binds + resolves");
        assert!(res.friend, "the linked device belongs to the pinned account");
    }

    #[tokio::test]
    async fn wrong_linking_descriptor_cannot_decrypt_grant() {
        // A client that dials with a DIFFERENT descriptor (no shared one-time
        // token) can't derive the session and so never gets a usable grant.
        let fabric = LoopbackFabric::new();
        let desc = link_desc();
        let account = IdentityKeyPair::generate();
        let host = LinkHost::new(
            account,
            IdentityKeyPair::generate(),
            suite(),
            Arc::new(fabric.transport("primary2")),
            &desc,
            None,
            NOW,
        );
        let host = Box::leak(Box::new(host));
        host.run().await.unwrap();

        let mut wrong = link_desc();
        wrong.invite_token = vec![0xAB; 32]; // different token → different root
        let new_device = IdentityKeyPair::generate();
        let res = LinkClient::request(
            &new_device,
            suite(),
            Arc::new(fabric.transport("newdev2")),
            &wrong,
            "primary2",
            "phone",
            NOW,
        )
        .await;
        assert!(res.is_err(), "diverging linking roots must not yield a grant");
    }
}
