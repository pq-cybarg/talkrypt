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

/// Default validity of a freshly-issued device certificate (seconds) — **24
/// hours** (SECURITY-AUDIT L1). A device link cert is short-lived on purpose: it
/// lets the new device establish itself, after which it should re-key/rotate;
/// long-lived certs meant one leaked QR granted account access for years. The
/// window is configurable via [`LinkHost::with_cert_ttl`]; a `0` expiry ("never")
/// is deliberately NOT the default, and the issuance path forbids it (see
/// `grant_once`). Bounded so a compromised device cert self-expires quickly even
/// if revocation never reaches a peer.
pub const LINK_CERT_TTL: u64 = 24 * 3600;

/// How long the primary keeps a link offer open before it expires. The linking
/// descriptor is one-time and shared in person; bounding the accept window means
/// an invite token that later leaks (a photographed QR, a screenshot) cannot be
/// redeemed for a rogue device an hour — or a day — later. Combined with the
/// one-time accept policy (`run` stops after the first successful grant), an
/// exposed token yields at most one link, inside a short window
/// (SECURITY-AUDIT L1). Five minutes is comfortable for an in-person pairing.
pub const LINK_WINDOW: std::time::Duration = std::time::Duration::from_secs(300);

/// Operator approval hook: given the requested device label, decide whether to
/// certify it. Set via [`LinkHost::with_approval`]. By default the host **denies**
/// (fail closed, SECURITY-AUDIT L1): certifying a new device — which grants
/// account access — requires an explicit per-device human decision, never mere
/// possession of the invite token. A caller that genuinely wants unattended
/// pairing must opt in with [`LinkHost::auto_approve`].
pub type ApprovalFn = dyn Fn(&str) -> bool + Send + Sync;

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
    /// Optional per-device approval gate (see [`ApprovalFn`]). `None` means DENY
    /// (fail closed) — an explicit approval decision is required.
    approve: Option<Arc<ApprovalFn>>,
    /// Validity window for issued device certs (seconds). Defaults to
    /// [`LINK_CERT_TTL`] (24h).
    cert_ttl: u64,
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
            approve: None,
            cert_ttl: LINK_CERT_TTL,
        }
    }

    /// Require explicit operator approval before certifying each device. The
    /// closure receives the requested device label and returns whether to issue a
    /// certificate. Recommended for interactive hosts so linking needs a per-device
    /// human decision, not merely possession of the invite token (SECURITY-AUDIT L1).
    pub fn with_approval(mut self, approve: Arc<ApprovalFn>) -> Self {
        self.approve = Some(approve);
        self
    }

    /// Opt in to **unattended** pairing: certify any device that presents the
    /// one-time token, with no per-device human decision. Use only for headless
    /// flows where token possession is the intended authorization; interactive
    /// hosts should use [`with_approval`] instead (SECURITY-AUDIT L1).
    ///
    /// [`with_approval`]: LinkHost::with_approval
    pub fn auto_approve(mut self) -> Self {
        self.approve = Some(Arc::new(|_label: &str| true));
        self
    }

    /// Override the issued device-cert validity window (seconds). Kept short by
    /// default ([`LINK_CERT_TTL`], 24h) — extend only deliberately.
    pub fn with_cert_ttl(mut self, ttl: u64) -> Self {
        self.cert_ttl = ttl;
        self
    }

    /// Start accepting link requests (spawns a background accept loop).
    ///
    /// The offer is **one-time and time-bounded**: the loop stops after the first
    /// device is successfully certified, and in any case after [`LINK_WINDOW`].
    /// This is the enforcement behind the "one-time descriptor" documented above —
    /// previously the loop certified a fresh 10-year account certificate to *every*
    /// connection, indefinitely, so one exposure of the invite token minted
    /// unlimited rogue devices (SECURITY-AUDIT L1).
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
        let approve = self.approve.clone();
        let cert_ttl = self.cert_ttl;

        tokio::spawn(async move {
            let _ = tokio::time::timeout(LINK_WINDOW, async move {
                while let Ok(mut stream) = listener.accept().await {
                    let device_identity = IdentityKeyPair::from_secret_bytes(dev_seed);
                    let hs = handshake::respond(
                        stream.as_mut(),
                        &device_identity,
                        suite.as_ref(),
                        root0,
                    )
                    .await;
                    let Ok(hs) = hs else { continue };
                    let account = IdentityKeyPair::from_secret_bytes(acct_seed);
                    // Handle inline (not detached) so we can enforce the one-time
                    // policy: stop accepting once a device has been certified.
                    if grant_once(
                        stream,
                        hs.session,
                        account,
                        username.clone(),
                        now,
                        approve.as_deref(),
                        cert_ttl,
                    )
                    .await
                    {
                        break;
                    }
                }
            })
            .await;
        });
        Ok(endpoint)
    }
}

/// Per-connection: receive one LinkRequest, optionally gate on operator approval,
/// certify the device, and send the grant. Returns `true` iff a certificate was
/// actually issued, so the accept loop can enforce the one-time policy.
async fn grant_once(
    stream: Box<dyn Stream>,
    session: Box<dyn SessionHandle>,
    account: IdentityKeyPair,
    username: Option<String>,
    now: u64,
    approve: Option<&ApprovalFn>,
    cert_ttl: u64,
) -> bool {
    let mut stream = stream;
    let mut session = session;
    let frame = match stream.recv_frame().await {
        Ok(f) => f,
        Err(_) => return false,
    };
    let pt = match session.decrypt(&frame) {
        Ok(pt) => pt,
        Err(_) => return false,
    };
    let mut granted = false;
    let reply = match LinkRequest::decode(&pt) {
        // Fail closed: certify ONLY if an approval hook is present AND says yes.
        // No hook -> deny (SECURITY-AUDIT L1); token possession alone is never
        // enough to mint a device certificate.
        Ok(req) if approve.map(|a| a(&req.label)) == Some(true) => {
            // Certify the new device under the account: account → device. The cert
            // is short-lived (cert_ttl, default 24h) and its expiry is always a
            // bounded, non-zero timestamp — never "never".
            let ttl = if cert_ttl == 0 { LINK_CERT_TTL } else { cert_ttl };
            let chain = IdentityChain::device(
                &account,
                &req.device,
                format!("device:{}", req.label),
                now,
                now.saturating_add(ttl),
            );
            granted = true;
            LinkReply::Grant {
                chain,
                account: account.public().clone(),
                username,
            }
        }
        Ok(_) => LinkReply::Denied("pairing not approved".into()),
        Err(_) => LinkReply::Denied("malformed link request".into()),
    };
    if let Ok(ct) = session.encrypt(&reply.encode()) {
        let _ = stream.send_frame(&ct).await;
    }
    granted
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
        )
        .auto_approve();
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

    /// SECURITY-AUDIT L1: the offer is one-time. After one device links, a second
    /// device presenting the SAME (now-exposed) invite token is refused — before
    /// the fix it received its own fresh 10-year account certificate.
    #[tokio::test]
    async fn second_device_cannot_reuse_the_link_offer() {
        let fabric = LoopbackFabric::new();
        let desc = link_desc();
        let account = IdentityKeyPair::generate();
        let host = LinkHost::new(
            account,
            IdentityKeyPair::generate(),
            suite(),
            Arc::new(fabric.transport("primary3")),
            &desc,
            None,
            NOW,
        )
        .auto_approve();
        let host = Box::leak(Box::new(host));
        host.run().await.unwrap();

        // First device links successfully.
        let dev1 = IdentityKeyPair::generate();
        let first = LinkClient::request(
            &dev1, suite(), Arc::new(fabric.transport("d1")), &desc, "primary3", "laptop", NOW,
        )
        .await;
        assert!(first.is_ok(), "the first device should link");

        // Second device, same token — the one-time offer is already spent.
        let dev2 = IdentityKeyPair::generate();
        let second = LinkClient::request(
            &dev2, suite(), Arc::new(fabric.transport("d2")), &desc, "primary3", "rogue", NOW,
        )
        .await;
        assert!(second.is_err(), "a spent link offer must not certify a second device");
    }

    /// SECURITY-AUDIT L1: an approval hook that denies blocks certification even
    /// with a valid token and session.
    #[tokio::test]
    async fn approval_hook_can_refuse_a_device() {
        let fabric = LoopbackFabric::new();
        let desc = link_desc();
        let account = IdentityKeyPair::generate();
        let host = LinkHost::new(
            account,
            IdentityKeyPair::generate(),
            suite(),
            Arc::new(fabric.transport("primary4")),
            &desc,
            None,
            NOW,
        )
        .with_approval(Arc::new(|_label: &str| false)); // operator rejects everything
        let host = Box::leak(Box::new(host));
        host.run().await.unwrap();

        let dev = IdentityKeyPair::generate();
        let res = LinkClient::request(
            &dev, suite(), Arc::new(fabric.transport("d3")), &desc, "primary4", "laptop", NOW,
        )
        .await;
        assert!(res.is_err(), "an unapproved device must not be certified");
    }

    /// SECURITY-AUDIT L1: the DEFAULT posture (no approval hook set) is fail-closed
    /// — a device that presents the one-time token but gets no explicit approval is
    /// NOT certified. Possession of the invite must never be sufficient by itself.
    #[tokio::test]
    async fn default_without_approval_denies_certification() {
        let fabric = LoopbackFabric::new();
        let desc = link_desc();
        let account = IdentityKeyPair::generate();
        // No .auto_approve() and no .with_approval(): default deny.
        let host = LinkHost::new(
            account,
            IdentityKeyPair::generate(),
            suite(),
            Arc::new(fabric.transport("primary5")),
            &desc,
            None,
            NOW,
        );
        let host = Box::leak(Box::new(host));
        host.run().await.unwrap();

        let dev = IdentityKeyPair::generate();
        let res = LinkClient::request(
            &dev,
            suite(),
            Arc::new(fabric.transport("newdev5")),
            &desc,
            "primary5",
            "laptop",
            NOW,
        )
        .await;
        assert!(res.is_err(), "no approval hook must mean deny (fail closed)");
    }
}
