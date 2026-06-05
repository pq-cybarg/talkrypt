//! talkrypt-ffi — uniffi bindings exposing the core engine to other languages.
//!
//! This is the **single shared binding** consumed by the Android app (Kotlin)
//! and a desktop shell (Swift/Kotlin/Python), so the security-critical core is
//! implemented once and never reimplemented per platform. Generate bindings
//! with `uniffi-bindgen` against the built library; see `docs/PLATFORMS.md`.
//!
//! The async `Core` is wrapped behind a blocking facade: a multi-threaded
//! tokio runtime is owned by the client object, background tasks run on it, and
//! the exported methods are synchronous (mobile/desktop UIs poll `poll_event`).
//!
//! Transport is TCP here for portability; an Arti onion build is a feature swap.

use std::sync::{Arc, Mutex};

use tokio::runtime::Runtime;
use tokio::sync::mpsc::UnboundedReceiver;

use talkrypt_core::{
    resolve_across, ChatDescriptor, Core, Event, Persistence, RegistryClient, RegistryServer,
    TopologyKind,
};
use talkrypt_crypto::{
    dr_suite_id, IdentityChain, IdentityKeyPair, IdentityPublic, KemProfile, SignedClaim,
    SuiteRegistry, DEFAULT_SUITE_ID,
};
use talkrypt_topology::for_kind;
use talkrypt_transport::TcpTransport;

/// Current Unix time in seconds (registry claim timestamps).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex of bytes.
fn hex_bytes(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Parse 64 hex chars into a 32-byte seed.
fn parse_seed_hex(s: &str) -> Result<[u8; 32], String> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("account seed must be 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

uniffi::setup_scaffolding!();

/// Errors surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{0}")]
    Failed(String),
}

impl FfiError {
    fn from<E: std::fmt::Display>(e: E) -> Self {
        FfiError::Failed(e.to_string())
    }
}

/// The key-custody tier a platform achieves at runtime (mirrors
/// [`talkrypt_core::CustodyTier`]). The host detects this — e.g. the Android
/// app probes StrongBox/TEE availability — and reports it; talkrypt's crypto
/// never depends on the tier, only its at-rest protection does.
#[derive(uniffi::Enum)]
pub enum CustodyTier {
    SoftwareSealed,
    OsKeystore,
    HardwareBacked,
}

impl From<CustodyTier> for talkrypt_core::CustodyTier {
    fn from(t: CustodyTier) -> Self {
        match t {
            CustodyTier::SoftwareSealed => talkrypt_core::CustodyTier::SoftwareSealed,
            CustodyTier::OsKeystore => talkrypt_core::CustodyTier::OsKeystore,
            CustodyTier::HardwareBacked => talkrypt_core::CustodyTier::HardwareBacked,
        }
    }
}

/// Build this platform's **PQ + custody-tier parity report** (an encoded
/// `Capabilities`) from the strongest tier the host achieved. Identities are
/// always post-quantum (ML-DSA-87). Tiers are cumulative up to `achieved` (a
/// device that reaches `HardwareBacked` can also do the weaker tiers), so the
/// #305 parity audit can compare it against the desktop helper's report.
#[uniffi::export]
pub fn custody_report(achieved: CustodyTier) -> Vec<u8> {
    let achieved: talkrypt_core::CustodyTier = achieved.into();
    let tiers: Vec<talkrypt_core::CustodyTier> = [
        talkrypt_core::CustodyTier::SoftwareSealed,
        talkrypt_core::CustodyTier::OsKeystore,
        talkrypt_core::CustodyTier::HardwareBacked,
    ]
    .into_iter()
    .filter(|t| *t <= achieved)
    .collect();
    talkrypt_core::Capabilities {
        pq_identity: true,
        tiers,
    }
    .encode()
}

/// An event delivered to the host UI via `poll_event`.
#[derive(uniffi::Enum)]
pub enum FfiEvent {
    Message {
        from: String,
        channel: String,
        text: String,
        /// Classification banner (e.g. "SECRET//NOFORN"), or empty if unmarked.
        marking: String,
    },
    Connected {
        fingerprint: String,
    },
    /// A peer resolved its device to an account identity (it presented a
    /// certificate chain inside the encrypted session). `friend` is true iff the
    /// account is one the host pinned via `pin_friend` — unforgeable by anyone
    /// lacking that account's ML-DSA private key.
    Identity {
        from: String,
        account_fingerprint: String,
        username: String,
        friend: bool,
    },
    Disconnected {
        fingerprint: String,
    },
    Error {
        message: String,
    },
}

fn hex_fp(fp: &[u8; 48]) -> String {
    fp.iter().map(|b| format!("{b:02x}")).collect()
}

fn map_event(e: Event) -> FfiEvent {
    match e {
        Event::Message {
            from,
            channel,
            text,
            marking,
        } => FfiEvent::Message {
            from: hex_fp(&from),
            channel,
            text,
            marking: marking.map(|m| m.banner()).unwrap_or_default(),
        },
        Event::Connected { fingerprint } => FfiEvent::Connected {
            fingerprint: hex_fp(&fingerprint),
        },
        Event::Identity {
            from,
            account_fingerprint,
            username,
            friend,
        } => FfiEvent::Identity {
            from: hex_fp(&from),
            account_fingerprint: hex_fp(&account_fingerprint),
            username: username.unwrap_or_default(),
            friend,
        },
        Event::Disconnected { fingerprint } => FfiEvent::Disconnected {
            fingerprint: hex_fp(&fingerprint),
        },
        Event::Error(message) => FfiEvent::Error { message },
    }
}

/// Parse a posture string into a KEM profile (mirrors the CLI/TUI).
fn posture_from(s: &str) -> Option<KemProfile> {
    match s.to_ascii_lowercase().as_str() {
        "pq-pure" | "pqpure" | "pure" | "" => Some(KemProfile::pq_pure()),
        "hybrid" => Some(KemProfile::hybrid()),
        "pq-pure-compact" | "compact" => Some(KemProfile::pq_pure_compact()),
        _ => None,
    }
}

/// A talkrypt chat client, exported to other languages.
#[derive(uniffi::Object)]
pub struct TalkryptClient {
    rt: Runtime,
    core: Core,
    events: Mutex<UnboundedReceiver<Event>>,
}

#[uniffi::export]
impl TalkryptClient {
    /// Create and host a new chat; returns a client whose `invite_uri` can be
    /// shared with peers. `posture` selects the KEM posture: `pq-pure`
    /// (default/zero-EC), `hybrid`, or `pq-pure-compact`; an empty/unknown
    /// value falls back to PQ-pure.
    #[uniffi::constructor]
    pub fn host(listen: String, channel: String, posture: String) -> Result<Arc<Self>, FfiError> {
        let rt = Runtime::new().map_err(FfiError::from)?;
        let profile = posture_from(&posture).unwrap_or_else(KemProfile::pq_pure);
        let suite_id = dr_suite_id(profile);
        let suite = SuiteRegistry::with_defaults()
            .get(&suite_id)
            .map_err(FfiError::from)?;
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            &suite_id,
            vec![listen.clone()],
            channel,
        );
        let transport = Arc::new(TcpTransport::new(&listen));
        let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, transport, desc);
        rt.block_on(core.host()).map_err(FfiError::from)?;
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
        }))
    }

    /// Join an existing chat from a `talkrypt://` invite URI.
    #[uniffi::constructor]
    pub fn join(uri: String) -> Result<Arc<Self>, FfiError> {
        let rt = Runtime::new().map_err(FfiError::from)?;
        let desc = ChatDescriptor::from_uri(&uri).map_err(FfiError::from)?;
        // Resolve the chat's scheme by fingerprint (handles blank/optional
        // posture and custom schemes); must be registered in this build.
        let suite = SuiteRegistry::with_defaults()
            .get_by_scheme_hash(&desc.scheme_hash())
            .map_err(FfiError::from)?;
        let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
        let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, transport, desc.clone());
        rt.block_on(async {
            for_kind(desc.topology)
                .establish(&core, &desc.endpoints)
                .await
        })
        .map_err(FfiError::from)?;
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
        }))
    }

    /// Send a message to the channel.
    pub fn send(&self, text: String) -> Result<(), FfiError> {
        self.rt
            .block_on(self.core.send(&text))
            .map_err(FfiError::from)
    }

    /// The shareable invite URI for this chat.
    pub fn invite_uri(&self) -> String {
        self.core.descriptor().to_uri()
    }

    /// Our safety number, for out-of-band verification.
    pub fn safety_number(&self) -> String {
        self.core.identity_public().safety_number()
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> u32 {
        self.core.peer_count() as u32
    }

    /// Non-blocking poll for the next event; `None` if none pending.
    pub fn poll_event(&self) -> Option<FfiEvent> {
        let mut rx = self.events.lock().unwrap();
        rx.try_recv().ok().map(map_event)
    }

    /// Pin a friend by their **account public key** (raw ML-DSA-87 verifying-key
    /// bytes, as exchanged out of band via an invite/QR). A peer whose presented
    /// chain roots at this account then arrives as an `Identity` event with
    /// `friend = true`; nobody without the account's private key can forge that.
    pub fn pin_friend(&self, account_pubkey: Vec<u8>, username: Option<String>) {
        let account = IdentityPublic {
            sig_vk: account_pubkey,
        };
        self.core.pin_friend(account, username);
    }

    /// Present an account identity to peers: `chain_bytes` is an encoded
    /// `IdentityChain` (account→…→this device) and `username` an optional
    /// self-asserted label. Sent as the first frame *inside* the encrypted
    /// session. Not calling this leaves the client a pseudonym.
    pub fn present_identity(
        &self,
        chain_bytes: Vec<u8>,
        username: Option<String>,
    ) -> Result<(), FfiError> {
        let chain = IdentityChain::decode(&chain_bytes).map_err(FfiError::from)?;
        self.core.present_identity(chain, username);
        Ok(())
    }
}

// ===== username accounts + registry "anchors" =====

/// A username account identity (ML-DSA-87). Holds the long-term account key that
/// signs registry claims and certifies devices. Persist `seed_hex()` securely
/// (it is the account secret) and reload with [`Account::from_seed_hex`].
#[derive(uniffi::Object)]
pub struct Account {
    kp: IdentityKeyPair,
}

#[uniffi::export]
impl Account {
    /// Generate a fresh account.
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        Arc::new(Self {
            kp: IdentityKeyPair::generate(),
        })
    }

    /// Reload an account from its 64-hex-char seed.
    #[uniffi::constructor]
    pub fn from_seed_hex(seed_hex: String) -> Result<Arc<Self>, FfiError> {
        let seed = parse_seed_hex(&seed_hex).map_err(FfiError::Failed)?;
        Ok(Arc::new(Self {
            kp: IdentityKeyPair::from_secret_bytes(seed),
        }))
    }

    /// The 32-byte account seed as hex — the secret; store it protected.
    pub fn seed_hex(&self) -> String {
        hex_bytes(&self.kp.export_secret())
    }

    /// The account public key (ML-DSA-87 verifying key) as hex.
    pub fn public_hex(&self) -> String {
        hex_bytes(&self.kp.public().sig_vk)
    }

    /// The account's safety number, for out-of-band verification.
    pub fn safety_number(&self) -> String {
        self.kp.public().safety_number()
    }
}

/// A username **registry "anchor"** hosted on this device: a directory mapping
/// usernames to account keys. Spawn one and share its `uri()` so others can
/// register/resolve against it (e.g. via [`anchor_register`]/[`anchor_resolve`]).
#[derive(uniffi::Object)]
pub struct AnchorNode {
    // The runtime keeps the registry's background accept loop alive.
    _rt: Runtime,
    uri: String,
    _server: RegistryServer,
}

#[uniffi::export]
impl AnchorNode {
    /// Spawn a registry anchor bound to `listen` (host:port — use the device's
    /// LAN/hotspot address so others can reach it) on `channel`. Returns a node
    /// whose `uri()` is the shareable anchor location.
    #[uniffi::constructor]
    pub fn host(listen: String, channel: String) -> Result<Arc<Self>, FfiError> {
        let rt = Runtime::new().map_err(FfiError::from)?;
        let suite = SuiteRegistry::with_defaults()
            .get(DEFAULT_SUITE_ID)
            .map_err(FfiError::from)?;
        let desc = ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Persistent,
            DEFAULT_SUITE_ID,
            vec![listen.clone()],
            channel,
        );
        let transport = Arc::new(TcpTransport::new(&listen));
        let server = RegistryServer::new(IdentityKeyPair::generate(), suite, transport, &desc);
        rt.block_on(server.run()).map_err(FfiError::from)?;
        Ok(Arc::new(Self {
            _rt: rt,
            uri: desc.to_uri(),
            _server: server,
        }))
    }

    /// The shareable anchor URI (give this to others to register/resolve).
    pub fn uri(&self) -> String {
        self.uri.clone()
    }
}

/// Connect to an anchor at `uri` and return a client + parsed descriptor.
async fn anchor_client(uri: &str) -> Result<(RegistryClient, ChatDescriptor), FfiError> {
    let desc = ChatDescriptor::from_uri(uri).map_err(FfiError::from)?;
    let suite = SuiteRegistry::with_defaults()
        .get_by_scheme_hash(&desc.scheme_hash())
        .map_err(FfiError::from)?;
    let endpoint = desc
        .endpoints
        .first()
        .cloned()
        .ok_or_else(|| FfiError::Failed("anchor URI has no endpoint".into()))?;
    let id = IdentityKeyPair::generate();
    let client = RegistryClient::connect(
        &id,
        suite,
        Arc::new(TcpTransport::new("0.0.0.0:0")),
        &desc,
        &endpoint,
    )
    .await
    .map_err(FfiError::from)?;
    Ok((client, desc))
}

/// Register `account` under `username` at the anchor at `uri` (you must hold the
/// account key). The binding is self-signed by the account, so the anchor can't
/// forge it. Blocking (runs its own runtime).
#[uniffi::export]
pub fn anchor_register(uri: String, account: Arc<Account>, username: String) -> Result<(), FfiError> {
    let rt = Runtime::new().map_err(FfiError::from)?;
    rt.block_on(async move {
        let (mut client, _desc) = anchor_client(&uri).await?;
        let claim = SignedClaim::issue(&account.kp, username, now_secs());
        client.register(&claim).await.map_err(FfiError::from)
    })
}

/// Resolve `username` at the anchor at `uri`. Returns the resolved account's
/// **safety number** (verify it out of band) or `None` if unbound/inconsistent.
#[uniffi::export]
pub fn anchor_resolve(uri: String, username: String) -> Result<Option<String>, FfiError> {
    let rt = Runtime::new().map_err(FfiError::from)?;
    rt.block_on(async move {
        let (mut client, _desc) = anchor_client(&uri).await?;
        let claims = client.resolve(&username).await.map_err(FfiError::from)?;
        Ok(resolve_across(&username, &claims).map(|acct| acct.safety_number()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Spawn an anchor, register a username, and resolve it back — the exact
    /// surface the app's Anchors screen calls.
    #[test]
    fn anchor_host_register_resolve() {
        let anchor = AnchorNode::host("127.0.0.1:19944".into(), "#anchor".into()).expect("anchor");
        let uri = anchor.uri();
        assert!(uri.starts_with("talkrypt://"));

        let account = Account::generate();
        anchor_register(uri.clone(), account.clone(), "alice".into()).expect("register");

        // Resolves to the same account's safety number.
        let sn = anchor_resolve(uri.clone(), "alice".into()).expect("resolve call");
        assert_eq!(sn, Some(account.safety_number()));
        // Unknown name resolves to None.
        assert_eq!(anchor_resolve(uri, "nobody".into()).expect("resolve call"), None);

        // Seed round-trips so the app can persist + reload the account.
        let reloaded = Account::from_seed_hex(account.seed_hex()).expect("reload");
        assert_eq!(reloaded.safety_number(), account.safety_number());
    }

    /// Exercise the full FFI facade: host, join, send, receive — the exact
    /// surface other languages call.
    #[test]
    fn ffi_host_join_send_receive() {
        let addr = "127.0.0.1:19922".to_string();
        let host = TalkryptClient::host(addr, "#ffi".into(), "pq-pure".into()).expect("host");
        let uri = host.invite_uri();
        assert!(uri.starts_with("talkrypt://"));
        assert!(!host.safety_number().is_empty());

        let joiner = TalkryptClient::join(uri).expect("join");
        joiner.send("hello via ffi".into()).expect("send");

        // Poll the host for the decrypted message (background tasks are async).
        let mut got = None;
        for _ in 0..50 {
            while let Some(ev) = host.poll_event() {
                if let FfiEvent::Message { text, .. } = ev {
                    got = Some(text);
                }
            }
            if got.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(got.as_deref(), Some("hello via ffi"));
        assert_eq!(joiner.peer_count(), 1);
    }
}
