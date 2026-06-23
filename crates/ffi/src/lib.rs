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

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};

use tokio::runtime::Runtime;
use tokio::sync::mpsc::UnboundedReceiver;
use zeroize::Zeroize;

use talkrypt_core::{
    resolve_across, ChatDescriptor, Core, Event, LinkClient, LinkHost, Persistence, RegistryClient,
    RegistryServer, TopologyKind,
};
use talkrypt_crypto::{
    dr_suite_id, IdentityChain, IdentityKeyPair, IdentityPublic, KemProfile, Revocation,
    SignedClaim, SuiteRegistry, DEFAULT_SUITE_ID,
};
use talkrypt_topology::for_kind;
use talkrypt_transport::TcpTransport;

/// Build an Arti onion-state persistence rooted at a caller-supplied writable
/// directory (created if missing) — required on Android, where the temp dir is
/// not usable and the onion service keys + dir cache need a real path under the
/// app's storage.
#[cfg(feature = "tor")]
fn tor_persistence(state_dir: &str) -> talkrypt_transport::OnionPersistence {
    let path = std::path::PathBuf::from(state_dir);
    let _ = std::fs::create_dir_all(&path);
    talkrypt_transport::OnionPersistence::Persistent { state_dir: path }
}

/// One process-global Tokio runtime shared by every client. It outlives any
/// single client (it's `static`), so background tasks spawned by the shared Tor
/// client — circuit/dir managers, the onion rendezvous pump — keep running for
/// the life of the process instead of dying when one client is dropped.
///
/// We floor the worker-thread count at 4. `Runtime::new()` sizes the pool from
/// `available_parallelism()`, which Android can clamp to 1–2 for a constrained
/// or backgrounded app regardless of physical cores — too few to service the
/// inbound reader, the dial's circuit tasks, AND a joiner's onion publish at
/// once, which starved host→joiner delivery on-device while desktop (always
/// plenty of threads) worked fine. Hosting is preserved; we just guarantee the
/// threads to run everything concurrently.
fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .max(4);
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// One shared, bootstrapped Arti client reused by every Tor host/join. Avoids
/// the per-chat (and per-launch) cold directory bootstrap that made Tor "very
/// slow": the first onion action bootstraps once on the persistent [`rt`] using
/// the first `state_dir`; later chats reuse the warm client. Onion services get
/// unique nicknames (handled in `ArtiTransport::listen`) so one client can host
/// several chats. A rare race may bootstrap twice; the `OnceLock` keeps one.
#[cfg(feature = "tor")]
fn shared_tor(state_dir: &str) -> Result<Arc<talkrypt_transport::ArtiTransport>, FfiError> {
    static TOR: OnceLock<Arc<talkrypt_transport::ArtiTransport>> = OnceLock::new();
    if let Some(t) = TOR.get() {
        return Ok(t.clone());
    }
    install_tor_panic_logger(state_dir);
    // Feed the live bootstrap fraction into the global percent so the UI can poll
    // tor_bootstrap_percent() and show how far along the (slow) first connect is.
    let progress: Box<dyn Fn(f32) + Send> =
        Box::new(|frac| TOR_BOOT_PCT.store((frac * 100.0).round() as u8, Ordering::Relaxed));
    let built = Arc::new(
        rt().block_on(talkrypt_transport::ArtiTransport::bootstrap_with_progress(
            tor_persistence(state_dir),
            "talkrypt",
            None,
            Some(progress),
        ))
        .map_err(FfiError::from)?,
    );
    TOR_BOOT_PCT.store(100, Ordering::Relaxed);
    Ok(TOR.get_or_init(|| built).clone())
}

/// Latest Tor bootstrap progress, 0..=100. 100 once the shared client is up (or
/// before any Tor use, since the cell starts at 0 and a warm client returns
/// instantly). The connecting UI polls this to show "Bootstrapping Tor X%".
static TOR_BOOT_PCT: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

#[uniffi::export]
pub fn tor_bootstrap_percent() -> u8 {
    TOR_BOOT_PCT.load(Ordering::Relaxed)
}

/// One shared, connected Nym mixnet client, reused for every mixnet chat — the
/// gateway handshake is the slow part (like a Tor bootstrap), so connect once.
/// A rare race may connect twice; the `OnceLock` keeps one.
///
/// `mnemonic` empty → free ephemeral mode (`connect`). Non-empty → paid mode:
/// acquire a zk-nym bandwidth credential paying with that NYM wallet mnemonic,
/// persisting state under `<state_dir>/nym`. The mode is fixed at first connect
/// (the singleton client), so a paid mnemonic must be supplied on the first
/// Nym host/join of the process.
#[cfg(feature = "nym")]
fn shared_nym(state_dir: &str, mnemonic: &str) -> Result<Arc<talkrypt_transport::NymTransport>, FfiError> {
    static NYM: OnceLock<Arc<talkrypt_transport::NymTransport>> = OnceLock::new();
    if let Some(n) = NYM.get() {
        return Ok(n.clone());
    }
    let nym_dir = std::path::Path::new(state_dir).join("nym");
    let built = Arc::new(if !mnemonic.is_empty() {
        // Explicit mnemonic → acquire bandwidth on-chain (advanced path).
        rt()
            .block_on(talkrypt_transport::NymTransport::connect_paid(&nym_dir, mnemonic))
            .map_err(|e| FfiError::Failed(format!("nym paid connect failed: {e}")))?
    } else if nym_dir.exists() {
        // A ticketbook was imported (no mnemonic) → connect on the stored
        // credential. This is the preferred paid path.
        rt()
            .block_on(talkrypt_transport::NymTransport::connect_credentials(&nym_dir))
            .map_err(|e| FfiError::Failed(format!("nym credential connect failed: {e}")))?
    } else {
        // Nothing supplied → free ephemeral mixnet.
        rt()
            .block_on(talkrypt_transport::NymTransport::connect())
            .map_err(|e| FfiError::Failed(format!("nym connect failed: {e}")))?
    });
    Ok(NYM.get_or_init(|| built).clone())
}

/// Import a Nym **ticketbook** (a spend-limited bandwidth credential the user
/// minted with Nym's own tooling — the wallet seed never enters talkrypt) into
/// the persistent credential store under `<state_dir>/nym`. After this, a Nym
/// host/join with an empty mnemonic connects on the stored credential. Requires
/// the FFI built with `--features nym`. `ticketbook` is the raw bytes of an
/// `ImportableTicketBook` export.
#[uniffi::export]
pub fn nym_import_ticketbook(state_dir: String, ticketbook: Vec<u8>) -> Result<(), FfiError> {
    #[cfg(not(feature = "nym"))]
    {
        let _ = (state_dir, ticketbook);
        Err(FfiError::Failed(
            "this build has Nym disabled; rebuild the FFI with --features nym".into(),
        ))
    }
    #[cfg(feature = "nym")]
    {
        let nym_dir = std::path::Path::new(&state_dir).join("nym");
        rt()
            .block_on(talkrypt_transport::NymTransport::import_ticketbook(
                &nym_dir,
                &ticketbook,
            ))
            .map_err(|e| FfiError::Failed(format!("nym ticketbook import failed: {e}")))
    }
}

/// Route panics (incl. on Arti's worker threads, which Android can't surface) to
/// `<state_dir>/panic.txt`, so a Tor-bootstrap failure is diagnosable on device.
/// Installed once before the first Tor bootstrap.
#[cfg(feature = "tor")]
fn install_tor_panic_logger(state_dir: &str) {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let dir = state_dir.to_string();
    ONCE.call_once(move || {
        let _ = std::fs::create_dir_all(&dir);
        std::panic::set_hook(Box::new(move |info| {
            let _ = std::fs::write(format!("{dir}/panic.txt"), format!("{info}"));
        }));
    });
}

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

/// Parse an even-length hex string into bytes.
fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.is_empty() || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// Parse 96 hex chars into a 48-byte fingerprint.
fn parse_fp_hex(s: &str) -> Option<[u8; 48]> {
    let s = s.trim();
    if s.len() != 96 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 48];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
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

/// One-time secure init run by every FFI entry point that may create or load a
/// secret: first harden the process against RAM capture (disable core dumps /
/// ptrace — SECURITY-AUDIT R-8), then run the FIPS power-on self-test and abort
/// if any primitive is broken (R-5). Both are `Once`-guarded, so this is cheap
/// to call on every constructor.
fn ffi_secure_init() {
    talkrypt_crypto::ensure_hardened();
    talkrypt_crypto::ensure_self_tested();
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
#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq)]
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
    /// certificate chain inside the encrypted session). `contact` is true iff the
    /// account is a recognized contact (added via `add_contact`); `friend` iff
    /// you labeled it a friend. Neither implies access — both are unforgeable by
    /// anyone lacking that account's ML-DSA private key.
    Identity {
        from: String,
        account_fingerprint: String,
        username: String,
        contact: bool,
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

/// A persisted contact (account public key + remembered name + friend label).
#[derive(uniffi::Record)]
pub struct ContactRecord {
    pub account_pubkey_hex: String,
    pub name: String,
    pub friend: bool,
}

/// The result of a successful device link (the new-device side). Persist
/// `chain_hex` (with this device's seed) and pass both to `join_linked` /
/// `host_linked` to chat as this account on this device.
#[derive(uniffi::Record)]
pub struct LinkResult {
    /// The account→device certificate chain, hex-encoded.
    pub chain_hex: String,
    /// The account's safety number — verify it against the primary out of band
    /// before trusting this link.
    pub account_safety_number: String,
    /// The account's self-asserted username (empty if none).
    pub username: String,
    /// This device's fingerprint (give it to the account holder so they can
    /// revoke this device later if it is lost).
    pub device_fingerprint_hex: String,
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
            contact,
            friend,
        } => FfiEvent::Identity {
            from: hex_fp(&from),
            account_fingerprint: hex_fp(&account_fingerprint),
            username: username.unwrap_or_default(),
            contact,
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
    rt: &'static Runtime,
    core: Core,
    events: Mutex<UnboundedReceiver<Event>>,
    /// The shareable invite URI. For Tor hosts this carries the published
    /// `.onion`; otherwise it's the descriptor's URI.
    invite: String,
}

#[uniffi::export]
impl TalkryptClient {
    /// Create and host a new chat; returns a client whose `invite_uri` can be
    /// shared with peers. `posture` selects the KEM posture: `pq-pure`
    /// (default/zero-EC), `hybrid`, or `pq-pure-compact`; an empty/unknown
    /// value falls back to PQ-pure.
    #[uniffi::constructor]
    /// Host a plain-TCP chat. `listen` is the bind address (`host:port`).
    /// `endpoint`, if given, is advertised in the invite *instead of* `listen`
    /// — use it when the address peers must dial differs from the one you bind:
    /// bind `0.0.0.0` but hand out your LAN/public IP, or on an Android emulator
    /// hand out the host-loopback alias `10.0.2.2` (bridge the port with
    /// `adb forward`). Mirrors the CLI's `host --endpoint`. The session root is
    /// unaffected — it derives from the invite token, not the endpoint (the same
    /// reason `host_tor` can swap the published `.onion` into the invite).
    pub fn host(
        listen: String,
        channel: String,
        posture: String,
        endpoint: Option<String>,
    ) -> Result<Arc<Self>, FfiError> {
        let rt = rt();
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
        // Advertise the dial address peers should use. Defaults to the bound
        // `listen` when no override is supplied.
        let mut d = core.descriptor().clone();
        if let Some(ep) = endpoint {
            d.endpoints = vec![ep];
        }
        let invite = d.to_uri();
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
            invite,
        }))
    }

    /// Host over real Tor (Arti): publishes an onion service; `invite_uri`
    /// carries the `.onion`. Requires the FFI built with `--features tor`,
    /// otherwise returns an error.
    #[uniffi::constructor]
    pub fn host_tor(
        channel: String,
        posture: String,
        state_dir: String,
    ) -> Result<Arc<Self>, FfiError> {
        #[cfg(not(feature = "tor"))]
        {
            let _ = (channel, posture, state_dir);
            Err(FfiError::Failed(
                "this build has Tor disabled; rebuild the FFI with --features tor".into(),
            ))
        }
        #[cfg(feature = "tor")]
        {
            let rt = rt();
            let profile = posture_from(&posture).unwrap_or_else(KemProfile::pq_pure);
            let suite_id = dr_suite_id(profile);
            let suite = SuiteRegistry::with_defaults()
                .get(&suite_id)
                .map_err(FfiError::from)?;
            // One shared, warm Arti client (bootstrapped once) hosts this chat as
            // a fresh onion service. Arti needs a writable state dir; on Android
            // the app passes a persistent path (its filesDir).
            let arti = shared_tor(&state_dir)?;
            let desc = ChatDescriptor::new(
                TopologyKind::P2P,
                Persistence::Ephemeral,
                &suite_id,
                vec![],
                channel,
            );
            let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, arti.clone(), desc);
            rt.block_on(core.host()).map_err(FfiError::from)?;
            // Put the published .onion into the invite so peers can dial it.
            let mut d = core.descriptor().clone();
            if let Some(onion) = arti.onion_address() {
                d.endpoints = vec![onion];
            }
            let invite = d.to_uri();
            Ok(Arc::new(Self {
                rt,
                core,
                events: Mutex::new(rx),
                invite,
            }))
        }
    }

    /// Join an existing chat from a `talkrypt://` invite URI.
    #[uniffi::constructor]
    pub fn join(uri: String) -> Result<Arc<Self>, FfiError> {
        let rt = rt();
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
        let invite = core.descriptor().to_uri();
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
            invite,
        }))
    }

    /// Join over real Tor (Arti) — for a `.onion` invite. Requires the FFI built
    /// with `--features tor`, otherwise returns an error. `state_dir` is a
    /// writable path for Arti's state (the app's filesDir).
    #[uniffi::constructor]
    pub fn join_tor(uri: String, state_dir: String) -> Result<Arc<Self>, FfiError> {
        #[cfg(not(feature = "tor"))]
        {
            let _ = (uri, state_dir);
            Err(FfiError::Failed(
                "this build has Tor disabled; rebuild the FFI with --features tor".into(),
            ))
        }
        #[cfg(feature = "tor")]
        {
            let rt = rt();
            let desc = ChatDescriptor::from_uri(&uri).map_err(FfiError::from)?;
            let suite = SuiteRegistry::with_defaults()
                .get_by_scheme_hash(&desc.scheme_hash())
                .map_err(FfiError::from)?;
            // Reuse the shared, warm Arti client (no per-chat cold bootstrap).
            let arti = shared_tor(&state_dir)?;
            let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, arti, desc.clone());
            rt.block_on(async {
                for_kind(desc.topology)
                    .establish(&core, &desc.endpoints)
                    .await
            })
            .map_err(FfiError::from)?;
            let invite = core.descriptor().to_uri();
            Ok(Arc::new(Self {
                rt,
                core,
                events: Mutex::new(rx),
                invite,
            }))
        }
    }

    /// Host a chat multi-homed over BOTH the Nym mixnet and (when this build has
    /// Tor) a Tor onion. The invite advertises every endpoint so a joiner reaches
    /// us on whichever network it prefers. Requires the FFI built with
    /// `--features nym` (otherwise returns an error, like `host_tor`). `state_dir`
    /// is Arti's writable state path (the app's filesDir), used for the Tor leg.
    #[uniffi::constructor]
    pub fn host_nym(
        channel: String,
        posture: String,
        state_dir: String,
        mnemonic: String,
    ) -> Result<Arc<Self>, FfiError> {
        #[cfg(not(feature = "nym"))]
        {
            let _ = (channel, posture, state_dir, mnemonic);
            Err(FfiError::Failed(
                "this build has Nym disabled; rebuild the FFI with --features nym".into(),
            ))
        }
        #[cfg(feature = "nym")]
        {
            use talkrypt_transport::{split_endpoints, MultiTransport, Scheme};
            let rt = rt();
            let profile = posture_from(&posture).unwrap_or_else(KemProfile::pq_pure);
            let suite_id = dr_suite_id(profile);
            let suite = SuiteRegistry::with_defaults()
                .get(&suite_id)
                .map_err(FfiError::from)?;
            // Multi-home: a Nym leg always, plus a Tor leg when available. The
            // MultiTransport fans both listeners in and routes dials by scheme.
            let mut multi = MultiTransport::new();
            #[cfg(feature = "tor")]
            {
                multi = multi.with(Scheme::Onion, shared_tor(&state_dir)?);
            }
            multi = multi.with(Scheme::Nym, shared_nym(&state_dir, &mnemonic)?);
            let desc = ChatDescriptor::new(
                TopologyKind::P2P,
                Persistence::Ephemeral,
                &suite_id,
                vec![],
                channel,
            );
            let (core, rx) = Core::new(IdentityKeyPair::generate(), suite, Arc::new(multi), desc);
            // `host()` returns the multi-homed listener endpoint (onion + nym
            // joined); expand it into the invite so a joiner can pick by preference.
            let bound = rt.block_on(core.host()).map_err(FfiError::from)?;
            let mut d = core.descriptor().clone();
            d.endpoints = split_endpoints(&bound);
            let invite = d.to_uri();
            Ok(Arc::new(Self {
                rt,
                core,
                events: Mutex::new(rx),
                invite,
            }))
        }
    }

    /// Join over the Nym mixnet from a multi-homed invite. Connects only to the
    /// networks the invite actually advertises (a `nym:`-only invite never
    /// bootstraps Tor), then dials the single best endpoint by preference
    /// (Nym → Tor → LAN). Requires the FFI built with `--features nym`.
    #[uniffi::constructor]
    pub fn join_nym(uri: String, state_dir: String, mnemonic: String) -> Result<Arc<Self>, FfiError> {
        #[cfg(not(feature = "nym"))]
        {
            let _ = (uri, state_dir, mnemonic);
            Err(FfiError::Failed(
                "this build has Nym disabled; rebuild the FFI with --features nym".into(),
            ))
        }
        #[cfg(feature = "nym")]
        {
            use talkrypt_transport::{endpoint_scheme, select_endpoint, MultiTransport, Scheme};
            let rt = rt();
            let desc = ChatDescriptor::from_uri(&uri).map_err(FfiError::from)?;
            let suite = SuiteRegistry::with_defaults()
                .get_by_scheme_hash(&desc.scheme_hash())
                .map_err(FfiError::from)?;
            // Build only the legs the invite needs.
            let mut multi = MultiTransport::new();
            #[cfg(feature = "tor")]
            if desc.endpoints.iter().any(|e| e.contains(".onion")) {
                multi = multi.with(Scheme::Onion, shared_tor(&state_dir)?);
            }
            if desc
                .endpoints
                .iter()
                .any(|e| endpoint_scheme(e) == Scheme::Nym)
            {
                multi = multi.with(Scheme::Nym, shared_nym(&state_dir, &mnemonic)?);
            }
            let (core, rx) =
                Core::new(IdentityKeyPair::generate(), suite, Arc::new(multi), desc.clone());
            // Dial one endpoint, preferring the mixnet; fall back so a peer is
            // never stranded by a scheme we don't prefer.
            let prefs: &[Scheme] = &[Scheme::Nym, Scheme::Onion, Scheme::Tcp];
            let chosen: Vec<String> = select_endpoint(&desc.endpoints, prefs)
                .map(|s| vec![s.to_string()])
                .unwrap_or_default();
            rt.block_on(async { for_kind(desc.topology).establish(&core, &chosen).await })
                .map_err(FfiError::from)?;
            let invite = core.descriptor().to_uri();
            Ok(Arc::new(Self {
                rt,
                core,
                events: Mutex::new(rx),
                invite,
            }))
        }
    }

    /// Join a chat as a **linked device**: use the persistent `device` key and
    /// present the stored account certificate `chain_hex` (from [`link_accept`]),
    /// so peers who pinned the account resolve you as that account. `username` is
    /// the self-asserted label. The account key is never on this device — only
    /// the certificate chain is.
    #[uniffi::constructor]
    pub fn join_linked(
        uri: String,
        device: Arc<DeviceKey>,
        chain_hex: String,
        username: Option<String>,
    ) -> Result<Arc<Self>, FfiError> {
        let rt = rt();
        let desc = ChatDescriptor::from_uri(&uri).map_err(FfiError::from)?;
        let suite = SuiteRegistry::with_defaults()
            .get_by_scheme_hash(&desc.scheme_hash())
            .map_err(FfiError::from)?;
        let chain_bytes = parse_hex_bytes(&chain_hex)
            .ok_or_else(|| FfiError::Failed("link chain hex is malformed".into()))?;
        let chain = IdentityChain::decode(&chain_bytes).map_err(FfiError::from)?;
        let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
        let (core, rx) = Core::new(
            IdentityKeyPair::from_secret_bytes(device.kp.export_secret()),
            suite,
            transport,
            desc.clone(),
        );
        // Set the presentation BEFORE establishing, so the initiator's eager
        // presentation (sent as it connects) already carries our chain — the
        // host resolves us as the account on first contact, with no separate
        // post-connect announce (which would deliver the identity a second time).
        core.present_identity(chain, username);
        rt.block_on(async {
            for_kind(desc.topology)
                .establish(&core, &desc.endpoints)
                .await
        })
        .map_err(FfiError::from)?;
        let invite = core.descriptor().to_uri();
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
            invite,
        }))
    }

    /// Host a chat as a **linked device**: like [`Self::host`], but use the
    /// persistent `device` key and announce the stored account certificate
    /// `chain_hex` to joiners (so they resolve this host as the account).
    #[uniffi::constructor]
    pub fn host_linked(
        listen: String,
        channel: String,
        posture: String,
        device: Arc<DeviceKey>,
        chain_hex: String,
        username: Option<String>,
    ) -> Result<Arc<Self>, FfiError> {
        let rt = rt();
        let profile = posture_from(&posture).unwrap_or_else(KemProfile::pq_pure);
        let suite_id = dr_suite_id(profile);
        let suite = SuiteRegistry::with_defaults()
            .get(&suite_id)
            .map_err(FfiError::from)?;
        let chain_bytes = parse_hex_bytes(&chain_hex)
            .ok_or_else(|| FfiError::Failed("link chain hex is malformed".into()))?;
        let chain = IdentityChain::decode(&chain_bytes).map_err(FfiError::from)?;
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            &suite_id,
            vec![listen.clone()],
            channel,
        );
        let transport = Arc::new(TcpTransport::new(&listen));
        let (core, rx) = Core::new(
            IdentityKeyPair::from_secret_bytes(device.kp.export_secret()),
            suite,
            transport,
            desc,
        );
        rt.block_on(core.host()).map_err(FfiError::from)?;
        // Set the identity to present; joiners receive it as they connect.
        core.present_identity(chain, username);
        let invite = core.descriptor().to_uri();
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
            invite,
        }))
    }

    /// Join a chat as a **segment** sub-identity: the session authenticates as
    /// `segment` (a per-context unlinkable leaf key) and presents the full
    /// `account → device → segment` chain `chain_hex` (build it with
    /// [`account_segment_chain`] or [`linked_segment_chain`]). Peers who pinned
    /// the account still resolve you as that account, but two segments are
    /// unlinkable to each other (distinct leaf keys).
    #[uniffi::constructor]
    pub fn join_segment(
        uri: String,
        segment: Arc<SegmentKey>,
        chain_hex: String,
        username: Option<String>,
    ) -> Result<Arc<Self>, FfiError> {
        let rt = rt();
        let desc = ChatDescriptor::from_uri(&uri).map_err(FfiError::from)?;
        let suite = SuiteRegistry::with_defaults()
            .get_by_scheme_hash(&desc.scheme_hash())
            .map_err(FfiError::from)?;
        let chain_bytes = parse_hex_bytes(&chain_hex)
            .ok_or_else(|| FfiError::Failed("segment chain hex is malformed".into()))?;
        let chain = IdentityChain::decode(&chain_bytes).map_err(FfiError::from)?;
        let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
        let (core, rx) = Core::new(
            IdentityKeyPair::from_secret_bytes(segment.kp.export_secret()),
            suite,
            transport,
            desc.clone(),
        );
        // Present before establishing so the eager presentation carries the chain.
        core.present_identity(chain, username);
        rt.block_on(async {
            for_kind(desc.topology)
                .establish(&core, &desc.endpoints)
                .await
        })
        .map_err(FfiError::from)?;
        let invite = core.descriptor().to_uri();
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
            invite,
        }))
    }

    /// Host a chat as a **segment** sub-identity (see [`Self::join_segment`]): the
    /// session authenticates as `segment` and announces the `account → device →
    /// segment` chain `chain_hex` to joiners.
    #[uniffi::constructor]
    pub fn host_segment(
        listen: String,
        channel: String,
        posture: String,
        segment: Arc<SegmentKey>,
        chain_hex: String,
        username: Option<String>,
    ) -> Result<Arc<Self>, FfiError> {
        let rt = rt();
        let profile = posture_from(&posture).unwrap_or_else(KemProfile::pq_pure);
        let suite_id = dr_suite_id(profile);
        let suite = SuiteRegistry::with_defaults()
            .get(&suite_id)
            .map_err(FfiError::from)?;
        let chain_bytes = parse_hex_bytes(&chain_hex)
            .ok_or_else(|| FfiError::Failed("segment chain hex is malformed".into()))?;
        let chain = IdentityChain::decode(&chain_bytes).map_err(FfiError::from)?;
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            &suite_id,
            vec![listen.clone()],
            channel,
        );
        let transport = Arc::new(TcpTransport::new(&listen));
        let (core, rx) = Core::new(
            IdentityKeyPair::from_secret_bytes(segment.kp.export_secret()),
            suite,
            transport,
            desc,
        );
        rt.block_on(core.host()).map_err(FfiError::from)?;
        core.present_identity(chain, username);
        let invite = core.descriptor().to_uri();
        Ok(Arc::new(Self {
            rt,
            core,
            events: Mutex::new(rx),
            invite,
        }))
    }

    /// Send a message to the channel.
    pub fn send(&self, text: String) -> Result<(), FfiError> {
        self.rt
            .block_on(self.core.send(&text))
            .map_err(FfiError::from)
    }

    /// The shareable invite URI for this chat (carries the `.onion` for a Tor
    /// host).
    pub fn invite_uri(&self) -> String {
        self.invite.clone()
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

    /// Add a **contact** by their account public key (raw ML-DSA-87 verifying-key
    /// bytes, as exchanged out of band via an invite/QR). `friend` is your own
    /// elevated label. A peer whose presented chain roots at this account then
    /// arrives as an `Identity` event with `contact = true`; nobody without the
    /// account's private key can forge that. Recognition only — NOT access.
    pub fn add_contact(&self, account_pubkey: Vec<u8>, name: Option<String>, friend: bool) {
        let account = IdentityPublic {
            sig_vk: account_pubkey,
        };
        self.core.add_contact(account, name, friend);
    }

    /// Add a contact from a hex-encoded account public key (persistence-friendly).
    pub fn add_contact_hex(&self, account_pubkey_hex: String, name: Option<String>, friend: bool) {
        if let Some(pk) = parse_hex_bytes(&account_pubkey_hex) {
            self.core.add_contact(IdentityPublic { sig_vk: pk }, name, friend);
        }
    }

    /// Add a just-seen account (from an `Identity` event) as a contact by its
    /// fingerprint hex — the Core resolves the full key it saw. Returns false if
    /// no such account was seen this session. Verify the safety number out of
    /// band first (see `seen_account_safety_number`).
    pub fn add_seen_contact(
        &self,
        account_fingerprint_hex: String,
        name: Option<String>,
        friend: bool,
    ) -> bool {
        match parse_fp_hex(&account_fingerprint_hex) {
            Some(fp) => self.core.add_seen_contact(fp, name, friend),
            None => false,
        }
    }

    /// The safety number of a just-seen account (by fingerprint hex), for an
    /// out-of-band check before adding it. Empty if not seen.
    pub fn seen_account_safety_number(&self, account_fingerprint_hex: String) -> String {
        match parse_fp_hex(&account_fingerprint_hex) {
            Some(fp) => self
                .core
                .seen_account(fp)
                .map(|a| a.safety_number())
                .unwrap_or_default(),
            None => String::new(),
        }
    }

    /// Export contacts for the host to persist (reload with `add_contact_hex`).
    pub fn export_contacts(&self) -> Vec<ContactRecord> {
        self.core
            .export_contacts()
            .into_iter()
            .map(|(pk, name, friend)| ContactRecord {
                account_pubkey_hex: hex_bytes(&pk),
                name: name.unwrap_or_default(),
                friend,
            })
            .collect()
    }

    /// Grant one account access to this hosted channel by its fingerprint hex
    /// (48-byte SHA3-384, 96 hex chars). Unilateral — the account need not be a
    /// contact, a friend, or a mutual. No-op if the hex is malformed.
    pub fn allow_account(&self, account_fingerprint_hex: String) {
        if let Some(fp) = parse_fp_hex(&account_fingerprint_hex) {
            self.core.allow_account(fp);
        }
    }

    /// Set this hosted channel's access mode. `"open"` admits anyone with the
    /// invite; `"contacts"` admits recognized contacts; `"friends"` admits
    /// contacts you've labeled friends; anything else leaves it unchanged.
    /// (Registry-restriction is the separate `restrict_to_anchor`.)
    pub fn set_access_mode(&self, mode: String) {
        match mode.as_str() {
            "open" => self.core.open_access(),
            "contacts" => self.core.restrict_to_contacts(),
            "friends" => self.core.restrict_to_friends(),
            _ => {}
        }
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

    /// Revoke a device by its 96-hex fingerprint: the account signs a revocation
    /// and broadcasts it to connected peers, who then refuse that device even if
    /// its key leaks. Requires the issuing `account`. Returns false on bad input.
    pub fn revoke_device(
        &self,
        account: Arc<Account>,
        device_fingerprint_hex: String,
    ) -> Result<bool, FfiError> {
        let fp = parse_fp_hex(&device_fingerprint_hex)
            .ok_or_else(|| FfiError::Failed("device fingerprint must be 96 hex chars".into()))?;
        let rev = Revocation::issue(&account.kp, fp, now_secs());
        Ok(self.rt.block_on(self.core.broadcast_revocation(rev)))
    }

    /// Present THIS device as the given account: builds an account→device
    /// certificate (the account certifies this session's device key) and presents
    /// it inside the encrypted session. Required for the peer (or a registry-
    /// restricted host) to resolve you as that account. Also announces to any
    /// already-connected peers.
    pub fn present_account(&self, account: Arc<Account>, username: Option<String>) {
        let chain = IdentityChain::device(
            &account.kp,
            self.core.identity_public(),
            "device:app",
            now_secs(),
            0,
        );
        self.core.present_identity(chain, username);
        self.rt.block_on(self.core.announce_identity());
    }

    /// Restrict this hosted chat to the members of the anchor at `anchor_uri`:
    /// pulls the anchor's registered account fingerprints and admits only those
    /// (others are silenced + disconnected). Returns how many accounts are
    /// allowed. Use an anchor you are a member of, or you lock yourself out.
    pub fn restrict_to_anchor(&self, anchor_uri: String) -> Result<u32, FfiError> {
        self.rt.block_on(async {
            let (mut client, _desc) = anchor_client(&anchor_uri).await?;
            let claims = client.list().await.map_err(FfiError::from)?;
            let allowed: std::collections::HashSet<[u8; 48]> =
                claims.iter().map(|c| c.claim.account.fingerprint()).collect();
            let n = allowed.len() as u32;
            self.core.restrict_to_accounts(allowed);
            Ok(n)
        })
    }
}

// ===== username accounts + registry "anchors" =====

// ===== hardware-backed at-rest sealing (SECURITY-AUDIT R-8) =====

/// A host-implemented secure-element key wrapper, the mobile half of the
/// multiplatform sealing seam (`talkrypt_core::KeyWrapper`). The **host**
/// implements this against its platform API — Android Keystore / StrongBox
/// (a non-exportable, user-presence-gated `Cipher`) or iOS Secure Enclave — and
/// passes it in when sealing/unsealing. The Rust core never sees the secure
/// element's key: it hands over a random KEK to `wrap` and gets back an opaque
/// blob only this device can `unwrap`.
///
/// Note: this protects the seed **at rest**, not in use — today's secure
/// elements are classical-only and cannot hold/sign the PQ identity key, so the
/// seed is still unwrapped into memory to sign (see `custody_report` and
/// `docs/SECURITY-AUDIT.md` §3b).
#[uniffi::export(callback_interface)]
pub trait HardwareKeyWrapper: Send + Sync {
    /// Wrap (encrypt) `kek` with the device's secure element; return an opaque
    /// blob unwrappable only on this device. Return an error if the user
    /// declines a presence check or the key is unavailable.
    fn wrap(&self, kek: Vec<u8>) -> Result<Vec<u8>, FfiError>;
    /// Unwrap a blob previously produced by [`HardwareKeyWrapper::wrap`].
    fn unwrap(&self, wrapped: Vec<u8>) -> Result<Vec<u8>, FfiError>;
}

/// Bridges a host [`HardwareKeyWrapper`] to the core [`talkrypt_core::KeyWrapper`]
/// trait the seal codec consumes.
struct WrapperBridge(Box<dyn HardwareKeyWrapper>);

impl talkrypt_core::KeyWrapper for WrapperBridge {
    fn wrap(&self, kek: &[u8]) -> std::result::Result<Vec<u8>, talkrypt_core::WrapError> {
        self.0
            .wrap(kek.to_vec())
            .map_err(|e| talkrypt_core::WrapError(e.to_string()))
    }
    fn unwrap(&self, wrapped: &[u8]) -> std::result::Result<Vec<u8>, talkrypt_core::WrapError> {
        self.0
            .unwrap(wrapped.to_vec())
            .map_err(|e| talkrypt_core::WrapError(e.to_string()))
    }
}

impl From<talkrypt_core::CustodyTier> for CustodyTier {
    fn from(t: talkrypt_core::CustodyTier) -> Self {
        match t {
            talkrypt_core::CustodyTier::SoftwareSealed => CustodyTier::SoftwareSealed,
            talkrypt_core::CustodyTier::OsKeystore => CustodyTier::OsKeystore,
            talkrypt_core::CustodyTier::HardwareBacked => CustodyTier::HardwareBacked,
        }
    }
}

/// Seal `secret` bytes into a portable at-rest envelope. Supply a `passphrase`,
/// a hardware `wrapper`, or both (two-factor). With a wrapper the blob is
/// `HardwareBacked` and cannot be opened off this device; with only a passphrase
/// it is `SoftwareSealed`. At least one factor is required.
#[uniffi::export]
pub fn seal_secret(
    secret: Vec<u8>,
    passphrase: Option<String>,
    wrapper: Option<Box<dyn HardwareKeyWrapper>>,
) -> Result<Vec<u8>, FfiError> {
    ffi_secure_init();
    let mut secret = secret;
    let out = seal_bytes(&secret, passphrase.as_deref(), wrapper);
    secret.zeroize();
    out
}

/// Open an envelope produced by [`seal_secret`] (or `Account::seal`). Supply the
/// same factors it was sealed with; a missing factor, wrong passphrase, wrong
/// device, or any tampering fails.
#[uniffi::export]
pub fn unseal_secret(
    blob: Vec<u8>,
    passphrase: Option<String>,
    wrapper: Option<Box<dyn HardwareKeyWrapper>>,
) -> Result<Vec<u8>, FfiError> {
    ffi_secure_init();
    unseal_bytes(&blob, passphrase.as_deref(), wrapper)
}

/// Report the [`CustodyTier`] a sealed blob was produced at, without opening it
/// (so a UI can show "hardware-backed" vs "software-sealed").
#[uniffi::export]
pub fn sealed_tier(blob: Vec<u8>) -> Result<CustodyTier, FfiError> {
    Ok(talkrypt_core::tier_of(&blob).map_err(FfiError::from)?.into())
}

/// Seal `secret` with the given factors (shared by the free fn and key methods).
fn seal_bytes(
    secret: &[u8],
    passphrase: Option<&str>,
    wrapper: Option<Box<dyn HardwareKeyWrapper>>,
) -> Result<Vec<u8>, FfiError> {
    let bridge = wrapper.map(WrapperBridge);
    let opts = talkrypt_core::SealOptions {
        passphrase: passphrase.map(|p| p.as_bytes()),
        wrapper: bridge
            .as_ref()
            .map(|b| b as &dyn talkrypt_core::KeyWrapper),
    };
    talkrypt_core::seal(secret, opts).map_err(FfiError::from)
}

/// Unseal with the given factors.
fn unseal_bytes(
    blob: &[u8],
    passphrase: Option<&str>,
    wrapper: Option<Box<dyn HardwareKeyWrapper>>,
) -> Result<Vec<u8>, FfiError> {
    let bridge = wrapper.map(WrapperBridge);
    talkrypt_core::unseal(
        blob,
        passphrase.map(|p| p.as_bytes()),
        bridge
            .as_ref()
            .map(|b| b as &dyn talkrypt_core::KeyWrapper),
    )
    .map_err(FfiError::from)
}

/// Unseal a blob to exactly a 32-byte seed, zeroizing the transient buffer.
fn unseal_seed(
    blob: &[u8],
    passphrase: Option<&str>,
    wrapper: Option<Box<dyn HardwareKeyWrapper>>,
) -> Result<[u8; 32], FfiError> {
    let mut bytes = unseal_bytes(blob, passphrase, wrapper)?;
    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(FfiError::Failed("sealed seed has wrong length".into()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(seed)
}

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
        ffi_secure_init(); // RAM-capture hardening (R-8) + FIPS POST (R-5)
        Arc::new(Self {
            kp: IdentityKeyPair::generate(),
        })
    }

    /// Reload an account from its 64-hex-char seed.
    #[uniffi::constructor]
    pub fn from_seed_hex(seed_hex: String) -> Result<Arc<Self>, FfiError> {
        ffi_secure_init(); // RAM-capture hardening (R-8) + FIPS POST (R-5)
        let seed = parse_seed_hex(&seed_hex).map_err(FfiError::Failed)?;
        Ok(Arc::new(Self {
            kp: IdentityKeyPair::from_secret_bytes(seed),
        }))
    }

    /// Reload an account from a sealed blob (see [`Account::seal`]). Supply the
    /// same factors used to seal: a `passphrase`, a hardware `wrapper`, or both.
    /// The seed is unsealed straight into the account's page-locked store and
    /// never leaves Rust as plaintext.
    #[uniffi::constructor]
    pub fn from_sealed(
        blob: Vec<u8>,
        passphrase: Option<String>,
        wrapper: Option<Box<dyn HardwareKeyWrapper>>,
    ) -> Result<Arc<Self>, FfiError> {
        ffi_secure_init(); // RAM-capture hardening (R-8) + FIPS POST (R-5)
        let mut seed = unseal_seed(&blob, passphrase.as_deref(), wrapper)?;
        let kp = IdentityKeyPair::from_secret_bytes(seed);
        seed.zeroize();
        Ok(Arc::new(Self { kp }))
    }

    /// The 32-byte account seed as hex — the secret; store it protected.
    pub fn seed_hex(&self) -> String {
        hex_bytes(&self.kp.export_secret())
    }

    /// Seal this account's seed at rest into a portable envelope, **without**
    /// exposing the seed to the host. Prefer this over persisting `seed_hex()`:
    /// pass a hardware `wrapper` (Android StrongBox / Secure Enclave) for a
    /// `HardwareBacked` blob bound to this device, and/or a `passphrase` for
    /// two-factor custody. Reload with [`Account::from_sealed`].
    pub fn seal(
        &self,
        passphrase: Option<String>,
        wrapper: Option<Box<dyn HardwareKeyWrapper>>,
    ) -> Result<Vec<u8>, FfiError> {
        let mut seed = self.kp.export_secret();
        let out = seal_bytes(&seed, passphrase.as_deref(), wrapper);
        seed.zeroize();
        out
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

// ===== device linking (primary certifies a secondary device) =====

/// A persistent **device identity** (ML-DSA-87) for a *linked* secondary device
/// — the device that does NOT hold the account key. Generate it once, persist
/// `seed_hex()`, and reuse it so a link certificate ([`link_accept`]) stays valid
/// across sessions (the certificate certifies *this* device key). Distinct from
/// [`Account`], which holds the account secret.
#[derive(uniffi::Object)]
pub struct DeviceKey {
    kp: IdentityKeyPair,
}

#[uniffi::export]
impl DeviceKey {
    /// Generate a fresh device key.
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        ffi_secure_init(); // RAM-capture hardening (R-8) + FIPS POST (R-5)
        Arc::new(Self {
            kp: IdentityKeyPair::generate(),
        })
    }

    /// Reload a device key from its 64-hex-char seed.
    #[uniffi::constructor]
    pub fn from_seed_hex(seed_hex: String) -> Result<Arc<Self>, FfiError> {
        ffi_secure_init(); // RAM-capture hardening (R-8) + FIPS POST (R-5)
        let seed = parse_seed_hex(&seed_hex).map_err(FfiError::Failed)?;
        Ok(Arc::new(Self {
            kp: IdentityKeyPair::from_secret_bytes(seed),
        }))
    }

    /// Reload a device key from a sealed blob (see [`DeviceKey::seal`]).
    #[uniffi::constructor]
    pub fn from_sealed(
        blob: Vec<u8>,
        passphrase: Option<String>,
        wrapper: Option<Box<dyn HardwareKeyWrapper>>,
    ) -> Result<Arc<Self>, FfiError> {
        ffi_secure_init(); // RAM-capture hardening (R-8) + FIPS POST (R-5)
        let mut seed = unseal_seed(&blob, passphrase.as_deref(), wrapper)?;
        let kp = IdentityKeyPair::from_secret_bytes(seed);
        seed.zeroize();
        Ok(Arc::new(Self { kp }))
    }

    /// The 32-byte device seed as hex — the secret; store it protected.
    pub fn seed_hex(&self) -> String {
        hex_bytes(&self.kp.export_secret())
    }

    /// Seal this device seed at rest into a portable envelope without exposing it
    /// to the host (see [`Account::seal`]). Reload with [`DeviceKey::from_sealed`].
    pub fn seal(
        &self,
        passphrase: Option<String>,
        wrapper: Option<Box<dyn HardwareKeyWrapper>>,
    ) -> Result<Vec<u8>, FfiError> {
        let mut seed = self.kp.export_secret();
        let out = seal_bytes(&seed, passphrase.as_deref(), wrapper);
        seed.zeroize();
        out
    }

    /// This device's fingerprint (96 hex chars). Give it to the account holder so
    /// they can revoke this device later if it is lost.
    pub fn fingerprint_hex(&self) -> String {
        hex_bytes(&self.kp.public().fingerprint())
    }

    /// This device's safety number, for out-of-band verification.
    pub fn safety_number(&self) -> String {
        self.kp.public().safety_number()
    }
}

/// The **primary** side of device linking: hold the account key and certify new
/// devices that connect with the one-time linking URI. Spawn it, show `uri()`
/// (as a QR in person), and keep this object alive while pairing. The account
/// key never leaves this device — only a signed device certificate is sent.
#[derive(uniffi::Object)]
pub struct LinkOffer {
    // The runtime keeps the linking accept loop alive.
    _rt: &'static Runtime,
    uri: String,
    account_safety_number: String,
}

#[uniffi::export]
impl LinkOffer {
    /// Host a linking offer bound to `listen` (host:port — use the device's
    /// reachable LAN address). `username` is advertised with the account to the
    /// new device. Returns a node whose `uri()` the NEW device passes to
    /// [`link_accept`].
    #[uniffi::constructor]
    pub fn host(
        account: Arc<Account>,
        listen: String,
        username: Option<String>,
    ) -> Result<Arc<Self>, FfiError> {
        let rt = rt();
        let suite = SuiteRegistry::with_defaults()
            .get(DEFAULT_SUITE_ID)
            .map_err(FfiError::from)?;
        // A one-time linking descriptor: its random invite token is the in-person
        // secret carried by the QR. The account key never crosses the wire.
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec![listen.clone()],
            "#link",
        );
        let transport = Arc::new(TcpTransport::new(&listen));
        let host = LinkHost::new(
            IdentityKeyPair::from_secret_bytes(account.kp.export_secret()),
            IdentityKeyPair::generate(),
            suite,
            transport,
            &desc,
            username,
            now_secs(),
        );
        rt.block_on(host.run()).map_err(FfiError::from)?;
        Ok(Arc::new(Self {
            _rt: rt,
            uri: desc.to_uri(),
            account_safety_number: account.safety_number(),
        }))
    }

    /// The shareable linking URI (show as a QR to the new device).
    pub fn uri(&self) -> String {
        self.uri.clone()
    }

    /// The offering account's safety number — the new device should verify the
    /// value it gets back from `link_accept` matches this, out of band.
    pub fn account_safety_number(&self) -> String {
        self.account_safety_number.clone()
    }
}

/// **New-device** side of linking: connect to a [`LinkOffer`] `uri`, get this
/// `device` certified under the offering account, and return the certificate to
/// persist. `label` is a human note recorded in the certificate (e.g. "phone").
/// Verify `account_safety_number` against the primary out of band before
/// trusting. Blocking (runs its own runtime).
#[uniffi::export]
pub fn link_accept(
    device: Arc<DeviceKey>,
    uri: String,
    label: String,
) -> Result<LinkResult, FfiError> {
    let rt = Runtime::new().map_err(FfiError::from)?;
    rt.block_on(async move {
        let desc = ChatDescriptor::from_uri(&uri).map_err(FfiError::from)?;
        let suite = SuiteRegistry::with_defaults()
            .get_by_scheme_hash(&desc.scheme_hash())
            .map_err(FfiError::from)?;
        let endpoint = desc
            .endpoints
            .first()
            .cloned()
            .ok_or_else(|| FfiError::Failed("link URI has no endpoint".into()))?;
        let transport = Arc::new(TcpTransport::new("127.0.0.1:0"));
        let linked = LinkClient::request(
            &device.kp,
            suite,
            transport,
            &desc,
            &endpoint,
            label,
            now_secs(),
        )
        .await
        .map_err(FfiError::from)?;
        Ok(LinkResult {
            chain_hex: hex_bytes(&linked.chain.encode()),
            account_safety_number: linked.account.safety_number(),
            username: linked.username.unwrap_or_default(),
            device_fingerprint_hex: hex_bytes(&device.kp.public().fingerprint()),
        })
    })
}

// ===== segment sub-identities (mutually-unlinkable contextual identities) =====

/// A **segment** key (ML-DSA-87): a contextual sub-identity certified by a device
/// key (a signature subtree `account → device → segment`). Different segments
/// authenticate different sessions with *different* leaf keys, so they are
/// mutually unlinkable at the session/transport layer, yet each still resolves to
/// the same account for a contact who pinned it (the chain roots at the account).
/// Generate one per context (e.g. "work", "activism"), persist `seed_hex()`.
#[derive(uniffi::Object)]
pub struct SegmentKey {
    kp: IdentityKeyPair,
}

#[uniffi::export]
impl SegmentKey {
    /// Generate a fresh segment key.
    #[uniffi::constructor]
    pub fn generate() -> Arc<Self> {
        ffi_secure_init(); // RAM-capture hardening (R-8) + FIPS POST (R-5)
        Arc::new(Self {
            kp: IdentityKeyPair::generate(),
        })
    }

    /// Reload a segment key from its 64-hex-char seed.
    #[uniffi::constructor]
    pub fn from_seed_hex(seed_hex: String) -> Result<Arc<Self>, FfiError> {
        ffi_secure_init(); // RAM-capture hardening (R-8) + FIPS POST (R-5)
        let seed = parse_seed_hex(&seed_hex).map_err(FfiError::Failed)?;
        Ok(Arc::new(Self {
            kp: IdentityKeyPair::from_secret_bytes(seed),
        }))
    }

    /// The 32-byte segment seed as hex — the secret; store it protected.
    pub fn seed_hex(&self) -> String {
        hex_bytes(&self.kp.export_secret())
    }

    /// This segment's fingerprint (96 hex chars) — the key that authenticates a
    /// session presented as this segment. Distinct per segment (unlinkability).
    pub fn fingerprint_hex(&self) -> String {
        hex_bytes(&self.kp.public().fingerprint())
    }

    /// This segment's safety number. Two segments of the same account have
    /// different safety numbers — that is the point (they are unlinkable).
    pub fn safety_number(&self) -> String {
        self.kp.public().safety_number()
    }
}

/// Build an `account → device → segment` chain when you **hold the account key**
/// (the primary-device path): the account certifies `device`, then `device`
/// certifies `segment`. Returns the encoded chain as hex; present it with
/// [`TalkryptClient::join_segment`] / [`TalkryptClient::host_segment`], whose
/// session authenticates as `segment`. `label` is recorded in the segment cert
/// (e.g. "segment:work").
#[uniffi::export]
pub fn account_segment_chain(
    account: Arc<Account>,
    device: Arc<DeviceKey>,
    segment: Arc<SegmentKey>,
    label: String,
) -> String {
    let now = now_secs();
    let chain = IdentityChain::device(&account.kp, device.kp.public(), "device:app", now, 0)
        .extend(&device.kp, segment.kp.public(), format!("segment:{label}"), now, 0);
    hex_bytes(&chain.encode())
}

/// Build an `account → device → segment` chain when this is a **linked device**
/// (you hold `device` and its `account → device` certificate `device_chain_hex`
/// from [`link_accept`], but NOT the account key): `device` certifies `segment`
/// and the link is appended. The account key is never needed — a linked device
/// mints its own segments. Returns the encoded chain as hex.
#[uniffi::export]
pub fn linked_segment_chain(
    device: Arc<DeviceKey>,
    device_chain_hex: String,
    segment: Arc<SegmentKey>,
    label: String,
) -> Result<String, FfiError> {
    let bytes = parse_hex_bytes(&device_chain_hex)
        .ok_or_else(|| FfiError::Failed("device chain hex is malformed".into()))?;
    let device_chain = IdentityChain::decode(&bytes).map_err(FfiError::from)?;
    let chain = device_chain.extend(
        &device.kp,
        segment.kp.public(),
        format!("segment:{label}"),
        now_secs(),
        0,
    );
    Ok(hex_bytes(&chain.encode()))
}

/// A username **registry "anchor"** hosted on this device: a directory mapping
/// usernames to account keys. Spawn one and share its `uri()` so others can
/// register/resolve against it (e.g. via [`anchor_register`]/[`anchor_resolve`]).
#[derive(uniffi::Object)]
pub struct AnchorNode {
    // The runtime keeps the registry's background accept loop alive.
    _rt: &'static Runtime,
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
        let rt = rt();
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

/// The channel a `talkrypt://` invite/link URI encodes (e.g. `#link` for a
/// device-linking offer, so the app can route it to `link_accept` instead of
/// joining it as a chat). Empty string if the URI can't be parsed.
#[uniffi::export]
pub fn invite_channel(uri: String) -> String {
    ChatDescriptor::from_uri(&uri)
        .map(|d| d.channel)
        .unwrap_or_default()
}

/// True if the invite's dial endpoint is a Tor onion address — so the joiner
/// must route over Tor (`join_tor`) rather than plain TCP (`join`). The `.onion`
/// lives inside the base32-encoded descriptor, not the literal URI text, so this
/// decodes the descriptor to check. False on a malformed URI or a LAN invite.
#[uniffi::export]
pub fn invite_is_onion(uri: String) -> bool {
    ChatDescriptor::from_uri(&uri)
        .map(|d| d.endpoints.iter().any(|e| e.contains(".onion")))
        .unwrap_or(false)
}

/// Whether an invite advertises a Nym mixnet endpoint (a `nym:` address in the
/// decoded descriptor). The app uses this to route a mixnet invite through
/// `join_nym`. False on a malformed URI or an invite with no Nym endpoint.
#[uniffi::export]
pub fn invite_has_nym(uri: String) -> bool {
    ChatDescriptor::from_uri(&uri)
        .map(|d| d.endpoints.iter().any(|e| e.starts_with("nym:")))
        .unwrap_or(false)
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

    /// Two segments of one account both resolve to that account (a contact who
    /// pinned it recognizes both), yet they authenticate with distinct leaf keys
    /// — mutually unlinkable contextual identities. Exercises the exact surface
    /// the app's Segments screen calls.
    #[test]
    fn segments_belong_to_account_but_are_unlinkable() {
        let account = Account::generate();
        let device = DeviceKey::generate();
        let work = SegmentKey::generate();
        let play = SegmentKey::generate();

        // Distinct leaf keys → unlinkable at the session/transport layer.
        assert_ne!(work.fingerprint_hex(), play.fingerprint_hex());
        assert_ne!(work.safety_number(), play.safety_number());

        let work_chain = account_segment_chain(
            account.clone(),
            device.clone(),
            work.clone(),
            "work".into(),
        );
        assert!(!work_chain.is_empty());

        // A host pins the account; the "work" segment joins and resolves AS the
        // account (contact = true), proving the segment belongs to the account.
        let host =
            TalkryptClient::host("127.0.0.1:19957".into(), "#seg".into(), "pq-pure".into(), None)
                .expect("host");
        host.add_contact_hex(account.public_hex(), Some("alice".into()), false);
        let joiner =
            TalkryptClient::join_segment(host.invite_uri(), work, work_chain, None).expect("join seg");

        let mut resolved_as_account = false;
        for _ in 0..50 {
            while let Some(ev) = host.poll_event() {
                if let FfiEvent::Identity { contact, .. } = ev {
                    if contact {
                        resolved_as_account = true;
                    }
                }
            }
            if resolved_as_account {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            resolved_as_account,
            "a segment must resolve as the account that roots its chain"
        );
        assert_eq!(joiner.peer_count(), 1);

        // The linked-device path (no account key): obtain a real account→device
        // chain via linking, then mint a segment under the device key alone.
        let offer = LinkOffer::host(account.clone(), "127.0.0.1:19958".into(), None).expect("offer");
        let res = link_accept(device.clone(), offer.uri(), "phone".into()).expect("link");
        let seg_chain =
            linked_segment_chain(device, res.chain_hex, play, "play".into()).expect("seg chain");
        // It decodes, has 2 links (account→device→segment), and roots at the
        // same account — a linked device minted a segment with no account key.
        let decoded = IdentityChain::decode(&parse_hex_bytes(&seg_chain).unwrap()).unwrap();
        assert_eq!(decoded.links.len(), 2);
        assert_eq!(
            decoded.links.first().unwrap().issuer.fingerprint(),
            account.kp.public().fingerprint()
        );
    }

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

    /// Full device-linking flow over the FFI: a primary certifies a new device,
    /// then that linked device joins a chat and is resolved as the pinned
    /// account — the exact surface the app's linking screen calls.
    #[test]
    fn link_then_chat_as_linked_device() {
        // Primary holds the account and offers linking.
        let account = Account::generate();
        let offer = LinkOffer::host(account.clone(), "127.0.0.1:19955".into(), Some("alice".into()))
            .expect("offer");
        assert_eq!(offer.account_safety_number(), account.safety_number());

        // A new device gets certified under the account.
        let device = DeviceKey::generate();
        let res = link_accept(device.clone(), offer.uri(), "phone".into()).expect("link");
        assert_eq!(res.account_safety_number, account.safety_number());
        assert_eq!(res.username, "alice");
        assert!(!res.chain_hex.is_empty());
        assert_eq!(res.device_fingerprint_hex, device.fingerprint_hex());

        // A separate host pins the account as a contact; the linked device joins
        // presenting its certificate → the host resolves it as that contact. The
        // host also presents ITS OWN account *before* the joiner connects, so the
        // host→joiner identity travels the reactive responder path (the exact
        // on-device scenario that surfaced "identity chain did not bind").
        let host =
            TalkryptClient::host("127.0.0.1:19956".into(), "#linked".into(), "pq-pure".into(), None)
                .expect("host");
        let host_account = Account::generate();
        host.present_account(host_account.clone(), Some("bob".into()));
        host.add_contact_hex(account.public_hex(), Some("alice".into()), false);
        let joiner = TalkryptClient::join_linked(
            host.invite_uri(),
            device,
            res.chain_hex,
            Some("alice".into()),
        )
        .expect("join linked");

        let mut saw_contact = false;
        for _ in 0..50 {
            while let Some(ev) = host.poll_event() {
                if let FfiEvent::Identity {
                    contact, username, ..
                } = ev
                {
                    if contact && username == "alice" {
                        saw_contact = true;
                    }
                }
            }
            if saw_contact {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            saw_contact,
            "linked device must resolve as the pinned account/contact"
        );
        assert_eq!(joiner.peer_count(), 1);

        // Reverse direction: the linked joiner must resolve the host's presented
        // account (NOT raise "identity chain did not bind to peer").
        let mut saw_host_identity = false;
        for _ in 0..50 {
            while let Some(ev) = joiner.poll_event() {
                match ev {
                    FfiEvent::Identity { username, .. } if username == "bob" => {
                        saw_host_identity = true;
                    }
                    FfiEvent::Error { message } => {
                        panic!("linked joiner rejected the host identity: {message}");
                    }
                    _ => {}
                }
            }
            if saw_host_identity {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(
            saw_host_identity,
            "linked joiner must resolve the host's presented account"
        );
    }

    /// Exercise the full FFI facade: host, join, send, receive — the exact
    /// surface other languages call.
    #[test]
    fn ffi_host_join_send_receive() {
        let addr = "127.0.0.1:19922".to_string();
        let host = TalkryptClient::host(addr, "#ffi".into(), "pq-pure".into(), None).expect("host");
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

    /// Multi-session foundation: two independent chats run at once and don't
    /// cross-talk — the assumption the Android session manager relies on.
    #[test]
    fn two_concurrent_chats_are_independent() {
        let a = TalkryptClient::host("127.0.0.1:19931".into(), "#a".into(), "pq-pure".into(), None).expect("host a");
        let b = TalkryptClient::host("127.0.0.1:19932".into(), "#b".into(), "pq-pure".into(), None).expect("host b");
        let ja = TalkryptClient::join(a.invite_uri()).expect("join a");
        let jb = TalkryptClient::join(b.invite_uri()).expect("join b");
        ja.send("alpha".into()).expect("send a");
        jb.send("beta".into()).expect("send b");

        let mut on_a: Vec<String> = Vec::new();
        let mut on_b: Vec<String> = Vec::new();
        for _ in 0..50 {
            while let Some(ev) = a.poll_event() {
                if let FfiEvent::Message { text, .. } = ev { on_a.push(text); }
            }
            while let Some(ev) = b.poll_event() {
                if let FfiEvent::Message { text, .. } = ev { on_b.push(text); }
            }
            if !on_a.is_empty() && !on_b.is_empty() { break; }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(on_a.contains(&"alpha".to_string()), "chat A got: {on_a:?}");
        assert!(on_b.contains(&"beta".to_string()), "chat B got: {on_b:?}");
        // No cross-talk between the two rooms.
        assert!(!on_a.contains(&"beta".to_string()));
        assert!(!on_b.contains(&"alpha".to_string()));
    }

    /// `host` with an endpoint override advertises that address in the invite
    /// (not the bound one), yet a joiner dialing the advertised address still
    /// completes the handshake + exchanges a message. This is what lets a host
    /// bind 0.0.0.0 but hand out a reachable LAN/public IP (or, on an Android
    /// emulator, the host-loopback alias 10.0.2.2). It also proves the endpoint
    /// is a dial hint only — never part of the session root — the same property
    /// `host_tor`'s onion-swap depends on.
    #[test]
    fn host_endpoint_override_advertises_not_binds() {
        let host = TalkryptClient::host(
            "0.0.0.0:19933".into(),
            "#ep".into(),
            "pq-pure".into(),
            Some("127.0.0.1:19933".into()),
        )
        .expect("host");
        // The invite carries the advertised endpoint, not the 0.0.0.0 bind addr.
        let desc = ChatDescriptor::from_uri(&host.invite_uri()).expect("decode invite");
        assert_eq!(desc.endpoints, vec!["127.0.0.1:19933".to_string()]);

        // A joiner dialing the advertised address handshakes + delivers.
        let joiner = TalkryptClient::join(host.invite_uri()).expect("join");
        joiner.send("via advertised endpoint".into()).expect("send");
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
        assert_eq!(got.as_deref(), Some("via advertised endpoint"));
        assert_eq!(joiner.peer_count(), 1);
    }

    /// A joiner must pick its transport from the INVITE, not a UI toggle: an
    /// onion invite needs Tor, a LAN invite needs plain TCP. `invite_is_onion`
    /// drives that — it decodes the descriptor (the `.onion` is inside the base32,
    /// never in the URI text, so a substring check on the URI always fails).
    #[test]
    fn invite_is_onion_detects_endpoint_kind() {
        let lan = TalkryptClient::host("127.0.0.1:19934".into(), "#x".into(), "pq-pure".into(), None)
            .expect("lan host");
        assert!(!invite_is_onion(lan.invite_uri()), "LAN invite is not onion");
        // A naive substring check on the URI text wrongly reports false even for onions.
        assert!(!lan.invite_uri().contains(".onion"));

        let onionish = TalkryptClient::host(
            "127.0.0.1:19935".into(),
            "#x".into(),
            "pq-pure".into(),
            Some("abcdefghij234567.onion:9779".into()),
        )
        .expect("onion-advertised host");
        assert!(invite_is_onion(onionish.invite_uri()), "onion endpoint detected");
        assert!(!onionish.invite_uri().contains(".onion")); // proves the substring check is insufficient

        assert!(!invite_is_onion("talkrypt://not-base32!!!".into()));
    }

    /// A Rust stand-in for a host's secure element, exercising the
    /// `HardwareKeyWrapper` callback seam the way Android/iOS will. "Wraps" by
    /// XOR-ing with a per-instance pad so a different instance (a different
    /// "device") cannot unwrap.
    struct FakeSecureElement {
        pad: u8,
    }
    impl HardwareKeyWrapper for FakeSecureElement {
        fn wrap(&self, kek: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            Ok(kek.iter().map(|b| b ^ self.pad).collect())
        }
        fn unwrap(&self, wrapped: Vec<u8>) -> Result<Vec<u8>, FfiError> {
            Ok(wrapped.iter().map(|b| b ^ self.pad).collect())
        }
    }

    #[test]
    fn account_hardware_seal_roundtrip_via_callback() {
        let account = Account::generate();
        let seed = account.seed_hex();

        // Seal hardware-backed (device wrapper, no passphrase).
        let blob = account
            .seal(None, Some(Box::new(FakeSecureElement { pad: 0x5A })))
            .expect("seal");
        assert_eq!(
            sealed_tier(blob.clone()).unwrap(),
            CustodyTier::HardwareBacked
        );

        // Reload on the same "device" → same seed, same identity.
        let reloaded = Account::from_sealed(
            blob.clone(),
            None,
            Some(Box::new(FakeSecureElement { pad: 0x5A })),
        )
        .expect("from_sealed");
        assert_eq!(reloaded.seed_hex(), seed);
        assert_eq!(reloaded.public_hex(), account.public_hex());

        // A different "device" cannot open it.
        assert!(
            Account::from_sealed(blob, None, Some(Box::new(FakeSecureElement { pad: 0x11 }))).is_err()
        );
    }

    #[test]
    fn account_two_factor_seal_needs_passphrase_and_device() {
        let account = Account::generate();
        let seed = account.seed_hex();
        let blob = account
            .seal(
                Some("pass".into()),
                Some(Box::new(FakeSecureElement { pad: 0x42 })),
            )
            .expect("seal");
        assert_eq!(sealed_tier(blob.clone()).unwrap(), CustodyTier::HardwareBacked);

        // Both factors → ok.
        let ok = Account::from_sealed(
            blob.clone(),
            Some("pass".into()),
            Some(Box::new(FakeSecureElement { pad: 0x42 })),
        )
        .expect("both factors");
        assert_eq!(ok.seed_hex(), seed);

        // Missing passphrase, wrong passphrase, or missing device → all fail.
        assert!(Account::from_sealed(blob.clone(), None, Some(Box::new(FakeSecureElement { pad: 0x42 }))).is_err());
        assert!(Account::from_sealed(blob.clone(), Some("WRONG".into()), Some(Box::new(FakeSecureElement { pad: 0x42 }))).is_err());
        assert!(Account::from_sealed(blob, Some("pass".into()), None).is_err());
    }

    #[test]
    fn software_only_seal_secret_free_fns() {
        let secret = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".to_vec();
        let blob = seal_secret(secret.clone(), Some("pw".into()), None).expect("seal");
        assert_eq!(sealed_tier(blob.clone()).unwrap(), CustodyTier::SoftwareSealed);
        assert_eq!(unseal_secret(blob, Some("pw".into()), None).unwrap(), secret);
    }
}
