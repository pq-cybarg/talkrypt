//! The chat engine: identity + suite + transport tied together.
//!
//! `Core` hosts an inbound listener and dials peers, runs the authenticated
//! handshake, then maintains one ratchet session per peer. Each peer gets a
//! reader task that decrypts inbound frames into [`Event`]s.
//!
//! Two modes:
//!   * **Pairwise** ([`Core::new`]) — `send` encrypts directly to every peer
//!     (a P2P mesh).
//!   * **Group** ([`Core::new_group`]) — a [`GroupRole::Host`] founds a TreeKEM
//!     group and coordinates membership: joining [`GroupRole::Member`]s send a
//!     KeyPackage, receive a Welcome, and thereafter exchange `GroupMsg` frames
//!     (encrypted under the group epoch) that the host relays to all members.
//!
//! The engine is transport-agnostic: loopback for tests, TCP/Arti for real.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use tokio::sync::Mutex as AsyncMutex;

use talkrypt_crypto::suite::SessionHandle;
use talkrypt_crypto::{
    Commit, CryptoSuite, IdentityChain, IdentityKeyPair, IdentityPublic, KeyPackage, LeafKeyPair,
    Revocation, TreeKemGroup, Welcome,
};
use talkrypt_transport::{Endpoint, FrameReader, FrameWriter, Stream, Transport};
use talkrypt_wire::{Reader, Writer};

use crate::descriptor::ChatDescriptor;
use crate::error::Result;
use crate::contacts::{self, ContactStore, Presentation};
use crate::handshake::{self, HandshakeResult};
use crate::marking::{self, Marking};

/// An event emitted by the engine for the UI to render.
#[derive(Clone, Debug)]
pub enum Event {
    /// A peer completed the handshake; `fingerprint` is verified.
    Connected { fingerprint: [u8; 48] },
    /// A decrypted chat message from a peer.
    Message {
        from: [u8; 48],
        channel: String,
        text: String,
        /// Advisory classification marking carried (authenticated) with the
        /// message, if any. Displayed by every build; only originated by builds
        /// with the `markings` feature.
        marking: Option<Marking>,
    },
    /// A peer resolved its authenticated device to an **account** identity (it
    /// presented a certificate chain inside the encrypted session). `from` is
    /// the peer's authenticated device fingerprint; `account_fingerprint` is the
    /// account the chain roots at; `username` is the peer's self-asserted label
    /// (display only); `contact` is `true` iff that account is a recognized
    /// contact, and `friend` iff you've labeled that contact a friend (both
    /// unforgeable without the account's private key). Neither implies access.
    /// A peer that stays a pseudonym never triggers this event.
    Identity {
        from: [u8; 48],
        account_fingerprint: [u8; 48],
        username: Option<String>,
        contact: bool,
        friend: bool,
    },
    /// A peer connection closed.
    Disconnected { fingerprint: [u8; 48] },
    /// A non-fatal error (e.g. a frame that failed to decrypt).
    Error(String),
}

/// A frame carried inside the pairwise encrypted channel. `Chat` is a direct
/// pairwise message (P2P/non-group); the rest coordinate TreeKEM group chat,
/// where `GroupMsg` payloads are additionally encrypted under the group epoch.
enum Frame {
    Chat {
        channel: String,
        text: String,
        marking: Option<Marking>,
    },
    KeyPackage(Vec<u8>),
    Welcome(Vec<u8>),
    /// A membership commit tagged with the epoch it applies to (for ordering).
    Commit {
        from_epoch: u32,
        bytes: Vec<u8>,
    },
    GroupMsg(Vec<u8>),
    /// Full leaf→fingerprint roster snapshot, for message attribution.
    Roster(Vec<(u32, [u8; 48])>),
    /// An encoded [`crate::contacts::Presentation`] — the peer's account→device
    /// certificate chain (+ optional username). Sent as the FIRST frame inside
    /// the encrypted session (never in the plaintext handshake) so the sensitive
    /// account↔device linkage is AEAD-protected and forward-secret.
    Identity(Vec<u8>),
    /// The host refused this peer on a restricted channel (carries a short
    /// reason). Sent just before disconnecting so the joiner gets explicit
    /// feedback instead of a silent drop.
    AccessDenied(String),
    /// An encoded [`Revocation`] propagated in-band: the receiver verifies the
    /// account signature and adds it, locking out the revoked device.
    Revocation(Vec<u8>),
}

impl Frame {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Frame::Chat {
                channel,
                text,
                marking,
            } => {
                w.put_u8(0);
                w.put_bytes(channel.as_bytes());
                w.put_bytes(text.as_bytes());
                marking::put_opt(&mut w, marking);
            }
            Frame::KeyPackage(b) => {
                w.put_u8(1);
                w.put_bytes(b);
            }
            Frame::Welcome(b) => {
                w.put_u8(2);
                w.put_bytes(b);
            }
            Frame::Commit { from_epoch, bytes } => {
                w.put_u8(3);
                w.put_u32(*from_epoch);
                w.put_bytes(bytes);
            }
            Frame::GroupMsg(b) => {
                w.put_u8(4);
                w.put_bytes(b);
            }
            Frame::Roster(entries) => {
                w.put_u8(5);
                w.put_u32(entries.len() as u32);
                for (leaf, fp) in entries {
                    w.put_u32(*leaf);
                    w.put_bytes(fp);
                }
            }
            Frame::Identity(b) => {
                w.put_u8(6);
                w.put_bytes(b);
            }
            Frame::AccessDenied(reason) => {
                w.put_u8(7);
                w.put_bytes(reason.as_bytes());
            }
            Frame::Revocation(b) => {
                w.put_u8(8);
                w.put_bytes(b);
            }
        }
        w.into_vec()
    }

    fn decode(bytes: &[u8]) -> Option<Frame> {
        let mut r = Reader::new(bytes);
        let frame = match r.get_u8().ok()? {
            0 => Frame::Chat {
                channel: String::from_utf8(r.get_vec().ok()?).ok()?,
                text: String::from_utf8(r.get_vec().ok()?).ok()?,
                marking: marking::get_opt(&mut r).ok()?,
            },
            1 => Frame::KeyPackage(r.get_vec().ok()?),
            2 => Frame::Welcome(r.get_vec().ok()?),
            3 => Frame::Commit {
                from_epoch: r.get_u32().ok()?,
                bytes: r.get_vec().ok()?,
            },
            4 => Frame::GroupMsg(r.get_vec().ok()?),
            5 => {
                let n = r.get_u32().ok()?;
                if n > 100_000 {
                    return None;
                }
                let mut entries = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    let leaf = r.get_u32().ok()?;
                    let fpv = r.get_bytes().ok()?;
                    if fpv.len() != 48 {
                        return None;
                    }
                    let mut fp = [0u8; 48];
                    fp.copy_from_slice(fpv);
                    entries.push((leaf, fp));
                }
                Frame::Roster(entries)
            }
            6 => Frame::Identity(r.get_vec().ok()?),
            7 => Frame::AccessDenied(String::from_utf8(r.get_vec().ok()?).ok()?),
            8 => Frame::Revocation(r.get_vec().ok()?),
            _ => return None,
        };
        Some(frame)
    }
}

/// Who may participate in a (pairwise) channel. The host enforces this when a
/// peer presents its account identity inside the encrypted session.
///
/// A **registry-restricted channel** is built from this: the creator populates
/// [`AccessPolicy::Accounts`] with the account fingerprints registered on a
/// specific registry (a "beacon") that only the creator knows — so only members
/// of that registry can be heard, without the registry's address appearing in
/// the invite.
#[derive(Clone, Debug, Default)]
pub enum AccessPolicy {
    /// Anyone with the invite (and password, if any) may participate.
    #[default]
    Open,
    /// Only these account fingerprints may participate (an explicit allowlist —
    /// e.g. populated from a registry for a *registry-restricted channel*). A
    /// peer presenting a non-listed account — or no account (a pseudonym) — is
    /// silenced and disconnected.
    Accounts(std::collections::HashSet<[u8; 48]>),
    /// Only **recognized contacts** may participate. This is still a deliberate,
    /// unilateral access grant — you're choosing "let my contacts in" — it just
    /// derives the allowlist from whom you recognize rather than a fixed set.
    Contacts,
    /// Only contacts you've **labeled friends** may participate.
    Friends,
}

impl AccessPolicy {
    /// An open policy admits everyone immediately (no identity needed); the
    /// restrictive modes require the peer to present a qualifying account.
    fn is_open(&self) -> bool {
        matches!(self, AccessPolicy::Open)
    }

    /// Decide admission from a peer's resolved identity: its account
    /// fingerprint plus whether it's a recognized `contact` / labeled `friend`.
    fn admits(&self, account_fingerprint: &[u8; 48], contact: bool, friend: bool) -> bool {
        match self {
            AccessPolicy::Open => true,
            AccessPolicy::Accounts(set) => set.contains(account_fingerprint),
            AccessPolicy::Contacts => contact,
            AccessPolicy::Friends => friend,
        }
    }
}

/// The outcome of evaluating a peer's presented identity against the policy.
enum IdentityOutcome {
    /// Allowed (Open, or the account is listed) — peer is approved.
    Allowed,
    /// The account is not permitted — the peer must be disconnected.
    Rejected,
    /// The presentation was malformed / didn't bind — ignore it.
    Ignored,
}

/// Whether this node participates in a TreeKEM group, and as what.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GroupRole {
    /// Not a group chat — direct pairwise messaging.
    None,
    /// Group founder + coordinator (commits membership, relays group messages).
    Host,
    /// Group member that joins via Welcome.
    Member,
}

/// Where a routed frame should go, in **relayed** group mode (where a
/// non-member relay forwards between participants). The relay never reads the
/// inner group plaintext — it only routes the (still-encrypted) inner frame.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// To every participant except the sender.
    Broadcast,
    /// To one participant.
    Peer([u8; 48]),
    /// To the group's committer (the founder member).
    Committer,
}

/// A frame wrapped for relaying: routing intent + the original sender's
/// fingerprint (stamped by the relay) + the inner [`Frame`] bytes.
pub(crate) struct Routed {
    pub(crate) to: Route,
    pub(crate) from: [u8; 48],
    pub(crate) inner: Vec<u8>,
}

impl Routed {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self.to {
            Route::Broadcast => w.put_u8(0),
            Route::Peer(fp) => {
                w.put_u8(1);
                w.put_bytes(&fp);
            }
            Route::Committer => w.put_u8(2),
        }
        w.put_bytes(&self.from);
        w.put_bytes(&self.inner);
        w.into_vec()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Routed> {
        let mut r = Reader::new(bytes);
        let to = match r.get_u8().ok()? {
            0 => Route::Broadcast,
            1 => Route::Peer(read_fp(&mut r)?),
            2 => Route::Committer,
            _ => return None,
        };
        let from = read_fp(&mut r)?;
        let inner = r.get_vec().ok()?;
        Some(Routed { to, from, inner })
    }
}

fn read_fp(r: &mut Reader) -> Option<[u8; 48]> {
    let v = r.get_bytes().ok()?;
    if v.len() != 48 {
        return None;
    }
    let mut fp = [0u8; 48];
    fp.copy_from_slice(v);
    Some(fp)
}

type SharedSession = Arc<AsyncMutex<Box<dyn SessionHandle>>>;
type SharedWriter = Arc<AsyncMutex<Box<dyn FrameWriter>>>;

struct Peer {
    fingerprint: [u8; 48],
    writer: SharedWriter,
    session: SharedSession,
    /// Pairwise payloads queued because the session wasn't send-ready yet (a
    /// responder can't send before receiving the initiator's first frame).
    /// Flushed, in order, by the reader loop once the session is keyed — so the
    /// host's opening line isn't silently dropped.
    pending: Arc<Mutex<Vec<Vec<u8>>>>,
}

struct Inner {
    identity: IdentityKeyPair,
    suite: Arc<dyn CryptoSuite>,
    transport: Arc<dyn Transport>,
    descriptor: ChatDescriptor,
    root0: [u8; 32],
    peers: Mutex<Vec<Peer>>,
    events_tx: tokio::sync::mpsc::UnboundedSender<Event>,
    // --- TreeKEM group state (GroupRole::None for plain pairwise chats) ---
    role: GroupRole,
    group: AsyncMutex<Option<TreeKemGroup>>,
    /// A joining member's leaf key, consumed when its Welcome arrives.
    leaf_keypair: Mutex<Option<LeafKeyPair>>,
    /// leaf → member fingerprint, for attributing relayed group messages.
    roster: Mutex<HashMap<u32, [u8; 48]>>,
    /// Commits received ahead of our epoch, keyed by the epoch they apply to.
    pending_commits: Mutex<BTreeMap<u32, Vec<u8>>>,
    /// In relayed mode, frames are wrapped in [`Routed`] and a non-member relay
    /// fans them out (the participant never fans out itself).
    relayed: bool,
    /// Default marking applied to outgoing messages (from the channel policy in
    /// the descriptor). `None` in consumer builds / unmarked chats.
    default_marking: Option<Marking>,
    /// The account identity presentation (encoded [`Presentation`]) this node
    /// sends to each peer as the first encrypted frame. `None` ⇒ pseudonym
    /// (present nothing — unlinkable). Set via [`Core::present_identity`].
    present_chain: Mutex<Option<Vec<u8>>>,
    /// Recognized accounts (contacts, optionally labeled friends). An incoming
    /// chain rooting at one resolves as `contact: true`. Populated via
    /// [`Core::add_contact`]. Recognition only — NOT access (see `access`).
    contacts: Mutex<ContactStore>,
    /// Account keys seen on presented (verified, peer-bound) chains, keyed by
    /// account fingerprint. Lets the UI pin a just-seen account by fingerprint
    /// after an out-of-band safety-number check — TOFU friending without pasting
    /// a 2592-byte key. See [`Core::pin_seen_account`].
    seen_accounts: Mutex<HashMap<[u8; 48], IdentityPublic>>,
    /// Who may participate (pairwise). `Open` by default; a registry-restricted
    /// channel sets [`AccessPolicy::Accounts`]. See [`Core::restrict_to_accounts`].
    access: Mutex<AccessPolicy>,
    /// Revoked (account_fp, subject_fp) pairs. A presented chain with a revoked
    /// link is refused recognition even if otherwise valid. See
    /// [`Core::add_revocation`].
    revocations: Mutex<std::collections::HashSet<([u8; 48], [u8; 48])>>,
    /// Group-chat host: peers whose presented account the access policy admits.
    /// A KeyPackage is honored only from an admitted peer (under a restrictive
    /// policy), so group membership is gated like pairwise access.
    admitted_peers: Mutex<std::collections::HashSet<[u8; 48]>>,
}

/// The chat engine handle. Cheap to clone (shared inner state).
#[derive(Clone)]
pub struct Core {
    inner: Arc<Inner>,
}

impl Core {
    /// Build a core. Returns the engine and the receiver for its event stream.
    pub fn new(
        identity: IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: ChatDescriptor,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        Self::build(
            identity,
            suite,
            transport,
            descriptor,
            GroupRole::None,
            false,
        )
    }

    /// Build a host-coordinated TreeKEM group chat. The `Host` founds the group,
    /// coordinates membership, AND relays group messages (it is a member and can
    /// read them). For a relay that cannot read, see [`Core::new_relayed_group`].
    pub fn new_group(
        identity: IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: ChatDescriptor,
        is_host: bool,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let role = if is_host {
            GroupRole::Host
        } else {
            GroupRole::Member
        };
        Self::build(identity, suite, transport, descriptor, role, false)
    }

    /// Build a TreeKEM group chat that runs over a **non-member relay**
    /// ([`RelayHub`]): the committer (`is_committer`) founds the group and a
    /// member joins, but all frames are forwarded by a relay that never holds
    /// the group key and so cannot read group plaintext. Each participant dials
    /// the relay with [`Core::connect`].
    pub fn new_relayed_group(
        identity: IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: ChatDescriptor,
        is_committer: bool,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let role = if is_committer {
            GroupRole::Host
        } else {
            GroupRole::Member
        };
        Self::build(identity, suite, transport, descriptor, role, true)
    }

    fn build(
        identity: IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: ChatDescriptor,
        role: GroupRole,
        relayed: bool,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let root0 = descriptor.derive_root();
        let default_marking = descriptor.channel_marking.clone();
        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        // Group state uses the same KEM profile as the suite's pairwise
        // sessions, so TreeKEM node keys and ratchet keys agree posture + wire.
        let kem_profile = suite.kem_profile();
        let group = match role {
            GroupRole::Host => Some(TreeKemGroup::create_with(kem_profile)),
            _ => None,
        };
        let leaf_keypair = match role {
            GroupRole::Member => Some(LeafKeyPair::generate_with(kem_profile)),
            _ => None,
        };
        // The host founds the group at leaf 0; seed the roster with itself.
        let mut roster = HashMap::new();
        if role == GroupRole::Host {
            roster.insert(0u32, identity.public().fingerprint());
        }
        let inner = Arc::new(Inner {
            identity,
            suite,
            transport,
            descriptor,
            root0,
            peers: Mutex::new(Vec::new()),
            events_tx,
            role,
            group: AsyncMutex::new(group),
            leaf_keypair: Mutex::new(leaf_keypair),
            roster: Mutex::new(roster),
            pending_commits: Mutex::new(BTreeMap::new()),
            relayed,
            default_marking,
            present_chain: Mutex::new(None),
            contacts: Mutex::new(ContactStore::new()),
            seen_accounts: Mutex::new(HashMap::new()),
            access: Mutex::new(AccessPolicy::Open),
            revocations: Mutex::new(std::collections::HashSet::new()),
            admitted_peers: Mutex::new(std::collections::HashSet::new()),
        });
        (Core { inner }, events_rx)
    }

    /// Our own verified fingerprint (safety number source).
    pub fn fingerprint(&self) -> [u8; 48] {
        self.inner.identity.public().fingerprint()
    }

    /// Our public identity.
    pub fn identity_public(&self) -> &IdentityPublic {
        self.inner.identity.public()
    }

    /// Present an **account identity** to peers: from now on, every peer we
    /// connect to (or that connects to us) receives this account→…→device
    /// certificate `chain` plus an optional `username`, as the first frame
    /// *inside the encrypted session*. The chain's leaf MUST be this node's
    /// device key (so the peer can bind it to the key it authenticated).
    ///
    /// Call with a chain rooting at your account to appear as that account
    /// ("linked"); never call it (the default) to stay a pseudonym/rotating
    /// identity — unlinkable, and unable to claim any friended account.
    pub fn present_identity(&self, chain: IdentityChain, username: Option<String>) {
        let encoded = Presentation::new(chain, username).encode();
        *self.inner.present_chain.lock().unwrap() = Some(encoded);
    }

    /// Stop presenting an account identity (revert to pseudonym for future
    /// connections). Existing sessions are unaffected.
    pub fn clear_identity(&self) {
        *self.inner.present_chain.lock().unwrap() = None;
    }

    /// Send the current account presentation (if any) to all **already
    /// connected** peers — so a user can link mid-session, not only on new
    /// connections. No-op for pseudonyms and in group/relayed mode. The chain
    /// still travels inside each peer's encrypted session.
    pub async fn announce_identity(&self) {
        if self.inner.role != GroupRole::None || self.inner.relayed {
            return;
        }
        let bytes = self.inner.present_chain.lock().unwrap().clone();
        if let Some(bytes) = bytes {
            for (session, writer, _) in collect_peers(&self.inner) {
                let _ = send_payload(&session, &writer, &Frame::Identity(bytes.clone()).encode())
                    .await;
            }
        }
    }

    // ----- contacts + friends (recognition; unilateral; NOT access) -----

    /// Add (or update) a **contact** by account public key — you recognize this
    /// account, so a peer presenting it resolves as `contact: true` in
    /// [`Event::Identity`]. `friend` is your own elevated label. Unilateral: the
    /// other party need not recognize you, and this grants them nothing. Only the
    /// real account can produce a chain rooting at it (ML-DSA-87 unforgeability),
    /// so recognition can't be spoofed.
    pub fn add_contact(&self, account: IdentityPublic, name: Option<String>, friend: bool) {
        self.inner.contacts.lock().unwrap().add(account, name, friend);
    }

    /// Set (or clear) the friend label on an existing contact.
    pub fn set_friend(&self, account: &IdentityPublic, friend: bool) -> bool {
        self.inner.contacts.lock().unwrap().set_friend(account, friend)
    }

    /// Whether `account` is a recognized contact.
    pub fn is_contact(&self, account: &IdentityPublic) -> bool {
        self.inner.contacts.lock().unwrap().is_contact(account)
    }

    /// Whether `account` is a contact you've labeled a friend.
    pub fn is_friend(&self, account: &IdentityPublic) -> bool {
        self.inner.contacts.lock().unwrap().is_friend(account)
    }

    /// Record a **revocation** of a device/segment key (signed by its account).
    /// A presented chain containing a revoked link is then refused recognition,
    /// even if otherwise valid — so a lost/compromised device is locked out even
    /// if its key leaks. Returns `false` if the revocation's signature is bad.
    pub fn add_revocation(&self, revocation: Revocation) -> bool {
        if revocation.verify().is_err() {
            return false;
        }
        self.inner
            .revocations
            .lock()
            .unwrap()
            .insert((revocation.account.fingerprint(), revocation.subject_fp));
        true
    }

    /// Number of revocations held.
    pub fn revocation_count(&self) -> usize {
        self.inner.revocations.lock().unwrap().len()
    }

    /// Add a revocation locally AND propagate it to connected peers (in-band).
    /// Returns `false` if the signature is bad. Use this when you (the account)
    /// revoke one of your devices so contacts lock it out too.
    pub async fn broadcast_revocation(&self, revocation: Revocation) -> bool {
        if !self.add_revocation(revocation.clone()) {
            return false;
        }
        if self.inner.role == GroupRole::None && !self.inner.relayed {
            for (s, w, _) in collect_peers(&self.inner) {
                let _ =
                    send_payload(&s, &w, &Frame::Revocation(revocation.encode()).encode()).await;
            }
        }
        true
    }

    /// Number of recognized contacts.
    pub fn contact_count(&self) -> usize {
        self.inner.contacts.lock().unwrap().len()
    }

    // ----- access (a SEPARATE, unilateral grant — no contact/friend/mutual
    // relationship required to allow an account in) -----

    /// Restrict this (pairwise) channel to the given **account fingerprints**:
    /// only peers presenting one of these accounts are heard; pseudonyms and
    /// other accounts are silenced and disconnected. This is an access grant,
    /// independent of contacts/friends — you can allow accounts you've never
    /// recognized. Build the set from a registry you alone know for a
    /// *registry-restricted* channel.
    pub fn restrict_to_accounts(&self, accounts: std::collections::HashSet<[u8; 48]>) {
        *self.inner.access.lock().unwrap() = AccessPolicy::Accounts(accounts);
    }

    /// Restrict this channel to **recognized contacts** (a unilateral grant that
    /// derives the allowlist from whom you recognize). A peer is admitted iff its
    /// presented account is a contact.
    pub fn restrict_to_contacts(&self) {
        *self.inner.access.lock().unwrap() = AccessPolicy::Contacts;
    }

    /// Restrict this channel to contacts you've **labeled friends**.
    pub fn restrict_to_friends(&self) {
        *self.inner.access.lock().unwrap() = AccessPolicy::Friends;
    }

    /// Grant one account access by fingerprint (unilateral). On an explicit
    /// allowlist, adds to it; from any mode-based policy (`Open`/`Contacts`/
    /// `Friends`) it starts an explicit allowlist containing just this account.
    pub fn allow_account(&self, account_fingerprint: [u8; 48]) {
        let mut access = self.inner.access.lock().unwrap();
        match &mut *access {
            AccessPolicy::Accounts(set) => {
                set.insert(account_fingerprint);
            }
            _ => {
                let mut set = std::collections::HashSet::new();
                set.insert(account_fingerprint);
                *access = AccessPolicy::Accounts(set);
            }
        }
    }

    /// Revoke one account's access (no-op on an `Open` channel).
    pub fn deny_account(&self, account_fingerprint: [u8; 48]) {
        let mut access = self.inner.access.lock().unwrap();
        if let AccessPolicy::Accounts(set) = &mut *access {
            set.remove(&account_fingerprint);
        }
    }

    /// Set an explicit access policy (e.g. back to `Open`).
    pub fn set_access_policy(&self, policy: AccessPolicy) {
        *self.inner.access.lock().unwrap() = policy;
    }

    /// Remove all restrictions (anyone with the invite may participate).
    pub fn open_access(&self) {
        *self.inner.access.lock().unwrap() = AccessPolicy::Open;
    }

    /// The account public key seen (on a verified, peer-bound chain) for
    /// `account_fingerprint`, if any. Use its `safety_number()` for an
    /// out-of-band comparison before adding it.
    pub fn seen_account(&self, account_fingerprint: [u8; 48]) -> Option<IdentityPublic> {
        self.inner
            .seen_accounts
            .lock()
            .unwrap()
            .get(&account_fingerprint)
            .cloned()
    }

    /// Add a just-seen account as a contact by its fingerprint (TOFU after an
    /// out-of-band safety-number check). Returns `true` if the account was known
    /// from a prior [`Event::Identity`]; `false` if no such account was seen.
    pub fn add_seen_contact(
        &self,
        account_fingerprint: [u8; 48],
        name: Option<String>,
        friend: bool,
    ) -> bool {
        match self.seen_account(account_fingerprint) {
            Some(acct) => {
                self.inner.contacts.lock().unwrap().add(acct, name, friend);
                true
            }
            None => false,
        }
    }

    /// Fingerprints of all accounts seen on verified presentations this session
    /// (candidates for `add_seen_contact`).
    pub fn seen_account_fingerprints(&self) -> Vec<[u8; 48]> {
        self.inner
            .seen_accounts
            .lock()
            .unwrap()
            .keys()
            .copied()
            .collect()
    }

    /// All contacts (account fingerprint, remembered name, friend label).
    pub fn contacts(&self) -> Vec<([u8; 48], Option<String>, bool)> {
        self.inner
            .contacts
            .lock()
            .unwrap()
            .iter()
            .map(|c| (c.account_fingerprint, c.name.clone(), c.friend))
            .collect()
    }

    /// Export contacts for persistence: (account public-key bytes, name, friend).
    /// Reload them with [`Core::add_contact_bytes`] on a fresh session.
    pub fn export_contacts(&self) -> Vec<(Vec<u8>, Option<String>, bool)> {
        self.inner
            .contacts
            .lock()
            .unwrap()
            .iter()
            .map(|c| (c.account.sig_vk.clone(), c.name.clone(), c.friend))
            .collect()
    }

    /// Add a contact from raw account public-key bytes (the persistence-friendly
    /// counterpart to [`Core::add_contact`]).
    pub fn add_contact_bytes(&self, account_pubkey: Vec<u8>, name: Option<String>, friend: bool) {
        self.add_contact(
            IdentityPublic {
                sig_vk: account_pubkey,
            },
            name,
            friend,
        );
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.inner.peers.lock().unwrap().len()
    }

    /// The chat descriptor (shareable invite).
    pub fn descriptor(&self) -> &ChatDescriptor {
        &self.inner.descriptor
    }

    /// The current leaf→fingerprint roster (group chats).
    pub fn roster(&self) -> Vec<(u32, [u8; 48])> {
        self.inner
            .roster
            .lock()
            .unwrap()
            .iter()
            .map(|(l, f)| (*l, *f))
            .collect()
    }

    /// Host only: remove a group member by fingerprint and broadcast the
    /// membership commit. The removed member cannot derive the new epoch, so it
    /// cannot read any subsequent message (forward secrecy against removal).
    pub async fn remove_member(&self, fingerprint: [u8; 48]) -> Result<()> {
        if self.inner.role != GroupRole::Host {
            return Ok(());
        }
        let leaf = self
            .inner
            .roster
            .lock()
            .unwrap()
            .iter()
            .find(|(_, fp)| **fp == fingerprint)
            .map(|(l, _)| *l);
        let Some(leaf) = leaf else { return Ok(()) };

        let tagged = {
            let mut g = self.inner.group.lock().await;
            match g.as_mut() {
                Some(grp) => {
                    let from_epoch = grp.epoch();
                    grp.remove(leaf).ok().map(|c| (from_epoch, c.encode()))
                }
                None => None,
            }
        };
        let Some((from_epoch, commit_bytes)) = tagged else {
            return Ok(());
        };
        let roster_snapshot = {
            let mut roster = self.inner.roster.lock().unwrap();
            roster.remove(&leaf);
            roster.iter().map(|(l, f)| (*l, *f)).collect::<Vec<_>>()
        };
        // Broadcast the membership commit + new roster. The removed member, if
        // still connected, receives the commit but cannot apply it (it lacks the
        // new path secret), so it advances no further and stays locked out.
        route(
            &self.inner,
            Frame::Commit {
                from_epoch,
                bytes: commit_bytes,
            },
            Route::Broadcast,
        )
        .await;
        route(
            &self.inner,
            Frame::Roster(roster_snapshot),
            Route::Broadcast,
        )
        .await;
        Ok(())
    }

    /// Start accepting inbound connections (spawns a background accept loop).
    pub async fn host(&self) -> Result<Endpoint> {
        let listener = self.inner.transport.listen().await?;
        let endpoint = listener.endpoint();
        let inner = self.inner.clone();
        let mut listener = listener;
        tokio::spawn(async move {
            while let Ok(mut stream) = listener.accept().await {
                let hs = handshake::respond(
                    stream.as_mut(),
                    &inner.identity,
                    inner.suite.as_ref(),
                    inner.root0,
                )
                .await;
                match hs {
                    Ok(hs) => register(&inner, stream, hs, false),
                    Err(e) => {
                        let _ = inner
                            .events_tx
                            .send(Event::Error(format!("inbound handshake failed: {e}")));
                    }
                }
            }
        });
        Ok(endpoint)
    }

    /// Dial a peer endpoint and run the initiator handshake.
    pub async fn connect(&self, endpoint: &str) -> Result<[u8; 48]> {
        let mut stream = self.inner.transport.dial(&endpoint.to_string()).await?;
        let hs = handshake::initiate(
            stream.as_mut(),
            &self.inner.identity,
            self.inner.suite.as_ref(),
            self.inner.root0,
        )
        .await?;
        let fp = hs.peer_identity.fingerprint();
        register(&self.inner, stream, hs, true);

        // A joining group member sends its KeyPackage toward the committer
        // (directly to the host, or via the relay in relayed mode).
        if self.inner.role == GroupRole::Member {
            // Present our account FIRST (in-order, before the KeyPackage) so a
            // host with a restrictive access policy admits us before deciding on
            // the KeyPackage. Non-relayed only (relayed carries Routed envelopes).
            if !self.inner.relayed {
                let pres = self.inner.present_chain.lock().unwrap().clone();
                if let Some(bytes) = pres {
                    route(&self.inner, Frame::Identity(bytes), Route::Committer).await;
                }
            }
            let kp_bytes = self
                .inner
                .leaf_keypair
                .lock()
                .unwrap()
                .as_ref()
                .map(|k| k.key_package().encode());
            if let Some(kpb) = kp_bytes {
                route(&self.inner, Frame::KeyPackage(kpb), Route::Committer).await;
            }
        } else if self.inner.relayed && self.inner.role == GroupRole::Host {
            // A relayed committer is the session initiator toward the relay but
            // would otherwise send nothing first — which leaves the relay (a
            // ratchet responder) unable to forward to it. Send the initial
            // roster to prime the session (and announce the committer).
            let snapshot: Vec<(u32, [u8; 48])> = self
                .inner
                .roster
                .lock()
                .unwrap()
                .iter()
                .map(|(l, f)| (*l, *f))
                .collect();
            route(&self.inner, Frame::Roster(snapshot), Route::Broadcast).await;
        }
        Ok(fp)
    }

    /// Send `text`. In a plain chat this is a direct pairwise message to every
    /// peer; in a group chat it is encrypted once under the group epoch and
    /// fanned out (the host relays to all members).
    pub async fn send(&self, text: &str) -> Result<()> {
        self.send_marked(text, self.inner.default_marking.clone())
            .await
    }

    /// Send `text` carrying an explicit (authenticated) classification marking.
    /// The marking travels inside the AEAD-protected payload — confidential and
    /// tamper-evident — for both pairwise and group messages.
    pub async fn send_marked(&self, text: &str, marking: Option<Marking>) -> Result<()> {
        match self.inner.role {
            GroupRole::None => {
                let frame = Frame::Chat {
                    channel: self.inner.descriptor.channel.clone(),
                    text: text.to_string(),
                    marking,
                };
                let payload = frame.encode();
                for (session, writer, fp) in collect_peers(&self.inner) {
                    // A responder can't encrypt until it's received the peer's
                    // first frame; queue (don't drop) — the reader loop flushes
                    // it once the session is keyed.
                    let ready = { session.lock().await.can_send() };
                    if ready {
                        let _ = send_payload(&session, &writer, &payload).await;
                    } else if let Some(pending) = pending_for(&self.inner, fp) {
                        pending.lock().unwrap().push(payload.clone());
                    }
                }
            }
            GroupRole::Host | GroupRole::Member => {
                let payload = marking::encode_payload(&marking, text);
                let frame = {
                    let mut g = self.inner.group.lock().await;
                    match g.as_mut() {
                        Some(grp) => Frame::GroupMsg(grp.encrypt(&payload)?),
                        None => return Err(crate::error::CoreError::GroupNotReady),
                    }
                };
                route(&self.inner, frame, Route::Broadcast).await;
            }
        }
        Ok(())
    }
}

fn collect_peers(inner: &Arc<Inner>) -> Vec<(SharedSession, SharedWriter, [u8; 48])> {
    inner
        .peers
        .lock()
        .unwrap()
        .iter()
        .map(|p| (p.session.clone(), p.writer.clone(), p.fingerprint))
        .collect()
}

fn peer_handles(inner: &Arc<Inner>, fp: [u8; 48]) -> Option<(SharedSession, SharedWriter)> {
    inner
        .peers
        .lock()
        .unwrap()
        .iter()
        .find(|p| p.fingerprint == fp)
        .map(|p| (p.session.clone(), p.writer.clone()))
}

/// The outbound queue for a peer (messages held until its session is send-ready).
fn pending_for(inner: &Arc<Inner>, fp: [u8; 48]) -> Option<Arc<Mutex<Vec<Vec<u8>>>>> {
    inner
        .peers
        .lock()
        .unwrap()
        .iter()
        .find(|p| p.fingerprint == fp)
        .map(|p| p.pending.clone())
}

/// Encrypt a pairwise payload (a `Frame` or a `Routed` envelope) and send it.
async fn send_payload(
    session: &SharedSession,
    writer: &SharedWriter,
    payload: &[u8],
) -> Result<()> {
    let ct = {
        let mut s = session.lock().await;
        s.encrypt(payload)?
    };
    let mut w = writer.lock().await;
    w.send_frame(&ct).await?;
    Ok(())
}

/// Route a frame to its destination. In **relayed** mode the frame is wrapped
/// in a [`Routed`] envelope and sent to the single relay peer, which fans it
/// out. In host-coordinated mode it is sent directly to the resolved peers.
async fn route(inner: &Arc<Inner>, frame: Frame, to: Route) {
    if inner.relayed {
        let routed = Routed {
            to,
            from: inner.identity.public().fingerprint(),
            inner: frame.encode(),
        };
        let payload = routed.encode();
        // A relayed participant's only peer is the relay.
        for (s, w, _) in collect_peers(inner) {
            let _ = send_payload(&s, &w, &payload).await;
        }
    } else {
        let payload = frame.encode();
        match to {
            Route::Peer(fp) => {
                if let Some((s, w)) = peer_handles(inner, fp) {
                    let _ = send_payload(&s, &w, &payload).await;
                }
            }
            // Broadcast/Committer: the host's peers are exactly the members.
            Route::Broadcast | Route::Committer => {
                for (s, w, _) in collect_peers(inner) {
                    let _ = send_payload(&s, &w, &payload).await;
                }
            }
        }
    }
}

/// Register a freshly-handshaked peer: store it and spawn its reader task.
///
/// `is_initiator` is whether *we* dialed (ratchet initiator) vs. accepted
/// (responder). It matters for identity presentation: a ratchet **responder
/// cannot send until it has received the initiator's first frame**, so an
/// eager presentation from the responder would be dropped. The initiator
/// presents immediately (it sends first); the responder presents *reactively*
/// from the reader loop, right after its session becomes send-ready.
fn register(inner: &Arc<Inner>, stream: Box<dyn Stream>, hs: HandshakeResult, is_initiator: bool) {
    let (writer, reader) = stream.into_split();
    let fingerprint = hs.peer_identity.fingerprint();
    let session = Arc::new(AsyncMutex::new(hs.session));
    let writer = Arc::new(AsyncMutex::new(writer));

    inner.peers.lock().unwrap().push(Peer {
        fingerprint,
        writer: writer.clone(),
        session: session.clone(),
        pending: Arc::new(Mutex::new(Vec::new())),
    });
    let _ = inner.events_tx.send(Event::Connected { fingerprint });

    // Identity presentation rides as the first frame *inside* the encrypted
    // session (never in the plaintext handshake), so the sensitive
    // account↔device linkage is AEAD-protected. Only in plain pairwise mode —
    // group/relayed pairwise channels carry coordination/`Routed` envelopes.
    let present_pairwise = inner.role == GroupRole::None && !inner.relayed;
    if present_pairwise && is_initiator {
        // Initiator sends first, so it can present right away.
        if let Some(bytes) = inner.present_chain.lock().unwrap().clone() {
            let s = session.clone();
            let w = writer.clone();
            tokio::spawn(async move {
                let _ = send_payload(&s, &w, &Frame::Identity(bytes).encode()).await;
            });
        }
    }
    // The responder presents reactively (see reader_loop): once it has decrypted
    // the initiator's first frame, its ratchet is send-ready.
    let present_reactively = present_pairwise && !is_initiator;

    tokio::spawn(reader_loop(
        inner.clone(),
        reader,
        session,
        fingerprint,
        present_reactively,
    ));
}

async fn reader_loop(
    inner: Arc<Inner>,
    mut reader: Box<dyn FrameReader>,
    session: Arc<AsyncMutex<Box<dyn SessionHandle>>>,
    fingerprint: [u8; 48],
    present_reactively: bool,
) {
    // The responder presents its identity once, after the first inbound frame
    // makes its ratchet send-ready (see `register`).
    let mut presented = false;
    // Access gate: a peer is "approved" immediately under an Open policy, else
    // only after it presents an allowed account (see the Identity arm below).
    let mut approved = inner.access.lock().unwrap().is_open();
    loop {
        let frame = match reader.recv_frame().await {
            Ok(f) => f,
            Err(_) => {
                let _ = inner.events_tx.send(Event::Disconnected { fingerprint });
                break;
            }
        };
        let opened = {
            let mut s = session.lock().await;
            s.decrypt(&frame)
        };
        let pt = match opened {
            Ok(pt) => pt,
            Err(_) => {
                let _ = inner
                    .events_tx
                    .send(Event::Error("frame failed to decrypt".into()));
                continue;
            }
        };
        // Now send-ready: if we're a responder with an identity to present, send
        // it back to this peer exactly once.
        if present_reactively && !presented {
            presented = true;
            // Bind to a local so the std MutexGuard drops before the await.
            let pending = inner.present_chain.lock().unwrap().clone();
            if let Some(bytes) = pending {
                if let Some((s, w)) = peer_handles(&inner, fingerprint) {
                    let _ = send_payload(&s, &w, &Frame::Identity(bytes).encode()).await;
                }
            }
        }
        // The session is now send-ready: flush any pairwise payloads queued
        // before it was keyed (e.g. the host's opening message), in order, after
        // the identity presentation above. Empty (no-op) on later iterations.
        let queued: Vec<Vec<u8>> = pending_for(&inner, fingerprint)
            .map(|p| p.lock().unwrap().drain(..).collect())
            .unwrap_or_default();
        if !queued.is_empty() {
            if let Some((s, w)) = peer_handles(&inner, fingerprint) {
                for payload in queued {
                    let _ = send_payload(&s, &w, &payload).await;
                }
            }
        }
        // In relayed mode the pairwise payload is a Routed envelope; unwrap it
        // and use the relay-stamped original sender. Otherwise the payload is a
        // Frame straight from the pairwise peer.
        let (from, frame_bytes) = if inner.relayed {
            match Routed::decode(&pt) {
                Some(r) => (r.from, r.inner),
                None => continue,
            }
        } else {
            (fingerprint, pt)
        };
        let decoded = Frame::decode(&frame_bytes);
        // Access gate (pairwise): under a restrictive policy, a peer is heard
        // only once it presents an allowed account. Until then, drop everything
        // except its Identity frame (which is what flips `approved`).
        if inner.role == GroupRole::None && !approved && !matches!(decoded, Some(Frame::Identity(_)))
        {
            continue;
        }
        match decoded {
            Some(Frame::Chat {
                channel,
                text,
                marking,
            }) => {
                let _ = inner.events_tx.send(Event::Message {
                    from,
                    channel,
                    text,
                    marking,
                });
            }
            Some(Frame::KeyPackage(b)) if inner.role == GroupRole::Host => {
                handle_keypackage(&inner, from, b).await;
            }
            Some(Frame::Welcome(b)) if inner.role == GroupRole::Member => {
                handle_welcome(&inner, b).await;
            }
            Some(Frame::Commit { from_epoch, bytes }) if inner.role == GroupRole::Member => {
                handle_commit(&inner, from_epoch, bytes).await;
            }
            Some(Frame::Roster(entries)) if inner.role == GroupRole::Member => {
                let mut roster = inner.roster.lock().unwrap();
                *roster = entries.into_iter().collect();
            }
            Some(Frame::GroupMsg(b)) => {
                handle_group_msg(&inner, from, b).await;
            }
            Some(Frame::Identity(bytes)) if inner.role == GroupRole::None => {
                match handle_identity(&inner, fingerprint, bytes) {
                    IdentityOutcome::Allowed => approved = true,
                    IdentityOutcome::Ignored => {}
                    IdentityOutcome::Rejected => {
                        // Not permitted on this restricted channel. Tell the peer
                        // explicitly (we're send-ready: we just got their frame),
                        // then drop them — no silent disconnect.
                        if let Some((s, w)) = peer_handles(&inner, fingerprint) {
                            let denied = Frame::AccessDenied(
                                "not permitted on this channel".to_string(),
                            );
                            let _ = send_payload(&s, &w, &denied.encode()).await;
                        }
                        inner.peers.lock().unwrap().retain(|p| p.fingerprint != fingerprint);
                        let _ = inner.events_tx.send(Event::Disconnected { fingerprint });
                        break;
                    }
                }
            }
            Some(Frame::Identity(bytes))
                if inner.role == GroupRole::Host && !inner.relayed =>
            {
                // Group host: record whether the joiner's account is admitted, so
                // handle_keypackage can gate membership the same as pairwise.
                handle_group_member_identity(&inner, from, bytes);
            }
            Some(Frame::AccessDenied(reason)) if inner.role == GroupRole::None => {
                // The host refused us. Surface it so the UI can say why instead
                // of showing an unexplained disconnect.
                let _ = inner
                    .events_tx
                    .send(Event::Error(format!("not admitted: {reason}")));
            }
            Some(Frame::Revocation(b)) => {
                // A peer propagated a revocation; verify + store it (the account
                // signature makes it unforgeable, so this is safe to accept).
                if let Ok(rev) = Revocation::decode(&b) {
                    if rev.verify().is_ok() {
                        inner
                            .revocations
                            .lock()
                            .unwrap()
                            .insert((rev.account.fingerprint(), rev.subject_fp));
                    }
                }
            }
            _ => { /* frame not valid for this role; ignore */ }
        }
    }
}

/// First 6 bytes of a fingerprint as hex (for human-readable log lines).
fn short_hex6(fp: &[u8; 48]) -> String {
    fp[..6].iter().map(|b| format!("{b:02x}")).collect()
}

/// Current Unix time in seconds (for certificate validity windows). Crypto has
/// no clock; the engine supplies `now` for `IdentityChain` verification.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A peer presented an account identity inside the encrypted session. Decode it,
/// **bind** its leaf to the device we already authenticated (`peer_fp`), verify
/// the chain, check it against pinned friends, and emit [`Event::Identity`].
///
/// A presentation that fails to decode, doesn't bind to this peer, or carries a
/// malformed/expired chain is dropped (surfaced as a non-fatal `Error`) — it can
/// never be mistaken for a verified friend.
fn handle_identity(inner: &Arc<Inner>, peer_fp: [u8; 48], bytes: Vec<u8>) -> IdentityOutcome {
    let presentation = match Presentation::decode(&bytes) {
        Ok(p) => p,
        Err(_) => {
            let _ = inner
                .events_tx
                .send(Event::Error("malformed identity presentation".into()));
            return IdentityOutcome::Ignored;
        }
    };
    let now = now_secs();
    let resolved = {
        let store = inner.contacts.lock().unwrap();
        contacts::resolve_chain(&store, &presentation.chain, peer_fp, now)
    };
    match resolved {
        Some(res) => {
            // Reject a chain that includes a REVOKED link (the account revoked
            // that device/segment). Checked against revocations issued by this
            // chain's own account, so a leaked-but-revoked device is locked out.
            let revoked = {
                let revs = inner.revocations.lock().unwrap();
                presentation
                    .chain
                    .links
                    .iter()
                    .any(|l| revs.contains(&(res.account_fingerprint, l.cert.subject.fingerprint())))
            };
            if revoked {
                let _ = inner
                    .events_tx
                    .send(Event::Error("peer presented a revoked device".into()));
                return IdentityOutcome::Ignored;
            }
            // Enforce the access policy: on a restricted channel, a peer whose
            // account isn't permitted is rejected (caller disconnects it). The
            // decision can depend on contact/friend status (Contacts/Friends
            // modes), so it's made from the resolved identity, not just the fp.
            if !inner
                .access
                .lock()
                .unwrap()
                .admits(&res.account_fingerprint, res.contact, res.friend)
            {
                let _ = inner.events_tx.send(Event::Error(format!(
                    "rejected non-member account {}",
                    short_hex6(&res.account_fingerprint)
                )));
                return IdentityOutcome::Rejected;
            }
            // Remember the verified account key so the UI can pin it by
            // fingerprint after an out-of-band safety-number comparison.
            inner
                .seen_accounts
                .lock()
                .unwrap()
                .insert(res.account_fingerprint, res.account.clone());
            let _ = inner.events_tx.send(Event::Identity {
                from: peer_fp,
                account_fingerprint: res.account_fingerprint,
                username: presentation.username,
                contact: res.contact,
                friend: res.friend,
            });
            IdentityOutcome::Allowed
        }
        None => {
            // The chain didn't bind to this authenticated device, or was
            // invalid/expired — refuse to attribute it to any account.
            let _ = inner
                .events_tx
                .send(Event::Error("identity chain did not bind to peer".into()));
            IdentityOutcome::Ignored
        }
    }
}

/// Group host: a joining member presented its account. Resolve + bind it to the
/// member's device (`from`), check revocation, and — if the access policy admits
/// it — record `from` as admitted so [`handle_keypackage`] honors its join.
/// Emits an [`Event::Identity`] either way (for display).
fn handle_group_member_identity(inner: &Arc<Inner>, from: [u8; 48], bytes: Vec<u8>) {
    let Ok(presentation) = Presentation::decode(&bytes) else {
        return;
    };
    let now = now_secs();
    let resolved = {
        let store = inner.contacts.lock().unwrap();
        contacts::resolve_chain(&store, &presentation.chain, from, now)
    };
    let Some(res) = resolved else { return };
    // Reject a chain with a revoked link.
    let revoked = {
        let revs = inner.revocations.lock().unwrap();
        presentation
            .chain
            .links
            .iter()
            .any(|l| revs.contains(&(res.account_fingerprint, l.cert.subject.fingerprint())))
    };
    if revoked {
        let _ = inner
            .events_tx
            .send(Event::Error("group joiner presented a revoked device".into()));
        return;
    }
    inner
        .seen_accounts
        .lock()
        .unwrap()
        .insert(res.account_fingerprint, res.account.clone());
    if inner
        .access
        .lock()
        .unwrap()
        .admits(&res.account_fingerprint, res.contact, res.friend)
    {
        inner.admitted_peers.lock().unwrap().insert(from);
    }
    let _ = inner.events_tx.send(Event::Identity {
        from,
        account_fingerprint: res.account_fingerprint,
        username: presentation.username,
        contact: res.contact,
        friend: res.friend,
    });
}

/// Host: admit a new member, send them a Welcome, and broadcast the Commit to
/// existing members. (Sequential joins only; concurrent joins need a delivery
/// service to order commits — see docs/plans/0002-mls-pq.md.)
async fn handle_keypackage(inner: &Arc<Inner>, from: [u8; 48], kp_bytes: Vec<u8>) {
    // Access gate: under a restrictive policy, only admit a member whose account
    // we already admitted (recorded when it presented its identity, which the
    // joiner sends in-order before its KeyPackage). Open policy admits anyone.
    let admit = inner.access.lock().unwrap().is_open()
        || inner.admitted_peers.lock().unwrap().contains(&from);
    if !admit {
        let _ = inner.events_tx.send(Event::Error(format!(
            "refused group join from non-member {}",
            short_hex6(&from)
        )));
        return;
    }
    // Hold the group lock across decode + add + leaf assignment so concurrent
    // joins get distinct, ordered epochs. The KeyPackage is decoded with the
    // group's KEM profile (posture + wire padding). The commit is tagged with
    // the epoch it applies to, so members apply commits in order even if
    // delivery reorders them.
    let result = {
        let mut g = inner.group.lock().await;
        match g.as_mut() {
            Some(grp) => match KeyPackage::decode(grp.profile(), &kp_bytes) {
                Ok(kp) => {
                    let from_epoch = grp.epoch();
                    grp.add(&kp)
                        .ok()
                        .map(|(leaf, c, w)| (leaf, from_epoch, c.encode(), w.encode()))
                }
                Err(_) => None,
            },
            None => None,
        }
    };
    let Some((leaf, from_epoch, commit_bytes, welcome_bytes)) = result else {
        return;
    };
    let roster_snapshot = {
        let mut roster = inner.roster.lock().unwrap();
        roster.insert(leaf, from);
        roster.iter().map(|(l, f)| (*l, *f)).collect::<Vec<_>>()
    };

    // Welcome to the joiner; Commit to everyone (the joiner drops it as stale,
    // since it starts at the post-commit epoch); roster to everyone.
    route(inner, Frame::Welcome(welcome_bytes), Route::Peer(from)).await;
    route(
        inner,
        Frame::Commit {
            from_epoch,
            bytes: commit_bytes,
        },
        Route::Broadcast,
    )
    .await;
    route(inner, Frame::Roster(roster_snapshot), Route::Broadcast).await;
}

/// Member: enter the group from a Welcome using our reserved leaf key.
async fn handle_welcome(inner: &Arc<Inner>, welcome_bytes: Vec<u8>) {
    let keypair = inner.leaf_keypair.lock().unwrap().take();
    if let Some(kp) = keypair {
        // Decode the Welcome with the leaf key's KEM profile — both were fixed
        // by the chat's suite, so they agree.
        let welcome = match Welcome::decode(kp.profile(), &welcome_bytes) {
            Ok(w) => w,
            Err(_) => return,
        };
        match TreeKemGroup::join_with_welcome(kp, &welcome) {
            Ok(grp) => *inner.group.lock().await = Some(grp),
            Err(e) => {
                let _ = inner
                    .events_tx
                    .send(Event::Error(format!("welcome failed: {e}")));
            }
        }
    }
}

/// Member: apply a membership commit in epoch order. Commits that arrive ahead
/// of our epoch are buffered until their turn (so concurrent joins are safe).
async fn handle_commit(inner: &Arc<Inner>, from_epoch: u32, commit_bytes: Vec<u8>) {
    {
        let mut pending = inner.pending_commits.lock().unwrap();
        pending.insert(from_epoch, commit_bytes);
    }
    loop {
        let mut g = inner.group.lock().await;
        let Some(grp) = g.as_mut() else { return };
        let cur = grp.epoch();
        let next = {
            let mut pending = inner.pending_commits.lock().unwrap();
            // Drop anything already applied.
            let stale: Vec<u32> = pending.range(..cur).map(|(k, _)| *k).collect();
            for k in stale {
                pending.remove(&k);
            }
            pending.remove(&cur)
        };
        match next {
            Some(bytes) => match Commit::decode(grp.profile(), &bytes) {
                Ok(commit) => {
                    if grp.apply_commit(&commit).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
            None => return, // nothing applicable yet; wait for the missing commit
        }
    }
}

/// Decrypt a group message; the host also relays it to the other members.
async fn handle_group_msg(inner: &Arc<Inner>, from: [u8; 48], gct: Vec<u8>) {
    let opened = {
        let mut g = inner.group.lock().await;
        g.as_mut().and_then(|grp| grp.decrypt(&gct).ok())
    };
    if let Some(pt) = opened {
        if let Some((marking, text)) = marking::decode_payload(&pt) {
            // Attribute to the original sender via the roster (the `from` peer
            // may just be the relaying host), falling back to the relay peer.
            let sender = TreeKemGroup::sender_leaf(&gct)
                .and_then(|leaf| inner.roster.lock().unwrap().get(&leaf).copied())
                .unwrap_or(from);
            let _ = inner.events_tx.send(Event::Message {
                from: sender,
                channel: inner.descriptor.channel.clone(),
                text,
                marking,
            });
        }
    }
    // In host-coordinated mode the host relays to the other members. In relayed
    // mode the non-member relay does the fan-out, so participants never re-relay.
    if !inner.relayed && inner.role == GroupRole::Host {
        for (s, w, fp) in collect_peers(inner) {
            if fp != from {
                let _ = send_payload(&s, &w, &Frame::GroupMsg(gct.clone()).encode()).await;
            }
        }
    }
}

// Keep `fingerprint` field used even if future refactors drop direct reads.
impl Peer {
    #[allow(dead_code)]
    fn id(&self) -> [u8; 48] {
        self.fingerprint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{ChatDescriptor, Persistence, TopologyKind};
    use std::time::Duration;
    use talkrypt_crypto::{SuiteRegistry, DEFAULT_SUITE_ID};
    use talkrypt_transport::LoopbackFabric;
    use tokio::time::timeout;

    async fn next_event(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>) -> Event {
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("event before timeout")
            .expect("channel open")
    }

    /// Wait for the next `Message` event, ignoring Connected/Error noise.
    async fn next_message(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    ) -> (String, [u8; 48]) {
        loop {
            if let Event::Message { text, from, .. } = next_event(rx).await {
                return (text, from);
            }
        }
    }

    fn core_on(
        fabric: &LoopbackFabric,
        endpoint: &str,
        desc: &ChatDescriptor,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        core_on_suite(fabric, endpoint, desc, DEFAULT_SUITE_ID)
    }

    fn core_on_suite(
        fabric: &LoopbackFabric,
        endpoint: &str,
        desc: &ChatDescriptor,
        suite_id: &str,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let suite = SuiteRegistry::with_defaults().get(suite_id).unwrap();
        let transport = Arc::new(fabric.transport(endpoint));
        Core::new(IdentityKeyPair::generate(), suite, transport, desc.clone())
    }

    /// The engine is suite-agnostic: the same end-to-end flow works over the
    /// PQ-Noise suite, not just the default Double Ratchet.
    fn group_core(
        fabric: &LoopbackFabric,
        endpoint: &str,
        desc: &ChatDescriptor,
        is_host: bool,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let suite = SuiteRegistry::with_defaults()
            .get(DEFAULT_SUITE_ID)
            .unwrap();
        Core::new_group(
            IdentityKeyPair::generate(),
            suite,
            Arc::new(fabric.transport(endpoint)),
            desc.clone(),
            is_host,
        )
    }

    /// The host (responder) cannot encrypt before it has received the joiner's
    /// first frame. A message sent in that window must be QUEUED and delivered
    /// once the session is keyed — not silently dropped (the "host's opening
    /// line vanishes" bug). With no account presented, the initiator sends
    /// nothing on connect, so the host stays not-send-ready until the joiner's
    /// first chat — a deterministic queue window.
    #[tokio::test]
    async fn host_message_before_peer_speaks_is_queued_not_dropped() {
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec![],
            "#q",
        );
        let (host, mut host_rx) = core_on(&fabric, "host", &desc);
        host.host().await.unwrap();
        let (joiner, mut joiner_rx) = core_on(&fabric, "joiner", &desc);
        joiner.connect("host").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Host speaks first — responder isn't send-ready, so this is queued.
        host.send("welcome").await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Joiner speaks → host session becomes send-ready → queued "welcome"
        // flushes. Both directions then deliver.
        joiner.send("hi there").await.unwrap();
        assert_eq!(next_message(&mut host_rx).await.0, "hi there");
        assert_eq!(
            next_message(&mut joiner_rx).await.0,
            "welcome",
            "the host's pre-ratchet message must be delivered, not dropped"
        );
    }

    /// Full TreeKEM group chat through the engine over loopback: a host and two
    /// members that join via Welcome, then everyone exchanges group messages
    /// (the host relays). Members join sequentially (the documented model).
    #[tokio::test]
    async fn group_chat_over_engine() {
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["host".into()],
            "#grp",
        );
        let (host, mut host_rx) = group_core(&fabric, "host", &desc, true);
        host.host().await.unwrap();

        let (m1, mut m1_rx) = group_core(&fabric, "m1", &desc, false);
        m1.connect("host").await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;

        let (m2, mut m2_rx) = group_core(&fabric, "m2", &desc, false);
        m2.connect("host").await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Host broadcasts to the group; both members receive it.
        host.send("hello group").await.unwrap();
        assert_eq!(next_message(&mut m1_rx).await.0, "hello group");
        assert_eq!(next_message(&mut m2_rx).await.0, "hello group");

        // A member sends; the host displays it and relays to the other member.
        // Attribution: the message is credited to m1, not the relaying host.
        m1.send("from m1").await.unwrap();
        let (text, from) = next_message(&mut host_rx).await;
        assert_eq!(text, "from m1");
        assert_eq!(from, m1.fingerprint(), "host must attribute to m1");
        let (text2, from2) = next_message(&mut m2_rx).await;
        assert_eq!(text2, "from m1");
        assert_eq!(from2, m1.fingerprint(), "m2 must attribute to m1, not host");
    }

    /// Two members join nearly simultaneously: the host serializes adds and
    /// tags commits with their epoch, so buffered out-of-order delivery still
    /// converges. After a settle, all three message successfully.
    #[tokio::test]
    async fn concurrent_joins_converge() {
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["h".into()],
            "#cj",
        );
        let (host, _h) = group_core(&fabric, "h", &desc, true);
        host.host().await.unwrap();

        let (m1, mut m1_rx) = group_core(&fabric, "cj1", &desc, false);
        let (m2, mut m2_rx) = group_core(&fabric, "cj2", &desc, false);
        // Connect both without waiting between them.
        m1.connect("h").await.unwrap();
        m2.connect("h").await.unwrap();
        tokio::time::sleep(Duration::from_millis(600)).await;

        host.send("converged?").await.unwrap();
        assert_eq!(next_message(&mut m1_rx).await.0, "converged?");
        assert_eq!(next_message(&mut m2_rx).await.0, "converged?");
    }

    /// A removed member cannot read messages sent after its removal.
    #[tokio::test]
    async fn removed_member_is_locked_out() {
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["rh".into()],
            "#rm",
        );
        let (host, _h) = group_core(&fabric, "rh", &desc, true);
        host.host().await.unwrap();
        let (m1, mut m1_rx) = group_core(&fabric, "rm1", &desc, false);
        m1.connect("rh").await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        let (m2, mut m2_rx) = group_core(&fabric, "rm2", &desc, false);
        m2.connect("rh").await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;

        // Host removes m2, then sends a message.
        host.remove_member(m2.fingerprint()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        host.send("after removal").await.unwrap();

        // m1 (still a member) receives it...
        assert_eq!(next_message(&mut m1_rx).await.0, "after removal");
        // ...m2 (removed) must NOT be able to read any group message.
        let got = timeout(Duration::from_millis(500), async {
            loop {
                if let Event::Message { text, .. } = m2_rx.recv().await.unwrap() {
                    break text;
                }
            }
        })
        .await;
        assert!(
            got.is_err(),
            "removed member must not receive group messages"
        );
    }

    #[tokio::test]
    async fn engine_works_over_noise_suite() {
        use talkrypt_crypto::NOISE_SUITE_ID;
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            NOISE_SUITE_ID,
            vec!["bob".into()],
            "#noise",
        );
        let (bob, mut bob_rx) = core_on_suite(&fabric, "bob", &desc, NOISE_SUITE_ID);
        let (alice, _a) = core_on_suite(&fabric, "alice", &desc, NOISE_SUITE_ID);
        bob.host().await.unwrap();
        alice.connect("bob").await.unwrap();
        alice.send("over pq-noise").await.unwrap();
        let (text, from) = next_message(&mut bob_rx).await;
        assert_eq!(text, "over pq-noise");
        assert_eq!(from, alice.fingerprint());
    }

    #[tokio::test]
    async fn two_cores_exchange_messages() {
        let fabric = LoopbackFabric::new();
        // Both sides MUST share the descriptor (same invite token => same root).
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["bob".into()],
            "#general",
        );

        let (bob, mut bob_rx) = core_on(&fabric, "bob", &desc);
        let (alice, mut alice_rx) = core_on(&fabric, "alice", &desc);

        bob.host().await.unwrap();
        let bob_fp_seen_by_alice = alice.connect("bob").await.unwrap();

        // Both observe the other's verified fingerprint.
        assert_eq!(bob_fp_seen_by_alice, bob.fingerprint());

        alice.send("hello over PQ tor").await.unwrap();
        let (text, from) = next_message(&mut bob_rx).await;
        assert_eq!(text, "hello over PQ tor");
        assert_eq!(from, alice.fingerprint());

        // Reply path.
        bob.send("ack").await.unwrap();
        let (reply, from) = next_message(&mut alice_rx).await;
        assert_eq!(reply, "ack");
        assert_eq!(from, bob.fingerprint());

        assert_eq!(alice.peer_count(), 1);
        assert_eq!(bob.peer_count(), 1);
    }

    /// A classification marking rides authenticated inside the message payload:
    /// the receiver gets it on the `Message` event, for both pairwise and group.
    #[tokio::test]
    async fn marking_rides_with_messages_pairwise_and_group() {
        use crate::marking::{Classification, Marking};
        let secret = Marking {
            level: Classification::Secret,
            compartments: vec!["SI".into()],
            caveats: vec!["NOFORN".into()],
        };

        // --- pairwise ---
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["bob".into()],
            "#general",
        );
        let (bob, mut bob_rx) = core_on(&fabric, "bob", &desc);
        let (alice, _a_rx) = core_on(&fabric, "alice", &desc);
        bob.host().await.unwrap();
        alice.connect("bob").await.unwrap();

        alice.send_marked("classified", Some(secret.clone())).await.unwrap();
        loop {
            if let Event::Message { text, marking, .. } = next_event(&mut bob_rx).await {
                assert_eq!(text, "classified");
                assert_eq!(marking.unwrap().banner(), "SECRET//SI//NOFORN");
                break;
            }
        }
        // An unmarked send carries no marking.
        alice.send("plain").await.unwrap();
        loop {
            if let Event::Message { text, marking, .. } = next_event(&mut bob_rx).await {
                assert_eq!(text, "plain");
                assert!(marking.is_none());
                break;
            }
        }

        // --- group (marking inside the group-epoch ciphertext) ---
        let gfab = LoopbackFabric::new();
        let gdesc = ChatDescriptor::new(
            TopologyKind::Hub,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["host".into()],
            "#g",
        );
        let (host, _h_rx) = group_core(&gfab, "host", &gdesc, true);
        let (m1, mut m1_rx) = group_core(&gfab, "m1", &gdesc, false);
        host.host().await.unwrap();
        m1.connect("host").await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        host.send_marked("group secret", Some(secret.clone())).await.unwrap();
        loop {
            if let Event::Message { text, marking, .. } = next_event(&mut m1_rx).await {
                if text == "group secret" {
                    assert_eq!(marking.unwrap().banner(), "SECRET//SI//NOFORN");
                    break;
                }
            }
        }
    }

    /// End-to-end friending over the engine: Alice links her device to an
    /// account and presents the chain inside the encrypted session; Bob pins
    /// that account and resolves Alice's device to a verified **friend**. An
    /// impostor presenting a chain under a *different* account, even claiming
    /// the same username, resolves as a non-friend — unforgeable without the
    /// account key.
    #[tokio::test]
    async fn friending_resolves_account_over_engine() {
        use talkrypt_crypto::IdentityChain;

        async fn next_identity(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
        ) -> (Option<String>, bool, [u8; 48]) {
            loop {
                if let Event::Identity {
                    username,
                    friend,
                    account_fingerprint,
                    ..
                } = next_event(rx).await
                {
                    return (username, friend, account_fingerprint);
                }
            }
        }

        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["bob".into()],
            "#friends",
        );

        // Bob hosts; Alice's account certifies her (engine) device key.
        let (bob, mut bob_rx) = core_on(&fabric, "bob", &desc);
        let (alice, _a_rx) = core_on(&fabric, "alice", &desc);

        let alice_account = IdentityKeyPair::generate();
        let chain = IdentityChain::device(
            &alice_account,
            alice.identity_public(),
            "device:phone",
            0,
            0,
        );
        alice.present_identity(chain, Some("alice".into()));
        bob.add_contact(alice_account.public().clone(), Some("alice".into()), true);

        bob.host().await.unwrap();
        alice.connect("bob").await.unwrap();

        let (username, friend, acct_fp) = next_identity(&mut bob_rx).await;
        assert!(friend, "Alice's pinned account must resolve as a friend");
        assert_eq!(username.as_deref(), Some("alice"));
        assert_eq!(acct_fp, alice_account.public().fingerprint());

        // --- impostor: same username, different (unpinned) account ---
        let ifab = LoopbackFabric::new();
        let idesc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["bob2".into()],
            "#friends",
        );
        let (bob2, mut bob2_rx) = core_on(&ifab, "bob2", &idesc);
        let (mallory, _m_rx) = core_on(&ifab, "mallory", &idesc);
        // Bob2 still only trusts Alice's real account.
        bob2.add_contact(alice_account.public().clone(), Some("alice".into()), true);
        // Mallory mints a chain under HIS OWN account but claims "alice".
        let mallory_account = IdentityKeyPair::generate();
        let fake_chain = IdentityChain::device(
            &mallory_account,
            mallory.identity_public(),
            "device:phone",
            0,
            0,
        );
        mallory.present_identity(fake_chain, Some("alice".into()));

        bob2.host().await.unwrap();
        mallory.connect("bob2").await.unwrap();

        let (uname2, friend2, acct_fp2) = next_identity(&mut bob2_rx).await;
        assert!(!friend2, "impostor must NOT resolve as the pinned friend");
        assert_eq!(uname2.as_deref(), Some("alice")); // claimed name is advisory
        assert_ne!(
            acct_fp2,
            alice_account.public().fingerprint(),
            "impostor's account fingerprint differs from the real Alice"
        );
    }

    /// Both sides present an account: the initiator presents eagerly, the
    /// responder presents *reactively* once its ratchet is send-ready. Each must
    /// resolve the other as a pinned friend — this is the direction the eager-
    /// only presentation silently dropped.
    #[tokio::test]
    async fn friending_is_bidirectional_initiator_and_responder() {
        use talkrypt_crypto::IdentityChain;

        async fn next_identity(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
        ) -> (bool, [u8; 48]) {
            loop {
                if let Event::Identity {
                    friend,
                    account_fingerprint,
                    ..
                } = next_event(rx).await
                {
                    return (friend, account_fingerprint);
                }
            }
        }

        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["bob".into()],
            "#bidi",
        );
        let (bob, mut bob_rx) = core_on(&fabric, "bob", &desc); // responder (hosts)
        let (alice, mut alice_rx) = core_on(&fabric, "alice", &desc); // initiator (dials)

        let bob_account = IdentityKeyPair::generate();
        let alice_account = IdentityKeyPair::generate();
        bob.present_identity(
            IdentityChain::device(&bob_account, bob.identity_public(), "device:bob", 0, 0),
            Some("bob".into()),
        );
        alice.present_identity(
            IdentityChain::device(&alice_account, alice.identity_public(), "device:alice", 0, 0),
            Some("alice".into()),
        );
        // Each pins the other's account.
        bob.add_contact(alice_account.public().clone(), Some("alice".into()), true);
        alice.add_contact(bob_account.public().clone(), Some("bob".into()), true);

        bob.host().await.unwrap();
        alice.connect("bob").await.unwrap();

        // Responder (bob) receives the initiator's eager presentation.
        let (bob_sees_friend, acct_a) = next_identity(&mut bob_rx).await;
        assert!(bob_sees_friend, "bob must resolve alice as a friend");
        assert_eq!(acct_a, alice_account.public().fingerprint());

        // Initiator (alice) receives the responder's REACTIVE presentation — the
        // path the bug dropped.
        let (alice_sees_friend, acct_b) = next_identity(&mut alice_rx).await;
        assert!(alice_sees_friend, "alice must resolve bob as a friend (reactive)");
        assert_eq!(acct_b, bob_account.public().fingerprint());
    }

    /// Registry-restricted channel: the host allows only a specific account.
    /// A peer presenting an allowed account is heard; a peer presenting a
    /// different account is rejected and its messages never surface.
    #[tokio::test]
    async fn access_policy_restricts_to_allowed_accounts() {
        use std::collections::HashSet;
        use talkrypt_crypto::IdentityChain;

        async fn try_get_message(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
            dur: Duration,
        ) -> Option<String> {
            timeout(dur, async {
                loop {
                    match rx.recv().await {
                        Some(Event::Message { text, .. }) => break text,
                        Some(_) => continue,
                        None => break String::new(),
                    }
                }
            })
            .await
            .ok()
        }

        let allowed_account = IdentityKeyPair::generate();
        let other_account = IdentityKeyPair::generate();

        // --- allowed member is heard ---
        {
            let fabric = LoopbackFabric::new();
            let desc = ChatDescriptor::new(
                TopologyKind::P2P,
                Persistence::Ephemeral,
                DEFAULT_SUITE_ID,
                vec!["host".into()],
                "#restricted",
            );
            let (host, mut host_rx) = core_on(&fabric, "host", &desc);
            host.restrict_to_accounts(HashSet::from([allowed_account.public().fingerprint()]));
            let (member, _m) = core_on(&fabric, "member", &desc);
            member.present_identity(
                IdentityChain::device(&allowed_account, member.identity_public(), "d", 0, 0),
                Some("ok".into()),
            );
            host.host().await.unwrap();
            member.connect("host").await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            member.send("i belong here").await.unwrap();
            assert_eq!(
                try_get_message(&mut host_rx, Duration::from_secs(2)).await.as_deref(),
                Some("i belong here"),
                "allowed account must be heard"
            );
        }

        // --- non-member is rejected (message dropped) ---
        {
            let fabric = LoopbackFabric::new();
            let desc = ChatDescriptor::new(
                TopologyKind::P2P,
                Persistence::Ephemeral,
                DEFAULT_SUITE_ID,
                vec!["host2".into()],
                "#restricted",
            );
            let (host, mut host_rx) = core_on(&fabric, "host2", &desc);
            host.restrict_to_accounts(HashSet::from([allowed_account.public().fingerprint()]));
            let (intruder, _i) = core_on(&fabric, "intruder", &desc);
            intruder.present_identity(
                IdentityChain::device(&other_account, intruder.identity_public(), "d", 0, 0),
                Some("nope".into()),
            );
            host.host().await.unwrap();
            intruder.connect("host2").await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            intruder.send("let me in").await.unwrap();
            // The host must NOT surface the intruder's message.
            assert!(
                try_get_message(&mut host_rx, Duration::from_millis(600)).await.is_none(),
                "non-member account must be silenced"
            );
        }
    }

    /// Group membership is gated by the access policy: under `restrict_to_accounts`,
    /// a member presenting an allowed account joins and exchanges group messages;
    /// a member with a non-allowed account is refused membership (no group msg).
    #[tokio::test]
    async fn group_access_control_gates_membership() {
        use std::collections::HashSet;
        use talkrypt_crypto::IdentityChain;

        async fn member_receives_group_msg(allowed: bool) -> bool {
            let fabric = LoopbackFabric::new();
            let desc = ChatDescriptor::new(
                TopologyKind::Hub,
                Persistence::Ephemeral,
                DEFAULT_SUITE_ID,
                vec!["gh".into()],
                "#grp-acl",
            );
            let member_account = IdentityKeyPair::generate();
            let (host, _h) = group_core(&fabric, "gh", &desc, true);
            host.restrict_to_accounts(HashSet::from([member_account.public().fingerprint()]));
            if !allowed {
                // Host restricts to a DIFFERENT account than the member presents.
                host.restrict_to_accounts(HashSet::from([
                    IdentityKeyPair::generate().public().fingerprint()
                ]));
            }
            host.host().await.unwrap();

            let (member, mut m_rx) = group_core(&fabric, "gm", &desc, false);
            member.present_identity(
                IdentityChain::device(&member_account, member.identity_public(), "d", 0, 0),
                Some("m".into()),
            );
            member.connect("gh").await.unwrap();
            tokio::time::sleep(Duration::from_millis(400)).await;

            host.send("group hello").await.unwrap();
            // An admitted member gets the group message; a refused one never
            // joined the group, so it can't decrypt any group traffic.
            timeout(Duration::from_millis(800), async {
                loop {
                    if let Event::Message { text, .. } = next_event(&mut m_rx).await {
                        if text == "group hello" {
                            break true;
                        }
                    }
                }
            })
            .await
            .unwrap_or(false)
        }

        assert!(member_receives_group_msg(true).await, "allowed member must join");
        assert!(
            !member_receives_group_msg(false).await,
            "non-member account must be refused group membership"
        );
    }

    /// A revoked device is refused recognition even with an otherwise-valid
    /// chain: the host surfaces a "revoked device" error and does not recognize
    /// the account.
    #[tokio::test]
    async fn revoked_device_is_refused() {
        use talkrypt_crypto::{IdentityChain, Revocation};
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["h".into()],
            "#rev",
        );
        let account = IdentityKeyPair::generate();
        let (host, mut host_rx) = core_on(&fabric, "h", &desc);
        let (peer, _p) = core_on(&fabric, "p", &desc);
        // The host recognizes the account, but has revoked the peer's device.
        host.add_contact(account.public().clone(), Some("alice".into()), true);
        let dev_fp = peer.identity_public().fingerprint();
        assert!(host.add_revocation(Revocation::issue(&account, dev_fp, 1)));
        peer.present_identity(
            IdentityChain::device(&account, peer.identity_public(), "d", 0, 0),
            Some("alice".into()),
        );
        host.host().await.unwrap();
        peer.connect("h").await.unwrap();

        // Host gets a "revoked" error and never an Identity event for this peer.
        let saw_revoked = timeout(Duration::from_secs(2), async {
            loop {
                match next_event(&mut host_rx).await {
                    Event::Error(m) if m.contains("revoked") => break true,
                    Event::Identity { friend: true, .. } => break false,
                    _ => continue,
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(saw_revoked, "a revoked device must be refused, not recognized");
    }

    /// A rejected joiner gets explicit feedback (an `Error` "not admitted: …"),
    /// not just a silent disconnect.
    #[tokio::test]
    async fn rejected_joiner_gets_feedback() {
        use talkrypt_crypto::IdentityChain;
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec!["h".into()],
            "#fb",
        );
        let allowed = IdentityKeyPair::generate();
        let (host, _h) = core_on(&fabric, "h", &desc);
        host.restrict_to_accounts(std::collections::HashSet::from([allowed.public().fingerprint()]));
        let (peer, mut peer_rx) = core_on(&fabric, "p", &desc);
        let intruder = IdentityKeyPair::generate(); // not allowed
        peer.present_identity(
            IdentityChain::device(&intruder, peer.identity_public(), "d", 0, 0),
            Some("x".into()),
        );
        host.host().await.unwrap();
        peer.connect("h").await.unwrap();

        // The joiner receives an explicit "not admitted" error.
        let got = timeout(Duration::from_secs(2), async {
            loop {
                if let Event::Error(msg) = next_event(&mut peer_rx).await {
                    if msg.contains("not admitted") {
                        break true;
                    }
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(got, "rejected joiner must be told it was not admitted");
    }

    /// `restrict_to_contacts`: a recognized contact is admitted; a stranger
    /// (valid account, but not a contact) is silenced.
    #[tokio::test]
    async fn access_policy_contacts_mode() {
        use talkrypt_crypto::IdentityChain;

        async fn got_message(
            rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
            dur: Duration,
        ) -> bool {
            timeout(dur, async {
                loop {
                    match rx.recv().await {
                        Some(Event::Message { .. }) => break true,
                        Some(_) => continue,
                        None => break false,
                    }
                }
            })
            .await
            .unwrap_or(false)
        }

        async fn run(make_contact: bool) -> bool {
            let fabric = LoopbackFabric::new();
            let desc = ChatDescriptor::new(
                TopologyKind::P2P,
                Persistence::Ephemeral,
                DEFAULT_SUITE_ID,
                vec!["h".into()],
                "#contacts",
            );
            let (host, mut host_rx) = core_on(&fabric, "h", &desc);
            host.restrict_to_contacts();
            let peer_account = IdentityKeyPair::generate();
            if make_contact {
                host.add_contact(peer_account.public().clone(), Some("pal".into()), false);
            }
            let (peer, _p) = core_on(&fabric, "p", &desc);
            peer.present_identity(
                IdentityChain::device(&peer_account, peer.identity_public(), "d", 0, 0),
                Some("pal".into()),
            );
            host.host().await.unwrap();
            peer.connect("h").await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            peer.send("hi").await.unwrap();
            got_message(&mut host_rx, Duration::from_millis(700)).await
        }

        assert!(run(true).await, "a recognized contact must be admitted");
        assert!(!run(false).await, "a non-contact must be silenced");
    }

    #[tokio::test]
    async fn wrong_invite_token_fails_handshake_or_decrypt() {
        let fabric = LoopbackFabric::new();
        let desc_bob = ChatDescriptor::new(
            TopologyKind::P2P,
            Persistence::Ephemeral,
            DEFAULT_SUITE_ID,
            vec![],
            "#c",
        );
        // Alice uses a DIFFERENT descriptor (different invite token => root).
        let mut desc_alice = desc_bob.clone();
        desc_alice.invite_token = vec![0xAAu8; 32];

        let (bob, _bob_rx) = core_on(&fabric, "bob2", &desc_bob);
        let (alice, _a_rx) = core_on(&fabric, "alice2", &desc_alice);
        bob.host().await.unwrap();
        // Handshake itself completes (auth is by signature), but the diverging
        // roots mean Bob can never decrypt Alice's traffic.
        alice.connect("bob2").await.unwrap();
        alice.send("secret").await.unwrap();

        let (mut bob_rx, _) = (_bob_rx, ());
        // Bob should NOT surface a Message; he gets a decrypt Error instead.
        let mut saw_message = false;
        for _ in 0..3 {
            if let Ok(Some(Event::Message { .. })) =
                timeout(Duration::from_millis(300), bob_rx.recv()).await
            {
                saw_message = true;
            }
        }
        assert!(
            !saw_message,
            "diverging roots must not yield a plaintext message"
        );
    }
}
