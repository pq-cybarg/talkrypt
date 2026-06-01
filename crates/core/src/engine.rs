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
    Commit, CryptoSuite, IdentityKeyPair, IdentityPublic, KeyPackage, LeafKeyPair, TreeKemGroup,
    Welcome,
};
use talkrypt_transport::{Endpoint, FrameReader, FrameWriter, Stream, Transport};
use talkrypt_wire::{Reader, Writer};

use crate::descriptor::ChatDescriptor;
use crate::error::Result;
use crate::handshake::{self, HandshakeResult};

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
}

impl Frame {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Frame::Chat { channel, text } => {
                w.put_u8(0);
                w.put_bytes(channel.as_bytes());
                w.put_bytes(text.as_bytes());
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
        }
        w.into_vec()
    }

    fn decode(bytes: &[u8]) -> Option<Frame> {
        let mut r = Reader::new(bytes);
        let frame = match r.get_u8().ok()? {
            0 => Frame::Chat {
                channel: String::from_utf8(r.get_vec().ok()?).ok()?,
                text: String::from_utf8(r.get_vec().ok()?).ok()?,
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
            _ => return None,
        };
        Some(frame)
    }
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

type SharedSession = Arc<AsyncMutex<Box<dyn SessionHandle>>>;
type SharedWriter = Arc<AsyncMutex<Box<dyn FrameWriter>>>;

struct Peer {
    fingerprint: [u8; 48],
    writer: SharedWriter,
    session: SharedSession,
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
        Self::build(identity, suite, transport, descriptor, GroupRole::None)
    }

    /// Build a TreeKEM group chat. The `Host` founds the group and coordinates
    /// membership; a `Member` joins via the Welcome it receives after dialing
    /// the host. Plain pairwise chats use [`Core::new`].
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
        Self::build(identity, suite, transport, descriptor, role)
    }

    fn build(
        identity: IdentityKeyPair,
        suite: Arc<dyn CryptoSuite>,
        transport: Arc<dyn Transport>,
        descriptor: ChatDescriptor,
        role: GroupRole,
    ) -> (Core, tokio::sync::mpsc::UnboundedReceiver<Event>) {
        let root0 = descriptor.derive_root();
        let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
        let group = match role {
            GroupRole::Host => Some(TreeKemGroup::create()),
            _ => None,
        };
        let leaf_keypair = match role {
            GroupRole::Member => Some(LeafKeyPair::generate()),
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
        for (s, w, fp) in collect_peers(&self.inner) {
            if fp != fingerprint {
                let _ = send_frame_to(
                    &s,
                    &w,
                    &Frame::Commit {
                        from_epoch,
                        bytes: commit_bytes.clone(),
                    },
                )
                .await;
                let _ = send_frame_to(&s, &w, &Frame::Roster(roster_snapshot.clone())).await;
            }
        }
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
                    Ok(hs) => register(&inner, stream, hs),
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
        register(&self.inner, stream, hs);

        // A joining group member sends its KeyPackage to the host it dialed.
        if self.inner.role == GroupRole::Member {
            let kp_bytes = self
                .inner
                .leaf_keypair
                .lock()
                .unwrap()
                .as_ref()
                .map(|k| k.key_package().encode());
            if let (Some(kpb), Some((s, w))) = (kp_bytes, peer_handles(&self.inner, fp)) {
                let _ = send_frame_to(&s, &w, &Frame::KeyPackage(kpb)).await;
            }
        }
        Ok(fp)
    }

    /// Send `text`. In a plain chat this is a direct pairwise message to every
    /// peer; in a group chat it is encrypted once under the group epoch and
    /// fanned out (the host relays to all members).
    pub async fn send(&self, text: &str) -> Result<()> {
        let frame = match self.inner.role {
            GroupRole::None => Frame::Chat {
                channel: self.inner.descriptor.channel.clone(),
                text: text.to_string(),
            },
            GroupRole::Host | GroupRole::Member => {
                let mut g = self.inner.group.lock().await;
                match g.as_mut() {
                    Some(grp) => Frame::GroupMsg(grp.encrypt(text.as_bytes())?),
                    None => return Err(crate::error::CoreError::GroupNotReady),
                }
            }
        };
        for (session, writer, _) in collect_peers(&self.inner) {
            let _ = send_frame_to(&session, &writer, &frame).await;
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

/// Encrypt a frame under a peer's pairwise session and send it.
async fn send_frame_to(
    session: &SharedSession,
    writer: &SharedWriter,
    frame: &Frame,
) -> Result<()> {
    let bytes = frame.encode();
    let ct = {
        let mut s = session.lock().await;
        s.encrypt(&bytes)?
    };
    let mut w = writer.lock().await;
    w.send_frame(&ct).await?;
    Ok(())
}

/// Register a freshly-handshaked peer: store it and spawn its reader task.
fn register(inner: &Arc<Inner>, stream: Box<dyn Stream>, hs: HandshakeResult) {
    let (writer, reader) = stream.into_split();
    let fingerprint = hs.peer_identity.fingerprint();
    let session = Arc::new(AsyncMutex::new(hs.session));
    let writer = Arc::new(AsyncMutex::new(writer));

    inner.peers.lock().unwrap().push(Peer {
        fingerprint,
        writer: writer.clone(),
        session: session.clone(),
    });
    let _ = inner.events_tx.send(Event::Connected { fingerprint });

    tokio::spawn(reader_loop(inner.clone(), reader, session, fingerprint));
}

async fn reader_loop(
    inner: Arc<Inner>,
    mut reader: Box<dyn FrameReader>,
    session: Arc<AsyncMutex<Box<dyn SessionHandle>>>,
    fingerprint: [u8; 48],
) {
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
        match Frame::decode(&pt) {
            Some(Frame::Chat { channel, text }) => {
                let _ = inner.events_tx.send(Event::Message {
                    from: fingerprint,
                    channel,
                    text,
                });
            }
            Some(Frame::KeyPackage(b)) if inner.role == GroupRole::Host => {
                handle_keypackage(&inner, fingerprint, b).await;
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
                handle_group_msg(&inner, fingerprint, b).await;
            }
            _ => { /* frame not valid for this role; ignore */ }
        }
    }
}

/// Host: admit a new member, send them a Welcome, and broadcast the Commit to
/// existing members. (Sequential joins only; concurrent joins need a delivery
/// service to order commits — see docs/plans/0002-mls-pq.md.)
async fn handle_keypackage(inner: &Arc<Inner>, from: [u8; 48], kp_bytes: Vec<u8>) {
    let kp = match KeyPackage::decode(&kp_bytes) {
        Ok(kp) => kp,
        Err(_) => return,
    };
    // Hold the group lock across add + leaf assignment so concurrent joins get
    // distinct, ordered epochs. The commit is tagged with the epoch it applies
    // to, so members apply commits in order even if delivery reorders them.
    let result = {
        let mut g = inner.group.lock().await;
        match g.as_mut() {
            Some(grp) => {
                let from_epoch = grp.epoch();
                grp.add(&kp)
                    .ok()
                    .map(|(leaf, c, w)| (leaf, from_epoch, c.encode(), w.encode()))
            }
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

    if let Some((s, w)) = peer_handles(inner, from) {
        let _ = send_frame_to(&s, &w, &Frame::Welcome(welcome_bytes)).await;
    }
    for (s, w, fp) in collect_peers(inner) {
        if fp != from {
            let _ = send_frame_to(
                &s,
                &w,
                &Frame::Commit {
                    from_epoch,
                    bytes: commit_bytes.clone(),
                },
            )
            .await;
        }
    }
    // Everyone (incl. the new member) gets the updated roster.
    for (s, w, _) in collect_peers(inner) {
        let _ = send_frame_to(&s, &w, &Frame::Roster(roster_snapshot.clone())).await;
    }
}

/// Member: enter the group from a Welcome using our reserved leaf key.
async fn handle_welcome(inner: &Arc<Inner>, welcome_bytes: Vec<u8>) {
    let welcome = match Welcome::decode(&welcome_bytes) {
        Ok(w) => w,
        Err(_) => return,
    };
    let keypair = inner.leaf_keypair.lock().unwrap().take();
    if let Some(kp) = keypair {
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
            Some(bytes) => match Commit::decode(&bytes) {
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
        if let Ok(text) = String::from_utf8(pt) {
            // Attribute to the original sender via the roster (the `from` peer
            // may just be the relaying host), falling back to the relay peer.
            let sender = TreeKemGroup::sender_leaf(&gct)
                .and_then(|leaf| inner.roster.lock().unwrap().get(&leaf).copied())
                .unwrap_or(from);
            let _ = inner.events_tx.send(Event::Message {
                from: sender,
                channel: inner.descriptor.channel.clone(),
                text,
            });
        }
    }
    if inner.role == GroupRole::Host {
        for (s, w, fp) in collect_peers(inner) {
            if fp != from {
                let _ = send_frame_to(&s, &w, &Frame::GroupMsg(gct.clone())).await;
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
            match timeout(Duration::from_millis(300), bob_rx.recv()).await {
                Ok(Some(Event::Message { .. })) => saw_message = true,
                _ => {}
            }
        }
        assert!(
            !saw_message,
            "diverging roots must not yield a plaintext message"
        );
    }
}
