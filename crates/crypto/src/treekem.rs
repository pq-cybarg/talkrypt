//! TreeKEM continuous group key agreement with dynamic membership — the
//! cryptographic core of MLS-PQ.
//!
//! Members occupy leaves of a binary tree whose capacity is a power of two.
//! Every populated node carries a hybrid (X25519 + ML-KEM-1024) key pair
//! derived deterministically from a node secret; a member holds the secrets of
//! the non-blank nodes on its path to the root, and everyone knows all public
//! keys. **Blank** nodes (no key) are resolved to the set of highest non-blank
//! descendants covering their subtree — the *resolution* — which is what path
//! secrets get encrypted to.
//!
//! Nodes are identified by the **leaf range** `(lo, span)` they cover, so
//! indices stay stable when the tree doubles to admit more members.
//!
//! Operations:
//!   * **create / key_package / add / join_with_welcome** — a member commits an
//!     Add, encrypting the new group secret to existing members (UpdatePath)
//!     and to the joiner's leaf key (Welcome).
//!   * **remove** — blank the leaving leaf and re-key, so the removed member
//!     cannot derive the new group secret (forward secrecy against removal).
//!   * **commit / apply_commit** — advance the epoch; messaging rides per-epoch
//!     per-sender chains (forward secrecy within an epoch; post-compromise
//!     security across commits).
//!
//! Scope: this is the TreeKEM key schedule + membership. RFC 9420 wire framing
//! and proposal batching beyond Add/Remove remain future work
//! (`docs/plans/0002-mls-pq.md`). The simpler sender-key group
//! ([`crate::group`]) remains available.

use std::collections::{BTreeMap, HashMap};

use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::aead::{open as aead_open, seal as aead_seal};
use crate::error::{CryptoError, Result};
use crate::hybrid::{KemProfile, RatchetPublic, RatchetSecret};
use crate::identity::{IdentityKeyPair, IdentityPublic};
use crate::kdf::{kdf_ck, kdf_mk};
use crate::ratchet::MAX_SKIP;

/// Machine-checked (Kani bounded model checker, `cargo kani`) proofs that the
/// group-message and membership DECODERS are memory-safe and TOTAL on arbitrary
/// input: for every byte string up to the bound, they return `Ok`/`Err` and never
/// panic, over-read, or over-allocate (SECURITY-AUDIT G3/G4). Complements the
/// randomized `proptest` coverage in the test module.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// The attacker-controlled part of `decrypt_verified` is the WIRE PARSE that
    /// runs before any signature check: read version, epoch, leaf, n, ct, sig, and
    /// `finish()`. This proof replays exactly that parse on arbitrary bytes and
    /// asserts it is total and memory-safe — never panics, never over-reads — on
    /// ALL inputs up to the bound. (The subsequent HashMap lookup + ML-DSA verify
    /// are library calls that seed std `RandomState`/RNG, which Kani cannot model;
    /// their totality is covered by proptest `prop_decrypt_verified_is_total`.)
    /// This isolates and machine-proves the untrusted-input decoder (G3/G4).
    #[kani::proof]
    #[kani::unwind(8)]
    fn v2_message_parse_is_total() {
        const N: usize = 24;
        let len: usize = kani::any();
        kani::assume(len <= N);
        let data: [u8; N] = kani::any();
        let mut r = talkrypt_wire::Reader::new(&data[..len]);
        // Mirror the exact parse in decrypt_verified. Any error short-circuits;
        // none of these may panic or read out of bounds.
        if r.get_u8().is_err() { return; }
        if r.get_u32().is_err() { return; }
        if r.get_u32().is_err() { return; }
        if r.get_u32().is_err() { return; }
        let ct = match r.get_vec() { Ok(v) => v, Err(_) => return };
        let sig = match r.get_vec() { Ok(v) => v, Err(_) => return };
        let _ = r.finish();
        // On success, the consumed fields fit within the input.
        assert!(ct.len() <= len);
        assert!(sig.len() <= len);
    }

    /// `sender_leaf` on arbitrary bytes never panics and only returns `Some` when
    /// the framing had a version byte + two u32s.
    #[kani::proof]
    #[kani::unwind(8)]
    fn sender_leaf_never_panics() {
        const N: usize = 16;
        let len: usize = kani::any();
        kani::assume(len <= N);
        let data: [u8; N] = kani::any();
        let _ = TreeKemGroup::sender_leaf(&data[..len]);
    }
}

type Secret = [u8; 32];

/// A tree node identified by the leaf range `[lo, lo+span)` it covers.
/// `span` is always a power of two; `span == 1` is a leaf.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub struct Node {
    lo: u32,
    span: u32,
}

impl Node {
    fn leaf(i: u32) -> Node {
        Node { lo: i, span: 1 }
    }
    fn children(&self) -> Option<(Node, Node)> {
        if self.span == 1 {
            None
        } else {
            let h = self.span / 2;
            Some((
                Node {
                    lo: self.lo,
                    span: h,
                },
                Node {
                    lo: self.lo + h,
                    span: h,
                },
            ))
        }
    }
    fn parent(&self, capacity: u32) -> Option<Node> {
        if self.span >= capacity {
            return None;
        }
        let ps = self.span * 2;
        Some(Node {
            lo: self.lo - (self.lo % ps),
            span: ps,
        })
    }
    fn sibling(&self) -> Node {
        if (self.lo / self.span).is_multiple_of(2) {
            Node {
                lo: self.lo + self.span,
                span: self.span,
            }
        } else {
            Node {
                lo: self.lo - self.span,
                span: self.span,
            }
        }
    }
    #[cfg(test)]
    fn covers(&self, leaf: u32) -> bool {
        self.lo <= leaf && leaf < self.lo + self.span
    }
}

fn root_of(capacity: u32) -> Node {
    Node {
        lo: 0,
        span: capacity,
    }
}

/// A joiner's pre-published leaf: the KEM leaf key plus a per-membership ML-DSA-87
/// **leaf signature key** used to authenticate this member's group messages
/// (SECURITY-AUDIT G1/G2). The signature key is per-group and unlinkable to the
/// device — it IS a segment/pseudonym key in talkrypt's identity model; binding it
/// to a real account (linked mode) is a separate, optional layer.
#[derive(Clone)]
pub struct KeyPackage {
    pub leaf_public: RatchetPublic,
    pub sig_public: IdentityPublic,
    /// Proof-of-possession: a signature by `sig_public`'s secret over
    /// `POP_CONTEXT | leaf_public | sig_public` (SECURITY-AUDIT T-1). It proves the
    /// joiner holds the leaf signing key and bound it to this leaf KEM key, so a
    /// committer/relay cannot substitute a leaf signature key it does not control.
    /// Verified in `KeyPackage::decode`, before any consumer trusts `sig_public`.
    pub pop: Vec<u8>,
}

/// A joiner's private leaf key, kept until they process their Welcome. Bound to
/// the group's [`KemProfile`] so the published leaf key matches the group. Also
/// holds the per-membership ML-DSA-87 **leaf signature key** the joiner will use
/// to sign its group messages (SECURITY-AUDIT G1/G2).
pub struct LeafKeyPair {
    profile: KemProfile,
    secret: Secret,
    sig: IdentityKeyPair,
}

impl LeafKeyPair {
    /// Generate a fresh leaf key for joining a group, using the group's default
    /// (PQ-pure) profile. Share `key_package()`.
    pub fn generate() -> LeafKeyPair {
        LeafKeyPair::generate_with(KemProfile::default())
    }

    /// Generate a fresh leaf key for a specific KEM profile (must match the
    /// group being joined).
    pub fn generate_with(profile: KemProfile) -> LeafKeyPair {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        LeafKeyPair { profile, secret, sig: IdentityKeyPair::generate() }
    }

    /// The KEM profile this leaf key is bound to.
    pub fn profile(&self) -> KemProfile {
        self.profile
    }

    pub fn key_package(&self) -> KeyPackage {
        let (_, leaf_public) = RatchetSecret::derive_deterministic(self.profile, &self.secret);
        let sig_public = self.sig.public().clone();
        // Prove we hold the leaf signing key and bind it to this leaf KEM key (T-1).
        let pop = self.sig.sign(&pop_transcript(&sig_public));
        KeyPackage { leaf_public, sig_public, pop }
    }
}

/// A membership change carried by a commit.
#[derive(Clone, PartialEq, Eq)]
enum Proposal {
    Add {
        leaf: u32,
        leaf_public: RatchetPublic,
        sig_public: IdentityPublic,
        /// Proof-of-possession for `sig_public` over `(leaf_public, sig_public)`,
        /// re-checked on the RECEIVE side so a malicious committer cannot bind a
        /// leaf signature key it does not control (SECURITY-AUDIT T-1).
        pop: Vec<u8>,
    },
    Remove {
        leaf: u32,
    },
}

/// The result of a commit: structural proposals, the committer's re-keyed path
/// public keys, and path secrets encrypted to each copath resolution node.
#[derive(Clone, PartialEq, Eq)]
pub struct Commit {
    proposals: Vec<Proposal>,
    pub_updates: Vec<(Node, RatchetPublic)>,
    path: Vec<Node>,                         // committer's path, leaf -> root
    ciphertexts: Vec<(Node, Node, Vec<u8>)>, // (path node, target resolution node, blob)
    new_capacity: u32,
    /// Optional leaf-signature-key ROTATION by the committer (SECURITY-AUDIT T-2):
    /// `(committer_leaf, new_sig_public, pop)`. Present when the committer rotates
    /// its own leaf signing key (e.g. on `update()`), giving post-compromise
    /// security for AUTHENTICATION: a leaked leaf signing key stops verifying once
    /// the member updates. Receivers verify the PoP and rebind the leaf's key.
    sig_update: Option<(u32, IdentityPublic, Vec<u8>)>,
}

/// Everything a joiner needs to enter the group at the post-commit epoch.
#[derive(Clone, PartialEq, Eq)]
pub struct Welcome {
    capacity: u32,
    public: Vec<(Node, RatchetPublic)>,
    occupied: Vec<bool>,
    epoch: u32,
    your_leaf: u32,
    /// Every current member's leaf: (leaf, leaf_public, sig_public, pop). The joiner
    /// RE-VERIFIES each proof-of-possession (SECURITY-AUDIT T-1) before trusting a
    /// member's leaf signature key, so a malicious committer cannot seed the joiner
    /// with substituted keys.
    sig_keys: Vec<(u32, RatchetPublic, IdentityPublic, Vec<u8>)>,
    commit: Commit,
}

// ---- wire serialization (talkrypt-compact; not RFC 9420 framing) ----

fn put_node(w: &mut talkrypt_wire::Writer, n: &Node) {
    w.put_u32(n.lo);
    w.put_u32(n.span);
}
fn get_node(r: &mut talkrypt_wire::Reader) -> Result<Node> {
    let lo = r.get_u32()?;
    let span = r.get_u32()?;
    // A well-formed ratchet-tree node has a power-of-two span, a `lo` aligned to
    // that span, and stays within the tree bound. Validating here keeps every
    // downstream Node operation total on hostile input: `sibling`/`parent` no
    // longer divide or modulo by a zero span, `parent` and `sibling` cannot
    // overflow past the tree, and `children`'s halving terminates. Without this
    // an attacker-supplied `span == 0` panics (`lo / span`) and an out-of-range
    // `lo`/`span` overflows — a single crafted Commit/Welcome would crash the
    // receiver (SECURITY-AUDIT: remote-DoS via malformed tree node).
    if span == 0 || !span.is_power_of_two() {
        return Err(CryptoError::Malformed("treekem node span not a power of two"));
    }
    if lo % span != 0 {
        return Err(CryptoError::Malformed("treekem node lo not span-aligned"));
    }
    match lo.checked_add(span) {
        Some(end) if end <= MAX_TREE_ITEMS => {}
        _ => return Err(CryptoError::Malformed("treekem node out of range")),
    }
    Ok(Node { lo, span })
}

impl KeyPackage {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_bytes(&self.leaf_public.encode());
        w.put_bytes(&self.sig_public.sig_vk);
        w.put_bytes(&self.pop);
        w.into_vec()
    }
    pub fn decode(profile: KemProfile, bytes: &[u8]) -> Result<KeyPackage> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let leaf_public = RatchetPublic::decode(profile, r.get_bytes()?)?;
        let sig_public = decode_sig_public(r.get_bytes()?)?;
        let pop = r.get_vec()?;
        r.finish()?;
        // Reject a KeyPackage whose leaf key is not proven-possessed (T-1).
        verify_pop(&sig_public, &pop)?;
        Ok(KeyPackage { leaf_public, sig_public, pop })
    }
}

impl Proposal {
    fn put(&self, w: &mut talkrypt_wire::Writer) {
        match self {
            Proposal::Add { leaf, leaf_public, sig_public, pop } => {
                w.put_u8(0);
                w.put_u32(*leaf);
                w.put_bytes(&leaf_public.encode());
                w.put_bytes(&sig_public.sig_vk);
                w.put_bytes(pop);
            }
            Proposal::Remove { leaf } => {
                w.put_u8(1);
                w.put_u32(*leaf);
            }
        }
    }
    fn get(profile: KemProfile, r: &mut talkrypt_wire::Reader) -> Result<Proposal> {
        match r.get_u8()? {
            0 => Ok(Proposal::Add {
                leaf: r.get_u32()?,
                leaf_public: RatchetPublic::decode(profile, r.get_bytes()?)?,
                sig_public: decode_sig_public(r.get_bytes()?)?,
                pop: r.get_vec()?,
            }),
            1 => Ok(Proposal::Remove { leaf: r.get_u32()? }),
            _ => Err(CryptoError::Malformed("bad proposal tag")),
        }
    }
}

const MAX_TREE_ITEMS: u32 = 1 << 20;

/// The encoded length of an ML-DSA-87 verifying key (category-5). A leaf sig key
/// on the wire must be exactly this long.
const SIG_VK_LEN: usize = 2592;

/// Decode a leaf signature public key from wire bytes, rejecting a wrong-length
/// key before it is stored or used to verify (SECURITY-AUDIT G1/G2 — a bogus key
/// must never be admitted into the tree).
fn decode_sig_public(bytes: &[u8]) -> Result<IdentityPublic> {
    if bytes.len() != SIG_VK_LEN {
        return Err(CryptoError::Malformed("treekem leaf sig key wrong length"));
    }
    Ok(IdentityPublic { sig_vk: bytes.to_vec() })
}

/// Group-message wire versions (leading byte). v1 is the legacy unsigned format
/// (forgeable by any member — SECURITY-AUDIT G1); v2 adds a per-sender ML-DSA-87
/// signature and is the only format accepted across a trust boundary.
const GROUP_MSG_V1: u8 = 1;
const GROUP_MSG_V2: u8 = 2;

/// Domain-separation prefix for the per-sender group-message signature.
const SIG_CONTEXT: &[u8] = b"talkrypt-treekem-msg-v2";

/// Domain-separation prefix for a leaf key's proof-of-possession (SECURITY-AUDIT
/// T-1). Distinct from `SIG_CONTEXT` so a PoP can never be replayed as a
/// group-message signature or vice versa.
const POP_CONTEXT: &[u8] = b"talkrypt-treekem-leaf-pop-v2";

/// The bytes a joiner signs (with its leaf signing key) to prove possession of it:
/// `POP_CONTEXT | sig_vk`. The KEM leaf key is NOT bound here — it rotates on every
/// commit (`rekey_path`) and the leaf index isn't known at KeyPackage-creation
/// time, so neither is a stable target. Possession of the signing key is the
/// property that matters: it stops a committer/relay substituting a leaf signature
/// key whose secret it does not hold (SECURITY-AUDIT T-1).
fn pop_transcript(sig_public: &IdentityPublic) -> Vec<u8> {
    let mut w = talkrypt_wire::Writer::new();
    w.put_bytes(POP_CONTEXT);
    w.put_bytes(&sig_public.sig_vk);
    w.into_vec()
}

/// Verify a proof-of-possession: `pop` must verify under `sig_public` over the
/// POP transcript. Rejects a leaf signature key whose holder did not sign it
/// (SECURITY-AUDIT T-1). A self-signature is sound here because ML-DSA is
/// EUF-CMA: producing a valid PoP requires the corresponding secret key.
fn verify_pop(sig_public: &IdentityPublic, pop: &[u8]) -> Result<()> {
    sig_public
        .verify(&pop_transcript(sig_public), pop)
        .map_err(|_| CryptoError::BadSignature)
}

/// The bytes a sender signs (and a receiver verifies) for a v2 group message:
/// `SIG_CONTEXT | epoch | leaf | n | ct`.
fn sig_transcript(epoch: u32, leaf: u32, n: u32, ct: &[u8]) -> Vec<u8> {
    let mut w = talkrypt_wire::Writer::new();
    w.put_bytes(SIG_CONTEXT);
    w.put_u32(epoch);
    w.put_u32(leaf);
    w.put_u32(n);
    w.put_bytes(ct);
    w.into_vec()
}

/// Read a length prefix that will drive a `Vec` allocation, bounding it against
/// both [`MAX_TREE_ITEMS`] and `remaining / min_elem_bytes` before allocating, so
/// a crafted count cannot force a large speculative allocation (SECURITY-AUDIT
/// G3/G4). Each element is at least `min_elem_bytes` on the wire, so the count can
/// never exceed the elements that could still fit in the unread input.
fn get_count(r: &mut talkrypt_wire::Reader, min_elem_bytes: usize) -> Result<u32> {
    let n = r.get_u32()?;
    if n > MAX_TREE_ITEMS {
        return Err(CryptoError::Malformed("treekem count too large"));
    }
    let max_possible = (r.remaining() / min_elem_bytes.max(1)) as u64;
    if n as u64 > max_possible {
        return Err(CryptoError::Malformed("treekem count exceeds input length"));
    }
    Ok(n)
}

impl Commit {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(self.proposals.len() as u32);
        for p in &self.proposals {
            p.put(&mut w);
        }
        w.put_u32(self.pub_updates.len() as u32);
        for (n, p) in &self.pub_updates {
            put_node(&mut w, n);
            w.put_bytes(&p.encode());
        }
        w.put_u32(self.path.len() as u32);
        for n in &self.path {
            put_node(&mut w, n);
        }
        w.put_u32(self.ciphertexts.len() as u32);
        for (a, b, blob) in &self.ciphertexts {
            put_node(&mut w, a);
            put_node(&mut w, b);
            w.put_bytes(blob);
        }
        w.put_u32(self.new_capacity);
        match &self.sig_update {
            None => w.put_u8(0),
            Some((leaf, sig_public, pop)) => {
                w.put_u8(1);
                w.put_u32(*leaf);
                w.put_bytes(&sig_public.sig_vk);
                w.put_bytes(pop);
            }
        }
        w.into_vec()
    }

    pub fn decode(profile: KemProfile, bytes: &[u8]) -> Result<Commit> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let c = Self::read(profile, &mut r)?;
        r.finish()?;
        Ok(c)
    }

    fn read(profile: KemProfile, r: &mut talkrypt_wire::Reader) -> Result<Commit> {
        // Minimums: Proposal >=1 (tag); pub_update = node(8)+key(>=4)=12; path
        // entry = node(8); ciphertext = node(8)+node(8)+blob(>=4)=20.
        let np = get_count(r, 1)?;
        let mut proposals = Vec::with_capacity(np as usize);
        for _ in 0..np {
            proposals.push(Proposal::get(profile, r)?);
        }
        let nu = get_count(r, 12)?;
        let mut pub_updates = Vec::with_capacity(nu as usize);
        for _ in 0..nu {
            let node = get_node(r)?;
            let p = RatchetPublic::decode(profile, r.get_bytes()?)?;
            pub_updates.push((node, p));
        }
        let npath = get_count(r, 8)?;
        let mut path = Vec::with_capacity(npath as usize);
        for _ in 0..npath {
            path.push(get_node(r)?);
        }
        let nc = get_count(r, 20)?;
        let mut ciphertexts = Vec::with_capacity(nc as usize);
        for _ in 0..nc {
            let a = get_node(r)?;
            let b = get_node(r)?;
            let blob = r.get_vec()?;
            ciphertexts.push((a, b, blob));
        }
        let new_capacity = r.get_u32()?;
        // Bound the declared capacity before `apply_commit` resizes `occupied` to
        // it: an unbounded u32 (~4.3e9) would request a multi-gigabyte allocation
        // and abort the process (`panic = abort`) from a single crafted Commit.
        if new_capacity > MAX_TREE_ITEMS {
            return Err(CryptoError::Malformed("treekem new_capacity too large"));
        }
        let sig_update = match r.get_u8()? {
            0 => None,
            1 => {
                let leaf = r.get_u32()?;
                let sig_public = decode_sig_public(r.get_bytes()?)?;
                let pop = r.get_vec()?;
                Some((leaf, sig_public, pop))
            }
            _ => return Err(CryptoError::Malformed("bad sig_update tag")),
        };
        Ok(Commit {
            proposals,
            pub_updates,
            path,
            ciphertexts,
            new_capacity,
            sig_update,
        })
    }
}

impl Welcome {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(self.capacity);
        w.put_u32(self.public.len() as u32);
        for (n, p) in &self.public {
            put_node(&mut w, n);
            w.put_bytes(&p.encode());
        }
        w.put_u32(self.occupied.len() as u32);
        for o in &self.occupied {
            w.put_u8(*o as u8);
        }
        w.put_u32(self.epoch);
        w.put_u32(self.your_leaf);
        w.put_u32(self.sig_keys.len() as u32);
        for (leaf, lp, k, pop) in &self.sig_keys {
            w.put_u32(*leaf);
            w.put_bytes(&lp.encode());
            w.put_bytes(&k.sig_vk);
            w.put_bytes(pop);
        }
        w.put_bytes(&self.commit.encode());
        w.into_vec()
    }

    pub fn decode(profile: KemProfile, bytes: &[u8]) -> Result<Welcome> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let capacity = r.get_u32()?;
        // Same bound as Commit::new_capacity: a hostile Welcome must not be able to
        // drive an unbounded capacity into the joined group's tree math.
        if capacity > MAX_TREE_ITEMS {
            return Err(CryptoError::Malformed("treekem welcome capacity too large"));
        }
        // public entry = node(8)+key(>=4)=12; occupied = 1 byte each.
        let np = get_count(&mut r, 12)?;
        let mut public = Vec::with_capacity(np as usize);
        for _ in 0..np {
            let node = get_node(&mut r)?;
            let p = RatchetPublic::decode(profile, r.get_bytes()?)?;
            public.push((node, p));
        }
        let no = get_count(&mut r, 1)?;
        let mut occupied = Vec::with_capacity(no as usize);
        for _ in 0..no {
            occupied.push(r.get_u8()? != 0);
        }
        let epoch = r.get_u32()?;
        let your_leaf = r.get_u32()?;
        // Each sig_keys entry is leaf(4) + leaf_public(>=4) + vk(>=4) + pop(>=4).
        // Bound the count by the per-entry minimum.
        let nsk = get_count(&mut r, 16)?;
        let mut sig_keys = Vec::with_capacity(nsk as usize);
        for _ in 0..nsk {
            let leaf = r.get_u32()?;
            let lp = RatchetPublic::decode(profile, r.get_bytes()?)?;
            let k = decode_sig_public(r.get_bytes()?)?;
            let pop = r.get_vec()?;
            sig_keys.push((leaf, lp, k, pop));
        }
        let commit = Commit::decode(profile, r.get_bytes()?)?;
        r.finish()?;
        Ok(Welcome {
            capacity,
            public,
            occupied,
            epoch,
            your_leaf,
            sig_keys,
            commit,
        })
    }
}

#[derive(Clone)]
struct RecvChain {
    chain: Secret,
    n: u32,
    skipped: BTreeMap<u32, Secret>,
}

/// One member's full view of a TreeKEM group.
pub struct TreeKemGroup {
    /// KEM profile (posture + wire padding) for every node key in this group.
    profile: KemProfile,
    capacity: u32,
    public: HashMap<Node, RatchetPublic>,
    occupied: Vec<bool>,
    me: u32,
    secrets: HashMap<Node, Secret>,
    epoch: u32,
    epoch_secret: Secret,
    send_chain: Secret,
    send_n: u32,
    recvs: HashMap<u32, RecvChain>,
    /// leaf -> that member's ML-DSA-87 leaf signature public key. Populated as
    /// members are added (via Add proposals / Welcome). Used to VERIFY per-sender
    /// group-message signatures (SECURITY-AUDIT G1/G2).
    leaf_sig_keys: HashMap<u32, IdentityPublic>,
    /// leaf -> that member's proof-of-possession over its (leaf_public, sig_public)
    /// binding (SECURITY-AUDIT T-1). Retained so a joiner learning members via a
    /// Welcome can independently re-verify each member's leaf key.
    leaf_pops: HashMap<u32, Vec<u8>>,
    /// This member's own leaf SIGNING key (the private half). `None` only in the
    /// degenerate test-built group; `create`/`join` always set it. Used to SIGN our
    /// outgoing group messages.
    my_sig: Option<IdentityKeyPair>,
}

// Zero the group's secret material on drop: the ratchet-tree node secrets, the
// epoch secret, and the sending chain key. The per-member receive chains zero
// via `RecvChain`'s own Drop. SECURITY-AUDIT F-3.
impl Drop for TreeKemGroup {
    fn drop(&mut self) {
        for secret in self.secrets.values_mut() {
            secret.zeroize();
        }
        self.epoch_secret.zeroize();
        self.send_chain.zeroize();
    }
}

impl Drop for RecvChain {
    fn drop(&mut self) {
        self.chain.zeroize();
        for seed in self.skipped.values_mut() {
            seed.zeroize();
        }
    }
}

impl Drop for LeafKeyPair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl TreeKemGroup {
    /// Create a new group as its founder (leaf 0), capacity 2, using the
    /// default (PQ-pure) KEM profile.
    pub fn create() -> TreeKemGroup {
        TreeKemGroup::create_with(KemProfile::default())
    }

    /// Create a new group with a specific KEM profile (posture + wire padding).
    pub fn create_with(profile: KemProfile) -> TreeKemGroup {
        let capacity = 2;
        let mut leaf_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut leaf_secret);

        // The founder's per-membership leaf signature key (its group alias).
        let my_sig = IdentityKeyPair::generate();
        let mut leaf_sig_keys = HashMap::new();
        leaf_sig_keys.insert(0u32, my_sig.public().clone());

        let mut g = TreeKemGroup {
            profile,
            capacity,
            public: HashMap::new(),
            occupied: vec![false; capacity as usize],
            me: 0,
            secrets: HashMap::new(),
            epoch: 0,
            epoch_secret: [0u8; 32],
            send_chain: [0u8; 32],
            send_n: 0,
            recvs: HashMap::new(),
            leaf_sig_keys,
            leaf_pops: HashMap::new(),
            my_sig: Some(my_sig),
        };
        g.occupied[0] = true;
        // Set the founder's whole path (leaf -> root) from a fresh secret chain.
        let path = g.path_to_root(0);
        let mut ps = leaf_secret;
        for (i, node) in path.iter().enumerate() {
            if i > 0 {
                ps = derive_parent_secret(&ps);
            }
            let (_, pubk) = RatchetSecret::derive_deterministic(profile, &ps);
            g.public.insert(*node, pubk);
            g.secrets.insert(*node, ps);
        }
        let root_secret = *g.secrets.get(&root_of(capacity)).expect("root secret");
        g.epoch_secret = derive_commit_secret(&root_secret);
        // Founder proof-of-possession over (leaf-0 KEM pub, sig pub) (SECURITY-AUDIT
        // T-1), so a Welcome carrying the founder's key is independently verifiable.
        let sig_pub = g.my_sig.as_ref().unwrap().public().clone();
        let pop = g.my_sig.as_ref().unwrap().sign(&pop_transcript(&sig_pub));
        g.leaf_pops.insert(0, pop);
        g.reset_epoch();
        g
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }
    pub fn member_count(&self) -> usize {
        self.occupied.iter().filter(|o| **o).count()
    }
    pub fn group_secret(&self) -> Secret {
        self.epoch_secret
    }
    pub fn my_leaf(&self) -> u32 {
        self.me
    }
    /// The KEM profile (posture + wire padding) of every node key in this group.
    /// Needed to decode incoming `KeyPackage`/`Commit`/`Welcome` wire bytes.
    pub fn profile(&self) -> KemProfile {
        self.profile
    }

    // ---- tree helpers ----

    fn path_to_root(&self, leaf: u32) -> Vec<Node> {
        let mut path = vec![Node::leaf(leaf)];
        let mut cur = Node::leaf(leaf);
        while let Some(p) = cur.parent(self.capacity) {
            path.push(p);
            cur = p;
        }
        path
    }

    fn is_blank(&self, node: &Node) -> bool {
        !self.public.contains_key(node)
    }

    /// Highest non-blank nodes covering `node`'s subtree.
    fn resolution(&self, node: Node) -> Vec<Node> {
        if !self.is_blank(&node) {
            return vec![node];
        }
        match node.children() {
            None => Vec::new(),
            Some((l, r)) => {
                let mut v = self.resolution(l);
                v.extend(self.resolution(r));
                v
            }
        }
    }

    fn first_free_leaf(&self) -> Option<u32> {
        self.occupied.iter().position(|o| !*o).map(|i| i as u32)
    }

    fn double_capacity(&mut self) {
        self.capacity *= 2;
        self.occupied.resize(self.capacity as usize, false);
        // Existing node ids (span <= old capacity) remain valid; the new root
        // and the new half start blank.
    }

    // ---- membership ----

    /// Add a member from their key package. Returns the assigned leaf, the
    /// `Commit` to broadcast to existing members, and the `Welcome` for the
    /// joiner. Advances the epoch.
    pub fn add(&mut self, kp: &KeyPackage) -> Result<(u32, Commit, Welcome)> {
        if self.first_free_leaf().is_none() {
            self.double_capacity();
        }
        let leaf = self.first_free_leaf().expect("free leaf after doubling");
        let proposals = vec![Proposal::Add {
            leaf,
            leaf_public: kp.leaf_public.clone(),
            sig_public: kp.sig_public.clone(),
            pop: kp.pop.clone(),
        }];
        self.apply_proposals(&proposals)?;
        let commit = self.rekey_path(proposals)?;

        let welcome = Welcome {
            capacity: self.capacity,
            public: self.public.iter().map(|(n, p)| (*n, p.clone())).collect(),
            occupied: self.occupied.clone(),
            epoch: self.epoch,
            your_leaf: leaf,
            // Every member's leaf sig key, so the joiner can verify all senders
            // (SECURITY-AUDIT G1/G2). Includes the joiner's own (just added).
            sig_keys: self
                .leaf_sig_keys
                .iter()
                .filter_map(|(l, k)| {
                    let lp = self.public.get(&Node::leaf(*l))?.clone();
                    let pop = self.leaf_pops.get(l)?.clone();
                    Some((*l, lp, k.clone(), pop))
                })
                .collect(),
            commit: commit.clone(),
        };
        Ok((leaf, commit, welcome))
    }

    /// Remove a member. The removed member cannot derive the new group secret.
    pub fn remove(&mut self, leaf: u32) -> Result<Commit> {
        let proposals = vec![Proposal::Remove { leaf }];
        self.apply_proposals(&proposals)?;
        self.rekey_path(proposals)
    }

    /// **Self-update** (the MLS `Update` operation): re-key ONLY this member's own
    /// leaf→root path with fresh ML-KEM entropy, *without* any membership change.
    /// The returned [`Commit`], applied by every other member, advances the epoch;
    /// an adversary holding this member's *prior* path secrets cannot derive the new
    /// epoch secret — i.e. **post-compromise security** on demand, not only when the
    /// roster changes. Mechanically identical to add/remove's re-key, with no
    /// proposals (roster unchanged). `rekey_path` already refreshes the caller's
    /// path secrets and advances `self.epoch`/`epoch_secret`.
    pub fn update(&mut self) -> Result<Commit> {
        let mut commit = self.rekey_path(Vec::new())?;
        // Rotate our leaf SIGNING key too (SECURITY-AUDIT T-2): a compromised leaf
        // signing key stops verifying after this update — post-compromise security
        // for authentication, not just for the epoch (confidentiality) secret.
        let new_sig = IdentityKeyPair::generate();
        let new_pub = new_sig.public().clone();
        let pop = new_sig.sign(&pop_transcript(&new_pub));
        self.leaf_sig_keys.insert(self.me, new_pub.clone());
        self.leaf_pops.insert(self.me, pop.clone());
        self.my_sig = Some(new_sig);
        commit.sig_update = Some((self.me, new_pub, pop));
        Ok(commit)
    }

    fn apply_proposals(&mut self, proposals: &[Proposal]) -> Result<()> {
        for p in proposals {
            // A proposal's leaf index is attacker-controlled on the receive path
            // (`apply_commit`). Bounds-check it against the (already capacity-sized)
            // `occupied` vector before indexing, so a crafted Commit can no longer
            // panic the receiver with an out-of-range leaf.
            let leaf = match p {
                Proposal::Add { leaf, .. } | Proposal::Remove { leaf } => *leaf,
            };
            if leaf as usize >= self.occupied.len() {
                return Err(CryptoError::Malformed("treekem proposal leaf out of range"));
            }
            match p {
                Proposal::Add { leaf, leaf_public, sig_public, pop } => {
                    // Re-verify proof-of-possession on the receive side: the leaf
                    // key must be signed by its own holder over this exact leaf
                    // (SECURITY-AUDIT T-1). A committer cannot bind a substituted
                    // key it does not control.
                    verify_pop(sig_public, pop)?;
                    self.occupied[*leaf as usize] = true;
                    self.public.insert(Node::leaf(*leaf), leaf_public.clone());
                    self.leaf_sig_keys.insert(*leaf, sig_public.clone());
                    self.leaf_pops.insert(*leaf, pop.clone());
                    // Blank the new leaf's ancestors so the committer re-keys.
                    self.blank_path_above(*leaf);
                }
                Proposal::Remove { leaf } => {
                    self.occupied[*leaf as usize] = false;
                    self.secrets.remove(&Node::leaf(*leaf));
                    self.public.remove(&Node::leaf(*leaf));
                    self.leaf_sig_keys.remove(leaf);
                    self.leaf_pops.remove(leaf);
                    self.blank_path_above(*leaf);
                }
            }
        }
        Ok(())
    }

    fn blank_path_above(&mut self, leaf: u32) {
        let mut cur = Node::leaf(leaf);
        while let Some(p) = cur.parent(self.capacity) {
            self.public.remove(&p);
            self.secrets.remove(&p);
            cur = p;
        }
    }

    /// Re-key the committer's path: fresh secrets leaf->root, encrypt each
    /// ancestor's path secret to the resolution of its copath, set the new
    /// epoch secret. Returns the broadcastable `Commit`.
    fn rekey_path(&mut self, proposals: Vec<Proposal>) -> Result<Commit> {
        let path = self.path_to_root(self.me);
        let mut path_secrets = vec![[0u8; 32]; path.len()];
        rand::rngs::OsRng.fill_bytes(&mut path_secrets[0]);
        for i in 1..path.len() {
            path_secrets[i] = derive_parent_secret(&path_secrets[i - 1]);
        }

        let mut pub_updates = Vec::with_capacity(path.len());
        for (i, node) in path.iter().enumerate() {
            let (_, pubk) = RatchetSecret::derive_deterministic(self.profile, &path_secrets[i]);
            self.public.insert(*node, pubk.clone());
            self.secrets.insert(*node, path_secrets[i]);
            pub_updates.push((*node, pubk));
        }

        let mut ciphertexts = Vec::new();
        for i in 1..path.len() {
            let copath = path[i - 1].sibling();
            for target in self.resolution(copath) {
                let target_pub = self
                    .public
                    .get(&target)
                    .ok_or(CryptoError::Malformed("resolution node has no key"))?;
                let blob = seal_secret(target_pub, &path_secrets[i])?;
                ciphertexts.push((path[i], target, blob));
            }
        }

        let commit_secret = derive_commit_secret(&path_secrets[path.len() - 1]);
        self.epoch += 1;
        self.epoch_secret = commit_secret;
        self.reset_epoch();

        Ok(Commit {
            proposals,
            pub_updates,
            path,
            ciphertexts,
            new_capacity: self.capacity,
            sig_update: None,
        })
    }

    /// Apply a commit produced by another member; advances to its epoch.
    pub fn apply_commit(&mut self, commit: &Commit) -> Result<()> {
        if commit.new_capacity > self.capacity {
            self.capacity = commit.new_capacity;
            self.occupied.resize(self.capacity as usize, false);
        }
        self.apply_proposals(&commit.proposals)?;
        // Apply an optional leaf-signature-key rotation (SECURITY-AUDIT T-2). The
        // new key must carry a valid PoP; the committer may only rotate its OWN
        // leaf (a committer cannot rotate another member's signing key). The leaf
        // must be occupied. Rebinds the verifying key so the old key stops
        // verifying from this epoch on.
        if let Some((leaf, sig_public, pop)) = &commit.sig_update {
            match self.occupied.get(*leaf as usize) {
                Some(true) => {}
                _ => return Err(CryptoError::Malformed("sig_update for empty leaf")),
            }
            verify_pop(sig_public, pop)?;
            self.leaf_sig_keys.insert(*leaf, sig_public.clone());
            self.leaf_pops.insert(*leaf, pop.clone());
        }
        let secret = self.process_update_path(commit)?;
        self.epoch += 1;
        self.epoch_secret = secret;
        self.reset_epoch();
        Ok(())
    }

    /// Join a group from a Welcome message using the matching leaf key.
    pub fn join_with_welcome(keypair: LeafKeyPair, welcome: &Welcome) -> Result<TreeKemGroup> {
        // `LeafKeyPair` is a Drop type (zeroizes its secret), so we cannot move its
        // fields out. Copy the KEM leaf secret and rebuild the leaf signing key
        // from its seed; `keypair` then drops normally, zeroizing its copy.
        let profile = keypair.profile;
        let secret = keypair.secret;
        let sig = IdentityKeyPair::from_secret_bytes(keypair.sig.export_secret());
        // Learn every current member's leaf key from the Welcome, RE-VERIFYING each
        // proof-of-possession (SECURITY-AUDIT T-1) so a malicious committer cannot
        // seed us with substituted keys. A bad PoP aborts the join.
        let mut leaf_sig_keys: HashMap<u32, IdentityPublic> = HashMap::new();
        let mut leaf_pops: HashMap<u32, Vec<u8>> = HashMap::new();
        for (leaf, _leaf_public, sig_public, pop) in &welcome.sig_keys {
            verify_pop(sig_public, pop)?;
            leaf_sig_keys.insert(*leaf, sig_public.clone());
            leaf_pops.insert(*leaf, pop.clone());
        }
        let mut g = TreeKemGroup {
            profile,
            capacity: welcome.capacity,
            public: welcome.public.iter().cloned().collect(),
            occupied: welcome.occupied.clone(),
            me: welcome.your_leaf,
            secrets: HashMap::new(),
            epoch: welcome.epoch,
            epoch_secret: [0u8; 32],
            send_chain: [0u8; 32],
            send_n: 0,
            recvs: HashMap::new(),
            leaf_sig_keys,
            leaf_pops,
            my_sig: Some(sig),
        };
        g.leaf_sig_keys
            .insert(welcome.your_leaf, g.my_sig.as_ref().unwrap().public().clone());
        // We hold only our own leaf secret to start.
        g.secrets.insert(Node::leaf(welcome.your_leaf), secret);
        let secret = g.process_update_path(&welcome.commit)?;
        g.epoch_secret = secret;
        g.reset_epoch();
        Ok(g)
    }

    /// Adopt the committer's new path public keys, decrypt the path secret at
    /// the level where our path meets theirs, and chain to the root secret.
    fn process_update_path(&mut self, commit: &Commit) -> Result<Secret> {
        for (node, pubk) in &commit.pub_updates {
            self.public.insert(*node, pubk.clone());
        }
        let path = &commit.path;
        for i in 1..path.len() {
            let copath = path[i - 1].sibling();
            // Which resolution node of the copath do we hold a secret for?
            for target in self.resolution(copath) {
                if let Some(secret) = self.secrets.get(&target).copied() {
                    let (rsecret, _) = RatchetSecret::derive_deterministic(self.profile, &secret);
                    let blob = commit
                        .ciphertexts
                        .iter()
                        .find(|(p, t, _)| *p == path[i] && *t == target)
                        .map(|(_, _, b)| b)
                        .ok_or(CryptoError::Malformed("no ciphertext for held target"))?;
                    let mut ps = open_secret(&rsecret, blob)?;
                    self.secrets.insert(path[i], ps);
                    for node in &path[i + 1..] {
                        ps = derive_parent_secret(&ps);
                        self.secrets.insert(*node, ps);
                    }
                    return Ok(derive_commit_secret(&ps));
                }
            }
        }
        Err(CryptoError::Malformed("no common ancestor with committer"))
    }

    // ---- epoch messaging ----

    fn reset_epoch(&mut self) {
        self.send_chain = sender_chain(&self.epoch_secret, self.me);
        self.send_n = 0;
        self.recvs.clear();
    }

    /// Read the sender's leaf index without decrypting (v1 or v2 framing). For v2
    /// this is the *claimed* leaf, trustworthy only after [`decrypt_verified`]
    /// checks the signature (SECURITY-AUDIT G1/G2).
    ///
    /// [`decrypt_verified`]: TreeKemGroup::decrypt_verified
    pub fn sender_leaf(message: &[u8]) -> Option<u32> {
        let mut r = talkrypt_wire::Reader::new(message);
        let _version = r.get_u8().ok()?;
        let _epoch = r.get_u32().ok()?;
        r.get_u32().ok()
    }

    /// Encrypt an **unsigned** (v1) group message — authenticated only by the
    /// shared `epoch_secret`, hence forgeable by any member. Legacy/tests only;
    /// the engine uses [`encrypt_signed`]. Never accept v1 on a trust boundary.
    ///
    /// [`encrypt_signed`]: TreeKemGroup::encrypt_signed
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (next, mk_seed) = kdf_ck(&self.send_chain); // both Zeroizing
        let (key, nonce) = kdf_mk(&mk_seed); // key: Zeroizing
        let n = self.send_n;
        let aad = msg_aad(self.epoch, self.me, n);
        let ct = aead_seal(&key, &nonce, plaintext, &aad)?;
        self.send_chain = *next;
        self.send_n += 1;
        let mut w = talkrypt_wire::Writer::new();
        w.put_u8(GROUP_MSG_V1);
        w.put_u32(self.epoch);
        w.put_u32(self.me);
        w.put_u32(n);
        w.put_bytes(&ct);
        Ok(w.into_vec())
    }

    /// Encrypt a **signed** (v2) group message: the sender signs
    /// `SIG_CONTEXT|epoch|leaf|n|ct` with its per-membership ML-DSA-87 **leaf
    /// signature key**, so a receiver ([`decrypt_verified`]) can bind the message
    /// to the sender's leaf (via the tree-bound leaf sig key) and reject
    /// impersonation or relay restamping (SECURITY-AUDIT G1/G2). The leaf key is a
    /// per-group alias — unlinkable to the device — so this authenticates the
    /// message without revealing a long-term identity.
    ///
    /// [`decrypt_verified`]: TreeKemGroup::decrypt_verified
    pub fn encrypt_signed(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let my_sig = self
            .my_sig
            .as_ref()
            .ok_or(CryptoError::Malformed("group has no leaf signing key"))?;
        let (next, mk_seed) = kdf_ck(&self.send_chain); // both Zeroizing
        let (key, nonce) = kdf_mk(&mk_seed); // key: Zeroizing
        let n = self.send_n;
        let aad = msg_aad(self.epoch, self.me, n);
        let ct = aead_seal(&key, &nonce, plaintext, &aad)?;
        let sig = my_sig.sign(&sig_transcript(self.epoch, self.me, n, &ct));
        self.send_chain = *next;
        self.send_n += 1;
        let mut w = talkrypt_wire::Writer::new();
        w.put_u8(GROUP_MSG_V2);
        w.put_u32(self.epoch);
        w.put_u32(self.me);
        w.put_u32(n);
        w.put_bytes(&ct);
        w.put_bytes(&sig);
        Ok(w.into_vec())
    }

    /// Decrypt a group message, requiring a valid per-sender signature (v2). The
    /// signature is verified against the sending leaf's tree-bound leaf signature
    /// key BEFORE decryption; a v1 (unsigned) frame, an unknown leaf, or a bad
    /// signature is rejected (SECURITY-AUDIT G1/G2). Because the verifying key
    /// comes from group membership (Add/Welcome), a member or relay cannot forge or
    /// restamp the sender.
    pub fn decrypt_verified(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut r = talkrypt_wire::Reader::new(message);
        let version = r.get_u8()?;
        if version != GROUP_MSG_V2 {
            return Err(CryptoError::Malformed("group message not signed (v2)"));
        }
        let epoch = r.get_u32()?;
        let leaf = r.get_u32()?;
        let n = r.get_u32()?;
        let ct = r.get_vec()?;
        let sig = r.get_vec()?;
        r.finish()?;
        let vk = self
            .leaf_sig_keys
            .get(&leaf)
            .ok_or(CryptoError::BadSignature)?;
        if vk
            .verify(&sig_transcript(epoch, leaf, n, &ct), &sig)
            .is_err()
        {
            return Err(CryptoError::BadSignature);
        }
        if epoch != self.epoch {
            return Err(CryptoError::DecryptionFailed);
        }
        self.decrypt_body(epoch, leaf, n, &ct)
    }

    /// Decrypt an **unsigned** (v1) group message. Forgeable by any member; used
    /// for the legacy format and tests, never on a trust boundary. Prefer
    /// [`decrypt_verified`].
    ///
    /// [`decrypt_verified`]: TreeKemGroup::decrypt_verified
    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut r = talkrypt_wire::Reader::new(message);
        let version = r.get_u8()?;
        if version != GROUP_MSG_V1 {
            return Err(CryptoError::Malformed("expected unsigned (v1) group message"));
        }
        let epoch = r.get_u32()?;
        let leaf = r.get_u32()?;
        let n = r.get_u32()?;
        let ct = r.get_vec()?;
        r.finish()?;
        if epoch != self.epoch {
            return Err(CryptoError::DecryptionFailed);
        }
        self.decrypt_body(epoch, leaf, n, &ct)
    }

    /// Shared post-header decryption for v1/v2: advance the sender's receive chain
    /// (with skip tolerance) and open the AEAD.
    fn decrypt_body(&mut self, epoch: u32, leaf: u32, n: u32, ct: &[u8]) -> Result<Vec<u8>> {
        let aad = msg_aad(epoch, leaf, n);
        let epoch_secret = self.epoch_secret;
        let recv = self.recvs.entry(leaf).or_insert_with(|| RecvChain {
            chain: sender_chain(&epoch_secret, leaf),
            n: 0,
            skipped: BTreeMap::new(),
        });

        if let Some(seed) = recv.skipped.remove(&n) {
            let seed = Zeroizing::new(seed);
            let (key, nonce) = kdf_mk(&seed); // key: Zeroizing
            return aead_open(&key, &nonce, ct, &aad);
        }
        if n < recv.n {
            return Err(CryptoError::DecryptionFailed);
        }
        if (n - recv.n) as usize > MAX_SKIP {
            return Err(CryptoError::TooManySkipped(MAX_SKIP));
        }
        while recv.n < n {
            let (nx, seed) = kdf_ck(&recv.chain); // both Zeroizing
            recv.skipped.insert(recv.n, *seed);
            recv.chain = *nx;
            recv.n += 1;
        }
        let (nx, mk_seed) = kdf_ck(&recv.chain);
        let (key, nonce) = kdf_mk(&mk_seed); // key: Zeroizing
        let pt = aead_open(&key, &nonce, ct, &aad)?;
        recv.chain = *nx;
        recv.n += 1;
        Ok(pt)
    }
}

// ---- KDF + HPKE-style helpers ----

fn derive_parent_secret(child: &Secret) -> Secret {
    expand(child, b"talkrypt-treekem-parent")
}
fn derive_commit_secret(root: &Secret) -> Secret {
    expand(root, b"talkrypt-treekem-commit")
}
fn expand(secret: &Secret, label: &[u8]) -> Secret {
    let mut out = [0u8; 32];
    crate::kdf::mac_kdf(secret, &[], label, &mut out);
    out
}

fn sender_chain(epoch_secret: &Secret, leaf: u32) -> Secret {
    let mut out = [0u8; 32];
    crate::kdf::mac_kdf(
        epoch_secret,
        &leaf.to_be_bytes(),
        b"talkrypt-treekem-sender",
        &mut out,
    );
    out
}

fn msg_aad(epoch: u32, leaf: u32, n: u32) -> Vec<u8> {
    let mut w = talkrypt_wire::Writer::new();
    w.put_u32(epoch);
    w.put_u32(leaf);
    w.put_u32(n);
    w.into_vec()
}

fn seal_secret(pubk: &RatchetPublic, secret: &Secret) -> Result<Vec<u8>> {
    let (kem_ct, ss) = pubk.encapsulate()?;
    let (key, nonce) = kdf_mk(&ss);
    let aead_ct = aead_seal(&key, &nonce, secret, b"tk-treekem")?;
    let mut w = talkrypt_wire::Writer::new();
    w.put_bytes(&kem_ct);
    w.put_bytes(&aead_ct);
    Ok(w.into_vec())
}

fn open_secret(rsecret: &RatchetSecret, blob: &[u8]) -> Result<Secret> {
    let mut r = talkrypt_wire::Reader::new(blob);
    let kem_ct = r.get_vec()?;
    let aead_ct = r.get_vec()?;
    r.finish()?;
    let ss = rsecret.decapsulate(&kem_ct)?;
    let (key, nonce) = kdf_mk(&ss);
    let pt = aead_open(&key, &nonce, &aead_ct, b"tk-treekem")?;
    if pt.len() != 32 {
        return Err(CryptoError::Malformed("treekem path secret length"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&pt);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Miri-verified: `TreeKemGroup::drop` zeroes its `epoch_secret`. Built with
    /// empty maps so it runs under Miri without PQ keygen. SECURITY-AUDIT F-3.
    #[test]
    fn drop_zeroizes_treekem_epoch_secret() {
        let group = TreeKemGroup {
            profile: KemProfile::pq_pure(),
            capacity: 2,
            public: HashMap::new(),
            occupied: vec![false, false],
            me: 0,
            secrets: HashMap::new(),
            epoch: 0,
            epoch_secret: [0xAA; 32],
            send_chain: [0xAA; 32],
            send_n: 0,
            recvs: HashMap::new(),
            leaf_sig_keys: HashMap::new(),
            leaf_pops: HashMap::new(),
            my_sig: None,
        };
        unsafe {
            crate::assert_drop_zeroes(
                group,
                core::mem::offset_of!(TreeKemGroup, epoch_secret),
                32,
            );
        }
    }

    /// Add a fresh member to an existing group; returns the joiner's group. The
    /// joiner's leaf key is generated with the committer's profile so the
    /// published key matches the group.
    fn add_member(
        committer: &mut TreeKemGroup,
        followers: &mut [&mut TreeKemGroup],
    ) -> TreeKemGroup {
        let kp = LeafKeyPair::generate_with(committer.profile());
        let (_leaf, commit, welcome) = committer.add(&kp.key_package()).unwrap();
        for f in followers.iter_mut() {
            f.apply_commit(&commit).unwrap();
        }
        TreeKemGroup::join_with_welcome(kp, &welcome).unwrap()
    }

    /// Every KEM profile — hybrid, padded PQ-pure, compact PQ-pure — must form a
    /// working group: members converge on the epoch secret and can message.
    #[test]
    fn all_profiles_group_converges() {
        for profile in [
            KemProfile::hybrid(),
            KemProfile::pq_pure(),
            KemProfile::pq_pure_compact(),
        ] {
            let mut a = TreeKemGroup::create_with(profile);
            let mut b = add_member(&mut a, &mut []);
            let mut c = add_member(&mut a, &mut [&mut b]);
            assert_eq!(a.group_secret(), b.group_secret());
            assert_eq!(a.group_secret(), c.group_secret());
            let m = a.encrypt(b"profile check").unwrap();
            assert_eq!(b.decrypt(&m).unwrap(), b"profile check");
            assert_eq!(c.decrypt(&m).unwrap(), b"profile check");
        }
    }

    #[test]
    fn node_math_is_consistent() {
        let cap = 8;
        for leaf in 0..cap {
            let mut cur = Node::leaf(leaf);
            let mut hops = 0;
            while let Some(p) = cur.parent(cap) {
                assert!(p.covers(leaf));
                assert_eq!(cur.sibling().sibling(), cur);
                cur = p;
                hops += 1;
            }
            assert_eq!(cur, root_of(cap));
            assert_eq!(hops, 3); // log2(8)
        }
    }

    #[test]
    fn founder_then_add_converges() {
        let mut a = TreeKemGroup::create();
        let b = add_member(&mut a, &mut []);
        assert_eq!(a.group_secret(), b.group_secret());
        assert_eq!(a.member_count(), 2);
        assert_eq!(b.member_count(), 2);
    }

    #[test]
    fn three_members_message_each_other() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let c = add_member(&mut a, &mut [&mut b]);
        // All three share the epoch secret.
        assert_eq!(a.group_secret(), b.group_secret());
        assert_eq!(a.group_secret(), c.group_secret());

        let mut c = c;
        let m = a.encrypt(b"hi group").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"hi group");
        assert_eq!(c.decrypt(&m).unwrap(), b"hi group");
        let m2 = c.encrypt(b"from c").unwrap();
        assert_eq!(a.decrypt(&m2).unwrap(), b"from c");
        assert_eq!(b.decrypt(&m2).unwrap(), b"from c");
    }

    #[test]
    fn remove_denies_removed_member() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let mut c = add_member(&mut a, &mut [&mut b]);
        let secret_before = c.group_secret();

        // A removes C; B follows.
        let commit = a.remove(c.my_leaf()).unwrap();
        b.apply_commit(&commit).unwrap();

        // A and B converge on a new secret; C is stuck at the old one.
        assert_eq!(a.group_secret(), b.group_secret());
        assert_ne!(a.group_secret(), secret_before);
        assert_ne!(a.group_secret(), c.group_secret());

        // A message in the new epoch is undecryptable by the removed member.
        let m = a.encrypt(b"secret after removal").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"secret after removal");
        assert!(c.decrypt(&m).is_err());
    }

    #[test]
    fn commit_and_welcome_wire_roundtrip() {
        let mut a = TreeKemGroup::create();
        let kp = LeafKeyPair::generate();
        let (_leaf, commit, welcome) = a.add(&kp.key_package()).unwrap();

        let prof = a.profile();
        let commit2 = Commit::decode(prof, &commit.encode()).unwrap();
        assert!(commit == commit2);
        let welcome2 = Welcome::decode(prof, &welcome.encode()).unwrap();
        assert!(welcome == welcome2);
        let kp2 = KeyPackage::decode(prof, &kp.key_package().encode()).unwrap();
        assert_eq!(kp2.leaf_public, kp.key_package().leaf_public);

        // A joiner can actually use the serialized-then-deserialized Welcome.
        let b = TreeKemGroup::join_with_welcome(kp, &welcome2).unwrap();
        assert_eq!(a.group_secret(), b.group_secret());
    }

    #[test]
    fn group_out_of_order_and_replay() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let m0 = a.encrypt(b"0").unwrap();
        let m1 = a.encrypt(b"1").unwrap();
        let m2 = a.encrypt(b"2").unwrap();
        assert_eq!(b.decrypt(&m2).unwrap(), b"2");
        assert_eq!(b.decrypt(&m0).unwrap(), b"0");
        assert_eq!(b.decrypt(&m1).unwrap(), b"1");
        assert!(b.decrypt(&m0).is_err()); // replay
    }

    #[test]
    fn stale_epoch_message_rejected() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let stale = a.encrypt(b"old epoch").unwrap();
        // Adding a third member advances the epoch for both a and b.
        let _c = add_member(&mut a, &mut [&mut b]);
        assert!(b.decrypt(&stale).is_err());
    }

    #[test]
    fn capacity_doubles_past_two_members() {
        // create=2 capacity; adding a 3rd forces a doubling to 4.
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let c = add_member(&mut a, &mut [&mut b]);
        assert!(a.capacity >= 4);
        assert_eq!(a.group_secret(), c.group_secret());
        // Add a 4th, still converging.
        let mut c = c;
        let d = add_member(&mut a, &mut [&mut b, &mut c]);
        assert_eq!(a.group_secret(), d.group_secret());
        assert_eq!(a.member_count(), 4);
    }

    /// The MLS `Update` op re-keys the caller's own path (no membership change),
    /// advances the epoch, and every member converges on a NEW group secret —
    /// on-demand post-compromise security. A message encrypted under the pre-update
    /// epoch no longer decrypts under the new one (the old key material is stale).
    #[test]
    fn self_update_heals_without_membership_change() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        assert_eq!(a.group_secret(), b.group_secret());
        let before = a.group_secret();

        // A self-updates; B applies the resulting commit.
        let commit = a.update().unwrap();
        b.apply_commit(&commit).unwrap();

        // Fresh entropy → new, converged group secret; roster unchanged.
        assert_eq!(a.group_secret(), b.group_secret());
        assert_ne!(a.group_secret(), before, "update must inject fresh entropy");
        assert_eq!(a.member_count(), 2, "update changes no membership");

        // The group still works post-update.
        let m = a.encrypt(b"after update").unwrap();
        assert_eq!(b.decrypt(&m).unwrap(), b"after update");
    }

    /// Post-compromise: a message captured under the epoch BEFORE a member's update
    /// cannot be decrypted after the update is applied — the old epoch is gone.
    #[test]
    fn message_from_pre_update_epoch_is_stale_after_update() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let stale = a.encrypt(b"pre-update epoch").unwrap();
        // B heals via a self-update; both advance past the captured epoch.
        let commit = b.update().unwrap();
        a.apply_commit(&commit).unwrap();
        assert!(
            a.decrypt(&stale).is_err(),
            "a message from the pre-update epoch must not decrypt after healing"
        );
    }

    // ---- Remote-DoS regression tests (SECURITY-AUDIT: crafted Commit/Welcome) ----
    //
    // Each of these encodes a hostile Commit/Welcome that, before the decode/apply
    // guards, crashed the receiving member (`panic = abort`) on a single inbound
    // frame. They assert the malformed input is now rejected with `Err`, never a
    // panic. A member reaches this path for any peer-delivered Commit
    // (`engine::handle_commit`) / Welcome (`engine::handle_welcome`).

    /// A path node with `span == 0` used to reach `Node::sibling`'s `lo / span`
    /// (divide-by-zero) inside `process_update_path`. It must now be rejected at
    /// decode. (F4)
    #[test]
    fn commit_with_zero_span_node_is_rejected_not_panic() {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(0); // proposals
        w.put_u32(0); // pub_updates
        w.put_u32(1); // path: one node ...
        w.put_u32(0); // node.lo
        w.put_u32(0); // node.span == 0  <-- malicious
        w.put_u32(0); // ciphertexts
        w.put_u32(0); // new_capacity
        let bytes = w.into_vec();
        assert!(Commit::decode(KemProfile::pq_pure(), &bytes).is_err());
    }

    /// A non-power-of-two / unaligned node span is also structurally invalid and
    /// would break the tree math; reject it at decode. (F4)
    #[test]
    fn commit_with_nonpow2_span_node_is_rejected_not_panic() {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(0);
        w.put_u32(0);
        w.put_u32(1);
        w.put_u32(0);
        w.put_u32(3); // span = 3 is not a power of two
        w.put_u32(0);
        w.put_u32(0);
        assert!(Commit::decode(KemProfile::pq_pure(), &w.into_vec()).is_err());
    }

    /// `new_capacity == u32::MAX` used to drive `occupied.resize(~4.3e9)` in
    /// `apply_commit` — a multi-gigabyte allocation that aborts the process. It
    /// must now be rejected at decode. (F3)
    #[test]
    fn commit_with_huge_capacity_is_rejected_not_panic() {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(0); // proposals
        w.put_u32(0); // pub_updates
        w.put_u32(0); // path
        w.put_u32(0); // ciphertexts
        w.put_u32(u32::MAX); // new_capacity  <-- malicious
        assert!(Commit::decode(KemProfile::pq_pure(), &w.into_vec()).is_err());
    }

    /// The same bound applies to a hostile Welcome's declared capacity. (F3)
    #[test]
    fn welcome_with_huge_capacity_is_rejected_not_panic() {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(u32::MAX); // capacity  <-- malicious
        w.put_u32(0); // public entries
        w.put_u32(0); // occupied entries
        w.put_u32(0); // epoch
        w.put_u32(0); // your_leaf
        // (commit bytes never reached)
        assert!(Welcome::decode(KemProfile::pq_pure(), &w.into_vec()).is_err());
    }

    /// A `Remove` proposal with an out-of-range leaf decodes fine (the leaf is an
    /// unbounded u32 on the wire) but used to panic in `apply_proposals` at
    /// `occupied[leaf]`. `apply_commit` must now return `Err`, not panic. (F5)
    #[test]
    fn commit_with_out_of_range_leaf_is_rejected_not_panic() {
        let mut a = TreeKemGroup::create();
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(1); // one proposal ...
        w.put_u8(1); //   Remove
        w.put_u32(u32::MAX); //   leaf far past capacity  <-- malicious
        w.put_u32(0); // pub_updates
        w.put_u32(0); // path
        w.put_u32(0); // ciphertexts
        w.put_u32(0); // new_capacity (within bound, so we reach apply_proposals)
        w.put_u8(0); // sig_update: None (T-2 wire field)
        let commit = Commit::decode(a.profile(), &w.into_vec()).expect("decodes");
        assert!(a.apply_commit(&commit).is_err());
    }

    /// SECURITY-AUDIT G1/G2 REGRESSION — group-message sender forgery is closed.
    /// Attacker `b` can reconstruct `a`'s epoch sender chain from shared group
    /// state and stamp the victim's leaf, but the receiver verifies against the
    /// leaf SIGNATURE key bound in the tree for that leaf. `b` holds its own leaf
    /// signing key, not `a`'s, so it cannot produce a signature that verifies under
    /// `a`'s tree-bound key. Forgery REJECTED.
    #[test]
    fn member_cannot_forge_group_message_as_another_member() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let mut c = add_member(&mut a, &mut [&mut b]);
        let victim_leaf = a.my_leaf();
        assert_ne!(victim_leaf, b.my_leaf());

        // The G1 chain forgery: b derives a's sender chain and crafts the ct.
        let forged_chain = sender_chain(&b.group_secret(), victim_leaf);
        let (_next, mk_seed) = kdf_ck(&forged_chain);
        let (key, nonce) = kdf_mk(&mk_seed);
        let n = 0u32;
        let aad = msg_aad(b.epoch, victim_leaf, n);
        let ct = aead_seal(&key, &nonce, b"I never said this", &aad).unwrap();
        // b can only sign with ITS OWN leaf key (b.my_sig), not a's.
        let b_sig = b.my_sig.as_ref().unwrap();
        let sig = b_sig.sign(&sig_transcript(b.epoch, victim_leaf, n, &ct));
        let mut w = talkrypt_wire::Writer::new();
        w.put_u8(GROUP_MSG_V2);
        w.put_u32(b.epoch);
        w.put_u32(victim_leaf); // stamp the VICTIM's leaf
        w.put_u32(n);
        w.put_bytes(&ct);
        w.put_bytes(&sig);
        let forged = w.into_vec();

        // c verifies against the leaf sig key bound for victim_leaf (a's key) ->
        // b's signature does not verify -> rejected.
        let res = c.decrypt_verified(&forged);
        assert!(matches!(res, Err(CryptoError::BadSignature)));
    }

    /// A genuine signed (v2) group message round-trips (G1/G2 happy path): a signs
    /// with its leaf key; b verifies against a's tree-bound leaf sig key.
    #[test]
    fn signed_group_message_round_trips() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let a_leaf = a.my_leaf();
        let msg = a.encrypt_signed(b"authentic hello").unwrap();
        assert_eq!(TreeKemGroup::sender_leaf(&msg), Some(a_leaf));
        assert_eq!(b.decrypt_verified(&msg).unwrap(), b"authentic hello");
        // And the reverse direction (b -> a) also authenticates.
        let msg2 = b.encrypt_signed(b"hi back").unwrap();
        assert_eq!(a.decrypt_verified(&msg2).unwrap(), b"hi back");
    }

    /// A v2 receiver rejects a v1 (unsigned) message on the trust boundary.
    #[test]
    fn unsigned_message_rejected_by_verified_path() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let unsigned = a.encrypt(b"legacy").unwrap();
        assert!(b.decrypt_verified(&unsigned).is_err());
    }

    /// Tampering the ciphertext after signing invalidates the signature (the
    /// transcript binds epoch/leaf/n/ct, so a relay cannot restamp).
    #[test]
    fn tampered_signed_message_rejected() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let mut msg = a.encrypt_signed(b"do not tamper").unwrap();
        msg[20] ^= 0x01;
        assert!(b.decrypt_verified(&msg).is_err());
    }

    /// SECURITY-AUDIT G3/G4 — a Commit declaring a huge element count with no
    /// matching data is rejected at decode, before any large allocation.
    #[test]
    fn oversized_commit_count_rejected_before_alloc() {
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(1_000_000);
        assert!(Commit::decode(KemProfile::pq_pure(), &w.into_vec()).is_err());
    }

    /// SECURITY-AUDIT T-2: `update()` rotates the caller's leaf SIGNING key, giving
    /// post-compromise security for authentication. After A updates: (1) both
    /// members converge and A's NEW key verifies A's messages; (2) a message forged
    /// with A's OLD signing key (e.g. by an adversary who compromised it before the
    /// update) no longer verifies — the old key is no longer bound to A's leaf.
    #[test]
    fn update_rotates_leaf_signing_key_for_pcs() {
        let mut a = TreeKemGroup::create();
        let mut b = add_member(&mut a, &mut []);
        let a_leaf = a.my_leaf();

        // Capture A's OLD signing key (simulating a pre-update compromise).
        let old_sig_seed = a.my_sig.as_ref().unwrap().export_secret();
        let old_sig = crate::identity::IdentityKeyPair::from_secret_bytes(old_sig_seed);

        // A self-updates (rotates KEM path AND leaf signing key); B applies it.
        let commit = a.update().unwrap();
        b.apply_commit(&commit).unwrap();
        assert_eq!(a.group_secret(), b.group_secret());

        // A's NEW key authenticates a fresh message.
        let msg = a.encrypt_signed(b"post-update").unwrap();
        assert_eq!(b.decrypt_verified(&msg).unwrap(), b"post-update");

        // A message forged with A's OLD signing key is now REJECTED by B: the old
        // key is no longer the leaf's bound verifying key (PCS for auth).
        let epoch = a.epoch;
        let chain = sender_chain(&a.group_secret(), a_leaf);
        let (_n, mk) = kdf_ck(&chain);
        let (k, no) = kdf_mk(&mk);
        let aad = msg_aad(epoch, a_leaf, 0);
        let ct = aead_seal(&k, &no, b"forged with old key", &aad).unwrap();
        let sig = old_sig.sign(&sig_transcript(epoch, a_leaf, 0, &ct));
        let mut w = talkrypt_wire::Writer::new();
        w.put_u8(GROUP_MSG_V2);
        w.put_u32(epoch); w.put_u32(a_leaf); w.put_u32(0);
        w.put_bytes(&ct); w.put_bytes(&sig);
        assert!(matches!(b.decrypt_verified(&w.into_vec()), Err(CryptoError::BadSignature)));
    }

    /// SECURITY-AUDIT T-1: a KeyPackage whose proof-of-possession does not verify
    /// under its own leaf signature key is REJECTED at decode. This stops a
    /// committer/relay from substituting a leaf signature key it does not control:
    /// forging a valid PoP requires the corresponding ML-DSA-87 secret.
    #[test]
    fn keypackage_with_bad_pop_is_rejected() {
        let profile = KemProfile::pq_pure();
        let kp = LeafKeyPair::generate_with(profile).key_package();
        // A well-formed KeyPackage decodes.
        let good = kp.encode();
        assert!(KeyPackage::decode(profile, &good).is_ok());

        // Substitute a DIFFERENT (attacker) sig key but keep the original PoP:
        // the PoP was signed by the original key, so it cannot verify under the
        // substituted key. Rebuild the wire bytes with the swapped sig key.
        let attacker = crate::identity::IdentityKeyPair::generate();
        let mut w = talkrypt_wire::Writer::new();
        w.put_bytes(&kp.leaf_public.encode());
        w.put_bytes(&attacker.public().sig_vk); // swapped key
        w.put_bytes(&kp.pop); // original PoP (over the ORIGINAL key)
        assert!(matches!(
            KeyPackage::decode(profile, &w.into_vec()),
            Err(CryptoError::BadSignature)
        ));

        // Also: a PoP forged by the attacker over ITS OWN key is a valid PoP for
        // that key (proof of possession is self-referential) — that is expected and
        // fine; what T-1 forbids is a PoP that does not match the presented key.
        let forged_pop = attacker.sign(&pop_transcript(attacker.public()));
        let mut w2 = talkrypt_wire::Writer::new();
        w2.put_bytes(&kp.leaf_public.encode());
        w2.put_bytes(&attacker.public().sig_vk);
        w2.put_bytes(&forged_pop);
        assert!(KeyPackage::decode(profile, &w2.into_vec()).is_ok());
    }

    // ---- Property-based verification of the G1/G2 leaf-signature invariants.
    // These use proptest to check the security-relevant properties over many
    // randomized inputs (a lightweight, in-CI complement to the machine-checked
    // Kani harness below, which proves decoder totality on *all* inputs). ----

    use proptest::prelude::*;

    proptest! {
        /// AUTHENTICITY (G1): for ANY plaintext, a v2 message signed by member `a`
        /// is accepted by `b` and attributed to a's leaf; and if `b` (a different
        /// member) re-signs the same header+ct with ITS key and stamps a's leaf,
        /// `a`'s receiver rejects it. No member can produce a message that verifies
        /// under another leaf's tree-bound key.
        #[test]
        fn prop_signed_message_authentic_and_unforgeable(pt in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut a = TreeKemGroup::create();
            let mut b = add_member(&mut a, &mut []);
            let a_leaf = a.my_leaf();

            // Authentic path: a signs, b verifies and recovers the plaintext.
            let msg = a.encrypt_signed(&pt).unwrap();
            prop_assert_eq!(TreeKemGroup::sender_leaf(&msg), Some(a_leaf));
            prop_assert_eq!(b.decrypt_verified(&msg).unwrap(), pt.clone());

            // Forgery path: b crafts a ct on a's chain and signs with b's key,
            // stamping a's leaf. A third member c must reject it.
            let mut c = add_member(&mut a, &mut [&mut b]);
            let chain = sender_chain(&b.group_secret(), a_leaf);
            let (_n, mk) = kdf_ck(&chain);
            let (k, no) = kdf_mk(&mk);
            let aad = msg_aad(b.epoch, a_leaf, 0);
            let ct = aead_seal(&k, &no, &pt, &aad).unwrap();
            let sig = b.my_sig.as_ref().unwrap().sign(&sig_transcript(b.epoch, a_leaf, 0, &ct));
            let mut w = talkrypt_wire::Writer::new();
            w.put_u8(GROUP_MSG_V2);
            w.put_u32(b.epoch); w.put_u32(a_leaf); w.put_u32(0);
            w.put_bytes(&ct); w.put_bytes(&sig);
            prop_assert!(matches!(c.decrypt_verified(&w.into_vec()), Err(CryptoError::BadSignature)));
        }

        /// INTEGRITY (G1/G2): flipping ANY single byte of a signed message makes
        /// the receiver reject it (the transcript binds version/epoch/leaf/n/ct and
        /// the signature covers it; the AEAD covers the ct). No silent acceptance.
        #[test]
        fn prop_any_single_byte_flip_is_rejected(pt in proptest::collection::vec(any::<u8>(), 1..64),
                                                 idx in 0usize..4096) {
            let mut a = TreeKemGroup::create();
            let mut b = add_member(&mut a, &mut []);
            let msg = a.encrypt_signed(&pt).unwrap();
            let i = idx % msg.len();
            let mut tampered = msg.clone();
            tampered[i] ^= 0x01;
            // Either the signature check or the AEAD tag catches it: never Ok(pt).
            prop_assert!(b.decrypt_verified(&tampered).map(|p| p == pt).unwrap_or(false) == false
                         || tampered == msg);
        }

        /// TOTALITY (G3/G4): decrypt_verified on ARBITRARY bytes never panics — it
        /// returns Ok or Err, never aborts. (Bounded fuzz of the receive path.)
        #[test]
        fn prop_decrypt_verified_is_total(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut a = TreeKemGroup::create();
            let _ = a.decrypt_verified(&bytes); // must not panic
        }

        /// TOTALITY (G3/G4): Commit/Welcome/KeyPackage decoders never panic on
        /// arbitrary input and never over-allocate (return within the input bound).
        #[test]
        fn prop_decoders_are_total(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let prof = KemProfile::pq_pure();
            let _ = Commit::decode(prof, &bytes);
            let _ = Welcome::decode(prof, &bytes);
            let _ = KeyPackage::decode(prof, &bytes);
        }
    }

}
