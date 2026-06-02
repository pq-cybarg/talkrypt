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

use crate::aead::{open as aead_open, seal as aead_seal};
use crate::error::{CryptoError, Result};
use crate::hybrid::{RatchetPublic, RatchetSecret};
use crate::kdf::{kdf_ck, kdf_mk};
use crate::ratchet::MAX_SKIP;

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

/// A joiner's pre-published leaf public key.
#[derive(Clone)]
pub struct KeyPackage {
    pub leaf_public: RatchetPublic,
}

/// A joiner's private leaf key, kept until they process their Welcome.
pub struct LeafKeyPair {
    secret: Secret,
}

impl LeafKeyPair {
    /// Generate a fresh leaf key for joining a group. Share `key_package()`.
    pub fn generate() -> LeafKeyPair {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        LeafKeyPair { secret }
    }
    pub fn key_package(&self) -> KeyPackage {
        let (_, leaf_public) = RatchetSecret::derive_deterministic(&self.secret);
        KeyPackage { leaf_public }
    }
}

/// A membership change carried by a commit.
#[derive(Clone, PartialEq, Eq)]
enum Proposal {
    Add {
        leaf: u32,
        leaf_public: RatchetPublic,
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
}

/// Everything a joiner needs to enter the group at the post-commit epoch.
#[derive(Clone, PartialEq, Eq)]
pub struct Welcome {
    capacity: u32,
    public: Vec<(Node, RatchetPublic)>,
    occupied: Vec<bool>,
    epoch: u32,
    your_leaf: u32,
    commit: Commit,
}

// ---- wire serialization (talkrypt-compact; not RFC 9420 framing) ----

fn put_node(w: &mut talkrypt_wire::Writer, n: &Node) {
    w.put_u32(n.lo);
    w.put_u32(n.span);
}
fn get_node(r: &mut talkrypt_wire::Reader) -> Result<Node> {
    Ok(Node {
        lo: r.get_u32()?,
        span: r.get_u32()?,
    })
}

impl KeyPackage {
    pub fn encode(&self) -> Vec<u8> {
        self.leaf_public.encode()
    }
    pub fn decode(bytes: &[u8]) -> Result<KeyPackage> {
        Ok(KeyPackage {
            leaf_public: RatchetPublic::decode(bytes)?,
        })
    }
}

impl Proposal {
    fn put(&self, w: &mut talkrypt_wire::Writer) {
        match self {
            Proposal::Add { leaf, leaf_public } => {
                w.put_u8(0);
                w.put_u32(*leaf);
                w.put_bytes(&leaf_public.encode());
            }
            Proposal::Remove { leaf } => {
                w.put_u8(1);
                w.put_u32(*leaf);
            }
        }
    }
    fn get(r: &mut talkrypt_wire::Reader) -> Result<Proposal> {
        match r.get_u8()? {
            0 => Ok(Proposal::Add {
                leaf: r.get_u32()?,
                leaf_public: RatchetPublic::decode(r.get_bytes()?)?,
            }),
            1 => Ok(Proposal::Remove { leaf: r.get_u32()? }),
            _ => Err(CryptoError::Malformed("bad proposal tag")),
        }
    }
}

const MAX_TREE_ITEMS: u32 = 1 << 20;

fn get_count(r: &mut talkrypt_wire::Reader) -> Result<u32> {
    let n = r.get_u32()?;
    if n > MAX_TREE_ITEMS {
        return Err(CryptoError::Malformed("treekem count too large"));
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
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Commit> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let c = Self::read(&mut r)?;
        r.finish()?;
        Ok(c)
    }

    fn read(r: &mut talkrypt_wire::Reader) -> Result<Commit> {
        let np = get_count(r)?;
        let mut proposals = Vec::with_capacity(np as usize);
        for _ in 0..np {
            proposals.push(Proposal::get(r)?);
        }
        let nu = get_count(r)?;
        let mut pub_updates = Vec::with_capacity(nu as usize);
        for _ in 0..nu {
            let node = get_node(r)?;
            let p = RatchetPublic::decode(r.get_bytes()?)?;
            pub_updates.push((node, p));
        }
        let npath = get_count(r)?;
        let mut path = Vec::with_capacity(npath as usize);
        for _ in 0..npath {
            path.push(get_node(r)?);
        }
        let nc = get_count(r)?;
        let mut ciphertexts = Vec::with_capacity(nc as usize);
        for _ in 0..nc {
            let a = get_node(r)?;
            let b = get_node(r)?;
            let blob = r.get_vec()?;
            ciphertexts.push((a, b, blob));
        }
        let new_capacity = r.get_u32()?;
        Ok(Commit {
            proposals,
            pub_updates,
            path,
            ciphertexts,
            new_capacity,
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
        w.put_bytes(&self.commit.encode());
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<Welcome> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let capacity = r.get_u32()?;
        let np = get_count(&mut r)?;
        let mut public = Vec::with_capacity(np as usize);
        for _ in 0..np {
            let node = get_node(&mut r)?;
            let p = RatchetPublic::decode(r.get_bytes()?)?;
            public.push((node, p));
        }
        let no = get_count(&mut r)?;
        let mut occupied = Vec::with_capacity(no as usize);
        for _ in 0..no {
            occupied.push(r.get_u8()? != 0);
        }
        let epoch = r.get_u32()?;
        let your_leaf = r.get_u32()?;
        let commit = Commit::decode(r.get_bytes()?)?;
        r.finish()?;
        Ok(Welcome {
            capacity,
            public,
            occupied,
            epoch,
            your_leaf,
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
}

impl TreeKemGroup {
    /// Create a new group as its founder (leaf 0), capacity 2.
    pub fn create() -> TreeKemGroup {
        let capacity = 2;
        let mut leaf_secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut leaf_secret);

        let mut g = TreeKemGroup {
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
        };
        g.occupied[0] = true;
        // Set the founder's whole path (leaf -> root) from a fresh secret chain.
        let path = g.path_to_root(0);
        let mut ps = leaf_secret;
        for (i, node) in path.iter().enumerate() {
            if i > 0 {
                ps = derive_parent_secret(&ps);
            }
            let (_, pubk) = RatchetSecret::derive_deterministic(&ps);
            g.public.insert(*node, pubk);
            g.secrets.insert(*node, ps);
        }
        let root_secret = *g.secrets.get(&root_of(capacity)).expect("root secret");
        g.epoch_secret = derive_commit_secret(&root_secret);
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
        }];
        self.apply_proposals(&proposals);
        let commit = self.rekey_path(proposals)?;

        let welcome = Welcome {
            capacity: self.capacity,
            public: self.public.iter().map(|(n, p)| (*n, p.clone())).collect(),
            occupied: self.occupied.clone(),
            epoch: self.epoch,
            your_leaf: leaf,
            commit: commit.clone(),
        };
        Ok((leaf, commit, welcome))
    }

    /// Remove a member. The removed member cannot derive the new group secret.
    pub fn remove(&mut self, leaf: u32) -> Result<Commit> {
        let proposals = vec![Proposal::Remove { leaf }];
        self.apply_proposals(&proposals);
        self.rekey_path(proposals)
    }

    fn apply_proposals(&mut self, proposals: &[Proposal]) {
        for p in proposals {
            match p {
                Proposal::Add { leaf, leaf_public } => {
                    self.occupied[*leaf as usize] = true;
                    self.public.insert(Node::leaf(*leaf), leaf_public.clone());
                    // Blank the new leaf's ancestors so the committer re-keys.
                    self.blank_path_above(*leaf);
                }
                Proposal::Remove { leaf } => {
                    self.occupied[*leaf as usize] = false;
                    self.secrets.remove(&Node::leaf(*leaf));
                    self.public.remove(&Node::leaf(*leaf));
                    self.blank_path_above(*leaf);
                }
            }
        }
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
            let (_, pubk) = RatchetSecret::derive_deterministic(&path_secrets[i]);
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
        })
    }

    /// Apply a commit produced by another member; advances to its epoch.
    pub fn apply_commit(&mut self, commit: &Commit) -> Result<()> {
        if commit.new_capacity > self.capacity {
            self.capacity = commit.new_capacity;
            self.occupied.resize(self.capacity as usize, false);
        }
        self.apply_proposals(&commit.proposals);
        let secret = self.process_update_path(commit)?;
        self.epoch += 1;
        self.epoch_secret = secret;
        self.reset_epoch();
        Ok(())
    }

    /// Join a group from a Welcome message using the matching leaf key.
    pub fn join_with_welcome(keypair: LeafKeyPair, welcome: &Welcome) -> Result<TreeKemGroup> {
        let mut g = TreeKemGroup {
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
        };
        // We hold only our own leaf secret to start.
        g.secrets
            .insert(Node::leaf(welcome.your_leaf), keypair.secret);
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
                    let (rsecret, _) = RatchetSecret::derive_deterministic(&secret);
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

    /// Read the sender's leaf index from a group message without decrypting,
    /// for attribution against a roster. `None` if the framing is malformed.
    pub fn sender_leaf(message: &[u8]) -> Option<u32> {
        let mut r = talkrypt_wire::Reader::new(message);
        let _epoch = r.get_u32().ok()?;
        r.get_u32().ok()
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let (next, mk_seed) = kdf_ck(&self.send_chain);
        let (key, nonce) = kdf_mk(&mk_seed);
        let n = self.send_n;
        let aad = msg_aad(self.epoch, self.me, n);
        let ct = aead_seal(&key, &nonce, plaintext, &aad)?;
        self.send_chain = next;
        self.send_n += 1;
        let mut w = talkrypt_wire::Writer::new();
        w.put_u32(self.epoch);
        w.put_u32(self.me);
        w.put_u32(n);
        w.put_bytes(&ct);
        Ok(w.into_vec())
    }

    pub fn decrypt(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut r = talkrypt_wire::Reader::new(message);
        let epoch = r.get_u32()?;
        let leaf = r.get_u32()?;
        let n = r.get_u32()?;
        let ct = r.get_vec()?;
        r.finish()?;
        if epoch != self.epoch {
            return Err(CryptoError::DecryptionFailed);
        }
        let aad = msg_aad(epoch, leaf, n);
        let epoch_secret = self.epoch_secret;
        let recv = self.recvs.entry(leaf).or_insert_with(|| RecvChain {
            chain: sender_chain(&epoch_secret, leaf),
            n: 0,
            skipped: BTreeMap::new(),
        });

        if let Some(seed) = recv.skipped.remove(&n) {
            let (key, nonce) = kdf_mk(&seed);
            return aead_open(&key, &nonce, &ct, &aad);
        }
        if n < recv.n {
            return Err(CryptoError::DecryptionFailed);
        }
        if (n - recv.n) as usize > MAX_SKIP {
            return Err(CryptoError::TooManySkipped(MAX_SKIP));
        }
        while recv.n < n {
            let (nx, seed) = kdf_ck(&recv.chain);
            recv.skipped.insert(recv.n, seed);
            recv.chain = nx;
            recv.n += 1;
        }
        let (nx, mk_seed) = kdf_ck(&recv.chain);
        let (key, nonce) = kdf_mk(&mk_seed);
        let pt = aead_open(&key, &nonce, &ct, &aad)?;
        recv.chain = nx;
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

    /// Add a fresh member to an existing group; returns the joiner's group.
    fn add_member(
        committer: &mut TreeKemGroup,
        followers: &mut [&mut TreeKemGroup],
    ) -> TreeKemGroup {
        let kp = LeafKeyPair::generate();
        let (_leaf, commit, welcome) = committer.add(&kp.key_package()).unwrap();
        for f in followers.iter_mut() {
            f.apply_commit(&commit).unwrap();
        }
        TreeKemGroup::join_with_welcome(kp, &welcome).unwrap()
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

        let commit2 = Commit::decode(&commit.encode()).unwrap();
        assert!(commit == commit2);
        let welcome2 = Welcome::decode(&welcome.encode()).unwrap();
        assert!(welcome == welcome2);
        let kp2 = KeyPackage::decode(&kp.key_package().encode()).unwrap();
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
}
