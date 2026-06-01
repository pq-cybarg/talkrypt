//! TreeKEM continuous group key agreement (the cryptographic core of MLS-PQ).
//!
//! A balanced binary tree has one member per leaf. Every node carries a hybrid
//! (X25519 + ML-KEM-1024) key pair *derived deterministically* from a node
//! secret. A member holds the secrets of exactly the nodes on its path to the
//! root; everyone knows all public keys.
//!
//! When a member **updates** (re-keys), it generates a fresh chain of path
//! secrets from its leaf to the root and, for each node on the path, encrypts
//! the new path secret to the *copath sibling* — whose secret every member of
//! that sibling's subtree already holds. Each member decrypts at the level
//! where its path meets the updater's, then KDF-chains up to the same new root
//! secret. This gives the whole group a fresh shared secret in O(log N) and
//! **post-compromise security**: a compromised member heals the group by
//! updating.
//!
//! Scope: this is the TreeKEM key-agreement core with update operations. The
//! Welcome/Add/Remove flows and RFC 9420 wire framing are the remaining MLS
//! work (see `docs/plans/0002-mls-pq.md`). Groups also ship today via the
//! simpler sender-key suite in [`crate::group`].

use std::collections::HashMap;

use hkdf::Hkdf;
use rand::RngCore;

use crate::aead::{open as aead_open, seal as aead_seal};
use crate::error::{CryptoError, Result};
use crate::hash::Hash;
use crate::hybrid::{RatchetPublic, RatchetSecret};
use crate::kdf::kdf_mk;

type Secret = [u8; 32];

/// A balanced binary tree over `n` leaves (members).
#[derive(Clone, Debug)]
pub struct Tree {
    n_leaves: usize,
    parent: Vec<Option<usize>>,
    children: Vec<Option<(usize, usize)>>,
    leaf_node: Vec<usize>,
    root: usize,
}

impl Tree {
    /// Build a balanced tree for `n` members (`n >= 1`).
    pub fn new(n: usize) -> Tree {
        assert!(n >= 1, "group needs at least one member");
        let mut b = Builder {
            parent: Vec::new(),
            children: Vec::new(),
            leaf_node: vec![usize::MAX; n],
        };
        let leaves: Vec<usize> = (0..n).collect();
        let root = b.build(&leaves);
        Tree {
            n_leaves: n,
            parent: b.parent,
            children: b.children,
            leaf_node: b.leaf_node,
            root,
        }
    }

    pub fn member_count(&self) -> usize {
        self.n_leaves
    }

    /// The root node index.
    pub fn root(&self) -> usize {
        self.root
    }

    fn sibling(&self, node: usize) -> Option<usize> {
        let p = self.parent[node]?;
        let (l, r) = self.children[p].expect("internal node has children");
        Some(if l == node { r } else { l })
    }

    /// Path of node indices from a member's leaf up to (and including) the root.
    fn path_to_root(&self, leaf: usize) -> Vec<usize> {
        let mut path = vec![self.leaf_node[leaf]];
        let mut cur = self.leaf_node[leaf];
        while let Some(p) = self.parent[cur] {
            path.push(p);
            cur = p;
        }
        path
    }

    /// Is `node` an ancestor of (or equal to) the given member's leaf?
    fn covers(&self, node: usize, leaf: usize) -> bool {
        let mut cur = self.leaf_node[leaf];
        loop {
            if cur == node {
                return true;
            }
            match self.parent[cur] {
                Some(p) => cur = p,
                None => return false,
            }
        }
    }
}

struct Builder {
    parent: Vec<Option<usize>>,
    children: Vec<Option<(usize, usize)>>,
    leaf_node: Vec<usize>,
}

impl Builder {
    fn new_node(&mut self) -> usize {
        let id = self.parent.len();
        self.parent.push(None);
        self.children.push(None);
        id
    }

    fn build(&mut self, leaves: &[usize]) -> usize {
        if leaves.len() == 1 {
            let id = self.new_node();
            self.leaf_node[leaves[0]] = id;
            return id;
        }
        let mid = leaves.len().div_ceil(2);
        let l = self.build(&leaves[..mid]);
        let r = self.build(&leaves[mid..]);
        let id = self.new_node();
        self.children[id] = Some((l, r));
        self.parent[l] = Some(id);
        self.parent[r] = Some(id);
        id
    }
}

/// The public state shared by every member: all node public keys.
#[derive(Clone, Default)]
pub struct PublicTree {
    publics: HashMap<usize, RatchetPublic>,
}

/// One member's private view: the secrets of the nodes on its path.
#[derive(Clone)]
pub struct MemberState {
    pub leaf: usize,
    secrets: HashMap<usize, Secret>,
}

/// An update broadcast: new public keys for the updater's path, and the new
/// path secret for each path node encrypted to that node's copath sibling.
#[derive(Clone)]
pub struct UpdatePath {
    updater_leaf: usize,
    publics: Vec<(usize, RatchetPublic)>,
    encrypted: Vec<(usize, Vec<u8>)>, // (path node, sealed path secret for copath)
}

/// Initialize a group: generate every node's secret, returning the public tree
/// plus each member's private path view. Models the post-Welcome state; real
/// MLS distributes these via encrypted Welcome messages.
pub fn init_group(tree: &Tree) -> (PublicTree, Vec<MemberState>) {
    let mut rng = rand::rngs::OsRng;
    let total = tree.parent.len();
    let mut node_secret = vec![[0u8; 32]; total];
    let mut publics = HashMap::new();
    for (node, secret) in node_secret.iter_mut().enumerate() {
        rng.fill_bytes(secret);
        let (_, public) = RatchetSecret::derive_deterministic(secret);
        publics.insert(node, public);
    }
    let members = (0..tree.n_leaves)
        .map(|leaf| {
            let secrets = tree
                .path_to_root(leaf)
                .into_iter()
                .map(|n| (n, node_secret[n]))
                .collect();
            MemberState { leaf, secrets }
        })
        .collect();
    (PublicTree { publics }, members)
}

/// Perform an update from `member`. Returns the broadcast `UpdatePath` and the
/// new group (commit) secret; mutates `member` and `public` to the new keys.
pub fn update(
    tree: &Tree,
    public: &mut PublicTree,
    member: &mut MemberState,
) -> Result<(UpdatePath, Secret)> {
    let path = tree.path_to_root(member.leaf);

    // Fresh path-secret chain: leaf secret random, each parent derived from it.
    let mut path_secrets = vec![[0u8; 32]; path.len()];
    rand::rngs::OsRng.fill_bytes(&mut path_secrets[0]);
    for i in 1..path.len() {
        path_secrets[i] = derive_parent_secret(&path_secrets[i - 1]);
    }

    // New public keys for every node on the path.
    let mut publics = Vec::with_capacity(path.len());
    for (i, &node) in path.iter().enumerate() {
        let (_, pubk) = RatchetSecret::derive_deterministic(&path_secrets[i]);
        public.publics.insert(node, pubk.clone());
        member.secrets.insert(node, path_secrets[i]);
        publics.push((node, pubk));
    }

    // Encrypt each ancestor's new path secret to its copath sibling.
    let mut encrypted = Vec::new();
    for i in 1..path.len() {
        let copath = tree
            .sibling(path[i - 1])
            .expect("non-root path node has a sibling");
        let copath_pub = public
            .publics
            .get(&copath)
            .ok_or(CryptoError::Malformed("missing copath public"))?;
        let blob = seal_secret(copath_pub, &path_secrets[i])?;
        encrypted.push((path[i], blob));
    }

    let commit = derive_commit_secret(&path_secrets[path.len() - 1]);
    Ok((
        UpdatePath {
            updater_leaf: member.leaf,
            publics,
            encrypted,
        },
        commit,
    ))
}

/// Apply an update from another member. Returns the new group (commit) secret,
/// which must equal the updater's.
pub fn apply_update(
    tree: &Tree,
    public: &mut PublicTree,
    member: &mut MemberState,
    update: &UpdatePath,
) -> Result<Secret> {
    // Adopt all new public keys on the updater's path.
    for (node, pubk) in &update.publics {
        public.publics.insert(*node, pubk.clone());
    }

    let updater_path = tree.path_to_root(update.updater_leaf);

    // Find the level where our path meets the updater's: the lowest ancestor
    // of the updater whose copath sibling covers us.
    for i in 1..updater_path.len() {
        let copath = tree.sibling(updater_path[i - 1]).expect("has sibling");
        if tree.covers(copath, member.leaf) {
            // We hold `copath`'s secret -> reconstruct its key -> decapsulate.
            let copath_secret = member
                .secrets
                .get(&copath)
                .ok_or(CryptoError::Malformed("missing held copath secret"))?;
            let (rsecret, _) = RatchetSecret::derive_deterministic(copath_secret);
            let blob = update
                .encrypted
                .iter()
                .find(|(node, _)| *node == updater_path[i])
                .map(|(_, b)| b)
                .ok_or(CryptoError::Malformed("missing encrypted path secret"))?;
            let mut ps = open_secret(&rsecret, blob)?;

            // Store this node's secret, then chain up to the root.
            member.secrets.insert(updater_path[i], ps);
            for &node in &updater_path[i + 1..] {
                ps = derive_parent_secret(&ps);
                member.secrets.insert(node, ps);
            }
            return Ok(derive_commit_secret(&ps));
        }
    }
    Err(CryptoError::Malformed("no common ancestor with updater"))
}

fn derive_parent_secret(child: &Secret) -> Secret {
    expand(child, b"talkrypt-treekem-parent")
}

fn derive_commit_secret(root: &Secret) -> Secret {
    expand(root, b"talkrypt-treekem-commit")
}

fn expand(secret: &Secret, label: &[u8]) -> Secret {
    let hk = Hkdf::<Hash>::new(None, secret);
    let mut out = [0u8; 32];
    hk.expand(label, &mut out).expect("hkdf expand");
    out
}

/// Encrypt a 32-byte secret to a public key (KEM + AEAD).
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
    let mut out = [0u8; 32];
    if pt.len() != 32 {
        return Err(CryptoError::Malformed("treekem path secret length"));
    }
    out.copy_from_slice(&pt);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_math_is_consistent() {
        for n in 1..=17 {
            let tree = Tree::new(n);
            // Every leaf reaches the root; sibling-of-sibling is identity.
            for leaf in 0..n {
                let path = tree.path_to_root(leaf);
                assert_eq!(*path.last().unwrap(), tree.root, "n={n} leaf={leaf}");
                assert_eq!(path[0], tree.leaf_node[leaf]);
                for &node in &path {
                    if let Some(sib) = tree.sibling(node) {
                        assert_eq!(tree.sibling(sib), Some(node));
                    }
                }
            }
        }
    }

    /// The heart of CGKA: after any member updates, every member derives the
    /// SAME new group secret.
    fn check_update_converges(n: usize, updater: usize) {
        let tree = Tree::new(n);
        let (mut public, mut members) = init_group(&tree);

        // Updater re-keys.
        let (update_path, committed) = {
            let m = &mut members[updater];
            super::update(&tree, &mut public, m).unwrap()
        };

        // Every other member applies and must reach the same secret.
        for leaf in 0..n {
            if leaf == updater {
                continue;
            }
            let mut m = members[leaf].clone();
            let got = apply_update(&tree, &mut public.clone(), &mut m, &update_path).unwrap();
            assert_eq!(got, committed, "n={n} updater={updater} member={leaf}");
        }
    }

    #[test]
    fn update_converges_for_many_sizes() {
        for n in 2..=8 {
            for updater in 0..n {
                check_update_converges(n, updater);
            }
        }
    }

    #[test]
    fn post_compromise_secret_changes_each_update() {
        let tree = Tree::new(5);
        let (mut public, mut members) = init_group(&tree);
        let (_u1, c1) = update(&tree, &mut public, &mut members[0]).unwrap();
        let (_u2, c2) = update(&tree, &mut public, &mut members[1]).unwrap();
        // Fresh randomness each update -> the group secret heals/rotates.
        assert_ne!(c1, c2);
    }

    #[test]
    fn two_member_group_agrees() {
        let tree = Tree::new(2);
        let (mut public, mut members) = init_group(&tree);
        let (up, c0) = update(&tree, &mut public, &mut members[0]).unwrap();
        let mut m1 = members[1].clone();
        let c1 = apply_update(&tree, &mut public, &mut m1, &up).unwrap();
        assert_eq!(c0, c1);
    }
}
