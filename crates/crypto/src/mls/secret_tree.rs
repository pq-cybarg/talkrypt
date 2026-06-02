//! RFC 9420 (MLS) secret tree (§9) for ciphersuite 1 (AES-128-GCM): derives
//! per-leaf, per-generation handshake/application keys+nonces from the epoch's
//! `encryption_secret`, plus the sender-data key/nonce. Built on the validated
//! tree math and `ExpandWithLabel`, and checked against the working group's
//! official `secret-tree` test vectors.

use super::schedule::expand_with_label;
use super::treemath::{left, level, right, root};

/// AEAD key length for AES-128-GCM (`AEAD.Nk`).
pub const NK: u16 = 16;
/// AEAD nonce length (`AEAD.Nn`).
pub const NN: u16 = 12;
/// KDF hash length (`KDF.Nh`).
pub const NH: u16 = 32;

/// `DeriveTreeSecret(secret, label, generation, length)` =
/// `ExpandWithLabel(secret, label, generation_be32, length)`.
fn derive_tree_secret(secret: &[u8], label: &str, generation: u32, length: u16) -> Vec<u8> {
    expand_with_label(secret, label, &generation.to_be_bytes(), length)
}

/// Descend the secret tree from the epoch `encryption_secret` (the root) to a
/// leaf's secret. In the array layout, left-subtree node indices are below the
/// parent and right-subtree indices above, so the turn is a simple comparison.
pub fn leaf_secret(encryption_secret: &[u8], n_leaves: u32, leaf: u32) -> Vec<u8> {
    let target = 2 * leaf; // LeafIndex -> NodeIndex
    let mut node = root(n_leaves);
    let mut secret = encryption_secret.to_vec();
    while level(node) > 0 {
        if target < node {
            secret = expand_with_label(&secret, "tree", b"left", NH);
            node = left(node);
        } else {
            secret = expand_with_label(&secret, "tree", b"right", NH);
            node = right(node);
        }
    }
    secret
}

/// An AEAD key + nonce.
pub struct KeyNonce {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
}

/// The `which` ("handshake" or "application") ratchet key+nonce at `generation`
/// for a leaf, ratcheting forward from generation 0.
pub fn ratchet_key(leaf_secret: &[u8], which: &str, generation: u32) -> KeyNonce {
    let mut ratchet = expand_with_label(leaf_secret, which, &[], NH);
    for j in 0..generation {
        ratchet = derive_tree_secret(&ratchet, "secret", j, NH);
    }
    KeyNonce {
        key: derive_tree_secret(&ratchet, "key", generation, NK),
        nonce: derive_tree_secret(&ratchet, "nonce", generation, NN),
    }
}

/// Sender-data key+nonce, derived from `sender_data_secret` and a sample of the
/// message ciphertext (`ciphertext[0..min(len, Nh)]`).
pub fn sender_data_key_nonce(sender_data_secret: &[u8], ciphertext: &[u8]) -> KeyNonce {
    let sample = &ciphertext[..(NH as usize).min(ciphertext.len())];
    KeyNonce {
        key: expand_with_label(sender_data_secret, "key", sample, NK),
        nonce: expand_with_label(sender_data_secret, "nonce", sample, NN),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Official secret-tree.json, cipher_suite 1 (a single-leaf tree).
    #[test]
    fn leaf_ratchet_keys_match_rfc9420_vector() {
        let enc = hex("d69fcc35969e94680461974bd26c7cda7594cbf45985c4bf668c3b3118b765ab");
        let leaf = leaf_secret(&enc, 1, 0); // 1 leaf -> root is the leaf

        let hs = ratchet_key(&leaf, "handshake", 0);
        assert_eq!(hs.key, hex("a2d6b8a9255478e9b79a076872ae3563"));
        assert_eq!(hs.nonce, hex("8e8fc08a4eb5189b7b558527"));

        let app = ratchet_key(&leaf, "application", 0);
        assert_eq!(app.key, hex("442e691710646617a21e41482d868a4e"));
        assert_eq!(app.nonce, hex("c76e37884536a9ce33fb3070"));
    }

    #[test]
    fn sender_data_key_nonce_matches_rfc9420_vector() {
        let sds = hex("95684b805e1bbd9c71d1abaf8a1930c12112b9a06c12db937970be5bbb916573");
        let ct = hex("156f2eb3fa482cff20e3a090c267ce6481d4a0976aee2adb921d70ae8a04a6494339462ac049f185e7184d8245270e54e68b72bd5df66800367c50e423cafec0260ac4dc743c24cabfc6060fc5");
        let kn = sender_data_key_nonce(&sds, &ct);
        assert_eq!(kn.key, hex("92667d9c889a6b768c157538c0a79fed"));
        assert_eq!(kn.nonce, hex("362785b1cc8bc775fcc216e7"));
    }
}
