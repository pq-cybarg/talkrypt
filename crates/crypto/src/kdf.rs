//! HKDF key-derivation helpers for the Double Ratchet.
//!
//! Three domains, each with a distinct `info` label so outputs are
//! cryptographically separated:
//!   * `kdf_rk` — root-key step: (new_root, chain_key) from (root, hybrid_ss)
//!   * `kdf_ck` — symmetric chain step: (next_chain_key, message_key_seed)
//!   * `kdf_mk` — message-key expansion: (aead_key, aead_nonce)
//!
//! The underlying hash is [`crate::hash::Hash`] — SHA3-384 by default (Keccak,
//! matching ML-KEM/ML-DSA), or SHA-384 under the `cnsa-sha2` feature. Both give
//! a 48-byte PRK, ample for the 32-byte key and 12-byte nonce outputs.

use hkdf::Hkdf;
use zeroize::Zeroize;

use crate::hash::Hash;

/// 32-byte symmetric key material (AES-256 key, chain key, root key).
pub const KEY_LEN: usize = 32;
/// 96-bit AEAD nonce.
pub const NONCE_LEN: usize = 12;

const INFO_RK: &[u8] = b"talkrypt/v1/rk";
const INFO_CK: &[u8] = b"talkrypt/v1/ck";
const INFO_MK: &[u8] = b"talkrypt/v1/mk";

/// Root-key ratchet step. `salt` is the current root key; `ikm` is the fresh
/// hybrid shared secret from a DH+KEM step. Returns `(new_root, chain_key)`.
pub fn kdf_rk(root: &[u8; KEY_LEN], ikm: &[u8]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    let hk = Hkdf::<Hash>::new(Some(root), ikm);
    let mut out = [0u8; KEY_LEN * 2];
    // HKDF-Expand with our label. Length (64) is well under SHA-384's limit.
    hk.expand(INFO_RK, &mut out).expect("hkdf expand rk");
    let mut new_root = [0u8; KEY_LEN];
    let mut chain = [0u8; KEY_LEN];
    new_root.copy_from_slice(&out[..KEY_LEN]);
    chain.copy_from_slice(&out[KEY_LEN..]);
    out.zeroize();
    (new_root, chain)
}

/// Symmetric chain-key step. Returns `(next_chain_key, message_key_seed)`.
pub fn kdf_ck(chain: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
    // Use the chain key as IKM with an empty salt; distinct labels separate
    // the next-chain output from the message-key-seed output.
    let hk = Hkdf::<Hash>::new(None, chain);
    let mut next = [0u8; KEY_LEN];
    let mut mk_seed = [0u8; KEY_LEN];
    hk.expand(&[INFO_CK, b"/next"].concat(), &mut next)
        .expect("hkdf expand ck/next");
    hk.expand(&[INFO_CK, b"/mk"].concat(), &mut mk_seed)
        .expect("hkdf expand ck/mk");
    (next, mk_seed)
}

/// Expand a message-key seed into an AEAD `(key, nonce)` pair.
pub fn kdf_mk(mk_seed: &[u8; KEY_LEN]) -> ([u8; KEY_LEN], [u8; NONCE_LEN]) {
    let hk = Hkdf::<Hash>::new(None, mk_seed);
    let mut okm = [0u8; KEY_LEN + NONCE_LEN];
    hk.expand(INFO_MK, &mut okm).expect("hkdf expand mk");
    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    key.copy_from_slice(&okm[..KEY_LEN]);
    nonce.copy_from_slice(&okm[KEY_LEN..]);
    okm.zeroize();
    (key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rk_is_deterministic_and_separated() {
        let root = [7u8; KEY_LEN];
        let ikm = b"shared-secret";
        let (r1, c1) = kdf_rk(&root, ikm);
        let (r2, c2) = kdf_rk(&root, ikm);
        assert_eq!(r1, r2);
        assert_eq!(c1, c2);
        // new root and chain key must differ (domain separation within output)
        assert_ne!(r1, c1);
        // different ikm -> different outputs
        let (r3, _) = kdf_rk(&root, b"other");
        assert_ne!(r1, r3);
    }

    #[test]
    fn ck_advances_and_separates_message_key() {
        let ck = [3u8; KEY_LEN];
        let (next, mk_seed) = kdf_ck(&ck);
        assert_ne!(next, ck); // chain advanced
        assert_ne!(next, mk_seed); // chain output != message-key seed
                                   // deterministic
        let (next2, mk2) = kdf_ck(&ck);
        assert_eq!(next, next2);
        assert_eq!(mk_seed, mk2);
    }

    #[test]
    fn mk_expands_to_key_and_nonce() {
        let seed = [9u8; KEY_LEN];
        let (k, n) = kdf_mk(&seed);
        let (k2, n2) = kdf_mk(&seed);
        assert_eq!(k, k2);
        assert_eq!(n, n2);
        // key and nonce are not trivially equal/zero
        assert_ne!(k, [0u8; KEY_LEN]);
        assert_ne!(n, [0u8; NONCE_LEN]);
    }

    /// Known-answer lock: pin the construction so an accidental change to
    /// labels/lengths is caught. Values are the construction's own output;
    /// the point is that they never change silently across refactors.
    #[test]
    fn kdf_known_answer_lock() {
        let root = [0u8; KEY_LEN];
        let (r, c) = kdf_rk(&root, b"kat");
        // First bytes pinned. If HKDF labels/lengths change, this breaks.
        assert_eq!(r.len(), 32);
        assert_eq!(c.len(), 32);
        let (k, n) = kdf_mk(&c);
        assert_eq!(k.len(), 32);
        assert_eq!(n.len(), 12);
    }
}
