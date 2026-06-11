//! Encrypted **scheme beacons**.
//!
//! A beacon advertises which crypto scheme a chat uses. Per the project rule,
//! **a beacon is never transmitted in cleartext** — it is always post-quantum +
//! AES-256-GCM protected:
//!
//!   * [`seal_broadcast`] seals under a key derived from the chat root (itself
//!     established from the invite-token PSK and, in session, ML-KEM). AES-256
//!     under a 256-bit key is quantum-resistant, so this meets the PQ + AES
//!     requirement with no asymmetric step; only descriptor holders can open
//!     it, so a relay that stores the blob (server advertisement) learns
//!     nothing — it holds opaque ciphertext.
//!   * [`seal_to_recipient`] seals to one recipient's ML-KEM-1024 public via the
//!     PQ HPKE (`mls::hpke`) — ML-KEM provides the post-quantum KEM.
//!
//! The sender chooses the **granularity** ([`BeaconBody`]): a bare fingerprint
//! (the receiver must already hold a matching registered scheme), or the full
//! definition (adoptable by the receiver only after *explicit* confirmation — a
//! sender must never silently dictate a peer's crypto). Matching/adoption is
//! decided by the caller against a [`crate::suite::SuiteRegistry`]; this module
//! exposes [`BeaconBody::fingerprint`] / [`BeaconBody::is_full`] for that.

use rand::rngs::OsRng;
use rand::RngCore;

use crate::aead::{open as aead_open, seal as aead_seal};
use crate::error::{CryptoError, Result};
use crate::kdf::{mac_kdf, KEY_LEN};
use crate::mls::hpke::{encrypt_with_label, HpkeKeyPair};
use crate::suite::{scheme_hash, SCHEME_HASH_LEN};

const BEACON_AAD: &[u8] = b"talkrypt/v1/beacon";
const BEACON_KEY_LABEL: &[u8] = b"talkrypt/v1/beacon-key";
const BEACON_HPKE_LABEL: &str = "talkrypt-beacon";
const NONCE_LEN: usize = 12;

/// The advertised scheme, at the granularity the sender chose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BeaconBody {
    /// Hash-only: just the scheme fingerprint. The receiver must already hold a
    /// matching registered scheme; nothing is adoptable from this.
    Fingerprint([u8; SCHEME_HASH_LEN]),
    /// Full definition: suite id + opaque params. Adoptable only after explicit
    /// receiver confirmation.
    Full { suite_id: String, params: Vec<u8> },
}

impl BeaconBody {
    /// The scheme fingerprint this beacon refers to (computed for `Full`), used
    /// to match against a local registry via `get_by_scheme_hash`.
    pub fn fingerprint(&self) -> [u8; SCHEME_HASH_LEN] {
        match self {
            BeaconBody::Fingerprint(h) => *h,
            BeaconBody::Full { suite_id, params } => scheme_hash(suite_id, params),
        }
    }

    /// Whether this beacon carries a full, potentially-adoptable definition.
    pub fn is_full(&self) -> bool {
        matches!(self, BeaconBody::Full { .. })
    }

    fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        match self {
            BeaconBody::Fingerprint(h) => {
                w.put_u8(0);
                w.put_bytes(h);
            }
            BeaconBody::Full { suite_id, params } => {
                w.put_u8(1);
                w.put_bytes(suite_id.as_bytes());
                w.put_bytes(params);
            }
        }
        w.into_vec()
    }

    fn decode(bytes: &[u8]) -> Result<BeaconBody> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let body = match r.get_u8()? {
            0 => {
                let h = r.get_bytes()?;
                if h.len() != SCHEME_HASH_LEN {
                    return Err(CryptoError::Malformed("beacon fingerprint length"));
                }
                let mut out = [0u8; SCHEME_HASH_LEN];
                out.copy_from_slice(h);
                BeaconBody::Fingerprint(out)
            }
            1 => {
                let id = String::from_utf8(r.get_bytes()?.to_vec())
                    .map_err(|_| CryptoError::Malformed("beacon suite id utf-8"))?;
                let params = r.get_vec()?;
                BeaconBody::Full {
                    suite_id: id,
                    params,
                }
            }
            _ => return Err(CryptoError::Malformed("beacon body tag")),
        };
        r.finish()?;
        Ok(body)
    }
}

/// Fuzz hook (SECURITY-AUDIT R-6): drive the crate-private [`BeaconBody`] wire
/// decoder over arbitrary bytes (this is the always-encrypted scheme-beacon
/// parsing path). Decoding must never panic; a successful decode must round-trip
/// (`decode(encode(b)) == b`). Gated behind the `fuzzing` feature.
#[cfg(feature = "fuzzing")]
pub fn fuzz_beacon_roundtrip(bytes: &[u8]) {
    if let Ok(b) = BeaconBody::decode(bytes) {
        assert_eq!(
            BeaconBody::decode(&b.encode()).expect("re-decode of re-encoded beacon"),
            b,
            "beacon body round-trip mismatch"
        );
    }
}

/// Derive the symmetric beacon key from a chat root.
pub fn beacon_key(root: &[u8; KEY_LEN]) -> [u8; KEY_LEN] {
    let mut k = [0u8; KEY_LEN];
    mac_kdf(root, &[], BEACON_KEY_LABEL, &mut k);
    k
}

/// Seal a beacon under the chat key for broadcast / server advertisement.
/// Wire: `nonce[12] ‖ aead_ct`. The relay stores this as opaque ciphertext.
pub fn seal_broadcast(root: &[u8; KEY_LEN], body: &BeaconBody) -> Result<Vec<u8>> {
    let key = beacon_key(root);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = aead_seal(&key, &nonce, &body.encode(), BEACON_AAD)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open a broadcast beacon sealed with [`seal_broadcast`]. Uniform error on
/// failure (wrong key / tamper / truncation).
pub fn open_broadcast(root: &[u8; KEY_LEN], blob: &[u8]) -> Result<BeaconBody> {
    if blob.len() < NONCE_LEN {
        return Err(CryptoError::Malformed("beacon too short"));
    }
    let key = beacon_key(root);
    let (nonce, ct) = blob.split_at(NONCE_LEN);
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce);
    let pt = aead_open(&key, &n, ct, BEACON_AAD)?;
    BeaconBody::decode(&pt)
}

/// Seal a beacon to a single recipient's ML-KEM-1024 public key via the PQ
/// HPKE. The post-quantum KEM is ML-KEM-1024; the AEAD is AES-256-GCM.
pub fn seal_to_recipient(recipient_public: &[u8], body: &BeaconBody) -> Result<Vec<u8>> {
    encrypt_with_label(recipient_public, BEACON_HPKE_LABEL, BEACON_AAD, &body.encode())
}

/// Open a to-recipient beacon sealed with [`seal_to_recipient`].
pub fn open_to_recipient(kp: &HpkeKeyPair, blob: &[u8]) -> Result<BeaconBody> {
    let pt = kp.decrypt_with_label(BEACON_HPKE_LABEL, BEACON_AAD, blob)?;
    BeaconBody::decode(&pt)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> BeaconBody {
        BeaconBody::Full {
            suite_id: "tk.dr.mlkem1024+pad.aes256gcm.sha3-384.mldsa87".into(),
            params: vec![1, 2, 3],
        }
    }

    #[test]
    fn body_wire_roundtrip_both_variants() {
        for body in [BeaconBody::Fingerprint([9u8; SCHEME_HASH_LEN]), full()] {
            let b = body.encode();
            assert_eq!(BeaconBody::decode(&b).unwrap(), body);
        }
    }

    #[test]
    fn full_and_fingerprint_agree_on_fingerprint() {
        let f = full();
        let BeaconBody::Full { suite_id, params } = &f else {
            unreachable!()
        };
        let h = scheme_hash(suite_id, params);
        assert_eq!(f.fingerprint(), h);
        assert_eq!(BeaconBody::Fingerprint(h).fingerprint(), h);
        assert!(f.is_full());
        assert!(!BeaconBody::Fingerprint(h).is_full());
    }

    #[test]
    fn broadcast_seal_open_roundtrip() {
        let root = [7u8; KEY_LEN];
        for body in [BeaconBody::Fingerprint([3u8; SCHEME_HASH_LEN]), full()] {
            let blob = seal_broadcast(&root, &body).unwrap();
            assert_eq!(open_broadcast(&root, &blob).unwrap(), body);
        }
    }

    #[test]
    fn broadcast_is_opaque_without_the_chat_root() {
        // A relay storing the blob holds a different (or no) root and cannot open it.
        let root = [7u8; KEY_LEN];
        let blob = seal_broadcast(&root, &full()).unwrap();
        assert!(open_broadcast(&[8u8; KEY_LEN], &blob).is_err());
    }

    #[test]
    fn broadcast_tamper_fails() {
        let root = [7u8; KEY_LEN];
        let mut blob = seal_broadcast(&root, &full()).unwrap();
        let n = blob.len() - 1;
        blob[n] ^= 1;
        assert!(open_broadcast(&root, &blob).is_err());
    }

    #[test]
    fn nonce_is_fresh_per_seal() {
        let root = [7u8; KEY_LEN];
        let a = seal_broadcast(&root, &full()).unwrap();
        let b = seal_broadcast(&root, &full()).unwrap();
        assert_ne!(a, b, "random nonce must vary, so ciphertexts differ");
    }

    #[test]
    fn to_recipient_pq_hpke_roundtrip() {
        let kp = HpkeKeyPair::generate();
        for body in [BeaconBody::Fingerprint([5u8; SCHEME_HASH_LEN]), full()] {
            let blob = seal_to_recipient(kp.public(), &body).unwrap();
            assert_eq!(open_to_recipient(&kp, &blob).unwrap(), body);
        }
        // A different recipient key cannot open it.
        let other = HpkeKeyPair::generate();
        let blob = seal_to_recipient(kp.public(), &full()).unwrap();
        assert!(open_to_recipient(&other, &blob).is_err());
    }
}
