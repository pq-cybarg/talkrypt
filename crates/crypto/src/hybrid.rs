//! Asymmetric ratchet primitive with a selectable **KEM profile**.
//!
//! A "ratchet key" always carries an ML-KEM-1024 key pair; the [`KemProfile`]
//! selects what else it carries and how it combines secrets:
//!
//!   * [`KemPosture::Hybrid`] — ML-KEM-1024 **+ X25519**. Advancing the ratchet
//!     combines two independent shared secrets, `DH(our_x, peer_x)` and the
//!     ML-KEM `encapsulate`/`decapsulate` secret. Confidentiality holds if
//!     **either** primitive is unbroken (IETF-style defense-in-depth). The
//!     X25519 half is non-load-bearing: a future X25519 break cannot
//!     retroactively expose traffic, and ML-KEM covers harvest-now-decrypt-later.
//!   * [`KemPosture::PqPure`] — ML-KEM-1024 **only**, zero elliptic curve. The
//!     strict NSA CNSA 2.0 posture; there is no DH and no X25519 key. The IKM
//!     is the ML-KEM shared secret alone.
//!
//! Independently, a PQ-pure key may be **padded** on the wire ([`KemProfile`]'s
//! `pad_pure`) with 36 filler bytes so its encoding is byte-length-identical to
//! a hybrid key. This hides the posture from a relay that can only observe
//! frame sizes. The padding is cosmetic: it is stored so the key round-trips,
//! but it never enters key derivation.
//!
//! The profile is fixed for a session by the chosen crypto suite and is carried
//! in every ratchet public key, so both peers derive identically. Hybrid is the
//! historical default wire encoding and is preserved byte-for-byte.

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, B32};
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

type KemEk = <MlKem1024 as KemCore>::EncapsulationKey;
type KemDk = <MlKem1024 as KemCore>::DecapsulationKey;

/// 32-byte shared secret from one primitive.
pub const SS_LEN: usize = 32;

/// Which key-establishment primitives a ratchet key combines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KemPosture {
    /// ML-KEM-1024 + X25519 (defense-in-depth; non-load-bearing EC).
    Hybrid,
    /// ML-KEM-1024 only (strict CNSA 2.0; zero elliptic curve).
    PqPure,
}

impl KemPosture {
    /// Stable wire/scheme tag for this posture.
    pub fn tag(self) -> u8 {
        match self {
            KemPosture::Hybrid => 0,
            KemPosture::PqPure => 1,
        }
    }

    /// Parse a posture tag.
    pub fn from_tag(t: u8) -> Result<Self> {
        Ok(match t {
            0 => KemPosture::Hybrid,
            1 => KemPosture::PqPure,
            _ => return Err(CryptoError::Malformed("kem posture tag")),
        })
    }

    /// Whether this posture carries a load-bearing X25519 half.
    pub fn has_ec(self) -> bool {
        matches!(self, KemPosture::Hybrid)
    }
}

/// The complete on-wire profile of a ratchet key: posture plus whether a
/// PQ-pure key is padded to be frame-length-indistinguishable from hybrid.
///
/// Fixed per session by the crypto suite and carried in every key so both peers
/// agree. `Default` is talkrypt's preferred posture: PQ-pure, padded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KemProfile {
    pub posture: KemPosture,
    /// For `PqPure`: pad the wire with [`PAD_LEN`] filler bytes so the encoded
    /// length matches hybrid. Ignored for `Hybrid` (already padded by the
    /// X25519 public).
    pub pad_pure: bool,
}

/// Filler length that makes a padded PQ-pure key match a hybrid key on the wire
/// (the X25519 public it stands in for is 32 bytes).
pub const PAD_LEN: usize = 32;

impl KemProfile {
    /// ML-KEM + X25519 hybrid.
    pub const fn hybrid() -> Self {
        Self {
            posture: KemPosture::Hybrid,
            pad_pure: false,
        }
    }
    /// PQ-pure, padded to hybrid's wire length (the default).
    pub const fn pq_pure() -> Self {
        Self {
            posture: KemPosture::PqPure,
            pad_pure: true,
        }
    }
    /// PQ-pure with no padding (smallest wire; posture is frame-size-visible).
    pub const fn pq_pure_compact() -> Self {
        Self {
            posture: KemPosture::PqPure,
            pad_pure: false,
        }
    }
}

impl Default for KemProfile {
    fn default() -> Self {
        Self::pq_pure()
    }
}

/// The secret half of a ratchet key.
///
/// `Clone` is required so a `Session` can be trial-decrypted on a copy and only
/// committed on success (preventing state corruption from hostile messages).
#[derive(Clone)]
pub struct RatchetSecret {
    profile: KemProfile,
    /// `Some` only under [`KemPosture::Hybrid`].
    x: Option<XStaticSecret>,
    kem_dk: KemDk,
}

/// The public half of a ratchet key, as carried in a message header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetPublic {
    pub profile: KemProfile,
    /// X25519 public; `Some` only under [`KemPosture::Hybrid`].
    pub x_pub: Option<[u8; 32]>,
    /// Cosmetic wire padding for a padded PQ-pure key; `Some([u8; PAD_LEN])`
    /// only when `profile` is PQ-pure with `pad_pure`. Never enters key
    /// derivation.
    pub pad: Option<[u8; PAD_LEN]>,
    /// Serialized ML-KEM-1024 encapsulation key (1568 bytes).
    pub kem_ek: Vec<u8>,
}

impl RatchetSecret {
    /// Generate a fresh ratchet key for `profile` from the OS CSPRNG.
    pub fn generate(profile: KemProfile) -> (RatchetSecret, RatchetPublic) {
        let mut rng = OsRng;
        let (kem_dk, kem_ek) = MlKem1024::generate(&mut rng);
        let (x, x_pub, pad) = match profile.posture {
            KemPosture::Hybrid => {
                let x = XStaticSecret::random_from_rng(rng);
                let xp = XPublicKey::from(&x).to_bytes();
                (Some(x), Some(xp), None)
            }
            KemPosture::PqPure => {
                let pad = if profile.pad_pure {
                    let mut p = [0u8; PAD_LEN];
                    OsRng.fill_bytes(&mut p);
                    shape_like_x25519_public(&mut p);
                    Some(p)
                } else {
                    None
                };
                (None, None, pad)
            }
        };
        let public = RatchetPublic {
            profile,
            x_pub,
            pad,
            kem_ek: kem_ek.as_bytes().as_slice().to_vec(),
        };
        (
            RatchetSecret {
                profile,
                x,
                kem_dk,
            },
            public,
        )
    }

    /// Deterministically derive a ratchet key for `profile` from a 32-byte seed.
    ///
    /// Used by TreeKEM, where a node's key pair must be reproducible from the
    /// node secret. The seed is expanded (KMAC256 under SHA-3, HKDF-SHA384
    /// under cnsa-sha2, via `mac_kdf`) into the ML-KEM `(d, z)` generation
    /// seeds — and, under `Hybrid`, the X25519 secret, or under padded PQ-pure,
    /// the filler — so the same seed always yields the same key pair. The
    /// expansion labels differ by posture, so a Hybrid and a PqPure node from
    /// the same seed are independent.
    pub fn derive_deterministic(
        profile: KemProfile,
        seed: &[u8; 32],
    ) -> (RatchetSecret, RatchetPublic) {
        match profile.posture {
            KemPosture::Hybrid => {
                let mut okm = [0u8; 96];
                crate::kdf::mac_kdf(seed, &[], b"talkrypt-treekem-node", &mut okm);
                let mut x_bytes = [0u8; 32];
                x_bytes.copy_from_slice(&okm[..32]);
                let d = B32::try_from(&okm[32..64]).expect("32");
                let z = B32::try_from(&okm[64..96]).expect("32");
                let x = XStaticSecret::from(x_bytes);
                let x_pub = XPublicKey::from(&x).to_bytes();
                let (kem_dk, kem_ek) = MlKem1024::generate_deterministic(&d, &z);
                let public = RatchetPublic {
                    profile,
                    x_pub: Some(x_pub),
                    pad: None,
                    kem_ek: kem_ek.as_bytes().as_slice().to_vec(),
                };
                (
                    RatchetSecret {
                        profile,
                        x: Some(x),
                        kem_dk,
                    },
                    public,
                )
            }
            KemPosture::PqPure => {
                // 96 bytes: pad(32) ‖ d(32) ‖ z(32); the pad is dropped if the
                // profile is unpadded, but derivation stays stable either way.
                let mut okm = [0u8; 96];
                crate::kdf::mac_kdf(seed, &[], b"talkrypt-treekem-node-pq", &mut okm);
                let pad = if profile.pad_pure {
                    let mut p = [0u8; PAD_LEN];
                    p.copy_from_slice(&okm[..32]);
                    shape_like_x25519_public(&mut p);
                    Some(p)
                } else {
                    None
                };
                let d = B32::try_from(&okm[32..64]).expect("32");
                let z = B32::try_from(&okm[64..96]).expect("32");
                let (kem_dk, kem_ek) = MlKem1024::generate_deterministic(&d, &z);
                let public = RatchetPublic {
                    profile,
                    x_pub: None,
                    pad,
                    kem_ek: kem_ek.as_bytes().as_slice().to_vec(),
                };
                (
                    RatchetSecret {
                        profile,
                        x: None,
                        kem_dk,
                    },
                    public,
                )
            }
        }
    }

    /// The profile this key was generated for.
    pub fn profile(&self) -> KemProfile {
        self.profile
    }

    /// Decapsulate an ML-KEM ciphertext made against our encapsulation key.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<[u8; SS_LEN]> {
        let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ct)
            .map_err(|_| CryptoError::Malformed("ml-kem ciphertext length"))?;
        let ss = self
            .kem_dk
            .decapsulate(&ct)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(to_32(ss.as_slice()))
    }

    /// X25519 DH against a peer public key (Hybrid only).
    pub fn dh(&self, peer_x_pub: &[u8; 32]) -> Result<[u8; SS_LEN]> {
        let x = self
            .x
            .as_ref()
            .ok_or(CryptoError::Malformed("dh requested on a PQ-pure key"))?;
        let peer = XPublicKey::from(*peer_x_pub);
        Ok(x.diffie_hellman(&peer).to_bytes())
    }

    /// Sender asymmetric step against `peer`: encapsulate and combine into the
    /// posture's input keying material. Returns `(kem_ciphertext, ikm)`.
    ///
    /// `self` must be the freshly generated sending key; under `Hybrid` its
    /// X25519 secret is DH'd against the peer's X25519 public.
    pub fn step_to(&self, peer: &RatchetPublic) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
        let (ct, kem_ss) = peer.encapsulate()?;
        let kem_ss = Zeroizing::new(kem_ss); // raw KEM secret — wipe on drop
        let ikm = self.combine_ikm(peer, &kem_ss)?;
        Ok((ct, ikm))
    }

    /// Receiver asymmetric step from a peer header: decapsulate `ct` and combine
    /// into the posture's input keying material. Returns the `ikm` (zeroized on
    /// drop, like the raw KEM/DH secrets it is derived from).
    pub fn step_from(&self, peer_pub: &RatchetPublic, ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let kem_ss = Zeroizing::new(self.decapsulate(ct)?);
        self.combine_ikm(peer_pub, &kem_ss)
    }

    fn combine_ikm(&self, peer: &RatchetPublic, kem_ss: &[u8; SS_LEN]) -> Result<Zeroizing<Vec<u8>>> {
        match self.profile.posture {
            KemPosture::Hybrid => {
                let peer_x = peer
                    .x_pub
                    .ok_or(CryptoError::Malformed("hybrid step against PQ-pure peer"))?;
                let dh = Zeroizing::new(self.dh(&peer_x)?); // raw X25519 secret
                let mut ikm = Zeroizing::new(Vec::with_capacity(64));
                ikm.extend_from_slice(&*dh);
                ikm.extend_from_slice(kem_ss);
                Ok(ikm)
            }
            KemPosture::PqPure => Ok(Zeroizing::new(kem_ss.to_vec())),
        }
    }
}

impl RatchetPublic {
    /// Encapsulate to this public key: returns `(ciphertext, kem_shared_secret)`.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, [u8; SS_LEN])> {
        let enc = Encoded::<KemEk>::try_from(&self.kem_ek[..])
            .map_err(|_| CryptoError::Malformed("ml-kem encapsulation key length"))?;
        let ek = KemEk::from_bytes(&enc);
        let (ct, ss) = ek
            .encapsulate(&mut OsRng)
            .map_err(|_| CryptoError::Malformed("ml-kem encapsulation failed"))?;
        Ok((ct.as_slice().to_vec(), to_32(ss.as_slice())))
    }

    /// Wire encoding. A 32-byte field (X25519 public for hybrid, filler for
    /// padded PQ-pure) precedes the ML-KEM key; unpadded PQ-pure omits it.
    /// Hybrid is byte-for-byte the historical `bytes(x_pub) ‖ bytes(kem_ek)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        match (&self.x_pub, &self.pad) {
            (Some(xp), _) => w.put_bytes(xp),
            (None, Some(p)) => w.put_bytes(p),
            (None, None) => {}
        }
        w.put_bytes(&self.kem_ek);
        w.into_vec()
    }

    /// Decode for a known `profile` (supplied by the session's suite). Hybrid
    /// reads the X25519 public first; padded PQ-pure reads the filler; unpadded
    /// PQ-pure reads only the ML-KEM key.
    pub fn decode(profile: KemProfile, bytes: &[u8]) -> Result<RatchetPublic> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let (x_pub, pad) = match profile.posture {
            KemPosture::Hybrid => (Some(to_32(r.get_bytes()?)), None),
            KemPosture::PqPure if profile.pad_pure => (None, Some(to_32(r.get_bytes()?))),
            KemPosture::PqPure => (None, None),
        };
        let kem_ek = r.get_vec()?;
        Ok(RatchetPublic {
            profile,
            x_pub,
            pad,
            kem_ek,
        })
    }
}

fn to_32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[..32]);
    out
}

/// Shape 32 random bytes so they are indistinguishable from a serialized
/// X25519 public key. A real X25519 public is a Montgomery u-coordinate
/// `< 2^255 − 19`, so the top bit of the little-endian high byte is always 0.
/// Clearing it makes the padded-PQ-pure filler match that distribution (the
/// residual gap of 19 values out of 2^255 is cryptographically undetectable),
/// so an observer who sees the cleartext ratchet key cannot distinguish a
/// padded PQ-pure key from a hybrid key by content — only padding equalizes
/// length; this equalizes shape.
fn shape_like_x25519_public(p: &mut [u8; PAD_LEN]) {
    p[PAD_LEN - 1] &= 0x7f;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles() -> [KemProfile; 3] {
        [
            KemProfile::hybrid(),
            KemProfile::pq_pure(),
            KemProfile::pq_pure_compact(),
        ]
    }

    #[test]
    fn encapsulate_decapsulate_agree() {
        for p in profiles() {
            let (secret, public) = RatchetSecret::generate(p);
            let (ct, ss_enc) = public.encapsulate().unwrap();
            let ss_dec = secret.decapsulate(&ct).unwrap();
            assert_eq!(ss_enc, ss_dec);
        }
    }

    #[test]
    fn dh_is_symmetric_for_hybrid_only() {
        let (a_sec, a_pub) = RatchetSecret::generate(KemProfile::hybrid());
        let (b_sec, b_pub) = RatchetSecret::generate(KemProfile::hybrid());
        assert_eq!(
            a_sec.dh(&b_pub.x_pub.unwrap()).unwrap(),
            b_sec.dh(&a_pub.x_pub.unwrap()).unwrap()
        );
        // PQ-pure keys carry no X25519 secret and refuse DH.
        let (pq_sec, _) = RatchetSecret::generate(KemProfile::pq_pure());
        assert!(pq_sec.dh(&a_pub.x_pub.unwrap()).is_err());
    }

    #[test]
    fn padded_pure_matches_hybrid_wire_length() {
        let (_h, hp) = RatchetSecret::generate(KemProfile::hybrid());
        let (_p, pp) = RatchetSecret::generate(KemProfile::pq_pure());
        let (_c, cp) = RatchetSecret::generate(KemProfile::pq_pure_compact());
        // Padded pure is byte-length-identical to hybrid; compact is shorter.
        assert_eq!(pp.encode().len(), hp.encode().len());
        assert_eq!(cp.encode().len(), hp.encode().len() - (4 + PAD_LEN));
        // Padding is cosmetic — pure (padded or not) carries no X25519 secret.
        assert!(pp.x_pub.is_none() && cp.x_pub.is_none());
    }

    #[test]
    fn padded_pure_filler_is_x25519_shaped() {
        // A real X25519 public always has the high bit of its top byte clear
        // (u-coordinate < 2^255 − 19). The filler must match so a content
        // observer cannot distinguish padded pure from hybrid. Check many
        // random keys, plus the deterministic derivation.
        for _ in 0..64 {
            let (_s, p) = RatchetSecret::generate(KemProfile::pq_pure());
            assert_eq!(p.pad.unwrap()[PAD_LEN - 1] & 0x80, 0);
        }
        let (_d, dp) = RatchetSecret::derive_deterministic(KemProfile::pq_pure(), &[0xFFu8; 32]);
        assert_eq!(dp.pad.unwrap()[PAD_LEN - 1] & 0x80, 0);
    }

    #[test]
    fn step_agrees_both_directions() {
        for p in profiles() {
            let (recv_sec, recv_pub) = RatchetSecret::generate(p);
            let (send_sec, send_pub) = RatchetSecret::generate(p);
            let (ct, ikm_send) = send_sec.step_to(&recv_pub).unwrap();
            let ikm_recv = recv_sec.step_from(&send_pub, &ct).unwrap();
            assert_eq!(ikm_send, ikm_recv);
            // Hybrid mixes dh(32) ‖ kem(32) = 64; pure is kem(32) only,
            // regardless of cosmetic padding.
            let expected = if p.posture.has_ec() { 64 } else { 32 };
            assert_eq!(ikm_send.len(), expected);
        }
    }

    #[test]
    fn distinct_keys_give_distinct_secrets() {
        for p in profiles() {
            let (_a_sec, a_pub) = RatchetSecret::generate(p);
            let (_b_sec, b_pub) = RatchetSecret::generate(p);
            let (ct_a, ss_a) = a_pub.encapsulate().unwrap();
            let (ct_b, ss_b) = b_pub.encapsulate().unwrap();
            assert_ne!(ss_a, ss_b);
            assert_ne!(ct_a, ct_b);
        }
    }

    #[test]
    fn ratchet_public_wire_roundtrip() {
        for p in profiles() {
            let (_s, pk) = RatchetSecret::generate(p);
            let bytes = pk.encode();
            let p2 = RatchetPublic::decode(p, &bytes).unwrap();
            assert_eq!(pk, p2);
        }
    }

    #[test]
    fn wrong_secret_cannot_decapsulate_to_same() {
        for p in profiles() {
            let (_secret, public) = RatchetSecret::generate(p);
            let (other_secret, _) = RatchetSecret::generate(p);
            let (ct, ss_enc) = public.encapsulate().unwrap();
            let ss_other = other_secret.decapsulate(&ct).unwrap();
            assert_ne!(ss_enc, ss_other);
        }
    }

    #[test]
    fn deterministic_derivation_is_reproducible() {
        for p in profiles() {
            let (_s1, p1) = RatchetSecret::derive_deterministic(p, &[9u8; 32]);
            let (_s2, p2) = RatchetSecret::derive_deterministic(p, &[9u8; 32]);
            assert_eq!(p1, p2);
        }
        // Same seed, different posture → independent ML-KEM keys.
        let (_h, hp) = RatchetSecret::derive_deterministic(KemProfile::hybrid(), &[9u8; 32]);
        let (_q, qp) = RatchetSecret::derive_deterministic(KemProfile::pq_pure(), &[9u8; 32]);
        assert_ne!(hp.kem_ek, qp.kem_ek);
    }
}

// These KATs pin the exact bytes of deterministically-derived keys, which
// depend on the KDF — so they are specific to the default SHA-3/KMAC256 build.
// (The build-independent wire lengths and round-trips are covered in `mod
// tests`.) Under `cnsa-sha2`, derivation uses HKDF-SHA384 and would yield
// different digests, so these are gated to the default build.
#[cfg(all(test, not(feature = "cnsa-sha2")))]
mod kat {
    use super::*;
    use sha3::{Digest, Sha3_256};

    fn digest_hex(bytes: &[u8]) -> String {
        Sha3_256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// KAT locking the **Hybrid** public-key wire format. A change to the
    /// encoding, key sizes, or deterministic-derivation labels breaks this.
    /// (1608 = 4+32 X25519 || 4+1568 ML-KEM-1024 encapsulation key.)
    #[test]
    fn ratchet_public_hybrid_wire_kat() {
        let (_, pubk) = RatchetSecret::derive_deterministic(KemProfile::hybrid(), &[7u8; 32]);
        let enc = pubk.encode();
        assert_eq!(enc.len(), 1608, "hybrid public-key wire length");
        assert_eq!(
            digest_hex(&enc),
            "3876ca2f820da022654cbefd2e47648a1d72ba25af704710baf16948cdd47895",
            "hybrid public-key KAT digest (talkrypt-mlspq wire v1)"
        );
    }

    /// KAT locking the **padded PQ-pure** wire format: a 32-byte deterministic
    /// filler in the X25519 slot, then the ML-KEM key. Same 1608-byte length as
    /// hybrid (posture is not frame-size-distinguishable), but no EC.
    #[test]
    fn ratchet_public_pqpure_padded_wire_kat() {
        let (_, pubk) = RatchetSecret::derive_deterministic(KemProfile::pq_pure(), &[7u8; 32]);
        let enc = pubk.encode();
        assert_eq!(enc.len(), 1608, "padded pq-pure matches hybrid length");
        assert_eq!(
            digest_hex(&enc),
            "f91a843ac8a0a8215c2495f6bb554a137ff80abf143ab92e43839161ba87ba84",
            "padded pq-pure public-key KAT digest (talkrypt-mlspq wire v1)"
        );
    }

    /// KAT locking the **compact PQ-pure** wire format: no X25519 slot at all,
    /// just the length-prefixed ML-KEM-1024 key. (1572 = 4 + 1568.)
    #[test]
    fn ratchet_public_pqpure_compact_wire_kat() {
        let (_, pubk) =
            RatchetSecret::derive_deterministic(KemProfile::pq_pure_compact(), &[7u8; 32]);
        let enc = pubk.encode();
        assert_eq!(enc.len(), 1572, "compact pq-pure wire length");
        assert_eq!(
            digest_hex(&enc),
            "bc405fa1e6ba0a8fb5b6829eed88424e4ee2a1cdbd9e10030d6beb20150cc1cb",
            "compact pq-pure public-key KAT digest (talkrypt-mlspq wire v1)"
        );
    }
}
