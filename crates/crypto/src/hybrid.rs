//! Hybrid asymmetric primitive: X25519 (classical) + ML-KEM-1024 (PQ).
//!
//! A "ratchet key" bundles an X25519 secret and an ML-KEM decapsulation key.
//! Its public half publishes the X25519 public key and the ML-KEM
//! encapsulation key.
//!
//! Advancing the ratchet combines two independent shared secrets:
//!   * `dh`         — `DH(our_x_secret, peer_x_public)` (symmetric NIKE)
//!   * `decapsulate`/`encapsulate` — ML-KEM shared secret carried via a
//!     ciphertext in the message header
//!
//! The combined secret is fed to `kdf_rk`. Confidentiality holds if **either**
//! primitive is unbroken — so a future break of X25519 does not retroactively
//! expose traffic, and ML-KEM covers harvest-now-decrypt-later.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024, B32};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use crate::error::{CryptoError, Result};
use crate::hash::Hash;

type KemEk = <MlKem1024 as KemCore>::EncapsulationKey;
type KemDk = <MlKem1024 as KemCore>::DecapsulationKey;

/// 32-byte shared secret from one primitive.
pub const SS_LEN: usize = 32;

/// The secret half of a ratchet key (X25519 secret + ML-KEM decap key).
///
/// `Clone` is required so a `Session` can be trial-decrypted on a copy and only
/// committed on success (preventing state corruption from hostile messages).
#[derive(Clone)]
pub struct RatchetSecret {
    x: XStaticSecret,
    kem_dk: KemDk,
}

/// The public half of a ratchet key, as carried in a message header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetPublic {
    pub x_pub: [u8; 32],
    /// Serialized ML-KEM-1024 encapsulation key (1568 bytes).
    pub kem_ek: Vec<u8>,
}

impl RatchetSecret {
    /// Generate a fresh hybrid ratchet key from the OS CSPRNG.
    pub fn generate() -> (RatchetSecret, RatchetPublic) {
        let mut rng = OsRng;
        let x = XStaticSecret::random_from_rng(rng);
        let x_pub = XPublicKey::from(&x).to_bytes();
        let (kem_dk, kem_ek) = MlKem1024::generate(&mut rng);
        let public = RatchetPublic {
            x_pub,
            kem_ek: kem_ek.as_bytes().as_slice().to_vec(),
        };
        (RatchetSecret { x, kem_dk }, public)
    }

    /// Deterministically derive a hybrid ratchet key from a 32-byte secret.
    ///
    /// Used by TreeKEM, where a node's key pair must be reproducible from the
    /// node secret. The seed is HKDF-expanded into the X25519 secret and the
    /// ML-KEM `(d, z)` generation seeds, so the same secret always yields the
    /// same key pair.
    pub fn derive_deterministic(seed: &[u8; 32]) -> (RatchetSecret, RatchetPublic) {
        let hk = Hkdf::<Hash>::new(None, seed);
        let mut okm = [0u8; 96];
        hk.expand(b"talkrypt-treekem-node", &mut okm)
            .expect("hkdf expand node key");
        let mut x_bytes = [0u8; 32];
        x_bytes.copy_from_slice(&okm[..32]);
        let d = B32::try_from(&okm[32..64]).expect("32");
        let z = B32::try_from(&okm[64..96]).expect("32");

        let x = XStaticSecret::from(x_bytes);
        let x_pub = XPublicKey::from(&x).to_bytes();
        let (kem_dk, kem_ek) = MlKem1024::generate_deterministic(&d, &z);
        let public = RatchetPublic {
            x_pub,
            kem_ek: kem_ek.as_bytes().as_slice().to_vec(),
        };
        (RatchetSecret { x, kem_dk }, public)
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

    /// X25519 DH against a peer public key.
    pub fn dh(&self, peer_x_pub: &[u8; 32]) -> [u8; SS_LEN] {
        let peer = XPublicKey::from(*peer_x_pub);
        self.x.diffie_hellman(&peer).to_bytes()
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

    pub fn encode(&self) -> Vec<u8> {
        let mut w = talkrypt_wire::Writer::new();
        w.put_bytes(&self.x_pub);
        w.put_bytes(&self.kem_ek);
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<RatchetPublic> {
        let mut r = talkrypt_wire::Reader::new(bytes);
        let x_pub = to_32(r.get_bytes()?);
        let kem_ek = r.get_vec()?;
        Ok(RatchetPublic { x_pub, kem_ek })
    }
}

fn to_32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&b[..32]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encapsulate_decapsulate_agree() {
        let (secret, public) = RatchetSecret::generate();
        let (ct, ss_enc) = public.encapsulate().unwrap();
        let ss_dec = secret.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn dh_is_symmetric() {
        let (a_sec, a_pub) = RatchetSecret::generate();
        let (b_sec, b_pub) = RatchetSecret::generate();
        assert_eq!(a_sec.dh(&b_pub.x_pub), b_sec.dh(&a_pub.x_pub));
    }

    #[test]
    fn distinct_keys_give_distinct_secrets() {
        let (_a_sec, a_pub) = RatchetSecret::generate();
        let (_b_sec, b_pub) = RatchetSecret::generate();
        let (ct_a, ss_a) = a_pub.encapsulate().unwrap();
        let (ct_b, ss_b) = b_pub.encapsulate().unwrap();
        assert_ne!(ss_a, ss_b);
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn ratchet_public_wire_roundtrip() {
        let (_s, p) = RatchetSecret::generate();
        let bytes = p.encode();
        let p2 = RatchetPublic::decode(&bytes).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn wrong_secret_cannot_decapsulate_to_same() {
        let (_secret, public) = RatchetSecret::generate();
        let (other_secret, _) = RatchetSecret::generate();
        let (ct, ss_enc) = public.encapsulate().unwrap();
        // Decapsulating with the wrong key yields a different (implicit-reject) secret.
        let ss_other = other_secret.decapsulate(&ct).unwrap();
        assert_ne!(ss_enc, ss_other);
    }
}

#[cfg(test)]
mod kat {
    use super::*;
    use sha3::{Digest, Sha3_256};

    /// Known-answer vector locking the hybrid public-key wire format. A change
    /// to the encoding, key sizes, or the deterministic-derivation labels
    /// breaks this. (1608 = 4+32 X25519 || 4+1568 ML-KEM-1024 encapsulation key.)
    #[test]
    fn ratchet_public_wire_kat() {
        let (_, pubk) = RatchetSecret::derive_deterministic(&[7u8; 32]);
        let enc = pubk.encode();
        assert_eq!(enc.len(), 1608, "hybrid public-key wire length");
        let digest = Sha3_256::digest(&enc);
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex, "6cd0127130e7319190f97f7d904ff68966f3c2cbc3d1a1dfa4e69f93563ed58b",
            "hybrid public-key KAT digest (talkrypt-mlspq wire v1)"
        );
    }
}
