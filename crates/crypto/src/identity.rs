//! Long-term identity: a single ML-DSA-87 signing key. No elliptic curve.
//!
//! The public identity's **fingerprint** is `Hash(ml_dsa_vk)` (SHA3-384 by
//! default), rendered as a grouped "safety number" for out-of-band
//! verification. Authentication is post-quantum end to end; there is no EC
//! identity key (the per-session ratchet's hybrid X25519 half is separate and
//! strictly defense-in-depth — see [`crate::hybrid`]).
//!
//! The ML-DSA private key is stored as its 32-byte seed (the FIPS-204
//! preferred serialization), held in a page-locked, zeroize-on-drop
//! [`LockedBox`](crate::mem::LockedBox) — never swapped to disk or captured in a
//! core dump — and expanded on use (SECURITY-AUDIT R-8).

use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::Keypair;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, SigningKey, VerifyingKey, B32,
};
use rand::RngCore;
use sha3::Digest;

use crate::error::{CryptoError, Result};
use crate::hash::Hash;
use crate::mem::LockedBox;

/// Length of an identity fingerprint (the [`Hash`] output, 48 bytes).
pub const FINGERPRINT_LEN: usize = 48;

/// A long-term secret identity (ML-DSA-87). Not `Clone` — there should be one.
pub struct IdentityKeyPair {
    /// ML-DSA-87 signing seed (32 bytes). Held in page-locked memory so it is
    /// never swapped to disk or captured in a core dump, and zeroized on drop
    /// (SECURITY-AUDIT R-8 / F-3; see [`crate::mem`]).
    sig_seed: LockedBox<32>,
    /// Cached public half.
    public: IdentityPublic,
}

/// The shareable public identity (ML-DSA-87 verifying key).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityPublic {
    /// ML-DSA-87 verifying key, encoded (2592 bytes for category-5).
    pub sig_vk: Vec<u8>,
}

impl subtle::ConstantTimeEq for IdentityPublic {
    /// Constant-time key equality for the **authentication-decision** path
    /// (identity-chain verification). The key bytes are public, so this is
    /// defense-in-depth — an auth-gate comparison is constant-time by principle,
    /// leaking no position-of-first-difference even though the values aren't
    /// secret. The key length is public (a fixed parameter), so a length
    /// mismatch short-circuits to "not equal". (SECURITY-AUDIT R-4.)
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        if self.sig_vk.len() != other.sig_vk.len() {
            return subtle::Choice::from(0u8);
        }
        self.sig_vk.ct_eq(&other.sig_vk)
    }
}

impl IdentityPublic {
    /// Constant-time equality (see [`subtle::ConstantTimeEq`]).
    pub fn ct_eq(&self, other: &Self) -> bool {
        bool::from(subtle::ConstantTimeEq::ct_eq(self, other))
    }
}

impl IdentityKeyPair {
    /// Generate a fresh identity from the OS CSPRNG. The seed is drawn directly
    /// into page-locked memory ([`LockedBox`]) so it never lands in an unpinned
    /// temporary that could be swapped or dumped.
    pub fn generate() -> Self {
        let mut seed = LockedBox::<32>::zeroed();
        rand::rngs::OsRng.fill_bytes(seed.as_mut_array());
        let kp = Self::from_locked_seed(seed);
        kp.pairwise_consistency_check();
        kp
    }

    /// FIPS conditional self-test (pairwise consistency test) on key generation
    /// (SECURITY-AUDIT R-5): the freshly generated key must sign a probe and
    /// verify it. A failure means the keypair is faulty — a fault or corruption
    /// during generation — so we **abort** rather than ever hand back a key that
    /// can't sign-and-verify. Cheap (one ML-DSA-87 sign + verify); keygen is rare
    /// (account/device/segment creation), not per-message.
    fn pairwise_consistency_check(&self) {
        const PROBE: &[u8] = b"talkrypt ml-dsa-87 keygen PCT";
        let sig = self.sign(PROBE);
        if self.public.verify(PROBE, &sig).is_err() {
            eprintln!("FATAL: ML-DSA-87 key-generation pairwise-consistency test failed");
            std::process::abort();
        }
    }

    /// Reconstruct from a stored ML-DSA seed. The `sig_seed` argument is the
    /// caller's transient copy (e.g. just decrypted from at-rest storage); it is
    /// copied into page-locked memory here, and the caller owns and should
    /// zeroize their copy.
    pub fn from_secret_bytes(sig_seed: [u8; 32]) -> Self {
        Self::from_locked_seed(LockedBox::from_bytes(&sig_seed))
    }

    /// Build the keypair around an already-locked seed, deriving the public half.
    fn from_locked_seed(sig_seed: LockedBox<32>) -> Self {
        let signing = signing_key_from_seed(&sig_seed);
        let vk = signing.verifying_key();
        let sig_vk = vk.encode().as_slice().to_vec();
        Self {
            sig_seed,
            public: IdentityPublic { sig_vk },
        }
    }

    pub fn public(&self) -> &IdentityPublic {
        &self.public
    }

    /// Export the secret seed for encrypted-at-rest storage. Caller must
    /// protect this.
    pub fn export_secret(&self) -> [u8; 32] {
        *self.sig_seed
    }

    /// Sign a message with ML-DSA-87 (deterministic variant, empty context).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let signing = signing_key_from_seed(&self.sig_seed);
        let sig: Signature<MlDsa87> = signing.try_sign(msg).expect("ml-dsa sign");
        sig.encode().as_slice().to_vec()
    }
}

impl IdentityPublic {
    /// Fingerprint over the canonical public-key encoding.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        let mut h = Hash::new();
        h.update(&self.sig_vk);
        let out = h.finalize();
        let mut fp = [0u8; FINGERPRINT_LEN];
        fp.copy_from_slice(&out);
        fp
    }

    /// Human-readable safety number: fingerprint as space-grouped uppercase hex.
    pub fn safety_number(&self) -> String {
        let fp = self.fingerprint();
        fp.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.concat())
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Verify an ML-DSA-87 signature made by this identity.
    pub fn verify(&self, msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
        let vk = verifying_key_from_bytes(&self.sig_vk)?;
        let enc = EncodedSignature::<MlDsa87>::try_from(sig_bytes)
            .map_err(|_| CryptoError::Malformed("ml-dsa signature length"))?;
        let sig = Signature::<MlDsa87>::decode(&enc).ok_or(CryptoError::BadSignature)?;
        vk.verify(msg, &sig).map_err(|_| CryptoError::BadSignature)
    }
}

fn signing_key_from_seed(seed: &[u8; 32]) -> SigningKey<MlDsa87> {
    let b32 = B32::try_from(&seed[..]).expect("32-byte seed");
    SigningKey::<MlDsa87>::from_seed(&b32)
}

fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<MlDsa87>> {
    let enc = EncodedVerifyingKey::<MlDsa87>::try_from(bytes)
        .map_err(|_| CryptoError::Malformed("ml-dsa verifying key length"))?;
    Ok(VerifyingKey::<MlDsa87>::decode(&enc))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_48_bytes_and_stable() {
        let id = IdentityKeyPair::generate();
        let fp1 = id.public().fingerprint();
        let fp2 = id.public().fingerprint();
        assert_eq!(fp1.len(), 48);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn distinct_identities_have_distinct_fingerprints() {
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::generate();
        assert_ne!(a.public().fingerprint(), b.public().fingerprint());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let id = IdentityKeyPair::generate();
        let msg = b"attack at dawn";
        let sig = id.sign(msg);
        assert!(id.public().verify(msg, &sig).is_ok());
    }

    #[test]
    fn tampered_message_fails_verify() {
        let id = IdentityKeyPair::generate();
        let sig = id.sign(b"transfer $10");
        assert!(id.public().verify(b"transfer $90", &sig).is_err());
    }

    #[test]
    fn wrong_identity_fails_verify() {
        let a = IdentityKeyPair::generate();
        let b = IdentityKeyPair::generate();
        let sig = a.sign(b"hello");
        assert!(b.public().verify(b"hello", &sig).is_err());
    }

    #[test]
    fn secret_export_reimport_roundtrip() {
        let id = IdentityKeyPair::generate();
        let seed = id.export_secret();
        let id2 = IdentityKeyPair::from_secret_bytes(seed);
        assert_eq!(id.public().fingerprint(), id2.public().fingerprint());
        // signature from reimported key verifies under original public id
        let sig = id2.sign(b"same key");
        assert!(id.public().verify(b"same key", &sig).is_ok());
    }

    #[test]
    fn safety_number_is_grouped_hex() {
        let id = IdentityKeyPair::generate();
        let sn = id.public().safety_number();
        // 48 bytes -> 12 groups of 4 bytes (8 hex chars each) -> 11 spaces
        assert_eq!(sn.chars().filter(|c| *c == ' ').count(), 11);
        assert!(sn.chars().all(|c| c.is_ascii_hexdigit() || c == ' '));
    }
}
