//! Long-term identity: an ML-DSA-87 signing key plus an X25519 identity key.
//!
//! The public identity's **fingerprint** is `SHA-384(ml_dsa_vk || x25519_pub)`,
//! rendered as a grouped "safety number" for out-of-band verification.
//!
//! The ML-DSA private key is stored as its 32-byte seed (the FIPS-204
//! preferred serialization), held in a `Zeroizing` buffer and expanded on use.

use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::Keypair;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, SigningKey, VerifyingKey, B32,
};
use rand::RngCore;
use sha2::{Digest, Sha384};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Length of an identity fingerprint (SHA-384).
pub const FINGERPRINT_LEN: usize = 48;

/// A long-term secret identity. Not `Clone` — there should be one.
pub struct IdentityKeyPair {
    /// ML-DSA-87 signing seed (32 bytes), zeroized on drop.
    sig_seed: Zeroizing<[u8; 32]>,
    /// X25519 identity secret (zeroized on drop via the `zeroize` feature).
    x25519: XStaticSecret,
    /// Cached public half.
    public: IdentityPublic,
}

/// The shareable public identity.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentityPublic {
    /// ML-DSA-87 verifying key, encoded (2592 bytes for category-5).
    pub sig_vk: Vec<u8>,
    /// X25519 identity public key.
    pub x25519_pub: [u8; 32],
}

impl IdentityKeyPair {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut_slice());
        let x25519 = XStaticSecret::random_from_rng(rng);
        Self::from_parts(seed, x25519)
    }

    /// Reconstruct from a stored ML-DSA seed and X25519 secret bytes.
    pub fn from_secret_bytes(sig_seed: [u8; 32], x25519_secret: [u8; 32]) -> Self {
        Self::from_parts(Zeroizing::new(sig_seed), XStaticSecret::from(x25519_secret))
    }

    fn from_parts(sig_seed: Zeroizing<[u8; 32]>, x25519: XStaticSecret) -> Self {
        let signing = signing_key_from_seed(&sig_seed);
        let vk = signing.verifying_key();
        let sig_vk = vk.encode().as_slice().to_vec();
        let x25519_pub = XPublicKey::from(&x25519).to_bytes();
        let public = IdentityPublic { sig_vk, x25519_pub };
        Self {
            sig_seed,
            x25519,
            public,
        }
    }

    pub fn public(&self) -> &IdentityPublic {
        &self.public
    }

    /// Export secrets for encrypted-at-rest storage. Caller must protect these.
    pub fn export_secret(&self) -> ([u8; 32], [u8; 32]) {
        (*self.sig_seed, self.x25519.to_bytes())
    }

    /// Borrow the X25519 identity secret (for X3DH-style handshakes).
    pub fn x25519_secret(&self) -> &XStaticSecret {
        &self.x25519
    }

    /// Sign a message with ML-DSA-87 (deterministic variant, empty context).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let signing = signing_key_from_seed(&self.sig_seed);
        let sig: Signature<MlDsa87> = signing.try_sign(msg).expect("ml-dsa sign");
        sig.encode().as_slice().to_vec()
    }
}

impl IdentityPublic {
    /// SHA-384 fingerprint over the canonical public-key encoding.
    pub fn fingerprint(&self) -> [u8; FINGERPRINT_LEN] {
        let mut h = Sha384::new();
        h.update(&self.sig_vk);
        h.update(self.x25519_pub);
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
        let (seed, x) = id.export_secret();
        let id2 = IdentityKeyPair::from_secret_bytes(seed, x);
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
