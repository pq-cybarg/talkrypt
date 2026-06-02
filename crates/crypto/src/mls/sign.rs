//! Post-quantum MLS `SignWithLabel` / `VerifyWithLabel`.
//!
//! talkrypt's MLS is **PQ-only**: signatures use **ML-DSA-87** (FIPS 204), not
//! the classical Ed25519 of RFC 9420's standard ciphersuites — so there is zero
//! elliptic curve here. The signed body keeps the MLS framing
//! `SignContent = { opaque label<V> = "MLS 1.0 "+Label; opaque content<V> }`.
//!
//! No official PQ-MLS vectors exist, so this is validated by talkrypt KATs:
//! ML-DSA-87's deterministic variant makes the signature reproducible, so the
//! KAT pins the exact signature digest.

use ml_dsa::signature::{Signer, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa87, Signature, SigningKey, VerifyingKey,
    B32,
};

use super::schedule::labeled_content;
use crate::error::{CryptoError, Result};

/// A PQ MLS signer (ML-DSA-87), reconstructable from its 32-byte seed.
pub struct MlsSigner {
    seed: [u8; 32],
}

impl MlsSigner {
    pub fn from_seed(seed: [u8; 32]) -> MlsSigner {
        MlsSigner { seed }
    }

    fn signing_key(&self) -> SigningKey<MlDsa87> {
        let b32 = B32::try_from(&self.seed[..]).expect("32-byte seed");
        SigningKey::<MlDsa87>::from_seed(&b32)
    }

    /// The encoded ML-DSA-87 verifying key (the public signature key).
    pub fn verifying_key(&self) -> Vec<u8> {
        self.signing_key()
            .verifying_key()
            .encode()
            .as_slice()
            .to_vec()
    }

    /// `SignWithLabel(sk, label, content)` over the MLS-framed body.
    pub fn sign_with_label(&self, label: &str, content: &[u8]) -> Vec<u8> {
        let body = labeled_content(label, content);
        let sig: Signature<MlDsa87> = self.signing_key().try_sign(&body).expect("ml-dsa sign");
        sig.encode().as_slice().to_vec()
    }
}

/// `VerifyWithLabel(pub, label, content, sig)` with an ML-DSA-87 verifying key.
pub fn verify_with_label(
    verifying_key: &[u8],
    label: &str,
    content: &[u8],
    signature: &[u8],
) -> Result<()> {
    let enc_vk = EncodedVerifyingKey::<MlDsa87>::try_from(verifying_key)
        .map_err(|_| CryptoError::Malformed("ml-dsa verifying key length"))?;
    let vk = VerifyingKey::<MlDsa87>::decode(&enc_vk);
    let enc_sig = EncodedSignature::<MlDsa87>::try_from(signature)
        .map_err(|_| CryptoError::Malformed("ml-dsa signature length"))?;
    let sig = Signature::<MlDsa87>::decode(&enc_sig).ok_or(CryptoError::BadSignature)?;
    let body = labeled_content(label, content);
    vk.verify(&body, &sig)
        .map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let signer = MlsSigner::from_seed([9u8; 32]);
        let vk = signer.verifying_key();
        let sig = signer.sign_with_label("FramedContentTBS", b"hello mls");
        assert!(verify_with_label(&vk, "FramedContentTBS", b"hello mls", &sig).is_ok());
        // Wrong label, wrong content, and wrong key all fail.
        assert!(verify_with_label(&vk, "OtherLabel", b"hello mls", &sig).is_err());
        assert!(verify_with_label(&vk, "FramedContentTBS", b"tampered", &sig).is_err());
        let other = MlsSigner::from_seed([10u8; 32]).verifying_key();
        assert!(verify_with_label(&other, "FramedContentTBS", b"hello mls", &sig).is_err());
    }

    /// KAT: ML-DSA-87's deterministic signing makes the signature reproducible,
    /// so a fixed (seed, label, content) always yields this signature digest.
    #[test]
    fn sign_with_label_kat() {
        let signer = MlsSigner::from_seed([1u8; 32]);
        let sig = signer.sign_with_label("KatLabel", b"kat-content");
        assert_eq!(sig.len(), 4627, "ML-DSA-87 signature length");
        let digest: String = Sha3_256::digest(&sig)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            digest, "25a454541eb25f7486b9f45c349e41e405bd4b65a7ee9909e501d356b0e00e61",
            "PQ SignWithLabel KAT (ML-DSA-87, deterministic)"
        );
    }
}
