//! Post-quantum MLS `EncryptWithLabel` / `DecryptWithLabel` — the HPKE-style
//! public-key encryption used for Welcome `GroupSecrets`.
//!
//! talkrypt's MLS is **PQ-only**: this uses **ML-KEM-1024 alone** (no X25519,
//! no elliptic curve) as the KEM, HKDF-SHA3 to derive the AEAD key/nonce from
//! the encapsulated secret, and AES-256-GCM. The MLS framing
//! `{ opaque label<V> = "MLS 1.0 "+Label; opaque context<V> }` is bound as the
//! KDF info and the AEAD associated data.
//!
//! Wire: `bytes(kem_ciphertext) ‖ bytes(aead_ciphertext)`. ML-KEM encapsulation
//! is randomized, so this is validated by roundtrip + negative tests (no
//! deterministic ciphertext KAT is possible, and no official PQ-MLS vectors
//! exist).

use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;

use crate::aead::{open as aead_open, seal as aead_seal};
use crate::error::{CryptoError, Result};
use crate::mls::schedule::labeled_content;

type KemEk = <MlKem1024 as KemCore>::EncapsulationKey;
type KemDk = <MlKem1024 as KemCore>::DecapsulationKey;

/// An HPKE recipient key pair (ML-KEM-1024).
pub struct HpkeKeyPair {
    dk: KemDk,
    public: Vec<u8>,
}

impl HpkeKeyPair {
    /// Generate a recipient key pair; share `public()` with senders.
    pub fn generate() -> HpkeKeyPair {
        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        HpkeKeyPair {
            dk,
            public: ek.as_bytes().as_slice().to_vec(),
        }
    }

    /// The encoded ML-KEM-1024 encapsulation (public) key.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// `DecryptWithLabel(sk, label, context, ct)`.
    pub fn decrypt_with_label(&self, label: &str, context: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        let mut r = talkrypt_wire::Reader::new(blob);
        let kem_ct = r.get_vec()?;
        let aead_ct = r.get_vec()?;
        r.finish()?;
        let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(&kem_ct[..])
            .map_err(|_| CryptoError::Malformed("ml-kem ciphertext length"))?;
        let ss = self
            .dk
            .decapsulate(&ct)
            .map_err(|_| CryptoError::DecryptionFailed)?;
        let info = labeled_content(label, context);
        let (key, nonce) = derive(ss.as_slice(), &info);
        aead_open(&key, &nonce, &aead_ct, &info)
    }
}

/// `EncryptWithLabel(pub, label, context, plaintext)` to an ML-KEM-1024
/// public key. Returns `kem_ct ‖ aead_ct`.
pub fn encrypt_with_label(
    public: &[u8],
    label: &str,
    context: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let enc = Encoded::<KemEk>::try_from(public)
        .map_err(|_| CryptoError::Malformed("ml-kem encapsulation key length"))?;
    let ek = KemEk::from_bytes(&enc);
    let (kem_ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CryptoError::Malformed("ml-kem encapsulation failed"))?;
    let info = labeled_content(label, context);
    let (key, nonce) = derive(ss.as_slice(), &info);
    let aead_ct = aead_seal(&key, &nonce, plaintext, &info)?;

    let mut w = talkrypt_wire::Writer::new();
    w.put_bytes(kem_ct.as_slice());
    w.put_bytes(&aead_ct);
    Ok(w.into_vec())
}

/// Derive an AES-256-GCM `(key, nonce)` from the KEM shared secret and info,
/// keyed with KMAC256 (SHA-3 build) via the shared `mac_kdf`.
fn derive(ss: &[u8], info: &[u8]) -> ([u8; 32], [u8; 12]) {
    let mut okm = [0u8; 44];
    crate::kdf::mac_kdf(ss, info, b"talkrypt-mls-hpke", &mut okm);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..]);
    (key, nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let kp = HpkeKeyPair::generate();
        let ct =
            encrypt_with_label(kp.public(), "Welcome", b"group-ctx", b"group secrets").unwrap();
        let pt = kp.decrypt_with_label("Welcome", b"group-ctx", &ct).unwrap();
        assert_eq!(pt, b"group secrets");
    }

    #[test]
    fn wrong_label_context_or_key_fails() {
        let kp = HpkeKeyPair::generate();
        let ct = encrypt_with_label(kp.public(), "Welcome", b"ctx", b"secret").unwrap();
        assert!(kp.decrypt_with_label("Other", b"ctx", &ct).is_err());
        assert!(kp.decrypt_with_label("Welcome", b"different", &ct).is_err());
        let other = HpkeKeyPair::generate();
        assert!(other.decrypt_with_label("Welcome", b"ctx", &ct).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let kp = HpkeKeyPair::generate();
        let mut ct = encrypt_with_label(kp.public(), "Welcome", b"ctx", b"secret").unwrap();
        let n = ct.len();
        ct[n - 1] ^= 1;
        assert!(kp.decrypt_with_label("Welcome", b"ctx", &ct).is_err());
    }
}
