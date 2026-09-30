//! Post-quantum secure-element KEK wrapper — SEALSQ / WISeKey (QS7001, VaultIC
//! family) and any secure element that decapsulates **ML-KEM-1024 in silicon**.
//!
//! # Why this is different from every other wrapper
//!
//! A *classical* secure element (Apple Secure Enclave, Android StrongBox, a
//! TPM 2.0) can only wrap a KEK with classical asymmetric or symmetric crypto.
//! When that wrap is asymmetric (RSA/ECC), the wrapped-KEK stored at rest is
//! **quantum-recoverable** — which is exactly why [`talkrypt_core::seal`]'s
//! QROM/L5 rule refuses a classical hardware-only seal and forces a passphrase
//! whose Argon2id key keeps the AES-256-GCM contents post-quantum-safe (see the
//! project's `pqc-not-in-secure-elements` note). Hardware there protects the
//! seed at rest against an *off-device* attacker, but not against a *quantum*
//! one holding the exfiltrated blob.
//!
//! A **PQ secure element** removes that caveat for the KEK. It holds an
//! ML-KEM-1024 decapsulation key in tamper-resistant hardware and decapsulates
//! on-chip; the KEK is *encapsulated to the chip's ML-KEM public key*, so the
//! wrapped-KEK is not recoverable by a quantum adversary who captures the sealed
//! file. This wrapper therefore attests [`KeyWrapper::qrom_safe`] `= true`,
//! enabling the hardware-**only** L5/QROM custody tier with no passphrase — the
//! one hardware path that is post-quantum *at rest* end to end.
//!
//! It still does not defend a live-RAM attacker on a compromised host: the seed
//! is unwrapped into `mlock`'d memory to sign (R-8). The identity key is
//! ML-DSA-87 and is *not* held by the chip — no shipping secure element signs
//! ML-DSA — so this is at-rest custody of the seed, not in-use signing.
//!
//! # Wrap format (the opaque blob handed back to [`talkrypt_core::seal`])
//!
//! ```text
//! magic="TKPQ" ‖ version(u8)=1
//!   ‖ kem_ct(len-prefixed)   = ML-KEM-1024 ciphertext (encapsulated to the chip)
//!   ‖ nonce(len-prefixed, 12)
//!   ‖ ciphertext(len-prefixed) = AES-256-GCM(K, nonce, KEK; AAD = magic‖ver‖kem_ct‖nonce)
//! ```
//! where `K = mac_kdf(kem_shared_secret, "", "talkrypt-pqse-kek-v1")`. The whole
//! header is bound as AEAD AAD, so no field can be altered and the chip binding
//! cannot be stripped without failing the open. The KEK itself is the random
//! 32-byte value the core seal envelope generates; this wrapper never sees the
//! seed.
//!
//! # Driver seam
//!
//! Silicon vendors expose the chip over PKCS#11, a proprietary APDU/I²C stack,
//! or a host SDK. Rather than bind to one, this module takes any
//! [`PqSecureElement`] — a two-call transport seam (`encapsulation_key` +
//! `decapsulate`). A concrete SEALSQ/PKCS#11 driver implements it and is injected
//! via [`crate::store::KeyStore::with_wrapper`]. The crypto here is the audited
//! `talkrypt_crypto` ML-KEM-1024; the driver only moves bytes to and from the
//! chip. [`MockPqSecureElement`] is an in-process stand-in (a real ML-KEM key in
//! software) so the wrap/unwrap path is fully testable without hardware.

use std::sync::Arc;

use talkrypt_core::{KeyWrapper, WrapError};
use talkrypt_crypto::hybrid::{KemProfile, RatchetPublic, RatchetSecret};
use talkrypt_wire::{Reader, Writer};

const MAGIC: &[u8; 4] = b"TKPQ";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
/// The chip's ML-KEM-1024 encapsulation key is 1568 bytes; a decode guard.
const ML_KEM_1024_EK_LEN: usize = 1568;
/// Domain-separation label for deriving the AES key from the KEM shared secret.
const KEK_LABEL: &[u8] = b"talkrypt-pqse-kek-v1";

/// A post-quantum secure element that decapsulates ML-KEM-1024 on-chip.
///
/// The chip holds the ML-KEM-1024 **decapsulation** key in hardware; it never
/// leaves. The host reads the matching **encapsulation** key once and asks the
/// chip to decapsulate ciphertexts. A concrete implementation drives a SEALSQ
/// QS7001 / VaultIC (or any PQ secure element) over its transport (PKCS#11,
/// APDU, vendor SDK).
pub trait PqSecureElement: Send + Sync {
    /// The chip's ML-KEM-1024 encapsulation key (public, 1568 bytes). Stable for
    /// the life of the on-chip key; the host may cache it.
    fn encapsulation_key(&self) -> Result<Vec<u8>, WrapError>;

    /// Decapsulate an ML-KEM-1024 ciphertext on-chip with the non-exportable
    /// decapsulation key, returning the 32-byte shared secret.
    fn decapsulate(&self, kem_ct: &[u8]) -> Result<[u8; 32], WrapError>;
}

/// A [`KeyWrapper`] that wraps the KEK to a [`PqSecureElement`]'s ML-KEM key.
///
/// [`KeyWrapper::qrom_safe`] returns `true`: the hardware wrap is ML-KEM-1024, so
/// the wrapped-KEK is post-quantum at rest and the core will permit a
/// hardware-only (passphrase-less) L5/QROM seal.
pub struct PqSeWrapper {
    dev: Arc<dyn PqSecureElement>,
}

impl PqSeWrapper {
    /// Wrap the KEK to `dev`'s on-chip ML-KEM key.
    pub fn new(dev: Arc<dyn PqSecureElement>) -> Self {
        Self { dev }
    }
}

impl KeyWrapper for PqSeWrapper {
    fn wrap(&self, kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        let ek_bytes = self.dev.encapsulation_key()?;
        if ek_bytes.len() != ML_KEM_1024_EK_LEN {
            return Err(WrapError(format!(
                "pqse: encapsulation key is {} bytes, expected {ML_KEM_1024_EK_LEN}",
                ek_bytes.len()
            )));
        }
        // Encapsulate to the chip's public key using the audited ML-KEM-1024.
        let ek = RatchetPublic {
            profile: KemProfile::pq_pure_compact(),
            x_pub: None,
            pad: None,
            kem_ek: ek_bytes,
        };
        let (kem_ct, ss) = ek
            .encapsulate()
            .map_err(|e| WrapError(format!("pqse: ml-kem encapsulate: {e}")))?;

        let mut key = [0u8; 32];
        talkrypt_crypto::kdf::mac_kdf(&ss, &[], KEK_LABEL, &mut key);

        let mut nonce = [0u8; NONCE_LEN];
        talkrypt_crypto::fill_secure(&mut nonce);

        let header = encode_header(&kem_ct, &nonce);
        let ct = talkrypt_crypto::aead::seal(&key, &nonce, kek, &header)
            .map_err(|e| WrapError(format!("pqse: aead seal: {e}")))?;

        let mut out = header;
        let mut w = Writer::new();
        w.put_bytes(&ct);
        out.extend_from_slice(&w.into_vec());
        Ok(out)
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, WrapError> {
        let mut r = Reader::new(wrapped);
        let magic = r.get_bytes().map_err(wire_err)?;
        if magic != MAGIC {
            return Err(WrapError("pqse: bad magic".into()));
        }
        let version = r.get_u8().map_err(wire_err)?;
        if version != VERSION {
            return Err(WrapError("pqse: unsupported version".into()));
        }
        let kem_ct = r.get_bytes().map_err(wire_err)?.to_vec();
        let nonce_bytes = r.get_bytes().map_err(wire_err)?;
        if nonce_bytes.len() != NONCE_LEN {
            return Err(WrapError("pqse: bad nonce length".into()));
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_bytes);
        let ct = r.get_bytes().map_err(wire_err)?.to_vec();
        r.finish().map_err(wire_err)?;

        // Decapsulate on-chip; the shared secret re-derives the AES key.
        let ss = self.dev.decapsulate(&kem_ct)?;
        let mut key = [0u8; 32];
        talkrypt_crypto::kdf::mac_kdf(&ss, &[], KEK_LABEL, &mut key);

        let header = encode_header(&kem_ct, &nonce);
        talkrypt_crypto::aead::open(&key, &nonce, &ct, &header)
            .map_err(|e| WrapError(format!("pqse: aead open: {e}")))
    }

    fn qrom_safe(&self) -> bool {
        // The hardware wrap is ML-KEM-1024 — post-quantum. The wrapped-KEK at
        // rest is not recoverable by a quantum adversary, so a hardware-only
        // (passphrase-less) seal is L5/QROM-safe.
        true
    }
}

/// Serialize the header (everything before the ciphertext); reused verbatim as
/// the AEAD AAD on unwrap, so the two MUST agree byte for byte.
fn encode_header(kem_ct: &[u8], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_bytes(MAGIC);
    w.put_u8(VERSION);
    w.put_bytes(kem_ct);
    w.put_bytes(nonce);
    w.into_vec()
}

fn wire_err(e: talkrypt_wire::WireError) -> WrapError {
    WrapError(format!("pqse: malformed wrapped blob: {e}"))
}

/// An in-process stand-in for a PQ secure element: a real ML-KEM-1024 key pair
/// held in software. Exercises the exact wrap/unwrap path a real chip would,
/// without hardware. **Not** a secure element — for tests and local dev only.
pub struct MockPqSecureElement {
    secret: RatchetSecret,
    ek: Vec<u8>,
}

impl Default for MockPqSecureElement {
    fn default() -> Self {
        Self::new()
    }
}

impl MockPqSecureElement {
    /// Generate a fresh in-software ML-KEM-1024 key pair.
    pub fn new() -> Self {
        let (secret, public) = RatchetSecret::generate(KemProfile::pq_pure_compact());
        Self {
            secret,
            ek: public.kem_ek,
        }
    }
}

impl PqSecureElement for MockPqSecureElement {
    fn encapsulation_key(&self) -> Result<Vec<u8>, WrapError> {
        Ok(self.ek.clone())
    }

    fn decapsulate(&self, kem_ct: &[u8]) -> Result<[u8; 32], WrapError> {
        self.secret
            .decapsulate(kem_ct)
            .map_err(|e| WrapError(format!("pqse mock: decapsulate: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_core::seal::{seal, unseal, SealOptions};
    use talkrypt_core::CustodyTier;

    const KEK: &[u8] = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\
                         \x0f\x1e\x2d\x3c\x4b\x5a\x69\x78\x87\x96\xa5\xb4\xc3\xd2\xe1\xf0";

    fn wrapper() -> PqSeWrapper {
        PqSeWrapper::new(Arc::new(MockPqSecureElement::new()))
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let w = wrapper();
        let blob = w.wrap(KEK).unwrap();
        // The raw KEK must never appear in the wrapped bytes.
        assert!(blob.windows(KEK.len()).all(|win| win != KEK));
        let out = w.unwrap(&blob).unwrap();
        assert_eq!(out, KEK);
    }

    #[test]
    fn attests_qrom_safe() {
        assert!(wrapper().qrom_safe());
    }

    #[test]
    fn distinct_wraps_differ() {
        // Fresh encapsulation randomness + nonce each time.
        let w = wrapper();
        assert_ne!(w.wrap(KEK).unwrap(), w.wrap(KEK).unwrap());
    }

    #[test]
    fn a_different_chip_cannot_unwrap() {
        let a = wrapper();
        let b = wrapper(); // a different ML-KEM key pair == a different chip
        let blob = a.wrap(KEK).unwrap();
        // ML-KEM decapsulation is implicit-rejection: `b` decapsulates to a
        // *different* shared secret, so the AEAD open fails rather than yielding
        // a wrong KEK.
        assert!(b.unwrap(&blob).is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let w = wrapper();
        let blob = w.wrap(KEK).unwrap();
        for idx in [8usize, blob.len() / 2, blob.len() - 1] {
            let mut t = blob.clone();
            t[idx] ^= 0x01;
            assert!(w.unwrap(&t).is_err(), "tamper at {idx} should fail");
        }
    }

    #[test]
    fn bad_header_rejected() {
        let w = wrapper();
        assert!(w.unwrap(b"").is_err());
        assert!(w.unwrap(b"not a pqse blob").is_err());
    }

    #[test]
    fn wrong_encapsulation_key_length_rejected() {
        struct ShortEk;
        impl PqSecureElement for ShortEk {
            fn encapsulation_key(&self) -> Result<Vec<u8>, WrapError> {
                Ok(vec![0u8; 32])
            }
            fn decapsulate(&self, _: &[u8]) -> Result<[u8; 32], WrapError> {
                Ok([0u8; 32])
            }
        }
        let w = PqSeWrapper::new(Arc::new(ShortEk));
        assert!(w.wrap(KEK).is_err());
    }

    /// The whole point: a PQ chip permits the **hardware-only** L5/QROM seal that
    /// the core refuses for a classical secure element. Sealing a seed with only
    /// this wrapper (no passphrase) must succeed and round-trip.
    #[test]
    fn enables_hardware_only_qrom_seal_through_core() {
        let seed = [7u8; 32];
        let w = wrapper();
        let blob = seal(
            &seed,
            SealOptions {
                passphrase: None,
                wrapper: Some(&w),
                ..Default::default()
            },
        )
        .expect("PQ chip attests qrom_safe → hardware-only seal is allowed");
        assert_eq!(
            talkrypt_core::seal::tier_of(&blob).unwrap(),
            CustodyTier::HardwareBacked
        );
        let out = unseal(&blob, None, Some(&w)).unwrap();
        assert_eq!(out, seed);
    }
}
