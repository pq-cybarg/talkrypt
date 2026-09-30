//! External-HSM KEK wrapper — PKCS#11 tokens (YubiKey PIV, Nitrokey, SoftHSM,
//! Thales/Utimaco/AWS CloudHSM) and any hardware token you physically control.
//!
//! # Why this backend
//!
//! It gives real, non-exportable **hardware** key custody with **no Apple (or any
//! OS) code-signing identity, no entitlement, and no third-party software in the
//! trust boundary** — the wrap happens inside a token *you* own. Contrast the
//! macOS Secure Enclave ([`crate::macos_hw`]), whose key registration is gated by
//! an Apple-provisioned entitlement.
//!
//! Like [`crate::pqse`], the wrapper only ever touches the random 32-byte
//! **KEK** that `talkrypt_core::seal` hands it — never the seed. So an untrusted
//! or compromised token cannot recover the seed on its own: the seed is encrypted
//! under `KDF(KEK ‖ passphrase)`, and the QROM/L5 rule forces a passphrase for a
//! classical token (see `docs/hardware-backed-sealing.md`). The token holds the
//! wrapping key internally and performs both wrap and unwrap, so there is **no
//! wrapper public key persisted** anywhere for a quantum adversary to target —
//! the "don't persist the wrapper public key" hardening is satisfied by
//! construction.
//!
//! # Two layers
//!
//! - [`HsmToken`] — the raw token transport: the token wraps/unwraps the KEK with
//!   a resident key. A concrete PKCS#11 driver implements it (see
//!   [`crate::hsm::pkcs11`] behind the `pkcs11` feature); [`MockHsmToken`] is an
//!   in-process stand-in so the envelope logic is fully testable without a token.
//! - [`HsmKeyWrapper`] — a [`talkrypt_core::KeyWrapper`] over any [`HsmToken`],
//!   framing a versioned envelope and reporting `qrom_safe` from the token's
//!   declared wrap primitive (AES-256 key-wrap ⇒ true; RSA/ECC ⇒ false).

use std::sync::Arc;

use talkrypt_core::{KeyWrapper, WrapError};
use talkrypt_wire::{Reader, Writer};

const MAGIC: &[u8; 4] = b"TKHS";
const VERSION: u8 = 1;

/// A hardware token that wraps/unwraps a KEK with a key it holds internally.
///
/// The token never exports the wrapping key; it performs the operation on-device.
/// A concrete implementation drives a PKCS#11 token (or any HSM). The KEK is
/// 32 bytes.
pub trait HsmToken: Send + Sync {
    /// Wrap (encrypt / key-wrap) `kek` with the token-resident key; opaque blob.
    fn token_wrap(&self, kek: &[u8]) -> Result<Vec<u8>, WrapError>;

    /// Unwrap a blob previously produced by [`HsmToken::token_wrap`] on this token.
    fn token_unwrap(&self, blob: &[u8]) -> Result<Vec<u8>, WrapError>;

    /// Whether the token's wrap primitive is QROM-safe at rest: `true` only for a
    /// symmetric ≥256-bit wrap (e.g. AES-256 key-wrap / AES-256-GCM on the token).
    /// `false` (default, conservative) for RSA/ECC — such a token must be paired
    /// with a passphrase (the seam enforces this).
    fn qrom_safe(&self) -> bool {
        false
    }
}

/// A [`KeyWrapper`] backed by any [`HsmToken`]. Frames a small versioned envelope
/// around the token's opaque output.
pub struct HsmKeyWrapper {
    token: Arc<dyn HsmToken>,
}

impl HsmKeyWrapper {
    /// Wrap the KEK with `token`.
    pub fn new(token: Arc<dyn HsmToken>) -> Self {
        Self { token }
    }
}

impl KeyWrapper for HsmKeyWrapper {
    fn wrap(&self, kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        let inner = self.token.token_wrap(kek)?;
        let mut w = Writer::new();
        w.put_bytes(MAGIC);
        w.put_u8(VERSION);
        w.put_bytes(&inner);
        Ok(w.into_vec())
    }

    fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, WrapError> {
        let mut r = Reader::new(wrapped);
        let magic = r
            .get_bytes()
            .map_err(|e| WrapError(format!("hsm: malformed blob: {e}")))?;
        if magic != MAGIC {
            return Err(WrapError("hsm: bad magic".into()));
        }
        let version = r
            .get_u8()
            .map_err(|e| WrapError(format!("hsm: malformed blob: {e}")))?;
        if version != VERSION {
            return Err(WrapError("hsm: unsupported version".into()));
        }
        let inner = r
            .get_bytes()
            .map_err(|e| WrapError(format!("hsm: malformed blob: {e}")))?;
        r.finish()
            .map_err(|e| WrapError(format!("hsm: trailing bytes: {e}")))?;
        self.token.token_unwrap(inner)
    }

    fn qrom_safe(&self) -> bool {
        self.token.qrom_safe()
    }
}

/// An in-process stand-in for a hardware token: AES-256-GCM under a per-instance
/// key held in memory. Exercises the exact wrap/unwrap envelope a real token
/// would, without hardware. **Not** an HSM — for tests and local dev only.
pub struct MockHsmToken {
    key: [u8; 32],
    qrom: bool,
}

impl Default for MockHsmToken {
    fn default() -> Self {
        Self::new_symmetric()
    }
}

impl MockHsmToken {
    /// A symmetric (AES-256) token → QROM-safe wrap.
    pub fn new_symmetric() -> Self {
        let mut key = [0u8; 32];
        talkrypt_crypto::fill_secure(&mut key);
        Self { key, qrom: true }
    }

    /// A token that reports a CLASSICAL (not QROM-safe) wrap primitive (e.g. an
    /// RSA/ECC PKCS#11 key), for exercising the passphrase-required path.
    pub fn new_classical() -> Self {
        let mut t = Self::new_symmetric();
        t.qrom = false;
        t
    }
}

impl HsmToken for MockHsmToken {
    fn token_wrap(&self, kek: &[u8]) -> Result<Vec<u8>, WrapError> {
        let mut nonce = [0u8; 12];
        talkrypt_crypto::fill_secure(&mut nonce);
        let ct = talkrypt_crypto::aead::seal(&self.key, &nonce, kek, b"tk-hsm-mock")
            .map_err(|e| WrapError(format!("mock hsm seal: {e}")))?;
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn token_unwrap(&self, blob: &[u8]) -> Result<Vec<u8>, WrapError> {
        if blob.len() < 12 {
            return Err(WrapError("mock hsm: short blob".into()));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&blob[..12]);
        talkrypt_crypto::aead::open(&self.key, &nonce, &blob[12..], b"tk-hsm-mock")
            .map_err(|e| WrapError(format!("mock hsm open: {e}")))
    }

    fn qrom_safe(&self) -> bool {
        self.qrom
    }
}

#[cfg(feature = "pkcs11")]
pub mod pkcs11;

#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_core::seal::{seal, unseal, SealOptions};
    use talkrypt_core::CustodyTier;

    const KEK: &[u8] = b"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\
                         \xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf";

    fn wrapper_symmetric() -> HsmKeyWrapper {
        HsmKeyWrapper::new(Arc::new(MockHsmToken::new_symmetric()))
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let w = wrapper_symmetric();
        let blob = w.wrap(KEK).unwrap();
        assert!(blob.windows(KEK.len()).all(|x| x != KEK));
        assert_eq!(w.unwrap(&blob).unwrap(), KEK);
    }

    #[test]
    fn symmetric_token_is_qrom_safe_classical_is_not() {
        assert!(HsmKeyWrapper::new(Arc::new(MockHsmToken::new_symmetric())).qrom_safe());
        assert!(!HsmKeyWrapper::new(Arc::new(MockHsmToken::new_classical())).qrom_safe());
    }

    #[test]
    fn a_different_token_cannot_unwrap() {
        let a = wrapper_symmetric();
        let b = wrapper_symmetric(); // different in-memory key == different token
        let blob = a.wrap(KEK).unwrap();
        assert!(b.unwrap(&blob).is_err());
    }

    #[test]
    fn tampered_blob_fails() {
        let w = wrapper_symmetric();
        let blob = w.wrap(KEK).unwrap();
        for idx in [5usize, blob.len() / 2, blob.len() - 1] {
            let mut t = blob.clone();
            t[idx] ^= 0x01;
            assert!(w.unwrap(&t).is_err(), "tamper at {idx} should fail");
        }
    }

    #[test]
    fn bad_header_rejected() {
        let w = wrapper_symmetric();
        assert!(w.unwrap(b"").is_err());
        assert!(w.unwrap(b"nope").is_err());
    }

    /// A QROM-safe token (AES-256) permits a hardware-only, passphrase-less seal
    /// through the core; a classical token is refused hardware-only and needs a
    /// passphrase.
    #[test]
    fn qrom_token_enables_hardware_only_seal() {
        let seed = [0x33u8; 32];
        let w = wrapper_symmetric();
        let blob = seal(
            &seed,
            SealOptions {
                passphrase: None,
                wrapper: Some(&w),
                ..Default::default()
            },
        )
        .expect("symmetric token attests qrom_safe → hardware-only allowed");
        assert_eq!(
            talkrypt_core::seal::tier_of(&blob).unwrap(),
            CustodyTier::HardwareBacked
        );
        assert_eq!(unseal(&blob, None, Some(&w)).unwrap(), seed);

        // Classical token: hardware-only is refused; passphrase makes it succeed.
        let wc = HsmKeyWrapper::new(Arc::new(MockHsmToken::new_classical()));
        assert!(seal(
            &seed,
            SealOptions { passphrase: None, wrapper: Some(&wc), ..Default::default() }
        )
        .is_err());
        let blob = seal(
            &seed,
            SealOptions { passphrase: Some(b"pw"), wrapper: Some(&wc), ..Default::default() },
        )
        .unwrap();
        assert_eq!(unseal(&blob, Some(b"pw"), Some(&wc)).unwrap(), seed);
    }
}
