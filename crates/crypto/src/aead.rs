//! AES-256-GCM AEAD helpers shared by all built-in suites.
//!
//! Each call uses a unique (key, nonce) derived per message from a KDF, so
//! GCM nonce reuse cannot occur. Open failures are uniform (no detail leaked).
//!
//! When the workspace `fips` feature is enabled, these route through the
//! `aws-lc-rs` FIPS-validated module; otherwise through RustCrypto `aes-gcm`.

use crate::error::{CryptoError, Result};
use crate::kdf::KEY_LEN;

#[cfg(not(feature = "fips"))]
mod backend {
    use super::*;
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Malformed("aead key"))?;
        cipher
            .encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
            .map_err(|_| CryptoError::Malformed("aead seal"))
    }

    pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::Malformed("aead key"))?;
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

#[cfg(feature = "fips")]
mod backend {
    use super::*;
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

    fn key(k: &[u8; KEY_LEN]) -> Result<LessSafeKey> {
        let unbound =
            UnboundKey::new(&AES_256_GCM, k).map_err(|_| CryptoError::Malformed("aead key"))?;
        Ok(LessSafeKey::new(unbound))
    }

    pub fn seal(k: &[u8; KEY_LEN], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = key(k)?;
        let mut buf = pt.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut buf,
        )
        .map_err(|_| CryptoError::Malformed("aead seal"))?;
        Ok(buf)
    }

    pub fn open(k: &[u8; KEY_LEN], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = key(k)?;
        let mut buf = ct.to_vec();
        let pt = key
            .open_in_place(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                &mut buf,
            )
            .map_err(|_| CryptoError::DecryptionFailed)?;
        Ok(pt.to_vec())
    }
}

/// Seal `pt` under `key`/`nonce` with `aad` bound; returns `ciphertext‖tag`.
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    backend::seal(key, nonce, pt, aad)
}

/// Open `ct` under `key`/`nonce` with `aad`; uniform error on failure.
pub fn open(key: &[u8; KEY_LEN], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    backend::open(key, nonce, ct, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; 12];
        let ct = seal(&key, &nonce, b"hello", b"aad").unwrap();
        assert_eq!(open(&key, &nonce, &ct, b"aad").unwrap(), b"hello");
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; 12];
        let ct = seal(&key, &nonce, b"hello", b"aad").unwrap();
        assert!(open(&key, &nonce, &ct, b"different").is_err());
    }

    #[test]
    fn tampered_ct_fails() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; 12];
        let mut ct = seal(&key, &nonce, b"hello", b"aad").unwrap();
        ct[0] ^= 1;
        assert!(open(&key, &nonce, &ct, b"aad").is_err());
    }
}
