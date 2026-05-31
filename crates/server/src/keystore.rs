//! Encrypted-at-rest sealing for a persistent onion-service key (or any
//! secret). The onion secret key is never written in plaintext.
//!
//! Format: `salt(16) ‖ nonce(12) ‖ AES-256-GCM(ciphertext‖tag)`.
//! The 256-bit AEAD key is derived from the passphrase with **Argon2id** over
//! the random salt, so each sealed blob is independently keyed.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = SALT_LEN + NONCE_LEN;

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("key derivation failed")]
    Kdf,
    #[error("sealed blob is malformed or truncated")]
    Malformed,
    #[error("decryption failed (wrong passphrase or corrupt data)")]
    Decrypt,
}

fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], KeystoreError> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|_| KeystoreError::Kdf)?;
    Ok(key)
}

/// Seal `plaintext` under `passphrase`. Returns `salt ‖ nonce ‖ ciphertext`.
pub fn seal(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let mut key = derive_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| KeystoreError::Kdf)?;
    key.zeroize();

    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| KeystoreError::Decrypt)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unseal a blob produced by [`seal`]. Wrong passphrase ⇒ `Decrypt`.
pub fn unseal(passphrase: &[u8], blob: &[u8]) -> Result<Vec<u8>, KeystoreError> {
    if blob.len() < HEADER_LEN + 16 {
        return Err(KeystoreError::Malformed);
    }
    let salt = &blob[..SALT_LEN];
    let nonce = &blob[SALT_LEN..HEADER_LEN];
    let ct = &blob[HEADER_LEN..];

    let mut key = derive_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| KeystoreError::Kdf)?;
    key.zeroize();

    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| KeystoreError::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_roundtrip() {
        let secret = b"onion-ed25519-secret-key-material";
        let blob = seal(b"correct horse battery staple", secret).unwrap();
        let out = unseal(b"correct horse battery staple", &blob).unwrap();
        assert_eq!(out, secret);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let blob = seal(b"passphrase-A", b"secret").unwrap();
        assert!(matches!(
            unseal(b"passphrase-B", &blob),
            Err(KeystoreError::Decrypt)
        ));
    }

    #[test]
    fn no_plaintext_key_in_blob() {
        // The 32-byte AEAD key must never appear; check the secret plaintext
        // itself is absent from the sealed bytes.
        let secret = b"VERY-DISTINCTIVE-SECRET-0xDEADBEEF";
        let blob = seal(b"pw", secret).unwrap();
        assert!(
            blob.windows(secret.len()).all(|w| w != secret),
            "plaintext secret leaked into sealed blob"
        );
    }

    #[test]
    fn distinct_salts_yield_distinct_blobs() {
        let a = seal(b"pw", b"same").unwrap();
        let b = seal(b"pw", b"same").unwrap();
        assert_ne!(a, b, "salt/nonce randomization should differ");
    }

    #[test]
    fn truncated_blob_rejected() {
        let blob = seal(b"pw", b"secret").unwrap();
        assert!(matches!(
            unseal(b"pw", &blob[..10]),
            Err(KeystoreError::Malformed)
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let mut blob = seal(b"pw", b"secret").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(unseal(b"pw", &blob), Err(KeystoreError::Decrypt)));
    }
}
