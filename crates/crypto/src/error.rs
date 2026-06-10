//! Error type for the crypto layer.
//!
//! Decryption-path errors are intentionally coarse: a caller cannot tell
//! *why* an AEAD open failed (bad tag vs. bad key vs. unknown sender), only
//! that it failed. This avoids handing an attacker a decryption oracle.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    /// AEAD authentication/decryption failed. Deliberately uninformative.
    #[error("decryption failed")]
    DecryptionFailed,

    /// A serialized key, signature, or ciphertext had the wrong length/shape.
    #[error("malformed crypto material: {0}")]
    Malformed(&'static str),

    /// Signature verification failed.
    #[error("signature verification failed")]
    BadSignature,

    /// The skipped-message-key budget was exceeded (possible DoS attempt).
    #[error("too many skipped messages (max {0})")]
    TooManySkipped(usize),

    /// A message key for this (chain, index) was already used — replay.
    #[error("message key already used (replay)")]
    Replay,

    /// Wire (de)serialization error from the framing layer.
    #[error("wire error: {0}")]
    Wire(#[from] talkrypt_wire::WireError),

    /// Requested crypto suite is not registered.
    #[error("unknown crypto suite: {0}")]
    UnknownSuite(String),

    /// A suite's advertised primitives fall below the configured floor.
    #[error("suite '{0}' rejected: below security floor")]
    BelowFloor(String),

    /// A power-on self-test (known-answer / pairwise-consistency) failed — a
    /// primitive is broken or corrupted; the module must not be used.
    #[error("crypto self-test failed: {0}")]
    SelfTest(&'static str),
}

pub type Result<T> = core::result::Result<T, CryptoError>;
