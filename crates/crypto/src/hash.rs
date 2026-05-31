//! Central hash choice for the KDF and identity fingerprint.
//!
//! Default: **SHA3-384** (FIPS 202). ML-KEM and ML-DSA are already Keccak-based
//! internally, so SHA3-384 keeps the whole key-derivation/fingerprint stack on
//! one primitive family. Both options produce 48-byte output (192-bit level),
//! so [`crate::identity::FINGERPRINT_LEN`] is unchanged either way.
//!
//! Enable the `cnsa-sha2` feature to switch to **SHA-384** (SHA-2) for strict
//! CNSA 2.0 hash alignment.

/// The hash used for HKDF (all KDF steps) and the identity fingerprint.
#[cfg(not(feature = "cnsa-sha2"))]
pub type Hash = sha3::Sha3_384;

/// The hash used for HKDF and the identity fingerprint (CNSA-2.0 SHA-2 variant).
#[cfg(feature = "cnsa-sha2")]
pub type Hash = sha2::Sha384;

/// Short token naming the active hash, used in suite identifiers.
#[cfg(not(feature = "cnsa-sha2"))]
pub const HASH_TOKEN: &str = "sha3-384";
#[cfg(feature = "cnsa-sha2")]
pub const HASH_TOKEN: &str = "sha384";
