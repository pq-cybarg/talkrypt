//! talkrypt-crypto — the security-critical core.
//!
//! CNSA 2.0 algorithm set, all pure-Rust (RustCrypto):
//!   * KEM:        ML-KEM-1024 (FIPS 203) + X25519, combined as a hybrid
//!   * Signature:  ML-DSA-87 (FIPS 204)
//!   * AEAD:       AES-256-GCM
//!   * Hash/KDF:   SHA-384 / HKDF-SHA384
//!
//! Forward secrecy and post-compromise recovery come from a Double Ratchet
//! whose asymmetric step is the hybrid KEM (see `ratchet`, `hybrid`).
//!
//! **Honesty:** these are the CNSA 2.0 *algorithms*; this crate is not a
//! FIPS-validated module. With the workspace `fips` feature (planned) the same
//! APIs route through a validated backend.

pub mod account;
pub mod aead;
pub mod beacon;
pub mod error;
pub mod group;
pub mod hash;
pub mod hybrid;
pub mod identity;
pub mod kdf;
pub mod mls;
pub mod noise;
pub mod ratchet;
pub mod suite;
pub mod treekem;

pub use account::{
    belongs_to_account, cross_compare, IdentityChain, SignedCert, SignedClaim, UsernameClaim,
};
pub use beacon::BeaconBody;
pub use error::{CryptoError, Result};
pub use group::{GroupSession, MemberId};
pub use hybrid::{KemPosture, KemProfile};
pub use identity::{IdentityKeyPair, IdentityPublic, FINGERPRINT_LEN};
pub use noise::NoiseSession;
pub use ratchet::{Session, MAX_SKIP};
pub use suite::{
    dr_suite_id, noise_suite_id, offered_profiles, scheme_hash, CryptoSuite, DoubleRatchetSuite,
    NoiseSuite, SecurityLevel, SuiteDescriptor, SuiteRegistry, DEFAULT_SUITE_ID, NOISE_SUITE_ID,
    SCHEME_HASH_LEN,
};
pub use treekem::{Commit, KeyPackage, LeafKeyPair, TreeKemGroup, Welcome};
