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
pub mod selftest;
pub mod suite;
pub mod treekem;

pub use account::{
    belongs_to_account, cross_compare, IdentityChain, Revocation, SignedCert, SignedClaim,
    UsernameClaim, CLOCK_SKEW_TOLERANCE,
};
pub use beacon::BeaconBody;
pub use error::{CryptoError, Result};
pub use group::{GroupSession, MemberId};
pub use hybrid::{KemPosture, KemProfile};
pub use identity::{IdentityKeyPair, IdentityPublic, FINGERPRINT_LEN};
pub use noise::NoiseSession;
pub use ratchet::{Session, MAX_SKIP};
pub use selftest::{ensure_self_tested, self_test};
pub use suite::{
    dr_suite_id, noise_suite_id, offered_profiles, scheme_hash, CryptoSuite, DoubleRatchetSuite,
    NoiseSuite, SecurityLevel, SuiteDescriptor, SuiteRegistry, DEFAULT_SUITE_ID, NOISE_SUITE_ID,
    SCHEME_HASH_LEN,
};
pub use treekem::{Commit, KeyPackage, LeafKeyPair, TreeKemGroup, Welcome};

/// Test-only helper: soundly verify that a value's `Drop` zeroed an inline
/// secret field (SECURITY-AUDIT F-3). Heap-allocates the value, runs its `Drop`
/// glue with `drop_in_place` — which does NOT free the allocation — then reads
/// the field bytes from the still-live allocation (no use-after-free) and
/// asserts they are zero, before freeing the memory itself. Under Miri
/// (`cargo +nightly miri test`) this verifies both the wipe and that the drop
/// path is free of undefined behavior; `zeroize` guarantees the volatile write
/// is not optimized away. Pass `field_off` via `core::mem::offset_of!` (field
/// order is not guaranteed without `#[repr(C)]`). The field pointer is re-derived
/// from the allocation pointer after the drop to respect Miri's aliasing model.
///
/// # Safety
/// `field_off..field_off+len` must lie within `T` and name plain-byte secret
/// state (no invalid bit patterns) that `T::drop` zeroes.
#[cfg(test)]
pub(crate) unsafe fn assert_drop_zeroes<T>(value: T, field_off: usize, len: usize) {
    let raw = Box::into_raw(Box::new(value));
    let base = raw as *const u8;
    assert!(
        (0..len).any(|i| *base.add(field_off + i) != 0),
        "precondition: secret field was already all-zero before drop"
    );
    core::ptr::drop_in_place(raw); // runs T::drop (the zeroizing Drop impl)
    let p = (raw as *const u8).add(field_off); // re-derive after drop
    for i in 0..len {
        assert_eq!(*p.add(i), 0, "secret byte {i} not wiped on drop");
    }
    std::alloc::dealloc(raw as *mut u8, std::alloc::Layout::new::<T>());
}
