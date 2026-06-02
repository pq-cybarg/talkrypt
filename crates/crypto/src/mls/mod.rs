//! RFC 9420 (MLS) standards-track building blocks, validated against the MLS
//! working group's official test vectors.
//!
//! This brings the actual MLS layout/crypto online — distinct from talkrypt's
//! shipped PQ group ([`crate::treekem`]). Conformance status is tracked in
//! `docs/CONFORMANCE.md`; each module here passes the corresponding official
//! `mls-implementations` test vectors.

pub mod schedule;
pub mod secret_tree;
pub mod sign;
pub mod treemath;
