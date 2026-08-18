//! Sub-spec B linkage / predicate seam.
//!
//! One shape underlies all of Sub-spec B: a prover asserts a **predicate**; a
//! verifier learns only **pass/fail**; identity is revealed only as far as the
//! predicate requires. Phase B0 defines the abstraction and the audited ML-DSA
//! cert backend (`MlDsaCertBackend`, see below). Backend-1 (zero-knowledge)
//! predicate tags `0x10+` are RESERVED here and decode to `None` until that
//! review-gated crate lands.
//!
//! Design: `docs/superpowers/specs/2026-07-31-subspec-b-linkage-opsec-predicate-proofs-design.md`.

use talkrypt_wire::{Reader, Writer};

/// A statement a prover wants a verifier to accept, revealing no more than the
/// predicate requires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predicate {
    /// "These leaves share THIS account" (transparent linkage). tag 0
    LinkedToAccount { account_fp: [u8; 48] },
    /// "These leaves share this (per-chat) grouping key" (account-hidden). tag 1.
    /// `grouping_pub` = the chat-derived grouping public key bytes (`IdentityPublic.sig_vk`).
    Grouping { grouping_pub: Vec<u8> },
    /// "I descend from THIS specific known identity" (ancestor revealed). tag 2
    DerivedFromNamed { ancestor_fp: [u8; 48] },
    // 0x10+ reserved for Backend 1: MemberOfKnownSet, DerivedFromKnownSet, Attribute, And/Or.
}

impl Predicate {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Predicate::LinkedToAccount { account_fp } => {
                w.put_u8(0);
                w.put_bytes(account_fp);
            }
            Predicate::Grouping { grouping_pub } => {
                w.put_u8(1);
                w.put_bytes(grouping_pub);
            }
            Predicate::DerivedFromNamed { ancestor_fp } => {
                w.put_u8(2);
                w.put_bytes(ancestor_fp);
            }
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Option<Predicate> {
        let mut r = Reader::new(bytes);
        let p = match r.get_u8().ok()? {
            0 => Predicate::LinkedToAccount { account_fp: fp48(r.get_bytes().ok()?)? },
            1 => Predicate::Grouping { grouping_pub: r.get_bytes().ok()?.to_vec() },
            2 => Predicate::DerivedFromNamed { ancestor_fp: fp48(r.get_bytes().ok()?)? },
            _ => return None, // Backend-1 / unknown — append-only-safe
        };
        r.finish().ok()?;
        Some(p)
    }
}

fn fp48(b: &[u8]) -> Option<[u8; 48]> {
    (b.len() == 48).then(|| {
        let mut a = [0u8; 48];
        a.copy_from_slice(b);
        a
    })
}

/// A predicate plus the chat it is scoped to (anti cross-chat replay).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub predicate: Predicate,
    pub context: [u8; 32],
}

/// The opaque proof bytes a backend produces / consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof(pub Vec<u8>);

/// A verifier learns ONLY pass/fail — never which element / ancestor / attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
}

/// Pluggable proof backend. Phase B0 ships `MlDsaCertBackend`; Backend 1 (ZK) is a
/// separate, review-gated implementor behind the `zk` feature.
pub trait ProofBackend {
    fn verify(&self, claim: &Claim, proof: &Proof) -> Verdict;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_roundtrips_backend0_variants() {
        for p in [
            Predicate::LinkedToAccount { account_fp: [1u8; 48] },
            Predicate::Grouping { grouping_pub: vec![2u8; 32] },
            Predicate::DerivedFromNamed { ancestor_fp: [3u8; 48] },
        ] {
            assert_eq!(Predicate::decode(&p.encode()).as_ref(), Some(&p));
        }
    }

    #[test]
    fn unknown_predicate_tag_decodes_none() {
        // 0x10+ is reserved for Backend 1; a B0 client drops it gracefully.
        assert!(Predicate::decode(&[0x10u8]).is_none());
        assert!(Predicate::decode(&[0xFEu8]).is_none());
        assert!(Predicate::decode(&[]).is_none());
    }
}
