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

use talkrypt_crypto::{
    belongs_to_account, verify_grouping_cert, IdentityChain, IdentityPublic, SignedCert,
};
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

/// The concrete proof payload for the audited Backend-0 predicates. Each carries a
/// `ctx_sig` — the presented leaf/member key signing the chat `context` — which
/// binds the proof to THIS chat and to a holder of the private key (so a captured
/// chain/cert can't be replayed by someone who doesn't hold the leaf).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkageProof {
    /// For `LinkedToAccount` / `DerivedFromNamed`: a cert chain + the leaf's ctx sig.
    Chain { chain: IdentityChain, ctx_sig: Vec<u8> },
    /// For `Grouping`: the member public key, its grouping cert, + the member's ctx sig.
    Grouping { member: IdentityPublic, cert: SignedCert, ctx_sig: Vec<u8> },
}

impl LinkageProof {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            LinkageProof::Chain { chain, ctx_sig } => {
                w.put_u8(0);
                w.put_bytes(&chain.encode());
                w.put_bytes(ctx_sig);
            }
            LinkageProof::Grouping { member, cert, ctx_sig } => {
                w.put_u8(1);
                w.put_bytes(&member.sig_vk);
                w.put_bytes(&cert.encode());
                w.put_bytes(ctx_sig);
            }
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Option<LinkageProof> {
        let mut r = Reader::new(bytes);
        let p = match r.get_u8().ok()? {
            0 => LinkageProof::Chain {
                chain: IdentityChain::decode(r.get_bytes().ok()?).ok()?,
                ctx_sig: r.get_vec().ok()?,
            },
            1 => LinkageProof::Grouping {
                member: IdentityPublic { sig_vk: r.get_vec().ok()? },
                cert: SignedCert::decode(r.get_bytes().ok()?).ok()?,
                ctx_sig: r.get_vec().ok()?,
            },
            _ => return None,
        };
        r.finish().ok()?;
        Some(p)
    }
}

/// The audited Phase-B0 backend: verifies Backend-0 predicates purely from ML-DSA
/// cert machinery (`account.rs` + `grouping.rs`). `now` is the verifier's clock.
pub struct MlDsaCertBackend {
    pub now: u64,
}

impl ProofBackend for MlDsaCertBackend {
    fn verify(&self, claim: &Claim, proof: &Proof) -> Verdict {
        let Some(lp) = LinkageProof::decode(&proof.0) else { return Verdict::Fail };
        let ok = match (&claim.predicate, &lp) {
            (Predicate::LinkedToAccount { account_fp }, LinkageProof::Chain { chain, ctx_sig }) => {
                self.verify_chain_to_account(chain, ctx_sig, &claim.context)
                    .map(|acct_fp| &acct_fp == account_fp)
                    .unwrap_or(false)
            }
            (Predicate::DerivedFromNamed { ancestor_fp }, LinkageProof::Chain { chain, ctx_sig }) => {
                self.verify_chain_to_account(chain, ctx_sig, &claim.context).is_some()
                    && chain.links.iter().any(|c| c.issuer.fingerprint() == *ancestor_fp)
            }
            (Predicate::Grouping { grouping_pub }, LinkageProof::Grouping { member, cert, ctx_sig }) => {
                let gp = IdentityPublic { sig_vk: grouping_pub.clone() };
                verify_grouping_cert(&gp, cert, member, self.now)
                    && member.verify(&claim.context, ctx_sig).is_ok()
            }
            _ => false, // predicate / proof-shape mismatch
        };
        if ok { Verdict::Pass } else { Verdict::Fail }
    }
}

impl MlDsaCertBackend {
    /// Verify a chain roots at an account and its leaf signed `context`; returns the
    /// account fingerprint on success. The account is the chain root issuer.
    fn verify_chain_to_account(
        &self,
        chain: &IdentityChain,
        ctx_sig: &[u8],
        context: &[u8; 32],
    ) -> Option<[u8; 48]> {
        let account = chain.links.first()?.issuer.clone();
        let leaf = chain.leaf()?;
        if !belongs_to_account(&account, chain, leaf, self.now) {
            return None;
        }
        if leaf.verify(context, ctx_sig).is_err() {
            return None;
        }
        Some(account.fingerprint())
    }
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

    #[test]
    fn grouping_proof_verifies_and_hides_account() {
        use talkrypt_crypto::{GroupingKey, IdentityKeyPair};
        let now = 100u64;
        let ctx = [5u8; 32];
        let g = GroupingKey::from_root_seed([1u8; 32]);
        let member = IdentityKeyPair::generate();
        let cert = g.certify(&ctx, member.public(), 0, 10_000);
        let ctx_sig = member.sign(&ctx);
        let proof = Proof(
            LinkageProof::Grouping { member: member.public().clone(), cert, ctx_sig }.encode(),
        );
        let g_c_pub = g.derive_for_chat(&ctx).public().sig_vk.clone();
        let backend = MlDsaCertBackend { now };

        // Passes under the chat's grouping pub; the claim carries NO account_fp.
        let claim = Claim { predicate: Predicate::Grouping { grouping_pub: g_c_pub }, context: ctx };
        assert_eq!(backend.verify(&claim, &proof), Verdict::Pass);

        // A different chat's grouping pub must NOT verify this proof.
        let bad = Claim {
            predicate: Predicate::Grouping { grouping_pub: g.derive_for_chat(&[6u8; 32]).public().sig_vk.clone() },
            context: ctx,
        };
        assert_eq!(backend.verify(&bad, &proof), Verdict::Fail);
    }

    #[test]
    fn linked_to_account_verifies_and_wrong_context_fails() {
        use talkrypt_crypto::{IdentityChain, IdentityKeyPair};
        let now = 100u64;
        let ctx = [7u8; 32];
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", 0, 10_000);
        let ctx_sig = device.sign(&ctx);
        let proof = Proof(LinkageProof::Chain { chain, ctx_sig }.encode());
        let backend = MlDsaCertBackend { now };

        let claim = Claim {
            predicate: Predicate::LinkedToAccount { account_fp: account.public().fingerprint() },
            context: ctx,
        };
        assert_eq!(backend.verify(&claim, &proof), Verdict::Pass);

        // A claim for a DIFFERENT account fails.
        let other = IdentityKeyPair::generate();
        let wrong = Claim {
            predicate: Predicate::LinkedToAccount { account_fp: other.public().fingerprint() },
            context: ctx,
        };
        assert_eq!(backend.verify(&wrong, &proof), Verdict::Fail);

        // A proof whose ctx_sig is for a DIFFERENT context fails (anti-replay).
        let replayed = Claim {
            predicate: Predicate::LinkedToAccount { account_fp: account.public().fingerprint() },
            context: [9u8; 32],
        };
        assert_eq!(backend.verify(&replayed, &proof), Verdict::Fail);
    }
}
