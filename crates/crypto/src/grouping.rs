//! Per-chat, account-hidden **grouping key** for Sub-spec B opsec-selective linkage.
//!
//! A grouping discloses that several leaf identities are one person WITHIN a chat,
//! without revealing the account AND without the grouping key becoming a cross-chat
//! linkage vector: the presented keypair is derived per chat from a long-term root
//! seed, so the same grouping shows a *different* public key in every chat. See
//! `docs/superpowers/specs/2026-07-31-subspec-b-linkage-opsec-predicate-proofs-design.md` §3b.

use crate::account::{SignedCert, CLOCK_SKEW_TOLERANCE};
use crate::identity::{IdentityKeyPair, IdentityPublic};
use crate::kdf::mac_kdf;

const GROUPING_KDF_LABEL: &[u8] = b"talkrypt-grouping-key-v1";

/// A long-term grouping identity, held only by its owner. It is NEVER certified
/// upward to the account (that would relink it); its per-chat derivations are what
/// get presented in chats.
pub struct GroupingKey {
    root_seed: [u8; 32],
}

impl GroupingKey {
    /// Wrap a 32-byte root seed (a sibling of a segment seed; account-unlinkable).
    pub fn from_root_seed(root_seed: [u8; 32]) -> Self {
        Self { root_seed }
    }

    /// Fresh grouping keypair for THIS chat:
    /// `G_c = ML-DSA-keygen( KMAC256(root_seed, chat_context, "talkrypt-grouping-key-v1") )`.
    /// Deterministic per chat, unlinkable across chats.
    pub fn derive_for_chat(&self, chat_context: &[u8; 32]) -> IdentityKeyPair {
        let mut seed = [0u8; 32];
        mac_kdf(&self.root_seed, chat_context, GROUPING_KDF_LABEL, &mut seed);
        let kp = IdentityKeyPair::from_secret_bytes(seed);
        seed.iter_mut().for_each(|b| *b = 0); // wipe the transient derived seed
        kp
    }

    /// Certify that `member` is in this grouping, in this chat (issued under `G_c`).
    pub fn certify(
        &self,
        chat_context: &[u8; 32],
        member: &IdentityPublic,
        now: u64,
        exp: u64,
    ) -> SignedCert {
        let g_c = self.derive_for_chat(chat_context);
        SignedCert::issue(&g_c, member, "group", now, exp)
    }
}

/// Verify a grouping cert binds `member` under `grouping_pub` (the chat's derived
/// key), valid at `now`. Fail-closed: the issuer inside the cert MUST equal the
/// presented `grouping_pub` (else an attacker could self-issue), the subject MUST
/// equal `member`, the validity window must hold (with clock-skew tolerance), and
/// the signature must verify.
pub fn verify_grouping_cert(
    grouping_pub: &IdentityPublic,
    cert: &SignedCert,
    member: &IdentityPublic,
    now: u64,
) -> bool {
    grouping_pub.ct_eq(&cert.issuer)
        && member.ct_eq(&cert.cert.subject)
        && now.saturating_add(CLOCK_SKEW_TOLERANCE) >= cert.cert.valid_from
        && (cert.cert.expiry == 0 || now <= cert.cert.expiry.saturating_add(CLOCK_SKEW_TOLERANCE))
        && cert.verify_signature().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000;

    #[test]
    fn grouping_key_is_per_chat_unlinkable_but_deterministic() {
        let g = GroupingKey::from_root_seed([7u8; 32]);
        let ctx_a = [1u8; 32];
        let ctx_b = [2u8; 32];
        // Same chat context → same derived key (deterministic).
        assert_eq!(
            g.derive_for_chat(&ctx_a).public().sig_vk,
            g.derive_for_chat(&ctx_a).public().sig_vk
        );
        // Different chat context → different key (cross-chat unlinkable).
        assert_ne!(
            g.derive_for_chat(&ctx_a).public().sig_vk,
            g.derive_for_chat(&ctx_b).public().sig_vk
        );
    }

    #[test]
    fn grouping_cert_verifies_under_per_chat_key_only() {
        let g = GroupingKey::from_root_seed([9u8; 32]);
        let ctx = [3u8; 32];
        let member = IdentityKeyPair::generate();
        let cert = g.certify(&ctx, member.public(), NOW, NOW + 1000);
        let g_c_pub = g.derive_for_chat(&ctx).public().clone();
        // Verifies under the chat's grouping pub.
        assert!(verify_grouping_cert(&g_c_pub, &cert, member.public(), NOW));
        // Does NOT verify under a different chat's grouping pub (unlinkable + unforgeable).
        let g_other = g.derive_for_chat(&[4u8; 32]).public().clone();
        assert!(!verify_grouping_cert(&g_other, &cert, member.public(), NOW));
        // Does NOT verify for a different member.
        let other_member = IdentityKeyPair::generate();
        assert!(!verify_grouping_cert(&g_c_pub, &cert, other_member.public(), NOW));
        // Does NOT verify once expired (beyond the skew grace).
        assert!(!verify_grouping_cert(&g_c_pub, &cert, member.public(), NOW + 1000 + CLOCK_SKEW_TOLERANCE + 1));
    }
}
