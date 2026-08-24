//! Sub-spec C vouching: ML-DSA-signed, account-bound, per-chat trust attestations.
//!
//! Mirrors the B0 `linkage.rs` seam — pure, unit-testable types the engine wires
//! behind `VOUCH_SENTINEL = 0xF7`. A vouch only ever ADDS a positive hint (spec
//! §0.5 invariant 1); there is no negative-vouch primitive. The only negativity in
//! the whole system is the sybil ANTIBODY backfire (`evaluate`, spec §6a): a caught
//! puppeteer's self-inflicted, evidence-gated reversal — never a signal one person
//! can aim at another. Design:
//! `docs/superpowers/specs/2026-08-20-subspec-c-vouching-design.md`.

use talkrypt_crypto::{IdentityKeyPair, IdentityPublic};
use talkrypt_wire::{Reader, Writer};

/// What a vouch attests trust for (spec §1). Plural by design: account = durable;
/// name-binding = "this callsign really is this account here"; leaf = minimal opsec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VouchTarget {
    Account([u8; 48]),
    NameBinding { account: [u8; 48], name_tag: [u8; 8] },
    Leaf([u8; 48]),
}

impl VouchTarget {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            VouchTarget::Account(fp) => {
                w.put_u8(0);
                w.put_bytes(fp);
            }
            VouchTarget::NameBinding { account, name_tag } => {
                w.put_u8(1);
                w.put_bytes(account);
                w.put_bytes(name_tag);
            }
            VouchTarget::Leaf(fp) => {
                w.put_u8(2);
                w.put_bytes(fp);
            }
        }
        w.into_vec()
    }
    pub fn decode(bytes: &[u8]) -> Option<VouchTarget> {
        let mut r = Reader::new(bytes);
        let t = match r.get_u8().ok()? {
            0 => VouchTarget::Account(fp48(r.get_bytes().ok()?)?),
            1 => VouchTarget::NameBinding {
                account: fp48(r.get_bytes().ok()?)?,
                name_tag: fp8(r.get_bytes().ok()?)?,
            },
            2 => VouchTarget::Leaf(fp48(r.get_bytes().ok()?)?),
            _ => return None, // unknown tag — append-only-safe
        };
        r.finish().ok()?;
        Some(t)
    }
}

fn fp48(b: &[u8]) -> Option<[u8; 48]> {
    (b.len() == 48).then(|| {
        let mut a = [0u8; 48];
        a.copy_from_slice(b);
        a
    })
}
fn fp8(b: &[u8]) -> Option<[u8; 8]> {
    (b.len() == 8).then(|| {
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        a
    })
}

/// A single account-signed trust attestation, scoped to one chat (spec §1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vouch {
    pub target: VouchTarget,
    pub context: [u8; 32],
    pub epoch: u64,
    pub asserted_at: u64,
    pub sig: Vec<u8>,
    pub voucher: IdentityPublic,
}

impl Vouch {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_bytes(&self.target.encode());
        w.put_bytes(&self.context);
        w.put_u32((self.epoch >> 32) as u32);
        w.put_u32(self.epoch as u32);
        w.put_u32((self.asserted_at >> 32) as u32);
        w.put_u32(self.asserted_at as u32);
        w.put_bytes(&self.sig);
        w.put_bytes(&self.voucher.sig_vk);
        w.into_vec()
    }
    pub fn decode(bytes: &[u8]) -> Option<Vouch> {
        let mut r = Reader::new(bytes);
        let target = VouchTarget::decode(r.get_bytes().ok()?)?;
        let cb = r.get_bytes().ok()?;
        if cb.len() != 32 {
            return None;
        }
        let mut context = [0u8; 32];
        context.copy_from_slice(cb);
        let epoch = ((r.get_u32().ok()? as u64) << 32) | r.get_u32().ok()? as u64;
        let asserted_at = ((r.get_u32().ok()? as u64) << 32) | r.get_u32().ok()? as u64;
        let sig = r.get_vec().ok()?;
        let voucher = IdentityPublic { sig_vk: r.get_vec().ok()? };
        r.finish().ok()?;
        Some(Vouch { target, context, epoch, asserted_at, sig, voucher })
    }
}

const VOUCH_SIG_LABEL: &[u8] = b"talkrypt-vouch-v1";

/// The exact bytes an account signs for a vouch: label ‖ target ‖ context ‖ epoch ‖
/// asserted_at. The label domain-separates vouch sigs from any other ML-DSA use of
/// the account key.
pub fn vouch_signed_bytes(
    target: &VouchTarget,
    context: &[u8; 32],
    epoch: u64,
    asserted_at: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_bytes(VOUCH_SIG_LABEL);
    w.put_bytes(&target.encode());
    w.put_bytes(context);
    w.put_u32((epoch >> 32) as u32);
    w.put_u32(epoch as u32);
    w.put_u32((asserted_at >> 32) as u32);
    w.put_u32(asserted_at as u32);
    w.into_vec()
}

impl Vouch {
    pub fn signed_bytes(&self) -> Vec<u8> {
        vouch_signed_bytes(&self.target, &self.context, self.epoch, self.asserted_at)
    }
    /// True iff the sig is a valid account signature over this vouch's signed bytes.
    /// Account-bound + context-bound: a vouch cannot be forged without the voucher's
    /// private key, nor replayed into another chat (context differs).
    pub fn verify(&self) -> bool {
        self.voucher.verify(&self.signed_bytes(), &self.sig).is_ok()
    }
    /// The 48-byte fp of the identity this vouch is ABOUT (account or leaf); used to
    /// reject self-vouch (voucher == target) and to key the ledger.
    pub fn target_fp(&self) -> [u8; 48] {
        match &self.target {
            VouchTarget::Account(fp) | VouchTarget::Leaf(fp) => *fp,
            VouchTarget::NameBinding { account, .. } => *account,
        }
    }
}

/// Produce a signed vouch from the voucher's ACCOUNT key.
pub fn sign_vouch(
    voucher: &IdentityKeyPair,
    target: VouchTarget,
    context: [u8; 32],
    epoch: u64,
    asserted_at: u64,
) -> Vouch {
    let sig = voucher.sign(&vouch_signed_bytes(&target, &context, epoch, asserted_at));
    Vouch { target, context, epoch, asserted_at, sig, voucher: voucher.public().clone() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vouch_target_roundtrips_all_variants() {
        for t in [
            VouchTarget::Account([1u8; 48]),
            VouchTarget::NameBinding { account: [2u8; 48], name_tag: [3u8; 8] },
            VouchTarget::Leaf([4u8; 48]),
        ] {
            assert_eq!(VouchTarget::decode(&t.encode()).as_ref(), Some(&t));
        }
        assert!(VouchTarget::decode(&[0x7F]).is_none()); // unknown tag → None
        assert!(VouchTarget::decode(&[]).is_none());
    }

    #[test]
    fn vouch_roundtrips() {
        let kp = IdentityKeyPair::generate();
        let v = Vouch {
            target: VouchTarget::Account([9u8; 48]),
            context: [7u8; 32],
            epoch: 5,
            asserted_at: 123,
            sig: vec![0xAB; 16],
            voucher: kp.public().clone(),
        };
        assert_eq!(Vouch::decode(&v.encode()).as_ref(), Some(&v));
        assert!(Vouch::decode(&[0u8; 2]).is_none());
    }

    #[test]
    fn signed_vouch_verifies_and_rejects_tampering() {
        let voucher = IdentityKeyPair::generate();
        let v = sign_vouch(&voucher, VouchTarget::Account([5u8; 48]), [1u8; 32], 3, 100);
        assert!(v.verify(), "honest vouch verifies");
        let mut bad = v.clone();
        bad.target = VouchTarget::Account([6u8; 48]);
        assert!(!bad.verify());
        let mut replay = v.clone();
        replay.context = [2u8; 32];
        assert!(!replay.verify());
        let mut swapped = v.clone();
        swapped.voucher = IdentityKeyPair::generate().public().clone();
        assert!(!swapped.verify());
    }

    #[test]
    fn self_vouch_is_detectable_and_revoke_is_higher_epoch() {
        let acct = IdentityKeyPair::generate();
        let selfv = sign_vouch(
            &acct,
            VouchTarget::Account(acct.public().fingerprint()),
            [1u8; 32],
            1,
            10,
        );
        assert_eq!(selfv.target_fp(), acct.public().fingerprint());
        assert_eq!(selfv.voucher.fingerprint(), acct.public().fingerprint());
        let v1 = sign_vouch(&acct, VouchTarget::Leaf([2u8; 48]), [1u8; 32], 1, 10);
        let v2 = sign_vouch(&acct, VouchTarget::Leaf([2u8; 48]), [1u8; 32], 2, 20);
        assert!(v2.epoch > v1.epoch);
    }
}
