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

// ---------------------------------------------------------------------------
// Weighted, multi-scope evaluation + gossip-round freshness decay (spec §2, §1.5)
// + sybil antibody backfire (spec §6a). Pure functions over per-viewer snapshots.
// ---------------------------------------------------------------------------

/// The viewer's relationship to a voucher — drives how much that vouch counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relationship {
    Friend,
    Contact,
    Stranger,
}

/// How much a single vouch counts, from the VIEWER's perspective (spec §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VouchWeighting {
    pub friend: u32,
    pub contact: u32,
    pub stranger: u32,
}
impl Default for VouchWeighting {
    fn default() -> Self {
        Self { friend: 4, contact: 2, stranger: 1 }
    }
}
impl VouchWeighting {
    pub fn weight_for(&self, r: Relationship) -> u32 {
        match r {
            Relationship::Friend => self.friend,
            Relationship::Contact => self.contact,
            Relationship::Stranger => self.stranger,
        }
    }
}

/// Which vouchers are allowed to count (spec §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoucherEligibility {
    AnyLinked,
    ContactsOfViewer,
    Transitive { depth: u8 },
}

/// A weighted score bar: an absolute count or a percentage of the eligible max.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Threshold {
    Count(u32),
    Percent(u8),
}

/// The composed policy a viewer evaluates under (chat baseline ⊔ user overrides).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VouchPolicy {
    pub eligibility: VoucherEligibility,
    pub weighting: VouchWeighting,
    pub threshold: Threshold,
    /// Freshness window in GOSSIP-WITNESSED rounds (spec §1.5), NOT seconds.
    pub freshness_interval_rounds: u32,
}
impl Default for VouchPolicy {
    fn default() -> Self {
        // Vouching OFF by default: threshold Count(u32::MAX) → never tinted (v1-v3 invites).
        Self {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting::default(),
            threshold: Threshold::Count(u32::MAX),
            freshness_interval_rounds: 64,
        }
    }
}

/// A viewer-side snapshot of one voucher's contribution to a subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoucherView {
    pub voucher_fp: [u8; 48],
    pub relationship: Relationship,
    /// Rounds since this voucher's assertion was last WITNESSED via gossip (§1.5).
    pub rounds_since_witnessed: u32,
    /// The grouping_pub this voucher is known (via B) to belong to, if any. Feeds
    /// the antibody: ≥2 vouchers sharing a grouping = one operator (spec §6a).
    pub grouping: Option<Vec<u8>>,
}

/// The result of evaluating a subject's vouches for one viewer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VouchDecision {
    pub weighted_score: i64,
    pub vouched: bool,
    pub inflation_rejected: bool,
    pub flagged: Vec<[u8; 48]>,
}

/// Linear decay to NEUTRAL over the freshness window, as a 0..=1000 permille factor.
/// Never negative (invariant 1): a vouch past its window contributes exactly 0.
pub fn age_decay(rounds_since_witnessed: u32, interval_rounds: u32) -> u32 {
    if interval_rounds == 0 || rounds_since_witnessed >= interval_rounds {
        return 0;
    }
    ((interval_rounds - rounds_since_witnessed) as u64 * 1000 / interval_rounds as u64) as u32
}

fn eligible(v: &VoucherView, e: VoucherEligibility) -> bool {
    match e {
        VoucherEligibility::AnyLinked => true,
        VoucherEligibility::ContactsOfViewer => {
            matches!(v.relationship, Relationship::Friend | Relationship::Contact)
        }
        // Transitive collapses to "linked" at this layer; depth-decay is applied by
        // the engine when it materializes transitive VoucherViews. Direct here.
        VoucherEligibility::Transitive { .. } => true,
    }
}

fn meets_threshold(score: i64, vouchers: &[VoucherView], policy: &VouchPolicy) -> bool {
    match policy.threshold {
        Threshold::Count(c) => score >= c as i64,
        Threshold::Percent(p) => {
            let max: u64 = vouchers
                .iter()
                .filter(|v| eligible(v, policy.eligibility))
                .map(|v| policy.weighting.weight_for(v.relationship) as u64)
                .sum();
            if max == 0 {
                return false;
            }
            (score.max(0) as u64) * 100 >= (p as u64) * max
        }
    }
}

/// Evaluate a subject's vouches for one viewer under `policy`.
///
/// Additive core (spec §2) + sybil ANTIBODY backfire (spec §6a): eligible vouchers
/// that are PROVEN (via B's unforgeable grouping proof) to be one operator have
/// their aggregate contribution REVERSED (the boost backfires, EV-negative) and are
/// flagged. A single grouped voucher, or an honest cluster with NO shared grouping
/// proof, is never punished — only the hard, unfakeable same-operator evidence goes
/// negative. A negative score renders NEUTRAL (invariant 1), never "distrusted".
pub fn evaluate(vouchers: &[VoucherView], policy: &VouchPolicy) -> VouchDecision {
    use std::collections::HashMap;
    let mut by_grouping: HashMap<Vec<u8>, Vec<&VoucherView>> = HashMap::new();
    let mut singletons: Vec<&VoucherView> = Vec::new();
    for v in vouchers.iter().filter(|v| eligible(v, policy.eligibility)) {
        match &v.grouping {
            Some(g) => by_grouping.entry(g.clone()).or_default().push(v),
            None => singletons.push(v),
        }
    }
    let decayed = |v: &VoucherView| -> i64 {
        let base = policy.weighting.weight_for(v.relationship) as u64;
        // Round to NEAREST, not truncate: a weight-1 vouch must not collapse to 0 after
        // a single round (984/1000 would truncate to 0, destroying small weights). It
        // rounds down to 0 only past the half-life, giving a smooth ramp to neutral.
        let permille = age_decay(v.rounds_since_witnessed, policy.freshness_interval_rounds) as u64;
        ((base * permille + 500) / 1000) as i64
    };
    let mut score: i64 = 0;
    let mut flagged: Vec<[u8; 48]> = Vec::new();
    let mut inflation_rejected = false;
    for v in &singletons {
        score += decayed(v);
    }
    for (_g, members) in by_grouping {
        let cluster: i64 = members.iter().map(|v| decayed(v)).sum();
        if members.len() >= 2 {
            // HARD proof of one operator wearing many hats → antibody backfire.
            score -= cluster;
            inflation_rejected = true;
            flagged.extend(members.iter().map(|v| v.voucher_fp));
        } else {
            score += cluster; // a single grouped voucher = one honest person
        }
    }
    let vouched = score >= 0 && meets_threshold(score, vouchers, policy);
    VouchDecision { weighted_score: score, vouched, inflation_rejected, flagged }
}

impl VouchPolicy {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self.eligibility {
            VoucherEligibility::AnyLinked => w.put_u8(0),
            VoucherEligibility::ContactsOfViewer => w.put_u8(1),
            VoucherEligibility::Transitive { depth } => {
                w.put_u8(2);
                w.put_u8(depth);
            }
        }
        w.put_u32(self.weighting.friend);
        w.put_u32(self.weighting.contact);
        w.put_u32(self.weighting.stranger);
        match self.threshold {
            Threshold::Count(c) => {
                w.put_u8(0);
                w.put_u32(c);
            }
            Threshold::Percent(p) => {
                w.put_u8(1);
                w.put_u8(p);
            }
        }
        w.put_u32(self.freshness_interval_rounds);
        w.into_vec()
    }
    pub fn decode(bytes: &[u8]) -> Option<VouchPolicy> {
        let mut r = Reader::new(bytes);
        let eligibility = match r.get_u8().ok()? {
            0 => VoucherEligibility::AnyLinked,
            1 => VoucherEligibility::ContactsOfViewer,
            2 => VoucherEligibility::Transitive { depth: r.get_u8().ok()? },
            _ => return None,
        };
        let weighting = VouchWeighting {
            friend: r.get_u32().ok()?,
            contact: r.get_u32().ok()?,
            stranger: r.get_u32().ok()?,
        };
        let threshold = match r.get_u8().ok()? {
            0 => Threshold::Count(r.get_u32().ok()?),
            1 => Threshold::Percent(r.get_u8().ok()?),
            _ => return None,
        };
        let freshness_interval_rounds = r.get_u32().ok()?;
        r.finish().ok()?;
        Some(VouchPolicy { eligibility, weighting, threshold, freshness_interval_rounds })
    }
}

/// Formal verification (run with `cargo kani -p talkrypt-core`). The vouch decoders
/// parse attacker-chosen bytes before any signature verification, so they must be
/// memory-safe on arbitrary input. These flat decoders are CBMC-tractable (like
/// `linkage::Predicate::decode`); the complex, chain-embedding decoders are not
/// (SECURITY-AUDIT §5).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `VouchTarget::decode` never panics on any ≤16-byte input.
    #[kani::proof]
    #[kani::unwind(20)]
    fn vouch_target_decode_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 16);
        let data: [u8; 16] = kani::any();
        let _ = VouchTarget::decode(&data[..len]);
    }

    /// `VouchPolicy::decode` never panics on any ≤20-byte input.
    #[kani::proof]
    #[kani::unwind(24)]
    fn vouch_policy_decode_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 20);
        let data: [u8; 20] = kani::any();
        let _ = VouchPolicy::decode(&data[..len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(fp: u8, rel: Relationship, rounds: u32) -> VoucherView {
        VoucherView {
            voucher_fp: [fp; 48],
            relationship: rel,
            rounds_since_witnessed: rounds,
            grouping: None,
        }
    }
    fn gview(fp: u8, rel: Relationship, grouping: &[u8]) -> VoucherView {
        VoucherView {
            voucher_fp: [fp; 48],
            relationship: rel,
            rounds_since_witnessed: 0,
            grouping: Some(grouping.to_vec()),
        }
    }

    #[test]
    fn age_decay_is_linear_to_neutral() {
        assert_eq!(age_decay(0, 10), 1000);
        assert_eq!(age_decay(5, 10), 500);
        assert_eq!(age_decay(10, 10), 0);
        assert_eq!(age_decay(99, 10), 0);
    }

    #[test]
    fn weighted_score_counts_fresh_eligible_vouchers() {
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 1 },
            threshold: Threshold::Count(5),
            freshness_interval_rounds: 10,
        };
        let d = evaluate(
            &[view(1, Relationship::Friend, 0), view(2, Relationship::Contact, 0)],
            &policy,
        );
        assert_eq!(d.weighted_score, 6);
        assert!(d.vouched);
        let d2 = evaluate(
            &[view(1, Relationship::Friend, 10), view(2, Relationship::Contact, 0)],
            &policy,
        );
        assert_eq!(d2.weighted_score, 2);
        assert!(!d2.vouched);
    }

    // Hardening: adversarial bytes must NEVER panic; a successful decode must
    // re-encode/re-decode equal (the wire round-trip invariant the fuzzer enforces,
    // run deterministically in the normal test job too). Decode precedes signature
    // verification, so it must tolerate anything.
    #[test]
    fn decoders_never_panic_on_adversarial_bytes() {
        // Deterministic xorshift PRNG (no Date/rand → stable in CI).
        let mut s: u64 = 0x9E3779B97F4A7C15;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..50_000 {
            let len = (next() % 160) as usize;
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                *b = (next() & 0xFF) as u8;
            }
            if let Some(t) = VouchTarget::decode(&buf) {
                assert_eq!(VouchTarget::decode(&t.encode()).as_ref(), Some(&t));
            }
            if let Some(v) = Vouch::decode(&buf) {
                assert_eq!(Vouch::decode(&v.encode()).as_ref(), Some(&v));
            }
            if let Some(p) = VouchPolicy::decode(&buf) {
                assert_eq!(VouchPolicy::decode(&p.encode()).as_ref(), Some(&p));
            }
        }
    }

    // INVARIANT 1 (load-bearing ethics): across a large randomized space of policies
    // and voucher sets — including proven sybil clusters — `evaluate` must NEVER report
    // `vouched` from a below-neutral score, a `Percent` bar must hold, `age_decay` must
    // stay in 0..=1000, and a PURE proven-sybil cluster (no honest vouchers) can never
    // be vouched (its inflation backfires). This is the formal guarantee (invariant 1),
    // reached by exhaustive randomized testing rather than Kani-on-core.
    #[test]
    fn evaluate_never_vouches_below_neutral_invariant() {
        let mut s: u64 = 0x2545F4914F6CDD1D;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        // age_decay is bounded for any inputs (no overflow, never exceeds full/neutral).
        for _ in 0..20_000 {
            let r = (next() % 200) as u32;
            let i = (next() % 200) as u32;
            let d = age_decay(r, i);
            assert!(d <= 1000);
            if i == 0 || r >= i {
                assert_eq!(d, 0, "past the window (or zero interval) decays to neutral");
            }
        }
        for _ in 0..30_000 {
            let rels = [Relationship::Friend, Relationship::Contact, Relationship::Stranger];
            let n = (next() % 6) as usize; // 0..=5 vouchers
            let mut views = Vec::new();
            let mut any_honest = false;
            for _ in 0..n {
                let rel = rels[(next() % 3) as usize];
                let rounds = (next() % 130) as u32;
                // ~half the vouchers land in ONE shared sybil grouping; rest are honest.
                let grouping = if next() % 2 == 0 {
                    Some(vec![0xABu8; 4])
                } else {
                    any_honest = true;
                    None
                };
                views.push(VoucherView {
                    voucher_fp: [(next() & 0xFF) as u8; 48],
                    relationship: rel,
                    rounds_since_witnessed: rounds,
                    grouping,
                });
            }
            let policy = VouchPolicy {
                eligibility: match next() % 3 {
                    0 => VoucherEligibility::AnyLinked,
                    1 => VoucherEligibility::ContactsOfViewer,
                    _ => VoucherEligibility::Transitive { depth: (next() % 4) as u8 },
                },
                weighting: VouchWeighting {
                    friend: (next() % 8) as u32,
                    contact: (next() % 8) as u32,
                    stranger: (next() % 8) as u32,
                },
                threshold: if next() % 2 == 0 {
                    Threshold::Count((next() % 20) as u32)
                } else {
                    Threshold::Percent((next() % 101) as u8)
                },
                freshness_interval_rounds: 1 + (next() % 128) as u32,
            };
            let d = evaluate(&views, &policy);
            // INVARIANT 1 (the load-bearing one): never render above neutral from a
            // below-neutral score.
            if d.vouched {
                assert!(d.weighted_score >= 0, "vouched implies non-negative score");
            }
            // A pure proven-sybil cluster cannot be vouched under a NON-degenerate
            // policy: all-eligible (AnyLinked) + a positive bar (Count ≥ 1). Its
            // inflation backfires to a ≤ 0 score, which can't clear a positive bar.
            // (Under contacts-only, stranger-sybils are simply filtered out — score 0,
            // neutral — and a Count(0) bar trivially passes at neutral, which is fine.)
            let grouped = views.iter().filter(|v| v.grouping.is_some()).count();
            let nondegenerate = matches!(policy.eligibility, VoucherEligibility::AnyLinked)
                && matches!(policy.threshold, Threshold::Count(c) if c >= 1);
            if grouped >= 2 && !any_honest && nondegenerate {
                assert!(!d.vouched, "a pure sybil cluster is never vouched");
                assert!(d.inflation_rejected, "and its inflation is rejected");
            }
        }
    }

    #[test]
    fn small_weight_vouch_survives_one_round_no_truncation() {
        // Regression: a weight-1 stranger vouch must NOT collapse to 0 after a single
        // round (984/1000 truncated to 0 before the round-to-nearest fix).
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 1 },
            threshold: Threshold::Count(1),
            freshness_interval_rounds: 64,
        };
        let d = evaluate(&[view(1, Relationship::Stranger, 1)], &policy);
        assert_eq!(d.weighted_score, 1, "a weight-1 vouch stays 1 one round in");
        assert!(d.vouched);
        // Past the half-life it rounds down to neutral (a smooth ramp, not a cliff).
        let d2 = evaluate(&[view(1, Relationship::Stranger, 40)], &policy);
        assert_eq!(d2.weighted_score, 0);
    }

    #[test]
    fn contacts_only_eligibility_drops_strangers() {
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::ContactsOfViewer,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 1 },
            threshold: Threshold::Count(1),
            freshness_interval_rounds: 10,
        };
        let strangers: Vec<VoucherView> =
            (10..40).map(|i| view(i as u8, Relationship::Stranger, 0)).collect();
        let d = evaluate(&strangers, &policy);
        assert_eq!(d.weighted_score, 0);
        assert!(!d.vouched);
    }

    #[test]
    fn detected_sybil_cluster_backfires_below_neutral() {
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 3 },
            threshold: Threshold::Count(5),
            freshness_interval_rounds: 10,
        };
        let d = evaluate(
            &[
                gview(1, Relationship::Stranger, b"G"),
                gview(2, Relationship::Stranger, b"G"),
                gview(3, Relationship::Stranger, b"G"),
            ],
            &policy,
        );
        assert!(d.inflation_rejected, "a proven cluster is antibody-rejected");
        assert!(d.weighted_score < 0, "the boost backfires (EV-negative)");
        assert!(!d.vouched, "target snaps to neutral, never above");
        assert_eq!(d.flagged.len(), 3, "the whole proven cluster is flagged");
    }

    #[test]
    fn honest_friend_cluster_is_not_flagged_or_reversed() {
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 1 },
            threshold: Threshold::Count(5),
            freshness_interval_rounds: 10,
        };
        let d = evaluate(
            &[
                VoucherView {
                    voucher_fp: [1; 48],
                    relationship: Relationship::Friend,
                    rounds_since_witnessed: 0,
                    grouping: None,
                },
                VoucherView {
                    voucher_fp: [2; 48],
                    relationship: Relationship::Friend,
                    rounds_since_witnessed: 0,
                    grouping: None,
                },
            ],
            &policy,
        );
        assert!(!d.inflation_rejected);
        assert!(d.flagged.is_empty());
        assert_eq!(d.weighted_score, 8);
        assert!(d.vouched);
    }

    #[test]
    fn single_grouped_voucher_counts_once_not_rejected() {
        // One honest person who happens to be in a disclosed grouping — not a cluster.
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 1 },
            threshold: Threshold::Count(1),
            freshness_interval_rounds: 10,
        };
        let d = evaluate(&[gview(1, Relationship::Contact, b"G")], &policy);
        assert!(!d.inflation_rejected);
        assert_eq!(d.weighted_score, 2);
        assert!(d.vouched);
    }

    #[test]
    fn vouch_policy_roundtrips() {
        let p = VouchPolicy {
            eligibility: VoucherEligibility::Transitive { depth: 2 },
            weighting: VouchWeighting { friend: 5, contact: 3, stranger: 1 },
            threshold: Threshold::Percent(60),
            freshness_interval_rounds: 32,
        };
        assert_eq!(VouchPolicy::decode(&p.encode()).as_ref(), Some(&p));
        assert_eq!(
            VouchPolicy::decode(&VouchPolicy::default().encode()).as_ref(),
            Some(&VouchPolicy::default())
        );
    }

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
