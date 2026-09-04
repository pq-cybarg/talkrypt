# Sub-spec C — Vouching + Weighted Coloration + Sybil Antibody Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let members cast ML-DSA-signed, account-bound **vouches**; render a distinct `Tint::Vouched` when a subject clears a **weighted, multi-scope, freshness-decayed** threshold; and make detected sybil vouching **EV-negative** (antibody backfire) — all on audited ML-DSA-87, no ZK, not Backend-1-gated.

**Architecture:** A new `crates/core/src/vouch.rs` module mirrors the shipped `linkage.rs` seam: pure, unit-testable types (`Vouch`, `VouchTarget`, `VouchPolicy`, evaluation) with the engine wiring them behind a new `VOUCH_SENTINEL = 0xF7` exactly as B0 wired grouping behind `0xF6`. Evaluation is a pure function over per-viewer snapshots so scoring, freshness, and antibody logic test without the async engine. Rendering extends `resolve_render`; the invite gains descriptor **v4**.

**Tech Stack:** Rust (workspace), `talkrypt_crypto` (ML-DSA-87 `IdentityKeyPair`/`IdentityPublic`/`SignedCert`), `talkrypt_wire` (`Reader`/`Writer`), existing `LoopbackFabric` test harness, uniffi FFI → Kotlin/egui.

## Global Constraints

- **Crypto:** audited ML-DSA-87 account signatures only; no new crypto assumptions, no ZK. Reuse `talkrypt_crypto::{IdentityKeyPair, IdentityPublic, SignedCert}` and `presence::chat_context`.
- **Ethics invariants (spec §0.5) are load-bearing and MUST be tested:** (1) strictly additive — no negative-vouch primitive; a subject never renders below neutral; (2) trust ≠ credit ≠ access — vouch score is display-only, NEVER gates join/speak/read; (3) always recoverable — per-chat/context-scoped, epoch-superseding, no permanent/cross-chat record; (4) not exploitable — weighting + eligibility + antibody; antibody hits the **voucher**, never the target, and only on unforgeable grouping proof.
- **Wire discipline:** `VOUCH_SENTINEL = 0xF7` (A presence `0xF5`, B linkage `0xF6`). Append-only descriptor **v4**; v1–v3 invites decode with vouching off. Every new wire type has an encode/decode round-trip test + a re-encode fuzz-guard, like descriptor v2/v3.
- **Opsec:** commit AND author as `pq-cybarg <resistant@tuta.com>`. Use `-F` message files (backticks break under zsh). Push with `GIT_SSH_COMMAND=/usr/bin/ssh`, PRs via `gh -R pq-cybarg/talkrypt`.
- **Verification per task:** `cargo test -p talkrypt-core <name>` for unit/integration; `cargo build --workspace` before any surface commit. Never disable client hosting.
- **Freshness/decay is in GOSSIP-WITNESSED ROUNDS, never local seconds** (spec §1.5). `asserted_at` is only a monotonic sanity bound.

---

### Task 1: `Vouch` + `VouchTarget` types and wire codec

**Files:**
- Create: `crates/core/src/vouch.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod vouch;`)
- Test: in-module `#[cfg(test)]` in `vouch.rs`

**Interfaces:**
- Produces: `VouchTarget` enum (`Account([u8;48])`, `NameBinding{account:[u8;48], name_tag:[u8;8]}`, `Leaf([u8;48])`) with `encode()->Vec<u8>` / `decode(&[u8])->Option<VouchTarget>`; `Vouch { target, context:[u8;32], epoch:u64, asserted_at:u64, sig:Vec<u8>, voucher:talkrypt_crypto::IdentityPublic }` with `encode()`/`decode()`.

- [ ] **Step 1: Write the failing test**

```rust
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
        assert!(VouchTarget::decode(&[0x7F]).is_none()); // unknown tag → None (append-only-safe)
        assert!(VouchTarget::decode(&[]).is_none());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core vouch_target_roundtrips_all_variants`
Expected: FAIL — `vouch` module / `VouchTarget` not found.

- [ ] **Step 3: Implement the module skeleton + `VouchTarget`**

Create `crates/core/src/vouch.rs`:

```rust
//! Sub-spec C vouching: ML-DSA-signed, account-bound, per-chat trust attestations.
//!
//! Mirrors the B0 `linkage.rs` seam — pure, unit-testable types the engine wires
//! behind `VOUCH_SENTINEL = 0xF7`. A vouch only ever ADDS a positive hint (spec
//! §0.5 invariant 1); there is no negative-vouch primitive. Design:
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
            VouchTarget::Account(fp) => { w.put_u8(0); w.put_bytes(fp); }
            VouchTarget::NameBinding { account, name_tag } => {
                w.put_u8(1); w.put_bytes(account); w.put_bytes(name_tag);
            }
            VouchTarget::Leaf(fp) => { w.put_u8(2); w.put_bytes(fp); }
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
            _ => return None,
        };
        r.finish().ok()?;
        Some(t)
    }
}

fn fp48(b: &[u8]) -> Option<[u8; 48]> {
    (b.len() == 48).then(|| { let mut a = [0u8; 48]; a.copy_from_slice(b); a })
}
fn fp8(b: &[u8]) -> Option<[u8; 8]> {
    (b.len() == 8).then(|| { let mut a = [0u8; 8]; a.copy_from_slice(b); a })
}
```

Add to `crates/core/src/lib.rs` alongside `pub mod linkage;`:

```rust
pub mod vouch;
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-core vouch_target_roundtrips_all_variants`
Expected: PASS.

- [ ] **Step 5: Add `Vouch` struct + codec test, then implement**

Append test:

```rust
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
```

Append impl:

```rust
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
        w.put_u32((self.epoch >> 32) as u32); w.put_u32(self.epoch as u32);
        w.put_u32((self.asserted_at >> 32) as u32); w.put_u32(self.asserted_at as u32);
        w.put_bytes(&self.sig);
        w.put_bytes(&self.voucher.sig_vk);
        w.into_vec()
    }
    pub fn decode(bytes: &[u8]) -> Option<Vouch> {
        let mut r = Reader::new(bytes);
        let target = VouchTarget::decode(r.get_bytes().ok()?)?;
        let mut context = [0u8; 32];
        let cb = r.get_bytes().ok()?; if cb.len() != 32 { return None; }
        context.copy_from_slice(cb);
        let epoch = ((r.get_u32().ok()? as u64) << 32) | r.get_u32().ok()? as u64;
        let asserted_at = ((r.get_u32().ok()? as u64) << 32) | r.get_u32().ok()? as u64;
        let sig = r.get_vec().ok()?;
        let voucher = IdentityPublic { sig_vk: r.get_vec().ok()? };
        r.finish().ok()?;
        Some(Vouch { target, context, epoch, asserted_at, sig, voucher })
    }
}
```

- [ ] **Step 6: Run tests**

Run: `cargo test -p talkrypt-core vouch`
Expected: both PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/core/src/vouch.rs crates/core/src/lib.rs
git commit -F ../c1.txt   # "feat(vouch): Vouch + VouchTarget types + wire codec (Sub-spec C task 1)"
```

---

### Task 2: Vouch signing + verification (account-bound, anti-self-vouch, anti-replay)

**Files:**
- Modify: `crates/core/src/vouch.rs`
- Test: in-module

**Interfaces:**
- Produces: `sign_vouch(voucher:&IdentityKeyPair, target:VouchTarget, context:[u8;32], epoch:u64, asserted_at:u64) -> Vouch`; `Vouch::signed_bytes(&self)->Vec<u8>`; `Vouch::verify(&self)->bool`; `Vouch::target_fp(&self)->[u8;48]` (the account/leaf fp the vouch is *about*, for self-vouch checks).

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn signed_vouch_verifies_and_rejects_tampering() {
        let voucher = IdentityKeyPair::generate();
        let v = sign_vouch(&voucher, VouchTarget::Account([5u8; 48]), [1u8; 32], 3, 100);
        assert!(v.verify(), "honest vouch verifies");
        // Tampered target → sig no longer matches.
        let mut bad = v.clone();
        bad.target = VouchTarget::Account([6u8; 48]);
        assert!(!bad.verify());
        // Tampered context (cross-chat replay) → fails.
        let mut replay = v.clone();
        replay.context = [2u8; 32];
        assert!(!replay.verify());
        // Wrong voucher key bound to the sig → fails.
        let mut swapped = v.clone();
        swapped.voucher = IdentityKeyPair::generate().public().clone();
        assert!(!swapped.verify());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core signed_vouch_verifies_and_rejects_tampering`
Expected: FAIL — `sign_vouch` not found.

- [ ] **Step 3: Implement**

Append to `vouch.rs`:

```rust
const VOUCH_SIG_LABEL: &[u8] = b"talkrypt-vouch-v1";

/// The exact bytes an account signs for a vouch: label ‖ target ‖ context ‖ epoch ‖ asserted_at.
/// The label domain-separates vouch sigs from any other ML-DSA use of the account key.
pub fn vouch_signed_bytes(
    target: &VouchTarget, context: &[u8; 32], epoch: u64, asserted_at: u64,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.put_bytes(VOUCH_SIG_LABEL);
    w.put_bytes(&target.encode());
    w.put_bytes(context);
    w.put_u32((epoch >> 32) as u32); w.put_u32(epoch as u32);
    w.put_u32((asserted_at >> 32) as u32); w.put_u32(asserted_at as u32);
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
    voucher: &IdentityKeyPair, target: VouchTarget, context: [u8; 32],
    epoch: u64, asserted_at: u64,
) -> Vouch {
    let sig = voucher.sign(&vouch_signed_bytes(&target, &context, epoch, asserted_at));
    Vouch { target, context, epoch, asserted_at, sig, voucher: voucher.public().clone() }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-core signed_vouch`
Expected: PASS.

- [ ] **Step 5: Add self-vouch + revocation-shape test**

```rust
    #[test]
    fn self_vouch_is_detectable_and_revoke_is_higher_epoch() {
        let acct = IdentityKeyPair::generate();
        let selfv = sign_vouch(&acct, VouchTarget::Account(acct.public().fingerprint()), [1u8;32], 1, 10);
        // The engine drops this; here we assert the property it keys on.
        assert_eq!(selfv.target_fp(), acct.public().fingerprint());
        assert_eq!(selfv.voucher.fingerprint(), acct.public().fingerprint());
        // A revoke is simply a higher-epoch vouch withdrawing (empty target semantics
        // handled in the ledger; here we assert epoch monotonicity is expressible).
        let v1 = sign_vouch(&acct, VouchTarget::Leaf([2u8;48]), [1u8;32], 1, 10);
        let v2 = sign_vouch(&acct, VouchTarget::Leaf([2u8;48]), [1u8;32], 2, 20);
        assert!(v2.epoch > v1.epoch);
    }
```

- [ ] **Step 6: Run + Commit**

Run: `cargo test -p talkrypt-core vouch`
Expected: all PASS.

```bash
git add crates/core/src/vouch.rs
git commit -F ../c2.txt   # "feat(vouch): account-bound signing/verification + self-vouch/replay guards (task 2)"
```

---

### Task 3: Weighted, multi-scope evaluation with gossip-round freshness decay

**Files:**
- Modify: `crates/core/src/vouch.rs`
- Test: in-module

**Interfaces:**
- Produces: `Relationship{Friend,Contact,Stranger}`; `VouchWeighting{friend:u32,contact:u32,stranger:u32}` (+ `weight_for(Relationship)->u32`, `Default`); `VoucherEligibility{AnyLinked, ContactsOfViewer, Transitive{depth:u8}}`; `Threshold{Count(u32), Percent(u8)}`; `VouchPolicy{eligibility, weighting, threshold, freshness_interval_rounds:u32}` (+ `Default`); `VoucherView{voucher_fp:[u8;48], relationship:Relationship, rounds_since_witnessed:u32, grouping:Option<Vec<u8>>}`; `VouchDecision{weighted_score:i64, vouched:bool, inflation_rejected:bool, flagged:Vec<[u8;48]>}`; `age_decay(rounds:u32, interval:u32)->u32` (returns a 0..=1000 permille factor); `evaluate(vouchers:&[VoucherView], policy:&VouchPolicy)->VouchDecision` (antibody added in Task 4 — Task 3 leaves `inflation_rejected=false`, `flagged=[]`).

- [ ] **Step 1: Write the failing tests**

```rust
    fn view(fp: u8, rel: Relationship, rounds: u32) -> VoucherView {
        VoucherView { voucher_fp: [fp; 48], relationship: rel, rounds_since_witnessed: rounds, grouping: None }
    }
    #[test]
    fn age_decay_is_linear_to_neutral() {
        assert_eq!(age_decay(0, 10), 1000);   // fresh → full
        assert_eq!(age_decay(5, 10), 500);    // half-way → half
        assert_eq!(age_decay(10, 10), 0);     // at interval → zero (neutral, never negative)
        assert_eq!(age_decay(99, 10), 0);     // beyond → zero, never below
    }
    #[test]
    fn weighted_score_counts_fresh_eligible_vouchers() {
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 1 },
            threshold: Threshold::Count(5),
            freshness_interval_rounds: 10,
        };
        // friend(4, fresh) + contact(2, fresh) = 6 ≥ 5 → vouched.
        let d = evaluate(&[view(1, Relationship::Friend, 0), view(2, Relationship::Contact, 0)], &policy);
        assert_eq!(d.weighted_score, 6);
        assert!(d.vouched);
        // A stale friend contributes 0 → 2 < 5 → not vouched.
        let d2 = evaluate(&[view(1, Relationship::Friend, 10), view(2, Relationship::Contact, 0)], &policy);
        assert_eq!(d2.weighted_score, 2);
        assert!(!d2.vouched);
    }
    #[test]
    fn contacts_only_eligibility_drops_strangers() {
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::ContactsOfViewer,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 1 },
            threshold: Threshold::Count(1),
            freshness_interval_rounds: 10,
        };
        // A swarm of strangers is ineligible → score 0 → not vouched (anti-vouchflation).
        let strangers: Vec<VoucherView> = (10..40).map(|i| view(i as u8, Relationship::Stranger, 0)).collect();
        let d = evaluate(&strangers, &policy);
        assert_eq!(d.weighted_score, 0);
        assert!(!d.vouched);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core -- weighted_score age_decay contacts_only`
Expected: FAIL — types not found.

- [ ] **Step 3: Implement**

Append to `vouch.rs`:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Relationship { Friend, Contact, Stranger }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VouchWeighting { pub friend: u32, pub contact: u32, pub stranger: u32 }
impl Default for VouchWeighting {
    fn default() -> Self { Self { friend: 4, contact: 2, stranger: 1 } }
}
impl VouchWeighting {
    pub fn weight_for(&self, r: Relationship) -> u32 {
        match r { Relationship::Friend => self.friend, Relationship::Contact => self.contact, Relationship::Stranger => self.stranger }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VoucherEligibility { AnyLinked, ContactsOfViewer, Transitive { depth: u8 } }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Threshold { Count(u32), Percent(u8) }

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
    /// the antibody (Task 4): ≥2 vouchers sharing a grouping = one operator.
    pub grouping: Option<Vec<u8>>,
}

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
    if interval_rounds == 0 || rounds_since_witnessed >= interval_rounds { return 0; }
    ((interval_rounds - rounds_since_witnessed) as u64 * 1000 / interval_rounds as u64) as u32
}

fn eligible(v: &VoucherView, e: VoucherEligibility) -> bool {
    match e {
        VoucherEligibility::AnyLinked => true,
        VoucherEligibility::ContactsOfViewer =>
            matches!(v.relationship, Relationship::Friend | Relationship::Contact),
        // Transitive collapses to "linked" at this layer; depth-decay applied by the
        // engine when it materializes transitive VoucherViews (Task 7). Direct here.
        VoucherEligibility::Transitive { .. } => true,
    }
}

/// Sum of fresh, eligible, distinct vouchers' decayed weights. Antibody (Task 4)
/// overrides this for grouping clusters; Task 3 ships the additive core.
pub fn evaluate(vouchers: &[VoucherView], policy: &VouchPolicy) -> VouchDecision {
    let mut score: i64 = 0;
    for v in vouchers {
        if !eligible(v, policy.eligibility) { continue; }
        let base = policy.weighting.weight_for(v.relationship) as u64;
        let decayed = base * age_decay(v.rounds_since_witnessed, policy.freshness_interval_rounds) as u64 / 1000;
        score += decayed as i64;
    }
    let vouched = score >= 0 && meets_threshold(score, vouchers, policy);
    VouchDecision { weighted_score: score, vouched, inflation_rejected: false, flagged: Vec::new() }
}

fn meets_threshold(score: i64, vouchers: &[VoucherView], policy: &VouchPolicy) -> bool {
    match policy.threshold {
        Threshold::Count(c) => score >= c as i64,
        Threshold::Percent(p) => {
            // Denominator: full-weight-max over the eligible voucher set present.
            let max: u64 = vouchers.iter().filter(|v| eligible(v, policy.eligibility))
                .map(|v| policy.weighting.weight_for(v.relationship) as u64).sum();
            if max == 0 { return false; }
            (score as u64) * 100 >= (p as u64) * max
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-core -- weighted_score age_decay contacts_only`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/vouch.rs
git commit -F ../c3.txt   # "feat(vouch): weighted multi-scope evaluation + gossip-round freshness decay (task 3)"
```

---

### Task 4: Sybil antibody backfire (spec §6a) — hard reject on grouping proof, soft discount on correlation

**Files:**
- Modify: `crates/core/src/vouch.rs`
- Test: in-module

**Interfaces:**
- Consumes: `VoucherView.grouping` from Task 3.
- Produces: extends `evaluate()` so a grouping shared by ≥2 vouchers of one subject **reverses** that cluster's contribution (score can go negative) and returns their fps in `flagged` with `inflation_rejected=true`; the DECISION never renders a subject below neutral (`vouched=false`, engine snaps display to neutral). Soft correlation (same grouping but only 1 voucher, or arrival-cluster) is left as *discount only* — no negative.

- [ ] **Step 1: Write the failing test**

```rust
    fn gview(fp: u8, rel: Relationship, grouping: &[u8]) -> VoucherView {
        VoucherView { voucher_fp: [fp; 48], relationship: rel, rounds_since_witnessed: 0, grouping: Some(grouping.to_vec()) }
    }
    #[test]
    fn detected_sybil_cluster_backfires_below_neutral() {
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 3 },
            threshold: Threshold::Count(5),
            freshness_interval_rounds: 10,
        };
        // Three "strangers" PROVEN to share one grouping (B) = one operator.
        let d = evaluate(&[
            gview(1, Relationship::Stranger, b"G"),
            gview(2, Relationship::Stranger, b"G"),
            gview(3, Relationship::Stranger, b"G"),
        ], &policy);
        assert!(d.inflation_rejected, "a proven cluster is antibody-rejected");
        assert!(d.weighted_score < 0, "the boost backfires (EV-negative)");
        assert!(!d.vouched, "target snaps to neutral, never above");
        assert_eq!(d.flagged.len(), 3, "the whole proven cluster is flagged");
    }
    #[test]
    fn honest_friend_cluster_is_not_flagged_or_reversed() {
        // Two genuine friends, NO shared grouping proof → additive, never punished.
        let policy = VouchPolicy {
            eligibility: VoucherEligibility::AnyLinked,
            weighting: VouchWeighting { friend: 4, contact: 2, stranger: 1 },
            threshold: Threshold::Count(5),
            freshness_interval_rounds: 10,
        };
        let d = evaluate(&[
            VoucherView { voucher_fp: [1;48], relationship: Relationship::Friend, rounds_since_witnessed: 0, grouping: None },
            VoucherView { voucher_fp: [2;48], relationship: Relationship::Friend, rounds_since_witnessed: 0, grouping: None },
        ], &policy);
        assert!(!d.inflation_rejected);
        assert!(d.flagged.is_empty());
        assert_eq!(d.weighted_score, 8);
        assert!(d.vouched);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core -- detected_sybil_cluster honest_friend_cluster`
Expected: FAIL — current `evaluate` never rejects/flags.

- [ ] **Step 3: Implement — replace `evaluate` body**

Replace `evaluate` in `vouch.rs`:

```rust
pub fn evaluate(vouchers: &[VoucherView], policy: &VouchPolicy) -> VouchDecision {
    use std::collections::HashMap;
    // Group eligible vouchers by proven grouping_pub (hard, unforgeable evidence).
    let mut by_grouping: HashMap<Vec<u8>, Vec<&VoucherView>> = HashMap::new();
    let mut singletons: Vec<&VoucherView> = Vec::new();
    for v in vouchers.iter().filter(|v| eligible(v, policy.eligibility)) {
        match &v.grouping {
            Some(g) => by_grouping.entry(g.clone()).or_default().push(v),
            None => singletons.push(v),
        }
    }
    let mut score: i64 = 0;
    let mut flagged: Vec<[u8; 48]> = Vec::new();
    let mut inflation_rejected = false;
    let decayed = |v: &VoucherView| -> i64 {
        let base = policy.weighting.weight_for(v.relationship) as u64;
        (base * age_decay(v.rounds_since_witnessed, policy.freshness_interval_rounds) as u64 / 1000) as i64
    };
    for v in &singletons { score += decayed(v); }
    for (_g, members) in by_grouping {
        let cluster: i64 = members.iter().map(|v| decayed(v)).sum();
        if members.len() >= 2 {
            // HARD proof of one operator wearing many hats → antibody backfire:
            // the attempted boost REVERSES (EV-negative), the cluster is flagged.
            score -= cluster;
            inflation_rejected = true;
            flagged.extend(members.iter().map(|v| v.voucher_fp));
        } else {
            // A single grouped voucher is just one honest person → counts once.
            score += cluster;
        }
    }
    // Invariant 1: never render a subject below neutral — a negative score means
    // "inflation rejected → neutral", not "distrusted". `vouched` gates on the
    // additive threshold and a non-negative score.
    let vouched = score >= 0 && meets_threshold(score, vouchers, policy);
    VouchDecision { weighted_score: score, vouched, inflation_rejected, flagged }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-core vouch`
Expected: all PASS (Task 3 tests still green — none used `grouping: Some`).

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/vouch.rs
git commit -F ../c4.txt   # "feat(vouch): sybil antibody backfire — hard-proof reversal, honest clusters unpunished (task 4)"
```

---

### Task 5: Render precedence — `Tint::Vouched` fills its reserved slot

**Files:**
- Modify: `crates/core/src/nametrust.rs:122-180` (extend `resolve_render`)
- Test: `crates/core/src/nametrust.rs` in-module

**Interfaces:**
- Consumes: existing `resolve_render(subject_fp, rec, others, policy, safety_number, isolated, amplify_isolated)`.
- Produces: a new trailing param `vouched: bool` and `vouch_badge: Option<String>`; precedence `Vouched > Verified > Isolated > Default` (spec §3). All existing callers pass `false, None` (updated in this task).

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn vouched_outranks_verified_and_isolated() {
        // A verified name that is ALSO vouched shows the Vouched tint, badge retained.
        let r = resolve_render([1u8;48], &rec("Alice", NameTier::Linked, 1), &HashMap::new(),
            NameTrustPolicy::SignalStyle, "SN".into(), false, false, true, Some("✳ vouched · 6".into()));
        assert_eq!(r.tint, Tint::Vouched);
        assert_eq!(r.badge, NameTier::Linked.badge()); // verified badge kept
        assert_eq!(r.caveat.as_deref(), Some("✳ vouched · 6"));
        // Not vouched → unchanged from before (no regression).
        let r2 = resolve_render([2u8;48], &rec("Bob", NameTier::Bare, 2), &HashMap::new(),
            NameTrustPolicy::SignalStyle, "SN".into(), true, false, false, None);
        assert_eq!(r2.tint, Tint::Isolated);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core vouched_outranks`
Expected: FAIL — `resolve_render` takes fewer args.

- [ ] **Step 3: Implement — extend the signature + precedence**

In `resolve_render`, add params `vouched: bool, vouch_badge: Option<String>` after `amplify_isolated`. After the existing `tint` match block, override for vouched and thread the badge into `caveat`:

```rust
    // SUB-SPEC C: Vouched is the strongest, peer-corroborated tint. It outranks
    // Verified and Isolated but retains the tier badge; a below-threshold subject
    // is untouched (no regression). Never set from a below-neutral score — the
    // engine passes vouched=false when inflation was rejected (invariant 1).
    let tint = if vouched { Tint::Vouched } else { tint };
    let caveat = if vouched { vouch_badge.or(caveat) } else { caveat };
```

Update the four existing `resolve_render` call sites in `nametrust.rs` tests and any engine caller to append `false, None` (or the real values in Task 7).

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-core nametrust`
Expected: PASS (existing render tests updated with `false, None`).

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/nametrust.rs
git commit -F ../c5.txt   # "feat(vouch): Tint::Vouched render precedence (Vouched>Verified>Isolated) (task 5)"
```

---

### Task 6: Descriptor v4 — carry the chat `VouchPolicy` baseline

**Files:**
- Modify: `crates/core/src/descriptor.rs` (bump `DESCRIPTOR_VERSION` to 4; add field; encode/decode v4 block; KAT)
- Test: `crates/core/src/descriptor.rs` in-module + kat

**Interfaces:**
- Consumes: `crate::vouch::VouchPolicy` (Task 3), needs `encode()`/`decode()` on the policy — add `VouchPolicy::encode()->Vec<u8>` / `decode(&[u8])->Option<VouchPolicy>` in `vouch.rs` as part of this task.
- Produces: `ChatDescriptor.vouch_policy: crate::vouch::VouchPolicy`; v1-v3 invites decode with `VouchPolicy::default()` (vouching off).

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn v4_vouch_policy_roundtrips_and_v3_defaults() {
        use crate::vouch::{VouchPolicy, VoucherEligibility, VouchWeighting, Threshold};
        let mut d = ChatDescriptor::new(TopologyKind::P2P, Persistence::Ephemeral, "tk.dr.kat", vec![], "#v4");
        d.vouch_policy = VouchPolicy {
            eligibility: VoucherEligibility::ContactsOfViewer,
            weighting: VouchWeighting { friend: 5, contact: 3, stranger: 1 },
            threshold: Threshold::Percent(60),
            freshness_interval_rounds: 32,
        };
        let back = ChatDescriptor::from_uri(&d.to_uri()).unwrap();
        assert_eq!(back.vouch_policy, d.vouch_policy);
        assert_eq!(back, d);
        // v1 invite still decodes; vouching defaults OFF (threshold Count(u32::MAX)).
        let v1 = ChatDescriptor::from_uri(
            "talkrypt://aaaaaaiaaaaaaaajorvs4zdsfzvwc5aaaaaaaaaaaaaaaaaaeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaccg23boqaaa").unwrap();
        assert_eq!(v1.vouch_policy, VouchPolicy::default());
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core v4_vouch_policy_roundtrips`
Expected: FAIL — no `vouch_policy` field / no `VouchPolicy::encode`.

- [ ] **Step 3: Implement `VouchPolicy` codec in `vouch.rs`**

```rust
impl VouchPolicy {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self.eligibility {
            VoucherEligibility::AnyLinked => w.put_u8(0),
            VoucherEligibility::ContactsOfViewer => w.put_u8(1),
            VoucherEligibility::Transitive { depth } => { w.put_u8(2); w.put_u8(depth); }
        }
        w.put_u32(self.weighting.friend); w.put_u32(self.weighting.contact); w.put_u32(self.weighting.stranger);
        match self.threshold {
            Threshold::Count(c) => { w.put_u8(0); w.put_u32(c); }
            Threshold::Percent(p) => { w.put_u8(1); w.put_u8(p); }
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
        let weighting = VouchWeighting { friend: r.get_u32().ok()?, contact: r.get_u32().ok()?, stranger: r.get_u32().ok()? };
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
```

- [ ] **Step 4: Wire descriptor v4**

In `descriptor.rs`: set `const DESCRIPTOR_VERSION: u16 = 4;`. Add field `pub vouch_policy: crate::vouch::VouchPolicy,` to `ChatDescriptor`. In `new()` set `vouch_policy: crate::vouch::VouchPolicy::default()`. In `encode_bytes`, after the v3 block:

```rust
        if self.version >= 4 {
            w.put_bytes(&self.vouch_policy.encode());
        }
```

In `decode_bytes`, after the v3 block:

```rust
        let vouch_policy = if version >= 4 {
            crate::vouch::VouchPolicy::decode(r.get_bytes()?)
                .ok_or(CoreError::Malformed("vouch policy"))?
        } else {
            crate::vouch::VouchPolicy::default()
        };
```

Add `vouch_policy` to the returned struct and to every `ChatDescriptor { .. }` literal in the KAT tests (set `vouch_policy: crate::vouch::VouchPolicy::default()`).

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p talkrypt-core descriptor`
Expected: PASS (v2/v3 round-trip guards still green — v4 block only writes when `version>=4`).

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/descriptor.rs crates/core/src/vouch.rs
git commit -F ../c6.txt   # "feat(vouch): descriptor v4 carries chat VouchPolicy baseline (task 6)"
```

---

### Task 7: Engine state + wire — `VOUCH_SENTINEL 0xF7`, `handle_vouch`, Core API, `Event::Vouch`

**Files:**
- Modify: `crates/core/src/engine.rs` (Inner fields; `Event::Vouch`; `VOUCH_SENTINEL`; `handle_vouch`; sentinel dispatch; `send_vouch_now`; Core methods; gossip-round advance)
- Test: `crates/core/src/engine.rs` in-module (unit) — integration in Task 8

**Interfaces:**
- Consumes: `vouch::{Vouch, VouchTarget, VouchPolicy, VoucherView, Relationship, evaluate}`; `presence::chat_context`; `now_secs`; `groupings_seen`, `names`, `contacts` state.
- Produces: `Event::Vouch { subject:[u8;48], weighted_score:i64, vouched:bool, inflation_rejected:bool }`; `Core::vouch_for(VouchTarget)` / `revoke_vouch(VouchTarget)` (async, broadcast); `Core::set_vouch_weighting(VouchWeighting)` / `set_vouch_threshold(Threshold)` (user scope); `Core::vouch_decision(subject:[u8;48]) -> VouchDecision`; `pub(crate) const VOUCH_SENTINEL: u8 = 0xF7`.

- [ ] **Step 1: Write the failing unit test (round advance + ledger)**

```rust
    #[test]
    fn vouch_ledger_dedups_by_voucher_and_honors_epoch() {
        // Pure ledger check via the engine's helper (no network).
        use crate::vouch::{sign_vouch, VouchTarget};
        let (core, _rx) = test_core_pairwise();   // existing helper pattern in tests
        let voucher = talkrypt_crypto::IdentityKeyPair::generate();
        let ctx = core.debug_chat_context();      // add a tiny test accessor
        let target = VouchTarget::Leaf([9u8;48]);
        let v1 = sign_vouch(&voucher, target.clone(), ctx, 1, 10);
        let v2 = sign_vouch(&voucher, target.clone(), ctx, 2, 20);
        let stale = sign_vouch(&voucher, target.clone(), ctx, 1, 5);
        core.debug_ingest_vouch(voucher.public().fingerprint(), v1);
        core.debug_ingest_vouch(voucher.public().fingerprint(), v2);
        core.debug_ingest_vouch(voucher.public().fingerprint(), stale); // epoch 1 ≤ 2 → dropped
        let d = core.vouch_decision([9u8;48]);
        assert_eq!(d.weighted_score >= 0, true);
        // one distinct voucher recorded at epoch 2
        assert_eq!(core.debug_vouch_count([9u8;48]), 1);
    }
```

(Add `#[cfg(test)]` helpers `debug_chat_context`, `debug_ingest_vouch`, `debug_vouch_count` on `Core` — thin wrappers so the unit test doesn't need the async fabric.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core vouch_ledger_dedups`
Expected: FAIL — no vouch state/methods.

- [ ] **Step 3: Add Inner state**

In `Inner` (near `linkage_seq`):

```rust
    /// SUB-SPEC C: per-subject vouch ledger — subject fp -> (voucher fp -> (epoch, Vouch)).
    vouches: Mutex<std::collections::HashMap<[u8; 48], std::collections::HashMap<[u8; 48], (u64, crate::vouch::Vouch)>>>,
    /// SUB-SPEC C: user-scope overrides (stricter-than-chat, spec §2).
    user_weighting: Mutex<Option<crate::vouch::VouchWeighting>>,
    user_threshold: Mutex<Option<crate::vouch::Threshold>>,
    /// SUB-SPEC C: gossip-witnessed round counter (§1.5) + the round at which each
    /// voucher fp was last witnessed, so freshness = current_round - last_seen_round.
    round: std::sync::atomic::AtomicU64,
    voucher_round: Mutex<std::collections::HashMap<[u8; 48], u64>>,
```

Initialize in `Core::new` (`vouches: Mutex::new(HashMap::new())`, `user_weighting: Mutex::new(None)`, `user_threshold: Mutex::new(None)`, `round: AtomicU64::new(0)`, `voucher_round: Mutex::new(HashMap::new())`).

- [ ] **Step 4: Add `Event::Vouch`, `VOUCH_SENTINEL`, `handle_vouch`, `send_vouch_now`**

Add to `Event`:

```rust
    /// SUB-SPEC C: a subject's vouch standing changed. `weighted_score` may be
    /// negative when inflation was rejected (display snaps to neutral, never below).
    Vouch { subject: [u8; 48], weighted_score: i64, vouched: bool, inflation_rejected: bool },
```

Add wire constant + handler (near `LINKAGE_SENTINEL`/`handle_linkage`):

```rust
pub(crate) const VOUCH_SENTINEL: u8 = 0xF7;

fn handle_vouch(inner: &Arc<Inner>, sender_fp: [u8; 48], bytes: Vec<u8>) {
    use crate::vouch::Vouch;
    let Some(v) = Vouch::decode(&bytes) else { return };
    // Context-bound: only vouches for THIS chat count.
    let ctx = crate::presence::chat_context(&inner.descriptor.invite_token, &inner.descriptor.channel);
    if v.context != ctx { return; }
    // Account-bound + unforgeable: the sig must verify under the voucher key, and the
    // sender must have authenticated that account this chat (reuse the names cache /
    // authenticated account set). A vouch cannot be attributed to a silent account.
    if !v.verify() { return; }
    let voucher_fp = v.voucher.fingerprint();
    // Self-vouch dropped.
    if voucher_fp == v.target_fp() { return; }
    let subject = v.target_fp();
    // Dedup by distinct voucher; epoch monotonic per (voucher, subject); revoke =
    // higher-epoch withdraw (sig over target with a sentinel epoch handled by caller).
    {
        let mut led = inner.vouches.lock().unwrap();
        let per = led.entry(subject).or_default();
        if let Some((last_epoch, _)) = per.get(&voucher_fp) {
            if v.epoch <= *last_epoch { return; }
        }
        per.insert(voucher_fp, (v.epoch, v));
    }
    // Witnessing this assertion advances freshness for this voucher.
    let r = inner.round.load(std::sync::atomic::Ordering::Relaxed);
    inner.voucher_round.lock().unwrap().insert(voucher_fp, r);
    let d = compute_vouch_decision(inner, subject);
    let _ = inner.events_tx.send(Event::Vouch {
        subject, weighted_score: d.weighted_score, vouched: d.vouched, inflation_rejected: d.inflation_rejected,
    });
}

/// Materialize per-viewer VoucherViews from the ledger + relationship + grouping +
/// gossip-round freshness, then run the pure evaluator under the effective policy.
fn compute_vouch_decision(inner: &Arc<Inner>, subject: [u8; 48]) -> crate::vouch::VouchDecision {
    use crate::vouch::{VoucherView, Relationship};
    let policy = effective_policy(inner);
    let cur = inner.round.load(std::sync::atomic::Ordering::Relaxed);
    let led = inner.vouches.lock().unwrap();
    let grouping_of = grouping_index(inner);   // voucher fp -> grouping_pub
    let rounds = inner.voucher_round.lock().unwrap();
    let views: Vec<VoucherView> = led.get(&subject).map(|per| per.keys().map(|vf| {
        let last = rounds.get(vf).copied().unwrap_or(0);
        VoucherView {
            voucher_fp: *vf,
            relationship: relationship_of(inner, *vf),
            rounds_since_witnessed: cur.saturating_sub(last) as u32,
            grouping: grouping_of.get(vf).cloned(),
        }
    }).collect()).unwrap_or_default();
    crate::vouch::evaluate(&views, &policy)
}
```

Add helpers `effective_policy` (max-strictness merge of chat `descriptor.vouch_policy` + user overrides — spec §2 user-trumps-group protective direction), `grouping_index` (invert `groupings_seen`: leaf fp → grouping_pub), `relationship_of` (Friend if pinned friend, Contact if known contact, else Stranger — reuse the contacts/friends state the Identity path already tracks). Wire `send_vouch_now` mirroring `send_linkage_now` but behind `VOUCH_SENTINEL`.

- [ ] **Step 5: Dispatch the sentinel**

At the pairwise presence dispatch (near `if bytes.first() == Some(&LINKAGE_SENTINEL)`), add:

```rust
                } else if bytes.first() == Some(&VOUCH_SENTINEL) {
                    handle_vouch(inner, attributed_fp, bytes[1..].to_vec());
```

and the same in the group-payload sentinel dispatch (near line 2776).

- [ ] **Step 6: Add Core API + test helpers**

```rust
    /// SUB-SPEC C: cast a vouch (async broadcast). Additive-only; never gates access.
    pub async fn vouch_for(&self, target: crate::vouch::VouchTarget) {
        let ctx = crate::presence::chat_context(&self.inner.descriptor.invite_token, &self.inner.descriptor.channel);
        let epoch = now_secs(); // monotonic per (voucher,target); superseded by later casts
        let v = crate::vouch::sign_vouch(&self.inner.identity, target, ctx, epoch, now_secs());
        let mut framed = vec![VOUCH_SENTINEL]; framed.extend_from_slice(&v.encode());
        send_vouch_now(&self.inner, framed).await;
    }
    pub async fn revoke_vouch(&self, target: crate::vouch::VouchTarget) { /* higher-epoch withdraw: sign with next epoch + empty-marker; symmetric to vouch_for */ }
    pub fn set_vouch_weighting(&self, w: crate::vouch::VouchWeighting) { *self.inner.user_weighting.lock().unwrap() = Some(w); }
    pub fn set_vouch_threshold(&self, t: crate::vouch::Threshold) { *self.inner.user_threshold.lock().unwrap() = Some(t); }
    pub fn vouch_decision(&self, subject: [u8; 48]) -> crate::vouch::VouchDecision { compute_vouch_decision(&self.inner, subject) }
    /// Advance the gossip-witnessed round (§1.5) — called by the engine when it
    /// witnesses activity from a DISTINCT connected member (Task 9 wires the trigger).
    pub(crate) fn advance_round(&self) { self.inner.round.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }

    #[cfg(test)]
    pub(crate) fn debug_chat_context(&self) -> [u8; 32] { crate::presence::chat_context(&self.inner.descriptor.invite_token, &self.inner.descriptor.channel) }
    #[cfg(test)]
    pub(crate) fn debug_ingest_vouch(&self, sender: [u8; 48], v: crate::vouch::Vouch) { handle_vouch(&self.inner, sender, { let mut f = vec![VOUCH_SENTINEL]; f.extend_from_slice(&v.encode()); f[1..].to_vec() }); }
    #[cfg(test)]
    pub(crate) fn debug_vouch_count(&self, subject: [u8; 48]) -> usize { self.inner.vouches.lock().unwrap().get(&subject).map(|m| m.len()).unwrap_or(0) }
```

- [ ] **Step 7: Run to verify it passes**

Run: `cargo test -p talkrypt-core vouch_ledger_dedups`
Expected: PASS.

- [ ] **Step 8: Build the workspace + commit**

Run: `cargo build --workspace`
Expected: builds (all `resolve_render` callers updated with real vouch args).

```bash
git add crates/core/src/engine.rs
git commit -F ../c7.txt   # "feat(vouch): engine wire (0xF7) + handle_vouch + Core API + Event::Vouch (task 7)"
```

---

### Task 8: Freshness re-assertion + gossip-round advance

**Files:**
- Modify: `crates/core/src/engine.rs` (round advance on distinct-member gossip; periodic vouch re-assertion on the presence cadence)
- Test: `crates/core/src/engine.rs` in-module

**Interfaces:**
- Consumes: `advance_round`, `voucher_round`, the existing presence cadence + `SeenSet` distinct-member gossip.
- Produces: freshness advancing only on DISTINCT-member witnessed rounds (§1.5); a vouch re-asserted within its window keeps full weight, one past it decays to 0.

- [ ] **Step 1: Write the failing test**

```rust
    #[test]
    fn freshness_decays_over_gossip_rounds_not_seconds() {
        let (core, _rx) = test_core_pairwise();
        let voucher = talkrypt_crypto::IdentityKeyPair::generate();
        let ctx = core.debug_chat_context();
        let v = crate::vouch::sign_vouch(&voucher, crate::vouch::VouchTarget::Leaf([9u8;48]), ctx, 1, 10);
        core.set_vouch_threshold(crate::vouch::Threshold::Count(1));
        core.debug_ingest_vouch(voucher.public().fingerprint(), v);
        assert!(core.vouch_decision([9u8;48]).weighted_score > 0, "fresh at round 0");
        // Advance rounds past the default freshness window without re-assertion.
        for _ in 0..100 { core.advance_round(); }
        assert_eq!(core.vouch_decision([9u8;48]).weighted_score, 0, "decayed to neutral over rounds");
        assert!(!core.vouch_decision([9u8;48]).vouched);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core freshness_decays_over_gossip_rounds`
Expected: FAIL if the round wiring is incomplete (score stays > 0).

- [ ] **Step 3: Implement round advance + re-assertion**

- In the distinct-member gossip path (where `SeenSet::insert` returns true for a NEW message from a member), call `inner`-level `round.fetch_add(1, Relaxed)` **only when the witnessed sender fp is distinct from the last round's advancer** (track `last_round_advancer: Mutex<Option<[u8;48]>>`), so sock-puppets from one sender can't fast-forward (§1.5 distinct-person deflation).
- Add a periodic re-assertion: when the presence cadence fires (`build_my_presence`), also re-emit our current outbound vouches (from a `my_vouches: Mutex<Vec<(VouchTarget,u64)>>` set populated by `vouch_for`) at a fresh `asserted_at`, floor-clamped like presence.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-core freshness_decays_over_gossip_rounds`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/engine.rs
git commit -F ../c8.txt   # "feat(vouch): gossip-round freshness advance + periodic re-assertion (task 8)"
```

---

### Task 9: Integration tests over `LoopbackFabric`

**Files:**
- Modify: `crates/core/src/engine.rs` (`#[cfg(test)]` integration module, mirroring the B linkage integration tests around line 3300-3460)
- Test: same

**Interfaces:**
- Consumes: existing `LoopbackFabric` group harness + `Event::Vouch`.

- [ ] **Step 1: Write the integration tests**

```rust
    // 3-member group: two members vouch a third → a fourth viewer sees Tint::Vouched.
    #[tokio::test]
    async fn two_vouches_clear_threshold_and_render_vouched() { /* build 4-node fabric,
        set chat vouch_policy Count(2) via descriptor, A & B vouch C's account, D drains
        Event::Vouch { subject: C, vouched: true } then asserts resolve_render(C).tint == Vouched */ }

    // User stricter than chat: viewer requires more → NOT tinted though chat baseline met.
    #[tokio::test]
    async fn user_stricter_than_chat_withholds_tint() { /* D.set_vouch_threshold(Count(3));
        two vouches meet chat Count(2) but not D's Count(3) → vouched=false for D */ }

    // Sybil grouping (via B) → antibody backfire: inflation_rejected, C snaps to neutral.
    #[tokio::test]
    async fn proven_sybil_cluster_backfires() { /* one operator presents 2 grouped leaves
        (B grouping proof) that both vouch C → Event::Vouch { inflation_rejected: true,
        vouched: false }; C rendered neutral, the cluster flagged */ }

    // Revocation drops the tint.
    #[tokio::test]
    async fn revocation_drops_vouched_tint() { /* A vouches C (tinted), A.revoke_vouch(C)
        → Event::Vouch { vouched: false } */ }
```

- [ ] **Step 2: Run to verify they fail, then implement fixtures**

Run: `cargo test -p talkrypt-core two_vouches_clear_threshold -- --nocapture`
Expected: FAIL first (fixtures incomplete), then PASS after filling the harness bodies using the B linkage integration tests as the template (settle delays as in the B access tests to avoid message races).

- [ ] **Step 3: Run all four**

Run: `cargo test -p talkrypt-core -- two_vouches user_stricter proven_sybil revocation_drops`
Expected: 4 PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/core/src/engine.rs
git commit -F ../c9.txt   # "test(vouch): LoopbackFabric integration — threshold, user-strict, antibody, revoke (task 9)"
```

---

### Task 10: Adversarial hardening tests

**Files:**
- Modify: `crates/core/src/engine.rs` + `crates/core/src/vouch.rs` (`#[cfg(test)]`)
- Test: same

**Interfaces:** consumes everything above; asserts the §6 security properties + ethics invariants.

- [ ] **Step 1: Write the adversarial tests**

```rust
    #[test] fn forged_vouch_sig_rejected() { /* flip a sig byte → verify()==false, ledger unchanged */ }
    #[test] fn cross_chat_replay_rejected() { /* a vouch with a different context is dropped by handle_vouch */ }
    #[test] fn stale_epoch_rejected() { /* epoch ≤ last for (voucher,subject) is ignored */ }
    #[test] fn poisoning_an_honest_target_only_self_harms() {
        /* adversary sybil-cluster vouches honest C → C's score reverses to ≤0 → C renders
           NEUTRAL (never below), and the ADVERSARY's cluster fps are the ones flagged, not C */ }
    #[test] fn vouch_never_gates_access() {
        /* assert there is no code path where vouch_decision feeds handle_identity's
           access gate — a compile-time/logic assertion that access uses only
           descriptor.access_predicate (B), never Event::Vouch */ }
```

- [ ] **Step 2: Run to verify they fail where expected, implement any missing guard, re-run**

Run: `cargo test -p talkrypt-core -- forged_vouch cross_chat_replay stale_epoch poisoning vouch_never_gates`
Expected: all PASS (the guards exist from Tasks 2/4/7; this task proves them).

- [ ] **Step 3: Commit**

```bash
git add crates/core/src/engine.rs crates/core/src/vouch.rs
git commit -F ../c10.txt   # "test(vouch): adversarial — forgery, replay, poison-self-harm, no-access-gate (task 10)"
```

---

### Task 11: Surfaces — FFI + CLI + Android/desktop

**Files:**
- Modify: `crates/ffi/src/lib.rs` (FfiEvent::Vouch; `vouch_for`/`revoke_vouch`/`set_vouch_*` exports)
- Modify: `crates/cli/src/main.rs` (`/vouch`, `/unvouch`, `/vouchpolicy`, `/vouches`)
- Modify: `android/app/src/main/kotlin/com/talkrypt/app/*` (FfiEvent.Vouch fold → `Member.vouched`/badge; a "Vouch for" roster action)
- Modify: desktop egui roster (Vouched tint + badge; "Vouch for" action)
- Test: `android/app/src/test/kotlin/com/talkrypt/app/ChatEventsTest.kt` (Vouch event fold), CLI smoke

**Interfaces:** consumes `Event::Vouch`, `Core::vouch_for/…`. Mirrors B0's surface wiring exactly (the `FfiEvent.Linkage`→`Member.grouped` pattern in `ChatEventsTest.kt`).

- [ ] **Step 1: FFI — add `FfiEvent::Vouch` + exports (with a test)**

Add `Vouch { subject: String, weightedScore: i64, vouched: bool, inflationRejected: bool }` to `FfiEvent`, map from `Event::Vouch` in the event bridge, and export `vouch_for(target_fp, kind)`, `revoke_vouch(...)`, `set_vouch_threshold_count(...)`. Regenerate bindings:
`cargo run -p talkrypt-ffi --bin uniffi-bindgen -- generate --library target/debug/libtalkrypt_ffi.dylib --language kotlin`

- [ ] **Step 2: Android — fold the event (write the failing Kotlin test first)**

In `ChatEventsTest.kt`, mirror `linkage_marks_peer_as_grouped_and_notes_it`:

```kotlin
    @Test fun vouch_marks_member_vouched_and_notes_it() {
        val s = Sessions(); val a = s.open(meta("a"), null)
        val m = applyEvent(s, "a", a, FfiEvent.Vouch("peerfp123456", 6, true, false))
        assertEquals(MsgKind.SYSTEM, m.kind)
        assertTrue(m.text.contains("vouched"))
        assertTrue(a.roster["peerfp123456"]!!.vouched)
    }
```

Add `var vouched: Boolean = false` to `Member`; handle `FfiEvent.Vouch` in `applyEvent` (set `vouched`, append a system line). Run `./gradlew testDebugUnitTest --tests '*ChatEventsTest*'`.

- [ ] **Step 3: CLI commands**

Add `/vouch <fp>`, `/unvouch <fp>`, `/vouchpolicy count <n> | percent <p>`, `/vouches` (list subject→score) to the CLI dispatch, mirroring `/grouping`/`/showall`. Smoke: `cargo run -p talkrypt-cli -- --help` shows them.

- [ ] **Step 4: Desktop egui roster**

Render the Vouched tint + weighted-count badge on names/bubbles; add a "Vouch for" context action; host vouch-policy control in the New-Chat advanced foldout; user weighting/threshold in settings — mirroring the B isolated-tint/grouping surfaces.

- [ ] **Step 5: Build + test all surfaces**

Run: `cargo build --workspace` and the Android JVM test.
Expected: green.

- [ ] **Step 6: Commit**

```bash
git add crates/ffi/src/lib.rs crates/cli/src/main.rs android/ crates/desktop/
git commit -F ../c11.txt   # "feat(vouch): FFI + CLI + Android/desktop surfaces (task 11)"
```

---

## Self-Review

**Spec coverage:** §1 vouch/target → Tasks 1-2; §1.5 freshness + gossip clock → Tasks 3,8; §2 weighted multi-scope → Tasks 3,7; §3 render precedence → Task 5; §4 wire 0xF7 + descriptor v4 → Tasks 6-7; §5 surfaces → Task 11; §6 security + §6a antibody → Tasks 4,10; §7 testing → Tasks 9-10; §8 staging (audited-now) → whole plan; §0.5 invariants → Tasks 4,5,10 (`vouch_never_gates_access`, `poisoning_an_honest_target_only_self_harms`, never-below-neutral). Open questions (§10: degrees-of-separation, decay curve) intentionally NOT built.

**Placeholder scan:** Task 7 `revoke_vouch` and Task 8/9/11 bodies carry inline `/* ... */` describing exact behavior (symmetric to `vouch_for`, template = B linkage tests) rather than full code — flagged as the one area an implementer fills from the cited template; every type/signature they need is defined in Tasks 1-7.

**Type consistency:** `VouchTarget`, `Vouch`, `VouchPolicy`, `VoucherView`, `VouchDecision`, `Relationship`, `Threshold`, `evaluate`, `age_decay`, `VOUCH_SENTINEL=0xF7`, `Event::Vouch{subject,weighted_score,vouched,inflation_rejected}` are used identically across Tasks 1-11. `resolve_render` gains `vouched: bool, vouch_badge: Option<String>` (Task 5) and every caller is updated in Tasks 5/7.
