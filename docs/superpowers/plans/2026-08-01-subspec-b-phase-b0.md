# Sub-spec B — Phase B0 (audited ML-DSA linkage/opsec layer) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended)
> or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Ship the audited, ML-DSA-only linkage-disclosure + opsec layer of Sub-spec B — the `Claim`
predicate seam with the ML-DSA cert backend, opsec modes, the per-chat account-hidden grouping key, the
isolated sybil tint with the disclosure≠display split, show-all/foremost, sybil-count, and access-predicate
gating — wired core→FFI→CLI, with Android/desktop UI following the Sub-spec A precedent.

**Architecture:** One `Claim { predicate, context }` seam with a `ProofBackend` trait; Phase B0 implements
only `MlDsaCertBackend` over the existing `account.rs` signature-tree machinery
(`SignedCert`/`IdentityChain`/`belongs_to_account`). Linkage rides the existing Sub-spec A presence path
(`Frame::Presence` pairwise / group-payload-behind-`GroupMsg`) as a new `LinkagePayload`. Rendering decorates
Sub-spec A's `NameRender.tint` slot (`Tint::Isolated`). **Backend 1 (Winterfell ZK, attestation quorum,
predicate-gated delivery) is explicitly OUT of this plan** — a separate, review-gated plan.

**Tech Stack:** Rust (workspace crates `talkrypt-crypto`, `talkrypt-core`, `talkrypt-ffi`, `talkrypt-cli`);
ML-DSA-87 (RustCrypto `ml-dsa`) via `IdentityKeyPair`; KMAC256/SHA3 KDF (`mac_kdf`); uniffi FFI; Kotlin
(Android) / egui (desktop).

## Global Constraints
- **Zero elliptic curve in identity/auth** — ML-DSA-87 only; no EC anywhere in B0 crypto (memory: EC never load-bearing).
- **KDF = `talkrypt_crypto::mac_kdf(key, msg, label, out)`** (KMAC256 default / HKDF-SHA384 under `cnsa-sha2`). Never invent a KDF.
- **No new crypto assumptions in B0** — audited primitives only (FIPS-final ML-DSA-87 + SHA3). Novel ZK is Backend 1, out of scope.
- **Wire tags are append-only** — old clients drop unknown tags via `_ => None`. Never renumber an existing tag.
- **Descriptor bump v2 → v3 is back-compatible** — v1/v2 invites still decode with defaults; add a v3 KAT vector; version guard stays `0 < v <= DESCRIPTOR_VERSION`.
- **Commit AND author as `pq-cybarg <resistant@tuta.com>`** on every commit (`git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit --author="pq-cybarg <resistant@tuta.com>"`); write messages to a file and use `-F` (backticks in `-m` break under zsh).
- **Context binding:** every linkage payload binds `chat_context(invite_token, channel)` — reuse `crates/core/src/presence.rs::chat_context`.
- Run `cargo test -p <crate>` after each task; keep clippy clean.

## File Structure
- `crates/crypto/src/grouping.rs` (new) — `GroupingKey` (per-chat account-hidden grouping key derivation + cert issue/verify). Registered in `crates/crypto/src/lib.rs`.
- `crates/core/src/linkage.rs` (new) — `Predicate`, `Claim`, `Verdict`, `ProofBackend` trait, `MlDsaCertBackend`, `OpsecMode`, `GroupingId`, `LinkagePayload` encode/decode, sybil-count.
- `crates/core/src/engine.rs` (modify) — `Inner` fields (opsec_mode, groupings, group_display_policy, access_predicate, show_all); `Core` methods; `LinkagePayload` dispatch in `reader_loop`/`handle_group_msg`; `Tint::Isolated` population; `Event::Linkage`.
- `crates/core/src/nametrust.rs` (modify) — `resolve_render` gains an `isolated: bool` + `display_amplify` input.
- `crates/core/src/descriptor.rs` (modify) — v2→v3: `group_display_policy`, `access_predicate: Option<Predicate>`.
- `crates/ffi/src/lib.rs` (modify) — FFI types + methods + `FfiEvent::Linkage`.
- `crates/cli/src/main.rs` (modify) — `/opsec`, `/grouping`, `/showall`, `/gate` commands.
- `android/app/.../*.kt`, `crates/desktop/src/*` (modify) — UI following the A precedent.

---

### Task 1: Per-chat account-hidden grouping key (crypto)

**Files:**
- Create: `crates/crypto/src/grouping.rs`
- Modify: `crates/crypto/src/lib.rs` (add `pub mod grouping;`)
- Test: in `grouping.rs` `#[cfg(test)]`

**Interfaces:**
- Consumes: `IdentityKeyPair::{from_secret_bytes, public, sign}`, `IdentityPublic::fingerprint`, `SignedCert::{issue, verify}`, `mac_kdf`.
- Produces: `GroupingKey::from_root_seed([u8;32])`, `GroupingKey::derive_for_chat(&self, chat_context: &[u8;32]) -> IdentityKeyPair`, `GroupingKey::certify(&self, chat_context, member: &IdentityPublic, now, exp) -> SignedCert`, free `verify_grouping_cert(grouping_pub: &IdentityPublic, cert: &SignedCert, member: &IdentityPublic, now) -> bool`.

- [ ] **Step 1: Write the failing test**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::IdentityKeyPair;
    const NOW: u64 = 1_000;

    #[test]
    fn grouping_key_is_per_chat_unlinkable_but_deterministic() {
        let g = GroupingKey::from_root_seed([7u8; 32]);
        let ctx_a = [1u8; 32];
        let ctx_b = [2u8; 32];
        // Same chat → same derived key; different chat → different key (unlinkable).
        assert_eq!(g.derive_for_chat(&ctx_a).public(), g.derive_for_chat(&ctx_a).public());
        assert_ne!(g.derive_for_chat(&ctx_a).public(), g.derive_for_chat(&ctx_b).public());
    }

    #[test]
    fn grouping_cert_verifies_under_per_chat_key_only() {
        let g = GroupingKey::from_root_seed([9u8; 32]);
        let ctx = [3u8; 32];
        let member = IdentityKeyPair::generate();
        let cert = g.certify(&ctx, member.public(), NOW, NOW + 1000);
        let g_c_pub = g.derive_for_chat(&ctx).public().clone();
        // Verifies under the chat's grouping pub...
        assert!(verify_grouping_cert(&g_c_pub, &cert, member.public(), NOW));
        // ...but NOT under a different chat's grouping pub (unlinkable + unforgeable).
        let g_other = g.derive_for_chat(&[4u8; 32]).public().clone();
        assert!(!verify_grouping_cert(&g_other, &cert, member.public(), NOW));
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p talkrypt-crypto grouping:: -- --nocapture`
Expected: FAIL to compile (`GroupingKey` undefined).

- [ ] **Step 3: Implement `grouping.rs`**
```rust
//! Per-chat, account-hidden **grouping key** for Sub-spec B opsec-selective linkage.
//! A grouping discloses that several leaf identities are one person WITHIN a chat,
//! without revealing the account AND without the grouping key linking across chats:
//! the presented key is derived per chat from a long-term root seed, so the same
//! grouping shows a different public key in every chat. See
//! docs/superpowers/specs/2026-07-31-subspec-b-linkage-opsec-predicate-proofs-design.md §3b.

use crate::account::{SignedCert, verify_cert_pair};
use crate::identity::{IdentityKeyPair, IdentityPublic};
use crate::kdf::mac_kdf;

const GROUPING_KDF_LABEL: &[u8] = b"talkrypt-grouping-key-v1";

/// A long-term grouping identity, held only by its owner. Never certified upward to
/// the account (that would relink it); its per-chat derivations are what get presented.
pub struct GroupingKey {
    root_seed: [u8; 32],
}

impl GroupingKey {
    pub fn from_root_seed(root_seed: [u8; 32]) -> Self {
        Self { root_seed }
    }

    /// Fresh grouping keypair for THIS chat: G_c = ML-DSA-keygen(KDF(root, chat_context)).
    pub fn derive_for_chat(&self, chat_context: &[u8; 32]) -> IdentityKeyPair {
        let mut seed = [0u8; 32];
        mac_kdf(&self.root_seed, chat_context, GROUPING_KDF_LABEL, &mut seed);
        let kp = IdentityKeyPair::from_secret_bytes(seed);
        seed.iter_mut().for_each(|b| *b = 0); // wipe transient seed
        kp
    }

    /// Certify that `member` is in this grouping, in this chat.
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

/// Verify a grouping cert binds `member` under `grouping_pub` (the chat's derived key).
pub fn verify_grouping_cert(
    grouping_pub: &IdentityPublic,
    cert: &SignedCert,
    member: &IdentityPublic,
    now: u64,
) -> bool {
    verify_cert_pair(grouping_pub, cert, member, now)
}
```

- [ ] **Step 4: Add the helper `verify_cert_pair` if absent**

Check `crates/crypto/src/account.rs` for a single-cert verify. If `SignedCert` has `verify(&self, issuer: &IdentityPublic, subject: &IdentityPublic, now: u64) -> Result<()>`, replace the body of `verify_grouping_cert` with `grouping_pub.ct_eq(&cert.issuer) && cert.verify(grouping_pub, member, now).is_ok()`. Otherwise add to `account.rs`:
```rust
/// Verify a lone `SignedCert` binds `subject` under `issuer`, valid at `now`.
pub fn verify_cert_pair(issuer: &IdentityPublic, cert: &SignedCert, subject: &IdentityPublic, now: u64) -> bool {
    cert.issuer.ct_eq(issuer)
        && cert.cert.subject.ct_eq(subject)
        && cert.cert.valid_from.saturating_sub(CLOCK_SKEW_TOLERANCE) <= now
        && now <= cert.cert.expiry.saturating_add(CLOCK_SKEW_TOLERANCE)
        && issuer.verify(&cert.cert.encode(), &cert.sig).is_ok()
}
```
(Confirm field names `cert.cert`, `.subject`, `.valid_from`, `.expiry`, `.sig`, `.issuer` against `account.rs` and adjust; reuse the existing `CLOCK_SKEW_TOLERANCE`.)

- [ ] **Step 5: Register the module**

In `crates/crypto/src/lib.rs` add `pub mod grouping;` next to the other `pub mod` lines, and re-export: `pub use grouping::{GroupingKey, verify_grouping_cert};`.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test -p talkrypt-crypto grouping::`
Expected: PASS (2 tests).

- [ ] **Step 7: Commit**
```bash
git add crates/crypto/src/grouping.rs crates/crypto/src/lib.rs crates/crypto/src/account.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -F /tmp/b0-t1.txt --author="pq-cybarg <resistant@tuta.com>"
```
(`/tmp/b0-t1.txt` = "feat(crypto): per-chat account-hidden grouping key (Sub-spec B §3b)".)

---

### Task 2: `Predicate` / `Claim` / `ProofBackend` seam (core)

**Files:**
- Create: `crates/core/src/linkage.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod linkage;`)
- Test: in `linkage.rs`

**Interfaces:**
- Consumes: `talkrypt_crypto::{IdentityPublic, IdentityChain}`.
- Produces: `enum Predicate` (B0 variants), `struct Claim { predicate, context: [u8;32] }`, `enum Verdict { Pass, Fail }`, `trait ProofBackend { fn verify(&self, claim: &Claim, proof: &Proof) -> Verdict; }`, `struct Proof(Vec<u8>)` with encode/decode, and `Predicate` tag-based encode/decode.

- [ ] **Step 1: Write the failing test**
```rust
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
            assert_eq!(Predicate::decode(&p.encode()).unwrap(), p);
        }
    }
    #[test]
    fn unknown_predicate_tag_decodes_none() {
        assert!(Predicate::decode(&[0xFEu8]).is_none()); // reserved for Backend 1
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p talkrypt-core linkage::tests::predicate_roundtrips`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the seam**
```rust
//! Sub-spec B linkage/predicate seam. Phase B0 defines the abstraction and the
//! audited ML-DSA cert backend. Backend-1 (ZK) predicate tags 0x10+ are RESERVED
//! here and decode to None until that review-gated crate lands.

use talkrypt_crypto::{IdentityChain, IdentityPublic};
use talkrypt_wire::{Reader, Writer};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Predicate {
    LinkedToAccount { account_fp: [u8; 48] },  // tag 0
    Grouping { grouping_pub: Vec<u8> },        // tag 1 (per-chat derived grouping public)
    DerivedFromNamed { ancestor_fp: [u8; 48] },// tag 2
    // 0x10+ reserved for Backend 1 (MemberOfKnownSet, DerivedFromKnownSet, Attribute, And/Or)
}

impl Predicate {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Predicate::LinkedToAccount { account_fp } => { w.put_u8(0); w.put_bytes(account_fp); }
            Predicate::Grouping { grouping_pub } => { w.put_u8(1); w.put_bytes(grouping_pub); }
            Predicate::DerivedFromNamed { ancestor_fp } => { w.put_u8(2); w.put_bytes(ancestor_fp); }
        }
        w.into_vec()
    }
    pub fn decode(bytes: &[u8]) -> Option<Predicate> {
        let mut r = Reader::new(bytes);
        Some(match r.get_u8().ok()? {
            0 => Predicate::LinkedToAccount { account_fp: fp48(r.get_bytes().ok()?)? },
            1 => Predicate::Grouping { grouping_pub: r.get_bytes().ok()?.to_vec() },
            2 => Predicate::DerivedFromNamed { ancestor_fp: fp48(r.get_bytes().ok()?)? },
            _ => return None, // Backend-1 / unknown
        })
    }
}

fn fp48(b: &[u8]) -> Option<[u8; 48]> { (b.len() == 48).then(|| { let mut a = [0u8; 48]; a.copy_from_slice(b); a }) }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim { pub predicate: Predicate, pub context: [u8; 32] }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof(pub Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict { Pass, Fail }

/// A verifier learns ONLY Pass/Fail — never which element/ancestor/attribute.
pub trait ProofBackend {
    fn verify(&self, claim: &Claim, proof: &Proof) -> Verdict;
}
```
(Confirm `talkrypt_wire::{Reader, Writer}` method names against `crates/core/src/engine.rs` usage — `put_u8`, `put_bytes`, `get_u8`, `get_bytes`, `into_vec` — they match `engine.rs`.)

- [ ] **Step 4: Register + run**

Add `pub mod linkage;` to `crates/core/src/lib.rs`. Run: `cargo test -p talkrypt-core linkage::tests::` → PASS.

- [ ] **Step 5: Commit** (`feat(core): Claim/Predicate/ProofBackend seam (Sub-spec B, Backend-0 tags)`)

---

### Task 3: `MlDsaCertBackend` — the audited proof backend

**Files:** Modify `crates/core/src/linkage.rs`. Test in same file.

**Interfaces:**
- Consumes: `talkrypt_crypto::{belongs_to_account, verify_grouping_cert, IdentityChain, SignedCert, IdentityPublic}`; Task 2 types.
- Produces: `struct MlDsaCertBackend;` impl `ProofBackend`; `enum LinkageProof { Linked{chain}, Grouping{cert, member_sig}, Derived{chain} }` as the `Proof` payload (encode/decode); a prover helper `prove_grouping(g: &GroupingKey, chat_context, member_kp) -> Proof`.

- [ ] **Step 1: Write the failing test** (grouping proof verifies, account stays hidden, wrong-context fails)
```rust
#[test]
fn grouping_proof_verifies_and_hides_account() {
    use talkrypt_crypto::{GroupingKey, IdentityKeyPair};
    let ctx = [5u8; 32];
    let g = GroupingKey::from_root_seed([1u8; 32]);
    let member = IdentityKeyPair::generate();
    let cert = g.certify(&ctx, member.public(), 0, 10_000);
    let g_c_pub = g.derive_for_chat(&ctx).public().sig_vk.clone(); // the presented grouping pub bytes
    let proof = Proof(LinkageProof::Grouping { cert, member_fp: member.public().fingerprint() }.encode());
    let claim = Claim { predicate: Predicate::Grouping { grouping_pub: g_c_pub }, context: ctx };
    assert_eq!(MlDsaCertBackend.verify(&claim, &proof), Verdict::Pass);
    // A different context's grouping pub must NOT verify this proof.
    let bad = Claim { predicate: Predicate::Grouping { grouping_pub: g.derive_for_chat(&[6u8;32]).public().sig_vk.clone() }, context: ctx };
    assert_eq!(MlDsaCertBackend.verify(&bad, &proof), Verdict::Fail);
}
```

- [ ] **Step 2: Run → fails to compile.**

- [ ] **Step 3: Implement `LinkageProof` + `MlDsaCertBackend`** verifying each Backend-0 predicate:
`LinkedToAccount` → `belongs_to_account(account, chain, chain.leaf(), now)` and `account.fingerprint() == account_fp`; `Grouping` → reconstruct `IdentityPublic` from `grouping_pub` bytes and `verify_grouping_cert`; `DerivedFromNamed` → chain verifies and some link's issuer fp == `ancestor_fp`. Reveal only `Verdict`. (Full code: mirror the verify structure in `handle_presence`'s Linked path in `engine.rs:2068+`.)

- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** (`feat(core): MlDsaCertBackend — audited Backend-0 predicate verification`).

---

### Task 4: `OpsecMode` + grouping state on `Core`

**Files:** Modify `crates/core/src/linkage.rs` (add `OpsecMode`, `GroupingId`), `crates/core/src/engine.rs` (`Inner` fields + `Core` methods). Test in `engine.rs`.

**Interfaces:**
- Produces: `enum OpsecMode { Clean, Selective, Transparent { hide: bool } }` (default `Clean`); `type GroupingId = String`; `Inner` fields `opsec_mode: Mutex<OpsecMode>`, `groupings: Mutex<HashMap<GroupingId, Vec<String>>>` (grouping id → NameEntry ids), `show_all: AtomicBool`; `Core::set_opsec_mode`, `Core::opsec_mode`, `Core::define_grouping(ids: &[String]) -> GroupingId`, `Core::show_all_identities(bool)`.

- [ ] **Step 1: Failing test** — `set_opsec_mode` round-trips; `define_grouping` returns a stable id and stores the members; default is `Clean`.
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Add the `Inner` fields (init in `Core::new`/`new_group`) + the `Core` methods.** `define_grouping` id = hex of `mac_kdf` over the sorted member ids (stable). No presence emitted here (that's Task 5).
- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** (`feat(core): opsec mode + grouping definitions on Core`).

---

### Task 5: `LinkagePayload` wire + propagation (the disclosure act)

**Files:** Modify `crates/core/src/linkage.rs` (`LinkagePayload` + codec), `crates/core/src/engine.rs` (emit on `present_grouping`; dispatch in `reader_loop` pairwise arm and `handle_group_msg` behind a new sentinel, mirroring Sub-spec A's `PRESENCE_SENTINEL`). Test in `engine.rs` over `LoopbackFabric`.

**Interfaces:**
- Produces: `enum LinkagePayload { GroupingProof { grouping_pub: Vec<u8>, members: Vec<(/*leaf fp*/[u8;48], /*cert*/Vec<u8>, /*sig over seq‖ctx*/Vec<u8>)>, seq: u64 } }` + encode/decode; `Core::present_grouping(&self, id: &GroupingId)`; `Event::Linkage { subject: [u8;48], kind: LinkageKind, verdict: bool }`; `const LINKAGE_SENTINEL: u8 = 0xF6`.
- Consumes: Task 1 `GroupingKey`, Task 3 verification, A's `chat_context`, group signed path (`encrypt_signed`/`decrypt_verified`), `send_presence_now` pattern.

- [ ] **Step 1: Failing integration test** — 3-member group; member m1 defines a grouping of two of its leading names and calls `present_grouping`; the *other member* m2 receives an `Event::Linkage { verdict: true }` attributing both leaves to one grouping, and m2's `names` cache records no `account_fp` for them (account hidden). (Model on `group_member_presence_reaches_host`.)
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement.** `present_grouping` builds a `LinkagePayload::GroupingProof` (per-chat `GroupingKey::derive_for_chat` + a `certify` per member + each leaf signs `seq‖context`), sends it pairwise via `Frame::Presence(LINKAGE_SENTINEL ‖ payload)` and in groups via `grp.encrypt_signed(encode_group_linkage(...))` behind `LINKAGE_SENTINEL` (mirror `encode_group_presence`). Receiver: in the pairwise `Frame::Presence` arm and in `handle_group_msg`, if `bytes[0] == LINKAGE_SENTINEL` route to a new `handle_linkage(inner, sender, &bytes[1..])` that verifies via `MlDsaCertBackend`, records the grouping association, and emits `Event::Linkage`. Bind `context`, enforce `seq` monotonicity (reuse A's per-sender seq logic).
- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** (`feat(core): grouping-linkage payload + propagation (account-hidden)`).

---

### Task 6: Isolated tint + disclosure≠display in `resolve_render`

**Files:** Modify `crates/core/src/nametrust.rs` (extend `resolve_render`), `crates/core/src/engine.rs` (compute `isolated` + pass group display policy). Test in `nametrust.rs`.

**Interfaces:**
- Produces: `resolve_render(subject_fp, rec, others, policy, safety_number, isolated: bool, amplify_isolated: bool) -> NameRender` — when `isolated`, set `tint = Tint::Isolated` (unless already `Verified`), and if `amplify_isolated` also set a `caveat` note; precedence: `Verified` (linked/registry) > `Isolated` > `Default`.
- Consumes: A's `Tint`, `NameRecord`.

- [ ] **Step 1: Failing tests** — (a) a `Bare` record with `isolated=true` → `tint == Tint::Isolated`; (b) a `Linked` record with `isolated=true` → stays `Tint::Verified` (verified is never downgraded); (c) `amplify_isolated=true` adds a caveat.
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Extend `resolve_render`** with the two new params + precedence; update all call sites in `engine.rs` (`handle_presence`, `handle_linkage`) to pass `isolated = !has_verifiable_linkage(subject)` and `amplify = inner.group_display_policy.amplify_isolated`. `has_verifiable_linkage` = subject is a contact/friend, OR has a `Linked` name, OR appears in a verified grouping.
- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** (`feat(core): isolated sybil tint + display amplification (disclosure!=display)`).

---

### Task 7: Sybil-count

**Files:** Modify `crates/core/src/engine.rs`. Test there.

**Interfaces:** Produces `Core::sybil_estimate(&self) -> SybilCount { distinct_accounts: usize, distinct_groupings: usize, isolated: usize, min_distinct_people: usize }` where `min_distinct_people = distinct_accounts + distinct_groupings + isolated`.

- [ ] **Step 1: Failing test** — a chat with two members linked to one account, one 2-leaf grouping, and two isolated bare identities → `min_distinct_people == 1 + 1 + 2 == 4`.
- [ ] **Step 2..5:** implement over the `names`/groupings/contacts caches; run; commit (`feat(core): honest sybil-count estimate`).

---

### Task 8: Descriptor v3 — group display policy + access predicate

**Files:** Modify `crates/core/src/descriptor.rs`. Test there.

**Interfaces:** Produces `DESCRIPTOR_VERSION = 3`; fields `group_display_policy: GroupDisplayPolicy { amplify_isolated: bool }` and `access_predicate: Option<Predicate>`; append-only encode gated on `version >= 3` (mirror the v2 `name_trust_policy` fix — encode the field ONLY when `self.version >= 3`, so parsed v1/v2 descriptors round-trip); decode reads them only when `version >= 3` else defaults.

- [ ] **Step 1: Failing test** — `v3_fields_roundtrip_and_v2_defaults`: a v3 descriptor with `amplify_isolated=true` + an `access_predicate` round-trips through `to_uri`/`from_uri`; the frozen v2 URI (reuse the one from `v2_policy_roundtrips_and_v1_defaults`) still decodes with defaults; **a parsed v2 descriptor re-encodes and re-parses equal** (the fuzz-caught round-trip guard, extended to v3).
- [ ] **Step 2: Run → fails.**
- [ ] **Step 3: Implement** the v3 encode (guarded `if self.version >= 3`), decode (`if version >= 3`), and add a frozen v3 KAT. Keep the version guard `0 < version <= DESCRIPTOR_VERSION`.
- [ ] **Step 4: Run → PASS.**  **Step 5: Commit** (`feat(descriptor): v3 — group display policy + access predicate (v1/v2 back-compat)`).

---

### Task 9: Access-predicate gating (Backend-0)

**Files:** Modify `crates/core/src/engine.rs` (join/admit path). Test over `LoopbackFabric`.

**Interfaces:** Consumes descriptor `access_predicate`, `MlDsaCertBackend`, the existing `AccessPolicy`/identity-presentation gate. A joiner that presents a `LinkagePayload`/`Claim` satisfying `access_predicate` is admitted; one that cannot is denied with the existing `Frame::AccessDenied` → `Event::Error("not admitted")` — **without the denier learning anything beyond pass/fail** (Verdict is two-valued).

- [ ] **Step 1: Failing test** — host sets `access_predicate = LinkedToAccount{acct}`; a joiner linked to `acct` is admitted and exchanges a message; a bare joiner is denied (`Event::Error` contains "not admitted"). 
- [ ] **Step 2..5:** implement the gate in the admission path (reuse `handle_identity`/`handle_group_member_identity` seam), run, commit (`feat(core): access-predicate gating over Backend-0 claims`).

---

### Task 10: show-all vs foremost emission

**Files:** Modify `crates/core/src/engine.rs`. Test over `LoopbackFabric`.

**Interfaces:** When `show_all == true` and opsec mode is `Selective`/`Transparent`, on-join/announce emits the grouping proof (all associated identities) in addition to the A leading name; when `false`, only the A leading name is emitted (today's behavior).

- [ ] **Step 1: Failing test** — with `show_all(true)` + a defined grouping, a peer receives `Event::Linkage` for the grouping on join; with `show_all(false)`, it does not.
- [ ] **Step 2..5:** wire into the on-join/announce path (reuse the A on-join trigger + Task 5 `present_grouping`), run, commit (`feat(core): show-all vs foremost identity emission`).

---

### Task 11: FFI surface

**Files:** Modify `crates/ffi/src/lib.rs`. FFI has no unit tests for UI methods (precedent); verify with `cargo build -p talkrypt-ffi` + the uniffi bindgen at APK build.

**Interfaces:** Expose `set_opsec_mode(mode: FfiOpsecMode)`, `define_grouping(name_ids: Vec<String>) -> String`, `present_grouping(id: String)`, `show_all_identities(on: bool)`, `sybil_estimate() -> FfiSybilCount`; map `Event::Linkage` → `FfiEvent::Linkage { subject, kind, verdict }`; host/join gain optional `access_predicate` + `group_display_policy` (or post-construct setters). Mirror the Sub-spec A FFI additions (`set_leading_name` etc.).

- [ ] **Steps:** add the enums/records/methods + `map_event` arm; `cargo build -p talkrypt-ffi`; commit (`feat(ffi): expose Sub-spec B B0 linkage/opsec API`).

---

### Task 12: CLI surface

**Files:** Modify `crates/cli/src/main.rs`. Add a `parse_opsec` unit test (mirror `parse_name_policy`).

**Interfaces:** `/opsec clean|selective|transparent[ hide]`, `/grouping new <name-id...>` / `/grouping show <id>`, `/showall on|off`, and host flags `--access-predicate linked:<acct-fp>` + `--display amplify-isolated`. `Event::Linkage` printer line. Follow the A CLI precedent (`cmd_name`, `parse_name_policy`, the Event printer).

- [ ] **Steps:** add commands + `parse_opsec` + tests; `cargo test -p talkrypt-cli`; commit (`feat(cli): /opsec /grouping /showall + access-predicate flag`).

---

### Task 13: Android + desktop UI (follow the Sub-spec A precedent)

**Files:** Modify `android/app/src/main/kotlin/com/talkrypt/app/{ChatEvents.kt, MainActivity.kt, ChatModels.kt}`, `crates/desktop/src/*`. Android JVM test in `ChatEventsTest.kt`.

**Interfaces:** Opsec-mode picker + grouping editor over the name book; per-chat show-all toggle; **isolated tint** rendered on roster/bubbles (reuse the A tier-badge rendering path, add an isolated coloration); sybil-count readout; host controls for display policy + optional access predicate. `applyEvent` gains an `FfiEvent.Linkage` arm updating grouping display. Follow `ChatEvents.kt`/`MainActivity.kt` patterns from Sub-spec A.

- [ ] **Steps:** add the `FfiEvent.Linkage` arm + a `ChatEventsTest` for it (mirror `message_bubble_shows_resolved_cq_name_when_known`); wire the UI controls; `./gradlew :app:testDebugUnitTest`; commit (`feat(android+desktop): Sub-spec B B0 opsec/grouping/isolated-tint UI`).

---

## Self-Review
- **Spec coverage (§ of design doc):** §2 Claim seam → T2; §3a transparent → covered by A + `LinkedToAccount` (T3); §3b grouping key → T1+T5; §3c derived-from-named → T3; §3d isolated tint → T6; §1 disclosure≠display → T6 (`amplify` is display; emission is member-only in T5/T10) + T9 (access ≠ compelled disclosure); opsec modes → T4; show-all/foremost → T10; sybil-count → T7; wire/descriptor → T5+T8; surfaces → T11–T13. **Backend 1 (§4) intentionally absent** — separate plan. Groupings revocation (§10 open Q) = re-issue certs per chat/epoch; deferred to a follow-up (not blocking B0).
- **Placeholder scan:** UI tasks (T11–T13) are interface+step level by design (mechanical, mirror shipped A code) — acceptable per the skill's "follow established patterns"; crypto/core/wire tasks carry full code/tests. No TBDs.
- **Type consistency:** `Predicate::Grouping.grouping_pub: Vec<u8>` = the derived grouping public key bytes (`IdentityPublic.sig_vk`) — used consistently in T2/T3/T5. `chat_context: [u8;32]`, `account_fp/ancestor_fp/subject: [u8;48]`, `Verdict::{Pass,Fail}`, `LINKAGE_SENTINEL=0xF6` (distinct from A's `PRESENCE_SENTINEL=0xF5`) — consistent across tasks.

## Notes / open confirmations before execution
- Confirm `SignedCert` field/verify names in Task 1 Step 4 against `account.rs` (the plan gives the exact adaptation).
- `IdentityPublic` reconstruction from `sig_vk` bytes in T3/T5 — confirm the public-from-bytes constructor name in `identity.rs` (add a `IdentityPublic::from_sig_vk(Vec<u8>)` thin ctor if absent; one-line).
