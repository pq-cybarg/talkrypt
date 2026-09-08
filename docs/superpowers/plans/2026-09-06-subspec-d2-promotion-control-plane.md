# Sub-spec D2 (Promotion Control Plane) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Coordinated, consented, re-keyed promotion of a live ephemeral group chat into a persistent successor — a signed `Promote` proposal + per-member `Consent` + member picker + target tier, committed with a PCS-boundary re-key.

**Architecture:** `Promote`/`Consent` are new `Frame`s (tags 13/14) signed under the sender's tree-bound leaf key over NEW domain-separated transcripts, so `GroupAuth.fst`'s theorems extend by construction. On the consent rule being met, the host commits a re-key reusing the existing `self_update`/`commit_update`/`Proposal::Remove` machinery (un-picked members removed), then marks the chat persistent (`Core::set_persistence(true)` from D1). Retention (D3) rides the `retention_mode` field.

**Tech Stack:** Rust (`crates/crypto/src/treekem.rs`, `crates/core/src/engine.rs`, `descriptor.rs`), `talkrypt_wire`, `cargo test`, `cargo kani`.

## Global Constraints

- **Depends on D1** (merged: `Core::set_persistence`, the outbox). Depends on **LeafSigMode** (merged: `my_sig`, `my_leaf_sig_public()`).
- **FV-preservation:** `Promote`/`Consent` signed under `leaf_sig_keys[me]` over transcripts **domain-separated from `SIG_CONTEXT` (`b"talkrypt-treekem-msg-v2"`) and `POP_CONTEXT` (`b"talkrypt-treekem-leaf-pop-v2"`)** — else GroupAuth Thm 6 (`PopDomainSep`) breaks. Transcripts injective (length-prefixed) — Thm 2. Re-key rebinds leaf keys via the existing `sig_update`/PoP path — Thms 4/7/8. Decoders flat/bounded (`MAX_PICKED` fixed cap) with Kani proofs. Never edit `crates/wire/src/lib.rs` codec.
- **Wire tags:** `Promote` = **13**, `Consent` = **14** (D1 took 15-18). `Route` tags 3+ free.
- **Commit identity:** `pq-cybarg <resistant@tuta.com>`; branch `feat/subspec-d2-promotion` off main; push `GIT_SSH_COMMAND=/usr/bin/ssh`.

## File Structure

- **Modify `crates/crypto/src/treekem.rs`** — add `PROMOTE_CONTEXT`/`CONSENT_CONTEXT`, `promote_transcript`/`consent_transcript`, and `TreeKemGroup::{sign_promote, verify_promote, sign_consent, verify_consent}` mirroring `encrypt_signed`/`decrypt_verified`.
- **Modify `crates/core/src/engine.rs`** — `Frame::Promote`/`Consent` (13/14) + flat decode + Kani; `PromoteState` (pending proposal + tallied consents) in `Inner`; `Core::propose_promote`/`respond_promote`; reader-loop dispatch (`handle_promote`/`handle_consent`); the commit-on-satisfied re-key; `Event::{PromoteProposed, Promoted, PromoteAborted}`.
- **Modify `crates/core/src/descriptor.rs`** — descriptor **v6**: append `promotion: Option<PromotionMeta>` under `if version >= 6`.
- **Modify `crates/ffi/src/lib.rs`, `crates/cli/src/main.rs`, `crates/tui/src/main.rs`, `crates/desktop/src/main.rs`** — FFI methods + `/promote` `/consent` CLI + event handling for the new `Event`s (exhaustive matches).

---

### Task 1: Promotion transcripts + sign/verify in TreeKEM

**Files:** Modify `crates/crypto/src/treekem.rs` (near `sig_transcript` `:475`, `SIG_CONTEXT` `:420`).

**Interfaces produced:**
- `pub fn sign_promote(&self, body: &[u8]) -> Result<Vec<u8>>` — returns `my_sig`'s signature over `promote_transcript(epoch, my_leaf, body)`.
- `pub fn verify_promote(&self, leaf: u32, body: &[u8], sig: &[u8]) -> bool` — verifies under `leaf_sig_keys[leaf]`, fail-closed on unknown leaf.
- `sign_consent`/`verify_consent` identically over `consent_transcript`.

- [ ] **Step 1: Write the failing test** (in treekem.rs tests):

```rust
#[test]
fn promote_consent_sign_verify_and_domain_separation() {
    let g = TreeKemGroup::create_with(KemProfile::default());
    let body = b"promote-body";
    let sig = g.sign_promote(body).unwrap();
    assert!(g.verify_promote(0, body, &sig), "own leaf verifies its promote sig");
    assert!(!g.verify_promote(0, b"tampered", &sig), "a different body must not verify");
    // Domain separation: a promote signature must NOT verify as a consent (Thm 6).
    assert!(!g.verify_consent(0, body, &sig), "promote sig must not verify under consent context");
    // Unknown leaf fails closed.
    assert!(!g.verify_promote(99, body, &sig));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-crypto promote_consent_sign_verify_and_domain_separation 2>&1 | tail -5`
Expected: FAIL — `sign_promote` undefined.

- [ ] **Step 3: Implement.** After `POP_CONTEXT` (`:425`):

```rust
/// Domain-separated from SIG_CONTEXT and POP_CONTEXT so a promote/consent signature can
/// never be replayed as a group message, a PoP, or each other (GroupAuth Thm 6).
const PROMOTE_CONTEXT: &[u8] = b"talkrypt-treekem-promote-v1";
const CONSENT_CONTEXT: &[u8] = b"talkrypt-treekem-consent-v1";

fn promote_transcript(epoch: u32, leaf: u32, body: &[u8]) -> Vec<u8> {
    let mut w = talkrypt_wire::Writer::new();
    w.put_bytes(PROMOTE_CONTEXT);
    w.put_u32(epoch);
    w.put_u32(leaf);
    w.put_bytes(body);
    w.into_vec()
}
fn consent_transcript(epoch: u32, leaf: u32, body: &[u8]) -> Vec<u8> {
    let mut w = talkrypt_wire::Writer::new();
    w.put_bytes(CONSENT_CONTEXT);
    w.put_u32(epoch);
    w.put_u32(leaf);
    w.put_bytes(body);
    w.into_vec()
}
```

On `impl TreeKemGroup` (near `encrypt_signed`), add (using `self.my_sig`, `self.my_leaf`, `self.epoch`, `self.leaf_sig_keys`, mirroring `decrypt_verified`'s lookup+verify):

```rust
pub fn sign_promote(&self, body: &[u8]) -> Result<Vec<u8>> {
    let sk = self.my_sig.as_ref().ok_or(CryptoError::NotReady)?;
    Ok(sk.sign(&promote_transcript(self.epoch, self.my_leaf, body)))
}
pub fn verify_promote(&self, leaf: u32, body: &[u8], sig: &[u8]) -> bool {
    match self.leaf_sig_keys.get(&leaf) {
        Some(pk) => pk.verify(&promote_transcript(self.epoch, leaf, body), sig),
        None => false, // fail closed (Thm 1)
    }
}
pub fn sign_consent(&self, body: &[u8]) -> Result<Vec<u8>> {
    let sk = self.my_sig.as_ref().ok_or(CryptoError::NotReady)?;
    Ok(sk.sign(&consent_transcript(self.epoch, self.my_leaf, body)))
}
pub fn verify_consent(&self, leaf: u32, body: &[u8], sig: &[u8]) -> bool {
    match self.leaf_sig_keys.get(&leaf) {
        Some(pk) => pk.verify(&consent_transcript(self.epoch, leaf, body), sig),
        None => false,
    }
}
```

*(Confirm field names `my_leaf`/`epoch`/`leaf_sig_keys`/`my_sig` against treekem.rs and the exact `sign`/`verify` signatures on `IdentityKeyPair`/`IdentityPublic`; mirror `encrypt_signed`/`decrypt_verified` exactly.)*

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-crypto promote_consent_sign_verify_and_domain_separation 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/crypto/src/treekem.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d2): promote/consent transcripts + sign/verify (domain-separated, fail-closed)"
```

---

### Task 2: `Promote`/`Consent` frames (tags 13/14) — flat decode + Kani

**Files:** Modify `crates/core/src/engine.rs` (`Frame` enum, encode, decode, `d1_proofs`→add `d2_proofs`).

**Interfaces produced:**
- `Frame::Promote(Vec<u8>)` (tag 13) and `Frame::Consent(Vec<u8>)` (tag 14) — each an opaque signed blob (the inner structured `PromoteBody`/`ConsentBody` is decoded in core). The FRAME level is a length-prefixed `Vec<u8>` (like `GroupMsg`), so its decode is trivially flat.
- `PromoteBody { target_tier: u8, retention_mode: u8, consent_rule: u8, picked: Vec<[u8;48]> (cap MAX_PICKED=256), onion: String, epoch: u32 }` with `encode`/`decode` (flat: fixed fps in a capped Vec) + `ConsentBody { promote_id: [u8;32], accept: bool, leaf: u32, epoch: u32 }`.

- [ ] **Step 1: Write the failing test:**

```rust
#[test]
fn promote_consent_frames_and_bodies_roundtrip() {
    let body = PromoteBody { target_tier: 1, retention_mode: 0, consent_rule: 0,
        picked: vec![[1u8;48],[2u8;48]], onion: "abc.onion".into(), epoch: 3 };
    assert_eq!(PromoteBody::decode(&body.encode()).unwrap(), body);
    // Frame wrapper round-trips.
    let f = Frame::Promote(body.encode());
    assert!(matches!(Frame::decode(&f.encode()), Some(Frame::Promote(_))));
    // Over-cap picked list is rejected.
    let mut w = Writer::new(); w.put_u8(1); w.put_u8(0); w.put_u8(0); w.put_u32(300); // n_picked > MAX_PICKED
    assert!(PromoteBody::decode(&w.into_vec()).is_none());
    let cb = ConsentBody { promote_id: [7u8;32], accept: true, leaf: 2, epoch: 3 };
    assert_eq!(ConsentBody::decode(&cb.encode()).unwrap(), cb);
}
```

- [ ] **Step 2: Run — expect FAIL** (`PromoteBody` undefined).

Run: `cargo test -p talkrypt-core promote_consent_frames_and_bodies_roundtrip 2>&1 | tail -5`

- [ ] **Step 3: Implement.** Add `Frame::Promote(Vec<u8>)`/`Consent(Vec<u8>)` variants + encode arms (tags 13/14, `w.put_bytes(b)`) + decode arms (`13 => Frame::Promote(r.get_vec().ok()?)`, `14 => Frame::Consent(r.get_vec().ok()?)`). Add the body types (new small module or in engine.rs):

```rust
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PromoteBody {
    pub target_tier: u8, pub retention_mode: u8, pub consent_rule: u8,
    pub picked: Vec<[u8; 48]>, pub onion: String, pub epoch: u32,
}
impl PromoteBody {
    const MAX_PICKED: usize = 256;
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u8(self.target_tier); w.put_u8(self.retention_mode); w.put_u8(self.consent_rule);
        w.put_u32(self.picked.len() as u32);
        for fp in &self.picked { w.put_bytes(fp); }
        w.put_bytes(self.onion.as_bytes()); w.put_u32(self.epoch);
        w.into_vec()
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let target_tier = r.get_u8().ok()?; let retention_mode = r.get_u8().ok()?;
        let consent_rule = r.get_u8().ok()?;
        let n = r.get_u32().ok()? as usize;
        if n > Self::MAX_PICKED { return None; }
        let mut picked = Vec::with_capacity(n);
        for _ in 0..n {
            let v = r.get_bytes().ok()?; if v.len() != 48 { return None; }
            let mut fp = [0u8; 48]; fp.copy_from_slice(v); picked.push(fp);
        }
        let onion = String::from_utf8(r.get_vec().ok()?).ok()?;
        let epoch = r.get_u32().ok()?;
        r.finish().ok()?;
        Some(Self { target_tier, retention_mode, consent_rule, picked, onion, epoch })
    }
    /// SHA-256 of the canonical body — binds a Consent to exactly this proposal.
    pub fn id(&self) -> [u8; 32] { gossip_id(&self.encode()) }
}
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ConsentBody { pub promote_id: [u8;32], pub accept: bool, pub leaf: u32, pub epoch: u32 }
impl ConsentBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_bytes(&self.promote_id); w.put_u8(self.accept as u8);
        w.put_u32(self.leaf); w.put_u32(self.epoch); w.into_vec()
    }
    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let v = r.get_bytes().ok()?; if v.len()!=32 { return None; }
        let mut promote_id=[0u8;32]; promote_id.copy_from_slice(v);
        let accept = r.get_u8().ok()? != 0; let leaf = r.get_u32().ok()?; let epoch = r.get_u32().ok()?;
        r.finish().ok()?;
        Some(Self { promote_id, accept, leaf, epoch })
    }
}
```

Add Kani (in the `#[cfg(kani)] mod d1_proofs` or a new `d2_proofs`):

```rust
#[kani::proof] #[kani::unwind(6)]
fn promote_body_decode_never_panics() {
    let len: usize = kani::any(); kani::assume(len <= 64);
    let data: [u8; 64] = kani::any(); let _ = PromoteBody::decode(&data[..len]);
}
#[kani::proof] #[kani::unwind(6)]
fn consent_body_decode_never_panics() {
    let len: usize = kani::any(); kani::assume(len <= 64);
    let data: [u8; 64] = kani::any(); let _ = ConsentBody::decode(&data[..len]);
}
```

- [ ] **Step 4: Run — expect PASS.** `cargo test -p talkrypt-core promote_consent_frames_and_bodies_roundtrip`

- [ ] **Step 5: Commit** — `feat(d2): Promote/Consent frames (tags 13/14) + flat bodies + Kani proofs`

---

### Task 3: `PromoteState` in `Inner` + `propose_promote` (host broadcasts a signed proposal)

**Files:** Modify `crates/core/src/engine.rs` (`Inner`, `Core` impl).

**Interfaces produced:**
- `Inner.promote: Mutex<Option<PromoteState>>` where `PromoteState { body: PromoteBody, consents: HashMap<u32 /*leaf*/, bool> }`.
- `pub async fn Core::propose_promote(&self, target_tier: u8, retention_mode: u8, consent_rule: u8, picked: Vec<[u8;48]>, onion: String) -> Result<[u8;32]>` — builds `PromoteBody` (epoch = current group epoch), signs it (`sign_promote`), broadcasts `Frame::Promote(sig-wrapped body)`, stores `PromoteState`, returns the `promote_id`.

- [ ] **Step 1: failing test** — `propose_promote` on a host group returns a 32-byte id and stores pending state (`host.inner.promote.lock().unwrap().is_some()`).
- [ ] **Step 2: run → FAIL.**
- [ ] **Step 3: implement.** Signed-frame wire format: `body_bytes ‖ u32 leaf ‖ sig` (so receivers know which leaf to `verify_promote` under). Add `Inner.promote` field (init `Mutex::new(None)`). `propose_promote` reads the group epoch + `my_leaf`, `sign_promote(&body.encode())`, wraps `[body_len ‖ body ‖ leaf ‖ sig]`, `route(Broadcast)`, stores state.
- [ ] **Step 4: run → PASS.**
- [ ] **Step 5: commit** — `feat(d2): propose_promote broadcasts a signed Promote + tracks pending state`

---

### Task 4: Receive + verify `Promote`; prompt consent; send signed `Consent`

**Files:** `engine.rs` reader-loop dispatch + `handle_promote`.

**Interfaces:** consumes Task 1/2/3. Produces `Event::PromoteProposed { by: [u8;48], target_tier: u8, retention_mode: u8, picked: Vec<[u8;48]> }`; `Core::respond_promote(&self, promote_id: [u8;32], accept: bool)`.

- [ ] Steps: failing test (a member receives a `Promote`, verifies the signature under the proposer leaf, emits `PromoteProposed`); implement `handle_promote` (unwrap `body‖leaf‖sig`, `verify_promote(leaf, body, sig)` fail-closed, decode `PromoteBody`, store pending, emit event); `respond_promote` builds `ConsentBody{promote_id, accept, my_leaf, epoch}`, `sign_consent`, sends `Frame::Consent` to the committer/host. Reuse the L1 `ApprovalFn` pattern for the accept prompt where a UI hook is wanted. Commit.

---

### Task 5: Host tallies `Consent`; commit the re-key when the rule is met

**Files:** `engine.rs` `handle_consent` + a `commit_promotion` helper reusing `self_update`/`commit_update`/`Proposal::Remove`.

**Interfaces:** consumes Task 1-4. Produces `Event::Promoted { }` / `Event::PromoteAborted`.

- [ ] Steps: failing integration test (`LoopbackFabric`, host + 2 members, unanimous accept → `Promoted` fires + `host.is_persistent()` true + un-picked member removed from roster); implement `handle_consent` (verify under the consenting leaf via `verify_consent`, bind to `promote_id`, dedup per distinct leaf, reject stale-epoch/replay, tally into `PromoteState.consents`); when the `consent_rule` is satisfied over the picked set, run `commit_promotion`: build `Proposal::Remove` for each un-picked/decliner member, drive a `sig_update` re-key via the existing commit path, broadcast Commit+Roster, then `self.set_persistence(true)` and emit `Promoted`. Unanimous timeout/decline → signed abort + `PromoteAborted`, no re-key. Commit.

---

### Task 6: Descriptor v6 — carry the promotion target for reconnect

**Files:** `crates/core/src/descriptor.rs` (v5 → v6).

- [ ] Steps: failing round-trip test (a v6 descriptor with `promotion: Some(PromotionMeta{tier, onion})` re-encodes equal; a v1-v5 invite decodes with `promotion: None`); implement `DESCRIPTOR_VERSION = 6`, `pub promotion: Option<PromotionMeta>` field, encode under `if self.version >= 6`, decode under `if version >= 6` (append-only, same discipline as v4 `message_padding`/v5 `vouch_policy`). Commit.

---

### Task 7: Consent-rule variants (unanimous / opt-in / host-mandate) + adversarial tests

**Files:** `engine.rs` (the tally logic from Task 5, parameterized by `consent_rule`).

- [ ] Steps: failing tests for each rule — **unanimous** (any decline/timeout aborts); **opt-in-successor** (each accepting member is carried; non-consenters dropped, no abort); **host-mandate** (decliner removed via `Proposal::Remove`, promotion proceeds). Adversarial: a forged `Consent` (wrong leaf), a replayed `Consent` (old `promote_id`/epoch), a `Consent` from a non-picked member — all rejected. Implement the three-way tally + guards. Commit.

---

### Task 8: FFI + CLI/TUI/desktop surface + Kani-in-CI + full green

**Files:** `crates/ffi/src/lib.rs`, `crates/cli/src/main.rs`, `crates/tui/src/main.rs`, `crates/desktop/src/main.rs`, `.github/workflows/formal.yml`.

- [ ] Steps: FFI `propose_promote`/`respond_promote` + `FfiEvent::{PromoteProposed, Promoted, PromoteAborted}` and the `Event→FfiEvent` mapping; **update every exhaustive `Event` match** (cli/tui/desktop) for the 3 new variants; CLI `/promote <tier> <retention> <rule> <fp…>` and `/consent <id> yes|no`; add the two Kani harnesses to `formal.yml` (`engine::d2_proofs::promote_body_decode_never_panics`, `consent_body_decode_never_panics`). Run `cargo test -p talkrypt-core`, `cargo build --workspace`, and the two `cargo kani` harnesses (expect `VERIFICATION:- SUCCESSFUL`). Commit.

---

## Self-Review

**Spec coverage (D2):** signed Promote/Consent under leaf key + domain-separated transcripts — Task 1; frames + flat bodies + Kani — Task 2; propose/broadcast — Task 3; verify+consent — Task 4; tally+re-key commit — Task 5; descriptor v6 — Task 6; all three consent rules + adversarial — Task 7; FFI/UI/CI — Task 8. Retention `retention_mode` field is carried in `PromoteBody` (Task 2) and shown at consent (Task 4), with the D3 sealing behavior a separate plan. Member picker = `PromoteBody.picked` + `Proposal::Remove` of the rest (Task 5).

**Placeholder scan:** the crypto field names (`my_leaf`/`epoch`/`leaf_sig_keys`) and the `IdentityKeyPair::sign`/`IdentityPublic::verify` signatures must be confirmed against `treekem.rs` at implementation time (Task 1 Step 3 note) — mirror `encrypt_signed`/`decrypt_verified` exactly. Tasks 3-5/7 use prose steps with the interfaces named; each is one testable deliverable. All wire/body code is complete in Task 1/2/6.

**Type consistency:** `PromoteBody`/`ConsentBody` (Task 2) reused verbatim in Tasks 3-5/7; `promote_id = PromoteBody::id()` ([u8;32]) consistent across propose/consent/tally; `sign_promote`/`verify_promote`/`sign_consent`/`verify_consent` (Task 1) used in Tasks 3-5. `Event::{PromoteProposed, Promoted, PromoteAborted}` defined Task 4/5, mapped Task 8.

## Execution Handoff

Plan saved to `docs/superpowers/plans/2026-09-06-subspec-d2-promotion-control-plane.md`. Options: **1. Subagent-Driven (recommended)** — fresh subagent per task, review between (best for the crypto-adjacent tasks); **2. Inline Execution** — batch with checkpoints.
