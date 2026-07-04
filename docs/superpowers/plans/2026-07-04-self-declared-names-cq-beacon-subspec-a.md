# Self-Declared Names + CQ Beacon (Sub-spec A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a participant broadcast a self-declared name ("callsign") that renders over their messages to **every** member of a chat — pairwise or group — with honest trust tiers (bare / account-linked / registry-confirmed), a configurable CQ beacon, and per-chat collision policy.

**Architecture:** A new `NamePresence` payload (device-signed + chat-context-bound for the account-linked tier) is delivered pairwise as `Frame::Presence` (tag 9) and in groups as a sentinel-tagged group payload inside the existing `Frame::GroupMsg` envelope — so it inherits the committer fan-out + gossip + dedup path. A viewer caches `sender-fp → name`, resolves a display tier + collision caveat via a per-chat `NameTrustPolicy`, and emits `Event::Name`. Emission composes three modes: event-driven (join / roster-grow / manual), an optional periodic timer, and an optional on-message name-id.

**Tech Stack:** Rust (crates `core`, `crypto`, `wire`, `ffi`, `desktop`, `cli`), uniffi 0.31, Kotlin/Android, egui (desktop). ML-DSA-87 signatures (`Vec<u8>`), SHA-256 (`sha2`), TreeKEM sender-key groups.

## Global Constraints

- **Signatures are `Vec<u8>` everywhere public** — never an `ml_dsa::Signature` type. `IdentityKeyPair::sign(&[u8]) -> Vec<u8>`; `IdentityPublic::verify(&[u8], &[u8]) -> Result<()>`.
- **`IdentityKeyPair` is NOT `Clone`.** Sign with `inner.identity` in place; never move it.
- **`Frame`, `route`, `Inner`, `handle_*`, `register`, `reader_loop` are private to the `engine` module.** All engine changes are in-module (`crates/core/src/engine.rs`).
- **Fingerprints are `[u8; 48]`** (`FINGERPRINT_LEN = 48`).
- **Wire API** (`talkrypt_wire`): `Writer::new()` → `put_u8`, `put_u32`, `put_bytes` (length-prefixed), `into_vec()`. `Reader::new(&[u8])` → `get_u8`, `get_u32`, `get_bytes` (borrowed), `get_vec` (owned), `finish()`. **No `put_u64`/`get_u64`** — encode `u64` as two `u32` (hi, lo) via local helpers; do NOT modify the Kani-proven `wire` crate.
- **`marking::decode_payload` calls `r.finish()`** (rejects trailing bytes). The group-payload extension MUST use a leading sentinel byte `0xF5` that a legacy marking opt-flag (always `0x00`/`0x01`) can never be, so old clients drop presence payloads gracefully (`decode_payload` → `None`).
- **Descriptor version check is exact-equality** (`version != DESCRIPTOR_VERSION`) with a strict trailing `r.finish()`. Adding a field + bumping to v2 requires loosening both (accept v1 & v2; only read the new appended field when `version >= 2`).
- **The descriptor KAT** (`descriptor.rs` `mod kat`, frozen base32 string + full struct literal) must be updated for any field change.
- **"Beacon" is a reserved name** (`crypto/beacon.rs` = scheme adverts). Use `Presence` (types) / `CQ` (user-facing). Never name new symbols `beacon`.
- **Naming/opsec:** commit AND author as `pq-cybarg <resistant@tuta.com>`.
- **Never disable client hosting** on any client.

---

## File Structure

**New (core):**
- `crates/core/src/presence.rs` — `NamePresence` (Bare/Linked) wire type + `u64` helpers + sign/verify + chat-context derivation + `NameBacking`/`NameEntry`/`NameBook` + `NameRecord` + `PresenceCadence`.
- `crates/core/src/nametrust.rs` — `NameTier`, `NameTrustPolicy`, `Tint`, `Badge`, `NameRender`, `confusable_fold`, `resolve_render` (collision + policy), render-precedence with B/C no-op hooks.

**Modified (core):**
- `crates/core/src/engine.rs` — `Frame::Presence` (tag 9); group-payload sentinel dispatch; `Event::Name`; `Inner` fields (`leading_name`, `presence_seq`, `names`, `cadence`); `Core::set_leading_name`/`announce_presence`/`set_presence_cadence`; emission triggers + periodic timer; on-message name-id; group + pairwise verification handlers.
- `crates/core/src/descriptor.rs` — `name_trust_policy` field; `DESCRIPTOR_VERSION` 1→2 + back-compat decode + KAT v2.
- `crates/core/src/lib.rs` — `pub mod presence; pub mod nametrust;` + re-exports.

**Modified:** `crates/ffi/src/lib.rs`; Android (`MainActivity.kt`, `ChatEvents.kt`, new `NameBook.kt`); `crates/desktop/src/main.rs`; `crates/cli/src/main.rs`.

---

## Phase 1 — Core types

### Task 1: `NamePresence` wire type + `u64` helpers

**Files:**
- Create: `crates/core/src/presence.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod presence;`)

**Interfaces:**
- Produces: `enum NamePresence { Bare { seq: u64, label: String }, Linked { seq: u64, presentation: Presentation, context: [u8;48], sig: Vec<u8> } }`; `NamePresence::encode(&self) -> Vec<u8>`; `NamePresence::decode(&[u8]) -> Result<NamePresence>`; `NamePresence::seq(&self) -> u64`; `pub(crate) fn put_u64(&mut Writer, u64)`, `pub(crate) fn get_u64(&mut Reader) -> Result<u64>`.

Note: `context` is `[u8; 48]` to reuse fingerprint sizing conventions and the SHA-384-free path — we derive it as the first 48 bytes are unnecessary; use SHA-256 → 32 bytes. **Use `[u8; 32]`** (SHA-256). (Correction applied below.)

- [ ] **Step 1: Write the failing test**

Add to `crates/core/src/presence.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use talkrypt_crypto::{IdentityKeyPair, IdentityChain};

    #[test]
    fn bare_presence_roundtrip() {
        let p = NamePresence::Bare { seq: 7, label: "K1ABC".to_string() };
        let bytes = p.encode();
        assert_eq!(NamePresence::decode(&bytes).unwrap(), p);
        assert_eq!(NamePresence::decode(&bytes).unwrap().seq(), 7);
    }

    #[test]
    fn u64_helpers_roundtrip() {
        let mut w = talkrypt_wire::Writer::new();
        put_u64(&mut w, 0x0123_4567_89AB_CDEF);
        let v = w.into_vec();
        let mut r = talkrypt_wire::Reader::new(&v);
        assert_eq!(get_u64(&mut r).unwrap(), 0x0123_4567_89AB_CDEF);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core presence:: 2>&1 | tail -20`
Expected: FAIL — `cannot find type NamePresence` / module `presence` not found.

- [ ] **Step 3: Write minimal implementation**

Create `crates/core/src/presence.rs` (top of file):
```rust
//! Self-declared name presence ("callsign") payloads. A `NamePresence` is what a
//! peer broadcasts to say "this is <name>". The `Linked` variant is device-signed
//! and chat-context-bound, so it is unforgeable even by a malicious group member
//! (group message attribution is sender-key and insider-spoofable — see
//! `docs/superpowers/specs/2026-07-04-self-declared-names-cq-beacon-subspec-a-design.md`).

use talkrypt_crypto::{CryptoError, IdentityChain};
use talkrypt_wire::{Reader, Writer};
use crate::contacts::Presentation;
use crate::error::{CoreError, Result};

/// `u64` over the `u32`-only wire, big-endian hi‖lo (no `wire` crate change).
pub(crate) fn put_u64(w: &mut Writer, v: u64) {
    w.put_u32((v >> 32) as u32);
    w.put_u32((v & 0xFFFF_FFFF) as u32);
}
pub(crate) fn get_u64(r: &mut Reader) -> Result<u64> {
    let hi = r.get_u32().map_err(|_| CoreError::Malformed("u64 hi"))? as u64;
    let lo = r.get_u32().map_err(|_| CoreError::Malformed("u64 lo"))? as u64;
    Ok((hi << 32) | lo)
}

/// A self-declared name announcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NamePresence {
    /// Cosmetic, unauthenticated. Attribution rides the (insider-spoofable) group
    /// sender key / pairwise transport fp.
    Bare { seq: u64, label: String },
    /// Account-linked: a device-key signature over `(seq ‖ label ‖ context)`, plus
    /// the account→device certificate chain. Insider-unforgeable.
    Linked { seq: u64, presentation: Presentation, context: [u8; 32], sig: Vec<u8> },
}

impl NamePresence {
    pub fn seq(&self) -> u64 {
        match self { NamePresence::Bare { seq, .. } | NamePresence::Linked { seq, .. } => *seq }
    }

    pub fn label(&self) -> &str {
        match self {
            NamePresence::Bare { label, .. } => label,
            NamePresence::Linked { presentation, .. } =>
                presentation.username.as_deref().unwrap_or(""),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            NamePresence::Bare { seq, label } => {
                w.put_u8(0);
                put_u64(&mut w, *seq);
                w.put_bytes(label.as_bytes());
            }
            NamePresence::Linked { seq, presentation, context, sig } => {
                w.put_u8(1);
                put_u64(&mut w, *seq);
                w.put_bytes(&presentation.encode());
                w.put_bytes(context);
                w.put_bytes(sig);
            }
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<NamePresence> {
        let mut r = Reader::new(bytes);
        let np = match r.get_u8().map_err(|_| CoreError::Malformed("presence tag"))? {
            0 => {
                let seq = get_u64(&mut r)?;
                let label = String::from_utf8(
                    r.get_vec().map_err(|_| CoreError::Malformed("bare label"))?,
                ).map_err(|_| CoreError::Malformed("bare label utf-8"))?;
                NamePresence::Bare { seq, label }
            }
            1 => {
                let seq = get_u64(&mut r)?;
                let presentation = Presentation::decode(
                    r.get_bytes().map_err(|_| CoreError::Malformed("linked presentation"))?,
                )?;
                let ctx = r.get_bytes().map_err(|_| CoreError::Malformed("linked context"))?;
                if ctx.len() != 32 { return Err(CoreError::Malformed("context len")); }
                let mut context = [0u8; 32];
                context.copy_from_slice(ctx);
                let sig = r.get_vec().map_err(|_| CoreError::Malformed("linked sig"))?;
                NamePresence::Linked { seq, presentation, context, sig }
            }
            _ => return Err(CoreError::Malformed("presence variant")),
        };
        r.finish().map_err(|_| CoreError::Malformed("presence trailing"))?;
        Ok(np)
    }
}

// silence unused import until Task 3 uses it
#[allow(unused_imports)]
use IdentityChain as _IdentityChain;
```
Add to `crates/core/src/lib.rs` near the other `pub mod` lines:
```rust
pub mod presence;
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core presence:: 2>&1 | tail -20`
Expected: PASS (`bare_presence_roundtrip`, `u64_helpers_roundtrip`).

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/presence.rs crates/core/src/lib.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): NamePresence wire type + u64 wire helpers"
```

---

### Task 2: chat-context derivation + `Linked` sign/verify

**Files:**
- Modify: `crates/core/src/presence.rs`

**Interfaces:**
- Consumes: `NamePresence` (Task 1); `ChatDescriptor` fields `invite_token: Vec<u8>`, `channel: String`.
- Produces: `pub fn chat_context(invite_token: &[u8], channel: &str) -> [u8;32]`; `pub fn sign_input(seq: u64, label: &str, context: &[u8;32]) -> Vec<u8>`; `NamePresence::linked(seq, chain, label, context, signer: &IdentityKeyPair) -> NamePresence`; `NamePresence::verify_linked(&self, now: u64) -> Option<VerifiedName>`; `struct VerifiedName { account_fp: [u8;48], device_fp: [u8;48], label: String, seq: u64 }`.

- [ ] **Step 1: Write the failing test**

Add to the `tests` mod in `presence.rs`:
```rust
    #[test]
    fn linked_presence_signs_and_verifies() {
        let now = 1_000_000u64;
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", now, now + 10_000);
        let ctx = chat_context(&[9u8; 32], "#general");
        let p = NamePresence::linked(3, chain, "K1ABC", ctx, &device);
        let v = p.verify_linked(now).expect("verifies");
        assert_eq!(v.label, "K1ABC");
        assert_eq!(v.account_fp, account.public().fingerprint());
        assert_eq!(v.device_fp, device.public().fingerprint());
    }

    #[test]
    fn linked_presence_rejects_forged_sig() {
        let now = 1_000_000u64;
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", now, now + 10_000);
        let ctx = chat_context(&[9u8; 32], "#general");
        let mut p = NamePresence::linked(3, chain, "K1ABC", ctx, &device);
        if let NamePresence::Linked { sig, .. } = &mut p { sig[0] ^= 0xFF; }
        assert!(p.verify_linked(now).is_none());
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core presence::tests::linked 2>&1 | tail -20`
Expected: FAIL — `chat_context`/`linked`/`verify_linked` not found.

- [ ] **Step 3: Write minimal implementation**

Add to `presence.rs` (replace the `#[allow(unused_imports)]` shim from Task 1):
```rust
use talkrypt_crypto::IdentityKeyPair;
use sha2::{Digest, Sha256};

/// SHA-256(invite_token ‖ channel) — binds a `Linked` presence to THIS chat so it
/// cannot be replayed into another chat to impersonate.
pub fn chat_context(invite_token: &[u8], channel: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(invite_token);
    h.update(channel.as_bytes());
    h.finalize().into()
}

/// The exact bytes the device key signs / a verifier reconstructs.
pub fn sign_input(seq: u64, label: &str, context: &[u8; 32]) -> Vec<u8> {
    let mut w = Writer::new();
    put_u64(&mut w, seq);
    w.put_bytes(label.as_bytes());
    w.put_bytes(context);
    w.into_vec()
}

/// A verified account-linked name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedName {
    pub account_fp: [u8; 48],
    pub device_fp: [u8; 48],
    pub label: String,
    pub seq: u64,
}

impl NamePresence {
    /// Build a signed account-linked presence. `signer` MUST be the chain's leaf
    /// (device) key; `chain.username` is set to `label`.
    pub fn linked(seq: u64, chain: IdentityChain, label: &str, context: [u8; 32],
                  signer: &IdentityKeyPair) -> NamePresence {
        let sig = signer.sign(&sign_input(seq, label, &context));
        NamePresence::Linked {
            seq,
            presentation: Presentation::new(chain, Some(label.to_string())),
            context,
            sig,
        }
    }

    /// Verify a `Linked` presence end to end: chain internally valid, signature by
    /// the chain's device leaf over `(seq ‖ label ‖ context)`. Returns the account
    /// + device fingerprints. `None` for `Bare` or any failure. Does NOT check the
    /// context matches the current chat (the caller does, having the descriptor) or
    /// revocation (the engine does, having the revocation set).
    pub fn verify_linked(&self, now: u64) -> Option<VerifiedName> {
        let NamePresence::Linked { seq, presentation, context, sig } = self else { return None };
        let leaf = presentation.chain.leaf()?;
        let account = presentation.chain.links.first()?.issuer.clone();
        presentation.chain.verify(&account, leaf, now).ok()?;
        let label = presentation.username.clone()?;
        leaf.verify(&sign_input(*seq, &label, context), sig).ok()?;
        Some(VerifiedName {
            account_fp: account.fingerprint(),
            device_fp: leaf.fingerprint(),
            label,
            seq: *seq,
        })
    }
}
```
Confirm `sha2` is a dependency of `crates/core/Cargo.toml` (added during the gossip work). If `cargo test` errors on `sha2`, add `sha2.workspace = true` under `[dependencies]`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core presence:: 2>&1 | tail -20`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/presence.rs crates/core/Cargo.toml
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): chat-context binding + Linked presence sign/verify"
```

---

### Task 3: `NameBook` / `NameEntry` / `NameBacking` + `NameRecord` + `PresenceCadence`

**Files:**
- Modify: `crates/core/src/presence.rs`

**Interfaces:**
- Produces: `enum NameBacking { Bare, Account { chain: IdentityChain } }`; `struct NameEntry { id: String, label: String, backing: NameBacking }`; `struct NameBook { entries: Vec<NameEntry>, default: Option<String> }` with `encode`/`decode`; `struct NameRecord { label: String, tier: NameTier, seq: u64, account_fp: Option<[u8;48]> }` (uses `NameTier` from Task 4 — declare a forward `use crate::nametrust::NameTier;`); `struct PresenceCadence { periodic_secs: Option<u64>, on_message_id: bool }` with `const MIN_PERIODIC_SECS: u64 = 60;`.

- [ ] **Step 1: Write the failing test**
```rust
    #[test]
    fn namebook_roundtrip() {
        let now = 1u64;
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", now, now + 10);
        let book = NameBook {
            entries: vec![
                NameEntry { id: "1".into(), label: "Whiskey".into(), backing: NameBacking::Bare },
                NameEntry { id: "2".into(), label: "K1ABC".into(),
                            backing: NameBacking::Account { chain } },
            ],
            default: Some("2".into()),
        };
        let bytes = book.encode();
        assert_eq!(NameBook::decode(&bytes).unwrap(), book);
    }

    #[test]
    fn cadence_enforces_floor() {
        let c = PresenceCadence { periodic_secs: Some(1), on_message_id: false };
        assert_eq!(c.effective_periodic(), Some(MIN_PERIODIC_SECS));
        assert_eq!(PresenceCadence::default().effective_periodic(), None);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core presence::tests::namebook 2>&1 | tail -20`
Expected: FAIL — types not found.

- [ ] **Step 3: Write minimal implementation**

Add to `presence.rs`:
```rust
use crate::nametrust::NameTier;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameBacking {
    Bare,
    Account { chain: IdentityChain },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameEntry { pub id: String, pub label: String, pub backing: NameBacking }

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NameBook { pub entries: Vec<NameEntry>, pub default: Option<String> }

impl NameBook {
    pub fn get(&self, id: &str) -> Option<&NameEntry> { self.entries.iter().find(|e| e.id == id) }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_u32(self.entries.len() as u32);
        for e in &self.entries {
            w.put_bytes(e.id.as_bytes());
            w.put_bytes(e.label.as_bytes());
            match &e.backing {
                NameBacking::Bare => w.put_u8(0),
                NameBacking::Account { chain } => { w.put_u8(1); w.put_bytes(&chain.encode()); }
            }
        }
        match &self.default {
            Some(d) => { w.put_u8(1); w.put_bytes(d.as_bytes()); }
            None => w.put_u8(0),
        }
        w.into_vec()
    }

    pub fn decode(bytes: &[u8]) -> Result<NameBook> {
        let mut r = Reader::new(bytes);
        let n = r.get_u32().map_err(|_| CoreError::Malformed("book len"))? as usize;
        if n > 4096 { return Err(CoreError::Malformed("too many names")); }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let id = String::from_utf8(r.get_vec().map_err(|_| CoreError::Malformed("id"))?)
                .map_err(|_| CoreError::Malformed("id utf-8"))?;
            let label = String::from_utf8(r.get_vec().map_err(|_| CoreError::Malformed("label"))?)
                .map_err(|_| CoreError::Malformed("label utf-8"))?;
            let backing = match r.get_u8().map_err(|_| CoreError::Malformed("backing tag"))? {
                0 => NameBacking::Bare,
                1 => NameBacking::Account {
                    chain: IdentityChain::decode(
                        r.get_bytes().map_err(|_| CoreError::Malformed("chain"))?)?,
                },
                _ => return Err(CoreError::Malformed("backing variant")),
            };
            entries.push(NameEntry { id, label, backing });
        }
        let default = match r.get_u8().map_err(|_| CoreError::Malformed("default tag"))? {
            0 => None,
            1 => Some(String::from_utf8(r.get_vec().map_err(|_| CoreError::Malformed("default"))?)
                .map_err(|_| CoreError::Malformed("default utf-8"))?),
            _ => return Err(CoreError::Malformed("default variant")),
        };
        r.finish().map_err(|_| CoreError::Malformed("book trailing"))?;
        Ok(NameBook { entries, default })
    }
}

/// A viewer's cached, resolved name for one peer fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameRecord {
    pub label: String,
    pub tier: NameTier,
    pub seq: u64,
    pub account_fp: Option<[u8; 48]>,
}

pub const MIN_PERIODIC_SECS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct PresenceCadence {
    pub periodic_secs: Option<u64>,
    pub on_message_id: bool,
}
impl PresenceCadence {
    /// Periodic interval clamped to the floor; `None` = periodic disabled.
    pub fn effective_periodic(&self) -> Option<u64> {
        self.periodic_secs.map(|s| s.max(MIN_PERIODIC_SECS))
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core presence:: 2>&1 | tail -20`
Expected: FAIL to COMPILE until Task 4 defines `NameTier` — so **do Task 4 next, then re-run.** (This is an intentional cross-task type; see Task 4 Interfaces.)

- [ ] **Step 5: Commit** (after Task 4 makes it compile — see Task 4 Step 5.)

---

### Task 4: `nametrust.rs` — tiers, policy, render surface, confusable-fold

**Files:**
- Create: `crates/core/src/nametrust.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod nametrust;`)

**Interfaces:**
- Produces: `enum NameTier { Bare, Linked, RegistryConfirmed }`; `enum NameTrustPolicy { SignalStyle, WarnOnCollision, SuppressColliding }` (default `SignalStyle`) with `tag()`/`from_tag()`; `enum Tint { Default, Verified, /* B/C hooks: */ Isolated, Vouched }`; `struct Badge(pub &'static str)`; `struct NameRender { label: Option<String>, tier: NameTier, badge: Badge, tint: Tint, caveat: Option<String>, safety_number: String }`; `fn confusable_fold(&str) -> String`; `fn resolve_render(subject_fp: [u8;48], rec: &NameRecord, others: &HashMap<[u8;48], NameRecord>, policy: NameTrustPolicy, safety_number: String) -> NameRender`.

- [ ] **Step 1: Write the failing test**

Create `crates/core/src/nametrust.rs` with:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::NameRecord;
    use std::collections::HashMap;

    fn rec(label: &str, tier: NameTier, acct: u8) -> NameRecord {
        NameRecord { label: label.into(), tier, seq: 1, account_fp: Some([acct; 48]) }
    }

    #[test]
    fn confusable_fold_collapses_cyrillic() {
        assert_eq!(confusable_fold("Аlice"), confusable_fold("alice")); // Cyrillic А
    }

    #[test]
    fn signal_style_never_warns() {
        let mut others = HashMap::new();
        others.insert([1u8; 48], rec("Alice", NameTier::RegistryConfirmed, 1));
        let r = resolve_render([2u8; 48], &rec("Alice", NameTier::Bare, 2),
                               &others, NameTrustPolicy::SignalStyle, "SN".into());
        assert_eq!(r.label.as_deref(), Some("Alice"));
        assert!(r.caveat.is_none());
    }

    #[test]
    fn warn_flags_bare_collision_with_verified() {
        let mut others = HashMap::new();
        others.insert([1u8; 48], rec("Alice", NameTier::RegistryConfirmed, 1));
        let r = resolve_render([2u8; 48], &rec("Alice", NameTier::Bare, 2),
                               &others, NameTrustPolicy::WarnOnCollision, "SN".into());
        assert_eq!(r.label.as_deref(), Some("Alice"));
        assert!(r.caveat.as_deref().unwrap().contains("does not match"));
    }

    #[test]
    fn suppress_hides_bare_collision() {
        let mut others = HashMap::new();
        others.insert([1u8; 48], rec("Alice", NameTier::Linked, 1));
        let r = resolve_render([2u8; 48], &rec("Alice", NameTier::Bare, 2),
                               &others, NameTrustPolicy::SuppressColliding, "SN".into());
        assert!(r.label.is_none());
        assert!(r.caveat.as_deref().unwrap().contains("suppressed"));
    }

    #[test]
    fn verified_name_keeps_verified_tint() {
        let r = resolve_render([1u8; 48], &rec("Alice", NameTier::RegistryConfirmed, 1),
                               &HashMap::new(), NameTrustPolicy::SignalStyle, "SN".into());
        assert_eq!(r.tint, Tint::Verified);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core nametrust:: 2>&1 | tail -20`
Expected: FAIL — module/type not found.

- [ ] **Step 3: Write minimal implementation**

Prepend to `crates/core/src/nametrust.rs`:
```rust
//! Trust tiers + per-chat display policy for self-declared names. The render surface
//! (`NameRender`) exposes a `tint` colour slot that Sub-specs B (isolation marking)
//! and C (vouch thresholds) fill via the `Tint::Isolated` / `Tint::Vouched` hooks.

use std::collections::HashMap;
use crate::presence::NameRecord;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameTier { Bare, Linked, RegistryConfirmed }
impl NameTier {
    pub fn rank(self) -> u8 { match self { NameTier::Bare => 0, NameTier::Linked => 1, NameTier::RegistryConfirmed => 2 } }
    pub fn badge(self) -> Badge {
        match self {
            NameTier::Bare => Badge(""),
            NameTier::Linked => Badge("\u{1F517}"),          // 🔗
            NameTier::RegistryConfirmed => Badge("\u{2713}"), // ✓
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameTrustPolicy { SignalStyle, WarnOnCollision, SuppressColliding }
impl Default for NameTrustPolicy { fn default() -> Self { NameTrustPolicy::SignalStyle } }
impl NameTrustPolicy {
    pub fn tag(self) -> u8 { match self { Self::SignalStyle => 0, Self::WarnOnCollision => 1, Self::SuppressColliding => 2 } }
    pub fn from_tag(t: u8) -> Option<Self> {
        match t { 0 => Some(Self::SignalStyle), 1 => Some(Self::WarnOnCollision), 2 => Some(Self::SuppressColliding), _ => None }
    }
}

/// Colour slot. `Default`/`Verified` are set by Sub-spec A; `Isolated` (B) and
/// `Vouched` (C) are reserved hooks that later sub-specs populate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tint { Default, Verified, Isolated, Vouched }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Badge(pub &'static str);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameRender {
    pub label: Option<String>,
    pub tier: NameTier,
    pub badge: Badge,
    pub tint: Tint,
    pub caveat: Option<String>,
    pub safety_number: String,
}

/// v1 confusable fold: NFKC + Unicode case-fold (via `to_lowercase`) + strip
/// combining marks. A full Unicode-confusables skeleton is a noted refinement.
pub fn confusable_fold(s: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    // NFKC folds compatibility variants; lowercase case-folds; then map a small set
    // of common cross-script homoglyphs to ASCII and drop combining marks.
    let nfkc: String = s.nfkc().collect::<String>().to_lowercase();
    nfkc.chars().filter_map(homoglyph_to_ascii).collect()
}

fn homoglyph_to_ascii(c: char) -> Option<char> {
    // Drop combining marks entirely.
    if ('\u{0300}'..='\u{036F}').contains(&c) { return None; }
    Some(match c {
        'а' => 'a', 'е' => 'e', 'о' => 'o', 'р' => 'p', 'с' => 'c', 'х' => 'x', 'у' => 'y', // Cyrillic
        'ѕ' => 's', 'і' => 'i', 'ј' => 'j', 'ԁ' => 'd',
        'ο' => 'o', 'α' => 'a', 'ρ' => 'p', // Greek
        other => other,
    })
}

/// Resolve one peer's cached name into a renderable form, applying the chat policy's
/// collision handling. `others` is the current name cache for the rest of the chat.
pub fn resolve_render(
    subject_fp: [u8; 48],
    rec: &NameRecord,
    others: &HashMap<[u8; 48], NameRecord>,
    policy: NameTrustPolicy,
    safety_number: String,
) -> NameRender {
    let folded = confusable_fold(&rec.label);
    // A collision: some OTHER peer holds a HIGHER-tier name that folds the same.
    let collides = others.iter().any(|(fp, o)| {
        *fp != subject_fp
            && o.tier.rank() > rec.tier.rank()
            && confusable_fold(&o.label) == folded
    });
    let tint = match rec.tier {
        NameTier::Linked | NameTier::RegistryConfirmed => Tint::Verified,
        NameTier::Bare => Tint::Default,
    };
    let (label, caveat) = match (collides, policy) {
        (false, _) => (Some(rec.label.clone()), None),
        (true, NameTrustPolicy::SignalStyle) => (Some(rec.label.clone()), None),
        (true, NameTrustPolicy::WarnOnCollision) => (
            Some(rec.label.clone()),
            Some(format!("claims to be “{}” — unverified, does not match the verified “{}”",
                         rec.label, rec.label)),
        ),
        (true, NameTrustPolicy::SuppressColliding) => (
            None,
            Some(format!("a peer tried to use the name “{}” (suppressed — not verified)", rec.label)),
        ),
    };
    NameRender { label, tier: rec.tier, badge: rec.tier.badge(), tint, caveat, safety_number }
}
```
Add to `crates/core/src/lib.rs`:
```rust
pub mod nametrust;
```
Add to `crates/core/Cargo.toml` under `[dependencies]`:
```toml
unicode-normalization = "0.1"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core nametrust:: presence:: 2>&1 | tail -25`
Expected: PASS — all `nametrust` and `presence` tests (Task 3 now compiles).

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/nametrust.rs crates/core/src/presence.rs crates/core/src/lib.rs crates/core/Cargo.toml
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): trust tiers, per-chat policy, collision render + confusable-fold"
```

---

### Task 5: audit the new dependency

**Files:** none (verification task).

`unicode-normalization` is new to the tree and the `audit` CI job runs on any `Cargo.toml`/`Cargo.lock` change.

- [ ] **Step 1: Run the local audit mirror**

Run: `bash scripts/audit-deps.sh 2>&1 | tail -20`
Expected: `advisories/bans/licenses/sources ok`. `unicode-normalization` is Apache-2.0/MIT, pure-Rust, widely used — no advisory expected.

- [ ] **Step 2: If cargo-deny flags a license/source**, add the justified entry to `deny.toml` (mirror in `scripts/audit-deps.sh`) exactly as the nym advisories were handled; otherwise no change.

- [ ] **Step 3: Commit** (only if `deny.toml`/`Cargo.lock` changed)
```bash
git add Cargo.lock deny.toml scripts/audit-deps.sh
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "chore(audit): unicode-normalization for name confusable-fold"
```

---

## Phase 2 — Descriptor v2 (per-chat trust policy)

### Task 6: add `name_trust_policy` to `ChatDescriptor`, bump `DESCRIPTOR_VERSION` 1→2

**Files:**
- Modify: `crates/core/src/descriptor.rs`

**Interfaces:**
- Consumes: `NameTrustPolicy` (Task 4).
- Produces: `ChatDescriptor.name_trust_policy: NameTrustPolicy` (public field); v1 invites decode with `SignalStyle`.

- [ ] **Step 1: Write the failing test**

Add to `crates/core/src/descriptor.rs` `#[cfg(test)] mod kat` (or a new `mod v2_tests`):
```rust
    #[test]
    fn v2_policy_roundtrips_and_v1_defaults() {
        use crate::nametrust::NameTrustPolicy;
        let mut d = ChatDescriptor {
            version: 2,
            topology: TopologyKind::P2P,
            persistence: Persistence::Ephemeral,
            suite_id: "tk.dr.kat".to_string(),
            suite_params: vec![],
            endpoints: vec![],
            invite_token: vec![0u8; 32],
            channel: "#kat".to_string(),
            group: false,
            channel_marking: None,
            name_trust_policy: NameTrustPolicy::WarnOnCollision,
            password: None,
        };
        let uri = d.to_uri();
        let back = ChatDescriptor::from_uri(&uri).unwrap();
        assert_eq!(back.name_trust_policy, NameTrustPolicy::WarnOnCollision);
        // A v1 URI (frozen KAT string) still decodes, defaulting to SignalStyle.
        let v1 = ChatDescriptor::from_uri(
            "talkrypt://aaaaaaiaaaaaaaajorvs4zdsfzvwc5aaaaaaaaaaaaaaaaaaeaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaccg23boqaaa"
        ).unwrap();
        assert_eq!(v1.name_trust_policy, NameTrustPolicy::SignalStyle);
        d.version = 2; // silence unused mut if refactored
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core descriptor 2>&1 | tail -20`
Expected: FAIL — `ChatDescriptor` has no field `name_trust_policy` (struct literal error).

- [ ] **Step 3: Write minimal implementation**

In `descriptor.rs`:
1. Bump the const: `const DESCRIPTOR_VERSION: u16 = 2;`
2. Add the field to the struct (after `channel_marking`):
```rust
    pub name_trust_policy: crate::nametrust::NameTrustPolicy,
```
3. In `encode_bytes`, after `crate::marking::put_opt(&mut w, &self.channel_marking);`:
```rust
    // v2+: per-chat name trust policy (advisory display). Appended last so a v1
    // reader that stops after channel_marking is unaffected.
    w.put_u8(self.name_trust_policy.tag());
```
4. In `decode_bytes`, change the version guard and the tail:
```rust
    let version = r.get_u32()? as u16;
    if version == 0 || version > DESCRIPTOR_VERSION {
        return Err(CoreError::UnsupportedVersion(version));
    }
    // ... unchanged reads up through channel_marking ...
    let channel_marking = crate::marking::get_opt(&mut r)?;
    let name_trust_policy = if version >= 2 {
        crate::nametrust::NameTrustPolicy::from_tag(r.get_u8()?)
            .ok_or(CoreError::Malformed("name trust policy tag"))?
    } else {
        crate::nametrust::NameTrustPolicy::default()
    };
    r.finish().map_err(|_| CoreError::Malformed("trailing descriptor bytes"))?;
    Ok(Self { version, topology, persistence, suite_id, suite_params, endpoints,
              invite_token, channel, group, channel_marking, name_trust_policy, password: None })
```
5. Update every `ChatDescriptor { .. }` struct literal in the crate (there are a few — `ChatDescriptor::new`, the KAT, tests) to include `name_trust_policy: NameTrustPolicy::default()`. In `ChatDescriptor::new(...)`, set `version: DESCRIPTOR_VERSION` (it likely already uses the const) and add `name_trust_policy: crate::nametrust::NameTrustPolicy::default(),`.
6. **Update the KAT** (`descriptor_uri_kat`): set `version: 2`, add `name_trust_policy: NameTrustPolicy::default(),` to the literal, then regenerate the frozen base32: run the test once, copy the actual `d.to_uri()` value from the failure diff into the `assert_eq!`, re-run.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core descriptor 2>&1 | tail -20`
Expected: PASS — `v2_policy_roundtrips_and_v1_defaults` and the updated `descriptor_uri_kat`.

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/descriptor.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): descriptor v2 carries per-chat NameTrustPolicy (v1 back-compat)"
```

---

## Phase 3 — Engine: propagation + verification

### Task 7: `Frame::Presence` (tag 9) + `Event::Name`

**Files:**
- Modify: `crates/core/src/engine.rs`

**Interfaces:**
- Produces: `Frame::Presence(Vec<u8>)` (tag 9); `Event::Name { from: [u8;48], account_fingerprint: Option<[u8;48]>, label: Option<String>, tier: NameTier, seq: u64, caveat: Option<String> }`.

- [ ] **Step 1: Write the failing test**

Add to `engine.rs` `#[cfg(test)] mod tests`:
```rust
    #[test]
    fn frame_presence_roundtrips() {
        let f = Frame::Presence(vec![1, 2, 3, 4]);
        let bytes = f.encode();
        match Frame::decode(&bytes) {
            Some(Frame::Presence(b)) => assert_eq!(b, vec![1, 2, 3, 4]),
            other => panic!("expected Presence, got {other:?}"),
        }
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core frame_presence 2>&1 | tail -20`
Expected: FAIL — no variant `Presence`.

- [ ] **Step 3: Write minimal implementation**

In `engine.rs`:
1. Add to `enum Frame`:
```rust
    /// An encoded [`crate::presence::NamePresence`] — a self-declared name, sent
    /// directly in pairwise chats (in groups it rides a sentinel-tagged group
    /// payload instead; see `handle_group_msg`).
    Presence(Vec<u8>),                                                   // tag 9
```
2. In `encode()`:
```rust
        Frame::Presence(b) => { w.put_u8(9); w.put_bytes(b); }
```
3. In `decode()`, before `_ => return None`:
```rust
        9 => Frame::Presence(r.get_vec().ok()?),
```
4. Add to `enum Event` (and derive stays `Clone, Debug`):
```rust
    /// A peer's resolved self-declared name changed. `account_fingerprint` is set
    /// only for account-linked/registry tiers; `label` is `None` when suppressed.
    Name {
        from: [u8; 48],
        account_fingerprint: Option<[u8; 48]>,
        label: Option<String>,
        tier: crate::nametrust::NameTier,
        seq: u64,
        caveat: Option<String>,
    },
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core frame_presence 2>&1 | tail -20`
Expected: PASS. (Also run `cargo build -p talkrypt-core` — the new `Event::Name` may surface non-exhaustive `match` warnings/errors in `map_event`-style code; there are none in core yet, FFI is handled in Task 14.)

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): Frame::Presence (tag 9) + Event::Name"
```

---

### Task 8: `Inner` name state + `handle_presence` (verify, cache, emit)

**Files:**
- Modify: `crates/core/src/engine.rs`

**Interfaces:**
- Consumes: `NamePresence`, `NameRecord`, `chat_context`, `PresenceCadence` (Phase 1); `resolve_render`, `NameTier` (Task 4).
- Produces: `Inner.names: Mutex<HashMap<[u8;48], NameRecord>>`; `Inner.leading_name: Mutex<Option<NameEntry>>`; `Inner.presence_seq: AtomicU64`; `Inner.cadence: Mutex<PresenceCadence>`; `fn handle_presence(inner: &Arc<Inner>, attributed_fp: [u8;48], bytes: Vec<u8>)`.

- [ ] **Step 1: Write the failing test** (integration-style, uses the existing `LoopbackFabric` helpers already imported in the test mod)
```rust
    #[tokio::test]
    async fn pairwise_bare_name_emits_name_event() {
        // Reuse the crate's existing pairwise loopback harness helper if present;
        // otherwise this asserts handle_presence directly:
        use crate::presence::{NamePresence, NameRecord};
        use crate::nametrust::NameTier;
        let inner = test_inner_pairwise(); // helper below
        let np = NamePresence::Bare { seq: 5, label: "Whiskey".into() };
        handle_presence(&inner, [7u8; 48], np.encode());
        let rec = inner.names.lock().unwrap().get(&[7u8; 48]).cloned().unwrap();
        assert_eq!(rec, NameRecord { label: "Whiskey".into(), tier: NameTier::Bare, seq: 5, account_fp: None });
        // stale seq is ignored
        let older = NamePresence::Bare { seq: 4, label: "Nope".into() };
        handle_presence(&inner, [7u8; 48], older.encode());
        assert_eq!(inner.names.lock().unwrap().get(&[7u8; 48]).unwrap().label, "Whiskey");
    }
```
Add a small test helper near the other test helpers:
```rust
    fn test_inner_pairwise() -> std::sync::Arc<Inner> {
        // Build a minimal Core in pairwise role over Loopback and return its Inner.
        let suite = SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID).unwrap();
        let fabric = LoopbackFabric::new();
        let desc = ChatDescriptor::new(TopologyKind::P2P, Persistence::Ephemeral,
            DEFAULT_SUITE_ID, vec![], "#t".into());
        let (core, _rx) = Core::new(IdentityKeyPair::generate(), suite, fabric.endpoint("a"), desc);
        core.inner.clone()
    }
```
(If `Core.inner` is private, add `#[cfg(test)] pub(crate) fn inner(&self) -> &Arc<Inner> { &self.inner }` and use `core.inner().clone()`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core pairwise_bare_name 2>&1 | tail -20`
Expected: FAIL — `inner.names` / `handle_presence` not found.

- [ ] **Step 3: Write minimal implementation**

1. Add `Inner` fields (init them in `build()` alongside the existing fields):
```rust
    names: Mutex<std::collections::HashMap<[u8; 48], crate::presence::NameRecord>>,
    leading_name: Mutex<Option<crate::presence::NameEntry>>,
    presence_seq: std::sync::atomic::AtomicU64,
    cadence: Mutex<crate::presence::PresenceCadence>,
```
In `build(...)` `Inner { ... }` literal add:
```rust
    names: Mutex::new(std::collections::HashMap::new()),
    leading_name: Mutex::new(None),
    presence_seq: std::sync::atomic::AtomicU64::new(0),
    cadence: Mutex::new(crate::presence::PresenceCadence::default()),
```
2. Add the handler (near `handle_identity`):
```rust
/// A peer announced a self-declared name (pairwise `Frame::Presence`, or a group
/// sentinel payload). Verify (Linked only), enforce seq monotonicity, cache the
/// record, and emit `Event::Name` with the policy-resolved label/caveat/tier.
///
/// `attributed_fp` is the message-attribution fingerprint (pairwise transport peer,
/// or `roster[sender_leaf]` in a group). For a `Linked` presence the device
/// signature — not `attributed_fp` — is the authority; `attributed_fp` is only the
/// cache/render key so the name shows over that peer's messages.
fn handle_presence(inner: &Arc<Inner>, attributed_fp: [u8; 48], bytes: Vec<u8>) {
    use crate::presence::{NamePresence, NameRecord};
    use crate::nametrust::{resolve_render, NameTier};
    let Ok(np) = NamePresence::decode(&bytes) else { return };
    let now = now_secs();
    let (rec, key) = match &np {
        NamePresence::Bare { seq, label } => (
            NameRecord { label: label.clone(), tier: NameTier::Bare, seq: *seq, account_fp: None },
            attributed_fp,
        ),
        NamePresence::Linked { .. } => {
            let Some(v) = np.verify_linked(now) else { return };
            // Context must match THIS chat.
            let ctx = crate::presence::chat_context(
                &inner.descriptor.invite_token, &inner.descriptor.channel);
            if !matches!(&np, NamePresence::Linked { context, .. } if *context == ctx) { return; }
            // Reject a revoked device.
            let revoked = {
                let revs = inner.revocations.lock().unwrap();
                revs.contains(&(v.account_fp, v.device_fp))
            };
            if revoked { return; }
            (
                NameRecord { label: v.label.clone(), tier: NameTier::Linked, seq: v.seq,
                             account_fp: Some(v.account_fp) },
                v.device_fp, // the signed device == the group/transport attribution key
            )
        }
    };
    // seq monotonicity per cache key.
    {
        let mut names = inner.names.lock().unwrap();
        if let Some(existing) = names.get(&key) {
            if rec.seq <= existing.seq { return; }
        }
        names.insert(key, rec.clone());
    }
    // Resolve render against the rest of the cache under the chat policy.
    let (label, caveat, tier, account_fp) = {
        let names = inner.names.lock().unwrap();
        let policy = inner.descriptor.name_trust_policy;
        let sn = short_hex6(&key); // safety-number-ish; clients show the full one
        let r = resolve_render(key, &rec, &names, policy, sn);
        (r.label, r.caveat, r.tier, rec.account_fp)
    };
    let _ = inner.events_tx.send(Event::Name {
        from: key, account_fingerprint: account_fp, label, tier, seq: rec.seq, caveat });
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core pairwise_bare_name 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): Inner name cache + handle_presence (verify, seq, policy, emit)"
```

---

### Task 9: dispatch presence — pairwise `Frame::Presence` + group sentinel payload

**Files:**
- Modify: `crates/core/src/engine.rs`

**Interfaces:**
- Consumes: `handle_presence` (Task 8); `marking::decode_payload` / `encode_payload`; the group send path in `send_marked`.
- Produces: `pub(crate) const PRESENCE_SENTINEL: u8 = 0xF5;` + presence dispatch in `reader_loop` (pairwise) and `handle_group_msg` (group).

- [ ] **Step 1: Write the failing test** (group: a MEMBER's Bare name reaches another MEMBER, not just the host)
```rust
    #[tokio::test]
    async fn group_presence_reaches_all_members() {
        // 3-node group over LoopbackFabric: host H, members A, B (reuse the existing
        // group test harness in this module — mirror `gossip_bridges_two_transport_islands`).
        let g = spawn_group_of_three().await; // helper mirroring existing group tests
        g.a.core.announce_presence().await;    // A declares (added in Task 11)
        // B should receive Event::Name for A's fingerprint with A's label.
        let ev = wait_for_name(&mut g.b_rx).await;
        assert_eq!(ev_label(&ev).as_deref(), Some("A-callsign"));
    }
```
If a 3-node group helper does not already exist, add `spawn_group_of_three()` modeled on the existing `gossip_bridges_two_transport_islands` test (same `LoopbackFabric`, `Core::new_group(.., true)` host + two `Core::new_group(.., false)` members that connect and exchange KeyPackage/Welcome). Set each member's leading name via `set_leading_name` (Task 11) to a `Bare` entry before connecting.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core group_presence_reaches_all 2>&1 | tail -20`
Expected: FAIL — presence not dispatched / `announce_presence` missing (Task 11).

- [ ] **Step 3: Write minimal implementation**

1. Add the sentinel + helpers near the `marking` usage:
```rust
/// Leading byte marking a TYPED group payload (vs a legacy marking+text Chat
/// payload, whose first byte is always an opt-marking flag 0x00/0x01). A legacy
/// client's `marking::decode_payload` returns `None` on this, dropping presence
/// gracefully.
pub(crate) const PRESENCE_SENTINEL: u8 = 0xF5;

fn encode_group_presence(np_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(np_bytes.len() + 1);
    v.push(PRESENCE_SENTINEL);
    v.extend_from_slice(np_bytes);
    v
}
```
2. In `handle_group_msg`, after `let Some(pt) = opened` and BEFORE the `marking::decode_payload` branch, dispatch on the sentinel:
```rust
    if let Some(pt) = opened {
        if pt.first() == Some(&PRESENCE_SENTINEL) {
            // Attribute to the original sender via the roster (like Chat).
            let sender = TreeKemGroup::sender_leaf(&gct)
                .and_then(|leaf| inner.roster.lock().unwrap().get(&leaf).copied())
                .unwrap_or(from);
            handle_presence(&inner, sender, pt[1..].to_vec());
        } else if let Some((marking, text)) = marking::decode_payload(&pt) {
            // ... existing Event::Message emission unchanged ...
        }
    }
    // ... existing fan-out/gossip unchanged (it re-floods the raw `gct`) ...
```
3. In `reader_loop`, add a pairwise arm (next to the pairwise `Frame::Identity` arm):
```rust
            Some(Frame::Presence(bytes)) if inner.role == GroupRole::None => {
                handle_presence(&inner, fingerprint, bytes);
            }
```

- [ ] **Step 4: Run test to verify it passes** (after Task 11 lands `announce_presence`/`set_leading_name`; if executing strictly in order, mark this step and re-run at the end of Task 11)

Run: `cargo test -p talkrypt-core group_presence_reaches_all 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): dispatch presence — pairwise frame + group sentinel payload"
```

---

### Task 10: insider-spoof + context-replay security tests

**Files:**
- Modify: `crates/core/src/engine.rs` (tests) and/or `crates/core/src/presence.rs` (tests)

**Interfaces:** consumes everything above; adds no new production code (pure hardening tests). If a test reveals a gap, fix it in `handle_presence`.

- [ ] **Step 1: Write the failing/spec tests**
```rust
    #[test]
    fn linked_presence_rejects_wrong_chat_context() {
        // handle_presence must drop a Linked presence whose context != this chat.
        let inner = test_inner_pairwise();
        let now = now_secs();
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", now, now + 10_000);
        let wrong_ctx = crate::presence::chat_context(b"other-token", "#other");
        let np = crate::presence::NamePresence::linked(1, chain, "Alice", wrong_ctx, &device);
        handle_presence(&inner, device.public().fingerprint(), np.encode());
        assert!(inner.names.lock().unwrap().is_empty());
    }

    #[test]
    fn insider_cannot_forge_linked_name() {
        // A malicious member has the epoch_secret and can spoof sender_leaf, but a
        // Bare presence stays Bare (tier is honest) and a Linked presence for an
        // account whose device key they DON'T hold cannot be produced: signing with
        // the wrong key fails verify_linked.
        let now = now_secs();
        let account = IdentityKeyPair::generate();
        let real_device = IdentityKeyPair::generate();
        let attacker = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, real_device.public(), "dev", now, now + 10_000);
        let ctx = crate::presence::chat_context(b"tok", "#c");
        // Attacker forges by signing the real chain with THEIR key:
        let mut forged = crate::presence::NamePresence::linked(1, chain, "Alice", ctx, &attacker);
        // (linked() signed with `attacker`, but the chain leaf is real_device)
        assert!(forged.verify_linked(now).is_none());
        let _ = &mut forged;
    }
```

- [ ] **Step 2: Run to verify they fail if the guard is missing, else pass**

Run: `cargo test -p talkrypt-core -- linked_presence_rejects_wrong_chat_context insider_cannot_forge 2>&1 | tail -20`
Expected: PASS (the Task 8 context + signature checks already enforce these). If `linked_presence_rejects_wrong_chat_context` FAILS, the context guard in `handle_presence` is wrong — fix it there.

- [ ] **Step 3: (only if a test failed) fix `handle_presence`** per the failure.

- [ ] **Step 4: Re-run**

Run: `cargo test -p talkrypt-core 2>&1 | tail -20`
Expected: whole-crate PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/engine.rs crates/core/src/presence.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "test(names): insider-spoof + cross-chat replay guards"
```

---

## Phase 4 — Engine: emission / cadence

### Task 11: `set_leading_name` + `announce_presence` (manual + on-join)

**Files:**
- Modify: `crates/core/src/engine.rs`

**Interfaces:**
- Consumes: `NameEntry`/`NameBacking`, `NamePresence`, `chat_context`, `PresenceCadence`.
- Produces: `Core::set_leading_name(&self, entry: Option<NameEntry>)`; `Core::announce_presence(&self) -> Result<()>`; internal `build_my_presence(inner) -> Option<Vec<u8>>`.

- [ ] **Step 1: Write the failing test**
```rust
    #[tokio::test]
    async fn announce_presence_sends_bare_pairwise() {
        // Two pairwise peers over Loopback; A sets a bare leading name and announces;
        // B receives Event::Name.
        let (a, mut _arx, b, mut brx) = spawn_pairwise_pair().await; // existing-style helper
        a.set_leading_name(Some(NameEntry { id: "1".into(), label: "Whiskey".into(),
            backing: NameBacking::Bare }));
        a.announce_presence().await.unwrap();
        let ev = wait_for_name(&mut brx).await;
        assert_eq!(ev_label(&ev).as_deref(), Some("Whiskey"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core announce_presence_sends_bare 2>&1 | tail -20`
Expected: FAIL — methods not found.

- [ ] **Step 3: Write minimal implementation**

Add to `impl Core`:
```rust
    /// Set (or clear) the leading self-declared name for this chat. Does not send;
    /// call `announce_presence` (or rely on the cadence triggers) to broadcast.
    pub fn set_leading_name(&self, entry: Option<crate::presence::NameEntry>) {
        *self.inner.leading_name.lock().unwrap() = entry;
    }

    /// Broadcast a fresh CQ of the current leading name to the chat. No-op if no
    /// leading name is set. Increments the per-sender seq so it supersedes.
    pub async fn announce_presence(&self) -> Result<()> {
        let Some(bytes) = build_my_presence(&self.inner) else { return Ok(()); };
        match self.inner.role {
            GroupRole::None => {
                let payload = Frame::Presence(bytes).encode();
                for (session, writer, fp) in collect_peers(&self.inner) {
                    let ready = { session.lock().await.can_send() };
                    if ready { let _ = send_payload(&session, &writer, &payload).await; }
                    else if let Some(pending) = pending_for(&self.inner, fp) {
                        pending.lock().unwrap().push(payload.clone());
                    }
                }
            }
            GroupRole::Host | GroupRole::Member => {
                let frame = {
                    let mut g = self.inner.group.lock().await;
                    match g.as_mut() {
                        Some(grp) => Frame::GroupMsg(grp.encrypt(&encode_group_presence(&bytes))?),
                        None => return Ok(()), // group not ready yet; on-join trigger re-fires
                    }
                };
                route(&self.inner, frame, Route::Broadcast).await;
            }
        }
        Ok(())
    }
```
Add the free function:
```rust
/// Encode this node's current leading name as a `NamePresence`, or `None` if no
/// leading name is set. Bumps `presence_seq`.
fn build_my_presence(inner: &Arc<Inner>) -> Option<Vec<u8>> {
    use crate::presence::{NameBacking, NamePresence};
    let entry = inner.leading_name.lock().unwrap().clone()?;
    let seq = inner.presence_seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
    let np = match entry.backing {
        NameBacking::Bare => NamePresence::Bare { seq, label: entry.label.clone() },
        NameBacking::Account { chain } => {
            let ctx = crate::presence::chat_context(&inner.descriptor.invite_token,
                                                    &inner.descriptor.channel);
            NamePresence::linked(seq, chain, &entry.label, ctx, &inner.identity)
        }
    };
    Some(np.encode())
}
```
Wire the **on-join** trigger: in `register(...)`, after a peer is fully added and (for pairwise) after the eager identity present, spawn/queue an `announce_presence`-equivalent. Simplest: at the end of `register`, if `inner.leading_name` is set, push the presence payload into the same eager/pending path the identity uses. Mirror the existing `present_chain` eager-send block: where `register` sends `Frame::Identity(bytes)` for `present_pairwise`, also send `Frame::Presence(build_my_presence(inner)?)`. For group members, the on-join announce fires after Welcome is processed (in `handle_welcome`/`enter_group`): after the group is ready, call the group branch of `announce_presence`. Add a helper `spawn_announce(inner: Arc<Inner>)` that `tokio::spawn`s the role-appropriate send, and call it (a) at the end of `register` for pairwise, (b) after group entry completes.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core announce_presence_sends_bare group_presence_reaches_all 2>&1 | tail -20`
Expected: PASS (this also unblocks Task 9's group test).

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): set_leading_name + announce_presence + on-join CQ"
```

---

### Task 12: roster-grow re-announce + `set_presence_cadence` periodic timer

**Files:**
- Modify: `crates/core/src/engine.rs`

**Interfaces:**
- Consumes: `announce_presence`/`build_my_presence`, `PresenceCadence`.
- Produces: `Core::set_presence_cadence(&self, cadence: PresenceCadence)`; a periodic task; a roster-grow hook.

- [ ] **Step 1: Write the failing test**
```rust
    #[tokio::test]
    async fn new_member_triggers_reannounce() {
        // Host + member A (A has a leading name). A new member B joins; A re-announces
        // so B learns A's name without A acting.
        let g = spawn_group_host_and_member_with_name().await;
        let b = g.join_new_member().await;         // B connects after A already present
        let ev = wait_for_name(&mut b.rx).await;   // B hears A's re-announced name
        assert_eq!(ev_label(&ev).as_deref(), Some("A-callsign"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core new_member_triggers_reannounce 2>&1 | tail -20`
Expected: FAIL — no re-announce on roster grow.

- [ ] **Step 3: Write minimal implementation**

1. Add the setter:
```rust
    /// Configure CQ cadence: an optional periodic re-beacon (clamped to a floor)
    /// and whether to stamp a name-id on outgoing messages (Task 13).
    pub fn set_presence_cadence(&self, cadence: crate::presence::PresenceCadence) {
        *self.inner.cadence.lock().unwrap() = cadence;
        // (Re)start the periodic task if enabled.
        if let Some(secs) = cadence.effective_periodic() {
            let inner = self.inner.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(secs));
                ticker.tick().await; // consume the immediate first tick
                loop {
                    ticker.tick().await;
                    // Stop if cadence was disabled/changed.
                    let still = inner.cadence.lock().unwrap().effective_periodic() == Some(secs);
                    if !still { break; }
                    if let Some(bytes) = build_my_presence(&inner) {
                        send_presence_now(&inner, bytes).await;
                    }
                }
            });
        }
    }
```
2. Factor the role-appropriate send out of `announce_presence` into `async fn send_presence_now(inner: &Arc<Inner>, bytes: Vec<u8>)` (the body of the `match self.inner.role { ... }` from Task 11) and have `announce_presence` call it. The periodic task and roster-grow hook reuse it.
3. **Roster-grow hook:** in the host path where a new member is admitted and the roster grows (right after `roster.insert(leaf, from)` in the group-add handler that broadcasts the new `Roster`), spawn a debounced re-announce:
```rust
    // A new member appeared — re-broadcast our leading name so they resolve us.
    if inner.leading_name.lock().unwrap().is_some() {
        let inner2 = inner.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await; // debounce burst
            if let Some(bytes) = build_my_presence(&inner2) { send_presence_now(&inner2, bytes).await; }
        });
    }
```
Also apply the same hook for **members** when they receive a `Roster` update whose entry count grew (in the `Frame::Roster` member arm): compare new len to the previous roster len and re-announce on growth.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core new_member_triggers_reannounce 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): roster-grow re-announce + periodic CQ timer"
```

---

### Task 13: on-message name-id (optional cadence mode)

**Files:**
- Modify: `crates/core/src/engine.rs`, `crates/core/src/presence.rs`

**Interfaces:**
- Produces: `presence::name_tag(label: &str, context: &[u8;32], seq: u64) -> [u8;8]`; the group Chat payload optionally carries a trailing name-tag when `cadence.on_message_id` is set; receivers whose cache tag differs learn their cache is stale.

- [ ] **Step 1: Write the failing test** (in `presence.rs`)
```rust
    #[test]
    fn name_tag_is_stable_and_seq_sensitive() {
        let ctx = chat_context(b"t", "#c");
        assert_eq!(name_tag("Alice", &ctx, 1), name_tag("Alice", &ctx, 1));
        assert_ne!(name_tag("Alice", &ctx, 1), name_tag("Alice", &ctx, 2));
        assert_ne!(name_tag("Alice", &ctx, 1), name_tag("Bob", &ctx, 1));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-core name_tag_is_stable 2>&1 | tail -20`
Expected: FAIL — `name_tag` not found.

- [ ] **Step 3: Write minimal implementation**

In `presence.rs`:
```rust
/// A short, non-secret tag identifying "which name at which seq" a sender is using,
/// stamped on outgoing messages when the on-message cadence mode is on. A viewer
/// whose cached tag differs knows its name cache is stale and awaits a presence.
pub fn name_tag(label: &str, context: &[u8; 32], seq: u64) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(context);
    put_hash_u64(&mut h, seq);
    h.update(label.as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}
fn put_hash_u64(h: &mut sha2::Sha256, v: u64) { use sha2::Digest; h.update(v.to_be_bytes()); }
```
In `engine.rs` `send_marked` group branch: when `inner.cadence.lock().unwrap().on_message_id` is true and a leading name is set, append the current name-tag to the group payload using a second sentinel section, OR (simpler, keeps Chat wire stable) piggyback by emitting a lightweight `Presence` alongside the message only when the tag changed since the last message. **Choose the simpler, wire-stable option:** track `last_sent_tag` in `Inner` (`Mutex<Option<[u8;8]>>`); in `send_marked`, if `on_message_id` and the current tag != `last_sent_tag`, call `send_presence_now(build_my_presence)` right before sending the message and update `last_sent_tag`. This guarantees "name rides over every message" (a presence precedes any message whose name changed) without altering the Chat payload format. Document that choice in a code comment.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-core name_tag presence:: 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**
```bash
git add crates/core/src/presence.rs crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(names): on-message cadence mode (name-tag precedes changed-name messages)"
```

---

## Phase 5 — FFI

### Task 14: FFI types, `FfiEvent::Name`, event mapping

**Files:**
- Modify: `crates/ffi/src/lib.rs`

**Interfaces:**
- Produces: `#[derive(uniffi::Enum)] FfiNameTier { Bare, Linked, RegistryConfirmed }`; `#[derive(uniffi::Enum)] FfiTrustPolicy { SignalStyle, WarnOnCollision, SuppressColliding }`; `#[derive(uniffi::Record)] FfiNameEntry { id: String, label: String, account_chain_hex: Option<String> }`; `FfiEvent::Name { from, account_fingerprint, label, tier: FfiNameTier, seq: u64, caveat, safety_number }`.

- [ ] **Step 1: Write the failing test**
```rust
    #[test]
    fn name_entry_backing_from_hex() {
        // FfiNameEntry with no chain → Bare; with a chain hex → Account.
        let e = FfiNameEntry { id: "1".into(), label: "K1ABC".into(), account_chain_hex: None };
        assert!(matches!(e.to_core().unwrap().backing, NameBacking::Bare));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-ffi name_entry_backing 2>&1 | tail -20`
Expected: FAIL — `FfiNameEntry` not found.

- [ ] **Step 3: Write minimal implementation**

Add the records/enums + `map_event` arm:
```rust
#[derive(uniffi::Enum)]
pub enum FfiNameTier { Bare, Linked, RegistryConfirmed }
impl From<talkrypt_core::nametrust::NameTier> for FfiNameTier {
    fn from(t: talkrypt_core::nametrust::NameTier) -> Self {
        use talkrypt_core::nametrust::NameTier::*;
        match t { Bare => Self::Bare, Linked => Self::Linked, RegistryConfirmed => Self::RegistryConfirmed }
    }
}

#[derive(uniffi::Enum)]
pub enum FfiTrustPolicy { SignalStyle, WarnOnCollision, SuppressColliding }
impl FfiTrustPolicy {
    fn to_core(&self) -> talkrypt_core::nametrust::NameTrustPolicy {
        use talkrypt_core::nametrust::NameTrustPolicy::*;
        match self { Self::SignalStyle => SignalStyle, Self::WarnOnCollision => WarnOnCollision, Self::SuppressColliding => SuppressColliding }
    }
}

#[derive(uniffi::Record)]
pub struct FfiNameEntry { pub id: String, pub label: String, pub account_chain_hex: Option<String> }
impl FfiNameEntry {
    fn to_core(&self) -> Result<talkrypt_core::presence::NameEntry, FfiError> {
        use talkrypt_core::presence::{NameBacking, NameEntry};
        let backing = match &self.account_chain_hex {
            None => NameBacking::Bare,
            Some(hex) => {
                let bytes = hex_decode(hex).map_err(|_| FfiError::Failed("bad chain hex".into()))?;
                NameBacking::Account { chain: IdentityChain::decode(&bytes).map_err(FfiError::from)? }
            }
        };
        Ok(NameEntry { id: self.id.clone(), label: self.label.clone(), backing })
    }
}
```
Add to `FfiEvent`:
```rust
    Name { from: String, account_fingerprint: Option<String>, label: Option<String>,
           tier: FfiNameTier, seq: u64, caveat: Option<String>, safety_number: String },
```
Add to `map_event`:
```rust
    Event::Name { from, account_fingerprint, label, tier, seq, caveat } => FfiEvent::Name {
        from: hex_fp(&from),
        account_fingerprint: account_fingerprint.map(|f| hex_fp(&f)),
        label,
        tier: tier.into(),
        seq,
        caveat,
        safety_number: /* full safety number of `from`: */ safety_number_of(&from),
    },
```
For `safety_number_of`, reuse the fingerprint→grouped-hex helper (mirror `IdentityPublic::safety_number` formatting on the raw `[u8;48]`; if only the fp is available, format `hex_fp` grouped). Use the existing `hex_fp` and group it, matching what other screens show.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-ffi name_entry_backing 2>&1 | tail -20 && cargo build -p talkrypt-ffi 2>&1 | tail -5`
Expected: PASS + clean build (the `map_event` match is now exhaustive).

- [ ] **Step 5: Commit**
```bash
git add crates/ffi/src/lib.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(ffi): FfiEvent::Name + name entry/tier/policy types"
```

---

### Task 15: FFI methods — leading name, announce, cadence, book persistence

**Files:**
- Modify: `crates/ffi/src/lib.rs`

**Interfaces:**
- Produces on `TalkryptClient`: `set_leading_name(&self, entry: Option<FfiNameEntry>) -> Result<(), FfiError>`; `announce_presence(&self) -> Result<(), FfiError>`; `set_presence_cadence(&self, periodic_secs: Option<u64>, on_message_id: bool)`; free fns `name_book_encode(entries, default) -> Vec<u8>` / `name_book_decode(Vec<u8>) -> Vec<FfiNameEntry>` for client persistence.

- [ ] **Step 1: Write the failing test**
```rust
    #[test]
    fn book_encode_decode_roundtrip_ffi() {
        let entries = vec![FfiNameEntry { id: "1".into(), label: "W".into(), account_chain_hex: None }];
        let bytes = name_book_encode(entries.clone(), Some("1".into()));
        let back = name_book_decode(bytes).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].label, "W");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-ffi book_encode_decode_roundtrip_ffi 2>&1 | tail -20`
Expected: FAIL — free fns not found.

- [ ] **Step 3: Write minimal implementation**

Add instance methods inside the `#[uniffi::export] impl TalkryptClient`:
```rust
    pub fn set_leading_name(&self, entry: Option<FfiNameEntry>) -> Result<(), FfiError> {
        let core_entry = match entry { Some(e) => Some(e.to_core()?), None => None };
        self.core.set_leading_name(core_entry);
        Ok(())
    }
    pub fn announce_presence(&self) -> Result<(), FfiError> {
        self.rt.block_on(self.core.announce_presence()).map_err(FfiError::from)
    }
    pub fn set_presence_cadence(&self, periodic_secs: Option<u64>, on_message_id: bool) {
        self.core.set_presence_cadence(talkrypt_core::presence::PresenceCadence {
            periodic_secs, on_message_id });
    }
```
Add free fns (outside the impl, with `#[uniffi::export]`):
```rust
#[uniffi::export]
pub fn name_book_encode(entries: Vec<FfiNameEntry>, default: Option<String>) -> Result<Vec<u8>, FfiError> {
    let mut core_entries = Vec::with_capacity(entries.len());
    for e in &entries { core_entries.push(e.to_core()?); }
    Ok(talkrypt_core::presence::NameBook { entries: core_entries, default }.encode())
}
#[uniffi::export]
pub fn name_book_decode(bytes: Vec<u8>) -> Result<Vec<FfiNameEntry>, FfiError> {
    let book = talkrypt_core::presence::NameBook::decode(&bytes).map_err(FfiError::from)?;
    Ok(book.entries.into_iter().map(|e| FfiNameEntry {
        id: e.id, label: e.label,
        account_chain_hex: match e.backing {
            talkrypt_core::presence::NameBacking::Bare => None,
            talkrypt_core::presence::NameBacking::Account { chain } => Some(hex_encode(&chain.encode())),
        },
    }).collect())
}
```
Add an optional `name_trust_policy` param to `host`/`host_tor`/host_nym constructors (default `SignalStyle` if `None`) — set it on the descriptor before `Core::new_group`: `desc.name_trust_policy = policy.map(|p| p.to_core()).unwrap_or_default();`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-ffi 2>&1 | tail -20`
Expected: PASS. Regenerate bindings sanity: `cargo build -p talkrypt-ffi 2>&1 | tail -5`.

- [ ] **Step 5: Commit**
```bash
git add crates/ffi/src/lib.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(ffi): leading-name/announce/cadence methods + name-book codec"
```

---

## Phase 6 — Android

### Task 16: name book model + persistence (`NameBook.kt`)

**Files:**
- Create: `android/app/src/main/kotlin/com/talkrypt/app/NameBook.kt`

**Interfaces:**
- Consumes FFI: `nameBookEncode(entries, default)`, `nameBookDecode(bytes)`, `FfiNameEntry`.
- Produces: `object NameBookStore { fun load(ctx): List<FfiNameEntry>; fun save(ctx, entries, default); fun defaultId(ctx): String? }` backed by SharedPreferences key `name_book` (Base64 of the FFI-encoded blob).

- [ ] **Step 1: Write the failing test** (JVM unit test)

Create `android/app/src/test/kotlin/com/talkrypt/app/NameBookTest.kt`:
```kotlin
package com.talkrypt.app
import org.junit.Assert.assertEquals
import org.junit.Test
class NameBookTest {
    @Test fun encodesAndDecodesViaFfi() {
        // Pure-logic check that Base64 wrapping is symmetric (FFI codec is covered in Rust).
        val raw = byteArrayOf(1, 2, 3, 4)
        val b64 = android.util.Base64.encodeToString(raw, android.util.Base64.NO_WRAP)
        val back = android.util.Base64.decode(b64, android.util.Base64.NO_WRAP)
        assertEquals(raw.toList(), back.toList())
    }
}
```
(Android `Base64` isn't available in plain JVM tests; if the harness lacks Robolectric, assert the store's pure key/format logic instead — e.g. a `NameBookStore.PREF_KEY == "name_book"` constant.)

- [ ] **Step 2: Run to verify it fails**

Run: `android/gradlew -p android :app:testDebugUnitTest --tests '*NameBookTest*' 2>&1 | tail -20`
Expected: FAIL — `NameBookStore` not found (or the constant check fails).

- [ ] **Step 3: Write minimal implementation**

Create `NameBook.kt`:
```kotlin
package com.talkrypt.app

import android.content.Context
import android.util.Base64
import uniffi.talkrypt_ffi.FfiNameEntry
import uniffi.talkrypt_ffi.nameBookEncode
import uniffi.talkrypt_ffi.nameBookDecode

/** Persistent name book (callsigns), stored as Base64 of the FFI-encoded blob in
 *  the shared "talkrypt" prefs. The FFI codec owns the wire format; this only
 *  Base64-wraps for SharedPreferences. (EncryptedSharedPreferences is a noted
 *  hardening follow-up, like nym_mnemonic.) */
object NameBookStore {
    const val PREF_KEY = "name_book"
    const val DEFAULT_KEY = "name_book_default"

    fun load(ctx: Context): List<FfiNameEntry> {
        val prefs = ctx.getSharedPreferences("talkrypt", Context.MODE_PRIVATE)
        val b64 = prefs.getString(PREF_KEY, null) ?: return emptyList()
        return runCatching {
            nameBookDecode(Base64.decode(b64, Base64.NO_WRAP))
        }.getOrDefault(emptyList())
    }

    fun defaultId(ctx: Context): String? =
        ctx.getSharedPreferences("talkrypt", Context.MODE_PRIVATE).getString(DEFAULT_KEY, null)

    fun save(ctx: Context, entries: List<FfiNameEntry>, default: String?) {
        val blob = nameBookEncode(entries, default)
        ctx.getSharedPreferences("talkrypt", Context.MODE_PRIVATE).edit()
            .putString(PREF_KEY, Base64.encodeToString(blob, Base64.NO_WRAP))
            .putString(DEFAULT_KEY, default)
            .apply()
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `android/gradlew -p android :app:testDebugUnitTest --tests '*NameBookTest*' 2>&1 | tail -20`
Expected: PASS. Also `TALKRYPT_NYM=1 bash android/build-apk.sh 2>&1 | tail -5` compiles (bindings regenerate with the new FFI symbols).

- [ ] **Step 5: Commit**
```bash
git add android/app/src/main/kotlin/com/talkrypt/app/NameBook.kt android/app/src/test/kotlin/com/talkrypt/app/NameBookTest.kt
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(android): name book model + SharedPreferences persistence"
```

---

### Task 17: New Chat advanced foldout (trust policy) + leading-name picker

**Files:**
- Modify: `android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt`

**Interfaces:**
- Consumes: `NameBookStore` (Task 16), `FfiTrustPolicy`, `darkSpinner`, `label`, `CheckBox` pattern, `startHost`.
- Produces: a collapsible "Advanced" section in `newChatScreen()` containing a NAME TRUST spinner + a LEADING NAME spinner; `startHost` passes the chosen policy + leading name.

- [ ] **Step 1: Write the failing test** — UI is not unit-tested here; the deliverable is verified on-device in Task 21. Add a compile-guard assertion instead: a JVM test asserting the policy label list is stable.

Create `android/app/src/test/kotlin/com/talkrypt/app/TrustPolicyLabelsTest.kt`:
```kotlin
package com.talkrypt.app
import org.junit.Assert.assertEquals
import org.junit.Test
class TrustPolicyLabelsTest {
    @Test fun policyLabelsMatchOrder() {
        assertEquals(listOf("Signal-style (default)", "Warn on collision", "Suppress colliding"),
                     ChatForm.TRUST_POLICY_LABELS)
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `android/gradlew -p android :app:testDebugUnitTest --tests '*TrustPolicyLabelsTest*' 2>&1 | tail -20`
Expected: FAIL — `ChatForm.TRUST_POLICY_LABELS` not found.

- [ ] **Step 3: Write minimal implementation**

1. Add a small companion holding the label list + mapping (top of `MainActivity.kt` or a new `ChatForm` object):
```kotlin
object ChatForm {
    val TRUST_POLICY_LABELS = listOf("Signal-style (default)", "Warn on collision", "Suppress colliding")
    fun policyAt(i: Int): uniffi.talkrypt_ffi.FfiTrustPolicy = when (i) {
        1 -> uniffi.talkrypt_ffi.FfiTrustPolicy.WARN_ON_COLLISION
        2 -> uniffi.talkrypt_ffi.FfiTrustPolicy.SUPPRESS_COLLIDING
        else -> uniffi.talkrypt_ffi.FfiTrustPolicy.SIGNAL_STYLE
    }
}
```
2. In `newChatScreen()`, after the Nym rows, add a foldout. Introduce the pattern (none exists today): an "Advanced ▾" toggle button whose click flips a child `LinearLayout` visibility and re-renders:
```kotlin
val advanced = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; visibility = View.GONE }
val advToggle = TextView(this).apply {
    text = "Advanced ▾"; setTextColor(accent); setPadding(0, 24, 0, 8)
    setOnClickListener {
        advanced.visibility = if (advanced.visibility == View.GONE) View.VISIBLE else View.GONE
        text = if (advanced.visibility == View.VISIBLE) "Advanced ▴" else "Advanced ▾"
    }
}
advanced.addView(label("NAME TRUST"))
val trustSpin = darkSpinner(ChatForm.TRUST_POLICY_LABELS); advanced.addView(trustSpin)
advanced.addView(label("LEADING NAME"))
val names = NameBookStore.load(this)
val nameLabels = listOf("(none — pseudonym)") + names.map { it.label }
val nameSpin = darkSpinner(nameLabels); advanced.addView(nameSpin)
col.addView(advToggle); col.addView(advanced)
```
3. In the Host button handler, pass the selections into `startHost(...)` (extend its signature): `val policy = ChatForm.policyAt(trustSpin.selectedItemPosition)`; `val leading = nameSpin.selectedItemPosition.let { if (it == 0) null else names[it - 1] }`. In `startHost`, forward `policy` to the constructor (`TalkryptClient.host(..., policy)` / `hostNym(..., policy)`) and, after the client is created, `client.setLeadingName(leading)` + `client.announcePresence()`.

- [ ] **Step 4: Run to verify it passes**

Run: `android/gradlew -p android :app:testDebugUnitTest --tests '*TrustPolicyLabelsTest*' 2>&1 | tail -20 && TALKRYPT_NYM=1 bash android/build-apk.sh 2>&1 | tail -5`
Expected: test PASS + APK BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**
```bash
git add android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt android/app/src/test/kotlin/com/talkrypt/app/TrustPolicyLabelsTest.kt
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(android): New Chat advanced foldout (trust policy) + leading-name picker"
```

---

### Task 18: render names in bubbles + mid-chat switch + CQ toggles

**Files:**
- Modify: `android/app/src/main/kotlin/com/talkrypt/app/ChatEvents.kt`, `MainActivity.kt`

**Interfaces:**
- Consumes: `FfiEvent.Name`, `addBubble`, the chat overflow menu (`⋯`).
- Produces: `applyEvent` handles `FfiEvent.Name` (updates member display + tier glyph + caveat); a chat menu action "Change name / CQ" that lists the name book, calls `setLeadingName` + `announcePresence`, and toggles periodic/on-message cadence.

- [ ] **Step 1: Write the failing test** (model fold in `ChatEvents.kt` is pure — test it)

Create/extend `android/app/src/test/kotlin/com/talkrypt/app/ChatEventsTest.kt`:
```kotlin
    @Test fun nameEventUpdatesMemberDisplayWithTier() {
        val sessions = Sessions()
        val id = /* create a session id per existing test helpers */ seedSession(sessions)
        applyEvent(sessions, id, sessions.get(id)!!,
            FfiEvent.Name(from = "aabbccdd", accountFingerprint = null,
                label = "Whiskey", tier = FfiNameTier.BARE, seq = 1u,
                caveat = null, safetyNumber = "AABB CCDD"))
        assertEquals("Whiskey", sessions.get(id)!!.members["aabbccdd"]?.display)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `android/gradlew -p android :app:testDebugUnitTest --tests '*ChatEventsTest*' 2>&1 | tail -20`
Expected: FAIL — `applyEvent` has no `FfiEvent.Name` arm (member display unchanged).

- [ ] **Step 3: Write minimal implementation**

1. In `ChatEvents.kt` `applyEvent`, add:
```kotlin
        is FfiEvent.Name -> {
            val mem = lc.members.getOrPut(e.from) { Member(display = e.from.take(8)) }
            val glyph = when (e.tier) {
                FfiNameTier.REGISTRY_CONFIRMED -> " ✓"
                FfiNameTier.LINKED -> " 🔗"
                FfiNameTier.BARE -> ""
            }
            mem.display = (e.label ?: e.safetyNumber) + glyph
            mem.caveat = e.caveat            // add `var caveat: String? = null` to Member
        }
```
2. In `MainActivity.kt` `addBubble`, when a caveat is present for the sender, render it as a small warning line above the sender label (reuse the marking-banner style): `if (caveat != null) bubble.addView(text("⚠ $caveat", 10f, warnColor, bold = false))`. Thread the caveat via the `ChatMsg`/`Member` model into `handleEvent`'s `addBubble` call.
3. Add a chat overflow (`⋯`) menu action "Name / CQ": opens a dialog listing `NameBookStore.load(this)` labels + "(none)", a "Periodic CQ" checkbox with an interval field, and an "over every message" checkbox. On confirm: `client.setLeadingName(chosen)`, `client.announcePresence()`, `client.setPresenceCadence(periodicSecs, onMessageId)`, and persist the default via `NameBookStore.save`.

- [ ] **Step 4: Run to verify it passes**

Run: `android/gradlew -p android :app:testDebugUnitTest --tests '*ChatEventsTest*' 2>&1 | tail -20 && TALKRYPT_NYM=1 bash android/build-apk.sh 2>&1 | tail -5`
Expected: test PASS + APK BUILD SUCCESSFUL.

- [ ] **Step 5: Commit**
```bash
git add android/app/src/main/kotlin/com/talkrypt/app/ChatEvents.kt android/app/src/main/kotlin/com/talkrypt/app/MainActivity.kt android/app/src/test/kotlin/com/talkrypt/app/ChatEventsTest.kt
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(android): render name tiers/caveats in bubbles + mid-chat name/CQ menu"
```

---

## Phase 7 — Desktop

### Task 19: desktop name UI (egui)

**Files:**
- Modify: `crates/desktop/src/main.rs`

**Interfaces:**
- Consumes: `Core::set_leading_name`/`announce_presence`/`set_presence_cadence`, `Event::Name`, `NameTrustPolicy`, `combo_section`, `bubble`.
- Produces: a NAME TRUST + LEADING NAME control in `new_chat_screen`; `Event::Name → UiEvt` bridge; a name/CQ control in the chat screen.

- [ ] **Step 1: Write the failing test**
```rust
    #[test]
    fn name_event_maps_to_line() {
        // The Event::Name → UiEvt bridge produces a system line the chat screen renders.
        let evt = talkrypt_core::Event::Name {
            from: [0xAB; 48], account_fingerprint: None, label: Some("Whiskey".into()),
            tier: talkrypt_core::nametrust::NameTier::Bare, seq: 1, caveat: None };
        let ui = map_core_event_to_uievt("chat1", evt); // extract/name the existing bridge fn
        assert!(matches!(ui, Some(UiEvt::Name { .. })));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-desktop name_event_maps_to_line 2>&1 | tail -20`
Expected: FAIL — `UiEvt::Name` / mapping not found.

- [ ] **Step 3: Write minimal implementation**

1. Add `UiEvt::Name { id: String, from: String, label: Option<String>, tier: String, caveat: Option<String> }`.
2. In the `Event → UiEvt` bridge (main.rs ~:540), add:
```rust
        Event::Name { from, label, tier, caveat, .. } => Some(UiEvt::Name {
            id: id.clone(), from: short(&from),
            label, tier: format!("{tier:?}"), caveat }),
```
3. In `new_chat_screen`, add after the Nym checkbox:
```rust
        combo_section(ui, "NAME TRUST", "name_trust", &mut self.name_trust,
            &["Signal-style (default)", "Warn on collision", "Suppress colliding"]);
        combo_section(ui, "LEADING NAME", "leading_name", &mut self.leading_name,
            &self.name_labels()); // "(none)" + book labels
```
Add `name_trust: String`, `leading_name: String`, and a `name_book: Vec<(String,String)>` to the app struct (defaults `"Signal-style (default)"`, `"(none)"`). On Host/Join `Cmd`, include the chosen policy + leading name; in the worker set `desc.name_trust_policy` before `Core::new_group`, then `core.set_leading_name(..)` + `core.announce_presence().await`.
4. In `chat_screen`, when a `UiEvt::Name` with a caveat arrives, render a centered warning line; append the tier glyph to the peer's display name used in `bubble(..)`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-desktop 2>&1 | tail -20 && cargo build -p talkrypt-desktop 2>&1 | tail -5`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**
```bash
git add crates/desktop/src/main.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(desktop): name trust + leading-name UI, Event::Name rendering"
```

---

## Phase 8 — CLI

### Task 20: CLI `/name`, `/cq`, `--name`, `--name-policy`

**Files:**
- Modify: `crates/cli/src/main.rs`

**Interfaces:**
- Consumes: `Core::set_leading_name`/`announce_presence`/`set_presence_cadence`, `Event::Name`, `NameBook`, `NameTrustPolicy`.
- Produces: REPL commands `/name new|list|use`, `/cq`, `/cq periodic <mins>|off`; `Host`/`Join` gain `--name <id>`; `Host` gains `--name-policy signal|warn|suppress`; the event printer prints `Event::Name`.

- [ ] **Step 1: Write the failing test**
```rust
    #[test]
    fn parse_name_policy_arg() {
        assert_eq!(parse_name_policy("warn"), Some(NameTrustPolicy::WarnOnCollision));
        assert_eq!(parse_name_policy("signal"), Some(NameTrustPolicy::SignalStyle));
        assert_eq!(parse_name_policy("bogus"), None);
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p talkrypt-cli parse_name_policy 2>&1 | tail -20`
Expected: FAIL — `parse_name_policy` not found.

- [ ] **Step 3: Write minimal implementation**

1. Helper:
```rust
fn parse_name_policy(s: &str) -> Option<talkrypt_core::nametrust::NameTrustPolicy> {
    use talkrypt_core::nametrust::NameTrustPolicy::*;
    match s { "signal" => Some(SignalStyle), "warn" => Some(WarnOnCollision),
              "suppress" => Some(SuppressColliding), _ => None }
}
```
2. Add clap fields: `Host { .., name: Option<String>, name_policy: Option<String> }`, `Join { .., name: Option<String> }`. When building the descriptor, set `desc.name_trust_policy = host.name_policy.as_deref().and_then(parse_name_policy).unwrap_or_default();`. After `Core::new_group`/`new`, if `--name <id>` resolves in the loaded `NameBook`, `core.set_leading_name(Some(entry))`.
3. Add `run_command` arms:
```rust
        "name" => cmd_name(core, state, arg),   // new <label> | list | use <id>
        "cq" => {
            if arg.trim().is_empty() { core.announce_presence().await.ok(); }
            else if let Some(rest) = arg.strip_prefix("periodic ") {
                let secs = if rest.trim() == "off" { None } else { rest.trim().parse::<u64>().ok().map(|m| m*60) };
                core.set_presence_cadence(PresenceCadence { periodic_secs: secs, on_message_id: false });
            }
        }
```
`cmd_name` maintains `state.name_book: NameBook` (add the field) and prints/edits it; `/name use <id>` calls `core.set_leading_name` + `core.announce_presence().await`.
4. In the event-printer task, add:
```rust
        Event::Name { from, label, tier, caveat, .. } => {
            let who = short(&from);
            let l = label.unwrap_or_else(|| "(suppressed)".into());
            println!("[name] {who} is “{l}” [{tier:?}]{}",
                     caveat.map(|c| format!(" ⚠ {c}")).unwrap_or_default());
        }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p talkrypt-cli 2>&1 | tail -20 && cargo build -p talkrypt-cli 2>&1 | tail -5`
Expected: PASS + clean build.

- [ ] **Step 5: Commit**
```bash
git add crates/cli/src/main.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(cli): /name, /cq, --name, --name-policy + Event::Name printing"
```

---

## Phase 9 — On-device verification

### Task 21: two-emulator Nym name/CQ test

**Files:** none (verification; reuses the harness from task #62).

- [ ] **Step 1:** Build + install the nym APK on both emulators:
```bash
TALKRYPT_NYM=1 bash android/build-apk.sh
for S in emulator-5554 emulator-5556; do adb -s "$S" install -r android/app/build/outputs/apk/debug/app-debug.apk; done
```

- [ ] **Step 2:** On emulator A: New Chat → open **Advanced** → set LEADING NAME to a bare name (e.g. "K1ABC"), keep NAME TRUST = Signal-style, enable Nym, Host. Extract the invite; deep-link-join on B; "Join as pseudonym".

- [ ] **Step 3:** Verify **A's name renders over A's messages on B**: A sends a message; B's bubble shows sender "K1ABC" (not a safety-number). Expected: `K1ABC` appears as the sender label on B.

- [ ] **Step 4:** Verify **mid-chat switch**: on A, chat menu → Name/CQ → switch to a different name → confirm. B's subsequent (and re-announced) attribution updates to the new name. Verify **periodic CQ**: enable periodic (1 min → clamped to floor); confirm B keeps resolving A after an idle period.

- [ ] **Step 5:** Document the result in the task tracker (pass/flake) exactly as task #62 did (UI text dumps via `/tmp/uihelper.sh`). No commit (verification only); if a bug is found, fix it in the relevant crate with its own TDD task + commit.

---

## Self-Review

**Spec coverage:** §1 tiers → Tasks 2/4/8; §2 name book + tiers → Tasks 3/4; §3 wire (`Frame::Presence` + group sentinel) + verification → Tasks 7/8/9; §4 cadence (event/periodic/on-message) → Tasks 11/12/13; §5 render surface + policy + descriptor bump + collision → Tasks 4/6/8; §6 client surfaces → Tasks 14–20; §7 testing → embedded per task + Tasks 10/21; §8 security (insider-spoof, replay, confidentiality) → Tasks 10 + the group-epoch encryption inherited in Task 9; §9 non-goals → untouched (tracked as #66–#69). No gaps.

**Placeholder scan:** no "TBD/handle edge cases/etc." — each code step is concrete. The two spots that say "if a helper doesn't exist, add one modeled on X" (Tasks 8/9 test harness) name the exact existing test to mirror (`gossip_bridges_two_transport_islands`), which is acceptable scaffolding guidance, not a code placeholder.

**Type consistency:** `NameTier` (core `nametrust`) ↔ `FfiNameTier` (ffi) ↔ Kotlin `FfiNameTier`/desktop `format!("{tier:?}")`; `NameTrustPolicy.tag()`/`from_tag()` used identically in descriptor (Task 6) and ffi (Task 14); `NamePresence`/`NameRecord`/`NameEntry`/`NameBook` field names match across Tasks 1–4, 8, 14–15; `chat_context` signature `(&[u8], &str) -> [u8;32]` consistent in Tasks 2, 8, 11, 13; `Event::Name` fields identical in Tasks 7, 8, 14, 19, 20. `context` corrected to `[u8;32]` (SHA-256) throughout (the Task 1 interface note flagged and fixed the initial `[u8;48]` slip).

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-04-self-declared-names-cq-beacon-subspec-a.md`. Two execution options:

1. **Subagent-Driven (recommended)** — a fresh subagent per task, two-stage review between tasks.
2. **Inline Execution** — execute tasks in this session with batch checkpoints.

Which approach?
