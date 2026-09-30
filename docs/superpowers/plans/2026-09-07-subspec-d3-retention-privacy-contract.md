# Sub-spec D3 — Retention-privacy contract Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Govern what happens to a room's ephemeral backlog when it is promoted (D2): default `Fresh` (nothing retained), opt-in `Carry` (each member seals its OWN backlog), `CarryFromPoint` (seal only messages at/after a promoter-set timestamp). Promotion authorizes RETENTION, never TRANSMISSION.

**Architecture:** A bounded, member-local in-memory backlog captures each message this node sees (own-sent + received) in a group chat. On promotion commit, `retention_mode` (already in the signed D2 `Promote` body) selects the sealing behavior; sealed records go to a host-injected `HistoryStore` (mirrors `OutboxStore`), opaque at rest. Delete/return-to-ephemeral purges the sealed blob. Ethics invariants are test-enforced.

**Tech Stack:** Rust, `crates/core` only. No new wire frame; one new `u64` field (`carry_from_secs`) added to the D2 `PromoteBody`. No group-auth change.

## Global Constraints

- FV-preserving: no edit to existing wire frames' semantics; `PromoteBody` gains one flat `u64` field, Kani `promote_body_decode_never_panics` stays trivially total; GroupAuth.fst untouched.
- Retention is LOCAL: history is never transmitted; a member seals only its own already-received copy; decline ⇒ nothing sealed; no backfill to latecomers.
- Default-safe: absent an explicit choice, `Fresh`.
- Recoverable: sealed history is purgeable (Delete / return-to-ephemeral).
- History records are local-at-rest only (never attacker-controlled over the wire), so their (de)serialization needs no Kani proof; keep it flat and robust anyway.
- Commit as `pq-cybarg <resistant@tuta.com>`.

---

### Task 1: Retention mode enum + `carry_from_secs` on PromoteBody

**Files:**
- Modify: `crates/core/src/engine.rs` (PromoteBody struct + encode/decode + `RetentionMode` enum + D2 tests/constructors that build PromoteBody)

**Interfaces:**
- Produces: `enum RetentionMode { Fresh=0, Carry=1, CarryFromPoint=2 }` with `from_u8`/`as_u8`; `PromoteBody.carry_from_secs: u64` (encoded after `onion`, before `epoch` — pick a stable slot and mirror in decode).

- [ ] **Step 1** Add `RetentionMode` enum + `from_u8(u8)->Option<Self>` / `as_u8(&self)->u8` near PromoteBody. `from_u8` returns `None` for unknown tags (fail-closed).
- [ ] **Step 2** Add `pub carry_from_secs: u64` field to `PromoteBody`; put it in `encode()` (append after existing fields, before nothing that reorders) and read it in `decode()` at the matching position; update the `Some(Self{..})`.
- [ ] **Step 3** Update every PromoteBody constructor / test literal in engine.rs to set `carry_from_secs` (0 for existing D2 tests).
- [ ] **Step 4** `cargo test -p talkrypt-core promote_consent_frames_and_bodies_roundtrip` — PASS.
- [ ] **Step 5** Commit.

### Task 2: `HistoryStore` trait + in-memory default + `HistoryRecord`

**Files:**
- Create: `crates/core/src/history.rs`
- Modify: `crates/core/src/lib.rs` (add `mod history;` + re-exports)

**Interfaces:**
- Produces: `trait HistoryStore { fn put(&self,chat:&str,gid:[u8;32],record:&[u8]); fn load(&self,chat:&str)->Vec<([u8;32],Vec<u8>)>; fn purge(&self,chat:&str); }`; `struct InMemoryHistory`; `struct HistoryRecord { from:[u8;48], ts:u64, text:String, marking:Option<Marking> }` with `encode()/decode(&[u8])->Option<Self>`.

- [ ] **Step 1** Write `HistoryRecord` with flat encode/decode (reuse `talkrypt_wire` Writer/Reader) + a round-trip unit test.
- [ ] **Step 2** Write `HistoryStore` trait + `InMemoryHistory` (HashMap chat -> Vec<(gid,record)>; `purge` clears the chat) + a put/load/purge unit test.
- [ ] **Step 3** `cargo test -p talkrypt-core history::` — PASS.
- [ ] **Step 4** Commit.

### Task 3: Member-local backlog capture (bounded)

**Files:**
- Modify: `crates/core/src/engine.rs` (Inner fields, Core::new/host wiring, send_marked, handle_group_msg)

**Interfaces:**
- Produces: `Inner.backlog: Mutex<Vec<BacklogEntry>>` (`BacklogEntry { gid:[u8;32], ts:u64, record:Vec<u8> }`), `Inner.history: Arc<dyn HistoryStore>`, `Core::set_history_store(Arc<dyn HistoryStore>)`; helper `record_backlog(inner,&gid,record_bytes,ts)` (bounded to `BACKLOG_CAP`, drops oldest).

- [ ] **Step 1** Add `BacklogEntry`, `BACKLOG_CAP` const, `Inner.backlog`, `Inner.history` (default `InMemoryHistory`); init in `Core::new`.
- [ ] **Step 2** In `send_marked` group path, after building `ct`, record own outgoing to backlog (`gid=gossip_id(&ct)`, `ts=now_secs()`, `record=HistoryRecord{from:me,ts,text,marking}.encode()`).
- [ ] **Step 3** In `handle_group_msg`, after emitting `Event::Message`, record incoming to backlog (`gid=gossip_id(&gct)`, `ts=now_secs()`).
- [ ] **Step 4** Add `Core::set_history_store` + a test asserting backlog grows on send/receive and is bounded by cap.
- [ ] **Step 5** `cargo test -p talkrypt-core backlog` — PASS. Commit.

### Task 4: Apply retention on commit

**Files:**
- Modify: `crates/core/src/engine.rs` (`commit_promotion`, gate on `retention_mode`)

**Interfaces:**
- Consumes: `RetentionMode`, `Inner.backlog`, `Inner.history`, the pending `PromoteState.body`.
- Produces: `apply_retention(inner, mode, carry_from_secs)` called inside `commit_promotion` BEFORE `set_persistence(true)` and BEFORE the backlog would otherwise be cleared.

- [ ] **Step 1** In `commit_promotion`, read `retention_mode`+`carry_from_secs` from the committing `PromoteState.body` (thread it in), call `apply_retention`.
- [ ] **Step 2** `apply_retention`: `Fresh` → clear backlog, seal nothing; `Carry` → seal every backlog entry to `history`; `CarryFromPoint` → seal entries with `ts >= carry_from_secs`; unknown → treat as `Fresh` (fail-safe). Clear the in-memory backlog afterward.
- [ ] **Step 3** Test: promote with each mode; assert `history.load(chat)` contains exactly the expected subset.
- [ ] **Step 4** `cargo test -p talkrypt-core retention` — PASS. Commit.

### Task 5: Recoverability — purge on delete/return-to-ephemeral

**Files:**
- Modify: `crates/core/src/engine.rs` (`set_persistence(false)` path + a `purge_history` affordance)

**Interfaces:**
- Produces: `Core::purge_history()` (calls `history.purge(channel)` + clears backlog); `set_persistence(false)` purges sealed history (return-to-ephemeral erases the blob, invariant 4).

- [ ] **Step 1** Add `Core::purge_history`; call it from `set_persistence(false)`.
- [ ] **Step 2** Test: seal via Carry, then `set_persistence(false)`, assert `history.load` empty.
- [ ] **Step 3** `cargo test -p talkrypt-core purge` — PASS. Commit.

### Task 6: Ethics invariant tests (mirror Sub-spec C §0.5)

**Files:**
- Modify: `crates/core/src/engine.rs` (tests)

- [ ] **Step 1** Invariant 1 default-safe: a promotion with `retention_mode` absent/`Fresh` seals nothing.
- [ ] **Step 2** Invariant 2 consented: a member who DECLINES (not in `carried`, evicted) seals nothing for itself.
- [ ] **Step 3** Invariant 3 no-fabrication/no-transmission: a latecomer (empty backlog) gains nothing on a Carry promotion; sealing never sends a frame (assert no new outbound history frame exists — there is no history wire type).
- [ ] **Step 4** Invariant 4 recoverable: covered by Task 5; add an explicit named test.
- [ ] **Step 5** `cargo test -p talkrypt-core` full — PASS. Commit.

### Task 7: FFI surface + descriptor retention tag (optional disclosure) + docs

**Files:**
- Modify: `crates/ffi/src/lib.rs` (expose `set_history_store` is host-internal; expose `purge_history`; map retention mode in propose), `crates/core/src/engine.rs` (ensure `propose_promote` accepts `retention_mode`+`carry_from_secs`)

- [ ] **Step 1** Ensure `propose_promote` signature carries `retention_mode` + `carry_from_secs`; thread into `PromoteBody`. Update D2 callers/tests.
- [ ] **Step 2** FFI `purge_history` wrapper; keep history-store injection host-side (in-memory default is fine for now).
- [ ] **Step 3** `cargo build --workspace` + full `cargo test -p talkrypt-core` — PASS. Commit.

### Task 8: Kani re-proof + CI note

**Files:**
- Modify: `crates/core/src/engine.rs` (Kani harness comment), `.github/workflows/formal.yml` (note carry_from_secs coverage)

- [ ] **Step 1** Confirm `promote_body_decode_never_panics` still covers the new `u64` field (flat) — no new harness needed; update the harness/CI comment to mention `carry_from_secs`.
- [ ] **Step 2** `cargo kani -p talkrypt-core --harness engine::d1_proofs::promote_body_decode_never_panics` if Kani available locally; else rely on CI. Commit.
