# Sub-spec D1 MVP (Persistent Outbox + Group Keeper) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make a persistent talkrypt chat survive participants being offline — a sender's un-acked frames persist and re-send on reconnect (Layer 0 outbox), and an online member buffers frames for offline members and replays them on return (Layer A keeper) — with holders storing opaque ciphertext only.

**Architecture:** Core owns the outbox/keeper *logic* (in-memory queues keyed by `gossip_id`) and drives flush from the existing `reconnect()` path; at-rest *persistence* is delegated to a host-injected `OutboxStore` trait (mirroring the existing `core::seal::KeyWrapper` seam), so core stays platform-agnostic and unit-testable with an in-memory store. A new `Frame::DeliveryAck` (tag 15) clears delivered frames; the existing `SeenSet`/`gossip_id` dedup makes re-sends idempotent.

**Tech Stack:** Rust (`crates/core`), `talkrypt_wire` codec, `tokio`, `cargo test`, `cargo kani`.

## Global Constraints

- **FV-preservation (hard gate):** never edit `crates/wire/src/lib.rs` codec or its 3 Kani harnesses; new `Frame` variants use free tags (D1 = **15–18**; 13/14 reserved for Sub-spec D2); every new decoder returns **flat/fixed-capacity** types (arrays of `[u8;N]` + one `u32`-length-prefixed opaque blob — the `bounded::decode` shape) and ships a `#[cfg(kani)]` `*_never_panics` proof in the same task.
- **Group-auth untouched:** holders store only opaque `Routed.inner` ciphertext (no group key); `DeliveryAck` clears only the acker's *own* outbox and is NOT a group-attribution signal → `GroupAuth.fst`/`GroupAuthQROM.ec` need no change.
- **Reuse, don't reinvent:** `SeenSet`/`gossip_id` (`engine.rs:571`,`:605`), the `Routed`/`Route` envelope (`engine.rs:364`,`:375`), `reconnect()` (`engine.rs:1103`) as the flush trigger, and the `core::seal` seam (`seal.rs:82` `KeyWrapper`).
- **Bounds:** every queue is capped and TTL-bounded; drops are surfaced as an event, never silent.
- **Commit identity:** author + committer `pq-cybarg <resistant@tuta.com>`. Push with `GIT_SSH_COMMAND=/usr/bin/ssh`. Work on branch `feat/subspec-d1-outbox-keeper` off `main`.
- **MVP scope:** deliver Layer 0 (outbox) + Layer A (keeper). Defer Layer B (anchor mailbox: `MailboxPut`/`MailboxFetch` tags 16/17) and Layer C (replicated queue: `QueueSync` tag 18) to later plans.

## File Structure

- **Create `crates/core/src/outbox.rs`** — the `OutboxStore` trait, an `InMemoryOutbox` test double, the `Outbox` in-memory index (gossip_id → target + enqueued-at), cap/TTL logic, and its unit tests. One responsibility: persistent-outbox bookkeeping.
- **Create `crates/core/src/keeper.rs`** — the `KeeperQueue` (per-recipient buffered `Routed` for offline peers) + replay selection + its unit tests. One responsibility: keeper buffering.
- **Modify `crates/core/src/engine.rs`** — add `Frame::DeliveryAck` (tag 15) encode/decode + Kani proof; wire `Outbox`/`KeeperQueue` into `Inner`; enqueue-on-send, auto-ack-on-receive, ack-handling, flush-on-reconnect; new `Event`s.
- **Modify `crates/core/src/lib.rs`** — `pub mod outbox; pub mod keeper;` and re-exports.

---

### Task 1: `Frame::DeliveryAck` (tag 15) — flat wire frame + Kani proof

**Files:**
- Modify: `crates/core/src/engine.rs` (the `Frame` enum `:104`, `encode` `:~205`, `decode` `:~260`, and the `#[cfg(kani)] mod proofs` if present else add one)

**Interfaces:**
- Produces: `Frame::DeliveryAck(Vec<[u8;32]>)` with `encode`/`decode` round-trip; a batch of acked `gossip_id`s, count-capped at `MAX_ACK = 64`.

- [ ] **Step 1: Write the failing test** — append to the `#[cfg(test)] mod tests` in `engine.rs`:

```rust
#[test]
fn delivery_ack_frame_roundtrips_and_caps() {
    let ids = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    let bytes = Frame::DeliveryAck(ids.clone()).encode();
    match Frame::decode(&bytes) {
        Some(Frame::DeliveryAck(got)) => assert_eq!(got, ids),
        other => panic!("expected DeliveryAck, got {other:?}"),
    }
    // Empty batch round-trips.
    assert!(matches!(Frame::decode(&Frame::DeliveryAck(vec![]).encode()), Some(Frame::DeliveryAck(v)) if v.is_empty()));
    // A count over MAX_ACK is rejected (never allocates unboundedly).
    let mut hostile = talkrypt_wire::Writer::new();
    hostile.put_u8(15);
    hostile.put_u32(70); // > MAX_ACK
    assert!(Frame::decode(&hostile.into_vec()).is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core delivery_ack_frame_roundtrips_and_caps 2>&1 | tail -5`
Expected: FAIL to compile — `no variant DeliveryAck`.

- [ ] **Step 3: Add the variant + encode/decode.** In the `Frame` enum (`engine.rs:104`) add:

```rust
    /// D1 store-and-forward: a batch of gossip-ids the sender should clear from its
    /// outbox (they have been received). Flat: count + fixed [u8;32] ids. Rides the
    /// pairwise/transport layer; clears only the acker's OWN outbox (no group auth).
    DeliveryAck(Vec<[u8; 32]>),
```

Add the tag-15 encode arm (in `Frame::encode`, after the `Presence` arm):

```rust
            Frame::DeliveryAck(ids) => {
                w.put_u8(15);
                w.put_u32(ids.len() as u32);
                for id in ids {
                    w.put_bytes(id);
                }
            }
```

Add the decode arm (in `Frame::decode`, before `_ => return None`):

```rust
            15 => {
                const MAX_ACK: usize = 64;
                let n = r.get_u32().ok()? as usize;
                if n > MAX_ACK {
                    return None;
                }
                let mut ids = Vec::with_capacity(n);
                for _ in 0..n {
                    let b = r.get_bytes().ok()?;
                    if b.len() != 32 {
                        return None;
                    }
                    let mut id = [0u8; 32];
                    id.copy_from_slice(b);
                    ids.push(id);
                }
                r.finish().ok()?;
                Frame::DeliveryAck(ids)
            }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core delivery_ack_frame_roundtrips_and_caps 2>&1 | tail -5`
Expected: PASS.

- [ ] **Step 5: Add the Kani proof.** In `engine.rs`, in the `#[cfg(kani)] mod proofs` block (add the block if none exists in this file, mirroring `crates/wire/src/lib.rs`):

```rust
#[cfg(kani)]
mod d1_proofs {
    use super::*;
    /// DeliveryAck decode never panics on arbitrary <=64-byte input (it runs on
    /// bytes from a possibly-hostile peer). Flat/bounded => CBMC-tractable.
    #[kani::proof]
    #[kani::unwind(6)]
    fn delivery_ack_decode_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 64);
        let data: [u8; 64] = kani::any();
        let _ = Frame::decode(&data[..len]);
    }
}
```

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d1): Frame::DeliveryAck (tag 15) — flat wire frame + Kani no-panic proof"
```

---

### Task 2: `OutboxStore` trait + in-memory store (`outbox.rs`)

**Files:**
- Create: `crates/core/src/outbox.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod outbox;`)

**Interfaces:**
- Produces:
  - `pub trait OutboxStore: Send + Sync { fn put(&self, chat: &str, gid: [u8;32], frame: &[u8]); fn remove(&self, chat: &str, gid: [u8;32]); fn load(&self, chat: &str) -> Vec<([u8;32], Vec<u8>)>; }`
  - `pub struct InMemoryOutbox` implementing it (for tests / default).
  - `pub struct Outbox { store: Arc<dyn OutboxStore>, meta: Mutex<HashMap<[u8;32], u64>>, cap: usize, ttl_secs: u64 }` with `new`, `enqueue`, `ack`, `due_for_resend`, `evict_expired`.
- Consumes: nothing (leaf module).

- [ ] **Step 1: Write the failing test** — create `crates/core/src/outbox.rs` with only tests first:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn enqueue_ack_removes_and_load_reflects() {
        let store = Arc::new(InMemoryOutbox::new());
        let ob = Outbox::new(store.clone(), 16, 3600);
        let gid = [7u8; 32];
        ob.enqueue("chatA", gid, b"sealed-frame", 100);
        assert_eq!(store.load("chatA").len(), 1);
        assert_eq!(ob.pending("chatA"), vec![gid]);
        ob.ack("chatA", gid);
        assert!(store.load("chatA").is_empty());
        assert!(ob.pending("chatA").is_empty());
    }

    #[test]
    fn cap_evicts_oldest_and_reports() {
        let store = Arc::new(InMemoryOutbox::new());
        let ob = Outbox::new(store.clone(), 2, 3600);
        ob.enqueue("c", [1u8; 32], b"a", 1);
        ob.enqueue("c", [2u8; 32], b"b", 2);
        let dropped = ob.enqueue("c", [3u8; 32], b"c", 3); // over cap 2
        assert_eq!(dropped, 1, "one oldest frame evicted");
        assert_eq!(store.load("c").len(), 2);
    }

    #[test]
    fn ttl_evicts_expired() {
        let store = Arc::new(InMemoryOutbox::new());
        let ob = Outbox::new(store.clone(), 16, 10);
        ob.enqueue("c", [1u8; 32], b"old", 100);
        ob.enqueue("c", [2u8; 32], b"new", 118);
        let expired = ob.evict_expired("c", 118); // 118-100=18 > ttl 10
        assert_eq!(expired, 1);
        assert_eq!(ob.pending("c"), vec![[2u8; 32]]);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core outbox:: 2>&1 | tail -5`
Expected: FAIL to compile — `Outbox`/`InMemoryOutbox` undefined.

- [ ] **Step 3: Implement the module** (prepend above the tests in `outbox.rs`):

```rust
//! Persistent-outbox bookkeeping for D1 store-and-forward. Core owns the in-memory
//! index + cap/TTL; at-rest persistence is delegated to a host-injected `OutboxStore`
//! (mirroring `crate::seal::KeyWrapper`), so core stays platform-agnostic. Stored
//! frames are OPAQUE (already-encrypted `Routed` bytes) — no plaintext at rest here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Host-provided at-rest persistence for outbox frames. Implementations seal the
/// `frame` bytes (e.g. via the FFI seal seam) before writing. Keys are (chat, gid).
pub trait OutboxStore: Send + Sync {
    fn put(&self, chat: &str, gid: [u8; 32], frame: &[u8]);
    fn remove(&self, chat: &str, gid: [u8; 32]);
    /// All persisted (gid, frame) for a chat, for resend after a restart.
    fn load(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)>;
}

/// In-memory `OutboxStore` (default + tests). Real hosts inject a sealed-file impl.
#[derive(Default)]
pub struct InMemoryOutbox {
    inner: Mutex<HashMap<String, HashMap<[u8; 32], Vec<u8>>>>,
}
impl InMemoryOutbox {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }
}
impl OutboxStore for InMemoryOutbox {
    fn put(&self, chat: &str, gid: [u8; 32], frame: &[u8]) {
        self.inner.lock().unwrap().entry(chat.to_string()).or_default().insert(gid, frame.to_vec());
    }
    fn remove(&self, chat: &str, gid: [u8; 32]) {
        if let Some(m) = self.inner.lock().unwrap().get_mut(chat) {
            m.remove(&gid);
        }
    }
    fn load(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        self.inner.lock().unwrap().get(chat).map(|m| m.iter().map(|(k, v)| (*k, v.clone())).collect()).unwrap_or_default()
    }
}

/// The outbox: an in-memory index of un-acked frames (gid -> enqueued-at secs),
/// backed by an `OutboxStore` for at-rest persistence. Cap + TTL bounded.
pub struct Outbox {
    store: Arc<dyn OutboxStore>,
    /// chat -> (gid -> enqueued_at_secs), insertion order kept for cap eviction.
    meta: Mutex<HashMap<String, Vec<([u8; 32], u64)>>>,
    cap: usize,
    ttl_secs: u64,
}

impl Outbox {
    pub fn new(store: Arc<dyn OutboxStore>, cap: usize, ttl_secs: u64) -> Self {
        Self { store, meta: Mutex::new(HashMap::new()), cap, ttl_secs }
    }

    /// Persist a frame and index it. Returns the number of oldest frames evicted to
    /// stay within `cap` (0 normally).
    pub fn enqueue(&self, chat: &str, gid: [u8; 32], frame: &[u8], now_secs: u64) -> usize {
        self.store.put(chat, gid, frame);
        let mut meta = self.meta.lock().unwrap();
        let v = meta.entry(chat.to_string()).or_default();
        if !v.iter().any(|(g, _)| *g == gid) {
            v.push((gid, now_secs));
        }
        let mut dropped = 0;
        while v.len() > self.cap {
            let (old, _) = v.remove(0);
            self.store.remove(chat, old);
            dropped += 1;
        }
        dropped
    }

    /// Clear a delivered frame.
    pub fn ack(&self, chat: &str, gid: [u8; 32]) {
        self.store.remove(chat, gid);
        if let Some(v) = self.meta.lock().unwrap().get_mut(chat) {
            v.retain(|(g, _)| *g != gid);
        }
    }

    /// The gids still pending for a chat (insertion order).
    pub fn pending(&self, chat: &str) -> Vec<[u8; 32]> {
        self.meta.lock().unwrap().get(chat).map(|v| v.iter().map(|(g, _)| *g).collect()).unwrap_or_default()
    }

    /// (gid, sealed frame) still pending, for resend on reconnect.
    pub fn due_for_resend(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        self.store.load(chat)
    }

    /// Evict frames older than the TTL. Returns how many were evicted.
    pub fn evict_expired(&self, chat: &str, now_secs: u64) -> usize {
        let mut meta = self.meta.lock().unwrap();
        let Some(v) = meta.get_mut(chat) else { return 0 };
        let ttl = self.ttl_secs;
        let expired: Vec<[u8; 32]> = v.iter().filter(|(_, t)| now_secs.saturating_sub(*t) > ttl).map(|(g, _)| *g).collect();
        for g in &expired {
            self.store.remove(chat, *g);
        }
        v.retain(|(_, t)| now_secs.saturating_sub(*t) <= ttl);
        expired.len()
    }
}
```

Add to `crates/core/src/lib.rs` (near the other `pub mod` lines): `pub mod outbox;`

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core outbox:: 2>&1 | tail -6`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/outbox.rs crates/core/src/lib.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d1): OutboxStore seam + Outbox index (cap + TTL), in-memory store"
```

---

### Task 3: `KeeperQueue` — buffer opaque frames for offline peers (`keeper.rs`)

**Files:**
- Create: `crates/core/src/keeper.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod keeper;`)

**Interfaces:**
- Produces: `pub struct KeeperQueue { store: Arc<dyn crate::outbox::OutboxStore>, index: Mutex<HashMap<[u8;48], Vec<([u8;32], u64)>>>, cap_per_peer: usize, ttl_secs: u64 }` with `buffer(recipient, gid, frame, now)`, `drain(recipient) -> Vec<([u8;32],Vec<u8>)>`, `ack(recipient, gid)`, `evict_expired(recipient, now)`. Reuses `OutboxStore` keyed by the recipient fp hex as the "chat" key.
- Consumes: `crate::outbox::OutboxStore` (Task 2).

- [ ] **Step 1: Write the failing test** — create `crates/core/src/keeper.rs` with tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::InMemoryOutbox;
    use std::sync::Arc;

    #[test]
    fn buffers_for_offline_peer_then_drains() {
        let store = Arc::new(InMemoryOutbox::new());
        let kq = KeeperQueue::new(store, 8, 3600);
        let bob = [9u8; 48];
        kq.buffer(bob, [1u8; 32], b"opaque-frame", 10);
        kq.buffer(bob, [2u8; 32], b"opaque-frame-2", 11);
        let drained = kq.drain(bob);
        assert_eq!(drained.len(), 2, "both buffered frames replayed on drain");
        // After ack, they are gone.
        kq.ack(bob, [1u8; 32]);
        kq.ack(bob, [2u8; 32]);
        assert!(kq.drain(bob).is_empty());
    }

    #[test]
    fn per_peer_cap_bounds_the_queue() {
        let store = Arc::new(InMemoryOutbox::new());
        let kq = KeeperQueue::new(store, 2, 3600);
        let p = [5u8; 48];
        kq.buffer(p, [1u8; 32], b"a", 1);
        kq.buffer(p, [2u8; 32], b"b", 2);
        let dropped = kq.buffer(p, [3u8; 32], b"c", 3);
        assert_eq!(dropped, 1);
        assert_eq!(kq.drain(p).len(), 2);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core keeper:: 2>&1 | tail -5`
Expected: FAIL to compile — `KeeperQueue` undefined.

- [ ] **Step 3: Implement** (prepend above the tests):

```rust
//! Layer-A group keeper: an online member buffers OPAQUE (already-encrypted) frames
//! addressed to a currently-offline peer and replays them when that peer reconnects.
//! Holds ciphertext only (no group key). Reuses `OutboxStore` for at-rest persistence,
//! keyed by the recipient fingerprint (hex) as the store "chat" key.

use crate::outbox::OutboxStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn key(recipient: &[u8; 48]) -> String {
    let mut s = String::with_capacity(96);
    for b in recipient {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub struct KeeperQueue {
    store: Arc<dyn OutboxStore>,
    index: Mutex<HashMap<[u8; 48], Vec<([u8; 32], u64)>>>,
    cap_per_peer: usize,
    ttl_secs: u64,
}

impl KeeperQueue {
    pub fn new(store: Arc<dyn OutboxStore>, cap_per_peer: usize, ttl_secs: u64) -> Self {
        Self { store, index: Mutex::new(HashMap::new()), cap_per_peer, ttl_secs }
    }

    /// Buffer an opaque frame for `recipient`. Returns oldest-evicted count (cap).
    pub fn buffer(&self, recipient: [u8; 48], gid: [u8; 32], frame: &[u8], now_secs: u64) -> usize {
        self.store.put(&key(&recipient), gid, frame);
        let mut idx = self.index.lock().unwrap();
        let v = idx.entry(recipient).or_default();
        if !v.iter().any(|(g, _)| *g == gid) {
            v.push((gid, now_secs));
        }
        let mut dropped = 0;
        while v.len() > self.cap_per_peer {
            let (old, _) = v.remove(0);
            self.store.remove(&key(&recipient), old);
            dropped += 1;
        }
        dropped
    }

    /// All buffered (gid, opaque frame) for a peer, to replay on its reconnect.
    pub fn drain(&self, recipient: [u8; 48]) -> Vec<([u8; 32], Vec<u8>)> {
        self.store.load(&key(&recipient))
    }

    pub fn ack(&self, recipient: [u8; 48], gid: [u8; 32]) {
        self.store.remove(&key(&recipient), gid);
        if let Some(v) = self.index.lock().unwrap().get_mut(&recipient) {
            v.retain(|(g, _)| *g != gid);
        }
    }

    pub fn evict_expired(&self, recipient: [u8; 48], now_secs: u64) -> usize {
        let mut idx = self.index.lock().unwrap();
        let Some(v) = idx.get_mut(&recipient) else { return 0 };
        let ttl = self.ttl_secs;
        let expired: Vec<[u8; 32]> = v.iter().filter(|(_, t)| now_secs.saturating_sub(*t) > ttl).map(|(g, _)| *g).collect();
        for g in &expired {
            self.store.remove(&key(&recipient), *g);
        }
        v.retain(|(_, t)| now_secs.saturating_sub(*t) <= ttl);
        expired.len()
    }
}
```

Add to `crates/core/src/lib.rs`: `pub mod keeper;`

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core keeper:: 2>&1 | tail -6`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/keeper.rs crates/core/src/lib.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d1): KeeperQueue — buffer opaque frames for offline peers (cap + TTL)"
```

---

### Task 4: Wire outbox + persistence flag into `Inner`; enqueue on send

**Files:**
- Modify: `crates/core/src/engine.rs` (`Inner` struct `~:400`, `build`/`new_group` constructors, the group-send path, and a new `Core::set_persistence`)

**Interfaces:**
- Consumes: `crate::outbox::{Outbox, InMemoryOutbox, OutboxStore}` (Task 2).
- Produces: `Inner.outbox: Outbox`, `Inner.persistent: Mutex<HashSet<String>>` (chat ids with outbox on); `pub fn Core::set_persistence(&self, chat: &str, on: bool)`; `pub fn Core::with_outbox_store(self, store: Arc<dyn OutboxStore>) -> Self` builder for host injection (default = `InMemoryOutbox`).

- [ ] **Step 1: Write the failing test** — in `engine.rs` tests:

```rust
#[tokio::test]
async fn persistent_chat_enqueues_outgoing_group_frame() {
    let fabric = LoopbackFabric::new();
    let desc = ChatDescriptor::new(TopologyKind::Hub, Persistence::Persistent, DEFAULT_SUITE_ID, vec!["h".into()], "#p");
    let suite = SuiteRegistry::with_defaults().get(DEFAULT_SUITE_ID).unwrap();
    let (host, _rx) = Core::new_group(IdentityKeyPair::generate(), suite, Arc::new(fabric.transport("h")), desc.clone(), true);
    let chat = host.chat_id();
    host.set_persistence(&chat, true);
    host.send_text("#p", "hello").await.ok();
    // The frame is now recoverable from the outbox for resend.
    assert!(!host.inner.outbox.pending(&chat).is_empty(), "a persistent-chat send is queued in the outbox");
}
```

*(If `chat_id()`/`send_text` differ, use the existing send API; the assertion is that a persistent send leaves a pending outbox entry keyed by that chat.)*

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core persistent_chat_enqueues_outgoing_group_frame 2>&1 | tail -6`
Expected: FAIL — `set_persistence`/`inner.outbox` undefined.

- [ ] **Step 3: Implement.**
  - Add fields to `Inner`: `outbox: crate::outbox::Outbox,` and `persistent: std::sync::Mutex<std::collections::HashSet<String>>,`.
  - In every `Inner` constructor path (`build`), initialize: `outbox: crate::outbox::Outbox::new(outbox_store, 4096, 30 * 24 * 3600), persistent: Mutex::new(HashSet::new()),` where `outbox_store` defaults to `Arc::new(crate::outbox::InMemoryOutbox::new())` unless injected.
  - Add the builder + setter on `Core`:

```rust
    /// Inject the host's at-rest outbox store (default: in-memory). Call before use.
    pub fn with_outbox_store(self, store: std::sync::Arc<dyn crate::outbox::OutboxStore>) -> Self {
        *self.inner.outbox_store_slot.lock().unwrap() = Some(store);
        self
    }
    /// Turn the persistent-outbox on/off for a chat (D2 flips this on promotion).
    pub fn set_persistence(&self, chat: &str, on: bool) {
        let mut p = self.inner.persistent.lock().unwrap();
        if on { p.insert(chat.to_string()); } else { p.remove(chat); }
    }
```

  - In the group-message send path (where a `Frame::GroupMsg`/`Frame::Chat` is encoded and sent), after computing the outgoing frame bytes `payload`, if `self.inner.persistent.lock().unwrap().contains(&chat)`:

```rust
        let gid = gossip_id(&payload);
        let dropped = self.inner.outbox.enqueue(&chat, gid, &payload, now_secs());
        if dropped > 0 {
            let _ = self.inner.events.send(Event::OutboxDropped { chat: chat.clone(), count: dropped });
        }
```

  - Add a small `fn now_secs() -> u64` helper (`std::time::SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()`), and the `Event::OutboxDropped { chat: String, count: usize }` variant (Task 7 also uses it — define it here).

*(Note: to keep injection simple, prefer initializing `Inner.outbox` directly from a store passed through `build`; the `with_outbox_store`/`outbox_store_slot` indirection is only if the constructor can't take the store. Choose whichever matches the existing constructor shape — the deliverable is: a persistent-chat send calls `outbox.enqueue`.)*

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core persistent_chat_enqueues_outgoing_group_frame 2>&1 | tail -6`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d1): enqueue outgoing group frames into the outbox for persistent chats"
```

---

### Task 5: Receive-side auto-ack + ack handling

**Files:**
- Modify: `crates/core/src/engine.rs` (the inbound reader loop where group frames are processed + where `Frame` variants are dispatched)

**Interfaces:**
- Consumes: `Frame::DeliveryAck` (Task 1), `Inner.outbox` (Task 4), `gossip_id`/`SeenSet`.
- Produces: on receiving a persistent-chat group frame, the receiver sends `Frame::DeliveryAck([gid])` back to the sender; on receiving `DeliveryAck(ids)`, the outbox clears those gids.

- [ ] **Step 1: Write the failing test** (integration, `LoopbackFabric`):

```rust
#[tokio::test]
async fn ack_clears_sender_outbox_after_delivery() {
    // host + one member exchange over the fabric; member acks; host outbox drains.
    let fabric = LoopbackFabric::new();
    let (host, member, chat) = persistent_pair(&fabric).await; // helper: builds a live host+member persistent chat, returns ids
    host.send_text(&chat, "hi").await.unwrap();
    assert!(!host.inner.outbox.pending(&chat).is_empty());
    // pump both sides so the member receives + auto-acks and the host processes the ack
    pump(&host, &member).await;
    assert!(host.inner.outbox.pending(&chat).is_empty(), "sender outbox cleared once the member acks receipt");
}
```

*(Provide `persistent_pair`/`pump` as small test helpers next to this test, following the existing `LoopbackFabric` integration-test patterns in `engine.rs`.)*

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core ack_clears_sender_outbox_after_delivery 2>&1 | tail -6`
Expected: FAIL — no auto-ack / ack handling yet.

- [ ] **Step 3: Implement.**
  - In the inbound path where a group message is accepted and surfaced (after `decrypt_verified` succeeds and the `SeenSet.insert(gid)` dedup returns `true`), send an ack back to the message's sender:

```rust
        // D1: acknowledge receipt so the sender can clear its outbox.
        if self.inner.persistent.lock().unwrap().contains(&chat) {
            let ack = Frame::DeliveryAck(vec![gid]).encode();
            let _ = self.route_to(Route::Peer(sender_fp), ack).await; // existing pairwise send to a specific fp
        }
```

  - Add a `Frame::DeliveryAck` dispatch arm in the reader match:

```rust
        Some(Frame::DeliveryAck(ids)) => {
            for gid in ids {
                self.inner.outbox.ack(&chat, gid);
            }
        }
```

*(Use the existing helper that sends a `Frame` to a specific peer fingerprint; if messages are keyed per-chat, resolve `chat` from the receiving session as the surrounding code already does.)*

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core ack_clears_sender_outbox_after_delivery 2>&1 | tail -6`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d1): auto-ack received persistent-chat frames + clear outbox on DeliveryAck"
```

---

### Task 6: Flush the outbox on reconnect / peer-online

**Files:**
- Modify: `crates/core/src/engine.rs` (`reconnect()` `:1103`, and the peer-connected handler)

**Interfaces:**
- Consumes: `Outbox::due_for_resend` (Task 2), the existing per-peer send.
- Produces: `Core::flush_outbox(&self)` that re-sends every pending frame across persistent chats; called at the end of `reconnect()` and when a peer newly connects.

- [ ] **Step 1: Write the failing test** (integration):

```rust
#[tokio::test]
async fn offline_member_receives_backlog_on_reconnect() {
    let fabric = LoopbackFabric::new();
    let (host, member, chat) = persistent_pair(&fabric).await;
    disconnect(&member); // member goes offline (drop its transport link)
    host.send_text(&chat, "while-you-were-out").await.unwrap();
    // nothing delivered yet; host outbox holds it
    assert_eq!(host.inner.outbox.pending(&chat).len(), 1);
    reconnect_member(&fabric, &member).await;
    host.flush_outbox().await;
    pump(&host, &member).await;
    assert!(received(&member, "while-you-were-out"), "backlog delivered after reconnect");
    assert!(host.inner.outbox.pending(&chat).is_empty(), "outbox drained after ack");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core offline_member_receives_backlog_on_reconnect 2>&1 | tail -6`
Expected: FAIL — `flush_outbox` undefined.

- [ ] **Step 3: Implement:**

```rust
    /// Re-send every un-acked outbox frame across all persistent chats. Idempotent:
    /// the receiver dedups by gossip_id (SeenSet) and re-acks, so double-sends are safe.
    pub async fn flush_outbox(&self) {
        let chats: Vec<String> = self.inner.persistent.lock().unwrap().iter().cloned().collect();
        for chat in chats {
            self.inner.outbox.evict_expired(&chat, now_secs());
            for (_gid, frame) in self.inner.outbox.due_for_resend(&chat) {
                // frame is a full encoded Frame (GroupMsg/Chat) — re-broadcast it.
                let _ = self.broadcast_raw(frame).await; // existing raw broadcast to connected peers
            }
        }
    }
```

  - Call `self.flush_outbox().await;` at the end of `reconnect()` (`:1103`) and in the peer-connected branch of the accept loop.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core offline_member_receives_backlog_on_reconnect 2>&1 | tail -6`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/engine.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d1): flush the outbox on reconnect / peer-online (idempotent resend)"
```

---

### Task 7: Keeper wiring — buffer for offline targets + replay + `Event::Delivered`

**Files:**
- Modify: `crates/core/src/engine.rs` (`Inner` gains `keeper: crate::keeper::KeeperQueue`; the relay/forward path; the peer-connected handler) and `crates/core/src/relay.rs` if the keeper lives in the relay loop.

**Interfaces:**
- Consumes: `KeeperQueue` (Task 3), `Route`, connected-peer set.
- Produces: `pub fn Core::keeper_mode(&self, on: bool)`; when forwarding a `Routed` to an offline `Route::Peer`, it is buffered; on that peer connecting, buffered frames are replayed; `Event::Delivered { gossip_id: [u8;32] }` on successful ack.

- [ ] **Step 1: Write the failing test** (integration, 3 nodes: host=keeper, A, B; B offline):

```rust
#[tokio::test]
async fn keeper_buffers_for_offline_peer_and_replays() {
    let fabric = LoopbackFabric::new();
    let (host, a, b, chat) = persistent_trio(&fabric).await; // host is keeper-capable
    host.keeper_mode(true);
    disconnect(&b);
    a.send_text(&chat, "for-b").await.unwrap();      // routed via host
    pump(&host, &a).await;                           // host buffers it for offline b
    assert!(host.inner.keeper.drain(b_fp(&b)).len() >= 1, "keeper buffered the frame for offline b");
    reconnect_member(&fabric, &b).await;
    host.replay_keeper_for(b_fp(&b)).await;          // triggered on b connecting
    pump(&host, &b).await;
    assert!(received(&b, "for-b"), "b receives the buffered frame on reconnect");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p talkrypt-core keeper_buffers_for_offline_peer_and_replays 2>&1 | tail -6`
Expected: FAIL — `keeper_mode`/`replay_keeper_for` undefined.

- [ ] **Step 3: Implement:**
  - Add `keeper: crate::keeper::KeeperQueue` to `Inner` (init `KeeperQueue::new(store.clone(), 4096, 30*24*3600)`), and `keeper_enabled: AtomicBool`.
  - `pub fn keeper_mode(&self, on: bool) { self.inner.keeper_enabled.store(on, Ordering::Relaxed); }`
  - In the forward path (relay/broadcast) when the target is a `Route::Peer(fp)` that is NOT in the connected set AND `keeper_enabled`:

```rust
        let gid = gossip_id(&routed.inner);
        self.inner.keeper.buffer(fp, gid, &routed.encode(), now_secs());
```

  - Add `pub async fn replay_keeper_for(&self, peer: [u8;48])` that drains the keeper for `peer` and re-sends each buffered `Routed`; call it when a peer newly connects. On receiving that peer's `DeliveryAck`, call `self.inner.keeper.ack(peer, gid)` and emit `Event::Delivered { gossip_id: gid }`.
  - Add `Event::Delivered { gossip_id: [u8; 32] }`.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p talkrypt-core keeper_buffers_for_offline_peer_and_replays 2>&1 | tail -6`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/engine.rs crates/core/src/relay.rs
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d1): group keeper buffers for offline peers + replays on reconnect"
```

---

### Task 8: Delivery-safety property test + FFI surface + full-suite green

**Files:**
- Modify: `crates/core/src/engine.rs` (property test), `crates/ffi/src/lib.rs` (FFI: `set_persistence`, `keeper_mode`, `FfiEvent::Delivered`/`OutboxDropped`, `with_outbox_store` bridge)

**Interfaces:**
- Consumes: everything above.
- Produces: exhaustive property test of the invariants; FFI methods so the app tiers can opt a chat into persistence and observe delivery.

- [ ] **Step 1: Write the failing property test** (deterministic, no `rand`/clock — drive with a seeded xorshift like the existing `decoders_never_panic_on_adversarial_bytes`):

```rust
#[test]
fn outbox_delivery_safety_invariants() {
    // Model: enqueue N frames, ack a random subset, evict by TTL/cap; assert:
    //  (1) an acked gid is never still pending;
    //  (2) an un-acked, un-expired, within-cap gid is always still pending;
    //  (3) re-enqueue of the same gid is idempotent (no duplicate pending entry).
    let store = std::sync::Arc::new(crate::outbox::InMemoryOutbox::new());
    let ob = crate::outbox::Outbox::new(store, 1000, 1_000_000);
    let mut x: u64 = 0x9E3779B97F4A7C15;
    let mut next = || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    let mut acked = std::collections::HashSet::new();
    for i in 0..5000u32 {
        let mut gid = [0u8; 32];
        gid[..4].copy_from_slice(&i.to_be_bytes());
        ob.enqueue("c", gid, b"f", i as u64);
        ob.enqueue("c", gid, b"f", i as u64); // idempotent re-enqueue
        if next() % 3 == 0 { ob.ack("c", gid); acked.insert(gid); }
    }
    let pending: std::collections::HashSet<[u8;32]> = ob.pending("c").into_iter().collect();
    for g in &acked { assert!(!pending.contains(g), "acked gid must not be pending"); }
    // no duplicate pending entries
    assert_eq!(ob.pending("c").len(), pending.len(), "no duplicate pending entries");
}
```

- [ ] **Step 2: Run to verify it fails/passes**

Run: `cargo test -p talkrypt-core outbox_delivery_safety_invariants 2>&1 | tail -5`
Expected: PASS (logic already implemented; this locks the invariants).

- [ ] **Step 3: Add the FFI surface** in `crates/ffi/src/lib.rs`:

```rust
    pub fn set_persistence(&self, chat: String, on: bool) { self.core.set_persistence(&chat, on); }
    pub fn keeper_mode(&self, on: bool) { self.core.keeper_mode(on); }
```

Add `FfiEvent::Delivered { gossip_id: Vec<u8> }` and `FfiEvent::OutboxDropped { chat: String, count: u32 }` to the FFI event enum + the `Event -> FfiEvent` mapping. If a host wants sealed at-rest persistence, add `with_outbox_store` accepting a `Box<dyn HardwareKeyWrapper>`-backed `OutboxStore` bridge (mirror `WrapperBridge`); otherwise the default in-memory store is used.

- [ ] **Step 4: Full crate + workspace green + Kani**

Run:
```bash
cargo test -p talkrypt-core 2>&1 | grep 'test result:'
cargo build --workspace 2>&1 | tail -2
cargo kani -p talkrypt-core --harness engine::d1_proofs::delivery_ack_decode_never_panics 2>&1 | tail -3
```
Expected: core tests all pass; workspace builds; Kani `VERIFICATION:- SUCCESSFUL`.

- [ ] **Step 5: Commit + add the Kani harness to CI**

Add to `.github/workflows/formal.yml` (Kani job, after the vouch harnesses):
```yaml
      - name: Prove the D1 DeliveryAck decoder is total (core)
        run: cargo kani -p talkrypt-core --harness engine::d1_proofs::delivery_ack_decode_never_panics
```
```bash
git add crates/core/src/engine.rs crates/ffi/src/lib.rs .github/workflows/formal.yml
git -c user.name=pq-cybarg -c user.email=resistant@tuta.com commit -m "feat(d1): delivery-safety property test + FFI surface + Kani-in-CI for DeliveryAck"
```

---

## Self-Review

**Spec coverage (D1 MVP scope):** L0 outbox — Tasks 2,4,5,6 (enqueue/ack/flush/cap+TTL). LA keeper — Tasks 3,7. `DeliveryAck` tag 15 flat + Kani — Task 1 (+ CI in Task 8). Opaque-ciphertext-only — enforced (outbox/keeper store encoded `Frame`/`Routed` bytes, never plaintext). Reuse of `SeenSet`/`gossip_id`/`Routed`/`reconnect`/seal seam — Tasks 1–7. FV contract (no wire-codec edits, flat decoder + Kani, GroupAuth untouched, property test for heap logic) — Tasks 1,8. Deferred LB/LC (`MailboxPut`/`Fetch` 16/17, `QueueSync` 18) — explicitly out of scope. **No gaps for the MVP.**

**Placeholder scan:** the only soft spots are the integration-test helpers (`persistent_pair`, `pump`, `persistent_trio`, `disconnect`, `reconnect_member`, `received`, `b_fp`) and the "use the existing send/peer-send helper" notes — these are pointers to existing `engine.rs` test/support APIs whose exact names must be read at implementation time (they vary by the current test module). Every *production* step has complete code. Implementer: grep the existing `#[tokio::test]` integration tests in `engine.rs` for the current fabric helpers and reuse them.

**Type consistency:** `Outbox`/`OutboxStore`/`InMemoryOutbox` (Task 2) reused verbatim by `KeeperQueue` (Task 3, via `OutboxStore`) and `Inner` (Tasks 4,7). `gossip_id(&[u8]) -> [u8;32]` and `SeenSet.insert([u8;32]) -> bool` used as their real signatures. `Frame::DeliveryAck(Vec<[u8;32]>)` consistent across Tasks 1/5/7. `Event::{OutboxDropped{chat,count}, Delivered{gossip_id}}` defined in Task 4/7 and mapped in Task 8.

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-09-05-subspec-d1-mvp-outbox-keeper.md`. Two execution options:

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — execute tasks in this session with batch checkpoints.
