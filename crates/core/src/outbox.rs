//! Persistent-outbox bookkeeping for D1 store-and-forward. Core owns the in-memory
//! index + cap/TTL; at-rest persistence is delegated to a host-injected `OutboxStore`
//! (mirroring `crate::seal::KeyWrapper`), so core stays platform-agnostic. Stored
//! frames are OPAQUE (already-encoded `Frame`/`Routed` bytes) — no plaintext at rest.

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
        self.inner
            .lock()
            .unwrap()
            .entry(chat.to_string())
            .or_default()
            .insert(gid, frame.to_vec());
    }
    fn remove(&self, chat: &str, gid: [u8; 32]) {
        if let Some(m) = self.inner.lock().unwrap().get_mut(chat) {
            m.remove(&gid);
        }
    }
    fn load(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        self.inner
            .lock()
            .unwrap()
            .get(chat)
            .map(|m| m.iter().map(|(k, v)| (*k, v.clone())).collect())
            .unwrap_or_default()
    }
}

/// The outbox: an in-memory index of un-acked frames (gid -> enqueued-at secs),
/// backed by an `OutboxStore` for at-rest persistence. Cap + TTL bounded.
pub struct Outbox {
    /// At-rest backend. Mutex-wrapped so a host can swap the in-memory default for a
    /// sealed-file store after construction (see [`Outbox::set_store`]).
    store: Mutex<Arc<dyn OutboxStore>>,
    /// chat -> [(gid, enqueued_at_secs)], insertion order kept for cap eviction.
    meta: Mutex<HashMap<String, Vec<([u8; 32], u64)>>>,
    cap: usize,
    ttl_secs: u64,
}

impl Outbox {
    pub fn new(store: Arc<dyn OutboxStore>, cap: usize, ttl_secs: u64) -> Self {
        Self { store: Mutex::new(store), meta: Mutex::new(HashMap::new()), cap, ttl_secs }
    }

    /// Snapshot the current backend (clone the Arc so store I/O runs without holding the lock).
    fn store(&self) -> Arc<dyn OutboxStore> {
        self.store.lock().unwrap().clone()
    }

    /// SUB-SPEC D at-rest: swap in a host-provided [`OutboxStore`] (e.g. a sealed file).
    /// Does NOT rehydrate — the caller then calls [`Outbox::rehydrate`] for its chat, since
    /// only the owning `Core` knows which chat this outbox serves.
    pub fn set_store(&self, store: Arc<dyn OutboxStore>) {
        *self.store.lock().unwrap() = store;
    }

    /// SUB-SPEC D at-rest (restart survival): repopulate the in-memory index for `chat` from
    /// whatever the backing store already holds, so cap/TTL/flush operate after a restart.
    /// Rehydrated entries are stamped `now_secs` (the pre-restart enqueue time isn't persisted;
    /// the TTL is a generous backstop, so resetting it on restart is acceptable). Idempotent.
    pub fn rehydrate(&self, chat: &str, now_secs: u64) {
        let persisted = self.store().load(chat);
        let mut meta = self.meta.lock().unwrap();
        let v = meta.entry(chat.to_string()).or_default();
        for (gid, _frame) in persisted {
            if !v.iter().any(|(g, _)| *g == gid) {
                v.push((gid, now_secs));
            }
        }
    }

    /// Persist a frame and index it. Returns the number of oldest frames evicted to
    /// stay within `cap` (0 normally). Re-enqueue of the same gid is idempotent.
    pub fn enqueue(&self, chat: &str, gid: [u8; 32], frame: &[u8], now_secs: u64) -> usize {
        let store = self.store();
        store.put(chat, gid, frame);
        let mut meta = self.meta.lock().unwrap();
        let v = meta.entry(chat.to_string()).or_default();
        if !v.iter().any(|(g, _)| *g == gid) {
            v.push((gid, now_secs));
        }
        let mut dropped = 0;
        while v.len() > self.cap {
            let (old, _) = v.remove(0);
            store.remove(chat, old);
            dropped += 1;
        }
        dropped
    }

    /// Clear a delivered frame.
    pub fn ack(&self, chat: &str, gid: [u8; 32]) {
        self.store().remove(chat, gid);
        if let Some(v) = self.meta.lock().unwrap().get_mut(chat) {
            v.retain(|(g, _)| *g != gid);
        }
    }

    /// The gids still pending for a chat (insertion order).
    pub fn pending(&self, chat: &str) -> Vec<[u8; 32]> {
        self.meta
            .lock()
            .unwrap()
            .get(chat)
            .map(|v| v.iter().map(|(g, _)| *g).collect())
            .unwrap_or_default()
    }

    /// (gid, sealed frame) still pending, for resend on reconnect.
    pub fn due_for_resend(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        self.store().load(chat)
    }

    /// Evict frames older than the TTL. Returns how many were evicted.
    pub fn evict_expired(&self, chat: &str, now_secs: u64) -> usize {
        let mut meta = self.meta.lock().unwrap();
        let Some(v) = meta.get_mut(chat) else {
            return 0;
        };
        let ttl = self.ttl_secs;
        let expired: Vec<[u8; 32]> = v
            .iter()
            .filter(|(_, t)| now_secs.saturating_sub(*t) > ttl)
            .map(|(g, _)| *g)
            .collect();
        let store = self.store.lock().unwrap().clone();
        for g in &expired {
            store.remove(chat, *g);
        }
        v.retain(|(_, t)| now_secs.saturating_sub(*t) <= ttl);
        expired.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// SUB-SPEC D at-rest: an un-acked frame written to a sealed store by one run is
    /// recovered by a fresh Outbox on the next run via `rehydrate` — restart survival.
    #[test]
    fn rehydrate_recovers_unacked_frames_from_sealed_store() {
        use crate::atrest::SealedFileStore;
        let mut n = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
        let dir = std::env::temp_dir().join(format!(
            "tk-ob-restart-{}",
            n.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let chat = "#restart";
        let gid = [5u8; 32];
        // Pre-restart: enqueue into a sealed-file-backed outbox.
        {
            let store = Arc::new(SealedFileStore::open(&dir, Some(b"pw"), None).unwrap());
            let ob = Outbox::new(store, 16, 3600);
            ob.enqueue(chat, gid, b"opaque-frame", 100);
            assert_eq!(ob.pending(chat), vec![gid]);
        }
        // Restart: a fresh Outbox over the SAME sealed store starts empty, then rehydrates.
        {
            let store = Arc::new(SealedFileStore::open(&dir, Some(b"pw"), None).unwrap());
            let ob = Outbox::new(store, 16, 3600);
            assert!(ob.pending(chat).is_empty(), "fresh in-memory index is empty");
            ob.rehydrate(chat, 200);
            assert_eq!(ob.pending(chat), vec![gid], "rehydrate recovers the un-acked frame");
            assert_eq!(ob.due_for_resend(chat).len(), 1, "frame bytes are available to resend");
            // Rehydrate is idempotent.
            ob.rehydrate(chat, 300);
            assert_eq!(ob.pending(chat), vec![gid]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reenqueue_same_gid_is_idempotent() {
        let store = Arc::new(InMemoryOutbox::new());
        let ob = Outbox::new(store, 16, 3600);
        ob.enqueue("c", [1u8; 32], b"a", 1);
        ob.enqueue("c", [1u8; 32], b"a", 2);
        assert_eq!(ob.pending("c").len(), 1, "no duplicate pending entry");
    }

    /// Exhaustive delivery-safety invariants over 5000 seeded operations (the heap
    /// queue logic is CBMC-intractable, so this is the FV-parity property test): an
    /// acked gid is never still pending; re-enqueue is idempotent (no duplicate
    /// pending entry); `pending` has no duplicates. Deterministic xorshift (no clock
    /// / no rand) so it is reproducible in CI.
    #[test]
    fn outbox_delivery_safety_invariants() {
        let store = Arc::new(InMemoryOutbox::new());
        let ob = Outbox::new(store, 100_000, 1_000_000);
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut acked = std::collections::HashSet::new();
        for i in 0..5000u32 {
            let mut gid = [0u8; 32];
            gid[..4].copy_from_slice(&i.to_be_bytes());
            ob.enqueue("c", gid, b"f", i as u64);
            ob.enqueue("c", gid, b"f", i as u64); // idempotent re-enqueue
            if next() % 3 == 0 {
                ob.ack("c", gid);
                acked.insert(gid);
            }
        }
        let pending: Vec<[u8; 32]> = ob.pending("c");
        let pending_set: std::collections::HashSet<[u8; 32]> = pending.iter().copied().collect();
        for g in &acked {
            assert!(!pending_set.contains(g), "an acked gid must never still be pending");
        }
        assert_eq!(pending.len(), pending_set.len(), "no duplicate pending entries");
    }
}
