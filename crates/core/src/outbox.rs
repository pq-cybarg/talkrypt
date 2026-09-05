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
    store: Arc<dyn OutboxStore>,
    /// chat -> [(gid, enqueued_at_secs)], insertion order kept for cap eviction.
    meta: Mutex<HashMap<String, Vec<([u8; 32], u64)>>>,
    cap: usize,
    ttl_secs: u64,
}

impl Outbox {
    pub fn new(store: Arc<dyn OutboxStore>, cap: usize, ttl_secs: u64) -> Self {
        Self { store, meta: Mutex::new(HashMap::new()), cap, ttl_secs }
    }

    /// Persist a frame and index it. Returns the number of oldest frames evicted to
    /// stay within `cap` (0 normally). Re-enqueue of the same gid is idempotent.
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
        self.meta
            .lock()
            .unwrap()
            .get(chat)
            .map(|v| v.iter().map(|(g, _)| *g).collect())
            .unwrap_or_default()
    }

    /// (gid, sealed frame) still pending, for resend on reconnect.
    pub fn due_for_resend(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        self.store.load(chat)
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
        for g in &expired {
            self.store.remove(chat, *g);
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

    #[test]
    fn reenqueue_same_gid_is_idempotent() {
        let store = Arc::new(InMemoryOutbox::new());
        let ob = Outbox::new(store, 16, 3600);
        ob.enqueue("c", [1u8; 32], b"a", 1);
        ob.enqueue("c", [1u8; 32], b"a", 2);
        assert_eq!(ob.pending("c").len(), 1, "no duplicate pending entry");
    }
}
