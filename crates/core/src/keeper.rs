//! Layer-A group keeper: an online member buffers OPAQUE (already-encrypted) frames
//! addressed to a currently-offline peer and replays them when that peer reconnects.
//! Holds ciphertext only (no group key). Reuses `OutboxStore` for at-rest persistence,
//! keyed by the recipient fingerprint (hex) as the store "chat" key.

use crate::outbox::OutboxStore;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

fn key(recipient: &[u8; 48]) -> String {
    let mut s = String::with_capacity(96);
    for b in recipient {
        let _ = write!(s, "{b:02x}");
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
        let Some(v) = idx.get_mut(&recipient) else {
            return 0;
        };
        let ttl = self.ttl_secs;
        let expired: Vec<[u8; 32]> = v
            .iter()
            .filter(|(_, t)| now_secs.saturating_sub(*t) > ttl)
            .map(|(g, _)| *g)
            .collect();
        for g in &expired {
            self.store.remove(&key(&recipient), *g);
        }
        v.retain(|(_, t)| now_secs.saturating_sub(*t) <= ttl);
        expired.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbox::InMemoryOutbox;

    #[test]
    fn buffers_for_offline_peer_then_drains() {
        let store = Arc::new(InMemoryOutbox::new());
        let kq = KeeperQueue::new(store, 8, 3600);
        let bob = [9u8; 48];
        kq.buffer(bob, [1u8; 32], b"opaque-frame", 10);
        kq.buffer(bob, [2u8; 32], b"opaque-frame-2", 11);
        let drained = kq.drain(bob);
        assert_eq!(drained.len(), 2, "both buffered frames replayed on drain");
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
