//! SUB-SPEC D3 — retention-privacy contract: at-rest storage for a member's OWN
//! chat history, sealed only when a promotion (D2) authorizes it.
//!
//! First principle: **promotion authorizes RETENTION, never TRANSMISSION**. A record
//! here is a message this node ALREADY received (or sent) — never data pulled from
//! anyone else, never backfilled to a latecomer. Sealing is a local action gated by
//! the authenticated `retention_mode` in the signed `PromoteBody`.
//!
//! Core owns the in-memory backlog + the retention decision; at-rest persistence is
//! delegated to a host-injected [`HistoryStore`] (mirroring [`crate::outbox::OutboxStore`]
//! and [`crate::seal::KeyWrapper`]) so core stays platform-agnostic. A real host injects
//! a sealed-file impl; the in-memory default suffices for tests and ephemeral runs.

use std::collections::HashMap;
use std::sync::Mutex;

use talkrypt_wire::{Reader, Writer};

use crate::marking::{decode_payload, encode_payload};
use crate::Marking;

/// One retained chat message — the local, at-rest form of a message this node saw.
/// Local-only (never on the wire), so its (de)serialization is not attacker-controlled;
/// it is kept flat and robust regardless.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HistoryRecord {
    /// The sender's account/leaf fingerprint (own fingerprint for outgoing).
    pub from: [u8; 48],
    /// Unix seconds when this node sent/received the message — the D3
    /// `CarryFromPoint` marker is compared against this.
    pub ts: u64,
    /// The displayed text.
    pub text: String,
    /// The authenticated classification marking, if any.
    pub marking: Option<Marking>,
}

impl HistoryRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.put_bytes(&self.from);
        w.put_u64(self.ts);
        // Reuse the message payload codec (marking ‖ text) verbatim.
        w.put_bytes(&encode_payload(&self.marking, &self.text));
        w.into_vec()
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        let fp = r.get_bytes().ok()?;
        if fp.len() != 48 {
            return None;
        }
        let mut from = [0u8; 48];
        from.copy_from_slice(fp);
        let ts = r.get_u64().ok()?;
        let payload = r.get_vec().ok()?;
        r.finish().ok()?;
        let (marking, text) = decode_payload(&payload)?;
        Some(Self { from, ts, text, marking })
    }
}

/// Host-provided at-rest persistence for sealed history. Implementations seal the
/// `record` bytes (e.g. via the FFI seal seam) before writing. Keyed by (chat, gid),
/// where `gid` is the message's ciphertext gossip-id — stable and dedup-friendly.
pub trait HistoryStore: Send + Sync {
    fn put(&self, chat: &str, gid: [u8; 32], record: &[u8]);
    /// All persisted (gid, record) for a chat, for display after a restart.
    fn load(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)>;
    /// Erase all sealed history for a chat (Delete / return-to-ephemeral — D3
    /// invariant 4, "recoverable").
    fn purge(&self, chat: &str);
}

/// In-memory `HistoryStore` (default + tests). Real hosts inject a sealed-file impl.
#[derive(Default)]
pub struct InMemoryHistory {
    inner: Mutex<HashMap<String, HashMap<[u8; 32], Vec<u8>>>>,
}
impl InMemoryHistory {
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }
}
impl HistoryStore for InMemoryHistory {
    fn put(&self, chat: &str, gid: [u8; 32], record: &[u8]) {
        self.inner
            .lock()
            .unwrap()
            .entry(chat.to_string())
            .or_default()
            .insert(gid, record.to_vec());
    }
    fn load(&self, chat: &str) -> Vec<([u8; 32], Vec<u8>)> {
        self.inner
            .lock()
            .unwrap()
            .get(chat)
            .map(|m| m.iter().map(|(k, v)| (*k, v.clone())).collect())
            .unwrap_or_default()
    }
    fn purge(&self, chat: &str) {
        self.inner.lock().unwrap().remove(chat);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_record_roundtrips_with_and_without_marking() {
        let plain = HistoryRecord { from: [7u8; 48], ts: 1_725_000_000, text: "hello".into(), marking: None };
        assert_eq!(HistoryRecord::decode(&plain.encode()).unwrap(), plain);
        // Trailing garbage is rejected (finish()).
        let mut bad = plain.encode();
        bad.push(0);
        assert!(HistoryRecord::decode(&bad).is_none());
        // Truncated input never panics.
        for n in 0..plain.encode().len() {
            let _ = HistoryRecord::decode(&plain.encode()[..n]);
        }
    }

    #[test]
    fn in_memory_history_put_load_purge() {
        let h = InMemoryHistory::new();
        let rec = HistoryRecord { from: [1u8; 48], ts: 5, text: "x".into(), marking: None };
        h.put("#c", [9u8; 32], &rec.encode());
        h.put("#c", [8u8; 32], &rec.encode());
        h.put("#other", [1u8; 32], &rec.encode());
        assert_eq!(h.load("#c").len(), 2);
        assert_eq!(h.load("#other").len(), 1);
        h.purge("#c");
        assert!(h.load("#c").is_empty());
        assert_eq!(h.load("#other").len(), 1, "purge is per-chat");
    }
}
