//! Mesh (LoRa) fragmentation + reassembly for talkrypt-over-mesh.
//!
//! A LoRa mesh packet carries only ~200-240 usable application bytes, but a
//! talkrypt sealed frame (a CQ beacon is a few hundred bytes; a handshake frame
//! is multi-KB) does not fit in one. This module splits a sealed blob across N
//! mesh packets with a small, flat, self-describing header and reassembles it on
//! the far side.
//!
//! The header decoder ([`parse_fragment`]) is deliberately FLAT and bounded — no
//! nested / length-prefixed heap fields — so it is a straight-line, Kani-provable
//! parse (mirroring the `talkrypt_wire` decoder convention). The [`Reassembler`]
//! is runtime-only (a bounded `HashMap` of partial messages — nested heap, not a
//! Kani target), with hard caps so a flood of partial fragments cannot exhaust
//! memory.
//!
//! Wire (fixed 10-byte header, then the chunk):
//! ```text
//! byte 0     MAGIC0 = 0xA7          two-byte magic marks a talkrypt fragment
//! byte 1     MAGIC1 = 0x6D ('m')     apart from arbitrary foreign mesh bytes
//! byte 2     version = 1
//! byte 3     kind                   0 = Advert (beacon CQ), 1 = Frame (chat message)
//! bytes 4-5  msg_id      (u16 BE)    per-sender rolling id grouping one message
//! bytes 6-7  frag_index  (u16 BE)    0-based
//! bytes 8-9  frag_count  (u16 BE)    total fragments (>=1); index < count
//! bytes 10.. chunk                   payload slice (<= mtu - 10)
//! ```
//!
//! Byte 3 is the `kind` discriminator so a beacon advert and a chat-message frame
//! can share one mesh channel + magic without cross-feeding each other's
//! reassembly. It was the reserved `flags` byte (always 0), so existing beacon
//! fragments are already [`KIND_ADVERT`] — backward-compatible on the wire. Unknown
//! `kind` values parse fine and are simply filtered out by a kind-scoped
//! [`Reassembler`], leaving room for future kinds.

use std::collections::HashMap;

/// Talkrypt-over-mesh magic (byte 0, byte 1). Two bytes so random foreign mesh
/// text is overwhelmingly unlikely to be misclassified as a talkrypt fragment.
pub const MAGIC0: u8 = 0xA7;
pub const MAGIC1: u8 = 0x6D; // 'm'
/// Fragment wire-format version.
pub const FRAG_VERSION: u8 = 1;
/// Fixed header length that precedes every fragment's chunk.
pub const HEADER_LEN: usize = 10;

/// Fragment `kind` (header byte 3): a pre-session presence beacon (CQ) blob.
pub const KIND_ADVERT: u8 = 0;
/// Fragment `kind` (header byte 3): a chat-message `Frame` (mesh messaging).
pub const KIND_FRAME: u8 = 1;

/// The smallest MTU we will fragment for: must leave at least one payload byte
/// after the header. Real LoRa MTUs (~184-240) are far above this.
pub const MIN_MTU: usize = HEADER_LEN + 1;

/// A talkrypt frame that would need more than this many fragments does not belong
/// on a LoRa mesh (it would take minutes and dominate airtime). Rejected at
/// encode; caps reassembly work per message. `u16` frag fields allow up to 65535,
/// but we bound well below that.
pub const MAX_FRAGMENTS: usize = 256;

/// A parsed fragment header plus the byte range of its chunk within the input.
/// Flat (all scalars + a range) so [`parse_fragment`] is a bounded, panic-free
/// decode with no nested allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fragment<'a> {
    pub kind: u8,
    pub msg_id: u16,
    pub frag_index: u16,
    pub frag_count: u16,
    pub chunk: &'a [u8],
}

/// Parse one mesh packet as a talkrypt fragment. Returns `None` for anything that
/// is not a well-formed talkrypt fragment (wrong/short magic, bad version, or an
/// inconsistent index/count) so foreign mesh bytes classify cleanly rather than
/// crashing. FLAT + bounded: only fixed-offset reads guarded by a single length
/// check, so it never indexes out of bounds.
pub fn parse_fragment(packet: &[u8]) -> Option<Fragment<'_>> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    if packet[0] != MAGIC0 || packet[1] != MAGIC1 || packet[2] != FRAG_VERSION {
        return None;
    }
    let kind = packet[3]; // 0 = Advert, 1 = Frame; unknown kinds tolerated (filtered later).
    let msg_id = u16::from_be_bytes([packet[4], packet[5]]);
    let frag_index = u16::from_be_bytes([packet[6], packet[7]]);
    let frag_count = u16::from_be_bytes([packet[8], packet[9]]);
    // A count of zero, or an index at/beyond the count, is malformed.
    if frag_count == 0 || frag_index >= frag_count {
        return None;
    }
    Some(Fragment {
        kind,
        msg_id,
        frag_index,
        frag_count,
        chunk: &packet[HEADER_LEN..],
    })
}

/// Split a sealed `payload` into mesh fragments of the given `kind`
/// ([`KIND_ADVERT`] / [`KIND_FRAME`]) for the given `mtu` (bytes usable per
/// packet). Returns one `Vec<u8>` per fragment, each header-prefixed and
/// `<= mtu`. `msg_id` groups this message's fragments (the caller rolls it per
/// send). Returns `None` if `mtu` is too small, the payload is empty, or it would
/// need more than [`MAX_FRAGMENTS`] fragments.
pub fn fragment(kind: u8, msg_id: u16, payload: &[u8], mtu: usize) -> Option<Vec<Vec<u8>>> {
    if mtu < MIN_MTU || payload.is_empty() {
        return None;
    }
    let chunk_size = mtu - HEADER_LEN;
    let count = payload.len().div_ceil(chunk_size);
    if count == 0 || count > MAX_FRAGMENTS {
        return None;
    }
    let frag_count = count as u16;
    let mut out = Vec::with_capacity(count);
    for (i, chunk) in payload.chunks(chunk_size).enumerate() {
        let mut pkt = Vec::with_capacity(HEADER_LEN + chunk.len());
        pkt.push(MAGIC0);
        pkt.push(MAGIC1);
        pkt.push(FRAG_VERSION);
        pkt.push(kind);
        pkt.extend_from_slice(&msg_id.to_be_bytes());
        pkt.extend_from_slice(&(i as u16).to_be_bytes());
        pkt.extend_from_slice(&frag_count.to_be_bytes());
        pkt.extend_from_slice(chunk);
        out.push(pkt);
    }
    Some(out)
}

/// A single message being reassembled: its fragment count, the chunks received so
/// far (indexed), and how many distinct indices have arrived.
struct Partial {
    frag_count: u16,
    chunks: Vec<Option<Vec<u8>>>,
    have: usize,
    bytes: usize,
}

/// Bounded reassembly of talkrypt-over-mesh fragments, keyed by
/// `(source, msg_id, kind)`.
///
/// Including `kind` in the key means an Advert and a Frame from the same source
/// that happen to share a `msg_id` (the two carries roll independent counters)
/// never collide. An optional [`Reassembler::for_kind`] filter additionally drops
/// fragments of other kinds up front, so a carry only spends memory on its own
/// traffic.
///
/// Hard caps (anti-DoS): at most [`Reassembler::max_messages`] partial messages in
/// flight and [`Reassembler::max_bytes`] buffered across all of them; the oldest
/// partial is evicted when a cap is hit. A message whose fragments disagree on
/// `frag_count` is dropped. Runtime-only — NOT a Kani target (nested heap); the
/// per-fragment decode it consumes ([`parse_fragment`]) is the proven part.
pub struct Reassembler {
    partials: HashMap<(String, u16, u8), Partial>,
    /// Insertion order of keys, for oldest-first eviction.
    order: Vec<(String, u16, u8)>,
    /// If set, only fragments of this `kind` are accepted (others are ignored).
    only_kind: Option<u8>,
    max_messages: usize,
    max_bytes: usize,
    buffered: usize,
}

impl Default for Reassembler {
    fn default() -> Self {
        // Defaults sized for a handful of concurrent multi-KB frames on a slow
        // link: 32 in-flight messages, 1 MiB total buffered. Accepts any kind.
        Self::with_limits(32, 1024 * 1024)
    }
}

impl Reassembler {
    pub fn with_limits(max_messages: usize, max_bytes: usize) -> Self {
        Self {
            partials: HashMap::new(),
            order: Vec::new(),
            only_kind: None,
            max_messages: max_messages.max(1),
            max_bytes: max_bytes.max(1),
            buffered: 0,
        }
    }

    /// A reassembler that only accepts fragments of `kind` ([`KIND_ADVERT`] /
    /// [`KIND_FRAME`]) — so a beacon carry and a messaging carry can share one mesh
    /// channel and each ignore the other's fragments.
    pub fn for_kind(kind: u8) -> Self {
        let mut r = Self::default();
        r.only_kind = Some(kind);
        r
    }

    /// Feed one raw mesh packet from `source`. Returns `Some(reassembled)` when a
    /// packet completes a message, else `None`. Non-fragment (foreign) packets,
    /// malformed fragments, and (if a kind filter is set) other-kind fragments
    /// return `None` without disturbing state.
    pub fn accept(&mut self, source: &str, packet: &[u8]) -> Option<Vec<u8>> {
        let frag = parse_fragment(packet)?;
        if let Some(want) = self.only_kind {
            if frag.kind != want {
                return None;
            }
        }
        let key = (source.to_string(), frag.msg_id, frag.kind);
        let idx = frag.frag_index as usize;
        let count = frag.frag_count as usize;

        // Fetch or create the partial slot, evicting oldest if we would exceed caps.
        if !self.partials.contains_key(&key) {
            self.evict_if_needed(frag.chunk.len());
            self.partials.insert(
                key.clone(),
                Partial {
                    frag_count: frag.frag_count,
                    chunks: vec![None; count],
                    have: 0,
                    bytes: 0,
                },
            );
            self.order.push(key.clone());
        }

        let done = {
            let p = self.partials.get_mut(&key)?;
            // Reject a fragment that disagrees with the established count for this key.
            if p.frag_count != frag.frag_count || idx >= p.chunks.len() {
                return None;
            }
            if p.chunks[idx].is_none() {
                p.chunks[idx] = Some(frag.chunk.to_vec());
                p.have += 1;
                p.bytes += frag.chunk.len();
                self.buffered += frag.chunk.len();
            }
            p.have == p.frag_count as usize
        };

        if done {
            let p = self.partials.remove(&key).unwrap();
            self.order.retain(|k| k != &key);
            self.buffered = self.buffered.saturating_sub(p.bytes);
            let mut out = Vec::with_capacity(p.bytes);
            for chunk in p.chunks.into_iter() {
                out.extend_from_slice(&chunk.unwrap_or_default());
            }
            Some(out)
        } else {
            None
        }
    }

    /// Evict oldest partials until there is room for `incoming` more bytes and one
    /// more message.
    fn evict_if_needed(&mut self, incoming: usize) {
        while (self.partials.len() >= self.max_messages
            || self.buffered + incoming > self.max_bytes)
            && !self.order.is_empty()
        {
            let oldest = self.order.remove(0);
            if let Some(p) = self.partials.remove(&oldest) {
                self.buffered = self.buffered.saturating_sub(p.bytes);
            }
        }
    }

    /// Number of messages currently being reassembled (for tests / metrics).
    pub fn in_flight(&self) -> usize {
        self.partials.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reassemble_all(msg_id: u16, payload: &[u8], mtu: usize) -> Vec<u8> {
        let frags = fragment(KIND_FRAME, msg_id, payload, mtu).expect("fragmentable");
        let mut r = Reassembler::default();
        let mut done = None;
        for f in &frags {
            if let Some(out) = r.accept("peer", f) {
                done = Some(out);
            }
        }
        done.expect("reassembled")
    }

    #[test]
    fn single_fragment_round_trips() {
        let payload = b"CQ CQ short beacon";
        let frags = fragment(KIND_FRAME, 7, payload, 240).unwrap();
        assert_eq!(frags.len(), 1);
        assert_eq!(reassemble_all(7, payload, 240), payload);
    }

    #[test]
    fn multi_fragment_round_trips_across_small_mtu() {
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let mtu = 64;
        let frags = fragment(KIND_FRAME, 1, &payload, mtu).unwrap();
        assert!(frags.len() > 40, "3000B over MTU 64 needs many fragments");
        for f in &frags {
            assert!(f.len() <= mtu, "no fragment exceeds the MTU");
        }
        assert_eq!(reassemble_all(1, &payload, mtu), payload);
    }

    #[test]
    fn boundary_sizes_exact_and_plus_one() {
        let mtu = 50;
        let chunk = mtu - HEADER_LEN; // 40
        for len in [chunk, chunk + 1, chunk * 2, chunk * 2 + 1] {
            let payload: Vec<u8> = (0..len as u32).map(|i| i as u8).collect();
            assert_eq!(reassemble_all(9, &payload, mtu), payload, "len={len}");
        }
    }

    #[test]
    fn out_of_order_reassembly() {
        let payload: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let mut frags = fragment(KIND_FRAME, 3, &payload, 64).unwrap();
        frags.reverse(); // deliver last-to-first
        let mut r = Reassembler::default();
        let mut done = None;
        for f in &frags {
            if let Some(out) = r.accept("peer", f) {
                done = Some(out);
            }
        }
        assert_eq!(done.unwrap(), payload);
    }

    #[test]
    fn duplicate_fragment_is_idempotent() {
        let payload: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        let frags = fragment(KIND_FRAME, 4, &payload, 64).unwrap();
        let mut r = Reassembler::default();
        let mut done = None;
        // Feed every fragment twice, interleaved.
        for f in frags.iter().chain(frags.iter()) {
            if let Some(out) = r.accept("peer", f) {
                done = Some(out);
            }
        }
        assert_eq!(done.unwrap(), payload);
    }

    #[test]
    fn rejects_bad_mtu_and_empty_payload() {
        assert!(fragment(KIND_FRAME, 0, b"x", MIN_MTU - 1).is_none());
        assert!(fragment(KIND_FRAME, 0, b"", 240).is_none());
    }

    #[test]
    fn rejects_over_max_fragments() {
        // With MTU MIN_MTU (1 payload byte/frag), a payload longer than
        // MAX_FRAGMENTS bytes cannot be fragmented.
        let payload = vec![0u8; MAX_FRAGMENTS + 1];
        assert!(fragment(KIND_FRAME, 0, &payload, MIN_MTU).is_none());
        // ...but exactly MAX_FRAGMENTS bytes fits.
        let ok = vec![0u8; MAX_FRAGMENTS];
        assert_eq!(
            fragment(KIND_FRAME, 0, &ok, MIN_MTU).unwrap().len(),
            MAX_FRAGMENTS
        );
    }

    #[test]
    fn parse_rejects_foreign_and_malformed() {
        assert!(parse_fragment(b"").is_none());
        assert!(parse_fragment(b"hello mesh world").is_none()); // wrong magic
        assert!(parse_fragment(&[MAGIC0, MAGIC1]).is_none()); // too short
                                                              // right magic, bad version
        assert!(parse_fragment(&[MAGIC0, MAGIC1, 99, 0, 0, 0, 0, 0, 0, 1, 42]).is_none());
        // right magic/version, count=0
        assert!(parse_fragment(&[MAGIC0, MAGIC1, FRAG_VERSION, 0, 0, 0, 0, 0, 0, 0]).is_none());
        // index >= count (index 1, count 1)
        assert!(parse_fragment(&[MAGIC0, MAGIC1, FRAG_VERSION, 0, 0, 0, 0, 1, 0, 1, 42]).is_none());
        // well-formed (byte 3 = kind = 1 = Frame)
        let f = parse_fragment(&[MAGIC0, MAGIC1, FRAG_VERSION, 1, 0, 5, 0, 0, 0, 2, 0xAA]).unwrap();
        assert_eq!(f.kind, KIND_FRAME);
        assert_eq!(f.msg_id, 5);
        assert_eq!(f.frag_index, 0);
        assert_eq!(f.frag_count, 2);
        assert_eq!(f.chunk, &[0xAA]);
        // byte 3 = 0 parses as an Advert.
        let a = parse_fragment(&[MAGIC0, MAGIC1, FRAG_VERSION, 0, 0, 5, 0, 0, 0, 2, 0xAA]).unwrap();
        assert_eq!(a.kind, KIND_ADVERT);
    }

    #[test]
    fn kind_filtered_reassembler_ignores_other_kinds() {
        // An advert and a frame from the same source with the SAME msg_id must not
        // cross-feed a kind-scoped reassembler (and would not collide even in an
        // unscoped one, since kind is part of the key).
        let payload: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let adverts = fragment(KIND_ADVERT, 0, &payload, 64).unwrap();
        let frames = fragment(KIND_FRAME, 0, &payload, 64).unwrap();

        let mut only_frames = Reassembler::for_kind(KIND_FRAME);
        for f in &adverts {
            assert!(only_frames.accept("peer", f).is_none(), "advert ignored");
        }
        let mut done = None;
        for f in &frames {
            if let Some(out) = only_frames.accept("peer", f) {
                done = Some(out);
            }
        }
        assert_eq!(done.unwrap(), payload, "frames still reassemble");
    }

    #[test]
    fn distinct_msg_ids_and_sources_do_not_collide() {
        let a: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let b: Vec<u8> = (0..200u32).map(|i| (i + 7) as u8).collect();
        let fa = fragment(KIND_FRAME, 1, &a, 64).unwrap();
        let fb = fragment(KIND_FRAME, 2, &b, 64).unwrap();
        let mut r = Reassembler::default();
        // Interleave two different messages from two different sources.
        let mut out_a = None;
        let mut out_b = None;
        let max = fa.len().max(fb.len());
        for i in 0..max {
            if let Some(f) = fa.get(i) {
                if let Some(o) = r.accept("alice", f) {
                    out_a = Some(o);
                }
            }
            if let Some(f) = fb.get(i) {
                if let Some(o) = r.accept("bob", f) {
                    out_b = Some(o);
                }
            }
        }
        assert_eq!(out_a.unwrap(), a);
        assert_eq!(out_b.unwrap(), b);
    }

    #[test]
    fn reassembler_evicts_under_message_cap() {
        let mut r = Reassembler::with_limits(2, 1024 * 1024);
        // Start 3 different partial messages (each 2 fragments, only feed the first).
        for msg in 0..3u16 {
            let payload: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
            let frags = fragment(KIND_FRAME, msg, &payload, 64).unwrap();
            assert!(frags.len() >= 2);
            r.accept(&format!("peer{msg}"), &frags[0]); // only first fragment
        }
        // Cap is 2 → the oldest was evicted.
        assert!(r.in_flight() <= 2, "in-flight bounded by the message cap");
    }

    #[test]
    fn reassembler_evicts_under_byte_cap() {
        // Byte cap smaller than two messages' worth forces eviction.
        let mut r = Reassembler::with_limits(100, 150);
        for msg in 0..3u16 {
            let payload: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
            let frags = fragment(KIND_FRAME, msg, &payload, 64).unwrap();
            r.accept(&format!("peer{msg}"), &frags[0]);
        }
        assert!(r.in_flight() <= 2, "byte cap forces eviction of oldest");
    }
}

// ---------------------------------------------------------------------------
// Formal verification: the per-fragment decoder is proven TOTAL (never panics)
// and in-bounds for all short inputs, exactly like the `talkrypt_wire` bounded
// decoders. The `Reassembler` (nested heap) is covered by the unit tests above,
// not claimed here — per the project's FV posture (chunk flat decoders only).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    /// `parse_fragment` never panics on arbitrary bytes (it runs on attacker-
    /// influenced mesh input) and, on success, the returned chunk is a suffix of
    /// the input — so no out-of-bounds slice. Proven for all inputs up to 16 bytes
    /// (past the 10-byte header, enough to exercise the chunk slice).
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_fragment_never_panics_and_is_bounded() {
        let len: usize = kani::any();
        kani::assume(len <= 16);
        let data: [u8; 16] = kani::any();
        match parse_fragment(&data[..len]) {
            Some(f) => {
                // The chunk lies entirely within the input, after the header.
                assert!(f.chunk.len() <= len);
                assert!(len >= HEADER_LEN);
                assert!(f.frag_index < f.frag_count);
                assert!(f.frag_count >= 1);
            }
            None => {}
        }
    }
}
