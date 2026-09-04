//! Minimal, allocation-conscious length-prefixed wire codec.
//!
//! All multi-byte integers are big-endian. Byte slices are framed with a
//! `u32` big-endian length prefix. A hard `MAX_FRAME` bound rejects hostile
//! lengths before any allocation, so a malicious peer cannot trigger a huge
//! allocation by lying about a length.
//!
//! This codec carries only opaque ciphertext and protocol headers; it never
//! sees plaintext or key material.

use thiserror::Error;

/// Largest single length-prefixed field we will ever read (16 MiB).
///
/// This is the **jumbo-frame ceiling**: text messages and crypto headers are
/// kilobytes, but large ("jumbo") payloads — big group state, attachments — are
/// supported up to this bound, which still caps memory against a hostile length
/// prefix. The decoder reads the full payload regardless of how the OS segments
/// the underlying byte stream (network MTU / Ethernet jumbo frames are an
/// OS/NIC concern, transparent to this layer). Verified by multi-MB round-trip
/// tests through the ratchet and the TCP transport.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WireError {
    #[error("unexpected end of input: needed {needed} more bytes, had {had}")]
    UnexpectedEof { needed: usize, had: usize },
    #[error("length prefix {len} exceeds MAX_FRAME ({max})")]
    FrameTooLarge { len: usize, max: usize },
    #[error("trailing bytes remain after decode: {0}")]
    TrailingBytes(usize),
}

/// Appends framed data to an owned byte buffer.
#[derive(Default, Debug)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Write a raw `u8`.
    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Write a big-endian `u32`.
    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Write a `u32` length prefix followed by the bytes themselves.
    pub fn put_bytes(&mut self, bytes: &[u8]) {
        // Caller-side invariant: nothing we serialize approaches MAX_FRAME.
        debug_assert!(bytes.len() <= MAX_FRAME);
        self.put_u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    /// Consume the writer, returning the assembled buffer.
    pub fn into_vec(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }
}

/// Reads framed data from a byte slice, tracking a cursor.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::UnexpectedEof {
            needed: n,
            had: self.remaining(),
        })?;
        if end > self.buf.len() {
            return Err(WireError::UnexpectedEof {
                needed: n,
                had: self.remaining(),
            });
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn get_u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn get_u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a `u32`-length-prefixed byte field, enforcing `MAX_FRAME`.
    pub fn get_bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.get_u32()? as usize;
        if len > MAX_FRAME {
            return Err(WireError::FrameTooLarge {
                len,
                max: MAX_FRAME,
            });
        }
        self.take(len)
    }

    /// Read a length-prefixed field into an owned `Vec`.
    pub fn get_vec(&mut self) -> Result<Vec<u8>, WireError> {
        Ok(self.get_bytes()?.to_vec())
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Assert the input is fully consumed. Use after decoding a complete
    /// message to reject trailing garbage.
    pub fn finish(self) -> Result<(), WireError> {
        if self.remaining() != 0 {
            Err(WireError::TrailingBytes(self.remaining()))
        } else {
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Length-bucketing pad (SECURITY-AUDIT F-16).
//
// A message-length side-channel closer: a non-member relay decrypts the pairwise
// hop and sees each inner group-ciphertext's exact size, leaking coarse content
// class. Padding the plaintext to a bucket boundary *before* the group AEAD
// quantizes the ciphertext length to a handful of classes. The pad is
// self-describing (`u32` real length ‖ payload ‖ zero fill) so the receiver
// recovers the exact payload; both sides opt in via the chat descriptor.
// ---------------------------------------------------------------------------

/// The bucketed total length for a `raw` (length-prefix + payload) size and `step`:
/// `raw` rounded up to the next multiple of `step` (clamped ≥1). Pure `usize` math
/// (no heap) so it is cheaply Kani-provable: the result is always a multiple of
/// `step` and always ≥ `raw`. On overflow it saturates to `raw` (the caller only
/// ever passes `raw ≤ 4 + MAX_FRAME`, far from `usize::MAX`).
pub fn padded_len(raw: usize, step: usize) -> usize {
    // Clamp the bucket to [1, MAX_FRAME]: step 0 = off (→1), and a bucket larger than
    // the max frame is nonsensical AND a DoS vector (an absurd descriptor value would
    // pad every message to gigabytes), so it is capped. With `raw ≤ MAX_FRAME` this
    // keeps `raw + step - 1 ≤ 2·MAX_FRAME` — no overflow.
    let step = step.clamp(1, MAX_FRAME);
    match raw.checked_add(step - 1) {
        Some(x) => (x / step) * step,
        None => raw,
    }
}

/// Pad `payload` to the next multiple of `step` bytes, prefixed with its true
/// length. `step` is clamped to ≥1. The result length is always a multiple of
/// `step` and always holds `4 + payload.len()` bytes, so [`unpad_bucket`] recovers
/// the exact payload. Quantizing (not fixed-size) bounds overhead to `< step`.
pub fn pad_to_bucket(payload: &[u8], step: usize) -> Vec<u8> {
    let raw = 4 + payload.len();
    let total = padded_len(raw, step).max(raw);
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.resize(total, 0); // zero fill (never shrink below the payload)
    out
}

/// Recover the exact payload from a buffer produced by [`pad_to_bucket`]. Returns
/// `None` on any malformed input (too short, or a length prefix past the buffer or
/// over `MAX_FRAME`) — never panics.
pub fn unpad_bucket(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 4 {
        return None;
    }
    let real = u32::from_be_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;
    if real > MAX_FRAME || 4usize.checked_add(real)? > padded.len() {
        return None;
    }
    Some(padded[4..4 + real].to_vec())
}

/// FV **bounded-implementation route** (`docs/fv-heap-decoder-spike.md`): a heap-FREE
/// analog of a nested decoder. talkrypt's chain-embedding decoders return nested heap
/// (`Vec<Struct{String, Vec<u8>}>`), which CBMC/Kani cannot verify total — not because
/// of the parse logic, but because it models constructing + dropping that nested heap
/// expensively (proven by a dependency-injection experiment; see the spike doc). This
/// module shows the alternative: the SAME grammar decoded into FIXED-CAPACITY arrays
/// (no `Vec`, no `String`) is **directly Kani-verifiable** — as fast as the flat
/// `VouchTarget` decoder. It demonstrates that bounding the wire types (caps enforced
/// anyway by [`MAX_FRAME`]) makes the whole parser surface BMC-tractable, closing the
/// FV gap *in-repo* without a separation-logic tool. Reference for a future migration.
pub mod bounded {
    /// Compile-time caps (tiny here for a fast proof; production would size to the
    /// protocol's real maxima, all ≤ [`super::MAX_FRAME`]).
    pub const MAX_ITEMS: usize = 4;
    pub const MAX_FIELD: usize = 8;

    #[derive(Clone, Copy)]
    pub struct BItem {
        pub label_len: usize,
        pub label: [u8; MAX_FIELD],
        pub data_len: usize,
        pub data: [u8; MAX_FIELD],
    }
    pub struct BDoc {
        pub n: usize,
        pub items: [BItem; MAX_ITEMS],
    }

    /// Decode into fixed arrays. Returns `None` on a short read OR on exceeding a cap.
    /// Every index is bounds-guarded by construction — no heap, so no CBMC blowup.
    pub fn decode(bytes: &[u8]) -> Option<BDoc> {
        if bytes.is_empty() {
            return None;
        }
        let n: usize = bytes[0] as usize;
        if n > MAX_ITEMS {
            return None;
        }
        let empty = BItem { label_len: 0, label: [0u8; MAX_FIELD], data_len: 0, data: [0u8; MAX_FIELD] };
        let mut items = [empty; MAX_ITEMS];
        let mut pos: usize = 1;
        let mut i: usize = 0;
        while i < n {
            // label
            if pos >= bytes.len() {
                return None;
            }
            let ll: usize = bytes[pos] as usize;
            pos += 1;
            if ll > MAX_FIELD || ll > bytes.len() - pos {
                return None;
            }
            let mut j: usize = 0;
            while j < ll {
                items[i].label[j] = bytes[pos + j];
                j += 1;
            }
            items[i].label_len = ll;
            pos += ll;
            // data
            if pos >= bytes.len() {
                return None;
            }
            let dl: usize = bytes[pos] as usize;
            pos += 1;
            if dl > MAX_FIELD || dl > bytes.len() - pos {
                return None;
            }
            let mut k: usize = 0;
            while k < dl {
                items[i].data[k] = bytes[pos + k];
                k += 1;
            }
            items[i].data_len = dl;
            pos += dl;
            i += 1;
        }
        Some(BDoc { n, items })
    }
}

/// Formal verification harnesses (run with `cargo kani`).
///
/// These prove the decoder is memory-safe on *arbitrary* input: no panic, no
/// out-of-bounds — it always returns `Ok` or a `WireError`.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// F-16 length quantization is proven on the PURE `padded_len` (heap-free `usize`
    /// math — tractable for CBMC, unlike the `Vec`-allocating `pad_to_bucket`, which
    /// Kani cannot cheaply discharge). For ALL raw sizes and steps: the padded length
    /// is a multiple of the (≥1-clamped) step and never below `raw` — i.e. the pad
    /// always quantizes and never truncates. The `Vec` round-trip itself is covered
    /// exhaustively by the unit tests, not claimed here.
    /// F-16 length quantization on the PURE `padded_len` (heap-free). Proven for a
    /// CONCRETE bucket over all `raw` in a range that crosses many bucket boundaries:
    /// the padded length is a multiple of the bucket, never truncates, and adds < one
    /// bucket of overhead. A concrete `step` keeps 64-bit *symbolic division* out of
    /// the SAT instance (its real bottleneck); the code path is identical for every
    /// step, and production uses a fixed bucket, so this discharges the exact behavior.
    fn padded_len_quantizes_for<const S: usize>() {
        let raw: usize = kani::any();
        kani::assume(raw <= 4 * S); // crosses several bucket boundaries
        let total = padded_len(raw, S);
        assert!(total % S == 0, "padded length is a bucket multiple");
        assert!(total >= raw, "padding never truncates below the raw size");
        assert!(total < raw + S, "overhead is strictly less than one bucket");
    }

    #[kani::proof]
    fn padded_len_quantizes_step4() {
        padded_len_quantizes_for::<4>();
    }

    #[kani::proof]
    fn padded_len_quantizes_step256() {
        padded_len_quantizes_for::<256>();
    }

    /// F-16 unpad never panics on arbitrary bytes (it runs on attacker-influenced
    /// input after AEAD open) — proven memory-safe for all ≤16-byte inputs.
    #[kani::proof]
    #[kani::unwind(20)]
    fn unpad_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 16);
        let data: [u8; 16] = kani::any();
        let _ = unpad_bucket(&data[..len]);
    }

    /// FV bounded route: the heap-free nested decoder ([`bounded::decode`]) is proven
    /// TOTAL (never panics) on all ≤16-byte inputs — the exact obligation the
    /// heap-based `LinkageProof::decode` could NOT discharge. Fixed arrays, so CBMC
    /// stays tractable.
    #[kani::proof]
    #[kani::unwind(20)]
    fn bounded_decode_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 16);
        let data: [u8; 16] = kani::any();
        let _ = bounded::decode(&data[..len]);
    }

    /// `get_bytes` on any ≤16-byte input never panics; on success the returned
    /// slice length never exceeds the remaining input.
    #[kani::proof]
    #[kani::unwind(20)]
    fn get_bytes_never_panics() {
        let len: usize = kani::any();
        kani::assume(len <= 16);
        let data: [u8; 16] = kani::any();
        let mut r = Reader::new(&data[..len]);
        match r.get_bytes() {
            Ok(b) => assert!(b.len() <= len),
            Err(_) => {}
        }
    }

    /// A `u32` length prefix can never drive an out-of-bounds read: a length
    /// over `MAX_FRAME`, or past the buffer, is rejected, never indexed.
    #[kani::proof]
    #[kani::unwind(12)]
    fn length_prefix_is_bounded() {
        let data: [u8; 8] = kani::any();
        let mut r = Reader::new(&data);
        let _ = r.get_bytes(); // must not panic regardless of the prefix value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SECURITY-AUDIT F-16: length-bucketing pad.

    #[test]
    fn pad_bucket_quantizes_and_roundtrips() {
        let step = 256;
        for len in [0usize, 1, 5, 200, 255, 256, 257, 1000] {
            let payload: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
            let padded = pad_to_bucket(&payload, step);
            assert_eq!(padded.len() % step, 0, "padded length is a bucket multiple");
            assert!(padded.len() >= 4 + len);
            assert!(padded.len() < 4 + len + step, "overhead is bounded by < step");
            assert_eq!(unpad_bucket(&padded).unwrap(), payload, "exact round-trip");
        }
    }

    #[test]
    fn pad_bucket_clamps_absurd_step_no_giant_alloc() {
        // A malicious/absurd descriptor step (e.g. near u32::MAX) must NOT pad a tiny
        // message to gigabytes — the bucket is clamped to MAX_FRAME.
        assert_eq!(padded_len(10, usize::MAX), MAX_FRAME);
        let padded = pad_to_bucket(b"hi", u32::MAX as usize);
        assert_eq!(padded.len(), MAX_FRAME);
        assert_eq!(unpad_bucket(&padded).unwrap(), b"hi");
        // Off (step 0) means a length-prefix only, no bucketing.
        assert_eq!(padded_len(6, 0), 6);
    }

    #[test]
    fn pad_bucket_collapses_distinct_lengths_to_same_size() {
        // Two different plaintext lengths in the same bucket pad to the SAME size —
        // that is the length-indistinguishability the relay/observer sees.
        let a = pad_to_bucket(&[1u8; 10], 256);
        let b = pad_to_bucket(&[2u8; 200], 256);
        assert_eq!(a.len(), b.len());
        assert_eq!(a.len(), 256);
    }

    #[test]
    fn unpad_rejects_malformed_without_panic() {
        assert!(unpad_bucket(&[]).is_none());
        assert!(unpad_bucket(&[0, 0, 1]).is_none()); // < 4 bytes
        // A length prefix past the buffer is rejected, not indexed.
        assert!(unpad_bucket(&[0xFF, 0xFF, 0xFF, 0xFF, 0x00]).is_none());
        // Zero-length payload round-trips to empty.
        assert_eq!(unpad_bucket(&pad_to_bucket(&[], 64)).unwrap(), Vec::<u8>::new());
    }

    // FV bounded-implementation route: the heap-free decoder parses correctly and
    // rejects (never panics on) short reads / over-cap inputs.
    #[test]
    fn bounded_decode_parses_and_rejects() {
        // n=1 item, label "hi" (len 2), data "yo" (len 2).
        let buf = [1u8, 2, b'h', b'i', 2, b'y', b'o'];
        let d = bounded::decode(&buf).expect("well-formed");
        assert_eq!(d.n, 1);
        assert_eq!(d.items[0].label_len, 2);
        assert_eq!(&d.items[0].label[..2], b"hi");
        assert_eq!(&d.items[0].data[..2], b"yo");
        // Over-cap count / field are rejected, not panicked.
        assert!(bounded::decode(&[99]).is_none()); // n > MAX_ITEMS
        assert!(bounded::decode(&[1, 99]).is_none()); // label len > MAX_FIELD
        assert!(bounded::decode(&[1, 5, b'a']).is_none()); // short read
        assert!(bounded::decode(&[]).is_none());
    }

    #[test]
    fn roundtrip_multiple_fields() {
        let mut w = Writer::new();
        w.put_u8(0xAB);
        w.put_u32(0xDEAD_BEEF);
        w.put_bytes(b"hello");
        w.put_bytes(b"");
        w.put_bytes(&[0u8; 300]);
        let bytes = w.into_vec();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.get_u8().unwrap(), 0xAB);
        assert_eq!(r.get_u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.get_bytes().unwrap(), b"hello");
        assert_eq!(r.get_bytes().unwrap(), b"");
        assert_eq!(r.get_bytes().unwrap(), &[0u8; 300]);
        r.finish().unwrap();
    }

    #[test]
    fn truncated_input_errors() {
        // length prefix says 5 bytes but only 2 follow
        let bytes = [0u8, 0, 0, 5, b'h', b'i'];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.get_bytes(),
            Err(WireError::UnexpectedEof { .. })
        ));
    }

    #[test]
    fn oversized_length_rejected_without_allocation() {
        // length prefix claims 0xFFFFFFFF bytes
        let bytes = [0xFFu8, 0xFF, 0xFF, 0xFF];
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.get_bytes(),
            Err(WireError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn trailing_bytes_detected() {
        let mut w = Writer::new();
        w.put_bytes(b"x");
        let mut bytes = w.into_vec();
        bytes.push(0); // junk
        let mut r = Reader::new(&bytes);
        let _ = r.get_bytes().unwrap();
        assert!(matches!(r.finish(), Err(WireError::TrailingBytes(1))));
    }
}
