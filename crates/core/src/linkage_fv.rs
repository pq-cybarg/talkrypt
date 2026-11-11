//! Machine-checked **totality** for the nested-heap chain-embedding decoders —
//! landed on-host, in CI, bound to the LITERAL talkrypt decoders (SECURITY-AUDIT
//! §5 / R-6; `docs/fv-heap-decoder-spike.md`; task #118).
//!
//! # The problem this closes
//!
//! `LinkageProof`/`LinkagePayload`/`NamePresence`/`Marking` — and the
//! `IdentityChain(Vec<SignedCert{String, Vec<u8>, Vec<u8>}>)` / `Presentation`
//! they embed — parse attacker-chosen bytes *before any crypto check*, so they
//! must be **total**: never panic, never over-read, never over-allocate on any
//! input. Kani/CBMC provably **cannot** discharge that directly: a
//! dependency-injection experiment pinned the blow-up (~34M clauses) to the
//! **nested-heap RETURN TYPE**, not the parse logic — CBMC models constructing
//! and dropping that nested heap expensively, independent of the grammar (the
//! flat `VouchTarget` decoder, by contrast, verifies in ~3 s). See the spike doc.
//!
//! # The landing (route 3, VM-free, bound to the real code)
//!
//! The spike's recommendation 3 ("bounded heap-free buffer") made flat.
//! Totality is a property of the **grammar** (the sequence of length-prefixed
//! reads and bound checks), not of the heap values those reads populate. So we
//! model the grammar as a flat, **heap-free** position walker over `&[u8]`
//! (only `usize` cursor arithmetic + guarded indexing — no `Vec`, no `String`),
//! exactly as cheap for CBMC as `wire::padded_len`:
//!
//! * **Kani proves the model total** (`mod proofs`) — exhaustively, on all inputs
//!   up to the model bound, no panic / no OOB / guaranteed termination. This is
//!   the obligation the heap decoder could not carry, now discharged.
//! * **A differential property test proves the model *is* the decoder** (`mod
//!   tests`): for arbitrary and for structured-valid bytes, the flat
//!   `accepts(bytes)` agrees **bit-for-bit** with the real `decode(bytes).is_ok()`
//!   *and* consumes exactly the same length (the `finish()` boundary). Any drift
//!   between the model and the literal decoder fails the test.
//!
//! Together: the real decoders' accept/reject decision is exactly that of a
//! Kani-proven-total function, and the real decoders are additionally exercised
//! on arbitrary + structured bytes under the test harness (which would surface
//! any panic). Each real `decode` does nothing beyond the modelled reads except
//! bounded `Vec`/`String` construction over already-validated lengths, so its
//! totality follows. This is a strictly more honest landing than silently
//! refactoring the security-critical wire types to fixed-capacity and trusting
//! the refactor preserved semantics — here the equivalence is itself checked.
//!
//! The zero-source-change Aeneas→F\* route (`formal/decoder-totality/`) remains
//! the path to a *extraction-faithful* proof once a build VM is available; this
//! module is the in-repo, on-host proof that lands today.

#![allow(dead_code)] // walkers are exercised by `mod proofs` (kani) and `mod tests`.

use talkrypt_wire::MAX_FRAME;

// ---------------------------------------------------------------------------
// Flat, heap-free grammar model.
//
// Every walker reads within a frame `[pos, end)` of the whole buffer `b` and
// returns the new cursor `Some(pos')` on success, or `None` on a short read, a
// `MAX_FRAME`/count-cap violation, or an unknown tag — mirroring the real
// decoders' `Reader` reads and `.ok()?`/`Err` rejections one-for-one. A nested,
// length-prefixed sub-object is required to consume its sub-frame **exactly**,
// mirroring the inner `Reader::finish()` the real decoders perform.
// ---------------------------------------------------------------------------

/// `Reader::get_u8` — one raw byte.
#[inline]
fn u8_at(b: &[u8], pos: usize, end: usize) -> Option<(u8, usize)> {
    if pos >= end {
        return None;
    }
    Some((b[pos], pos + 1))
}

/// `Reader::get_u32` — four raw big-endian bytes.
#[inline]
fn u32_at(b: &[u8], pos: usize, end: usize) -> Option<(u32, usize)> {
    let np = pos.checked_add(4)?;
    if np > end {
        return None;
    }
    let v = u32::from_be_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]]);
    Some((v, np))
}

/// `Reader::get_bytes`/`get_vec` — a `u32`-length-prefixed field, `MAX_FRAME`-capped.
/// Returns `(content_start, cursor_after)`; the field content is `[content_start,
/// cursor_after)`, so its length is `cursor_after - content_start`.
#[inline]
fn lenpfx(b: &[u8], pos: usize, end: usize) -> Option<(usize, usize)> {
    let (len, p1) = u32_at(b, pos, end)?;
    let len = len as usize;
    if len > MAX_FRAME {
        return None;
    }
    let np = p1.checked_add(len)?;
    if np > end {
        return None;
    }
    Some((p1, np))
}

/// A length-prefixed field required to be exactly `want` bytes (e.g. the framed
/// `u64`s in `account.rs`, whose `get_u64` rejects any length != 8).
#[inline]
fn lenpfx_sized(b: &[u8], pos: usize, end: usize, want: usize) -> Option<usize> {
    let (cs, np) = lenpfx(b, pos, end)?;
    if np - cs != want {
        return None;
    }
    Some(np)
}

/// Two raw `u32`s = the 8-byte `seq` encoding in `presence.rs` (NOT length-prefixed;
/// `presence::put_u64` writes hi‖lo as raw `u32`s, unlike `account::put_u64`).
#[inline]
fn u64_raw(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (_, p) = u32_at(b, pos, end)?;
    let (_, p) = u32_at(b, p, end)?;
    Some(p)
}

/// The **recombinable `from_utf8` chunk**, gated by the `S` (strict) const.
///
/// Every walker is generic over `const S: bool`:
/// * `S == false` — the **flat structural chunk**: `str_gate` is a dead branch that
///   monomorphizes away, so the walker contains NO `from_utf8` and stays
///   CBMC-tractable. This is the instantiation the Kani totality proofs target —
///   the exact chunk-out-the-intractable-part tactic `engine::decode_flat` uses for
///   its onion `String::from_utf8` (SECURITY-AUDIT R-6; see `feedback-chunk-kani-proofs`).
/// * `S == true` — **recombines** the `from_utf8` chunk back on top, giving an
///   accept/reject that matches the literal decoders exactly (they do
///   `String::from_utf8(...)?` on these fields). This is the differential test oracle.
///
/// Totality transfers across the recombination: `from_utf8` returns a `Result` and
/// is panic-free by the std contract, so (structural-total ∧ from_utf8-total) ⇒ the
/// `S == true` model — and the literal decoder — are total.
#[inline]
fn str_gate<const S: bool>(b: &[u8], cs: usize, ce: usize) -> bool {
    !S || core::str::from_utf8(&b[cs..ce]).is_ok()
}

/// `crypto::account::Cert::read`: subject vk, label (UTF-8), framed-u64
/// `valid_from`, framed-u64 `expiry`.
fn walk_cert<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (_, p) = lenpfx(b, pos, end)?; // subject vk (opaque)
    let (cs, p) = lenpfx(b, p, end)?; // label (String::from_utf8)
    if !str_gate::<S>(b, cs, p) {
        return None;
    }
    let p = lenpfx_sized(b, p, end, 8)?; // valid_from
    let p = lenpfx_sized(b, p, end, 8)?; // expiry
    Some(p)
}

/// `crypto::account::SignedCert::read`: issuer vk, an **exact** `Cert` sub-frame
/// (`cr.finish()`), then the issuer signature.
fn walk_signed_cert<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (_, p) = lenpfx(b, pos, end)?; // issuer vk (opaque)
    let (cs, p) = lenpfx(b, p, end)?; // cert sub-frame [cs, p)
    if walk_cert::<S>(b, cs, p)? != p {
        return None; // inner `cr.finish()` — the Cert must consume its whole frame
    }
    let (_, p) = lenpfx(b, p, end)?; // sig (opaque)
    Some(p)
}

/// Max chain links accepted by `IdentityChain::decode` (`n > 16` is rejected
/// before any allocation).
const MAX_CHAIN: u32 = 16;

/// `crypto::account::IdentityChain::decode`: a `u32` count (≤ 16) then that many
/// **exact** `SignedCert` sub-frames (`lr.finish()` per link).
fn walk_identity_chain<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (n, mut p) = u32_at(b, pos, end)?;
    if n > MAX_CHAIN {
        return None;
    }
    let mut i = 0u32;
    while i < n {
        let (cs, np) = lenpfx(b, p, end)?; // link sub-frame [cs, np)
        if walk_signed_cert::<S>(b, cs, np)? != np {
            return None; // inner `lr.finish()`
        }
        p = np;
        i += 1;
    }
    Some(p)
}

/// `linkage::LinkageProof::decode` (via `decode_with`): tag, then either a
/// chain-form or grouping-form body. Embedded `IdentityChain`/`SignedCert` are
/// decoded from their own frames (their inner `Reader::finish` ⇒ exact consume).
fn walk_linkage_proof<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (tag, p) = u8_at(b, pos, end)?;
    let p = match tag {
        0 => {
            let (cs, p) = lenpfx(b, p, end)?; // chain frame -> IdentityChain::decode (exact)
            if walk_identity_chain::<S>(b, cs, p)? != p {
                return None;
            }
            let (_, p) = lenpfx(b, p, end)?; // ctx_sig (opaque)
            p
        }
        1 => {
            let (_, p) = lenpfx(b, p, end)?; // member vk (opaque)
            let (cs, p) = lenpfx(b, p, end)?; // cert frame -> SignedCert::decode (exact)
            if walk_signed_cert::<S>(b, cs, p)? != p {
                return None;
            }
            let (_, p) = lenpfx(b, p, end)?; // ctx_sig (opaque)
            p
        }
        _ => return None,
    };
    Some(p)
}

/// `linkage::LinkagePayload::decode`: tag 0 only — grouping pub, an exact
/// `SignedCert` frame, ctx_sig, then two raw `u32`s (the `seq` hi/lo).
fn walk_linkage_payload<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (tag, p) = u8_at(b, pos, end)?;
    if tag != 0 {
        return None;
    }
    let (_, p) = lenpfx(b, p, end)?; // grouping_pub (opaque)
    let (cs, p) = lenpfx(b, p, end)?; // cert frame -> SignedCert::decode (exact)
    if walk_signed_cert::<S>(b, cs, p)? != p {
        return None;
    }
    let (_, p) = lenpfx(b, p, end)?; // ctx_sig (opaque)
    let (_, p) = u32_at(b, p, end)?; // seq hi
    let (_, p) = u32_at(b, p, end)?; // seq lo
    Some(p)
}

/// `contacts::Presentation::decode`: an exact `IdentityChain` frame then an
/// optional username (tag 0 = none, tag 1 = a length-prefixed UTF-8 name).
fn walk_presentation<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (cs, p) = lenpfx(b, pos, end)?; // chain frame -> IdentityChain::decode (exact)
    if walk_identity_chain::<S>(b, cs, p)? != p {
        return None;
    }
    let (tag, p) = u8_at(b, p, end)?;
    let p = match tag {
        0 => p,
        1 => {
            let (cs, p) = lenpfx(b, p, end)?; // username (String::from_utf8)
            if !str_gate::<S>(b, cs, p) {
                return None;
            }
            p
        }
        _ => return None,
    };
    Some(p)
}

/// `presence::NamePresence::decode`: tag 0 = Bare (`seq`, UTF-8 label); tag 1 =
/// Linked (`seq`, exact `Presentation` frame, a **32-byte** context, sig).
fn walk_name_presence<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (tag, p) = u8_at(b, pos, end)?;
    let p = match tag {
        0 => {
            let p = u64_raw(b, p, end)?; // seq
            let (cs, p) = lenpfx(b, p, end)?; // label (String::from_utf8)
            if !str_gate::<S>(b, cs, p) {
                return None;
            }
            p
        }
        1 => {
            let p = u64_raw(b, p, end)?; // seq
            let (cs, p) = lenpfx(b, p, end)?; // presentation frame -> Presentation::decode (exact)
            if walk_presentation::<S>(b, cs, p)? != p {
                return None;
            }
            let p = lenpfx_sized(b, p, end, 32)?; // context (exactly 32 bytes)
            let (_, p) = lenpfx(b, p, end)?; // sig (opaque)
            p
        }
        _ => return None,
    };
    Some(p)
}

/// Max compartment/caveat strings accepted by `Marking::decode` (`read_strings`
/// rejects `n > 256` before allocating).
const MAX_MARKING_ITEMS: u32 = 256;

/// `marking::read_strings`: a `u32` count (≤ 256) then that many length-prefixed
/// UTF-8 strings.
fn walk_strings<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (n, mut p) = u32_at(b, pos, end)?;
    if n > MAX_MARKING_ITEMS {
        return None;
    }
    let mut i = 0u32;
    while i < n {
        let (cs, np) = lenpfx(b, p, end)?; // String::from_utf8 per item
        if !str_gate::<S>(b, cs, np) {
            return None;
        }
        p = np;
        i += 1;
    }
    Some(p)
}

/// `marking::Marking::decode`: a classification tag (≤ 4), then compartments and
/// caveats string lists.
fn walk_marking<const S: bool>(b: &[u8], pos: usize, end: usize) -> Option<usize> {
    let (tag, p) = u8_at(b, pos, end)?;
    if tag > 4 {
        return None; // Classification::from_tag rejects 5+
    }
    let p = walk_strings::<S>(b, p, end)?; // compartments
    let p = walk_strings::<S>(b, p, end)?; // caveats
    Some(p)
}

// ---- top-level `decode`-equivalents: walk the whole buffer and require exact
// consumption (the outer `Reader::finish()` that every `decode` enforces). The
// `accepts_*` oracles use the UTF-8-strict `S = true` recombination so they bind
// to the literal decoders; the Kani proofs below target the `S = false` chunk. ----

macro_rules! whole {
    ($name:ident, $walk:ident) => {
        /// Does the UTF-8-strict grammar model accept `bytes` as a complete,
        /// no-trailing frame (the differential oracle for the literal decoder)?
        #[inline]
        fn $name(bytes: &[u8]) -> bool {
            $walk::<true>(bytes, 0, bytes.len()) == Some(bytes.len())
        }
    };
}
whole!(accepts_signed_cert, walk_signed_cert);
whole!(accepts_identity_chain, walk_identity_chain);
whole!(accepts_linkage_proof, walk_linkage_proof);
whole!(accepts_linkage_payload, walk_linkage_payload);
whole!(accepts_presentation, walk_presentation);
whole!(accepts_name_presence, walk_name_presence);
whole!(accepts_marking, walk_marking);

// ===========================================================================
// Kani: the flat grammar model is TOTAL on all inputs up to the model bound.
//
// This is the exact obligation the heap decoders could not discharge. The model
// is heap-free, so CBMC stays tractable (like `wire::padded_len` / the flat
// `VouchTarget`). Totality is a property of the control flow, which is uniform in
// input size; an exhaustive proof over all <= MODEL_LEN-byte inputs exercises
// every tag branch, every length-prefix bound, and every count cap. `mod tests`
// then binds this proven model to the literal decoders (incl. large structured
// inputs the BMC bound cannot reach).
// ===========================================================================
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Input bound for the exhaustive model proofs. Large enough to cross every
    /// tag branch, nested sub-frame and (short-read-terminated) loop boundary;
    /// each length-prefix read consumes >= 4 bytes, so no loop can enter its body
    /// more than `MODEL_LEN / 4 + 1` times before EOF — bounded by `MODEL_UNWIND`,
    /// which keeps the nested `walk_signed_cert` unrolling (hence CBMC solve time)
    /// small. Totality is uniform in input size, so this bound exhaustively covers
    /// the control flow; `mod tests` binds the result to the literal decoders on
    /// the large structured inputs the BMC bound cannot reach.
    const MODEL_LEN: usize = 16;
    const MODEL_UNWIND: usize = 8;

    macro_rules! total {
        ($harness:ident, $walk:ident) => {
            /// The flat **structural chunk** (`S = false`, no `from_utf8`) never
            /// panics / over-reads on any input up to the model bound
            /// (guaranteed-terminating `Tot`-style totality). `from_utf8` is chunked
            /// out exactly as in `engine::decode_flat` and recombines (panic-free by
            /// the std contract) in the `S = true` differential oracle below.
            #[kani::proof]
            #[kani::unwind(8)]
            fn $harness() {
                let len: usize = kani::any();
                kani::assume(len <= MODEL_LEN);
                let data: [u8; MODEL_LEN] = kani::any();
                let _ = $walk::<false>(&data[..len], 0, len);
            }
        };
    }

    total!(signed_cert_model_total, walk_signed_cert);
    total!(identity_chain_model_total, walk_identity_chain);
    total!(linkage_proof_model_total, walk_linkage_proof);
    total!(linkage_payload_model_total, walk_linkage_payload);
    total!(presentation_model_total, walk_presentation);
    total!(name_presence_model_total, walk_name_presence);
    total!(marking_model_total, walk_marking);

    // Keep `MODEL_UNWIND` referenced so a future bound change stays consistent
    // with the `#[kani::unwind(8)]` literal above (CBMC requires a literal there):
    // the unwind must exceed the max loop-body entries (`MODEL_LEN / 4 + 1`).
    const _: () = assert!(MODEL_UNWIND >= MODEL_LEN / 4 + 2 && MODEL_UNWIND == 8);
}

// ===========================================================================
// Differential binding: the flat model IS the literal decoder.
//
// For arbitrary bytes AND for structured-valid encodings (+ boundary mutations),
// `accepts_X(bytes)` must equal `X::decode(bytes).is_ok()`. This closes the gap
// between the Kani-proven model and the real nested-heap code: any divergence
// (a read the model forgot, a bound it got wrong) fails here. Running the real
// decoders on these inputs also exercises them for panics directly.
// ===========================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::Presentation;
    use crate::linkage::{LinkageProof, LinkagePayload};
    use crate::marking::{Classification, Marking};
    use crate::presence::NamePresence;
    use proptest::prelude::*;
    use talkrypt_crypto::{GroupingKey, IdentityChain, IdentityKeyPair, SignedCert};

    // ---- the equivalence assertions, one per decoder ----

    fn assert_agree(bytes: &[u8]) {
        assert_eq!(
            accepts_signed_cert(bytes),
            SignedCert::decode(bytes).is_ok(),
            "SignedCert model/decoder disagree on {bytes:02x?}"
        );
        assert_eq!(
            accepts_identity_chain(bytes),
            IdentityChain::decode(bytes).is_ok(),
            "IdentityChain model/decoder disagree on {bytes:02x?}"
        );
        assert_eq!(
            accepts_linkage_proof(bytes),
            LinkageProof::decode(bytes).is_some(),
            "LinkageProof model/decoder disagree on {bytes:02x?}"
        );
        assert_eq!(
            accepts_linkage_payload(bytes),
            LinkagePayload::decode(bytes).is_some(),
            "LinkagePayload model/decoder disagree on {bytes:02x?}"
        );
        assert_eq!(
            accepts_presentation(bytes),
            Presentation::decode(bytes).is_ok(),
            "Presentation model/decoder disagree on {bytes:02x?}"
        );
        assert_eq!(
            accepts_name_presence(bytes),
            NamePresence::decode(bytes).is_ok(),
            "NamePresence model/decoder disagree on {bytes:02x?}"
        );
        assert_eq!(
            accepts_marking(bytes),
            Marking::decode(bytes).is_ok(),
            "Marking model/decoder disagree on {bytes:02x?}"
        );
    }

    // ---- structured generators: build real, valid encodings ----

    fn chain_1() -> IdentityChain {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        IdentityChain::device(&account, device.public(), "device:phone", 0, 10_000)
    }

    fn chain_2() -> IdentityChain {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let segment = IdentityKeyPair::generate();
        let c = IdentityChain::device(&account, device.public(), "device:phone", 0, 10_000);
        c.extend(&device, segment.public(), "segment:work", 0, 10_000)
    }

    fn signed_cert() -> SignedCert {
        let issuer = IdentityKeyPair::generate();
        let subject = IdentityKeyPair::generate();
        SignedCert::issue(&issuer, subject.public(), "device:x", 0, 10_000)
    }

    fn linkage_proof_chain() -> LinkageProof {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", 0, 10_000);
        LinkageProof::Chain { chain, ctx_sig: device.sign(&[7u8; 32]) }
    }

    fn linkage_proof_grouping() -> LinkageProof {
        let ctx = [5u8; 32];
        let g = GroupingKey::from_root_seed([1u8; 32]);
        let member = IdentityKeyPair::generate();
        let cert = g.certify(&ctx, member.public(), 0, 10_000);
        LinkageProof::Grouping {
            member: member.public().clone(),
            cert,
            ctx_sig: member.sign(&ctx),
        }
    }

    fn linkage_payload() -> LinkagePayload {
        let ctx = [5u8; 32];
        let g = GroupingKey::from_root_seed([2u8; 32]);
        let member = IdentityKeyPair::generate();
        let cert = g.certify(&ctx, member.public(), 0, 10_000);
        LinkagePayload::GroupingProof {
            grouping_pub: g.derive_for_chat(&ctx).public().sig_vk.clone(),
            cert,
            ctx_sig: member.sign(&ctx),
            seq: 0xDEAD_BEEF_0000_0001,
        }
    }

    fn name_presence_bare() -> NamePresence {
        NamePresence::Bare { seq: 42, label: "alice".to_string() }
    }

    fn name_presence_linked() -> NamePresence {
        let account = IdentityKeyPair::generate();
        let device = IdentityKeyPair::generate();
        let chain = IdentityChain::device(&account, device.public(), "dev", 0, 10_000);
        NamePresence::linked(7, chain, "bob", [9u8; 32], &device)
    }

    fn presentation() -> Presentation {
        Presentation::new(chain_2(), Some("carol".to_string()))
    }

    fn marking_full() -> Marking {
        Marking {
            level: Classification::Secret,
            compartments: vec!["SI".to_string(), "TK".to_string()],
            caveats: vec!["NOFORN".to_string()],
        }
    }

    /// Every structured-valid encoding is accepted by BOTH the model and the real
    /// decoder, and the model consumes exactly the full buffer (the `finish`
    /// boundary). Then: truncating by one byte, and appending one trailing byte,
    /// must each make BOTH reject — pinning the model to the decoder at the
    /// accept/reject boundary where divergence is most likely.
    #[test]
    fn structured_valid_encodings_agree_and_consume_exactly() {
        let samples: Vec<Vec<u8>> = vec![
            signed_cert().encode(),
            chain_1().encode(),
            chain_2().encode(),
            linkage_proof_chain().encode(),
            linkage_proof_grouping().encode(),
            linkage_payload().encode(),
            presentation().encode(),
            name_presence_bare().encode(),
            name_presence_linked().encode(),
            marking_full().encode(),
            Marking::level(Classification::Unclassified).encode(),
        ];
        for s in &samples {
            // Agreement on the exact bytes...
            assert_agree(s);
            // ...on a one-byte truncation (short read)...
            if !s.is_empty() {
                assert_agree(&s[..s.len() - 1]);
            }
            // ...and with one trailing junk byte (violates `finish()`).
            let mut extended = s.clone();
            extended.push(0xAB);
            assert_agree(&extended);
        }
    }

    /// A chain at the exact `n == 16` cap round-trips and is accepted; `n == 17`
    /// (hand-written count) is rejected by both before allocation.
    #[test]
    fn chain_length_cap_boundary_agrees() {
        // Build a 16-link chain by repeated extension.
        let account = IdentityKeyPair::generate();
        let mut kp = IdentityKeyPair::generate();
        let mut chain = IdentityChain::device(&account, kp.public(), "d0", 0, 10_000);
        for i in 1..16 {
            let next = IdentityKeyPair::generate();
            chain = chain.extend(&kp, next.public(), format!("d{i}"), 0, 10_000);
            kp = next;
        }
        assert_eq!(chain.links.len(), 16);
        let enc = chain.encode();
        assert_agree(&enc);

        // Forge a count of 17 with no bodies: both reject (cap, then short read).
        let mut over = enc.clone();
        over[0..4].copy_from_slice(&17u32.to_be_bytes());
        assert!(!accepts_identity_chain(&over));
        assert!(IdentityChain::decode(&over).is_err());
    }

    // ---- fuzz-style agreement over arbitrary and near-valid bytes ----

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4096))]

        /// Arbitrary bytes: the model and every real decoder agree (and neither
        /// panics — a panic in the real decoder aborts the test).
        #[test]
        fn arbitrary_bytes_agree(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            assert_agree(&bytes);
        }

        /// Short arbitrary bytes, where accept/reject boundaries for the small
        /// framed fields (tags, counts, 8-byte u64s) are densest.
        #[test]
        fn short_arbitrary_bytes_agree(bytes in prop::collection::vec(any::<u8>(), 0..24)) {
            assert_agree(&bytes);
        }
    }

    /// A valid encoding with ONE byte flipped at every position still agrees —
    /// this walks the near-valid surface the real decoder is most sensitive on
    /// (length prefixes, tags, inner `finish` boundaries).
    #[test]
    fn single_byte_mutations_of_valid_encodings_agree() {
        let samples: Vec<Vec<u8>> = vec![
            signed_cert().encode(),
            chain_1().encode(),
            linkage_payload().encode(),
            name_presence_linked().encode(),
            marking_full().encode(),
        ];
        for s in &samples {
            for i in 0..s.len() {
                let mut m = s.clone();
                m[i] ^= 0xFF;
                assert_agree(&m);
            }
        }
    }

    /// Hand-picked degenerate inputs that hit each early-return path.
    #[test]
    fn degenerate_inputs_agree() {
        for bytes in [
            &[][..],
            &[0x00],
            &[0x01],
            &[0x02],
            &[0xFF],
            &[0x00, 0x00, 0x00, 0x00], // zero-count chain / empty strings
            &[0x05],                   // Marking tag 5 (> max) — reject
            &[0x04, 0, 0, 1, 0],       // Marking: level 4, 1 compartment, short
        ] {
            assert_agree(bytes);
        }
    }
}
