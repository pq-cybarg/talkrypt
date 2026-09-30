# Spike: reaching full FV on the nested-heap decoders (what CBMC/Kani cannot)

**Question:** talkrypt's chain-embedding decoders (`LinkageProof`/`LinkagePayload`/
`NamePresence`, and `Marking`) could not be proven total by Kani/CBMC. Can a
*different verification paradigm* discharge them **without changing the
implementation**? This spike answers: **yes** — and identifies which tools and at
what supply-chain cost.

## Why Kani/CBMC fails here (root cause, empirically pinned down)

Kani uses **CBMC, a bounded model checker**: it symbolically executes concrete
memory and encodes it into SAT. A dependency-injection experiment
(`LinkageProof::decode_with`, on branch `test/kani-core-assess`) proved the
bottleneck is **not** the sub-decoders and **not** the parse logic — with the real
`IdentityChain`/`SignedCert` decoders replaced by trivial total stubs it *still*
blew up to ~34M clauses. The cost is the **nested-heap RETURN TYPE**
(`IdentityChain(Vec<SignedCert{String, Vec<u8>, Vec<u8>}>)`): CBMC models
constructing **and dropping** that nested heap expensively, independent of logic.
That is why flat, fixed-array decoders (`VouchTarget`) verify in ~3 s and these
cannot. **BMC is simply the wrong paradigm for unbounded heap.**

## The fix is a paradigm change, not a tactic

Reasoning about heap modularly is what **separation logic** ("the graph theory of
heap") was invented for — a `Vec<T>` is *one abstract predicate*, not N symbolic
allocations. Two paradigm families reach full FV here:

1. **Deductive verification with separation logic / SMT** — Verus, Prusti, Creusot.
2. **Ownership → functional translation** — Aeneas (Rust MIR → a pure functional
   model with *no heap*, exploiting the borrow checker's no-aliasing guarantee),
   emitting F\* (which talkrypt already runs in CI).

("Geometric/polyhedral abstraction" is real but for numeric/loop bounds, not heap
shape. "Statistical" methods are the property tests we already have — high
confidence, not a ∀-proof.)

## Result — Verus discharges the exact class CBMC could not

A representative nested-heap decoder (`decode(&[u8]) -> Option<Doc>` where
`Doc{items: Vec<Item>}`, `Item{label: Vec<u8>, data: Vec<u8>}` — the same
Vec-of-struct-with-Vecs shape) was expressed for **Verus** with `invariant` /
`decreases` specs and verified:

```
verus verus_decode.rs
-> verification results:: 4 verified, 0 errors    (seconds)
```

This **proves totality** (no panic, no overflow, no OOB) for **all inputs** — the
exact obligation Kani blew up on. Verus uses `rustc 1.97.1` (its build-matched
toolchain) + a bundled Z3. **Route 1 (deductive/SMT) validated.**

Caveat on "no impl change": Verus verifies code in the `verus!{}` dialect (specs
added), so the decoder is *re-expressed*, not the literal talkrypt Rust. The true
zero-source-change fits are **Prusti** (annotations on real Rust) and **Aeneas**
(operates on MIR).

## Supply-chain vetting (done BEFORE building anything — security gate)

Every tool runs in a throwaway dir on a toy file — none touch talkrypt's dep graph.
But *source builds* execute hundreds of third-party build scripts on the host, so
each was provenance-checked + `cargo audit`ed first:

| Tool | Provenance | `cargo audit` | Decision |
| --- | --- | --- | --- |
| **Verus** | official `verus-lang` **prebuilt binary** (no build scripts) | n/a | **used** — lowest risk |
| **Prusti** (source) | official `viperproject`, but **2024-pinned** tree | **25 CVEs** incl. `libgit2-sys` RUSTSEC-2024-0013 (**arbitrary code execution**), `openssl` UAF ×3, `h2` DoS ×3 | **NOT built** (paused at clone; no build scripts ran) |
| **Creusot** (source) | current (2026-08-25, J-H Jourdan) | **0 vulnerabilities** (1 low `anyhow` unsoundness notice) | **clean** — build attempted (see below) |
| **Charon** (Aeneas frontend) | current (2026-08-26) | **11 CVEs** (`h2`/`rustls-webpki` ×4/`tar`/`time`/`bytes` — all DoS/unsoundness, **no** ACE/UAF/corruption) | not clean → **Aeneas route skipped** |
| **Aeneas** (OCaml, Son Ho, 2026-08-26) | current | (depends on Charon) | skipped with Charon |

**Finding:** the FV-tooling ecosystem has *very uneven* supply-chain hygiene.
Prusti's stale binary/tree carries an arbitrary-code-execution CVE; Creusot is
clean; Charon is in between. For an opsec-sensitive machine, prefer the **prebuilt
official Verus binary**, and build source tools only after a `cargo audit`, ideally
in a throwaway VM — not the host.

## Status of the other routes (interrupted by a host crash)

- **Creusot** (clean, current): its Rust workspace compiled, but its installer
  tried to create its own `opam` switch + install system packages via brew
  non-interactively, which failed. It should instead be pointed at the machine's
  existing `why3`/`z3` (`--external` options). A host crash then wiped the scratch
  build. **Re-runnable**: install `nightly-2026-08-03`, `cargo run --bin
  creusot-install -- --external why3 --external z3`, then `cargo creusot` the file.
- **Aeneas → F\***: **skipped** on this host because its Charon frontend has 11 CVEs.
  It is the highest-leverage route (heap disappears; lands in talkrypt's existing
  F\* toolchain) and worth doing **in a VM**.

## Recommendation

1. **Proven now:** the paradigm change works — Verus discharges the nested-heap
   totality Kani cannot. This closes the "is it even possible?" question.
2. **To land it in-repo, without changing the implementation:** pursue **Aeneas →
   F\*** (zero source change; reuses the F\* CI already proving `GroupAuth.fst`) or
   **Prusti** (annotations on real Rust) — both **in a throwaway VM**, given the
   supply-chain findings above.
3. **Consider a bounded implementation next** (separate note): if the wire types
   used fixed-capacity, heap-free buffers (`heapless`/arrayvec-style, capped by the
   already-enforced `MAX_FRAME`), the decoders would become flat — and then even
   *Kani/CBMC* verifies them directly (as it already does for the fixed-array
   `VouchTarget`). That trades a little allocation flexibility for making the whole
   parser surface BMC-tractable. Worth weighing against the deductive-tool route.

## Reproducible artifact (Verus harness)

```rust
use vstd::prelude::*;
verus! {
pub struct Item { pub label: Vec<u8>, pub data: Vec<u8> }
pub struct Doc { pub items: Vec<Item> }
pub fn decode(bytes: &[u8]) -> Option<Doc> {
    if bytes.len() == 0 { return None; }
    let n: usize = bytes[0] as usize;
    let mut pos: usize = 1;
    let mut items: Vec<Item> = Vec::new();
    let mut i: usize = 0;
    while i < n
        invariant pos <= bytes.len(), i <= n, decreases n - i,
    {
        if pos >= bytes.len() { return None; }
        let ll: usize = bytes[pos] as usize; pos = pos + 1;
        if ll > bytes.len() - pos { return None; }
        let mut label: Vec<u8> = Vec::new();
        let mut j: usize = 0;
        while j < ll
            invariant pos + ll <= bytes.len(), pos <= bytes.len(), j <= ll, decreases ll - j,
        { label.push(bytes[pos + j]); j = j + 1; }
        pos = pos + ll;
        if pos >= bytes.len() { return None; }
        let dl: usize = bytes[pos] as usize; pos = pos + 1;
        if dl > bytes.len() - pos { return None; }
        let mut data: Vec<u8> = Vec::new();
        let mut k: usize = 0;
        while k < dl
            invariant pos + dl <= bytes.len(), pos <= bytes.len(), k <= dl, decreases dl - k,
        { data.push(bytes[pos + k]); k = k + 1; }
        pos = pos + dl;
        items.push(Item { label, data }); i = i + 1;
    }
    Some(Doc { items })
}
} // verus!
fn main() {}
```
