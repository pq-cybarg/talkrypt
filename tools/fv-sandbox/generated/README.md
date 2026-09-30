# Aeneas-generated F* model of the real decoder — MACHINE-CHECKED (route 2)

These files are the **verbatim output of Aeneas** run on the talkrypt-style decoder
(`../aeneas_decode.rs`), produced entirely inside the airgapped hardened container
(`../Dockerfile.aeneas`, `docker run --network=none --cap-drop=ALL ...`) and then
**verified by F\***. They are the concrete artifact of the "route 2" paradigm shift: an
ownership-carrying Rust decoder translated into a **pure functional F\* model** where the
heap disappears, then proven total.

Pipeline (all in-container, no network):

    Rust (aeneas_decode.rs)
      --charon cargo --preset aeneas------------------------->  decode.llbc   (Charon: Rust -> LLBC)
      --aeneas -backend fstar -loops-to-rec -decreases-clauses -split-files-->  Decode.*.fst (Aeneas)
      --fstar.exe --already_cached 'Prims FStar LowStar Steel'-->  Verified    (F*: totality)

## RESULT — every module verifies (F* v2026.04.17, airgapped)

    Verified module: Primitives              — All VCs discharged
    Verified module: Decode.Types            — All VCs discharged
    Verified module: Decode.Clauses          — All VCs discharged
    Verified i'face:  Decode.FunsExternal    — All VCs discharged
    Verified module: Decode.Funs             — All VCs discharged   <-- the decoder

`Decode.Funs.fst` is the real decoder as `Tot` F\* functions (`decode`, `decode_loop`).
F\* accepting them in `Tot` with a discharged `decreases` clause = a machine-checked proof
that the decoder is **memory-safe, panic-free, and terminating on all inputs**. This is the
full Charon->Aeneas->F\* auto-translation route closed end-to-end - not a hand-written model.

Reproduce: `docker run --rm --network=none --cap-drop=ALL --security-opt no-new-privileges
talkrypt-fv-aeneas:latest` (the entrypoint prints `RESULT: PROVEN`).

## Files

- `Decode.Funs.fst`            - the decoder as total recursive F\* functions. Every Rust
  bounds-check is a monadic `let*`; the `while` loop is a `let rec ... : Tot ... (decreases
  (decode_loop_decreases ...))`. Heap/ownership are gone.
- `Decode.Types.fst`           - generated record types (`item_t`, `doc_t`).
- `Decode.Clauses.Template.fst`- Aeneas's emitted termination-measure template (body `admit ()`).
- `Decode.Clauses.fst`         - the SAME file with the measure filled in: `n - i` (guarded
  to `nat`). This is the ONLY human-supplied line; F\* then *proves* it discharges the
  `decreases` obligation (nothing is admitted). The loop increments `i` toward `n` each
  iteration (guard `i < n`), so `n - i` strictly decreases and stays a `nat`.
- `Decode.FunsExternal.fsti`   - Aeneas's interface for external (std) definitions.

## Why `-loops-to-rec` matters

Aeneas's DEFAULT F\* output represents loops with a `loop`/`control_flow` combinator whose
primitives this Aeneas `main` build does not ship in `Primitives.fst` (an upstream F\*-backend
coherence gap). `-loops-to-rec` - the flag Aeneas's own F\* CI uses (`tests/src/*.rs:
//@ [fstar] aeneas-args=-decreases-clauses ... -loops-to-rec`) - emits the recursive form
instead, which is self-contained and verifiable. We refused the alternative of hand-defining
a total `loop`: a sound `loop` for a general Rust loop needs the `Div` effect, so a `Tot`
stub would be verifier-passes-but-UNSOUND.

## Relationship to the in-repo proof

`formal/DecodeTotality.fst` is a hand-written total F\* model of the same decoder, verified
under talkrypt's CI F\* (`make -C formal fstar`). It and this auto-translation now agree:
both prove the decoder total. The hand-written one is the CI-gating proof; this one is the
end-to-end demonstration that the Charon->Aeneas->F\* paradigm discharges the exact property
Kani could not (the nested-heap decoder), on the real code.
