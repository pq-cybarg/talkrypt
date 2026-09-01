# Aeneas-generated F* model of the real decoder (route-2 evidence)

These files are the **verbatim output of Aeneas** run on the talkrypt-style decoder
(`../aeneas_decode.rs`), produced entirely inside the airgapped hardened container
(`../Dockerfile.aeneas`, `docker run --network=none --cap-drop=ALL ...`). They are the
concrete artifact of the "route 2" paradigm shift: an ownership-carrying Rust decoder
translated into a **pure functional F\* model** where the heap disappears.

Pipeline (all in-container, no network):

    Rust (aeneas_decode.rs)
      --charon cargo --preset aeneas-->  decode.llbc            (Charon: Rust -> LLBC)
      --aeneas -backend fstar -split-files-->  Decode.Funs.fst  (Aeneas: LLBC -> F*)

Files:
- `Decode.Funs.fst`       - the decoder as total-structured F\* functions (`decode`,
  `decode_loop`, `decode_loop_body`); every Rust bounds-check is a monadic `let*`, the
  `while` loop is a `control_flow`/`loop` fixpoint. Heap/ownership are gone.
- `Decode.Types.fst`      - the generated record types (`item_t`, `doc_t`).
- `Decode.FunsExternal.fsti` - Aeneas's stub for external (std) definitions.

## What was machine-verified here (F* v2026.04.17, in-container)

- **Aeneas's runtime `Primitives.fst` type-checks**: `Verified module: Primitives /
  All verification conditions discharged successfully` (with the Aeneas
  `--already_cached 'Prims FStar LowStar Steel'` flags).
- **Charon ingests the real decoder** and emits LLBC airgapped; **Aeneas emits the
  functional model** above in ~0.6 s.

## Honest gap (why the generated model is not itself checked green here)

`Decode.Funs.fst` references two Aeneas *primitives* - `control_flow` and `loop` - that
**this Aeneas `main` build does not emit into its own `Primitives.fst`** (its
`backends/fstar/` ships only `Primitives.fst`, and that file defines neither). This is an
internal coherence gap in the specific Charon-pin / Aeneas-main / F*-release triple, not a
property of the decoder. It is NOT closed by hand-defining `loop`: a sound `loop` for a
general Rust loop needs a divergence-permitting effect (`Div`), so a hand-rolled `Tot loop`
would be *verifier-passes-but-unsound* - the exact thing we refuse to ship.

## Where the real proof lives

The totality property this route would establish is **already machine-checked, and more
soundly**, in `formal/DecodeTotality.fst`: a hand-written *total* F\* model of the same
decoder, verified under talkrypt's CI F\* (`make -C formal fstar`). It carries an explicit
`decreases` measure - a genuine termination proof - where Aeneas's auto-`loop` only assumes
a divergence effect. So the in-repo proof is strictly stronger than the auto-translation's
endpoint. The auto-translation here is corroborating evidence that the paradigm works on the
real code, not the load-bearing proof.
