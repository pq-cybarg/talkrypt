# Vendored `superboring` 0.1.15 — pinned, verbatim (no source patch)

Local vendored copy of `superboring` 0.1.15, applied via `[patch.crates-io]`.
In the graph **only** under the `nym` feature (it is jwt-simple 0.13's `pure-rust`
PQ-JWT backend).

## Status: pinned, UNMODIFIED

This crate was **previously** vendored at 0.1.11 with a source patch that widened its
`ml-dsa` requirement (from a conservative `=0.1.0-rc.11`) to unify on the released
`ml-dsa 0.1.1` that talkrypt's own ML-DSA-87 identity uses. **That patch is obsolete:**
superboring **0.1.15** declares `ml-dsa = "0.1.1"` natively, so there is nothing left to
reconcile and the vendored copy is now a **verbatim** 0.1.15.

We **updated** (0.1.11 → 0.1.15) rather than dropping the vendored copy, and keep it
under `[patch]`, deliberately: superboring is a crypto-adjacent dependency (PQ-JWT /
ML-DSA), so retaining a pinned, in-tree, inspectable copy preserves supply-chain control
— if an advisory lands on it we can re-patch immediately instead of waiting on upstream.

## Re-vendoring

To refresh for a new upstream version: re-copy the crate, re-check that no source patch
is needed (`ml-dsa` still unifies with talkrypt's), rebuild `--features nym`, re-run
`scripts/audit-deps.sh`.
