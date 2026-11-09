# Vendored, patched `nym-upgrade-mode-check` 2.0.0 — jwt-simple ^0.12 → 0.13

Standalone, de-workspace-ified copy of nym's `common/upgrade-mode-check` (@ nym rev
`e416f724`), applied via `[patch."https://github.com/nymtech/nym"]`. The **second** of
two nym crates that pin `jwt-simple` (pulled transitively via
`nym-credentials-interface`).

## Why / change

Same one-line fix as `nym-crypto`: loosen **`jwt-simple ^0.12 -> 0.13`** so cargo pulls
the real jwt-simple 0.13 (modern k256/p256/p384 0.14 stack, clearing crypto-bigint
0.5.5 / RUSTSEC-2026-0387). This crate uses jwt-simple for **Ed25519 token
verification only** (`Claims` / `Token` / `verify_token` / `Ed25519PublicKey`), whose
API is stable across 0.12 → 0.13, so `src/` is copied verbatim. De-workspace-ified with
deps pinned to nym's own `[workspace.dependencies]`; internal nym deps stay git
(`nym-crypto` redirects to our patched path copy). Drop once nym bumps jwt-simple
upstream. See `third-party/nym-crypto/TALKRYPT-PATCH.md` for the full rationale.
