# Vendored, patched `nym-crypto` 2.0.0 — jwt-simple ^0.12 → 0.13

Standalone, de-workspace-ified copy of nym's `common/crypto` (nym-crypto 2.0.0 @ nym
rev `e416f724`), applied via `[patch."https://github.com/nymtech/nym"]`. One of **two**
nym crates we patch (the other is `nym-upgrade-mode-check`); all other nym crates still
come from the pinned git rev and unify against this copy (same name + version 2.0.0,
identical public API).

## Why

nym-crypto pins **`jwt-simple ^0.12`**. jwt-simple 0.12 rides the old `k256/p256/p384
0.13` EC stack → `crypto-bigint 0.5.5` (RUSTSEC-2026-0387). The real, upstream-released
**jwt-simple 0.13** already runs on the modern 0.14 curves — but cargo won't pull it
while nym-crypto's `^0.12` constraint stands.

## The change

The ONLY substantive change is loosening the pin: **`jwt-simple = "0.13"`** (keeping
`default-features = false, features = ["pure-rust"]`, i.e. the superboring backend —
now 0.1.14, which declares `ml-dsa = "0.1.1"` natively, obsoleting our former
`superboring` patch). nym-crypto uses jwt-simple for **Ed25519 / EdDSA only**
(`Ed25519PublicKey` / `Ed25519KeyPair` / `Edwards25519KeyPair`), whose public API is
identical across 0.12 → 0.13, so the crate `src/` is copied **verbatim** and compiles
unchanged.

The Cargo.toml is a de-workspace-ified form of the original (which used `{ workspace =
true }` inheritance): every external dep is pinned to the EXACT version from nym's own
`[workspace.dependencies]` so the graph stays unified with the rest of the git nym
crates; the two internal nym deps (`nym-sphinx-types`, `nym-pemstore`) stay git at the
same rev. Drop this once nym bumps jwt-simple to 0.13 upstream.
