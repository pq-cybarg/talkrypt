# Vendored, patched `nym-validator-client` 2.0.0 — bip32 ^0.5 → 0.6

Standalone, de-workspace-ified copy of nym's `common/client-libs/validator-client`
(@ nym rev `e416f724`), applied via `[patch."https://github.com/nymtech/nym"]`. The
**last** nym crate pulling the old EC stack.

## Why

nym-validator-client has a **direct `bip32 ^0.5` dependency** (for HD-wallet
`XPrv::derive_from_path` on the Cosmos signing path) → `k256 0.13` → `elliptic-curve
0.13` → **`crypto-bigint 0.5.5`** (RUSTSEC-2026-0387). bip32 0.5 is also what broke:
once our vendored `cosmrs` moved to bip32 0.6, nym-validator-client's bip32 0.5 lost the
`secp256k1` feature-unification cosmrs used to provide (`XPrv` became "configured out").

## The change

`Cargo.toml`: **`bip32 "0.5" -> "0.6"`** (bip32 0.6 rides k256 0.14 / crypto-bigint 0.7,
and re-unifies with cosmrs's own vendored bip32 0.6 — `XPrv` and
`cosmrs::bip32::DerivationPath` are the same version again). bip32 0.6 dropped the `std`
feature (it's std-by-default); its `default = ["secp256k1"]` provides `XPrv`.

`src/signing/mod.rs`: bip32 0.6's `XPrv::derive_from_path` takes `&[u8]` (not
`impl AsRef<[u8]>` by value as 0.5 did) → pass `seed.as_ref()`. (One line; the rest of
`src/` is verbatim.)

De-workspace-ified with all external deps pinned to nym's own
`[workspace.dependencies]`; the many internal nym contract-common crates stay git at the
same rev. Drop this once nym bumps bip32 upstream.
