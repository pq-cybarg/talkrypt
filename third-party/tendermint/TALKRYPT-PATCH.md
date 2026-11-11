# Vendored, patched `tendermint` 0.40.4 — secp256k1 keys → k256 0.14

Local, source-patched copy of `tendermint` 0.40.4, applied via `[patch.crates-io]`.
In the graph **only** under the `nym` feature (cosmrs/tendermint-rpc pull it).

## Why

tendermint 0.40.4 (the latest release) pins **`k256 0.13`** for its secp256k1
consensus keys → `elliptic-curve 0.13` → `crypto-bigint 0.5.5` (RUSTSEC-2026-0387).

## The change

`Cargo.toml`: `k256 0.13 -> 0.14`, and `signature 2 -> 3` (k256 0.14's `VerifyingKey`
impls the `signature 3` `Verifier` trait). tendermint touches `k256` in only a handful
of sites — type re-exports (`SigningKey`/`VerifyingKey`/`Signature` aliases) plus
`Signature::try_from`/`from_der` and one `signature::Verifier::verify` call in
`crypto/default/signature.rs` (the sole external `signature`-crate use; ed25519 goes
through `ed25519-consensus`, untouched). No source change was required beyond the
version bumps unifying. Drop this once tendermint ships on k256 0.14.
