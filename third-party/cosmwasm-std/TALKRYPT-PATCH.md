# Vendored, patched `cosmwasm-std` 2.2.2 — test-mock RNG → rand 0.10

Local, source-patched copy of `cosmwasm-std` 2.2.2, applied via `[patch.crates-io]`.
In the graph **only** under the `nym` feature.

## Why

cosmwasm-std is the paired consumer of this workspace's patched `cosmwasm-crypto`
(whose `ed25519_batch_verify` now rides ed25519-zebra 5 / rand_core 0.10). cosmwasm-std's
native-only test-mock backend (`src/testing/mock.rs`, compiled unconditionally on
non-wasm via `#[cfg(not(target_arch = "wasm32"))]`) calls `ed25519_batch_verify(&mut
OsRng, …)` with rand_core 0.6's `OsRng`, which no longer satisfies the rand_core-0.10
`CryptoRng` bound.

## The change

`Cargo.toml`: the non-wasm `rand_core 0.6.4` dev/test dep → `rand 0.10`.
`src/testing/mock.rs`: `rand_core::OsRng` → `rand::rng()`. rand 0.10 merged away the
`OsRng` struct; `rand::rng()` (ThreadRng, OS-seeded ChaCha12, `CryptoRng`) is its
successor and the designed choice for ephemeral/blinding randomness like batch-verify.
This is the crate's only rand usage. Drop once cosmwasm-crypto/cosmwasm-std move to a
unified modern rand upstream.
