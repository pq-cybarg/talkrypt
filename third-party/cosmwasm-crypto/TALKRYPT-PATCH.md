# Vendored, patched `cosmwasm-crypto` 2.3.3 — secp256k1/r1 verify stack → crypto-bigint 0.7

Local, source-patched copy of `cosmwasm-crypto` 2.3.3, applied via `[patch.crates-io]`.
In the graph **only** under the `nym` feature (via nym's CosmWasm contract-interface
crates: `nym-directory-contract-common` → `cw-controllers` → `cosmwasm-std` →
`cosmwasm-crypto`).

## Why

cosmwasm-crypto 2.3.3 (and *every* released version, incl. the 3.x line) pins the
**old RustCrypto EC stack** — `ecdsa 0.16 / k256 0.13 / p256 0.13` → `elliptic-curve
0.13` → **`crypto-bigint 0.5.5`** (RUSTSEC-2026-0387, constant-time variability; fixed
only in `crypto-bigint >= 0.7.6`). There is no upstream release on the new stack, so we
forward-port it.

## The change

`Cargo.toml`:
- `ecdsa 0.16 -> 0.17`, `k256 0.13 -> 0.14`, `p256 0.13 -> 0.14` (ride elliptic-curve
  0.14 / crypto-bigint 0.7.10).
- `ed25519-zebra =4.0.3 -> 5.0.0` and `rand_core -> 0.10` (the pair zebra 5 uses), with
  the `alloc` feature (zebra 5 gates its `batch` module behind it). This keeps the whole
  tree on one modern rand_core line (no 0.6 holdout).

`src/secp256k1.rs` + `src/secp256r1.rs`: the Cosmos inputs are **already SHA-256
hashes**, so verification/recovery move from the old `DigestVerifier` + custom
`Identity256` wrapper-digest to ecdsa 0.17's **prehash API** —
`PrehashVerifier::verify_prehash(&hash, &sig)` and
`VerifyingKey::recover_from_prehash(&hash, &sig, id)` (both take `&[u8]`). This sidesteps
the digest-trait version churn entirely. Also: `normalize_s()` now returns `Self`
(not `Option`) so it's called unconditionally, with an equality check to decide the
recovery-id y-parity flip; SEC1 encoding uses the `ToSec1Point` trait (renamed from
`to_encoded_point`).

`src/ed25519.rs`: `CryptoRngCore` (dropped in rand_core 0.10) → `CryptoRng`; tests use
`rand::rng()` (ThreadRng — rand 0.10 merged away the `OsRng` struct).

**No crypto primitive is hand-written** — the curve arithmetic is entirely upstream
k256 0.14 / p256 0.14 / ed25519-zebra 5. Correctness is re-verified by this crate's own
**wycheproof + rootberg** KAT suites (secp256k1 + secp256r1), which pass against the
ported code.

## Re-vendoring

Verbatim 2.3.3 with the Cargo.toml bumps + the prehash/rand adjustments (all marked
`TALKRYPT PATCH`). Drop this once CosmWasm ships on crypto-bigint 0.7.
