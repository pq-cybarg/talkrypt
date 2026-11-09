# Vendored, patched `cosmrs` 0.22.0 — secp256k1 signing stack → crypto-bigint 0.7

Local, source-patched copy of `cosmrs` 0.22.0, applied via `[patch.crates-io]` in
the workspace root `Cargo.toml`. Only in the dependency graph under the **`nym`**
feature (Nym's cosmos / zk-nym bandwidth-credential path).

## Why it exists

`cosmrs` 0.22.0 pins the **old RustCrypto EC stack** — `ecdsa 0.16`, `k256 0.13`,
`bip32 0.5` — which resolve to `elliptic-curve 0.13 → crypto-bigint 0.5.5`, the
crate flagged by **RUSTSEC-2026-0387** (multiple timing-variability issues in
operations intended to be constant-time; fixed only in `crypto-bigint >= 0.7.6`).
No released `elliptic-curve` that `cosmrs 0.22` accepts has moved off
crypto-bigint 0.5, and `cosmrs 0.22.0` is the latest release (Nym's `develop`
still pins it). So we patch locally until upstream moves.

Note this is **not load-bearing** for talkrypt: content is sealed by the PQ Double
Ratchet (ML-KEM-1024 + ML-DSA-87) above the transport; this secp256k1 path only
signs Cosmos transactions to mint zk-nym bandwidth credentials. It is also absent
from the default and `tor` builds. We fix it for a clean audit + defense in depth.

## The change

`Cargo.toml` only — bump the crypto deps to the **released** newer majors that
already ride `elliptic-curve 0.14 → crypto-bigint 0.7.10` (the patched line, and
already in this workspace via Nym's own `ecdsa 0.17`):

```diff
- ecdsa      = "0.16"
+ ecdsa      = "0.17"
- k256       = "0.13"   (features ecdsa, sha256)
+ k256       = "0.14"
- bip32      = "0.5"
+ bip32      = "0.6"
- rand_core  = "0.6"
+ rand_core  = "0.9"
- signature  = { version = "2", features = ["std"] }
+ signature  = { version = "3", features = ["alloc"] }   # 3 dropped `std`
```

and one source line in `src/crypto/secp256k1/signing_key.rs`: ecdsa 0.17's
`SigningKey::random` takes an infallible `CryptoRng`, while rand_core 0.9's `OsRng`
is fallible (`TryRngCore`), so the call becomes
`SigningKey::random(&mut OsRng.unwrap_err())` (`.unwrap_err()` adapts the fallible
OS RNG to an infallible one, panicking only on OS RNG failure — the same contract
rand_core 0.6's `OsRng` had). **No crypto primitive is hand-written** — the curve
arithmetic is entirely upstream-released k256 0.14 / elliptic-curve 0.14.

## Re-vendoring

Verbatim `cosmrs` 0.22.0 with only the `Cargo.toml` dep bumps (marked `TALKRYPT
PATCH`) and the one `OsRng` adapter line. To refresh for a new upstream: re-copy,
re-apply, rebuild `--features nym`, re-run `scripts/audit-deps.sh`. Drop this patch
once Nym/cosmrs ship on crypto-bigint 0.7+.
