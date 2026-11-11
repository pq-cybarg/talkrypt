# Vendored, patched `ssh-key-fork-arti` 0.6.7 — optional NIST-curve deps → 0.14

Local, source-patched copy of `ssh-key-fork-arti` 0.6.7 (Arti's fork of `ssh-key`,
pulled by `tor-key-forge` for onion-service key handling), applied via
`[patch.crates-io]`. In the graph under the **`tor`** feature.

## Why

ssh-key-fork-arti declares **optional** `p256 0.13 / p384 0.13 / p521 0.13` ECDSA
dependencies (behind its `p256`/`p384`/`p521` features). Those curves pull
`elliptic-curve 0.13` → **`crypto-bigint 0.5.5`** (RUSTSEC-2026-0387). cargo records all
*declared* optional deps in `Cargo.lock` regardless of activation, so after the nym-side
EC migration this was the **last lockfile source** of crypto-bigint 0.5.5 — flagged by
`cargo audit` even though it is compiled in **zero** talkrypt builds (no build enables
the NIST-curve features; Arti uses ssh-key for ed25519/rsa host keys).

## The change

`Cargo.toml` only: **`p256 / p384 / p521 0.13 -> 0.14`**. Because the curve-gated code is
never compiled in any talkrypt build, this is a pure dependency-version bump — it moves
the LOCKED (but unused) curves onto `elliptic-curve 0.14` / `crypto-bigint 0.7`, so
`crypto-bigint 0.5.5` disappears from the lockfile entirely and `cargo audit` is clean.
No source change. Drop once Arti/ssh-key-fork-arti bump their ECDSA deps upstream.
