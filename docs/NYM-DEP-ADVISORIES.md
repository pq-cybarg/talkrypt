# Nym transitive-dependency advisories — upstream report (DEFERRED)

**Status:** tracked, not yet reported. Draft + send to Nym *after* talkrypt's own
work is done. None of these affect talkrypt's content crypto — they are scoped to
the **optional `nym` mixnet transport** (feature `nym`, absent from the default and
`tor` builds). talkrypt's end-to-end AEAD/KEM/signature layer is RustCrypto
(`aes-gcm`, `ml-kem`, `ml-dsa`, `sha3`), **not** libcrux, and rides *above* any
transport. These are recorded so the ignores in `deny.toml` / `scripts/audit-deps.sh`
are auditable and get dropped when the `nym-sdk` pin (rev `7cee643`) advances to a
tree with patched libcrux.

## Advisories to report upstream (all via `libcrux-psq → nym-crypto → nym-sdk`)

| Advisory | Crate (locked) | Issue | Upstream fix | Blocked by |
|---|---|---|---|---|
| RUSTSEC-2026-0211 | libcrux-aesgcm 0.0.7 | Non-constant-time AES-GCM auth-tag check (timing side-channel) | none published | — |
| RUSTSEC-2026-0209 | libcrux-aesgcm 0.0.7 | AAD length limit not enforced | none published | — |
| RUSTSEC-2026-0207 | libcrux-sha3 0.0.8 | Incremental portable SHAKE wrong output on multiple squeezes | 0.0.10 | nym pins `^0.0.8` |
| RUSTSEC-2026-0208 | libcrux-sha3 0.0.8 | Potential panic in AVX2 SHAKE-256 | 0.0.10 | nym pins `^0.0.8` |
| RUSTSEC-2026-0212 | libcrux-secrets 0.0.5 | Possibly-incorrect constant-time swap/select on aarch64 | 0.0.6 | nym pins `^0.0.5` |
| RUSTSEC-2026-0124 | libcrux-chacha20poly1305 0.0.7 | Panic on overlong ciphertext buffer | 0.0.8 | nym pins `^0.0.7` |
| RUSTSEC-2026-0125 | libcrux-ml-dsa 0.0.8 | AVX2 signature-verification edge case | 0.0.9 | nym pins `^0.0.8` |
| RUSTSEC-2026-0126 | libcrux-ml-dsa 0.0.8 | Related unsoundness | 0.0.9 | nym pins `^0.0.8` |

The `libcrux-aesgcm` crate has also been **renamed to `libcrux-aes`** (RUSTSEC-2026-0210,
informational); nym-crypto still depends on the old name.

## Ask for Nym
Bump the `libcrux-*` dependency set in `nym-crypto`/`libcrux-psq` to the patched
releases above (and migrate `libcrux-aesgcm` → `libcrux-aes`), then cut a rev
talkrypt can re-pin to.

## talkrypt-side follow-up
When Nym publishes such a rev: bump the `nym-sdk` pin in `crates/transport/Cargo.toml`,
`cargo update`, then **remove** the corresponding entries from `deny.toml [advisories].ignore`
and the `AUDIT_IGNORES` list in `scripts/audit-deps.sh`, and confirm `cargo audit` +
`cargo deny check` stay green.
