# Vendored, patched `rsa` 0.9.10 — RUSTSEC-2023-0071 mitigation

This is a **local, source-patched copy of `rsa` 0.9.10**, applied to the talkrypt
workspace via `[patch.crates-io]` in the root `Cargo.toml`. Because it is a
`[patch]`, the fix is applied automatically to **every build and `cargo install`**
of this workspace — there is no separate step to forget.

## Why it exists

`rsa` is pulled in transitively, **only** under the `tor` feature, by Arti's
onion-service crypto:

```
arti-client → tor-hscrypto → tor-key-forge → ssh-key-fork-arti → rsa
```

`ssh-key-fork-arti` uses `rsa` for SSH-format **key parsing / representation**
(Tor's keystore), not for RSA encryption or signing — so the vulnerable path is
not even exercised in this dependency chain, and **default (non-`tor`) builds
contain no `rsa` at all** (talkrypt's own crypto is ML-KEM-1024 / ML-DSA-87 /
AES-256-GCM; it performs zero RSA operations).

`rsa` 0.9.10 is flagged by **RUSTSEC-2023-0071** (the "Marvin Attack": potential
private-key recovery through a timing side-channel in the RSA private-key
operation). Upstream has shipped **no fixed release**, so an upgrade is not an
option — hence this source patch.

## The patch

One change, at the single chokepoint through which **every** RSA private-key
operation flows (`rsa_decrypt`, called by `rsa_decrypt_and_check`, which backs
PKCS#1 v1.5 decrypt + sign, OAEP decrypt, and PSS sign):

- **`src/algorithms/rsa.rs`** — when a caller supplies no blinding RNG, upstream
  runs the private-key modular exponentiation **unblinded** (the variable-time
  operation the Marvin attack exploits). The patch instead **blinds with the OS
  CSPRNG (`rand_core::OsRng`)**, so a private-key operation is *never* performed
  unblinded. Multiplicative blinding with a fresh random factor is the standard,
  recognized Marvin/Bleichenbacher countermeasure (it is exactly what the crate's
  own `decrypt_blinded` / `*_with_rng` APIs do).
- **`Cargo.toml`** — the `std` feature now also enables `getrandom` so
  `rand_core::OsRng` is available (Arti builds `rsa` with `std`). The unblinded
  path remains only behind `#[cfg(not(feature = "getrandom"))]`, which this
  workspace never builds.
- **`src/key.rs`** — doc comments on `decrypt`/`sign` note the blinding; no
  behavioral change there (the chokepoint does the work).

Nothing else is modified; the crate's license (`LICENSE-APACHE` / `LICENSE-MIT`)
and version are unchanged.

## Effect on advisory tooling

`cargo audit` / `cargo deny` match advisories by **crate name + version**, so they
still *report* RUSTSEC-2023-0071 against this `rsa` 0.9.10 — they cannot see that
the source has been patched. The advisory is therefore listed with a justification
in `deny.toml` and `scripts/audit-deps.sh` that points back to this file; the
ignore documents a *fixed* dependency, not an accepted-as-is risk. See
`docs/SECURITY-AUDIT.md` (R-1 / the RUSTSEC-2023-0071 entry).

## Updating

If a future `rsa` release fixes RUSTSEC-2023-0071, delete this directory, remove
the `[patch.crates-io]` entry, bump the dependency, and drop the advisory ignore.
