# Formal specification — at-rest seal, KDF seam, and release-seed custody

Scope: the passphrase/hardware **at-rest seal** (`core/src/seal.rs`, the `TKS1`
format), the **release-seed seal** (`crates/relsign/src/seal.rs`, `.seed.enc`), the
**KDF seam** (Argon2id / PBKDF2-HMAC-SHA384) shared by both, and the **QRL-2.0-style
seed encodings** (`crates/relsign/src/seed.rs`). Companion to the threat model and FV
obligations in [`plans/0004-keyvault.md`](plans/0004-keyvault.md).

This document states the properties precisely and records, for each, **how** it is
discharged: machine-checked (Kani), exhaustively property-tested (proptest), unit-
tested, or **assumed** of an upstream-proven primitive. "NOT FIPS-validated / audited"
throughout — "FIPS-approved KDF" names the algorithm (PBKDF2, SP 800-132), not a
validated module.

## 1. Primitives (assumed, not re-proven here)

- **AEAD** `aead::seal/open` = AES-256-GCM (FIPS 197 + SP 800-38D). Assumed IND-CCA2
  + INT-CTXT for a per-seal-unique `(key, nonce)`. Nonces are 96-bit, drawn fresh from
  the OS CSPRNG per seal.
- **KDF** ∈ { Argon2id (RFC 9106), PBKDF2-HMAC-SHA384 (SP 800-132) }. Assumed a
  one-way, salt-separating password hash; memory-hardness (Argon2id) / iteration cost
  (PBKDF2) are configuration, not correctness.
- **Keccak** SHAKE256 (FIPS 202) for the seed address; **ML-DSA-87** (FIPS 204) /
  **SLH-DSA-SHA2-256s** (FIPS 205) for signatures — EUF-CMA assumed (proven upstream;
  the group-auth reduction is F\*-checked separately, see `formal/`).

## 2. Definitions

Let `K` be a KDF descriptor, `s` a 16-byte salt, `n` a 12-byte nonce, `pw` a
passphrase, `seed ∈ {0,1}^256` the secret, `pk` its public key, `hdr` the serialized
header. `kdf(K, pw, s) → {0,1}^256`. `Seal(pw, K, seed) = hdr ‖ AEAD_seal(k, n, seed,
aad=hdr)` where `k` is derived from the present factors incl. `kdf(K,pw,s)`.
`Unseal(pw, blob)` parses `blob → hdr'`, recomputes `k'`, returns `AEAD_open(k', n,
ct, aad=hdr')`.

## 3. Properties

**P1 — Round-trip (correctness).** ∀ `pw, K, seed`: `Unseal(pw, Seal(pw, K, seed)) =
Ok(seed)`.

**P2 — Confidentiality at rest.** Given only `blob`, recovering `seed` is as hard as
breaking the AEAD or inverting the KDF on `pw`. (Reduction to §1; no independent
claim.)

**P3 — Fail-closed totality.** `Unseal`/`parse` are **total** on arbitrary bytes:
they never panic, over-read, or over-allocate, and return `Err` (never a partial or
wrong `seed`) on any malformed, truncated, wrong-passphrase, or tampered input.

**P4 — KDF-agnostic portability.** The header **self-describes** `K` (id + params),
so `Unseal` on any platform that can run `K` recovers `seed` regardless of that
platform's *default* KDF. A blob sealed under Argon2id unseals where PBKDF2 is the
default and vice-versa.

**P5 — Backward compatibility (core seal).** A pre-existing (`FLAG_KDF`-absent) blob
decrypts unchanged, read with `LEGACY_KDF` (Argon2id 19 MiB/2/1). A new seal using
exactly the legacy KDF is **byte-identical** to legacy output (descriptor omitted).

**P6 — No secret in blob.** `seed` (and `kdf(K,pw,s)`) never appear in `blob`; the
header stores only public fields (`K`, `s`, `n`, `pk`, tier/flags, wrapped-KEK).

**P7 — Zeroization.** The derived key, the recovered `seed` buffer, and all key
scratch are zeroized on **every** control-flow path (success, each `Err`, and
unwind via `Drop`/`Zeroizing`).

**P8 — AAD binding (tamper/strip-evidence).** `aad = hdr` exactly, so altering any
header field — the KDF descriptor, salt, nonce, tier/flags, or stripping the
passphrase/hardware factor bit — changes the AAD and fails `AEAD_open`.

**P9 — QROM/L5 custody baseline (core seal).** A hardware-ONLY seal is refused unless
the wrapper attests a symmetric (QROM-safe) wrap or the caller explicitly opts into
the classical tier; otherwise a passphrase is required, whose KDF output is mixed into
the KEK so the stored contents stay quantum-safe at rest.

**P10 — Seed encoding bijection (relsign seeds).** `hexseed ↔ mnemonic ↔ (descriptor,
entropy)` are mutually inverse; `address = Q ‖ hex(SHAKE256(desc‖pk)[-24..])` is a
deterministic function of `(desc, pk)`. All parsers are total and fail-closed on bad
words / lengths / unknown scheme.

## 4. Verification status

| Prop | Core seal (`core/src/seal.rs`) | Release seed seal (`relsign`) |
|------|--------------------------------|-------------------------------|
| P1 | unit: roundtrips (per KDF) | lib: `seal_unseal_roundtrips`, matrix |
| P2 | reduction to §1 (assumed) | reduction to §1 (assumed) |
| P3 | **Kani** `read_kdf_never_panics` (flat KDF decoder) **+ `header_parse_model_never_panics`** (flat heap-free model of the WHOLE header parse, bound to the real encoder by `header_model_accepts_a_real_seal_and_reports_flags`) **+ proptest** `unseal_..._never_panic_on_arbitrary_bytes` (the literal function; its nested-heap `Vec` returns are CBMC-intractable — SECURITY-AUDIT §5) | unit: `arbitrary_bytes_never_panic_and_fail_closed`; text parser is `from_utf8`-based → proptest/unit, not Kani (documented CBMC limit) |
| P4 | unit: `pbkdf2_kdf_roundtrips`, `explicit_argon2_preset_roundtrips`; **Kani** `write_then_read_kdf_roundtrips` | **matrix** `full_kdf_x_algo_matrix_roundtrips_and_fails_closed` |
| P5 | unit: `default_seal_omits_descriptor_*`, `explicitly_passing_the_legacy_kdf_is_byte_identical_to_default` | n/a (new format) |
| P6 | unit: `no_plaintext_seed_in_blob` | lib: `no_plaintext_seed_in_blob` |
| P7 | **type-enforced** `Zeroizing` on every secret buffer (derived key, KEK, unwrapped-KEK, pw-key): the compiler mechanically inserts the zeroizing `Drop` on ALL exit paths — success, every `?`/early-return, and unwind — so no path can skip it (strictly stronger than the former manual `.zeroize()`, which a mid-function error could bypass). Trusted base: the `zeroize` crate's audited `Drop`. | same — `Zeroizing<[u8;32]>` for the derived key + recovered seed |
| P8 | unit: `tampered_header_or_ciphertext_fails`, `kdf_mismatch_or_truncated_descriptor_fails_closed` | lib: `tampered_header_or_ct_fails_closed` |
| P9 | unit: `qrom_l5_hardware_only_rule_all_modes`, `wrong_device_cannot_unwrap` | n/a |
| P10 | n/a | lib: `mnemonic_roundtrips_both_schemes`, `mnemonic_and_hexseed_agree`, `address_is_q_prefixed_24_bytes_and_stable`, `parsing_is_total_and_fail_closed` |

**Kani harnesses run in CI** (`.github/workflows/formal.yml`): `read_kdf_never_panics`,
`write_then_read_kdf_roundtrips`, and `header_parse_model_never_panics`.

Both obligations that CBMC cannot discharge directly are now **mechanized**:

- **P3 (full header decode).** The literal decoder's nested-heap `Vec` return blows up
  CBMC (SECURITY-AUDIT §5), so — exactly as `linkage_fv` does for the chain decoders —
  a **flat heap-free model** (`header_parse_model`) issues the identical `Reader` call
  sequence and is **Kani-proven total**; `header_model_accepts_a_real_seal_and_reports_
  flags` binds the model to the real encoder, and the `unseal_..._never_panic` proptest
  proves the literal function total. Totality of the parse is thus a theorem (model) +
  property (literal), the strongest available without re-implementing the decoder flat.
- **P7 (zeroization).** Mechanized by the **type system**: every secret buffer is
  `Zeroizing`, so the compiler inserts the wiping `Drop` on all exit paths (success,
  `?`, unwind) — a machine-checked, all-paths guarantee. A bespoke **Verus** proof is
  *not* tractable here because the secret flows through external crypto crates
  (`argon2`, `pbkdf2`, `aes-gcm`) that carry no Verus specs; the `Zeroizing` ownership
  discipline is the stronger, sound mechanization (the `zeroize` crate's `Drop` is the
  trusted base, as elsewhere in the codebase).
