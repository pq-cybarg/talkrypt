# FIPS 140-3 / CNSA 2.0 self-assessment

> **This is a self-assessment, not a certification.** It is written *by the
> project* to inventory exactly what talkrypt does cryptographically and to map
> it against FIPS 140-3 and CNSA 2.0, so that an eventual *independent* lab/agency
> assessment starts from a precise, honest baseline. Nothing here is a validation.
> See the README banner and `SECURITY.md`. talkrypt is **NOT FIPS 140-validated,
> NOT CSfC-accredited, NOT NSA-approved, NOT authorized for any classification
> level, and NOT independently audited.**

Companion documents: `SECURITY-AUDIT.md` (internal security audit), `docs/CSFC.md`
(CSfC layered-architecture mapping), `docs/POSTURE.md` (KEM posture), `docs/WIRE.md`
(frozen wire format). Reproduce the algorithm inventory below with
`scripts/crypto-inventory.sh`.

---

## 1. Scope

The "cryptographic boundary" assessed here is the `talkrypt-crypto` crate plus
the key-management code in `talkrypt-core` (`descriptor.rs` custody/sealing) and
`talkrypt-server` (`keystore.rs`). Everything cryptographic is implemented once
in Rust and consumed by the CLI/TUI, the FFI, and the Android app — there is no
per-platform reimplementation.

Two build-time switches affect the assessment:

| Feature | Effect |
| --- | --- |
| *(default)* | RustCrypto primitives; hash/KDF = SHA3-384 / KMAC256 (FIPS 202). |
| `cnsa-sha2` | Hash/KDF = SHA-384 / HKDF-HMAC-SHA-384 — the exact CNSA 2.0 hash. |
| `fips` | Routes AES-256-GCM (and SHA-2) through **aws-lc-rs**, whose module is CMVP-validated. For an *actual* FIPS build, additionally enable `aws-lc-rs/fips`. |

---

## 2. CNSA 2.0 algorithm conformance

CNSA 2.0 (the NSA Commercial National Security Algorithm Suite 2.0) names a
specific quantum-resistant algorithm set. talkrypt's **default posture is
PQ-pure** (zero elliptic curve); the optional `+X25519` hybrid is defense-in-depth
and never solely load-bearing.

| CNSA 2.0 requirement | Parameter named | talkrypt uses | Parameter set | Source (crate @ version) | Conformant? |
| --- | --- | --- | --- | --- | --- |
| Symmetric block cipher | AES-256 | AES-256-GCM | 256-bit key, 96-bit nonce, 128-bit tag | `aes-gcm` 0.10.3 (or `aws-lc-rs` 1.x with `fips`) | Algorithm: **yes** |
| Key establishment (KEM) | ML-KEM-1024 | ML-KEM-1024 | FIPS 203, Category 5 | `ml-kem` 0.2.3 | Algorithm: **yes** |
| Digital signature (general) | ML-DSA-87 | ML-DSA-87 | FIPS 204, Category 5 | `ml-dsa` 0.1.0 | Algorithm: **yes** |
| Hash | SHA-384 or SHA-512 | SHA-384 *(with `cnsa-sha2`)* / SHA3-384 *(default)* | 384-bit | `sha2` 0.10.9 / `sha3` 0.10.9 | **yes with `cnsa-sha2`**; default uses SHA3-384 (FIPS 202, not the CNSA-named SHA-2) |
| Signature (stateful hash-based, firmware) | LMS / XMSS | — (talkrypt is not a firmware signer) | n/a | n/a | N/A |

**Honest nuance — the hash.** CNSA 2.0 names **SHA-384/512** (SHA-2). talkrypt's
*default* hash and KDF are **SHA3-384 / KMAC256** (FIPS 202 — an approved hash
family, but *not* the SHA-2 that CNSA 2.0 specifies). Build with `--features
cnsa-sha2` for strict CNSA 2.0 hash conformance (SHA-384 + HKDF-HMAC-SHA-384).
This is the only place the default deviates from the CNSA 2.0 *parameter* set,
and it deviates *toward* a different NIST-approved hash, not a weaker one.

**Parameter-set floor is enforced in code — against declared parameters, not a
self-declared tag.** `SuiteRegistry::register` rejects a suite two ways: (1) its
self-reported `SecurityLevel` must meet the floor, and (2) at the default
post-quantum floor its *declared algorithm parameters* — parsed from the suite id
by `suite::meets_cnsa_floor` — must be ML-KEM-1024, AES-256-GCM, a ≥384-bit hash,
and (if it signs) ML-DSA-87. So a suite cannot pass the floor by tagging itself
`PostQuantum` while naming AES-128 / ML-KEM-768 / ML-DSA-65 — it is rejected
regardless of the tag (`suite.rs::mislabeled_subfloor_suite_rejected_even_when_tagged_post_quantum`).
Lowering the floor (`set_floor`) is the single explicit, visible escape hatch.
Independently, the `ml-kem`/`ml-dsa` crates at these versions expose only the
Category-5 parameter sets, and `crate::aead` is typed `&[u8; 32]`, so a shorter
(AES-128-length) key cannot even be passed to the AEAD. Canonical suite IDs:

```
tk.dr.mlkem1024+pad.aes256gcm.sha3-384.mldsa87      (default: PQ-pure, padded)
tk.dr.mlkem1024+x25519.aes256gcm.sha3-384.mldsa87   (hybrid, +X25519 DiD)
tk.noise.mlkem1024+pad.aes256gcm.sha3-384           (PQ-Noise session)
```

With `cnsa-sha2` the `sha3-384` token becomes `sha384`.

---

## 3. FIPS 140-3 self-assessment by area

FIPS 140-3 (ISO/IEC 19790:2012) defines 11 areas. A *validation* is performed by
an accredited CMVP lab — **this is not that.** Below is an honest gap analysis:
what talkrypt does today, and the concrete delta to a validatable module.

| # | Area | talkrypt today | Gap to validation |
| --- | --- | --- | --- |
| 1 | Cryptographic module specification | Boundary defined informally (§1); algorithms inventoried (§2). | A formal Security Policy document; an explicit, testable module boundary. |
| 2 | Ports & interfaces | Library API (`CryptoSuite` trait) + FFI; data/control/status separated by type. | Documented logical interfaces with data-path/control-path/status separation per 140-3. |
| 3 | Roles, services, authentication | Single implicit user role; services = encrypt/decrypt/sign/verify/derive. | Defined roles & approved/non-approved service list; the module is not access-authenticated. |
| 4 | Software/firmware security | Pure-Rust, memory-safe; pinned `Cargo.lock`; no `unsafe` in crypto paths (RustCrypto). | Integrity test of the module image at load (approved digest); a defined module image. |
| 5 | Operating environment | Runs as an unprivileged library on a general-purpose OS. | A defined "modifiable operational environment" entry, OS/version bounds. |
| 6 | Physical security | N/A (software module). | N/A. |
| 7 | Non-invasive security | Decryption is **uniform-failure**; decrypt runs on cloned state (no partial-state leak). Not formally constant-time across all primitives. | Side-channel (timing) review of each primitive; constant-time guarantees. |
| 8 | Sensitive security parameter (SSP) management | ML-DSA seed in `Zeroizing`; **session symmetric secrets zeroized on drop** (ratchet + Noise; per-message keys in `Zeroizing` — SECURITY-AUDIT F-3, resolved); persistent keys sealed with Argon2id + AES-256-GCM; `OsRng` (`getrandom`) for keygen. | An approved DRBG with health tests; a documented SSP lifecycle table. |
| 9 | Self-tests | **Power-on self-tests implemented** (`talkrypt_crypto::self_test` / `ensure_self_tested`, SECURITY-AUDIT R-5): AES-256-GCM + hash KATs, ML-KEM/ML-DSA pairwise-consistency, KDF determinism — run once at start-up (CLI `main`, suite-registry init, FFI keygen) and **abort on failure**. Plus KAT-locked KDF/wire vectors, property tests, a Kani proof. | Per-operation conditional self-tests on every keygen (vs once at start-up); a CAVP-traceable KAT set; documented POST in the Security Policy. |
| 10 | Life-cycle assurance | Versioned, tested (211 tests), fuzzed wire codec, Kani-proven decoder, frozen+KAT-locked wire format. | Configuration-management, delivery, and operator-guidance documents per 140-3; CAVP test evidence. |
| 11 | Mitigation of other attacks | Replay rejection (bounded skip), AEAD AAD-bound headers, wire padding for frame-indistinguishability, invite-token PSK + safety-number MITM mitigation. | Formal documentation of mitigations and their limits. |

### Approved-algorithm validation status

Algorithm *choice* is CNSA 2.0-aligned (§2). Algorithm *implementation*
validation (CAVP) is separate:

- **Default build (RustCrypto):** the `ml-kem`, `ml-dsa`, `aes-gcm`, `sha2`,
  `sha3`, `hkdf`, `argon2` crates are **not CAVP-validated**. They are
  widely-used, audited-in-the-community Rust implementations, but they carry no
  CAVP certificate.
- **`--features fips` (aws-lc-rs):** routes AES-256-GCM (and SHA-2) through
  **aws-lc-rs**, which ships a **CMVP-validated** cryptographic module (AWS-LC;
  the certificate is listed on the NIST CMVP Validated Modules list — verify the
  current number there). That validation belongs to the *backend vendor*. Linking
  it does **not** make talkrypt-as-a-whole a validated module, and ML-KEM/ML-DSA
  are still RustCrypto even in this build.

---

## 4. Cryptographic dependency inventory (SBOM)

Exact versions from `Cargo.lock` (reproduce with `scripts/crypto-inventory.sh`):

| Crate | Version | Role | Standard |
| --- | --- | --- | --- |
| `ml-kem` | 0.2.3 | ML-KEM-1024 KEM | FIPS 203 |
| `ml-dsa` | 0.1.0 | ML-DSA-87 signatures | FIPS 204 |
| `aes-gcm` | 0.10.3 | AES-256-GCM AEAD (default) | FIPS 197 + SP 800-38D |
| `aws-lc-rs` | 1.17.0 | AES-256-GCM / SHA-2 (`fips` feature) | CMVP-validated module |
| `sha2` | 0.10.9 | SHA-384 (`cnsa-sha2`) | FIPS 180-4 |
| `sha3` | 0.10.9 | SHA3-384 (default) | FIPS 202 |
| `tiny-keccak` | 2.0.2 | KMAC256 KDF (default) | SP 800-185 |
| `hkdf` | 0.12.4 | HKDF-SHA-384 KDF (`cnsa-sha2`) | RFC 5869 |
| `x25519-dalek` | 2.0.1 | X25519 (hybrid half only, non-load-bearing) | RFC 7748 |
| `argon2` | 0.5.3 | Argon2id at-rest KDF (m=19 MiB, t=2, p=1, v1.3) | RFC 9106 |
| `zeroize` | 1.8.2 | SSP zeroization | — |
| `getrandom` | 0.2.17 | OS CSPRNG (via `rand::OsRng`) | OS entropy |

---

## 5. Gap analysis — deltas to an actual FIPS 140-3 validation

In priority order, to move from *algorithm-aligned* to *validatable*:

1. **Power-on self-tests (POST).** *Done* (`talkrypt_crypto::self_test` /
   `ensure_self_tested`): AES-256-GCM + hash KATs, ML-KEM-1024/ML-DSA-87
   pairwise-consistency, KDF determinism, run once at start-up and aborting on
   failure. Remaining for validation: per-keygen conditional self-tests and a
   CAVP-traceable KAT set.
2. **Approved DRBG with health tests.** Replace bare `OsRng` use at the boundary
   with an SP 800-90A DRBG seeded from a health-tested entropy source
   (SP 800-90B), or document the OS DRBG as the approved entropy source per the
   target platform's validation.
3. **Verify SSP zeroization.** Transient session secrets are now zeroized on drop
   (SECURITY-AUDIT F-3, resolved); add a Miri run to *verify* the wipe and extend
   the same treatment to any future secret-bearing types.
4. **CAVP algorithm testing.** Obtain CAVP certificates for each algorithm
   implementation, or build exclusively on a CAVP/CMVP-validated backend
   (`aws-lc-rs/fips` covers AES/SHA-2; ML-KEM/ML-DSA need a validated PQC
   implementation once CMVP offers PQC testing).
5. **Module boundary + Security Policy.** Write the formal FIPS 140-3 Security
   Policy (module spec, ports/interfaces, roles/services, SSP table, self-tests).
6. **Side-channel review.** Establish constant-time guarantees (or document
   limits) for the AEAD and signature paths.

---

## 6. Conclusion

talkrypt is **CNSA 2.0 algorithm-aligned** (ML-KEM-1024, ML-DSA-87, AES-256-GCM;
SHA-384 with `cnsa-sha2`) with a parameter-set floor enforced in code, and is
**FIPS-capable** in that it can route AES/SHA-2 through a CMVP-validated backend.
It is **not** a FIPS 140-3 validated module, and this document is a self-assessment
that an independent CMVP lab has not reviewed. Using the named algorithms is not
the same as being certified; treat every property here as unverified until an
external assessment establishes otherwise.
