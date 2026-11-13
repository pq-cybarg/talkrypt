# Plan 0003 — multi-scheme release co-signing (hash-based) + SHA3-384/SHA-384

> **Honest scope.** This hardens the *release-artifact* signing path. It adds
> CNSA-/NIST-/FIPS-*aligned* mechanisms; it is **not** a certification, validation, or
> accreditation, and nothing here changes the project's standing disclaimer (NOT
> FIPS-validated / NOT CSfC / NOT NSA-approved / NOT audited). "CNSA-aligned" means
> algorithm/mechanism choice only. See `docs/COMPLIANCE.md`, `docs/compliance/STANDARDS-MAP.md`.

## 1. Motivation (why ML-DSA is not the right *software-signing* target)

The three authorities differ on signing, and this feature is designed to satisfy all
three at once rather than pick one:

| Authority | General signature | **Software/firmware signing** | Hash family |
| --- | --- | --- | --- |
| **CNSA 2.0 (NSA)** — strictest | ML-DSA-87 (FIPS 204) | **LMS / XMSS** (stateful hash-based, NIST SP 800-208) — the *designated* code-signing mechanism; SLH-DSA is **not** in CNSA 2.0 | **SHA-2** only (SHA-384/512) |
| **NIST** — full menu | ML-DSA **and** SLH-DSA (FIPS 205) **and** LMS/XMSS | any of the three, use-case driven | SHA-2 **and** SHA-3 (FIPS 202) |
| **FIPS (140-3 approval)** | all approved | all approved | both families approved |

Today talkrypt signs the release manifest with **ML-DSA-87** (`talkrypt-relsign`, F-8) —
CNSA's *general* signature, not the designated *software-signing* one. The resolution:

- **Co-sign** the release manifest with **two independent hash-based signatures**:
  - **LMS** (NIST SP 800-208, stateful) — the **CNSA-2.0-designated** software-signing scheme.
  - **SLH-DSA** (FIPS 205, stateless) — the NIST stateless hash-based standard; no key-state hazard.
- A CNSA-bound verifier checks the LMS signature; a verifier preferring the stateless
  NIST standard checks SLH-DSA; **both must verify** (defense-in-depth — a weakness in one
  scheme cannot mask a forgery, mirroring the dual-hash rationale).
- **ML-DSA-87 is retained** for its correct roles (the general signature + the
  launch-attestation sidecars), not the code-signing role.
- Release checksums move to **SHA3-384 + SHA-384** (two independent 384-bit families —
  Keccak sponge + Merkle–Damgård — and exactly the two hashes talkrypt's crypto core
  already uses). SHA-384 satisfies CNSA's SHA-2 requirement; SHA3-384 covers FIPS 202.

Net: LMS ⇒ CNSA-aligned; SLH-DSA ⇒ NIST/FIPS stateless; SHA-384 ⇒ CNSA hash; SHA3-384 ⇒
FIPS 202 — every authority's preferred mechanism is present, none is the single point of
trust.

## 2. Design

### 2.1 Where the new primitives live

`talkrypt-relsign` is a **build/release utility, not part of the shipped app** — so the
two new signature crates are added **to `relsign` only**, keeping `talkrypt-crypto`'s
audited, app-facing surface unchanged (consistent with "app crypto implemented once"; a
release signer is tooling, not an app primitive). Candidate crates, to be vetted and (per
`third-party/` policy) pinned/vendored with written rationale before adoption:

- **SLH-DSA:** `fips205` 0.5.0 (stable; FIPS 205) — parameter set **SLH-DSA-SHA2-256s** or
  **-SHAKE-256s** (256-bit security, small-signature variant; "s" favours verify/size over
  sign speed, right for releases). Decide SHA2 vs SHAKE instantiation in Step 2.
- **LMS:** `hbs-lms` (keygen+sign+verify, SP 800-208, supports HSS) preferred over
  `lms-signature` (RFC 8554, verify-centric). LMS parameters: `LMS_SHA256_M32_H10`
  (height-10 tree ⇒ 1024 one-time signatures) with `LMOTS_SHA256_N32_W8`, or HSS L=2 for
  more capacity. SHA-256-based OTS is the SP 800-208 instantiation.

### 2.2 Co-signature artifacts

`hash-dist.sh` emits, in `dist/`:

```
SHA384SUMS            # SHA-384 of every artifact   (FIPS 180-4, CNSA)
SHA3-384SUMS          # SHA3-384 of every artifact  (FIPS 202)
MANIFEST.txt          # human-readable, both digests, skipped-target notes
SHA384SUMS.lms.sig    # LMS   signature over SHA384SUMS   (SP 800-208, CNSA)
SHA384SUMS.slh.sig    # SLH-DSA signature over SHA384SUMS (FIPS 205)
SHA384SUMS.mldsa.sig  # (optional, retained) ML-DSA-87 over SHA384SUMS (continuity)
verify.sh / verify.ps1
RELEASE_PUBKEY_LMS.hex / RELEASE_PUBKEY_SLH.hex / RELEASE_PUBKEY.hex  (ML-DSA, existing)
```

The canonical signed manifest is **`SHA384SUMS`** (SHA-2 family, CNSA-named). Both sums
files list the same artifacts, so signing one binds all artifact hashes; a verifier
checks that both digests match *and* that every present signature verifies.

### 2.3 Verify flow (`verify.sh` / `verify.ps1`)

1. Check **SHA-384** (sha384sum/shasum -a 384) and **SHA3-384** (openssl 3.x / python3 /
   rhash) — both must match for every file.
2. For each `SHA384SUMS.*.sig` present, if `talkrypt-relsign` is on PATH and the matching
   pinned public key is available (`$TALKRYPT_RELEASE_PUBKEY_{LMS,SLH}` or
   `RELEASE_PUBKEY_{LMS,SLH}.hex`), verify it. **All present signatures must pass**; a bad
   one fails the whole verification. Absent tool/key ⇒ that signature is *advisory*
   (reported, skipped) exactly as today — never silently passed.
3. Trust anchor: pin the public key obtained **out of band** (the repo copy for an
   official build), never one bundled by an untrusted mirror.

### 2.4 Key custody (the stateful hazard, handled)

- **SLH-DSA** is stateless — keygen/sign/verify with no persistent state (like ML-DSA).
- **LMS is stateful**: each one-time leaf index MUST be used **exactly once**; reusing an
  index is catastrophic (forgeable). Therefore:
  - The LMS private key **advances on every `sign`** and the updated state MUST be
    persisted back to the offline key store. `relsign` writes the advanced key atomically
    and refuses to sign if it cannot persist the new state.
  - Capacity is bounded (H=10 ⇒ 1024 releases); the plan documents re-key before
    exhaustion. The seed/state lives only in `TALKRYPT_RELEASE_SK_LMS` (offline / CI
    secret), never in the repo.
  - **Honest-scope:** the stateful-reuse risk is real and operational; it is documented in
    `PACKAGING.md` and the signer aborts rather than risk an index reuse.

### 2.5 `relsign` CLI (back-compatible)

```
talkrypt-relsign keygen --algo <ml-dsa|slh-dsa|lms>
talkrypt-relsign sign   --algo <...> <file> <seed-or-statefile>   # writes <file>.<algo>.sig
talkrypt-relsign verify --algo <...> <file> <sigfile> <pubkey>
```
`--algo ml-dsa` stays the default so existing `sign <file> <seed>` usage is unchanged.

## 3. TDD implementation steps

1. **Crate vetting + pin.** Add `fips205` and `hbs-lms` as `relsign` dev/real deps; run
   `cargo deny`/`cargo audit`; if advisories/licence require, vendor under `third-party/`
   with a `TALKRYPT-PATCH.md` rationale. Record SBOM rows in `COMPLIANCE.md §4`.
2. **SLH-DSA path (stateless) — test first.** Unit tests: keygen determinism from seed,
   sign→verify round-trip, tamper-reject, wrong-key-reject, KAT against a FIPS-205 ACVP
   vector. Then implement `--algo slh-dsa`. Pick + record the parameter set (SHA2-256s vs
   SHAKE-256s).
3. **LMS path (stateful) — test first.** Tests: keygen, sign advances state, verify,
   tamper/wrong-key reject, **index-reuse is impossible** (second sign uses a new index;
   signing without persisting state aborts), SP 800-208 KAT vector. Then implement
   `--algo lms` with atomic state persistence.
4. **Multi-sig CLI + back-compat test.** `--algo` dispatch; assert the legacy
   `sign/verify <file> <seed>` (ML-DSA) behaviour is byte-identical.
5. **hash-dist.sh → SHA3-384 + SHA-384**, emit the three `.sig`s when the respective
   `TALKRYPT_RELEASE_SK_*` are set; update `MANIFEST.txt` wording.
6. **verify.sh + verify.ps1** → SHA-384 + SHA3-384 and multi-signature verification (all
   present must pass); add the new backends (sha384sum/shasum -a 384; SHA3-384).
7. **Docs** (same change set): `PACKAGING.md`, `COMPLIANCE.md` (flip the LMS/XMSS row from
   "N/A" to implemented; add SLH-DSA; note SHA3-384/SHA-384), `compliance/STANDARDS-MAP.md`,
   `SPECIFICATION.md §7` note, `wiki/Packaging-and-Release.md`, `wiki/Getting-Started.md`,
   `CLAUDE.md` (verify.sh now checks SHA-384 + SHA3-384; releases carry LMS + SLH-DSA
   co-signatures).
8. **Dry-run on host.** Build a tiny `dist/` (macOS arm64 artifacts already build here),
   generate LMS + SLH-DSA + ML-DSA keys, co-sign, and prove `verify.sh` passes all digests
   + all three signatures; then flip one byte and prove it fails. Record the run.
9. **CI.** Extend the release/verify checks so a packaged `dist/` is verified in CI with
   test keys (no real release key in CI).

## 4. Out of scope / follow-ups

- Publishing the **real** `RELEASE_PUBKEY_*.hex` trust anchors (needs the offline keys) —
  tracked separately; until then signatures stay advisory, as today.
- XMSS (the other SP 800-208 scheme) is not added; LMS covers the CNSA-designated
  stateful requirement. Revisit if a verifier specifically needs XMSS.
- OS-native code signing (Apple notarization / Debian archive key) remains deliberately
  out of scope — the PQ co-signature is the project-controlled, CA-free integrity layer.
