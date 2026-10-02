# Custody & hardening — testing status

An honest catalog of **what has actually been exercised**, and how, for the
at-rest key-custody backends and the permissive-security hardening (PR:
`feat/desktop-pq-custody-backends`). No silent gaps: each item says whether it was
unit-tested, driven end-to-end on real hardware/tools, only compile-checked, or
still unvalidated (and why).

Legend:
- ✅ **Unit-tested** — automated `cargo test` coverage in CI.
- 🔬 **Verified live** — driven end-to-end against the real binary / tool / OS on
  this machine (Apple M5), beyond unit tests.
- 🧱 **Compile-checked only** — type-checks and builds under its feature, but the
  runtime path needs hardware / an entitlement / a token not present here.
- ⛔ **Not yet validated** — mechanism exists behind a seam; needs external parts.

## Core seal seam (`talkrypt_core::seal`, pre-existing, unchanged)

| Item | Status | Evidence |
|---|---|---|
| TKS1 envelope round-trip (software / hardware / hybrid) | ✅ | `crates/core/src/seal.rs` (9 tests) |
| QROM/L5 rule (classical hw-only refused; passphrase forced; qrom-safe allowed) | ✅ | `qrom_l5_hardware_only_rule_all_modes` |
| Wrong-device / wrong-passphrase / tamper / factor-strip / no-plaintext-leak | ✅ | same |

## Custody backends (this PR)

| Backend | Status | Evidence / caveat |
|---|---|---|
| **SEALSQ PQ chip** (`pqse`, ML-KEM-1024, `qrom_safe`) | ✅ 🔬(mock) | 8 unit tests: roundtrip, different-chip implicit-reject, tamper, bad header, ek-length guard, **hardware-only QROM seal through core**; + `KeyStore` end-to-end PQ put/get. Exercised via `MockPqSecureElement` (in-software ML-KEM). A **real SEALSQ chip driver** behind `PqSecureElement` is ⛔ (needs the vendor PKCS#11/APDU + silicon). |
| **Custom `with_wrapper` seam** | ✅ | `store.rs` HardwareBacked put/get via a mock SE; `hw_seal` honours `qrom_safe()` (weak-tier opt-in only when `!qrom_safe`). |
| **macOS Keychain-AES** (`macos-se`, `qrom_safe`) | ✅ 🔬 | 2 unit tests (roundtrip + tamper, hardware-only QROM seal) run on this Mac; uses the real login Keychain (same path as the pre-existing `keychain` test). |
| **macOS Secure Enclave** (`macos-se`, ECIES, classical) | 🧱 | Compiles; `#[ignore]` hardware test. The Enclave **is reached** (live `com.apple.setoken` `SecKeyRef`), but key *registration* needs the restricted `keychain-access-groups` entitlement: signed-without-it → `OSStatus -34018`; self-signed-with-it → `amfid` SIGKILL. Runs only on an Apple-**provisioned** signed build. Verified these outcomes empirically on M5. |
| **External HSM / PKCS#11** (`pkcs11`, cryptoki) | ✅ 🧱 | Generic `HsmToken` seam + envelope: 6 unit tests (roundtrip, qrom passthrough, wrong-token, tamper, bad header, **hardware-only QROM seal + classical-needs-passphrase**) via `MockHsmToken`. The `cryptoki` `Pkcs11Token` driver is 🧱 — compiles, but no token/SoftHSM in CI to run it. |
| **Linux TPM 2.0** (`tpm`, pre-existing) | 🧱 here | Validated against swtpm in `docs/linux-tpm-test.sh` (Linux); not exercised on this macOS host. |
| **Windows TPM / CNG** (`windows-tpm`, NCrypt RSA-OAEP, classical) | 🧱 | `CngWrapper` via the TPM-backed Platform Crypto Provider; `qrom_safe=false` → passphrase-gated. **Compile-checked against `x86_64-pc-windows-gnu`** (clean `cargo check` + no warnings); no Windows host/TPM here to run it. `available()` probes; never auto-selected. |

## Permissive-security hardening (`talkrypt_crypto::harden`, `attest`, `mem`)

| Item | Status | Evidence |
|---|---|---|
| PQ self-integrity (`attest::verify_bytes/verify_file/verify_self`) | ✅ 🔬 | Unit tests incl. **signing the running test binary and self-verifying** (+ tamper / wrong-key reject). |
| `release_pubkey()` embed + `parse_hex_with_comments` (2592-byte guard) | ✅ | Tests: comment-stripped real vk parses; placeholder → `None`; wrong length → `None`. Current `RELEASE_PUBKEY.hex` is a placeholder (documented by a test). |
| `deny_debugger()` (`PT_DENY_ATTACH`) | 🔬 | Not unit-tested (side-effecting syscall), but observed `debugger_denied: true` when running the real helper/desktop on M5. |
| Injection-env scan + `PostureReport::is_acceptable` | ✅ | Unit test sets/clears `DYLD_INSERT_LIBRARIES`; `from_env` hex/path + attest-gate tests. |
| **Helper entry point** refuse-to-start | 🔬 | Ran `talkrypt-helper` on M5: `LD_PRELOAD` → refuses; bogus attest → `self_attested: Some(false)` → refuses. |
| **Desktop entry point** refuse-to-start | 🔬 | Ran `talkrypt-desktop --headless` on M5: `LD_PRELOAD` → refuses; `debugger_denied` + `core_dumps_disabled` true. |
| **Sidecar attestation with real `relsign`** | 🔬 | `relsign keygen` → `sign <helper>` → `<helper>.sig`; run with `TALKRYPT_HARDEN=1` → `self_attested: Some(true)` proceeds; tampered sidecar → `Some(false)` refuses. |
| `scripts/sign-binaries.sh` | 🔬 | No-op without key; signs a directory's executables; runtime consumes the written sidecar (M5). |

## Aggregate

`cargo test`: core seal 9 · `pqse` 8 + `store` PQ e2e · `macos_hw` 2 (SE `#[ignore]`) ·
`hsm` 6 · `crypto::harden` 8 · `crypto::attest` 2. Full suites green:
**crypto 152 + 8 harden/attest**, **helper 40 + 1 ignored** (all features), desktop
builds. clippy clean; scripts `bash -n` clean.

## Known-unvalidated (need external parts, not code)

- macOS Secure Enclave **runtime** — needs an Apple-provisioned signed build.
- `cryptoki` PKCS#11 driver — needs a token or SoftHSM.
- Real **SEALSQ** chip driver — needs vendor SDK + silicon.
- Windows TPM/CNG wrapper **runtime** — built + compile-checked; needs a Windows host with a TPM.
- Launch-attestation **on by default** — needs a published `RELEASE_PUBKEY.hex`
  + shipped `<exe>.sig` (maintainer/opsec action).
