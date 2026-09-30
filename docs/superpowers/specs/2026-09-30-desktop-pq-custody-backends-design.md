# Desktop PQ custody backends — design record

**Date:** 2026-09-30
**Status:** Built (PR: desktop-pq-custody-backends)
**Area:** `crates/helper` (desktop key-custody helper), on the existing
`talkrypt_core::seal` seam. No seam/format change.

## Goal

Accommodate custom and post-quantum hardware key custody on desktop, and make
explicit that **PQ confidentiality at rest is preserved even when the HSM is
classical**. Driven by the requirement: *"PQ security if enclosed in a non-PQ
HSM + SEALSQ chip support."*

## Context

`talkrypt_core::seal` (TKS1 envelope) already wraps a random KEK with a host
`KeyWrapper` and binds the header as AEAD AAD. Its QROM/L5 rule refuses a
classical hardware-only seal unless the wrapper attests `qrom_safe()`, forcing a
passphrase whose Argon2id-256 key keeps the sealed AES-256-GCM contents
PQ-safe — i.e. "PQ inside a non-PQ HSM" was already enforced at the core. Before
this change the desktop helper wired only a Linux TPM backend; macOS/Windows
topped out at the `OsKeystore` tier.

## What was built

1. **`pqse` (`sealsq` feature) — PQ secure element.** `PqSecureElement` transport
   trait (chip holds ML-KEM-1024 dk, exposes ek + on-chip `decapsulate`) and
   `PqSeWrapper`, a `KeyWrapper` that encapsulates the KEK to the chip's ML-KEM
   key. `qrom_safe() = true` → enables a **hardware-only, passphrase-less L5
   seal** (SEALSQ / WISeKey QS7001 & VaultIC). Audited `talkrypt-crypto` ML-KEM;
   driver only moves bytes; `MockPqSecureElement` makes it fully testable.
2. **`KeyStore::with_wrapper` — custom-custody seam.** Public (was
   `#[cfg(test)]`): plug any PKCS#11 HSM / YubiKey / smartcard / PQ chip.
   `hw_seal` now honors `wrapper.qrom_safe()` — a PQ chip gets a real QROM-safe
   hardware-only seal; a classical TPM/SE stays the weak hardware-bound tier.
3. **`macos_hw` (`macos-se` feature).** `KeychainAesWrapper` (AES-256 key in the
   login Keychain; `qrom_safe() = true`; tested here) and `SecureEnclaveWrapper`
   (SE P-256 ECIES; `qrom_safe() = false` → seam forces a passphrase).

## Key decision: macOS Secure Enclave is provisioning-gated, not shipped-blind

Empirically confirmed on Apple M5: SE key creation registers a
data-protection-keychain reference needing the **restricted**
`keychain-access-groups` entitlement. Without it → `OSStatus -34018` (but the
Enclave *is* reached — a live `com.apple.setoken` `SecKeyRef` is minted). With it
on a self-signed identity → `amfid` SIGKILL, because the entitlement needs an
Apple-issued provisioning profile. macOS `codesign`/`amfid` verify only
RSA/ECDSA — **no XMSS/LMS/ML-DSA** — so PQ code signing is impossible at the
platform layer (PQ artifact signing lives in `crates/relsign`). Decision: ship
the SE wrapper **compile-checked**, `KeyStore` never auto-selects it (clean
fallback), and its hardware test is `#[ignore]` (reported *ignored*, never a
skip-as-pass) with a documented signed-build run recipe +
`crates/helper/macos-se.entitlements`. The tested macOS backend is
`KeychainAesWrapper`.

## Not done / out of scope

- Windows TPM/CNG wrapper (deferred; the `with_wrapper` seam accepts one).
- A real SEALSQ chip driver (the transport seam + mock are in; the vendor
  PKCS#11/APDU driver drops in behind `PqSecureElement`).

## Tests

8 `pqse` + 1 `store` PQ end-to-end + 2 `macos_hw` Keychain-AES (run); 1 SE
hardware test `#[ignore]`. All green with and without each feature.
Full detail: `docs/hardware-backed-sealing.md`.
