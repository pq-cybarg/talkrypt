# Key Custody & Storage

How talkrypt holds long-term secrets at rest, across platforms. Deep spec:
`docs/hardware-backed-sealing.md`. Source: `crates/core/seal.rs`,
`crates/core/custody.rs`, `crates/helper/`.

## Custody tiers

Every platform reports the strongest tier it achieves; the crypto is identical at
every tier — only the *at-rest protection* differs (`custody.rs`).

| Tier | What holds the key | Where |
| --- | --- | --- |
| **SoftwareSealed** | Argon2id + AES-256-GCM sealed file | every platform |
| **OsKeystore** | the OS key service (never exported) | macOS Keychain · Linux Secret Service · Windows Credential Manager |
| **HardwareBacked** | a secure element wraps the sealing KEK | Android StrongBox · iOS Secure Enclave · TPM 2.0 (desktop) |

A device **self-reports** its tier at runtime (e.g. `KeyInfo.isInsideSecureHardware()`),
so a device without a real secure element honestly reports `OsKeystore`, not
`HardwareBacked` — this feeds the #305 **PQ + custody parity audit**
(`crates/helper/parity.rs`), where PQ identity is hard-required and tier
differences are surfaced rather than failed.

## At-rest sealing (the `TKS1` envelope)

One **multiplatform** sealed-blob format and wrap/unwrap seam live in
`talkrypt-core` (`seal.rs`), so a blob sealed on any platform has a defined shape
everywhere and no host re-implements the crypto:

```
seal:   KEK_rand  ← CSPRNG (32 B)          [hardware only]
        wrapped   ← wrapper.wrap(KEK_rand)  [hardware only, the secure element]
        pw_key    ← Argon2id(passphrase)    [passphrase only]
        K_final   ← KMAC256/HKDF(flags ‖ [KEK_rand] ‖ [pw_key])
        ct        ← AES-256-GCM(K_final, nonce, seed;  AAD = header)
```

At least one factor is required. With **both** a passphrase and a hardware
wrapper it is **two-factor** (device *and* passphrase); with one, it degrades to
that factor. The `flags` byte and the whole header are bound as AEAD AAD, so
stripping a factor or tampering fails the open. `tier_of(blob)` reports the tier
without unsealing.

## Hardware-backed sealing — and its honest limit

Today's secure elements (StrongBox, the Solana Seeker's SE, Secure Enclave, TPM)
are **classical-only** — they cannot hold or sign with talkrypt's post-quantum
ML-DSA-87 key. So hardware protects the seed **at rest, not in use**: the secure
element wraps a random KEK with a non-exportable, user-presence-gated key; the
seed is still unwrapped into `mlock`'d RAM to sign. This hardens the at-rest and
device-theft cases; it does **not** defend a live-RAM attacker on a fully
compromised device. Hardware-backed *signing* is blocked on PQC-capable silicon,
not on talkrypt (`docs/SECURITY-AUDIT.md §3b`).

- **Mobile** — the [FFI](Platforms-and-Clients.md) exposes a
  `HardwareKeyWrapper` callback the host implements over Android Keystore/
  StrongBox or iOS Secure Enclave; `Account::seal` / `Account::from_sealed`
  seal/reload the account seed **without ever exposing it** to the host.
- **Desktop** — the [helper](#the-desktop-helper) routes its `HardwareBacked`
  tier through the same `seal` codec, wrapping the KEK with a **TPM 2.0** on Linux
  (validated against `swtpm`).

## The desktop helper

`talkrypt-helper` is a separate Rust sidecar that reuses the audited core (no
second-language reimplementation). The app talks to it over an **owner-only IPC
channel** — a `0600` Unix socket in a `0700` dir (macOS/Linux) or an SDDL-ACL'd
Named Pipe bound to the user's SID (Windows). It exposes Seal/Unseal, named blob
Put/Get/Delete, GenerateIdentity, IdentityFingerprint, ValidateInvite, and
Capabilities (for the parity audit). Source: `crates/helper/`.
