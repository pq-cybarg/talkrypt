# At-rest key custody — options & roadmap

Every way talkrypt can custody a long-term secret (the ML-DSA-87 **identity
seed**, NYM mnemonic, segment keys) at rest, with the trust / post-quantum /
attribution trade-offs of each. All ride the **one** seam —
`talkrypt_core::seal` (the `TKS1` envelope) — which wraps a random 32-byte **KEK**
with a `KeyWrapper` and encrypts the seed under `KDF(KEK ‖ passphrase)`. See
[`hardware-backed-sealing.md`](hardware-backed-sealing.md) for the format.

## The invariant that makes every wrapper interchangeable (and untrusted-safe)

The wrapper **only ever touches the random 32-byte KEK — never the seed.** The
seed is encrypted under `K_final = KDF(KEK ‖ pw_key)`. The QROM/L5 rule refuses a
hardware-only seal for a wrapper that isn't `qrom_safe()` unless a passphrase is
supplied, so for a classical wrapper a passphrase is **forced**. Consequences,
proven across the wrapper tests:

- A wrapper (SE / HSM / third party / chip) that learns the KEK **cannot recover
  the seed** without the passphrase — so even a *malicious* wrapper is outside the
  seed's confidentiality boundary (worst case: denial of service).
- **"Break the wrapper" never yields the seed** — only a value still protected by
  the PQ layer. Classically an attacker needs the wrapper (hardware) *and* the
  passphrase; against a CRQC the classical wrapper falls for free (Shor), so the
  **PQ guarantee rests entirely on passphrase entropy × Argon2 cost** — the
  classical hardware adds device-binding, not quantum resistance.
- **Post-quantum *hardware* barrier** requires a `qrom_safe()` wrapper: a
  symmetric ≥256-bit wrap (AES-256 on an HSM/Keychain) or an ML-KEM wrap (SEALSQ).
  Then a CRQC must break *both* the hardware wrap and the passphrase.

## Options

| # | Backend | Feature / entry | Apple identity | In TCB (sees KEK) | `qrom_safe` | Status |
|---|---|---|---|---|---|---|
| 1 | Software passphrase only | core `seal` (no wrapper) | none | — | n/a (PQ via passphrase) | shipped |
| 2 | Android StrongBox / iOS SE | FFI `HardwareKeyWrapper` | n/a (mobile) | hardware | no → passphrase | shipped |
| 3 | Linux TPM 2.0 | helper `tpm` | none | hardware | no → passphrase | shipped |
| 4 | macOS **Keychain-AES** | helper `macos-se` | none | login Keychain | **yes** (AES-256) | shipped (tested) |
| 5 | macOS **Secure Enclave** (ECIES) | helper `macos-se` | **Apple provisioning** | Enclave | no → passphrase | shipped (compile-checked; run needs signed+provisioned build) |
| 6 | **External HSM / PKCS#11** (YubiKey, SoftHSM, CloudHSM) | helper `pkcs11` | **none** | token you own | **yes** (AES-256 key-wrap) | shipped (compile-checked) |
| 7 | **SEALSQ / WISeKey PQ chip** (ML-KEM) | helper `sealsq` | **none** | chip you own | **yes** (ML-KEM-1024) | shipped (tested via mock) |
| 8 | Custom (smartcard / cloud KMS / anything) | `KeyStore::with_wrapper` | depends | depends | per wrapper | shipped (seam) |

### macOS Secure Enclave — the ways to reach it (option 5 variants)

The built-in Enclave is the only backend gated by **Apple provisioning** (SE key
registration needs the restricted `keychain-access-groups` entitlement; ad-hoc /
self-signed + that entitlement is SIGKILL'd by `amfid`). Ways to use it:

- **5a. Sign talkrypt (or a helper) yourself** with a provisioned Apple identity
  (paid Developer ID or a free Xcode personal team). Attributable to that identity.
  A minimal **signed helper** that does only SE create/wrap/unwrap over the helper
  IPC socket shrinks what must be signed to a tiny auditable shim — TK-main stays
  unsigned.
- **5b. Pre-existing signed third-party helper.** In principle TK → signed helper →
  SE → TK; the SE key lives under *the helper's* identity (no TK/personal Apple ID).
  Two catches: (i) no off-the-shelf tool exposes SE *decrypt/ECDH* for arbitrary
  data (Secretive/ssh-agent only *sign*, and SE ECDSA is non-deterministic, so you
  can't derive a stable key from a signature); (ii) the helper sees the KEK on
  unwrap — but per the invariant above, the KEK is useless without the passphrase,
  so the helper can be **untrusted for confidentiality**. TK can also do the *wrap*
  itself from the exported SE public key (no entitlement), so the helper is needed
  only for unwrap.
- **5c. Permissive security (no Apple identity).** Disable SIP + set
  `amfi_get_out_of_my_way=0x1` on a dedicated test machine; an ad-hoc-signed binary
  with the entitlement then runs. Downgrades that machine's security posture — see
  the hardening plan below.

**Hardening property for any SE/asymmetric path:** *do not persist the wrapper's
public key* alongside the blob. If the SE static public key is never stored, an
off-device CRQC with only the sealed file lacks the target to Shor, reinstating
"must reach the hardware" even against a quantum adversary (defense-in-depth, since
a public key can leak). The HSM/symmetric backends (4, 6, 7) satisfy this by
construction — the token holds everything and no public key is emitted.

## Recommendation

For **no Apple attribution + PQ-at-rest from hardware**, options **7 (SEALSQ, ML-KEM)**
and **6 (external HSM with an AES-256 key)** are best: hardware you physically own,
no code-signing identity, `qrom_safe` so no passphrase required, and the wrapper is
never in the confidentiality TCB. The built-in macOS Secure Enclave (5) is a fine
classical device-binding gate *with* a passphrase backstop, but only worth its
Apple-provisioning cost as part of the macOS distribution/notarization decision.

## Roadmap — planned, not yet built

### Permissive-security hardening mode (SIP-off compensation)

For users who choose option **5c** (disable SIP/AMFI to use the built-in Enclave
without an Apple identity), re-provide — in our own code — the integrity
protections SIP/AMFI would have enforced, so they are not left exposed:

- **PQ self-integrity attestation.** At launch, verify the app binary **and** the
  key-custody helper against an **ML-DSA-87** signature using the existing
  `crates/relsign` mechanism (artifact → SHA-256 → signed manifest → trusted
  pubkey). Refuse to run / refuse to unseal if the signature doesn't match — our
  own code-integrity check replacing the one AMFI stops enforcing. This is *better*
  than Apple's check: it's post-quantum and not tied to Apple's PKI.
- **Anti-debug / anti-inject process hardening.** Extend `crypto::mem::harden_process`
  to macOS: `ptrace(PT_DENY_ATTACH)`, check `csops` flags, sanitize `DYLD_*`
  injection env vars, refuse to run under a debugger. (`harden_process` already does
  core-dump suppression everywhere and `PR_SET_DUMPABLE` on Linux/Android.)
- **Launch-time posture report.** Surface in the UI whether SIP is off and whether
  the self-attestation passed, so the user sees exactly which protections are
  self-enforced vs. OS-enforced.

Build after threat-model sign-off. Tracked as a task; captured here so it sits
alongside the custody backends rather than as a loose thread.

### Also deferred

- **Windows TPM/CNG** wrapper (the `with_wrapper` seam accepts it).
- **A real SEALSQ vendor driver** behind `pqse::PqSecureElement` (PKCS#11/APDU).
- **PKCS#11 RSA-OAEP / EC mechanisms** (classical `qrom_safe=false`) in
  `hsm::pkcs11` for tokens without a symmetric key; AES-Key-Wrap-Pad is wired today.
