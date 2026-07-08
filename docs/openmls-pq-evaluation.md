# Evaluation: adopt OpenMLS + a PQ ciphersuite, or keep hardening the in-house TreeKEM?

**Status:** decision record (task #74)
**Date:** 2026-07-08
**Author:** pq-cybarg
**Scope:** talkrypt's group-messaging crypto (`crates/crypto/src/treekem.rs`), in the
context of repurposing talkrypt as a coordination side-channel for zRonin relayers.

## TL;DR — Recommendation: **adopt OpenMLS's pure-PQ suite as the target. Run a de-risking spike now; ship the in-house TreeKEM only as the interim while the spike + a PQ-path audit complete — then migrate, and redirect our formal-proof/audit budget onto OpenMLS's PQ path.**

OpenMLS implements the pure-PQ ciphersuite talkrypt needs —
`MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` (ML-KEM-1024 KEM **and** ML-DSA-87
signature, no classical signature on the auth path) — on the **same RustCrypto `ml-dsa`
crate talkrypt already uses**, and on the **feature-parity verification below every core
feature talkrypt needs is present in MLS, several of them natively where talkrypt bolted
them on** (per-sender authentication, untrusted delivery service, on-demand PCS). MLS is
also a peer-reviewed IETF standard with an audited implementation — i.e. **at least as
secure** as talkrypt's hand-rolled TreeKEM for everything except the new PQ ciphersuite
glue. The T-2 forgery bug found this cycle (a committer could rewrite any member's leaf
signing key) is precisely the *class* of bug that a correct, audited MLS state machine
does not have.

> **Empirically verified (spike #81 — [`docs/openmls-pq-spike`](./openmls-pq-spike/)):** a
> standalone crate pinned to OpenMLS git-main runs the **full lifecycle under
> `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`** — create → add → Welcome/join → encrypted
> application messages both ways → **member self-update (on-demand PCS)** → remove — all
> passing, on the same RustCrypto `ml-dsa`/`ml-kem` crates talkrypt uses. The pure-PQ suite
> is not just *defined*, it is *functionally complete* end-to-end. (Integration gotcha the
> spike caught: the `draft-ietf-mls-pq-ciphersuites` feature must also be enabled on
> `openmls_basic_credential`, or ML-DSA signature-key generation fails at runtime even
> though `supports()` returns Ok.)

> **Hash-family caveat (SHA-3 vs SHA-2):** talkrypt's *default* KDF is KMAC/Keccak (SHA-3
> family), with SHA-2 available under the `cnsa-sha2` feature. **No MLS ciphersuite uses
> SHA-3** — RFC 9420 and the PQ draft define suites over SHA-256/384/512 only (the ML-KEM /
> ML-DSA primitives use SHAKE/Keccak *internally*, but the MLS transcript/KDF hash is
> SHA-2). Adopting MLS therefore moves talkrypt's group-protocol hash to **SHA-384**. Note
> this is not a downgrade for CNSA 2.0: CNSA 2.0's specified hashes are SHA-384/SHA-512
> (SHA-2), so `…SHA384_MLDSA87` is the CNSA-compliant choice — talkrypt's SHA-3/KMAC default
> is the deviation from CNSA's *named* hash. If talkrypt has a hard SHA-3 requirement beyond
> CNSA, MLS cannot meet it today (would need a new, unregistered ciphersuite) — see §8 for a
> FIPS-only plan to add one.

The one genuine caveat is the **maturity of the PQ ciphersuite path**: it is gated behind
`#[cfg(feature = "draft-ietf-mls-pq-ciphersuites")]`, ships **only on OpenMLS's git `main`,
not in the crates.io release** (0.8.1 lists only classical suites) so adopting today means
pinning a git revision, tracks an unfinalized draft with **no IANA code points** (wire
identifier can still change; cross-implementation interop not yet guaranteed), and is almost
certainly **outside the scope of any completed OpenMLS/libcrux audit** (a rough edge confirms
this: the sibling `…SHA512_MLDSA87` variant is *listed* as supported but not actually
validated in the provider's `supports()`).

So the decision is: adopt OpenMLS for the audited protocol + real pure-PQ suite, and treat
the *PQ ciphersuite path* as the thing to verify and audit — which is a far better use of
formal-methods/audit budget than continuing to re-prove a hand-rolled TreeKEM whose
protocol logic MLS has already standardized and analyzed. Ship in-house only long enough
to run that verification.

> **Correction:** an earlier draft of this doc claimed OpenMLS's only PQ path was X-Wing
> (hybrid KEM + classical Ed25519 signature) and that no pure-PQ ML-DSA suite shipped.
> That was wrong (thanks to the maintainer for the catch) — the pure-PQ ML-DSA-87 suite is
> implemented behind the draft feature flag. This version corrects it and reframes toward
> adoption.

---

## 1. Feature-parity verification — does OpenMLS have everything talkrypt needs?

Legend: ✓ present/native · ✓+ native where talkrypt bolted it on (an upgrade) · ~ needs a
mapping/re-integration (feasible, scoped) · = same limitation as talkrypt.

| talkrypt requirement | In OpenMLS / MLS? | Notes |
|---|---|---|
| **ML-KEM-1024 + ML-DSA-87 pure-PQ ciphersuite** | ✓ (draft-gated, **git main only**) | `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87`; `supports() => Ok(())` in `openmls_rust_crypto`; HPKE `MlKem1024` wired; ML-DSA via RustCrypto `ml_dsa`. **Not in the crates.io release** (0.8.1, 2026-02-13, lists only classical suites) — the PQ suites are on the GitHub `main` branch behind the feature flag, so adopting today means pinning a **git revision**. **Spike-verified end-to-end (#81):** create→add→join→app-msg→member-self-update→remove all pass under this suite. |
| Group create / add / remove members | ✓ | Native Commit with Add/Remove proposals (RFC 9420). |
| Member self-rekey / on-demand PCS (talkrypt T-4) | ✓+ | Native Update proposal — a core MLS operation, not a bolt-on. |
| Forward secrecy | ✓ | Native (per-epoch secret tree, ratcheting). |
| Post-compromise security | ✓ | Native (Update/Commit rekeys the path). |
| Per-sender message authentication (anti-forge; talkrypt G1/G2) | ✓+ | Native signed FramedContent per leaf credential. This is exactly where talkrypt's *bolt-on* had the T-2 leaf-key-hijack bug; MLS does it in the audited core. |
| Untrusted delivery service (talkrypt relayed mode) | ✓+ | The MLS DS is untrusted **by design** — it cannot read or forge. talkrypt's relay maps directly and gets a stronger, standardized guarantee. |
| Encrypted application (chat) messages | ✓ | Native PrivateMessage; optional padding. |
| Custom / pseudonymous identity (talkrypt account chains, T-3; pseudonyms) | ~ | `BasicCredential::new(bytes)` carries arbitrary identity; X.509 and custom credential types supported. talkrypt's account→device chain maps to a credential (basic + app-level verification, or a custom credential). **Design the mapping.** |
| Stable-derived vs ephemeral leaf key (LeafSigMode) | ✓ | The signature keypair is app-generated; deriving it per-group (or minting it fresh) is entirely the application's choice — same `KDF(identity, group_id)` we just built. |
| Delivery over Tor / Nym / LAN / gossip | ~ | MLS is DS-agnostic; talkrypt's transports become the DS. **Re-integration work** (map welcome/commit/app-message objects onto our routing), feasible. |
| Wire padding / posture / classification marking | = | App/transport-layer concerns, unchanged by the protocol choice. |
| FIPS mode (talkrypt `fips` = aws-lc-rs) | ~ | Provider-dependent; PQ FIPS validation is nascent industry-wide. A FIPS provider for the PQ suite is an open item either way. |
| Decentralized multi-committer PCS (roadmap #73) | = | MLS is single-committer per epoch — **same limitation** as talkrypt's hub. Neither solves it; that remains the DCGKA research track. |

**Verdict:** no talkrypt requirement is *absent* from MLS/OpenMLS. Core security/functional
needs are native (and several are natively stronger). The work items are: (a) confirm the PQ
ciphersuite is functionally complete end-to-end, (b) map the identity/credential model,
(c) re-integrate the Tor/Nym/gossip delivery service, (d) settle FIPS. None is a blocker.

## 2. Is OpenMLS "at least as secure" as ours?

**Protocol:** yes, and by a wide margin. MLS/TreeKEM is an IETF standard (RFC 9420) with
substantial academic security analysis (the CGKA/TreeKEM literature, symbolic and
computational models) and a security-considerations section vetted by the WG. OpenMLS's
framing/state-machine has had third-party review, and its libcrux primitives are formally
verified. talkrypt's TreeKEM is a *hand-rolled variant* of the same ideas; even with our
F*/EasyCrypt/Kani proofs and hardening, its unproven protocol surface is larger — as the
T-2 finding this cycle demonstrated concretely.

**PQ ciphersuite glue:** this is the *only* place the comparison is not clearly in OpenMLS's
favour, and only because it is *new*, not because it is weak — the primitives (ML-KEM-1024,
ML-DSA-87) are the same NIST/RustCrypto ones talkrypt uses. It is draft-gated, un-IANA'd,
and outside completed audits. That is exactly the surface to verify and audit before
production — see §4.

## 3. Migrating our proof work / audits to OpenMLS

Your instinct is right and it *reduces* total assurance work rather than duplicating it:

- **Retire, don't port, the in-house *construction* proofs.** talkrypt's F* `GroupAuth`
  (auth theorems) and EasyCrypt QROM confidentiality/authentication proofs establish
  properties that MLS/TreeKEM already has standardized, peer-reviewed analysis for.
  Re-proving a hand-rolled variant is effort MLS's existing analysis already spent.
- **Retire the Kani decoder-totality proofs** — they harden talkrypt's hand-rolled wire
  parsers. OpenMLS brings its own (reviewed) parsers; the bespoke parser surface goes away.
- **Redirect the freed budget to the genuinely new surface: the PQ ciphersuite path.**
  Concretely: (a) an **external audit scoped to the draft PQ ciphersuites** in OpenMLS
  (HPKE-with-ML-KEM-1024, ML-DSA-87 signing, the KDF/AEAD wiring, the `supports()` /
  ciphersuite selection logic, the `SHA512` listed-not-supported class of edge); (b) if we
  want formal artifacts, focus them there (QROM security of ML-KEM-in-HPKE and ML-DSA in the
  MLS handshake) rather than on the tree construction. This is where analysis is missing
  industry-wide, so it is also the highest-value contribution.

Net: migration *shrinks* the bespoke-crypto attack surface we are on the hook to prove/audit,
from "a whole hand-rolled CGKA + parsers + auth layer" down to "one draft PQ ciphersuite
inside an audited stack."

## 4. Migration cost & the spike

Real costs, none fundamental:
- **Wire-format break** — RFC 9420 framing replaces talkrypt's compact wire (new descriptor
  version; no back-compat). Keep the in-house wire versioned so this is a clean bump.
- **Delivery-service re-integration** — wire talkrypt's Tor/Nym/LAN/gossip transports,
  relayed mode, and roster/attribution onto OpenMLS's message objects.
- **Footprint / portability** — OpenMLS + provider is a larger dependency than the ~2.4k-line
  in-house module; must build and run in the uniffi FFI + Android and egui desktop targets
  with the draft feature flag.
- **Identity mapping + FIPS** — per §1.

**Spike (start now, before committing):** stand up
`MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` behind the draft flag in a branch; run
create → add → remove → self-update → application-message end-to-end to confirm the PQ suite
is functionally complete; measure dependency footprint/build on Android/FFI/desktop; and
prototype the credential mapping + one transport as the DS. The spike output is what turns
"adopt" from a direction into a scheduled migration with real numbers.

## 5. Decision matrix

| Dimension | Adopt OpenMLS (draft-PQ) | Stay in-house |
|---|---|---|
| Pure-PQ ML-DSA-87 available | **Yes** (draft-gated, no IANA point yet) | Yes (shipping, integrated) |
| Posture fit ("EC never load-bearing") | **Passes** with the ML-DSA-87 suite | Passes by construction |
| Protocol state-machine assurance | **High** — standardized + audited (removes the T-2 bug class) | Hand-rolled (the T-2 risk class) |
| PQ ciphersuite assurance | Unaudited-for-PQ (new); the thing to audit | Same primitives, hand-rolled construction |
| Wire stability / interop | Pre-IANA; may change | Stable (self-versioned) |
| Assurance workload | **Shrinks** (audit one ciphersuite, not a whole CGKA) | Grows (own the whole stack forever) |
| Effort / time-to-ship | High (migration + spike) | Low (already integrated) |
| Footprint / portability | Larger; validate on all targets | Small; runs on all targets |
| License | MIT — OK | n/a |
| Control / minimalism | Lower | High |

## 6. Recommended sequence

1. **Interim: ship the hardened in-house TreeKEM** for any zRonin deadline that lands before
   the spike + PQ audit complete — it is posture-pure and already integrated. This is a
   bridge, not the destination.
2. **OpenMLS functional spike — DONE (#81, [`docs/openmls-pq-spike`](./openmls-pq-spike/)):**
   the PQ suite runs the full lifecycle. Remaining spike work: dependency footprint on
   Android/FFI/desktop, the credential mapping, and one transport wired as the DS.
3. **Commission the external audit scoped to OpenMLS's PQ ciphersuite path** (§3) — and stop
   spending audit budget re-validating the hand-rolled TreeKEM.
4. **Migrate to OpenMLS** once the spike is green and the PQ-path audit is satisfactory, gated
   additionally on the draft finalizing / IANA code points if a hard interop or
   wire-stability requirement exists at ship time. Retire the in-house construction proofs;
   keep only the redirected PQ-path assurance.
5. Track `draft-ietf-mls-pq-ciphersuites` to IANA assignment for interop, and OpenMLS's PQ
   suite toward "not experimental."

## 8. Adding a SHA-3 / SHAKE / KMAC ciphersuite to OpenMLS (FIPS-only)

talkrypt's default KDF is KMAC/Keccak (SHA-3 family). OpenMLS has no SHA-3 option, and we
require one — added, per the mandate, using **FIPS/NIST-validated primitives only**.

### 8.1 Why it's a fork, not a provider swap
OpenMLS's `Ciphersuite` is a **closed `#[repr(u16)]` enum**, and its `HashType` enum has
**only SHA-2** (`Sha2_256/384/512`); `hash_algorithm()` is a fixed compile-time match. A
crypto provider implements ops for the *existing* variants — it cannot introduce a new
ciphersuite or a new hash. So SHA-3 support requires a **fork of `openmls_traits`** (plus
`openmls` + a provider):
1. add `HashType::Sha3_384` (and/or a SHAKE256 XOF);
2. add a **private-use** `Ciphersuite` variant, e.g. `MLS_256_MLKEM1024_AES256GCM_SHA3-384_MLDSA87`, at an unregistered u16 code point;
3. point its KDF, transcript hash, and membership MAC at the new hash;
4. propagate the new `HashType` through every match site (KDF extract/expand, transcript hashes, secret-tree/PSK derivations).

### 8.2 FIPS/NIST-validated primitive sources
- **OpenSSL 3.x FIPS provider — recommended, covers everything.** A single FIPS 140-3
  validated module providing **SHA-3, SHAKE, and KMAC (SP 800-185)**, AES-256-GCM, and — as
  of OpenSSL 3.5 (2026) — **ML-KEM-1024 and ML-DSA-87**. This is the only source that cleanly
  covers **KMAC** *and* the PQ primitives in one validated boundary. (Confirm the FIPS
  validation certificate version covers 3.5's PQ module, since CMVP validation lags releases;
  SHA-3/SHAKE/KMAC/AES-GCM are validated in the shipped 3.0.x FIPS provider.) Reachable from
  Rust via `rust-openssl` bound to a FIPS-configured OpenSSL.
- **aws-lc-rs** (AWS-LC FIPS 3.0, already a talkrypt dep for `fips`): FIPS-validated SHA-3 +
  SHAKE + ML-KEM/ML-DSA, but **KMAC FIPS coverage is unconfirmed** — so aws-lc-rs suffices for
  an HKDF-SHA3 KDF, not necessarily for KMAC.
- **NOT usable under the FIPS-only rule:** RustCrypto `sha3` and `tiny-keccak` — which is
  talkrypt's *current* default KMAC KDF. NB this means talkrypt's own default KDF is **not on
  a FIPS path today**; a FIPS SHA-3/KMAC story already requires routing through OpenSSL-FIPS or
  aws-lc-rs regardless of the OpenMLS question.

**Clean overall FIPS story:** author one OpenMLS crypto provider (`OpenMlsCrypto`) backed by
the **OpenSSL 3.5 FIPS provider** — it supplies FIPS-validated KEM (ML-KEM-1024), signature
(ML-DSA-87), AEAD (AES-256-GCM), and hash/KDF (SHA-2 *and* SHA-3/SHAKE/KMAC) for the whole
MLS stack, including the forked SHA-3 ciphersuite. That makes the FIPS boundary one audited
module rather than a patchwork.

### 8.3 KDF choice — HKDF-SHA3-384 vs KMAC
- **HKDF-SHA3-384** (HMAC-SHA3-384): stays inside MLS's HKDF key schedule (RFC 9420 defines
  the KDF as HKDF over the ciphersuite hash) — the new ciphersuite just points MLS's existing
  HKDF at SHA-3-384. Smallest, cleanest fork; available FIPS via aws-lc-rs *or* OpenSSL.
- **KMAC-as-KDF** (talkrypt's Keccak-native preference): a larger deviation — MLS's key
  schedule assumes HKDF, so KMAC replaces the *construction*, not just the hash. Worth it only
  if KMAC specifically (not merely "SHA-3 family") is the hard requirement; needs OpenSSL-FIPS
  for a validated KMAC.

### 8.4 Tension to weigh before committing
A **private** ciphersuite forfeits two adoption benefits: (a) **interop** — an unregistered
code point talks only to other talkrypt nodes (fine for a closed zRonin ecosystem, but then
"standard protocol" is a code-reuse benefit, not an interop one); and (b) it re-introduces
**custom MLS-integration glue** (the `HashType`/ciphersuite fork + KDF wiring) that we own and
must audit — smaller than owning the whole TreeKEM, but not zero. And **SHA-384 is already
CNSA 2.0's specified hash**, so the stock `…SHA384_MLDSA87` suite is standards-compliant with
*no* fork. Confirm SHA-3 is a hard requirement (not a preference CNSA already meets with
SHA-384) before taking on the fork and its audit.

### 8.5 If we proceed
Fork `openmls`/`openmls_traits`; add `HashType::Sha3_384` + the private ciphersuite; back it
with an **OpenSSL-3.5-FIPS-provider** `OpenMlsCrypto` implementation (KMAC or HKDF-SHA3-384 per
§8.3); extend spike #81 to run the full lifecycle under it; scope the external audit to the
added hash/KDF wiring + the provider. Keep the fork rebased on upstream and offer the
`HashType::Sha3` addition to the WG.

## Sources

- OpenMLS `traits/src/types.rs` (PQ ciphersuite variants, `draft-ietf-mls-pq-ciphersuites` feature flag): https://github.com/openmls/openmls/blob/main/traits/src/types.rs
- OpenMLS `openmls_rust_crypto/src/provider.rs` (`supports()`: `MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87 => Ok(())`; `SHA512_MLDSA87` listed-not-supported; `ml_dsa`; HPKE `MlKem1024`): https://github.com/openmls/openmls/blob/main/openmls_rust_crypto/src/provider.rs
- OpenMLS repo (MIT license, providers), book, and docs.rs (`BasicCredential`): https://github.com/openmls/openmls · https://book.openmls.tech/ · https://docs.rs/openmls/latest/openmls/
- OpenMLS post-quantum background: https://blog.openmls.tech/tags/pq/ · https://cryspen.com/post/pq-openmls/
- `draft-ietf-mls-pq-ciphersuites-05` (status, ciphersuites, IANA TBDs): https://datatracker.ietf.org/doc/draft-ietf-mls-pq-ciphersuites/
- RFC 9420 (MLS — security properties, credentials, untrusted delivery service): https://www.rfc-editor.org/rfc/rfc9420.html
- OpenMLS `Ciphersuite`/`HashType` (closed `#[repr(u16)]` enum; `HashType` = SHA-2 only): https://github.com/openmls/openmls/blob/main/traits/src/types.rs
- AWS-LC FIPS 3.0 (FIPS 140-3; SHA-3/SHAKE + ML-KEM in the validated module): https://aws.amazon.com/blogs/security/aws-lc-fips-3-0-first-cryptographic-library-to-include-ml-kem-in-fips-140-3-validation/
- OpenSSL FIPS provider (FIPS 140-3 security policy; SHA-3/SHAKE/KMAC): https://csrc.nist.gov/projects/cryptographic-module-validation-program — OpenSSL 3.5 PQ (ML-KEM/ML-DSA): https://openssl-library.org/
- RustCrypto not FIPS-validated (sha3/tiny-keccak): https://github.com/RustCrypto
