# Classification & Compliance

What talkrypt aligns with — and, just as importantly, what it is **not**. Deep
specs: `docs/POSTURE.md`, `docs/COMPLIANCE.md`, `docs/CSFC.md`. Source:
`crates/core/marking.rs`, `crates/core/csfc.rs`, `crates/crypto/suite.rs`.

## Classification markings

talkrypt can carry a per-channel **classification marking** (level + advisory SCI
compartments + dissemination caveats, e.g. `SECRET//SI//NOFORN`):

- **Build-gated** — *originating* a marking needs the `--features markings` build;
  *reading* a received marking always works (safety). Off in consumer builds.
- **Integrity-protected** — the marking rides **inside** the AEAD-encrypted
  payload, so it's confidential and tamper-evident.
- **Advisory label, not a control** — the marking never changes how strongly
  content is protected. The crypto is uniform and maximal for **every** level
  (CNSA 2.0 is single-tier: ML-KEM-1024 / ML-DSA-87 / AES-256 are approved up to
  TOP SECRET). Actual compartment **access** is enforced by [TreeKEM group
  membership](Messaging-and-Transport.md) — who holds the group key — not by the
  label.

## CNSA 2.0

talkrypt implements the **NSA CNSA 2.0** algorithm set ([see the
algorithms](Cryptography.md)). The suite registry enforces the parameter floor
*in code*, against declared parameters (not a self-declared tag), and the AEAD
key type structurally bars sub-256-bit keys (`docs/COMPLIANCE.md`,
`SECURITY-AUDIT.md F-11`). The default hash is SHA3-384/KMAC256 (FIPS 202);
`--features cnsa-sha2` switches to the CNSA-named SHA-384/HKDF.

## FIPS posture

- A FIPS 140-3 **gap self-assessment** maps 11 areas (`docs/COMPLIANCE.md`):
  done — power-on self-tests + CAVP-traceable KATs, fuzzing/Kani, timing review,
  zeroization, dependency scanning; open — an approved DRBG wrapper, a formal
  module boundary + Security Policy, empirical side-channel testing.
- `--features fips` routes AES-256-GCM + SHA-2 through **aws-lc-rs** (a
  CMVP-validated module). The *binary* is not itself a validated module — the
  validation belongs to the vendor — and ML-KEM/ML-DSA remain RustCrypto.

## CSfC

talkrypt is **architecture-aligned** with CSfC's layered model: an inner E2E PQ
layer (the [Double Ratchet](Cryptography.md)) inside an outer
[Tor onion](Messaging-and-Transport.md) layer — independent implementations,
independent key hierarchies, each layer individually sufficient. `talkrypt csfc`
prints a preflight checklist and enumerates the **organizational** requirements
it cannot verify (Trusted Integrator, NSA registration, Components-List
listing). See `docs/CSFC.md`.

## The honesty posture

> talkrypt is **experimental, pre-release** software: **NOT** independently
> audited, **NOT** FIPS-validated, **NOT** CSfC-accredited, **NOT** NSA-approved,
> **NOT** authorized for classified use. Implementing the CNSA 2.0 *algorithms*
> is not certification. Every package and the `version` banner repeat this. The
> dominant risk is the absence of independent review — see
> [Security Assurance](Security-Assurance.md).
