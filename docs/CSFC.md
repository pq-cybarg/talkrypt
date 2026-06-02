# CSfC alignment

**Honest framing:** talkrypt is **architecture-aligned** with NSA's Commercial
Solutions for Classified (CSfC) program. It is **not** a CSfC-accredited
solution, and shipping software cannot make it one. This document maps what the
architecture does to CSfC's requirements, and states plainly what only an
organization (not code) can provide.

## CSfC in one paragraph

CSfC lets you protect classified data using **two independent layers of
commercial encryption** instead of NSA Type-1 crypto. Each layer must use
components from the **CSfC Components List** (NIAP Common Criteria + FIPS 140
validated), be configured per an NSA **Capability Package (CP)**, be deployed
by a **Trusted Integrator**, and be **registered with NSA**. The guarantee: a
flaw or compromise in one layer never exposes the protected data, because the
second, independent layer still stands.

## The two layers in talkrypt

```
            ┌─────────────────────────────────────────────┐
 plaintext  │  INNER LAYER  — E2E PQ Double Ratchet          │  AES-256-GCM
   ───────► │   keys: invite-token PSK + ML-KEM-1024         │  (RustCrypto / aws-lc-rs)
            │   (posture: PQ-pure default, or +X25519 hybrid)│
            └───────────────────────┬─────────────────────-┘
                                    │ ciphertext only
            ┌───────────────────────▼─────────────────────-┐
            │  OUTER LAYER — Tor onion service (Arti)        │  onion + rustls
            │   keys: ed25519 onion id + x25519 ntor circuit │  (independent codebase)
            └───────────────────────────────────────────────┘
                                    │
                              network / adversary
```

- **Independent implementations:** the inner layer is our crypto stack; the
  outer layer is Arti. Different code, different maintainers — reduces
  common-mode failure, as CSfC intends.
- **Independent keys:** inner keys (ratchet) and outer keys (onion/circuit)
  share no material. Breaking one layer's keys does not yield the other's.
- **The two CSfC layers are inner-E2E vs. outer-Tor** — *not* the inner KEM's
  pure-vs-hybrid choice. The inner posture (PQ-pure by default; `+X25519`
  hybrid optionally) is intra-layer belt-and-suspenders; the CSfC second layer
  is the outer onion. Each layer is individually sufficient for
  confidentiality: with Tor fully broken the inner PQ E2E layer still protects
  content, and the inner layer rests on ML-KEM-1024 against a quantum adversary
  regardless of posture.

## Requirement mapping

| CSfC requirement | Status in talkrypt | Notes |
|---|---|---|
| Two independent encryption layers | ✅ architecture | Inner E2E PQ + outer Tor onion |
| No cross-layer key reuse | ✅ enforced by design | Distinct key hierarchies |
| Approved cryptographic suite | ◐ algorithm-aligned | CNSA 2.0 PQ set; `fips` backend |
| FIPS 140 validated module | ◐ buildable | `--features fips` → aws-lc-rs validated module; validation is the vendor's, not ours |
| Components on CSfC Components List | ❌ out of scope | Requires NIAP CC + FIPS *product* certification |
| Conformance to a Capability Package | ❌ out of scope | Closest CPs: Mobile Access (MA), Multi-Site Connectivity (MSC) |
| Trusted Integrator deployment | ❌ organizational | |
| NSA registration | ❌ organizational | |
| Separate CAs / key management per layer | ◐ partial | Inner keys self-managed; PKI per CP is operational |
| Continuous monitoring, red/black separation | ❌ operational | |

Legend: ✅ done in code · ◐ partially / buildable · ❌ organizational, not code.

## What we enforce in code: the CSfC preflight

`talkrypt_core::csfc::preflight` evaluates the architectural preconditions we
*can* check and returns a structured report:

- two distinct layers present (inner E2E + outer onion transport),
- inner suite at the post-quantum floor — ML-KEM-1024, PQ-pure or hybrid (no
  weak suite),
- FIPS-validated AEAD backend active,
- ephemeral or sealed-at-rest key handling.

It also enumerates the organizational requirements it cannot verify, so an
operator sees the full picture rather than a false "compliant" stamp.

## Strengthening alignment further (optional, future)

- A true **second inner layer** (double-encrypt under two independent KEMs)
  to mirror "two layers each individually sufficient" *within* the E2E payload,
  independent of Tor.
- A documented build/run **CSfC profile** that hard-fails unless `fips` is on,
  the suite floor is post-quantum, and the outer onion layer is active.
- A written mapping to a specific Capability Package once a target CP is chosen.
