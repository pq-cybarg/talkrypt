# Security Assurance

What backs the security claims — and the honest limits. Full report:
`docs/SECURITY-AUDIT.md`. This is a **self-assessment**, not an independent audit.

## Threat model

- **In scope:** a passive/active network & metadata observer; a store-now-
  decrypt-later (quantum) adversary; first-contact MITM; a malicious peer; theft
  of a key for *past* traffic; hostile/malformed wire input.
- **Out of scope:** a live-compromised endpoint (keylogger, screen capture,
  kernel-level RAM scraping); global traffic-confirmation against Tor; coercion.

## What's tested

- **~243 automated tests** across the workspace (AEAD integrity, forward secrecy
  & post-compromise recovery, identity/auth unforgeability, access control,
  algorithm-floor enforcement, group removal FS, wire KATs, sealing).
- **9 coverage-guided fuzz targets** over every attacker-reachable decoder
  (`wire_reader`, `descriptor_parser`, `identity_chain`, `signed_claim`,
  `revocation`, `presentation`, `ratchet_header`, `beacon_body`, `suite_scheme`)
  — these **found and fixed** a remote-DoS panic (F-14). CI smoke job per change.
- **Miri** verifies secret zeroization (and the `LockedBox` drop) is wipe-correct
  and UB-free. A **Kani** proof bounds the wire decoder.
- **Dependency scanning** — `cargo audit` + `cargo deny` in CI (push/PR +
  weekly): advisories, licenses, banned crates, source policy.
- **Power-on self-tests** with **CAVP-traceable KATs** against official NIST
  vectors ([Cryptography](Cryptography.md)).

## Findings (F-1 … F-15)

| ID | Sev | Finding | Status |
| --- | --- | --- | --- |
| F-1 | High (meta) | No independent audit/review/pentest — every property is externally unverified | **Open** (disclosed) |
| F-2 | Med | Dependency scanning not in CI | Resolved |
| F-3 | Low | Transient secrets not zeroized | Resolved (Miri-verified) |
| F-4 | Low | Bare `getrandom`, no SP 800-90B / approved DRBG wrapper | Open |
| F-5 | Low | Cert ±5-min clock-skew tolerance | Accepted |
| F-6 | Info | Default hash is SHA3-384, not CNSA-named SHA-384 | By design (`cnsa-sha2`) |
| F-7 | Info | Group layer is custom PQ, not MLS-conformant | By design |
| F-8 | Low | Packages ad-hoc/un-signed; integrity rests on checksums | Open |
| F-9 | Info | Timing posture undocumented | Reviewed (R-4) |
| F-10 | Info | GUI bundles not built/tested in CI | Open |
| F-11 | Med | Suite floor checked the tag, not the parameters | Resolved |
| F-12 | Info | MLS conformance harness instantiates no cipher | By design |
| F-13 | Med | `rsa` Marvin advisory (transitive via Arti) | Resolved (vendored + source-patched) |
| F-14 | Med | Remote-DoS panic in the ratchet-header decoder (found by fuzzing) | Resolved (+ regression) |
| F-15 | Med | RAM-capture: secrets could swap/dump; no process hardening | Resolved/mitigated |

## Recommendations (R-1 … R-8)

| ID | Status | Recommendation |
| --- | --- | --- |
| R-1 | Done | `cargo audit` + `cargo deny` in CI |
| R-2 | **High, open** | Commission an **independent cryptographic review** |
| R-3 | Done | Miri-verify zeroization in CI |
| R-4 | Done | Constant-time review (§3a) |
| R-5 | Done | POST + per-keygen PCT + CAVP-traceable KATs (incl. NIST FIPS-203 ACVP) |
| R-6 | Done | Fuzz every attacker-reachable decoder |
| R-7 | Low | Sign/notarize packages once a release identity exists |
| R-8 | In progress | RAM-capture hardening + hardware-backed at-rest sealing |

## The dominant risk

talkrypt's security rests on self-testing. A single implementation bug could
silently void any property — the **only** remediation is **R-2, an independent
audit**. Until then, do not rely on it for high-stakes confidentiality. This is
stated everywhere, by design. See [Classification & Compliance](Classification-and-Compliance.md).
