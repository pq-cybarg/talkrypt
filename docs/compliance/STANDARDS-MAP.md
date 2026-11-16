# talkrypt 1.0 — Technology-only standards & compliance map

> **Honest scope — read first.** This document maps talkrypt's **technology** to the
> **technical** requirements of a set of communications-security standards. It records
> *mechanism alignment* and *where each mechanism is implemented* — it is **NOT** a
> certification, validation, accreditation, or statement of compliance. talkrypt is
> **NOT FIPS 140-validated, NOT CSfC-accredited, NOT NSA-approved, NOT HIPAA-certified,
> NOT IEC 62443-certified, NOT independently audited.** "Maps to" / "aligns with" / "implements
> the mechanism specified by" is always about an algorithm or technical control, never a
> guarantee that any accreditation has been obtained. Every row is unverified until an
> independent assessment establishes otherwise.

## Deliberate scope boundary: technology only

By request, this assessment covers **purely technical controls** and **excludes every
organizational, administrative, personnel, physical, procedural, and policy
requirement** — regardless of which framework defines them. Concretely, the following
are **out of scope here** (not because they do not matter, but because they are not
technology):

- Governance, risk-management programs, written policies, SSP/ISSO/ISSM roles.
- Workforce training, sanctions, background checks, separation-of-duties, least-privilege
  *administration*.
- Physical/facility security, media disposal procedures, environmental controls.
- Incident-response *process*, contingency/DR *plans*, Business Associate Agreements,
  audit *programs*, vendor-management *process*.
- Certification/validation lab engagement, Security Policy *documents*, CM/delivery
  *procedures* (these are tracked as deltas in `docs/COMPLIANCE.md §5`, not here).

Where a framework is *mostly* non-technical (HIPAA, IEC 62443 as a whole), only its
**technical-control subset** is mapped, and that is stated explicitly.

Companions this map references instead of duplicating: `docs/SPECIFICATION.md` (system &
security spec), `docs/COMPLIANCE.md` (FIPS 140-3 / CNSA 2.0 self-assessment + crypto
SBOM), `docs/CONFORMANCE.md` (RFC 9420 MLS), `docs/POSTURE.md`, `docs/CSFC.md`,
`formal/README.md` (machine-checked proofs).

---

## 0. Master index

| Framework | What talkrypt maps to (technical only) | Primary reference | Honest status |
| --- | --- | --- | --- |
| **FIPS 203/204/197/180-4/202** | ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-384, SHA3-384 **algorithms** | `COMPLIANCE.md §2,4` | Algorithm choice: aligned. Implementations **not CAVP-validated** (default build) |
| **FIPS 140-3** (ISO/IEC 19790) | module areas 1-11 self-gap-analysis; POST/PCT (area 9) implemented | `COMPLIANCE.md §3,5` | **Not a validated module**; `fips` routes AES/SHA-2 through a CMVP-validated *backend* only |
| **CNSA 2.0** | ML-KEM-1024 + ML-DSA-87 + AES-256 + SHA-384; in-code parameter floor | `COMPLIANCE.md §2` | Algorithm-aligned; default hash SHA3-384 is a documented deviation → `cnsa-sha2` for strict |
| **NIST SP 800-38D** | AES-GCM mode, unique (key,nonce) per message | §1 below | Mechanism implemented; impl not CAVP |
| **NIST SP 800-56C / 800-108 / 800-185** | HKDF-SHA-384 / KMAC256 KDF with domain separation | §1 | Mechanism implemented |
| **NIST SP 800-90A / 90B** | OS DRBG source + startup entropy health tests | §1 | 90B health tests implemented; DRBG boundary not CAVP |
| **NIST SP 800-57 / 800-131A / 800-175B** | key lifecycle (ratchet, rotation, zeroize, revoke) + PQ transition | §1 | Mechanisms implemented |
| **IETF RFC 9420 (MLS)** | tree-math / key-schedule / secret-tree vs official vectors; shipped PQ group **diverges** | `CONFORMANCE.md` | Harness KAT-passes official vectors; shipped group is **not** on-the-wire MLS by design |
| **IETF RFC 8446 (TLS 1.3)** | Tor guard-link TLS via rustls (under `tor`) | §2 | Used by the Arti dependency, not talkrypt's own protocol |
| **IETF RFC 7748 / 5869 / 9106** | X25519 (hybrid half), HKDF, Argon2id | §2 | Mechanisms implemented |
| **Tor onion-service v3 / Nym Sphinx** | anonymity/mixnet transports | §2 | Used via Arti / nym-sdk; opt-in |
| **IEEE** (1363 / 1619 / 802.1x-family) | *limited applicability* — app-layer, transport-agnostic | §3 | Mostly **N/A**; stated per standard |
| **HIPAA Security Rule §164.312** (technical safeguards only) | access control, integrity, auth, transmission security | §4 | 4 of 5 implemented; **audit controls §164.312(b) is a GAP** (no logging subsystem) |
| **IEC 62443-4-2** (comms-security component CRs only) | CR 1/2/3/4 identification, use-control, integrity, confidentiality | §5 | Technical CRs mapped; cert out of scope |
| **ISO/IEC 15408 (Common Criteria) / NIAP PP** | PP-relevant crypto & comms SFRs | §6 | **Not evaluated**; informative mapping only |

---

## 1. NIST — FIPS PQC & SP 800-series (technical mechanisms)

FIPS PQC/symmetric/hash algorithm mapping and the FIPS 140-3 area-by-area gap analysis
are fully developed in **`docs/COMPLIANCE.md`** (§2 CNSA/FIPS algorithms, §3 the eleven
140-3 areas, §4 SBOM, §5 deltas to a validation). This section adds the **SP 800-series
mechanism** mapping not covered there.

| NIST publication | Technical requirement (relevant part) | talkrypt mechanism | Where | Status |
| --- | --- | --- | --- | --- |
| **FIPS 203** | ML-KEM | ML-KEM-1024 KEM | `hybrid.rs`, `ratchet.rs`, `treekem.rs`, `mls/hpke.rs` | [KAT] ACVP keyGen/encaps/decaps |
| **FIPS 204** | ML-DSA | ML-DSA-87 signatures | `identity.rs`, `account.rs`, `treekem.rs`, `mls/sign.rs` | [KAT] FIPS-204 ref |
| **FIPS 205** | SLH-DSA | *not implemented* (no stateless hash-based sig path) | — | N/A — documented absent |
| **FIPS 197** | AES block cipher | AES-256-GCM | `aead.rs` | [KAT] NIST vector |
| **FIPS 180-4** | SHA-2 | SHA-384 (`cnsa-sha2`), SHA-256 (MLS harness only) | `hash.rs`, `mls/schedule.rs` | [KAT] |
| **FIPS 202** | SHA-3 / SHAKE | SHA3-384 (default), SHA3-256 (scheme/KAT) | `hash.rs`, `suite.rs` | [KAT] |
| **SP 800-38D** | GCM mode; nonce uniqueness | AES-256-GCM, per-message (key,nonce) from KDF — no reuse | `aead.rs`, `kdf.rs:20-85` | [PROVEN] DEM independence; nonce uniqueness by construction |
| **SP 800-56C** | key-derivation (extract-then-expand) | HKDF-HMAC-SHA-384 (`cnsa-sha2`) | `kdf.rs:42-48` | implemented |
| **SP 800-108** | KDF in feedback/counter | KMAC256-based `mac_kdf` (default) | `kdf.rs:34-40` | implemented |
| **SP 800-185** | KMAC / cSHAKE | KMAC256 keyed KDF (default) | `kdf.rs`, `tiny-keccak` | implemented |
| **SP 800-90A** | approved DRBG | OS CSPRNG (`getrandom` → kernel DRBG), no interposed user DRBG | `rng.rs:1-38` | source documented; boundary not CAVP |
| **SP 800-90B** | entropy source health tests | startup Repetition-Count + Adaptive-Proportion, abort-on-fail before keygen | `rng.rs:40-100` | [TESTED] (F-4) |
| **SP 800-57 Pt.1** | key-management lifecycle | generation (health-gated), separation (3 KDF domains), rotation (per-message ratchet, per-epoch rekey), destruction (zeroize-on-drop, Miri-verified), revocation | `kdf.rs`, `ratchet.rs`, `treekem.rs`, `mem.rs`, `account.rs:364` | [PROVEN] FS/PCS §9; [TESTED] zeroize |
| **SP 800-131A** | algorithm transition / disallow weak | PQ-pure default; CNSA floor rejects sub-floor params; AES-128 unrepresentable (`&[u8;32]`) | `suite.rs:138-163`, `aead.rs` | [TESTED] floor |
| **SP 800-175B** | guidance on using crypto | end-to-end AEAD above every transport; AAD-bound headers; domain-separated KDFs | `SPECIFICATION.md §2,5,8` | implemented |

Not in technical scope from these (excluded as non-technical, per the boundary above):
the 140-3 **Security Policy document**, CM/delivery procedures, and CAVP/CMVP **lab
engagement** — tracked as deltas in `COMPLIANCE.md §5`, not claimed here.

---

## 2. IETF (and adjacent transport specs)

| Spec | Technical requirement | talkrypt mechanism | Where | Status |
| --- | --- | --- | --- | --- |
| **RFC 9420 (MLS)** | MLS tree-math, key schedule, secret tree, framing | standards harness KAT-passes official vectors; **shipped PQ group deliberately diverges** (PQ ciphersuite + compact framing) | `crates/crypto/src/mls/`, `treekem.rs` | [KAT] vectors; divergence documented in `CONFORMANCE.md` |
| **RFC 8446 (TLS 1.3)** | guard/link transport security | Tor link TLS via rustls `CryptoProvider` installed before any TLS | `crates/transport/src/arti.rs:142-144` | provided by Arti dep (under `tor`), not talkrypt's own handshake |
| **RFC 7748 (X25519)** | Montgomery-curve DH | hybrid-KEM half only, **non-load-bearing** | `hybrid.rs:9-13,325-339` | implemented; never sole |
| **RFC 5869 (HKDF)** | HMAC-based KDF | HKDF-HMAC-SHA-384 under `cnsa-sha2` | `kdf.rs:42-48` | implemented |
| **RFC 9106 (Argon2)** | memory-hard passphrase KDF | Argon2id m=19 MiB,t=2,p=1 at-rest seal | `core/seal.rs:365-373` | implemented |
| **Tor Rendezvous / HS v3** | onion-service addressing & circuits | Arti `tor-hsservice`; ed25519 `.onion`; onion-only dial guard (F-23); restricted-discovery client auth | `arti.rs` | implemented under `tor` |
| **Nym / Sphinx** | mixnet packet format + cover traffic | `nym-sdk` mixnet stream; talkrypt adds no chaff of its own | `nym.rs` | implemented under `nym` |
| **Signal Double Ratchet** (spec, non-IETF) | asymmetric + symmetric ratchet, FS/PCS | PQ Double Ratchet (ML-KEM asymmetric step) | `ratchet.rs` | [PROVEN] FS/PCS (`RatchetFS.fst`) |
| **Noise Framework** (spec, non-IETF) | authenticated key-establishment patterns | PQ-Noise session suite | `noise.rs` | [TESTED] |

Honest note: RFC 8446 applies to a **dependency** (Arti's guard connections), not to any
talkrypt-authored protocol; talkrypt's own session security is the SIGMA handshake + PQ
ratchet/TreeKEM above it. The shipped group is **not** MLS on the wire.

---

## 3. IEEE — limited applicability (stated honestly)

talkrypt is an **application-layer, transport-agnostic** protocol; it does not implement
a link-layer or a PHY, so most IEEE communications-security standards do not apply. For
completeness:

| IEEE standard | Scope | Applicability to talkrypt |
| --- | --- | --- |
| **IEEE 1363 / 1363.1** | public-key crypto schemes (incl. lattice) | **Informative only** — talkrypt follows the NIST FIPS 203/204 parameterizations, not the IEEE scheme definitions. **N/A as a conformance target.** |
| **IEEE 1619 / 1619.1** | at-rest storage encryption (XTS / authenticated modes) | **N/A** — talkrypt seals at rest with AES-256-**GCM** authenticated envelopes (`seal.rs`), not XTS block-storage encryption. The *goal* (confidential+integrity-protected at-rest data) is met by a different, authenticated mechanism. |
| **IEEE 802.1X / 802.11i (WPA2/3)** | link-layer access control & encryption | **N/A** — a deployment concern of the underlying network, below talkrypt's layer. Content security does not depend on it. |
| **IEEE 802.15.4 security** | LR-WPAN MAC security | **N/A** — the LoRa mesh bearer treats mesh-native crypto as untrusted and seals above it (`mesh/mod.rs`). |

No IEEE conformance is claimed. These rows exist to document *why* each is out of scope.

---

## 4. HIPAA Security Rule — §164.312 technical safeguards **only**

**Scope restriction:** this maps **only** the *Technical Safeguards* (45 CFR §164.312).
The **Administrative Safeguards (§164.308)** and **Physical Safeguards (§164.310)** are
organizational/physical and are **excluded by request**. A product cannot itself be
"HIPAA compliant" — compliance is a property of a covered entity's whole program,
including a Business Associate Agreement; what a technology can do is **provide the
technical safeguards a compliant deployment needs**. The following is that mapping.

| §164.312 technical safeguard | Implementation specification | talkrypt mechanism | Where | Status |
| --- | --- | --- | --- | --- |
| **(a)(1) Access control** | — | channel `AccessPolicy` (Open / Accounts / Contacts / Friends) gated by resolved account fingerprint; admission on group join | `engine.rs:728-760,4245-4253` | Implemented |
| **(a)(2)(i) Unique user identification** | Required | ML-DSA-87 identity key / SHA3-384 fingerprint; account→device chain binding | `identity.rs`, `account.rs:207-258` | Implemented; [PROVEN] chain |
| **(a)(2)(iii) Automatic logoff** | Addressable | ephemeral-by-default sessions; no persistent authenticated session without re-keying | `SPECIFICATION.md §8` | Partial / deployment-dependent |
| **(a)(2)(iv) Encryption & decryption (at rest)** | Addressable | Argon2id + AES-256-GCM sealed stores; per-store DEK | `seal.rs:145-222`, `atrest.rs` | Implemented; [PROVEN] fuzz |
| **(b) Audit controls** | **Required** | **GAP — no audit-logging subsystem exists** (design deliberately excludes logging/telemetry). A deploying covered entity must supply audit logging externally. | `DESIGN.md:64-67` | **Not implemented (honest gap)** |
| **(c)(1) Integrity** | Required | AES-256-GCM tag + AAD-bound headers on every message; per-sender ML-DSA-87 group-message signature verified before decrypt; at-rest AAD binding; chain tamper detection | `aead.rs`, `ratchet.rs:33-45`, `treekem.rs`, `atrest.rs:117-164` | Implemented; [PROVEN] auth §9 |
| **(d) Person-or-entity authentication** | Required | SIGMA mutual handshake (both sides ML-DSA-87-sign transcript); device-cert chain vs pinned account; revocation refuses leaked keys | `handshake.rs:41-216`, `account.rs:258`, `:364` | Implemented; [PROVEN] `Handshake.fst` |
| **(e)(1) Transmission security** | Required | two-layer: E2E PQ ratchet/group AEAD **inside** anonymity transport; relay sees ciphertext only | `transport/`, `relay.rs` | Implemented |
| **(e)(2)(i) Integrity controls (in transit)** | Addressable | AEAD integrity + SIGMA transcript binding (downgrade/field-substitution resistant) | `aead.rs`, `handshake.rs:34-59` | Implemented |
| **(e)(2)(ii) Encryption (in transit)** | Addressable | AES-256-GCM under PQ-established keys on every bearer | `SPECIFICATION.md §2,6` | Implemented |

**Net:** talkrypt supplies the technical safeguards for §164.312 **except audit controls
(b)**, which it deliberately does not implement (no telemetry/logging). That is an honest,
material gap for any HIPAA deployment and must be met outside talkrypt.

---

## 5. IEC 62443-4-2 — communication-security component requirements **only**

**Scope restriction:** IEC 62443 is an industrial-automation security *program* standard;
only the **4-2 technical component requirements (CRs)** relevant to secure communication
are mapped. Zone/conduit architecture, the 62443-2-x organizational requirements, and
maturity/process levels are **excluded by request**. Security-level (SL) targets and
certification are out of scope.

| IEC 62443-4-2 CR (comms-relevant) | Technical requirement | talkrypt mechanism | Where | Status |
| --- | --- | --- | --- | --- |
| **CR 1.1 / 1.2** Human & software-process identification/authentication | authenticate endpoints | SIGMA mutual ML-DSA-87 handshake; identity = ML-DSA-87 keypair; KeyPackage PoP | `handshake.rs`, `identity.rs`, `treekem.rs:416-431` | Implemented; [PROVEN] |
| **CR 1.5** Authenticator management | manage keys/certs, validity | account→device→segment cert chain with validity windows + skew tolerance; short-lived (24 h) one-time link certs | `account.rs:85-173`, `linking.rs:146` | Implemented |
| **CR 1.9** Strength of public-key authentication | strong PKI | ML-DSA-87 (FIPS 204, Cat 5) everywhere; multi-registry cross-compare; revocation | `account.rs`, `registry.rs` | Implemented |
| **CR 2.1** Use control / authorization enforcement | enforce authz | access policy gating membership + KeyPackage honoring; vouch guard (Kani-proven) | `engine.rs:728-760`, `vouch.rs:353` | Implemented; [PROVEN] vouch |
| **CR 3.1** Communication integrity | detect comms tampering | AES-256-GCM + AAD on message & ratchet headers; SIGMA transcript binding; signed commits/roster (F-17) | `aead.rs`, `handshake.rs`, `treekem.rs:510` | Implemented; [PROVEN] §9 |
| **CR 3.4** Software/information integrity | detect data tampering at rest/release | sealed at-rest AAD binding; PQ-signed (ML-DSA-87) release manifest vs pinned key | `atrest.rs`, `crates/relsign/` | Implemented (F-8) |
| **CR 4.1** Information confidentiality | protect data in transit & at rest | PQ E2E (ML-KEM-1024 → AES-256-GCM) with FS/PCS; at-rest seal; metadata via Tor/Nym + opt-in padding | `ratchet.rs`, `treekem.rs`, `seal.rs` | Implemented; [PROVEN] confidentiality §9 |
| **CR 4.3** Use of cryptography | approved, correctly-used crypto | CNSA-aligned primitives; in-code floor; per-message nonce uniqueness; POST + CAVP-traceable KATs | `suite.rs`, `aead.rs`, `selftest.rs` | Implemented; [KAT] |

No SL-rating or IEC certification is claimed; this is a technical-CR mapping only.

---

## 6. Common Criteria (ISO/IEC 15408) / NIAP Protection Profiles — informative

talkrypt has **not** undergone a Common Criteria evaluation and claims no EAL or PP
conformance. Informatively, the crypto/comms **Security Functional Requirements** that a
network-device or app PP would exercise — **FCS** (cryptographic support: key generation,
key distribution, operation, destruction), **FIA** (identification & authentication),
**FDP** (user-data protection / confidentiality & integrity in transit and at rest),
**FPT** (self-test, TSF protection) — map to §1–§5 above and to `SPECIFICATION.md §9`
(POST/PCT = the FPT_TST self-test family; zeroize = FCS_CKM.4). This row exists to
orient a future evaluation, not to assert one.

---

## 7. Consolidated honest-scope conclusion

talkrypt **1.0** is, at the **technology/mechanism** level:

- **CNSA 2.0 algorithm-aligned** with an in-code parameter floor (`COMPLIANCE.md §2`);
- **FIPS-algorithm-aligned** (FIPS 203/204/197/180-4/202) with POST + per-keygen PCT +
  official-vector KATs, and **FIPS-capable** via a CMVP-validated backend under `fips`
  (the backend's validation, not talkrypt's);
- mapped to the **SP 800-series** key-management / KDF / DRBG-health / GCM mechanisms;
- an **RFC 9420 harness** that passes official MLS vectors, shipping a deliberately
  **non-MLS PQ group** on the wire;
- a supplier of the **HIPAA §164.312 technical safeguards except audit controls (b)**;
- aligned to the **IEC 62443-4-2 communication-security technical CRs**.

It is **none of**: FIPS 140-validated, CSfC-accredited, NSA-approved, HIPAA/IEC/CC
certified, or independently audited. Every "maps to" here is a technical statement about
a mechanism and its implementation site, **not** a certification. Treat all of it as
unverified until an independent assessment says otherwise.
