# talkrypt 1.0 — System & Security Specification

> **Status — read this first.** talkrypt is **NOT certified, NOT FIPS 140-validated,
> NOT CSfC-accredited, NOT NSA-approved, NOT authorized for any classification level,
> and NOT independently audited.** This document is a *self-written technical
> specification*: it states precisely what the 1.0 system does, which security
> properties are claimed, and — honestly — which of those are machine-checked, which
> are tested, and which are assumptions. "CNSA-aligned" and every standards reference
> here mean **algorithm / mechanism choice**, never a validation or accreditation. See
> the README banner, `SECURITY.md`, and `docs/SECURITY-AUDIT.md` (finding register).

This is the single consolidated specification for talkrypt **1.0**. It is deliberately
reference-heavy: the normative detail for each area lives in a focused companion
document, and this spec ties them into one picture and records the **assurance status**
(machine-checked / tested / assumed) of every security-relevant property.

Companions: `docs/DESIGN.md` (architecture), `docs/WIRE.md` (frozen wire format),
`docs/COMPLIANCE.md` (FIPS 140-3 / CNSA 2.0 self-assessment + crypto SBOM),
`docs/CONFORMANCE.md` (RFC 9420 MLS status & divergence), `docs/POSTURE.md` (KEM
posture / wire indistinguishability), `docs/CSFC.md` (CSfC layering preflight),
`docs/compliance/STANDARDS-MAP.md` (technology-only cross-framework standards map),
`formal/README.md` (machine-checked proofs).

---

## 0. Document conventions

- **MUST / SHALL** — a normative invariant the implementation enforces (and, where
  noted, a proof or test guards it).
- **Assurance tags** on each property: **[PROVEN]** machine-checked (F\* / EasyCrypt /
  Kani); **[KAT]** known-answer-tested against official vectors; **[TESTED]** covered by
  unit/property/fuzz tests; **[ASSUMED]** a stated assumption (e.g. primitive security,
  network liveness) reduced to but not proven here.
- File citations are `crate/path:line` against the 1.0 tree.

---

## 1. Scope & system overview

talkrypt is a minimalist, IRC-like, **post-quantum end-to-end-encrypted** chat. Messages
are sealed with a PQ Double Ratchet (pairwise) or a custom PQ TreeKEM group layer
(ML-KEM-1024 / ML-DSA-87 / AES-256-GCM, the CNSA 2.0 algorithm set); the transport sees
**only ciphertext and routing addresses**. It runs over LAN/TCP, Tor (Arti) onion
services, the Nym mixnet, or a LoRa mesh, with CLI / TUI / desktop / Android front-ends
over one shared Rust core.

**Trust model (one sentence):** identity and authentication are **pure post-quantum**
(ML-DSA-87); elliptic curve (X25519) is *never load-bearing* — it appears only as the
optional non-primary half of a hybrid KEM, so a classical break never costs
confidentiality or authenticity.

The cryptographic core is implemented **once** in `talkrypt-crypto` and consumed
unchanged by every client and the FFI — there is no per-platform crypto
reimplementation (`docs/COMPLIANCE.md:20-24`).

---

## 2. Cryptographic specification

### 2.1 Algorithm suite (normative)

| Role | Algorithm | Parameters | Standard | Source (default build) |
| --- | --- | --- | --- | --- |
| KEM / key establishment | **ML-KEM-1024** | Cat 5; ek 1568 B, ss 32 B | FIPS 203 | `ml-kem` 0.2.3 |
| Signature / identity | **ML-DSA-87** | Cat 5; seed 32 B, vk 2592 B, sig 4627 B, deterministic, empty ctx | FIPS 204 | `ml-dsa` 0.1.1 |
| AEAD | **AES-256-GCM** | 256-bit key, 96-bit nonce, 128-bit tag | FIPS 197 + SP 800-38D | `aes-gcm` 0.10.3 |
| Hash (default) | **SHA3-384** | 384-bit | FIPS 202 | `sha3` 0.10.9 |
| KDF/MAC (default) | **KMAC256** | keyed, label = customization string | SP 800-185 | `tiny-keccak` 2.0.2 |
| Hash (`cnsa-sha2`) | **SHA-384** | 384-bit | FIPS 180-4 | `sha2` 0.10.9 |
| KDF (`cnsa-sha2`) | **HKDF-HMAC-SHA-384** | extract+expand | SP 800-56C / 800-108 / RFC 5869 | `hkdf` 0.12.4 |
| Hybrid half (optional, DiD) | **X25519** | 32-B Montgomery DH | RFC 7748 | `x25519-dalek` 2.0.1 |
| At-rest passphrase KDF | **Argon2id** | m=19 MiB, t=2, p=1, v1.3, 32-B out | RFC 9106 | `argon2` 0.5.3 |

Canonical suite IDs and the in-code CNSA floor that rejects any sub-floor *declared
parameter set* are specified in `docs/COMPLIANCE.md:36-77` (`suite.rs::meets_cnsa_floor`,
enforced on registry insert). The AEAD key type is `&[u8; 32]`, so an AES-128-length key
is unrepresentable (`crates/crypto/src/aead.rs`).

- **[ASSUMED]** ML-KEM-1024 IND-CCA, ML-DSA-87 EUF-CMA, AES-256-GCM one-time
  confidentiality/integrity, KMAC256/HKDF PRF security — the primitive assumptions the
  proofs in §9 reduce to.

### 2.2 KDF domain separation (normative)

Three separated derivation domains, labels `talkrypt/v1/{rk,ck,mk}`
(`crates/crypto/src/kdf.rs:25-85`): `kdf_rk` (root step), `kdf_ck` (chain step),
`kdf_mk` (message-key → AES key ‖ 96-bit nonce). Per-message **(key, nonce) are unique
by construction**, so GCM nonce reuse cannot arise from the ratchet. **[PROVEN]** DEM
message-independence under fresh keys (`formal/ConfidentialityQROM.ec`); **[KAT]** KDF
determinism + domain separation (`selftest.rs`).

### 2.3 Hybrid KEM (defense-in-depth, optional)

In the hybrid posture the asymmetric step concatenates `dh(32) ‖ kem(32)` as IKM
(`crates/crypto/src/hybrid.rs:325-339`). X25519 is **strictly additive**: the CNSA floor
is met by ML-KEM-1024 regardless, and in the default/compact PQ-pure postures X25519 is
absent; the padded PQ-pure posture writes X25519-shaped filler that **never enters key
derivation** (`hybrid.rs:74-120,408-418`; wire indistinguishability in `docs/POSTURE.md`,
`docs/WIRE.md:28-38`).

### 2.4 Randomness & entropy

Source: OS CSPRNG via `rand::rngs::OsRng` (`getrandom` → kernel SP 800-90A DRBG;
`crates/crypto/src/rng.rs:1-38`), no interposed user-space DRBG. **[TESTED]** SP 800-90B
**startup health tests** — Repetition Count (C=6) and Adaptive Proportion (W=512, C=66,
α≈2⁻⁴⁰) — run over a fresh draw before any key is minted and **abort start-up** on
failure (`rng.rs:40-100`; SECURITY-AUDIT F-4). Keygen is health-gated via
`SecureRng`/`fill_secure`.

### 2.5 Power-on & conditional self-tests (SECURITY-AUDIT R-5)

`self_test()` runs once and `abort()`s on any failure, before any keygen (suite-registry
init, `SecureRng::new`; `selftest.rs:199-224`):

- **[KAT]** AES-256-GCM (NIST empty-message vector) + round-trip + tamper reject.
- **[KAT]** Active hash — SHA3-384 (default) / SHA-384 (`cnsa-sha2`).
- **[KAT]** KDF determinism + domain separation.
- **[KAT]** **ML-KEM-1024 keyGen against NIST FIPS-203 ACVP** (ek/dk SHA3-256 digests)
  + encaps/decaps agreement; full encaps/decaps vectors in
  `crates/crypto/tests/nist_mlkem_acvp.rs`.
- **[KAT]** **ML-DSA-87 keyGen against the FIPS-204 reference seed** + deterministic
  sigGen KAT + verify + wrong-message/wrong-key reject.
- **[TESTED]** SP 800-90B entropy health folded into POST.
- **[TESTED]** **Per-keygen PCT**: every ML-DSA-87 keygen signs+verifies a probe;
  every ML-KEM-1024 keygen encaps/decaps-agrees; abort on mismatch
  (`identity.rs:80`, `hybrid.rs:183,275`).

The commonly-cited C2SP/CCTV ML-KEM vectors are FIPS-203-**draft** and are deliberately
**not** used (`docs/COMPLIANCE.md:152-155`).

---

## 3. Identity, trust & authorization specification

| Mechanism | What it binds | Where | Assurance |
| --- | --- | --- | --- |
| Long-term identity | ML-DSA-87 key; SHA3-384 fingerprint = safety number | `crates/crypto/src/identity.rs` | [PROVEN] chain logic §9; [KAT] sign |
| Account→device→segment chain | account ML-DSA-87 key certifies devices; devices certify segments; validity windows + ±5-min skew | `crates/crypto/src/account.rs:85-229,258` | [PROVEN] `formal/IdentityChain.fst` |
| Multi-device linking | primary certifies a new device over an authenticated session; 24 h TTL, one-time, fail-closed | `crates/core/src/linking.rs:146,295` | [TESTED] |
| Revocation | account-signed; propagated in-band; locks out a leaked key, fail-closed | `account.rs:364`; engine `engine.rs:1406,1426` | [PROVEN] §9 (revocation-unforgeable/refused); [TESTED] |
| Username registries + cross-compare | self-signed claims; multi-registry agreement defeats equivocation | `crates/core/src/registry.rs`; `account.rs:341` | [TESTED] |
| Contacts / access (unbundled) | **recognition** (pin account key) is distinct from **access** (channel grant) | `crates/core/src/contacts.rs:193`; engine `AccessPolicy` | [PROVEN] fail-closed §9; [TESTED] |
| Vouching / web-of-trust | account-signed, per-chat, **additive-only** trust; sybil-antibody backfire | `crates/core/src/vouch.rs` | [PROVEN] Kani: vouched ⇒ score ≥ 0 |
| Linkage / predicate proofs | verifier learns only pass/fail of a bound predicate; per-chat anti-replay | `crates/core/src/linkage.rs`; `crates/crypto/src/grouping.rs` | [PROVEN] unlinkability (`LeafSigDeriveUnlink.ec`); [TESTED] |
| Self-declared names / CQ beacons | Linked presence is device-signed + chat-context-bound (insider-unforgeable) | `crates/core/src/presence.rs`, `nametrust.rs` | [TESTED] |

**Authorization (control plane) MUST be host-gated and signed:** group commits carry a
per-committer ML-DSA-87 signature; the roster is host-signed and monotonic-epoch checked;
`Accounts` policy fails closed (SECURITY-AUDIT F-17). **[PROVEN]** `formal/EngineAuth.fst`
(9 theorems) + `GroupAuthQROM.ec` route-completeness.

---

## 4. Protocol specification

| Protocol | Construction | Where | Assurance |
| --- | --- | --- | --- |
| Handshake | SIGMA-style mutual auth; both sides ML-DSA-87-sign the full transcript (identities, nonces, prekey, suite); root from invite-token PSK (+ optional Argon2id channel password) | `crates/core/src/handshake.rs:41-216`; `descriptor.rs:256-290` | [PROVEN] `formal/Handshake.fst` (mutual auth, agreement, domain-sep, session-secrecy) |
| Pairwise messaging | PQ **Double Ratchet** — ML-KEM-1024 asymmetric ratchet (+optional X25519), per-message symmetric ratchet, AES-256-GCM with header bound as AAD | `crates/crypto/src/ratchet.rs`, `hybrid.rs` | [PROVEN] `formal/RatchetFS.fst` (FS + PCS); [TESTED] out-of-order/skip |
| Session alternative | **PQ-Noise** single-establishment suite (session-granularity FS) | `crates/crypto/src/noise.rs` | [TESTED] |
| Group (shipped default) | custom PQ **TreeKEM** CGKA — ratchet tree, per-epoch/per-sender chains, Add/Remove commits, Welcome; per-sender ML-DSA-87 message signature verified **before** decrypt | `crates/crypto/src/treekem.rs` | [PROVEN] `formal/GroupAuth.fst` + `GroupAuthQROM.ec` + `TreeKemKS.fst` (PCS/FS) |
| MLS standards harness | RFC 9420 tree-math / key-schedule / secret-tree validated vs **official vectors**; PQ sign/HPKE; instantiates no cipher on any message path | `crates/crypto/src/mls/` | [KAT] official MLS vectors (`docs/CONFORMANCE.md`) |
| Non-member relay | terminates the pairwise hop, forwards still-encrypted group frames; holds **no** group key | `crates/core/src/relay.rs` | [TESTED] |

Group confidentiality healing (PCS) on rekey and forward secrecy on removal are
**[PROVEN]** in `formal/TreeKemKS.fst`.

---

## 5. Wire format

Custom compact **length-prefixed** encoding (big-endian, `u32` length prefix per byte
field, hard `MAX_FRAME = 16 MiB` ceiling before allocation); **not** RFC 9420
TLS-presentation framing, by design. The codec "carries only opaque ciphertext and
protocol headers; it never sees plaintext or key material"
(`crates/wire/src/lib.rs:1-22`). Frozen + KAT-locked: `docs/WIRE.md`.

- **[PROVEN]** wire `Reader` primitives panic-free + in-bounds; length-bucket
  quantization (`padded_len` is a bucket multiple, never truncates, overhead < one
  bucket); `unpad` no-panic (Kani, `crates/wire/src/lib.rs:301-384`).
- **F-16 length-bucket padding** is applied **inside the group AEAD**, not in transport;
  the wire layer only provides the primitive. Default off, opt-in per chat
  (descriptor v4 `message_padding`).

---

## 6. Transport specification

One `Transport`/`Listener`/`Stream` trait triple carries opaque frames; `Endpoint` is a
string; the engine never learns which network a peer used
(`crates/transport/src/lib.rs`, `multi.rs:16-18`). **No transport is enabled by default
at the crate level** (`default = []`); mesh *codecs* compile unconditionally but radios
are gated.

| Bearer | Protocol / standard | Framing | Observer sees | Gate | Assurance |
| --- | --- | --- | --- | --- | --- |
| Loopback | in-process mpsc | none | nothing (no network) | default | [TESTED] |
| TCP | plain TCP, no TLS (dev) | `u32`-len prefix | IP, timing, exact frame lengths, ciphertext | default | [TESTED] |
| **Tor / Arti** | Tor onion service **v3**; guard link TLS 1.3 (RFC 8446, rustls) | len prefix inside onion stream | onion-routed ciphertext + circuit timing; no IP/location; length hidden | `tor` | [TESTED]; F-23 onion-only dial guard, F-27 bounded backlog |
| **Nym** | Nym **mixnet** (Sphinx); mix path X25519 (RFC 7748) | len prefix over mixnet stream | Sphinx-wrapped ciphertext + mixnet unlinkability/cover | `nym` | [TESTED]; F-24 mutex timeout |
| Mesh / LoRa | Meshtastic / Meshcore / MQTT bearers; talkrypt seal rides **above** untrusted mesh crypto | flat magic headers (cleartext) + opaque sealed chunk | fragment existence, kind, counters, forgeable `from`, timing; **not** content | codecs default; radios `mesh-radio`/`mesh-mqtt` | [PROVEN] frag & packet decoders total (Kani); F-20/F-21/F-22 |

Mesh-native crypto (Meshtastic AES-256-CTR per-channel default key `AQ==`, no PFS/no
channel auth; Meshcore AES-128) **does not meet talkrypt's bar** and is treated as an
untrusted outer wrapper; native/plaintext downgrade send is gated behind explicit
consent (`NativeSend` default `Off`) (`crates/transport/src/mesh/mod.rs:17-165`).

---

## 7. Persistence & at-rest specification

- **Sealed-envelope codec (`TKS1`)** + `KeyWrapper` custody seam: SoftwareSealed /
  OsKeystore / HardwareBacked tiers; Argon2id(m=19 MiB,t=2,p=1) + AES-256-GCM seal of the
  ML-DSA identity seed; header bound as AAD (`crates/core/src/seal.rs:145-222,365-373`).
  **[PROVEN]** `seal::tier_of`/`unseal` fuzzed ~16 M runs clean (F-15).
- **Serverless store-and-forward (sub-spec D):** sealed on-disk outbox + consented
  history, per-store DEK, fresh nonce, AAD binds record to store-kind/chat/id; tampered
  records fail-open and are skipped (`crates/core/src/outbox.rs`, `history.rs`,
  `atrest.rs:117-164`). Authenticated `PromoteCommit`.
- **PQC-not-in-secure-elements caveat:** StrongBox / Secure Enclave / TPM are
  classical-only and cannot custody ML-DSA-87; only **at-rest sealing** is
  hardware-backed (SECURITY-AUDIT R-8; `docs/hardware-backed-sealing.md`).

---

## 8. Privacy & metadata model

Content is sealed by the PQ + AEAD inner layer that rides **above every transport**, so
no bearer or relay sees plaintext. Residual metadata, per the audit:

- **F-16 (length side-channel):** a non-member relay decrypts the *pairwise* hop to route
  and thus saw inner-ciphertext size + timing. Mitigation = length bucketing inside the
  group AEAD (opt-in). **Residual inherent leak:** a blind relay must see the
  **destination** in cleartext → the DM-destination graph is visible; the mitigation is
  topological (P2P / gossip) or the **Nym mixnet**, not a patch
  (`docs/SECURITY-AUDIT.md:44,223`).
- **F-17 (control-plane forgery) — RESOLVED:** every `Commit` is committer-signed and the
  `Roster` host-signed + monotonic (ML-DSA-87). **[PROVEN]** §9.
- No telemetry / no metadata-logging subsystem exists in core/server/cli/topology;
  ephemeral-by-default (`docs/DESIGN.md:64-67,362-368`; verified absence).

---

## 9. Assurance specification (the overall formal picture)

This is the consolidated "what is actually proven vs tested." Full detail +
model↔code fidelity in `formal/README.md`; each finding register row in
`docs/SECURITY-AUDIT.md` cites its proof by name.

### 9.1 Machine-checked (F\* / EasyCrypt / Kani)

| Security property | Artifact | Tool | Models (real code) |
| --- | --- | --- | --- |
| Per-message confidentiality (KEM-DEM, QROM-preserving) | `ConfidentialityQROM.ec` | EasyCrypt | ML-KEM-1024 `hybrid.rs` + AES-256-GCM under ratchet keys |
| Pairwise forward secrecy + post-compromise security | `RatchetFS.fst` | F\* | `ratchet.rs` next-chain / root inversion |
| Handshake mutual auth + agreement + session-key secrecy | `Handshake.fst` | F\* | `handshake.rs` SIGMA transcript |
| Identity-chain soundness / impersonation & revocation resistance | `IdentityChain.fst` | F\* | `account.rs::verify`/`belongs_to_account` |
| Group sender auth (symbolic) + PoP + auth-PCS + fail-closed | `GroupAuth.fst` (9 thms) | F\* | `treekem.rs::decrypt_verified` |
| Group mutual auth (tight computational reduction to EUF-CMA) | `GroupAuthQROM.ec` | EasyCrypt | `decrypt_verified` = `accepts` |
| Control-plane authorization route-completeness | `GroupAuthQROM.ec` + `EngineAuth.fst` (9 thms) | EasyCrypt + F\* | 5 branches of `decrypt_verified`; commit/roster host-gating |
| Group PCS (heal on rekey) + FS (removal/epoch) + path-secrecy | `TreeKemKS.fst` | F\* | `treekem.rs` derive_parent/derive_commit |
| Leaf-key unlinkability (key-hiding + cross-chat) | `LeafSigDeriveUnlink.ec` | EasyCrypt | `derive_leaf_sig_seed` (KMAC256), `LeafSigMode::Derived` |
| Gossip dedup soundness + eventual delivery (liveness under connectivity) | `GossipLiveness.fst` (6 thms) | F\* | `engine.rs` SeenSet / route flood |
| Decoder totality / panic-freedom (flat, in-CI) | wire / treekem / linkage / vouch / engine-D1 / mesh Kani harnesses | Kani | respective `*::decode`/parse fns |
| Decoder totality (nested-heap class) | `DecodeTotality.fst` + Aeneas→F\* route (`formal/decoder-totality/`) | F\* | `LinkageProof`/`NamePresence`/`Marking`/`IdentityChain`/`SignedCert::decode` |
| Vouch authorization soundness (vouched ⇒ score ≥ 0; decay bounded) | `vouch.rs` Kani harnesses | Kani | `is_vouched`, `age_decay` |

All F\* modules verify on-host via `make -C formal fstar`; the formal workflow runs
Kani + F\* + EasyCrypt in CI (`.github/workflows/formal.yml`). Reductions are
straight-line / rewinding-free → **QROM-preserving**.

### 9.2 Known-answer-tested (official vectors)

AES-256-GCM, SHA3-384/SHA-384, ML-DSA-87 (FIPS-204 ref), **ML-KEM-1024 (NIST FIPS-203
ACVP)**, MLS tree-math/key-schedule/secret-tree (official MLS WG vectors). See
`docs/COMPLIANCE.md:97,144-155` and `docs/CONFORMANCE.md`.

### 9.3 Fuzzed (attacker-reachable decoders, R-6)

16 cargo-fuzz targets cover every decoder parsing attacker bytes before auth: wire
`Reader`, `ChatDescriptor::from_uri`, identity chain / signed-cert / signed-claim /
revocation / presentation, ratchet header (found **F-14**), beacon body, suite scheme,
linkage / presence / marking, vouch, seal envelope (~16 M runs, F-15), treekem
KeyPackage/Commit/Welcome (~7.5 M runs, F-19), mesh parsers (F-20/F-22). Full list:
`fuzz/README.md`.

### 9.4 Honest assurance gaps

- **[ASSUMED]** pairwise ratchet FS/PCS at the *symmetric* level is proven in
  `RatchetFS.fst`; a dedicated end-to-end confidentiality proof binds via
  `ConfidentialityQROM.ec`, but there is no single monolithic "whole-session"
  machine proof — the properties compose from the per-area artifacts above.
- Nested-heap decoder totality against the **literal** Rust (not the heap-free model) is
  landed via the Aeneas→F\* route for the representative grammar; extraction of every
  literal decoder is tracked, not 100% complete (`formal/decoder-totality/README.md`).
- Constant-time behaviour is **not** formally established across all primitives
  (`docs/COMPLIANCE.md:95`).

---

## 10. Feature inventory (1.0 base + additions)

**Base (required):** pairwise PQ Double Ratchet, PQ-Noise session, custom PQ TreeKEM
group, MLS standards harness, CryptoSuite registry + CNSA floor, chat descriptor
(`talkrypt://` invite), mutual-auth handshake, P2P/Hub/Hybrid topologies, non-member
relay, persistent server + keep-alive, Tor/Nym/mesh transports, CLI/TUI.

**Added over the project:** account→device→segment identity chains, safety numbers,
unbundled contacts/access, multi-device linking, username registries + cross-compare,
revocation, vouching (sub-spec C), linkage/predicate/opsec proofs (sub-spec B),
self-declared names / CQ beacons / callsign (sub-spec A), scheme beacons, classification
markings (advisory, build-gated origination), serverless store-and-forward (sub-spec D),
hardware-backed at-rest sealing + custody tiers, gossip mesh + route descriptors +
reconnect, group control-plane authentication (F-17), length-bucket padding (F-16), CSfC
architectural preflight, RAM-capture hardening + POST, no-telemetry posture.

Per-feature "what / where" detail: `docs/DESIGN.md`, `docs/identity-accounts.md`,
`docs/SECURITY-AUDIT.md`, and the `docs/wiki/` pages.

---

## 11. Honest-scope statement

Every property in §2–§9 is **self-asserted**. Machine-checked properties are checked
against the stated model and the **[ASSUMED]** primitive security; they are not a
substitute for an independent audit, a FIPS validation, or an accreditation. The group
layer is a **custom PQ construction, not RFC 9420 MLS-on-the-wire** (`docs/CONFORMANCE.md`).
There is **no audit-logging subsystem** (relevant to, e.g., HIPAA §164.312(b) — see
`docs/compliance/STANDARDS-MAP.md`). Using the CNSA 2.0 algorithms is **not** the same as
being certified. Treat every claim here as unverified until an external assessment
establishes otherwise.
