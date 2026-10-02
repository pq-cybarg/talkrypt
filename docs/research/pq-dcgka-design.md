# Post-quantum decentralized CGKA (PQ-DCGKA) — design & research record

> **Status: R&D track, DOCUMENT-ONLY. Do NOT build yet.** This captures the
> grounded research for a *novel* post-quantum decentralized continuous group key
> agreement so it is preserved and reviewable. Shipping it is gated on **external
> cryptographic review + a machine-checked formal model** (Tamarin/ProVerif) —
> see §9. It is the **third** priority behind (1) the shipped per-identity
> signature auth layer and (2) the OpenMLS PQ-ciphersuite path. Full prior
> context: memory `group-relay-linking-security-redesign`.

## 1. Why this exists (and why it's novel)

talkrypt needs group key agreement that is simultaneously:

1. **Post-quantum** — ML-KEM-1024 + ML-DSA-87 (CNSA 2.0), no load-bearing
   classical primitive;
2. **Decentralized** — no single serializing committer / delivery server; works
   over a gossip mesh (the zRonin relayer-coordination use case has no trusted
   server);
3. **PCS-bearing** — post-compromise security: a compromised member heals after
   bounded honest activity.

**No published construction has all three.** The PQ-CGKA literature (MLS/TreeKEM,
Chained CmPKE) is all **central-server / single-committer**. The decentralized-CGKA
literature (DCGKA — Weidner & Kleppmann, CCS'21; DeCAF — Alwen et al., SCN'24) is
all **classical Diffie-Hellman**. The intersection is unsolved, so building it is
**novel cryptography** and must not ship without external review.

This document is the design for that intersection. The shipping alternatives
(which do NOT require novel crypto) are: the **per-identity ML-DSA signature auth
layer** (shipped — closes G1/G2, FS, no PCS in mesh mode) and the **standardized
MLS-PQ single-committer path** via OpenMLS (`MLS_256_MLKEM1024_AES256GCM_SHA*_MLDSA87`,
evaluated in `docs/openmls-pq-evaluation.md`). PQ-DCGKA is the research path toward
*decentralized* PCS specifically.

## 2. The load-bearing finding: the PQ surface is tiny and localized

The single most important design fact, extracted from the DCGKA extended paper
(eprint 2020/1281): **DCGKA's entire proven control plane is symmetric/generic and
survives a PQ port unchanged.** That control plane is:

- group operations `create / add / remove / update / process` + their
  `process-*` handlers + acknowledgements;
- **both KDF ratchets** — the per-sender forward-secure application ratchet
  (paper Fig. 1) and the PRF-PRNG update ratchet (Fig. 3);
- the **Decentralized Group Membership** CRDT (strong-remove semantics);
- the concurrency "forwarding" trick, ack/seq causal ordering, and the AEAD.

None of those touch asymmetric crypto. **The ONLY asymmetric dependency is the
two-party secure-messaging channel (2SM) + its KEM prekeys + the signatures.**

Therefore **PQ-DCGKA = swap the primitives in one module**:

- 2SM key exchange: X25519 → **ML-KEM-1024** (HPKE-style encapsulation);
- signatures: Ed25519/XEdDSA → **ML-DSA-87**;
- prekeys: X25519 prekey bundles → **ML-KEM-1024 prekey bundles**.

This is *not* inventing a group protocol — it is replacing the DH heart of a
proven one. That dramatically narrows what external review must cover (the 2SM and
its composition with the unchanged control plane), which is the whole point of
documenting it this precisely.

## 3. The 2SM must heal every message (the one real subtlety)

DCGKA pushes update seeds **one-directionally** (a member distributes a fresh seed
to each other member over the 2SM). For PCS this means: **a compromised member's
outbound 2SM state must self-heal immediately on its next send** — you cannot wait
for a round trip.

- Each `2SM-Send` ships a **fresh KEM encapsulation key** and encapsulates to the
  peer's latest advertised key → maps cleanly onto ML-KEM-1024 (fresh keypair per
  message; encapsulate-to-latest).
- **DO NOT reuse talkrypt's pairwise Double Ratchet as the 2SM.** The Double
  Ratchet only heals on a *round trip* (the DH step needs the peer to reply), so a
  push-only seed to a silent peer would heal "maybe never" — collapsing PCS. The
  2SM needs per-message rotation, which is actually **simpler** than a Double
  Ratchet: a stateless-ish ML-KEM HPKE channel that rotates its own keypair every
  send and remembers the peer's latest public key.

Design: a **PQ 2SM = HPKE(ML-KEM-1024)** with per-message sender-key rotation.
Sender generates `(ek_i, dk_i)`, encapsulates to the peer's latest `ek_peer`,
derives the message key via the KDF, ships `ek_i` + ciphertext; receiver stores
`ek_i` as the peer's new latest. Each direction's compromise self-heals on the
next send in that direction.

## 4. Reference implementation to adapt (and the license gate)

**`p2panda-encryption`** (the `message_scheme`) implements exactly this DCGKA over
HPKE(X25519) in Rust. It is the natural base: its control plane is the vetted DCGKA
state machine; only its crypto layer is classical.

**Exact PQ-port surface (swap these; leave the control plane untouched):**

| Port (classical → PQ) | Leave UNTOUCHED (generic control plane) |
|---|---|
| `two_party/two_party.rs` (2SM) | `dcgka.rs` |
| `two_party/x3dh.rs` → ML-KEM prekey agreement | `ratchet.rs` |
| `crypto/hpke.rs` → HPKE(ML-KEM-1024) | `group.rs` |
| `crypto/x25519.rs` → ML-KEM-1024 | (DGM CRDT, acks, seq) |
| `crypto/xeddsa.rs` → ML-DSA-87 | |
| `key_bundle/prekey.rs` → ML-KEM prekeys | |

**LICENSE GATE — CLEARED (verified 2026-10, crates.io / lib.rs).**
`p2panda-encryption` is dual-licensed **MIT OR Apache-2.0** (consistent across the
whole p2panda project), so it is **license-compatible** with talkrypt's Apache-2.0
— forking/adapting is permitted. (The earlier worry that it might be AGPL is
resolved; it is not.) Remaining caveat: p2panda's crypto is **audit-pending**, so
adopting it imports that status — the §9 external-review gate still applies to the
PQ 2SM surface regardless.

## 5. Proven lower bounds (why some costs are laws, not bugs)

Two results bound what *any* decentralized-concurrent PCS scheme can achieve — do
not try to engineer past them:

- **Concurrency cost** (Bienstock–Dodis–Rösler, TCC'20, eprint 2020/1171;
  Auerbach et al., TCC'23, eprint 2023/1123): fully-concurrent one-shot PCS
  *without* a serializing committer costs **Ω(t)** communication (or ~n²), OR
  requires multi-round healing. A gossip mesh with no total order pays this.
- **Forward secrecy at forks degrades** unless the key schedule is *puncturable*;
  naive ratchets retain enough state at a fork to break FS → needs PPRF puncturing
  (FREEK / DMLS, eprint 2023/394).

Implication: PQ-DCGKA is suitable for **relayer-coordination-scale** groups
(hundreds of members, bounded concurrency), **not** internet-scale channels. That
is exactly talkrypt's target, so the bound is acceptable — but it must be stated,
not hidden.

## 6. Fork-resilience and its residual PCS gap

Fork-resilience = **PPRF (puncturable PRF) puncturing** of the key schedule
(FREEK / DMLS, GGM-tree construction). On each epoch, puncture the init/epoch
secret so a later state cannot derive earlier keys.

**Residual (inherent, must be documented):** PPRF puncturing covers the
init/epoch secret but **not** the ratchet-tree / 2SM keys, which are still retained
across a fork → there is a **bounded PCS gap in the fork window**. This is the
proven lower bound from §5 made concrete; mitigation is **fast fork resolution**
(short causal-ordering windows), not elimination.

## 7. Residuals and caveats (all inherent, all to be surfaced)

- **dom-safe concurrency caveat:** after concurrent removes, a client must send a
  PCS update before its next message to stay dominance-safe.
- **O(n) per update:** each update is linear in membership → caps at ~hundreds
  (fine for relayer coordination).
- **Deniability lost:** ML-DSA signatures are non-repudiable; PQ + deniable +
  group is itself unsolved. If deniability is required, PQ-DCGKA is the wrong tool.
- **Fork-window PCS gap:** §6.
- **PKI assumption:** a mapping of member IDs → identity (ML-DSA) keys +
  ephemeral ML-KEM prekeys. talkrypt's account/cert model + presence already
  provides this.

## 8. What talkrypt already has that this builds on

- **Causal-broadcast minimum** = per-sender FIFO + ack-after-target. talkrypt's
  gossip + `seq` monotonicity already meets this (no new transport needed).
- **PKI** = the account→identity-key cert chains + ML-KEM prekeys; presence already
  distributes per-identity keys.
- **PQ primitives** = the same RustCrypto `ml-kem` / `ml-dsa` the rest of the stack
  uses; the 2SM HPKE(ML-KEM) and ML-DSA signing are already available via
  `talkrypt-crypto`.
- **Sizes** (budget the overhead): ML-KEM-1024 = 1568 B pk + 1568 B ct; ML-DSA-87
  = 4627 B sig, 2592 B vk. PQ commit bandwidth is large → consider mKEM/mPKE
  compression (mKyber ~48 B/recipient) if membership grows.

## 9. Release gate (non-negotiable)

PQ-DCGKA MUST NOT ship until **both**:

1. **External cryptographic review** of the 2SM and its composition with the
   DCGKA control plane (the novel surface), by a reviewer not on this project; and
2. A **machine-checked formal model** — Tamarin or ProVerif — of the PQ 2SM +
   update/heal flow, establishing FS + PCS (within the proven bounds) and
   authentication.

Until then, groups needing guaranteed PCS use the standardized **MLS-PQ**
single-committer path (OpenMLS); mesh groups use the shipped **signature + FS**
layer (no PCS), creator's choice per chat.

## 10. Build decision (deferred)

Two ways to build it *when* the gate is cleared:

- **(A) Adapt `p2panda-encryption`** — reuse the vetted DCGKA control plane, swap
  only the crypto (§4). Fastest to a correct control plane. **License is clear
  (MIT/Apache-2.0, §4)**, so this is viable; it imports p2panda's audit-pending
  status, covered by the §9 gate.
- **(B) Clean-room reimplement DCGKA** natively in talkrypt from the paper — full
  control, no third-party audit status to inherit, more work, more surface for the
  formal model to cover.

With the license cleared, **(A) is the recommended starting point** (vetted control
plane + narrow PQ crypto swap = smallest novel surface for review); fall back to
(B) only if p2panda's abstractions fight the primitive swap. Decided at
gate-clearing time.

## 11. Citations

- DCGKA — Weidner, Kleppmann et al., *"Key Agreement for Decentralized Secure
  Group Messaging…"*, CCS'21 / eprint **2020/1281**.
- DeCAF — Alwen et al., SCN'24 / eprint **2022/559**.
- FREEK / DMLS puncturing — eprint **2023/394**.
- Concurrency lower bounds — Bienstock–Dodis–Rösler TCC'20 eprint **2020/1171**;
  Auerbach et al. TCC'23 eprint **2023/1123**.
- A-CGKA (admin) — eprint **2022/1411**.
- Chained CmPKE (PQ CGKA, central) — eprint **2021/1407**.
- `draft-ietf-mls-pq-ciphersuites` (Mahy/Barnes) — the standardized PQ MLS suite;
  RFC 9420 §14.
- Reference impl: `p2panda-encryption` (`message_scheme`) — **MIT OR Apache-2.0**
  (verified 2026-10, crates.io / lib.rs), compatible with talkrypt; crypto
  audit-pending.
