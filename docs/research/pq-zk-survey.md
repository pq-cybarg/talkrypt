# Post-Quantum Zero-Knowledge Landscape for talkrypt (2024–2026 survey)

Grounds the Backend-1 crypto choices in `docs/superpowers/specs/2026-07-31-subspec-b-linkage-opsec-predicate-proofs-design.md`.
Compiled 2026-07-31. Sources cited inline; verify eprint numbers before treating figures as load-bearing.

## Governing distinction
Post-quantum soundness is decided by the **polynomial-commitment scheme**, not the "STARK/SNARK" label:
- **Hash / FRI** commitments (Merkle + Reed–Solomon proximity) → only collision-resistant hashes →
  **plausibly PQ** (Grover halves the margin). Winterfell, Plonky3, the STARK core of RISC Zero / SP1,
  Stone, stwo, Binius.
- **EC / pairing** commitments (KZG, IPA/Pedersen, Groth16/PLONK/BN254, Halo2/Pasta) → **Shor-broken**.
  All Nova/SuperNova/HyperNova folding, Zcash Orchard, BBS+, BLS.
- **TRAP:** RISC Zero and SP1 are PQ at the STARK core but **wrap in Groth16 over BN254 by default —
  quantum-broken**. PQ only if you consume the un-wrapped STARK receipt (vendors confirm).

## Rust PQ proof systems
| System | Crate | PCS | PQ? | Audit | Notes |
|---|---|---|---|---|---|
| **Plonky3** | `p3-*` | FRI | Yes | **Least Authority 2024** | Only PQ-pure + publicly audited. Not ZK by default. |
| SP1 | `sp1-*` | FRI / BN254 wrap | core yes | 4 firms | Use un-wrapped receipt; base not ZK |
| RISC Zero | `risc0-zkvm` | FRI / BN254 wrap | core yes | strongest | Use un-wrapped receipt; large receipts |
| Winterfell | `winterfell` | FRI | Yes | none public | Succinct, explicitly not ZK |
| stwo (Circle-STARK, M31) | `stwo` | FRI | Yes | none yet | Fastest field; unaudited |
| Binius64 | `binius*` | binary Merkle | Yes | none | orig repo archived 2025 |
| Nova/Halo2/`rabe`/BBS+ | — | EC/pairing | **NO** | — | **excluded (quantum-broken)** |

## Proximity test: FRI → STIR → WHIR (swappable, all hash-based/PQ)
The low-degree test under a STARK is interchangeable; the assumption class stays CRHF (PQ) regardless.
Prefer the newer tests — better queries/verify AND a defensive response to FRI's soundness regression:
- **STIR** (Arnon–Chiesa–Fenzi–Yogev, 2024) — query complexity ~O(λ + log²N) vs FRI O(λ·log N); smaller
  arguments, higher soundness margin/query.
- **WHIR** (2024/25) — constrained-Reed–Solomon proximity, **super-fast (µs) verification**, tighter current
  soundness analysis; unifies multilinear + univariate IOPs. Reference Rust impls exist (newer than FRI).
- **FRI caveat:** above-Johnson soundness lost its theorem late 2025 (eprint 2026/858 restores an
  unconditional bound at ~one extra query round) → lean on STIR/WHIR's current analysis, not a regressed FRI
  default. Whichever is used, derive + machine-check the concrete soundness parameters (author formally
  verifies). Winterfell's stock FRI is the reference/fallback.

## Three sharp risks (must be design/review items)
1. **STARKs are not ZK by default** — need witness+quotient masking, FRI-fold entropy care
   (Haböck–Kindi, eprint 2024/1037). Verify a ZK config; test witness independence.
2. **AF-hashes under cryptanalysis** — Poseidon2/Rescue (incl. over KoalaBear) — improving algebraic
   attacks (eprint 2025/954; Poseidon Initiative Phase 2 targets KoalaBear). Use Keccak/SHA3 or Blake3 for
   security-critical commitments.
3. **FRI above-Johnson soundness lost its theorem (late 2025)** — recalibrate query counts to the
   unconditional bound (eprint 2026/858, ~one extra round).

## Field choice
All target ~128-bit via extension fields (base prime is brute-forceable), so choice is speed-driven:
Goldilocks (2⁶⁴−2³²+1), BabyBear (2³¹−2²⁷+1, RISC0), KoalaBear (2³¹−2²⁴+1, but Poseidon-cryptanalysis
focus), Mersenne-31 (fastest, needs Circle STARKs/stwo). Masking + hash concerns dominate over the prime.

## Set-membership / ancestry (claims "you know me" / "derived from someone you know")
- **Pragmatic PQ path = Merkle/cert-chain membership inside a FRI/STARK circuit** (Plonky3 partially
  audited). A hash Merkle tree *is* the PQ accumulator. Only route with any audit + pure-Rust maturity.
- **Direct prior art: zk-X509** (arxiv 2603.25190) — CA-anonymous X.509 chain membership in a risc0-style
  zkVM; private key never enters circuit. Best fit for talkrypt's account→device→segment cert trees.
- **zk-creds** (eprint 2022/878) — alternative (issue standalone creds vs prove over existing certs).
- PQ **ring signatures** (Raptor/Calamari-Falafl/SMILE/LoTRS) and PQ **accumulators**: all research code,
  **none audited**, mostly C (LoTRS has a fresh unaudited Rust ref). Lattice one-out-of-many has a
  soundness gap vs DL. "Verifier hides the set from prover" = private set membership → research-only PQ.

## Attestation ("one heavy proof → cheap attest")
- **Verifiable-Credential shape** (W3C VCDM 2.0, Rec 2025-05): issuer verifies once → signs credential →
  cheap verify without contacting issuer. Sign with **ML-DSA-87** (FIPS 204 final; W3C PQ cryptosuite is
  draft "do not use"). ML-DSA verify ~20× faster than ECDSA — good for attest-many.
- **PCD/IVC**: PQ recursion via **Fractal** / STARK-recursion (Plonky3-recursion); Nova folding is **not
  PQ**. Frontier.
- **Quorum**: k-of-n is PQ only as **k separate ML-DSA sigs (linear)**. **No compact PQ threshold/aggregate
  at scale** — threshold ML-DSA is ≤~6 parties (research; Quorus/Trilithium/TALUS, eprint 2025/1166).
- **Anonymous credentials**: PQ least mature (BBS+ not PQ; lattice anon-creds ~60–700 KB, non-standard).

## Predicate-gated delivery
- **PQ ABE / predicate encryption = research-only, zero Rust, zero audits.** `rabe` is all BN254 pairings
  (not PQ; BN254 also sub-100-bit classically; YCT14 broken). Lattice ABE = orphaned C++/CUDA, ~16 attrs,
  MB keys — infeasible on mobile.
- **Recommended: prove-then-KEM** — encrypt to ephemeral **ML-KEM-1024**; gate key release on a passing PQ
  ZK attribute proof; pass/fail-only + wire padding hides the requirement. Real building blocks only.

## Bottom line
Build all three predicate proofs on a **hash-based STARK Merkle/cert-chain-membership circuit — Plonky3
(PQ-pure + audited) or un-wrapped SP1** — plus **ML-DSA-87 attestations** (cheap attest-many) and
**ML-KEM-1024** prove-then-KEM gating. **Not ready / exclude:** all lattice ZK (no audited Rust — cf.
Project Eleven "the belt is vacant"), PQ ring sigs / accumulators, PQ ABE, compact PQ threshold, PQ
anon-creds. Everything in Backend 1 is **review-gated**.
