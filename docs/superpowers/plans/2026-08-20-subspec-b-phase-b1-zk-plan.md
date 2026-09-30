# Sub-spec B — Phase B1 (PQ zero-knowledge predicate proofs) Implementation & Verification Plan

> **Status: REVIEW-GATED, NOT FOR MERGE-TO-DEFAULT.** This is the staged roadmap for the novel-crypto
> layer of Sub-spec B. Every phase ships **behind the `zk` cargo feature (off by default)** and does not
> become a ship default until the **author's formal verification** of that phase passes. Grounded in the
> design doc `docs/superpowers/specs/2026-07-31-subspec-b-linkage-opsec-predicate-proofs-design.md` §4 and
> the survey `docs/research/pq-zk-survey.md`. Phase B0 (the audited ML-DSA layer, PR #11) is the seam this
> plugs into: `crates/core/src/linkage.rs` already reserves `Predicate` tags `0x10+` and the
> `ProofBackend` trait for exactly this backend.

**Goal:** Implement the three ZK predicate archetypes — `MemberOfKnownSet` ("you know me"),
`DerivedFromKnownSet` ("derived from someone you know"), and `Attribute` (SCI-style) — as a second
`ProofBackend`, plus the ML-DSA quorum **attestation** layer and **prove-then-KEM** predicate-gated
delivery, all post-quantum (hash/CRHF) and **formally verified** before default-enable.

**Architecture:** A new `talkrypt-zk` crate (feature-gated) implements `ProofBackend` over a **Winterfell
FRI-STARK** on **KoalaBear** with a **WHIR/STIR** proximity layer, **Rescue-Prime** as the in-circuit
arithmetization hash, and **SHA3/SHAKE** commitments; all three predicates are one
**Merkle / cert-chain membership circuit** family with **verifier-issued witnesses** (VC/anon-cred-via-
Merkle). Attestation reuses B0's ML-DSA machinery; predicate-gated delivery layers a **predicate epoch
key** over the existing TreeKEM keying. The core wires `ZkPredicateBackend` behind `#[cfg(feature = "zk")]`.

**Tech Stack:** Rust; `winterfell` (FRI STARK, AIR); a WHIR/STIR proximity backend; **KoalaBear**
field; **Rescue-Prime** in-circuit hash; **SHA3/SHAKE** (`tiny_keccak`, in-tree) commitments; ML-DSA-87 + ML-KEM-1024 (RustCrypto, in-tree). Formal
verification: the repo's existing EasyCrypt / F* / Kani CI, extended with the STARK-soundness + ZK-masking
theorems.

## Global Constraints (verbatim, non-negotiable)
- **PQ = the polynomial-commitment scheme.** Only hash/FRI (→ WHIR/STIR) commitments. **No** pairing/EC
  (Groth16/PLONK-KZG/Halo2-IPA/Nova/BBS+/BLS) — hard exclusion. **Never** consume a Groth16-over-BN254 wrap.
- **Winterfell is the AIR/STARK baseline**, chosen on provable properties (exact knowledge soundness, one
  falsifiable CRHF assumption, arbitrary-NP AIR, single soundness object → most tractable to formally
  verify). Lattice ZK only for statements intrinsically about ML-DSA/ML-KEM key material (none of B1's are).
- **STARKs are NOT ZK by default** — witness + quotient masking must be ADDED and its zero-knowledge
  property machine-checked (Haböck–Kindi, eprint 2024/1037). No off-the-shelf crate is assumed ZK.
- **Layered hashing (deliberate):** the **in-circuit arithmetization hash is Rescue-Prime** — its
  *bidirectional full-round* structure resists the algebraic (Gröbner/resultant) attacks that break
  Poseidon/Poseidon2, so it is the SECURE AF-hash here (NOT interchangeable with Poseidon). The
  **commitment/Merkle layer uses SHA3/SHAKE** (Keccak sponge → length-extension resistant; SHA-384
  likewise, being truncated). **KoalaBear** (31-bit) is the field — chosen for **mobile device limits** (cheap arithmetic + low
  memory on phone CPUs; talkrypt is mobile-first); the KoalaBear-*Poseidon* cryptanalysis is moot since
  we use Rescue-Prime.
- **Proximity soundness parameters are derived + machine-checked, never a copied default** (FRI's above-
  Johnson bound regressed, 2026/858; prefer WHIR/STIR's current analysis).
- **Feature-gated + off by default; verification-gated to ship.** No B1 code path is reachable in a default
  or `tor` build. `commit AND author as pq-cybarg <resistant@tuta.com>`. Backticks-in-`-m` break zsh → `-F`.

---

## Phase 0 — Crate scaffold + backend seam (buildable now; no crypto yet)

**Files:** create `crates/zk/` (`talkrypt-zk`), add optional `zk` feature to `talkrypt-core`
(`zk = ["dep:talkrypt-zk"]`), wire a `ZkPredicateBackend` behind `#[cfg(feature = "zk")]` in
`crates/core/src/linkage.rs`.

- [ ] Scaffold `talkrypt-zk` with the `winterfell` dep and a `ProofBackend`-shaped API
  (`fn prove(statement, witness) -> Proof`, `fn verify(statement, proof) -> Verdict`), returning
  `Verdict::Fail`/`unimplemented!()` stubs.
- [ ] Extend `linkage::Predicate` (behind `#[cfg(feature = "zk")]`) with the reserved tags:
  `MemberOfKnownSet { set_commitment: [u8;32], epoch: u64 }` (0x10),
  `DerivedFromKnownSet { set_commitment: [u8;32], epoch: u64 }` (0x11),
  `Attribute { policy: [u8;32] }` (0x12), `And(Vec<Predicate>)` / `Or(Vec<Predicate>)`. Confirm the B0
  decoder still returns `None` for these when the feature is off (append-only invariant — already tested).
- [ ] `ZkPredicateBackend` implements `ProofBackend`; default build unaffected (feature off).
- **Verification obligation:** none yet (no crypto). CI must show the default + `tor` builds do NOT pull
  `talkrypt-zk` (`cargo tree` assertion in the audit job).

## Phase 1 — WHIR/STIR proximity + SHA3 commitment layer (VERIFICATION-GATED)

**Files:** `crates/zk/src/pcs.rs` (proximity), `crates/zk/src/commit.rs` (SHA3 Merkle).

- [ ] Integrate a WHIR (fallback STIR) proximity backend into the Winterfell pipeline on the **KoalaBear**
  field. **In-circuit hash = Rescue-Prime** (bidirectional full-round; the secure AF-hash). **Merkle /
  commitment hash = SHA3/SHAKE** (length-extension resistant). Configure for **true zero-knowledge**
  (witness + quotient masking, Phase-1 obligation 2).
- [ ] Derive the concrete query count / soundness parameters for the chosen proximity test; encode them as
  constants with a comment citing the analysis, NOT a library default.
- **Verification obligations (must pass before Phase 2 builds on it):**
  1. **Soundness** — machine-checked proof (Lean 4 STARK-soundness blueprint / EasyCrypt) of the FRI/WHIR
     round bound at the deployed parameters.
  2. **ZK / masking** — the added witness+quotient masking yields a proof statistically independent of the
     witness (a leak test + the Haböck–Kindi masking argument) → **true ZK**.
  3. **Rescue-Prime algebraic security** — track/justify the round count against min-degree /
     Gröbner-basis analyses (the full-round bidirectional argument), and SHA3/SHAKE commitment binding.
  4. **Kani** — decoder/verifier totality on the proof bytes (extends the existing Kani CI job).

## Phase 2 — Merkle / cert-chain membership circuit + verifier-issued witnesses (VERIFICATION-GATED)

**Files:** `crates/zk/src/membership.rs` (the AIR), `crates/core/src/linkage.rs` (witness issuance API).

- [ ] One AIR that proves a Merkle authentication path from a committed leaf to `set_commitment`, hiding
  the leaf + index (ZK from Phase 1). This single circuit underlies all three predicates.
- [ ] **Verifier-issued membership witness** (the ZK-both-ways mechanism): at "knowing" time the verifier
  privately issues a party its auth path (sibling hashes only — no set contents); the prover proves against
  the **published root**. `Core::issue_membership_witness(subject)` + `Core::prove_member(...)`. Epoch-bound
  root; witness re-issue on churn (add/remove → root rotates; `epoch` binds into `context`).
- [ ] `MemberOfKnownSet` and `DerivedFromKnownSet` (the latter = cert-chain membership up to *some*
  whitelisted ancestor; prior art **zk-X509 "CA-anonymous chain membership"**) both instantiate this AIR.
- **Verification obligations:** the circuit's relation matches the intended statement **exactly** (no
  relaxed relation); replay across chats fails (context+epoch binding); epoch monotonicity prevents proving
  against a stale root. Negative tests: wrong witness / wrong epoch / non-member all `Verdict::Fail`.

## Phase 3 — Attribute predicate + composition (VERIFICATION-GATED)

**Files:** `crates/zk/src/attribute.rs`.

- [ ] `Attribute { policy }` — prove possession of an issuer-signed credential whose attributes satisfy a
  policy circuit, revealing only pass/fail (the credential = a §4c attestation; circuit checks issuer-sig
  validity + the predicate). `And`/`Or` compose circuits.
- [ ] SCI-style use: prove clearance without the verifier signalling the requirement (pass/fail-only).
- **Verification obligations:** the attribute predicate leaks nothing beyond satisfaction; composition
  soundness (And/Or) holds.

## Phase 4 — ML-DSA quorum attestation (audited; shared with Sub-spec C)

**Files:** `crates/core/src/attest.rs` (or extend `linkage.rs`).

- [ ] A verifier who ran a Phase-2/3 proof issues an **ML-DSA-87 attestation**
  `Sign_verifier(context ‖ predicate_id ‖ subject_leaf ‖ epoch)`. Peers who can't re-run the STARK verify
  the cheap ML-DSA attestation instead.
- [ ] **Quorum = k distinct ML-DSA signatures** (no compact PQ threshold at scale exists). `Core::attest`,
  `Core::quorum_satisfied(subject, predicate, k)`. This is Sub-spec C's vouching mechanism generalized —
  **design the attestation type once here; C adds vouch-count→tint.**
- **Verification obligation (audited, not novel):** attestations are ML-DSA — standard; test quorum
  counting, attestation replay/epoch binding, revocation of an attestor.

## Phase 5 — Prove-then-KEM predicate-gated delivery (VERIFICATION-GATED for the gate; audited primitives)

**Files:** `crates/core/src/engine.rs` (predicate epoch key over TreeKEM), `crates/core/src/linkage.rs`.

- [ ] **NOT ABE** (research-only). A **predicate epoch key `K_{P,e}`** distributed TreeKEM-style: bootstrap
  by encrypting per-recipient (ML-KEM-1024) to members holding a valid quorum attestation for `P`; gated
  messages are one symmetric AEAD under `K_{P,e}`; admit = one-frame KEM add; revoke = predicate-scoped
  epoch bump (forward + post-compromise security). prove-then-KEM is the *entry gate* to `K_P`, not the
  message cipher.
- [ ] Non-satisfiers see a padding-indistinguishable unopenable frame (matches the existing posture); a
  `required-predicate` tag on a message routes it under `K_{P,e}`.
- **Verification obligations:** a satisfier derives `K_P`, a non-satisfier cannot; the gated frame is
  indistinguishable from padding to a non-satisfier; epoch rotation gives FS/PCS for the gate.

## Phase 6 — Surfaces (feature-gated, marked experimental)

- [ ] FFI/CLI/Android/desktop controls for the ZK claims + predicate-gated send, visible **only** in a `zk`
  build and clearly labelled experimental. Mirror the B0 surface wiring.

---

## Sequencing & gates
Phases build strictly in order; **each VERIFICATION-GATED phase must pass its formal-verification
obligations before the next phase depends on it.** Nothing here becomes a ship default until the whole
chain is verified. Phases 4 (attestation) and 6 (surfaces) rest on audited primitives and can proceed in
parallel once their inputs exist.

## Explicitly out / do-not-do
- No lattice ZK, PQ ring sigs, PQ accumulators, PQ ABE, or compact PQ threshold sigs (all research-only,
  no audited Rust — see the survey). No non-falsifiable knowledge assumptions. No BN254 wrap. No enabling
  `zk` by default at any point in this plan.

## Self-review
- **Spec coverage:** design §4a (Winterfell/WHIR/SHA3/masking) → Phase 1; §4a claim archetypes + §3-style
  witnesses → Phase 2; Attribute/compose → Phase 3; §4c attestation → Phase 4; §4d prove-then-KEM → Phase 5;
  surfaces → Phase 6. The three "sharp risks" (§4b) are the Phase-1 verification obligations.
- **Reuses the B0 seam** (`ProofBackend`, reserved `Predicate` tags 0x10+) verbatim — no rework of merged code.
- **No placeholders that hide crypto:** each VERIFICATION-GATED phase names its exact obligation; this is a
  research-build roadmap, so obligations (not TDD unit code) are the gate — deliberately, because the crypto
  must be proven, not just tested.
