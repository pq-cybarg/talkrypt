# Formal verification (`formal/`)

Machine-checked proofs of talkrypt's **group-message sender authentication**
(SECURITY-AUDIT G1/G2/T-1/T-2), verified under a **quantum threat model**.

## `GroupAuth.fst` — F* model + theorems

Signatures are modeled as an idealized **EUF-CMA** primitive (the standard
computational abstraction of **ML-DSA-87 / FIPS 204**); its unforgeability against
a cryptographically-relevant quantum computer is a NIST-standard assumption, so the
whole result is quantum-sound to exactly the degree ML-DSA is. The model mirrors the
Rust `decrypt_verified` / `verify_pop` / `apply_commit` logic line-for-line.

**Theorems (all discharged, no `admit`/`assume` in any proof):**
1. `thm_fail_closed` — a message for a leaf with no bound key is always rejected.
2. `thm_authenticity` — accept ⟹ the holder of the leaf's bound key signed exactly this (epoch, leaf, n, ct).
3. `thm_no_cross_leaf_forgery` (G1) — a member cannot get a message accepted as another leaf without that leaf's secret.
4. `thm_pop_binds_key` (T-1) — a verifying PoP proves possession of exactly the presented key.
5. `thm_pop_not_transferable` (T-1) — a PoP for `k` cannot admit a different key `k'`.
6. `thm_pop_msg_non_confusion` (T-1) — domain separation: a PoP signature is never a valid message signature (POP_CONTEXT ≠ SIG_CONTEXT).
7. `thm_rotation_rebinds` (T-2) — rotating a leaf rebinds it to the fresh key.
8. `thm_auth_pcs` (T-2) — after rotation, a signature under the compromised old key is rejected (post-compromise security for authentication).
9. `thm_decision_deterministic` — the acceptance decision is a pure function (no relay can make one frame accepted for A, rejected for B).

**Assumptions** (only primitive-level, all justified):
- `EUFCMA` — ML-DSA-87 is existentially unforgeable under chosen-message attack (FIPS 204).
- `TranscriptInjective`, `PopInjective`, `PopDomainSep` — guaranteed by the domain-separated, length-prefixed wire encoding. The *implementation* side of this (that the decoders are total and unambiguous on all inputs) is machine-proven separately by the **Kani** harnesses in `crates/crypto/src/treekem.rs` (`proofs::v2_message_parse_is_total`, `proofs::sender_leaf_never_panics`) and `crates/wire/src/lib.rs`.
- `PkInjective` — distinct signing keys have distinct public keys.

Run: `make verify` (or `fstar.exe GroupAuth.fst`).

## Verification stack (defense in depth)

| Layer | Tool | What it proves |
|---|---|---|
| Protocol auth logic | **F\*** (`GroupAuth.fst`) | The 9 security theorems above, by reduction to EUF-CMA. |
| Wire decoders | **Kani** (bounded model checker) | The v2 message + membership parsers are total & memory-safe on ALL inputs. |
| End-to-end behavior | **proptest** | Authenticity, integrity, PoP-rejection, decoder totality over randomized real-crypto runs. |
| Primitives | **FIPS KAT / ACVP** (`selftest.rs`) | ML-KEM-1024 / ML-DSA-87 match NIST test vectors. |
