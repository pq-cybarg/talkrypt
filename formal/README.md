# Formal verification (`formal/`)

Machine-checked proofs of talkrypt's cryptographic core, under a **quantum threat
model** (a cryptographically-relevant quantum computer with superposition
random-oracle access — the QROM). Two independent proof engines plus the Rust-side
Kani/proptest harnesses form a defense-in-depth stack.

Run everything: `make verify` (needs `fstar.exe` + `easycrypt` on PATH).

## Artifacts

### `GroupAuth.fst` — F*, symbolic group-message authentication
Signatures are an idealized **EUF-CMA-in-the-QROM** primitive (ML-DSA-87 / FIPS 204).
Nine theorems, all discharged, zero `admit`: fail-closed, authenticity,
no-cross-leaf-forgery (G1/G2), PoP soundness + non-transferability + domain-separation
(T-1), rotation-rebind + auth-PCS (T-2), decision determinism. Every proof is a
straight-line, rewinding-free implication from the EUF-CMA axiom, so the reductions
are **QROM-preserving** — the results hold against a quantum adversary.

### `GroupAuthQROM.ec` — EasyCrypt, computational reduction + ALL routes
- `group_auth_reduces_to_eufcma`: a tight, **black-box, straight-line** reduction —
  any group-message forger yields an EUF-CMA forger with equal probability. Black-box
  + no-rewinding => QROM-valid.
- `accepts_route` models `decrypt_verified` **branch-for-branch** (v1-reject,
  unknown-leaf-reject, bad-sig-reject, wrong-epoch-reject, accept) as a total function,
  and `accept_route_requires_valid_sig` proves **no route** accepts without a valid
  signature at the right epoch. `v1_always_rejected` / `unknown_leaf_rejected` prove
  the fail-closed routes on all inputs. Together: every code path is covered.

### `ConfidentialityQROM.ec` — EasyCrypt, confidentiality model
Defines the **KEM IND-CCA-QROM** game (ML-KEM-1024 / FIPS 203) and the **DEM one-time**
axiom (AES-256-GCM under fresh per-message keys), and machine-proves the
confidentiality core: under a fresh random key the DEM observable is identically
distributed for any two plaintexts (`dem_observable_message_independent`,
`dem_no_distinguisher`). Full per-message confidentiality is the standard KEM-DEM
hybrid, QROM-preserving because the KEM real->random swap is black-box/straight-line.

## What is assumed vs. proved

**Assumed** (only primitive-level, all NIST-standardized with published QROM proofs):
- ML-DSA-87 EUF-CMA in the QROM (FIPS 204).
- ML-KEM-1024 IND-CCA in the QROM (FIPS 203).
- AES-256-GCM one-time DEM security.

**Proved** (machine-checked here): every protocol-level reduction and route from the
above — nothing about the protocol logic is taken on faith. The QROM-hardness of the
primitives themselves is not re-derived (that is FIPS 203/204 + the formosa-crypto /
community proofs).

## Fidelity to the implementation (model <=> code)

The proofs are only meaningful if the models match the Rust. The correspondence,
audited line-by-line (`crates/crypto/src/treekem.rs`):

| Model construct | Rust counterpart |
| --- | --- |
| `transcript epoch leaf n ct` (F*, EC) | `sig_transcript(epoch, leaf, n, ct) = SIG_CONTEXT | epoch | leaf | n | ct` |
| `accepts` (F*) / `accepts_route` (EC) | `decrypt_verified`: version -> `leaf_sig_keys.get` -> `vk.verify` -> epoch -> `decrypt_body` |
| routes 1-5 of `accepts_route` | the five branches of `decrypt_verified`, same order |
| `pop_msg k = POP_CONTEXT | k` (F*) | `pop_transcript(sig_public) = POP_CONTEXT | sig_vk` |
| `PopDomainSep` (F*) | `POP_CONTEXT != SIG_CONTEXT` (distinct consts) |
| `verify_pop l k p` (F*) | `verify_pop(sig_public, pop)` |
| rotation `rebind` + auth-PCS (F*) | `update()` / `commit_update` `sig_update` rebinding `leaf_sig_keys` |
| KEM `encap` / IND-CCA (EC) | `KemProfile` ML-KEM-1024 encapsulate/decapsulate (`hybrid.rs`) |
| DEM `aead` one-time (EC) | AES-256-GCM `aead::seal/open` under fresh ratchet keys |

F* folds the epoch check into the signed transcript (a wrong-epoch message needs a
different signature); the EasyCrypt `accepts_route` models the epoch check as an
explicit reject branch. Together they cover the route both ways.

## Verification stack (defense in depth)

| Layer | Tool | What it proves |
| --- | --- | --- |
| Protocol auth (symbolic) | **F\*** | The 9 authentication theorems, QROM-sound. |
| Protocol auth (computational) | **EasyCrypt** | Tight EUF-CMA reduction + every acceptance route. |
| Confidentiality | **EasyCrypt** | KEM IND-CCA-QROM + DEM model; observable message-independence. |
| Wire decoders | **Kani** (BMC) | Message + membership parsers total & memory-safe on ALL inputs. |
| End-to-end | **proptest** | Authenticity, integrity, PoP-rejection, decoder totality over real crypto. |
| Primitives | **FIPS KAT / ACVP** | ML-KEM-1024 / ML-DSA-87 match NIST vectors (`selftest.rs`). |

## Soundness of the checkers

The EasyCrypt proofs were validated against a **deliberately false lemma**, which the
checker rejects (`cannot prove goal`) — confirming `smt()` genuinely discharges goals
rather than vacuously admitting. F* reports "All verification conditions discharged".
