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

### `IdentityChain.fst` — F*, account->device->segment chain verification
The logical-correctness counterpart to the decoder-totality work: proves the Rust
`IdentityChain::verify` / `belongs_to_account` **acceptance decision** is sound. Same
idealized EUF-CMA-in-the-QROM signature primitive. Nine theorems, all discharged, zero
`admit`: fail-closed-on-empty, leaf-binding, **chain soundness** (acceptance => every
link honestly signed by its issuer, by induction over the chain), account-roots-the-chain,
**impersonation resistance** (an account whose ML-DSA secret is not held signs nothing,
so NO chain verifies against it — forging friended-account membership is impossible),
validity-window enforcement, **revocation unforgeability** (only the certifying account
can revoke) + revoked-leaf-refused, decision determinism. Straight-line, rewinding-free
=> QROM-preserving.

### `RatchetFS.fst` — F*, pairwise Double Ratchet forward secrecy + PCS
Models the symmetric chain (`kdf_ck` = `next_ck`/`mk_of`) and root (`kdf_rk` =
`rk_root`/`rk_chain`) KDF steps as idealized **one-way PRFs**, via an inductive
DERIVABILITY relation `der ks k` whose only generators are the forward steps — the
absence of any inverse constructor *is* the one-wayness assumption (computational
analogue: HKDF/SHA-384 PRF-security). Four theorems, all discharged, zero `admit`:
**forward secrecy** (a message / chain key at an earlier generation is not derivable
from later keys — proven via a generation index no forward step decreases) and
**post-compromise security** (after a root step mixing a fresh KEM secret the
adversary cannot derive, the new root + first post-ratchet chain key are not
derivable — proven by inversion on the root step). Straight-line => QROM-preserving.

### `Handshake.fst` — F*, mutually-authenticated session handshake
Models the SIGMA-style handshake (`core::handshake::initiate`/`respond`, H-1): both
parties ML-DSA-sign the injective full transcript `tag | suite | id_i | n_i | id_r |
prekey | n_r`, domain-separated by tag. Same idealized EUF-CMA primitive;
session-key secrecy modeled as in `RatchetFS.fst` (one-way KDF from PSK + KEM secret).
Six theorems, all discharged, zero `admit`: **mutual authentication** (initiator
authenticates responder and vice versa), **agreement / no field substitution** (both
sides bound to the same identities/nonces/prekey/suite — downgrade-resistant, via
transcript injectivity), **domain separation** (a responder signature can never be
replayed as an initiator confirm), and **session-key secrecy** — the session root is
not derivable by an adversary lacking EITHER the invite-token PSK (a non-descriptor
holder / MITM) OR the ML-KEM shared secret (IND-CCA), so the two protections compose.

### `TreeKemKS.fst` — F*, TreeKEM group key-schedule PCS/FS
The group-layer secrecy counterpart to `GroupAuth.fst` (which proves group-message
*authentication*). Models the per-commit rekey (`derive_parent_secret` up the tree →
`derive_commit_secret` → epoch secret) as one-way derivations via the same inductive
`der` forward-closure as `RatchetFS.fst`. Four theorems, all discharged, zero `admit`:
**post-compromise security** (a member compromised before a commit heals — the new
epoch secret comes from a fresh root it cannot derive), **forward secrecy against
removal** (a removed member cannot derive any post-removal epoch secret), **epoch
forward secrecy** (an earlier epoch secret is not recoverable from a later one), and
**path-secrecy propagation** (one-wayness composes up the tree path from the fresh
leaf secret). Within-epoch per-sender message-key FS is the same `kdf_ck` one-wayness
proven in `RatchetFS.fst`. Straight-line => QROM-preserving.

### `EngineAuth.fst` — F*, control-plane authorization (F-17)
Models the engine's authorization state machine — the checks that CONSUME group-message
authenticity (`apply_commit` / `verify_host_sig` / `Frame::Roster` gating). Same
idealized EUF-CMA primitive. Nine theorems, all discharged, zero `admit`: a **commit**
is applied only if the committer is the host leaf AND the host signed it (so no member
can inject a commit), with epoch binding; a **roster** is applied only if host-signed
AND its epoch strictly advances (monotonic — anti-rollback/replay), with stale rosters
dropped; commit/roster **domain separation**; and the inbound **access gate** is
fail-closed (`Accounts` allow-list refuses non-listed peers; relationship gates require
the flag). Authority is the signature, never the relay-stamped `from` — a forged commit
is rejected regardless of sender restamping. Straight-line => QROM-preserving.

### `GossipLiveness.fst` — F*, gossip dedup soundness + eventual delivery
Models the relay/forward flooding mesh (`core::relay`, `core::engine::SeenSet`). **Honest
scope:** full temporal liveness depends on a network connectivity/fairness assumption
(outside F*/Kani); what is proven is the gossip LOGIC that enables it. Six theorems, all
discharged, zero `admit`: **dedup soundness** (a novel frame is always forwarded — no
message loss; a duplicate is dropped), **loop freedom / termination** (a frame is
forwarded by a node at most once, so the flood cannot storm), **insert monotonicity**,
and **eventual delivery under connectivity** (modeling the flood as reachability: every
node reachable from the source is delivered the frame — a reachability induction over the
forwarding rule) plus **delivery monotonicity** (progress is one-way). Connectivity is
the explicit assumption; the forwarding logic itself starves no reachable node.

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
| `cert_msg subject label vf exp` (F*, IdentityChain) | `Cert::encode` = subject_vk \| label \| valid_from \| expiry (`account.rs`) |
| `walk` / `chain_verifies` (F*) | `IdentityChain::verify`: root-at-account, per-link `verify_signature()` + `valid_at`, issuer==prev.subject, ends-at-leaf (`account.rs`) |
| `valid_at vf exp now skew` (F*) | `Cert::valid_at` with `CLOCK_SKEW_TOLERANCE` (`account.rs`) |
| `revoke_msg` + `revocation_valid` (F*) | `Revocation` signed by the account key (`account.rs`) |
| `next_ck` / `mk_of` (F*, RatchetFS) | `kdf_ck(ck) = (next chain key, message-key seed)` (`kdf.rs`) |
| `rk_root` / `rk_chain` (F*, RatchetFS) | `kdf_rk(root, ikm) = (new root, chain key)` (`kdf.rs`) |
| `der` forward closure (F*) | the one-wayness of HKDF/KMAC256-SHA-384 chain/root steps (no inverse) |
| `transcript tag suite idi ni idr pk nr` (F*, Handshake) | `handshake_transcript` = tag \| suite_id \| id_i \| nonce_i \| id_r \| prekey \| nonce_r (`handshake.rs`) |
| `t_resp` / `t_confirm` (F*) | `T_RESP` / `T_CONFIRM` domain-separation tags (`handshake.rs`) |
| `init_accepts` / `resp_accepts` (F*) | `peer_identity.verify(resp/confirm_transcript, sig)` in `initiate`/`respond` |
| `kdf_hs psk kem_ss` (F*) | `suite.begin_session(root0, prekey)` / `accept_session` (PSK + ML-KEM) |
| `derive_parent` / `derive_commit` (F*, TreeKemKS) | `derive_parent_secret` / `derive_commit_secret` — tree path → epoch secret (`treekem.rs`) |
| `der` closure (F*, TreeKemKS) | fresh path secrets sealed via ML-KEM to current members only (`rekey_path`) |
| `commit_transcript` / `apply_commit_ok` (F*, EngineAuth) | `commit_auth_transcript` + `apply_commit` host-leaf + sig check (`treekem.rs`) |
| `roster_transcript` / `apply_roster_ok` (F*) | `roster_transcript` + host-sig + monotonic `last_roster_epoch` (`engine.rs`) |
| `policy` / `allows` (F*) | `AccessPolicy` + `AccessPolicy::allows` inbound gate (`engine.rs`) |
| `insert` dedup (F*, GossipLiveness) | `SeenSet::insert` novel/duplicate decision (`engine.rs`) |
| `delivered` / `path` closure (F*) | `forward_loop` flooding over the connected relay mesh (`relay.rs`) |

F* folds the epoch check into the signed transcript (a wrong-epoch message needs a
different signature); the EasyCrypt `accepts_route` models the epoch check as an
explicit reject branch. Together they cover the route both ways.

## Verification stack (defense in depth)

| Layer | Tool | What it proves |
| --- | --- | --- |
| Protocol auth (symbolic) | **F\*** | The 9 authentication theorems, QROM-sound. |
| Identity-chain acceptance | **F\*** | Chain-verify soundness, impersonation resistance, revocation (9 theorems). |
| Pairwise ratchet secrecy | **F\*** | Double Ratchet forward secrecy + post-compromise security (4 theorems). |
| Handshake auth + secrecy | **F\*** | Mutual authentication, agreement, domain separation, session-key secrecy (6 theorems). |
| Group key-schedule secrecy | **F\*** | TreeKEM post-compromise security + forward secrecy (removal, epoch, path — 4 theorems). |
| Control-plane authorization | **F\*** | F-17 commit/roster gating: host-only, monotonic, fail-closed access (9 theorems). |
| Gossip liveness logic | **F\*** | Dedup soundness (no loss, loop-free) + eventual delivery under connectivity (6 theorems). |
| Protocol auth (computational) | **EasyCrypt** | Tight EUF-CMA reduction + every acceptance route. |
| Confidentiality | **EasyCrypt** | KEM IND-CCA-QROM + DEM model; observable message-independence. |
| Wire decoders | **Kani** (BMC) | Message + membership parsers total & memory-safe on ALL inputs. |
| End-to-end | **proptest** | Authenticity, integrity, PoP-rejection, decoder totality over real crypto. |
| Primitives | **FIPS KAT / ACVP** | ML-KEM-1024 / ML-DSA-87 match NIST vectors (`selftest.rs`). |

## Soundness of the checkers

The EasyCrypt proofs were validated against a **deliberately false lemma**, which the
checker rejects (`cannot prove goal`) — confirming `smt()` genuinely discharges goals
rather than vacuously admitting. F* reports "All verification conditions discharged".
