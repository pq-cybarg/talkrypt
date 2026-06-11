# Security self-audit

> **This is an internal audit performed by the project on its own code.** It is
> *not* an independent security audit, cryptographic review, or penetration test,
> and it cannot substitute for one. Its purpose is to (a) state the threat model
> precisely, (b) record the project's own findings honestly — including the ones
> that count against it — and (c) give an external auditor a structured starting
> point. Treat every "adequate" judgement below as **provisional, pending
> independent confirmation.** See the README banner, `SECURITY.md`, and
> `docs/COMPLIANCE.md`.

**Audit date:** 2026-06-08 · **Commit:** see `git log` · **Auditor:** the project (self).

---

## 1. Scope & methodology

**In scope:** the Rust workspace — crypto (`crates/crypto`), session/identity
engine (`crates/core`), transport (`crates/transport`), wire codec
(`crates/wire`), group layer (`treekem`), FFI (`crates/ffi`), and the CLI.
**Method:** source review against the threat model, mapping of each claimed
security property to its mechanism and its test(s), and an honest findings sweep
(including properties that are *not* yet met). 225 automated tests, nine
coverage-guided fuzz targets over every attacker-reachable decoder, and one Kani
proof back the review but are *not themselves* an audit.

**Out of scope:** the Arti/Tor dependency tree, the OS, the Rust standard library
and the cryptographic-primitive crates' internals (their correctness is assumed;
see `docs/COMPLIANCE.md` for their validation status), and the GUI bundles'
platform glue beyond the FFI boundary.

---

## 2. Threat model

**Assets:** message *content* (highest); identity↔account linkage; long-term
account/device keys; metadata (who-talks-to-whom, presence); membership of
restricted channels.

**Adversaries:**

| Adversary | Capability | Primary mitigation |
| --- | --- | --- |
| Network / metadata observer | sees all ciphertext + timing | Tor onion transport; PQ inner layer; wire padding for frame-indistinguishability |
| Store-now-decrypt-later (quantum) | records ciphertext, breaks ECC later | ML-KEM-1024 KEM; ML-DSA-87 identity (zero load-bearing ECC) |
| First-contact MITM | active on the first connection | invite-token PSK in the handshake + out-of-band safety-number (SHA3-384) comparison |
| Malicious peer | a valid session peer | identity unforgeable without the account ML-DSA key; access-policy gating; revocation |
| Endpoint key theft (past) | steals keys, wants old/future content | Double Ratchet forward secrecy + post-compromise recovery |
| Hostile wire input | sends malformed frames | bounded codec, fuzzed + Kani-proven decoder, uniform AEAD failure |

**Explicitly out of scope (no software defends these):** a fully-compromised live
endpoint (keylogger, screen capture, RAM scraping); global passive
traffic-confirmation against Tor itself; coercion of an endpoint holder.

**Trust boundaries:** (1) the AEAD session boundary — everything sensitive,
including the account↔device identity chain, travels *inside* it, never in the
plaintext handshake; (2) the custody boundary — long-term keys at the device's
strongest custody tier; (3) the FFI boundary — the host UI is untrusted to the
core for crypto decisions (it only polls events and supplies opaque inputs).

---

## 3. Cryptographic review

| Property | Mechanism | Evidence | Assessment |
| --- | --- | --- | --- |
| Confidentiality (PQ) | ML-KEM-1024 KEM → AES-256-GCM | `hybrid.rs`, `aead.rs` | Adequate (alg-level) |
| Forward secrecy | one-way KDF chain keys, deleted after use | `ratchet.rs`; `out_of_order_within_chain` | Adequate |
| Post-compromise recovery | fresh KEM entropy per asymmetric ratchet step | `ratchet.rs`; `keys_evolve_post_compromise` | Adequate |
| AEAD integrity | AES-256-GCM, message header bound as AAD | `aead.rs`; `wrong_aad_fails`, `tampered_ciphertext_fails` | Adequate |
| Nonce uniqueness | per-message key+nonce from KDF; never reused | `kdf.rs`; `nonce_is_fresh_per_seal` | Adequate |
| Replay resistance | counter + skipped-key cache, bounded by MAX_SKIP=1000 | `ratchet.rs`; `replay_is_rejected_without_corrupting_state`, `too_many_skipped_is_bounded` | Adequate |
| State-corruption safety | decrypt on cloned state, commit only on success | `ratchet.rs`; `tampered_fails_without_corrupting` | Adequate |
| Identity unforgeability | ML-DSA-87 cert chain account→device→segment | `account.rs`; `impostor_account_cannot_forge_membership`, `tampered_cert_fails_signature` | Adequate |
| Chain binding (no replay of another's chain) | leaf fp must equal authenticated peer fp | `contacts.rs`; `impostor_chain_does_not_resolve_as_known_contact` | Adequate |
| Cert validity window | `valid_at` with ±5-min clock-skew tolerance | `account.rs`; `expired_cert_is_rejected`, `fresh_cert_tolerates_verifier_clock_behind` | Adequate; see F-5 |
| Revocation | account-signed revocation refuses a leaked device | `engine.rs`; `revoked_device_is_refused` | Adequate |
| Access control | policy gates membership/keypackage by resolved account | `engine.rs`; `access_policy_*`, `rejected_joiner_gets_feedback` | Adequate |
| MITM (first contact) | invite-token PSK; safety-number OOB compare | `handshake.rs`; `wrong_root_cannot_decrypt`, `tampered_root_breaks_session` | Adequate (depends on OOB compare) |
| Frame indistinguishability | PQ-pure padded to hybrid wire length | `hybrid.rs`; `padded_pure_matches_hybrid_wire_length` | Adequate |
| Algorithm floor | registry rejects sub-floor *parameters* (not just a self-declared tag) | `suite.rs::meets_cnsa_floor`; `mislabeled_subfloor_suite_rejected_*` | Adequate; see F-11 |
| At-rest key sealing | Argon2id(m=19 MiB,t=2,p=1) + AES-256-GCM | `descriptor.rs`, `keystore.rs` | Adequate |
| Group FS on removal | TreeKEM re-key per commit/epoch | `treekem.rs`; `remove_denies_removed_member`, `stale_epoch_message_rejected` | Adequate |

---

### 3a. Constant-time analysis (R-4)

A timing-side-channel review of every comparison and branch that touches secret
or authentication-decision data. Scope: talkrypt's own code plus the
constant-time guarantees we inherit from the primitive crates.

| Surface | Operation | Constant-time? | Source |
| --- | --- | --- | --- |
| AEAD open | GCM tag verification + uniform failure (no plaintext on bad tag, single error path) | Yes | `aes-gcm` / `aws-lc-rs` verify the tag in constant time and return one opaque error; talkrypt never branches on *why* an open failed |
| ML-KEM decaps | Implicit rejection — a bad ciphertext yields a pseudo-random shared secret rather than an early error, with no secret-dependent branch | Yes | `ml-kem` (FIPS-203 §6.3 implicit rejection) |
| ML-DSA verify | Signature verification over public inputs; no secret-dependent timing in the signer's secret path that talkrypt exposes | Yes | `ml-dsa` |
| Identity-chain key equality | Issuer/subject/leaf verifying-key comparison on the **authentication-decision** path | Yes — `subtle::ConstantTimeEq` | `identity.rs::IdentityPublic::ct_eq`, used in `account.rs::IdentityChain::verify` |
| Ratchet decrypt | Runs against a **clone** of session state, committed only on success | N/A (no secret-dependent branch; failure is uniform) | `ratchet.rs`; `tampered_fails_without_corrupting` |
| At-rest unseal | Argon2id KDF then AES-256-GCM open; failure is the single AEAD error path | Yes (inherits AEAD uniform failure) | `keystore.rs`, `descriptor.rs` |

**talkrypt's own code:** audited for secret-dependent branches and
comparisons. There are none — no `==` on key/MAC/tag material, no early-return
keyed on secret content, no table or array index derived from a secret. The one
authentication-gate comparison (identity-chain key equality) was converted to
`subtle::ConstantTimeEq` as defense-in-depth: the verifying-key bytes are
public, so the prior `==` was not an exploitable leak, but an auth gate is
constant-time *by principle* — it must not leak position-of-first-difference
regardless of whether the operands are secret. The key length is a fixed public
parameter, so a length mismatch short-circuits to "not equal".

**Inherited guarantees:** the three PQ/AEAD primitives (`ml-kem`, `ml-dsa`,
`aes-gcm`/`aws-lc-rs`) provide their own constant-time and uniform-failure
behavior for the secret paths; talkrypt does not re-implement any primitive and
does not unwrap their internal state, so it cannot reintroduce a leak those
crates avoid.

**Residual:** constant-time behavior of the *underlying crates* is asserted by
those crates, not independently verified here; this is folded into F-1 (no
external review). No talkrypt-introduced timing leak was found.

---

### 3b. RAM-capture mitigation (R-8)

**Threat.** An attacker who can read this process's memory recovers live
secrets — the identity seed, ratchet chain keys, group keys, message plaintext.
The capture vectors, by how privileged the attacker is:

| Vector | Privilege | Mitigated? |
| --- | --- | --- |
| Secret paged to **swap**, read later from the swap file | disk access | Yes — `mlock` (`LockedBox`) keeps the identity seed off swap |
| **Core dump** on crash spills memory to disk | disk access | Yes — `setrlimit(RLIMIT_CORE,0)` + `MADV_DONTDUMP` on the locked pages |
| **`ptrace` / `/proc/<pid>/mem`** by a same-uid process | same-uid code exec | Yes (Linux/Android) — `prctl(PR_SET_DUMPABLE,0)` |
| **Cold-boot / DMA** read of physical RAM | physical access | Partial — only the *window* shrinks (zeroize-on-drop, FS); a live secret in RAM is readable |
| **Root / kernel** attacker reads arbitrary process memory | full device compromise | No — unwinnable in software, and (today) not closable by hardware either; see residual |

**What is implemented** (`crates/crypto/src/mem.rs`, wired into CLI `main` and
every FFI keygen via `ensure_hardened`):

1. **`LockedBox<N>`** — a heap-pinned secret buffer that is `mlock`'d (never
   swapped), `madvise(MADV_DONTDUMP)`'d (excluded from core dumps on
   Linux/Android), and zeroized-then-unlocked on drop. The ML-DSA-87 identity
   seed — the single most valuable long-lived secret — now lives here, and is
   generated *directly into* locked memory (`OsRng.fill_bytes(seed.as_mut_array())`)
   so it never transits an unpinned temporary. The drop path is Miri-verified
   free of UB (`mem::` tests in the `miri` workflow).
2. **`harden_process`** — at startup, disables core dumps process-wide and marks
   the process non-dumpable. Best-effort and idempotent; a denied syscall
   degrades hardening but never breaks functionality.

These compose with two properties already in place: **comprehensive
zeroize-on-drop** (F-3, Miri-verified) bounds every transient secret's lifetime,
and the **Double Ratchet's forward secrecy** means a single capture cannot
unwind past traffic.

**Residual (honest).** On a *fully compromised device* — a kernel-level or root
attacker who can read arbitrary process memory while talkrypt runs — RAM capture
is **not** defeatable in software: a secret must be plaintext in RAM at the
instant it is used. The mitigations above shrink the window and close the
disk-spill and same-uid vectors; they do not change the hostile-device verdict,
which is folded into F-1.

The defense that *would* remove the raw key from app RAM during use is a secure
element that performs the signature on-chip. **That option does not exist for us
today:** Android StrongBox / Titan M2, the Solana Seeker's secure element, Apple's
Secure Enclave, and TPMs implement only *classical* primitives (P-256 ECDSA/ECDH,
RSA, AES) — **none can generate, store, or sign with ML-DSA-87**. talkrypt's
identity is post-quantum by design ([[ec-never-load-bearing]]), so a classical
secure element cannot custody it. Putting the PQ signing key in hardware is
therefore blocked on **PQC-capable silicon shipping in commodity secure
elements**, not on talkrypt integration work — it is a hardware-roadmap
dependency, and we do not claim it as available mitigation.

What hardware *can* do today is protect the key **at rest, not in use**: a
classical key held in the secure element (biometric/PIN-gated, non-exportable)
can wrap the encryption key that seals the stored ML-DSA seed, so the seed cannot
be decrypted off-device or without user presence. This is exactly the
`CustodyTier::HardwareBacked` the FFI already surfaces
(`SoftwareSealed` / `OsKeystore` / `HardwareBacked`) — hardware-backed *sealing*
of the seed, distinct from hardware-backed *signing*. It hardens the at-rest and
theft cases; it does **not** help the live-RAM attacker, because the seed is
still unwrapped into (locked) RAM to sign. Tracked as **R-8**.

---

## 4. Findings register

Severity reflects impact *on the project's own claims*, assuming an honest user
who has read the disclaimers.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| F-1 | High (meta) | No independent audit / cryptographic review / penetration test. Every property above is unverified externally. | Open — disclosed in README & `SECURITY.md` |
| F-2 | Medium | Dependency vulnerability scanning (`cargo audit` / `cargo deny`) was not run in CI. | **Resolved** — `scripts/audit-deps.sh` + `deny.toml` + `.github/workflows/audit.yml` (push/PR + weekly) |
| F-3 | Low | Transient *symmetric* session secrets were not all zeroized-on-drop. | **Resolved** — Double Ratchet + PQ-Noise sessions now zeroize on drop; per-message keys held in `Zeroizing` |
| F-4 | Low | Keygen uses `rand::OsRng` (`getrandom`) with no SP 800-90B health tests or approved DRBG wrapper. | Open — relevant to FIPS (COMPLIANCE §5.2) |
| F-5 | Low | Cert validity tolerates ±5 min clock skew (`CLOCK_SKEW_TOLERANCE`), so a cert expired by <5 min, or not-yet-valid by <5 min, is accepted. | Accepted — bounded, necessary for unsynchronized device clocks; revisit if short-TTL certs are introduced |
| F-6 | Info | Default hash/KDF is SHA3-384/KMAC256 (FIPS 202), not the CNSA-named SHA-384; `--features cnsa-sha2` switches to SHA-384. | By design — `docs/COMPLIANCE.md` §2 |
| F-7 | Info | Group layer is a custom PQ construction, not RFC 9420 (MLS) conformant — no MLS interop. | By design — `docs/CONFORMANCE.md` |
| F-8 | Low | Desktop packages are ad-hoc-signed (macOS) or unsigned (`.deb`); integrity rests on `SHA256SUMS`, not a trusted signing authority or notarization. | Open — `docs/PACKAGING.md` |
| F-9 | Info | Timing side-channel posture not documented. | **Reviewed** (R-4): AEAD/signature/KEM are constant-time via their crates; our code has no secret-dependent comparison; the auth-decision key comparison is now constant-time. See §3a. |
| F-10 | Info | GUI bundles (Android APK, desktop) are not built/tested in CI; the Rust core + FFI they depend on are. | Open |
| F-11 | Medium | The suite-registry floor was enforced only against a suite's *self-declared* `SecurityLevel` tag — a suite naming AES-128 / ML-KEM-768 / ML-DSA-65 could pass by tagging itself `PostQuantum`. | **Resolved** — `register` now also enforces the declared parameters (`meets_cnsa_floor`); the AEAD type (`&[u8;32]`) structurally bars an AES-128-length key |
| F-12 | Info | The RFC 9420 conformance harness (`crates/crypto/src/mls/`) names the standard AES-128-GCM ciphersuite and derives 16-byte key-schedule bytes to match official MLS vectors. It instantiates no cipher, is not a registrable suite, and is not on any message path. | By design — `docs/CONFORMANCE.md`; walled off by F-11 + the AEAD type |
| F-13 | Medium | `rsa` 0.9.10 (RUSTSEC-2023-0071, Marvin timing attack, no upstream fix) is pulled transitively by Arti under the `tor` feature; absent from default builds; talkrypt performs no RSA. | **Resolved** — `rsa` vendored + source-patched to blind every private-key op (`third-party/rsa/`, applied via `[patch.crates-io]`); see R-1 entry below |
| F-14 | Medium | Remote-DoS panic in the ratchet-header decoder: a hybrid / padded-PQ-pure `RatchetPublic` whose length-prefixed X25519/pad field was shorter than 32 bytes triggered an out-of-range slice index (`hybrid.rs::to_32`), panicking the receiver on a single malformed inbound message. Found by the new `ratchet_header` fuzz target (R-6), in ~3.5k executions. | **Resolved** — decode path now uses a fallible `try_to_32` returning `Malformed`; regression test `short_x25519_or_pad_field_is_rejected_not_panic` + corpus seed `corpus/ratchet_header/regression-short-x25519-field` |
| F-15 | Medium | RAM-capture exposure: long-lived secrets (notably the ML-DSA-87 identity seed) could be paged to swap or written to a core dump, and no process hardening blocked `ptrace`/`/proc/<pid>/mem` scraping. On a fully compromised (root/kernel) device this is unwinnable in software, but the disk-spill and same-uid vectors are mitigable. | **Resolved (mitigated)** — identity seed now in `mlock`'d, `MADV_DONTDUMP`, zeroize-on-drop page-locked memory (`mem::LockedBox`); startup `harden_process` disables core dumps + sets non-dumpable. Residual (hostile-device) folded into F-1. Hardware-backed *signing* of the PQ key is impossible on today's classical-only secure elements (StrongBox / Seeker SE / Secure Enclave / TPM lack ML-DSA); hardware-backed *at-rest sealing* is the available next step (R-8). See §3b |

### Detail on the notable findings

**F-1 (the dominant risk).** talkrypt's security rests entirely on
self-testing. A single implementation bug — a mis-bound AAD, a nonce reuse, a
chain-verification shortcut — could silently void any property in §3. The
*only* remediation is an independent audit; until then the software must not be
relied on for high-stakes confidentiality. This is stated prominently and is not
boilerplate.

**F-3 (zeroization) — Resolved (comprehensively).** Done at the source so no
transient can be missed:

- **KDF outputs** — `kdf_rk`, `kdf_ck`, `kdf_mk` now return their secret outputs
  (root, chain keys, message-key seed, AEAD key) in `zeroize::Zeroizing`, so
  *every* caller's locals — across `ratchet`, `noise`, `group` (sender keys), and
  `treekem` — wipe on scope exit, including on early-return error paths.
- **Raw shared secrets** — `RatchetSecret::step_to`/`step_from`/`combine_ikm`
  return the `ikm` in `Zeroizing` and wipe the intermediate KEM secret (`kem_ss`)
  and the X25519 DH secret. These are the freshest, most sensitive transients and
  were previously left in plain `Vec`/array locals.
- **Session state on drop** — `ratchet::Session`, `noise::NoiseSession`,
  `group::SenderKey`/`SenderKeyReceiver`, and `treekem::{TreeKemGroup, RecvChain,
  LeafKeyPair}` implement `Drop` to zero their root/epoch/chain keys, cached
  skipped message-key seeds, and the TreeKEM node-secret map (the ratchet Session
  also wipes the transient clones made for trial-decryption). The ML-DSA seed and
  sealed keys were already zeroized; the X25519 ratchet secret self-zeroizes via
  dalek.

**Miri-verified (R-3 done).** The wipe is observed soundly with
`crate::assert_drop_zeroes`: heap-allocate the value, run its `Drop` via
`drop_in_place` (which does *not* free the allocation), then read the secret
field from the still-live allocation (no use-after-free) and assert it is zero.
Under `cargo +nightly miri test` this confirms both the wipe and freedom from
undefined behavior for every secret-bearing type — `ratchet::Session`,
`noise::NoiseSession`, `group::SenderKey`/`SenderKeyReceiver`,
`treekem::TreeKemGroup` — plus the `Zeroizing`-returning `kdf::*` paths and a full
ratchet encrypt/decrypt + populated-session drop run end-to-end (real ML-KEM
under Miri). `zeroize` itself guarantees the volatile write is not optimized away.
The existing 101 crypto tests confirm correctness is preserved.

**F-2 / R-1 (dependency scanning) — Resolved.** `scripts/audit-deps.sh` runs
`cargo audit` (RustSec DB) + `cargo deny check` (advisories, licenses, banned
crates, source policy via `deny.toml`); `.github/workflows/audit.yml` runs it on
push/PR **and weekly** (the schedule re-scans the unchanged tree so newly
disclosed advisories surface). Baseline at adoption: one vulnerability (F-13,
fixed by patch), three unmaintained transitive crates (`bincode`, `paste`,
`proc-macro-error2` — surfaced as non-failing warnings; not vulnerabilities), all
licenses permissive, all sources crates.io. The gate is green.

**F-13 (rsa / Marvin) — Resolved by source patch.** `rsa` 0.9.10 is flagged by
RUSTSEC-2023-0071 (private-key recovery via a timing side-channel) with no fixed
upstream release. It enters the tree **only** transitively through Arti
(`arti-client → … → ssh-key-fork-arti → rsa`) under the `tor` feature, for SSH
key *parsing* (not encryption/signing), and is **absent from default builds**;
talkrypt performs no RSA operations of its own. Rather than accept it, `rsa` is
**vendored and source-patched** (`third-party/rsa/`, wired via
`[patch.crates-io]` so the fix applies to every build/install): the single
private-key chokepoint (`algorithms/rsa.rs::rsa_decrypt`, which backs decrypt
*and* sign) now **blinds with the OS CSPRNG whenever no caller RNG is supplied**,
so a private-key operation is never performed unblinded — the recognized Marvin
countermeasure. The vendored crate's own 89 tests pass with the patch active,
confirming RSA correctness is preserved. Advisory tooling matches by version and
cannot see the source patch, so RUSTSEC-2023-0071 is listed in `deny.toml` /
`audit-deps.sh` with a justification pointing to `third-party/rsa/TALKRYPT-PATCH.md`
— documenting a *fixed* dependency, not an accepted risk.

**F-11 (floor enforcement) — Resolved.** The registry's floor originally rejected
a suite only if its self-reported `SecurityLevel` was below `PostQuantum`. Because
the level is *self-declared*, a custom or buggy suite could advertise
`PostQuantum` while its id named AES-128 / ML-KEM-768 / ML-DSA-65, and register.
Fixed: `register` now additionally enforces the *declared parameters* by parsing
the suite id (`meets_cnsa_floor` — requires ML-KEM-1024, AES-256-GCM, ≥384-bit
hash, ML-DSA-87 if signing); a sub-floor id is rejected at the default floor
regardless of the tag, with `set_floor` the only explicit way to admit one. Two
further structural barriers reinforce it: the `ml-kem`/`ml-dsa` crates expose only
Category-5 parameter sets, and `crate::aead` is typed `&[u8; 32]` so an
AES-128-length key cannot be passed to the cipher. Tests:
`floor_check_accepts_real_suites_rejects_subfloor_parameters`,
`mislabeled_subfloor_suite_rejected_even_when_tagged_post_quantum`. (The remaining
trust is that a *locally registered* suite's implementation matches its id — a
node only ever runs schemes it has registered itself; `scripts/crypto-inventory.sh`
asserts the built-in implementations use only floor algorithms.)

**F-5 (clock-skew tolerance).** Added after a live failure where a freshly-issued
device certificate was rejected by a peer whose clock lagged ~45 s. The ±5-min
window is the standard PKI not-before allowance. Because talkrypt's certificates
are long-lived (device link TTL ~10 years), the symmetric grace past expiry is
immaterial today; it would need re-evaluation if short-lived certificates are
introduced. Bounded, documented, and unit-tested (`fresh_cert_tolerates_verifier_clock_behind`).

---

## 5. Attack surface

- **Wire codec** (`crates/wire`): the primary untrusted-input surface. Bounded
  length-prefixed decoding, **fuzzed** (`fuzz_targets/wire_reader`) and
  **Kani-proven** for decoder bounds.
- **Invite/descriptor parsing** (`descriptor.rs`): parses attacker-influenceable
  `talkrypt://` URIs; **fuzzed** (`descriptor_parser`).
- **Identity resolution** (`contacts.rs`, `account.rs`, `engine.rs::handle_identity`):
  decodes and verifies attacker-supplied presentations, cert chains, username
  claims, and revocations *before* signature checks; the binding check
  (leaf == authenticated peer) is the anti-replay linchpin. All four decoders
  are **fuzzed** (`presentation`, `identity_chain`, `signed_claim`, `revocation`).
- **Per-message ratchet header** (`hybrid.rs`, `ratchet.rs`): the public key +
  KEM ciphertext parsed on every inbound message, across all three KEM profiles;
  **fuzzed** (`ratchet_header`) — this surfaced and fixed F-14.
- **Scheme beacons & suite matching** (`beacon.rs`, `suite.rs`): the
  always-encrypted scheme advertisement and the fingerprint-based registry
  lookup of an attacker-chosen suite id/params; **fuzzed** (`beacon_body`,
  `suite_scheme`).
- **FFI boundary** (`crates/ffi`): the host UI supplies opaque hex/URIs; malformed
  input returns typed errors, never panics across the boundary (uniffi).
- **Transport** (`crates/transport`): sees only ciphertext; a hostile relay
  (`RelayHub`) forwards without the group key.

---

## 6. Test coverage of security properties

211 workspace tests. Security-relevant, by property (all names verified present):

- **AEAD/integrity:** `wrong_aad_fails`, `tampered_ciphertext_fails`, `tampered_ct_fails`, `nonce_is_fresh_per_seal`.
- **FS / PCS / ratchet:** `keys_evolve_post_compromise`, `out_of_order_within_chain`, `out_of_order_across_ratchets`, `replay_is_rejected_without_corrupting_state`, `too_many_skipped_is_bounded`, `prop_arbitrary_direction_schedule`, `prop_out_of_order_permutation`.
- **Identity/auth:** `impostor_account_cannot_forge_membership`, `impostor_chain_does_not_resolve_as_known_contact`, `tampered_cert_fails_signature`, `tampered_message_fails_verify`, `expired_cert_is_rejected`, `expired_chain_is_rejected`, `fresh_cert_tolerates_verifier_clock_behind`, `revoked_device_is_refused`.
- **Access control:** `access_policy_contacts_mode`, `access_policy_restricts_to_allowed_accounts`, `rejected_joiner_gets_feedback`.
- **Algorithm floor:** `floor_check_accepts_real_suites_rejects_subfloor_parameters`, `mislabeled_subfloor_suite_rejected_even_when_tagged_post_quantum`, `weak_suite_rejected_unless_floor_lowered`.
- **Session/handshake:** `wrong_root_cannot_decrypt`, `tampered_root_breaks_session`, `tampered_fails_without_corrupting`, `replay_rejected`.
- **KDF/wire KAT:** `kdf_known_answer_lock`, `padded_pure_matches_hybrid_wire_length`, `padded_pure_filler_is_x25519_shaped`.
- **Group:** `remove_denies_removed_member`, `stale_epoch_message_rejected`, `broadcast_is_opaque_without_the_chat_root`.

- **Zeroization:** `dropping_active_session_runs_zeroize_drop`, plus the
  Miri-verified `drop_zeroizes_*` observation tests for `Session`, `NoiseSession`,
  `SenderKey`/`SenderKeyReceiver`, and `TreeKemGroup` (`assert_drop_zeroes`).

Gaps: no timing/side-channel tests (F-9); CVE scanning is wired (F-2) — keep the
ignore list reviewed.

---

## 7. Recommendations for the official audit

| ID | Priority | Recommendation |
| --- | --- | --- |
| R-1 | Done | `cargo audit` + `cargo deny` wired into CI (`.github/workflows/audit.yml`, push/PR + weekly) via `scripts/audit-deps.sh` + `deny.toml`. Keep the ignore list reviewed. (F-2, F-13) |
| R-2 | High | Commission an independent cryptographic review of the ratchet, handshake, and identity-chain logic — the properties in §3 are the audit's core. (F-1) |
| R-3 | Done | F-3 zeroization is Miri-verified (`assert_drop_zeroes` + `cargo +nightly miri test`); wire the Miri run into CI to keep it verified. |
| R-4 | Done | Timing review complete (§3a): AEAD/signature/KEM constant-time via their crates; uniform AEAD failure; no secret-dependent comparison in our code; identity-chain key comparison made constant-time (`subtle`). Next: a `dudect`/statistical timing test in CI for empirical confirmation. |
| R-5 | Done | POST (`self_test`/`ensure_self_tested`) + per-keygen PCT, abort on failure. **CAVP-traceable KATs against official vectors:** AES-256-GCM + SHA3-384/SHA-384 (NIST), ML-DSA-87 keyGen (FIPS-204 reference example, exact), and **ML-KEM-1024 keyGen/encaps/decaps against NIST FIPS-203 ACVP** (usnistgov/ACVP-Server — `selftest::kem_kat` + `tests/nist_mlkem_acvp.rs`, exact). Only the KDF (talkrypt's own KMAC256/HKDF) remains an implementation KAT. (Recorded en route: the C2SP/CCTV ML-KEM vectors are FIPS-203-**draft** and do not match a conformant final implementation — use NIST ACVP.) |
| R-6 | Done | Fuzz harness expanded from 2 to 9 targets covering every attacker-reachable decoder: `wire_reader`, `descriptor_parser`, `identity_chain`, `signed_claim`, `revocation`, `presentation`, `ratchet_header`, `beacon_body`, `suite_scheme` (`fuzz/fuzz_targets/`; the two crate-private codecs reached via the crypto crate's `fuzzing`-gated `fuzz_header_roundtrip`/`fuzz_beacon_roundtrip` hooks). Each ran ≥12 s clean except `ratchet_header`, which found a remote-DoS panic (F-14) in ~3.5k runs — now fixed, with a regression test + corpus seed, and re-fuzzed 30 s (3.9M runs) clean. Decoders are checked for no-panic and structural round-trip. A CI smoke job (`.github/workflows/fuzz.yml`) builds all targets and runs each 45 s on every decoder/harness change, re-exercising the regression corpus. Next: a longer (hours/days) external campaign. |
| R-7 | Low | Sign and notarize desktop packages once a release identity exists; sign the `.deb`. (F-8) |
| R-8 | In progress | RAM-capture hardening (§3b, F-15). **Done:** identity seed in `mlock`'d/`MADV_DONTDUMP`/zeroize-on-drop `LockedBox` (Miri-verified drop), `harden_process` (no core dumps + non-dumpable) wired into CLI + FFI startup. **Next (host integration, available now):** wrap the at-rest seed-sealing KEK with a secure-element classical key (biometric/PIN-gated) when the host reports `CustodyTier::HardwareBacked` — hardware-backed *sealing*. **Blocked (hardware roadmap):** hardware-backed *signing* of the PQ key is impossible until PQC-capable secure elements ship — StrongBox / the Seeker's SE / Secure Enclave / TPMs are classical-only and cannot hold ML-DSA-87. Not a talkrypt task; a silicon dependency. |

---

## 8. Conclusion

Within the stated threat model, talkrypt's design and implementation appear
**internally consistent and adequate** against the in-scope adversaries — *as
judged by the project itself*. The dominant, unresolved risk is **F-1: no
independent verification.** No property in this document should be relied upon
for high-stakes or classified use until an external audit confirms it. This
self-audit is a starting point for that audit, not a substitute for it.
