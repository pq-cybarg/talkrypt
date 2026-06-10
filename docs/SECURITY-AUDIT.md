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
(including properties that are *not* yet met). 211 automated tests, a fuzzed wire
codec, and one Kani proof back the review but are *not themselves* an audit.

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
| F-9 | Info | No formal constant-time guarantees across all primitives (timing side-channel review not performed). | Open — Recommendation R-4 |
| F-10 | Info | GUI bundles (Android APK, desktop) are not built/tested in CI; the Rust core + FFI they depend on are. | Open |
| F-11 | Medium | The suite-registry floor was enforced only against a suite's *self-declared* `SecurityLevel` tag — a suite naming AES-128 / ML-KEM-768 / ML-DSA-65 could pass by tagging itself `PostQuantum`. | **Resolved** — `register` now also enforces the declared parameters (`meets_cnsa_floor`); the AEAD type (`&[u8;32]`) structurally bars an AES-128-length key |
| F-12 | Info | The RFC 9420 conformance harness (`crates/crypto/src/mls/`) names the standard AES-128-GCM ciphersuite and derives 16-byte key-schedule bytes to match official MLS vectors. It instantiates no cipher, is not a registrable suite, and is not on any message path. | By design — `docs/CONFORMANCE.md`; walled off by F-11 + the AEAD type |
| F-13 | Medium | `rsa` 0.9.10 (RUSTSEC-2023-0071, Marvin timing attack, no upstream fix) is pulled transitively by Arti under the `tor` feature; absent from default builds; talkrypt performs no RSA. | **Resolved** — `rsa` vendored + source-patched to blind every private-key op (`third-party/rsa/`, applied via `[patch.crates-io]`); see R-1 entry below |

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

Regression guard: `ratchet::tests::dropping_active_session_runs_zeroize_drop`
exercises the drop path with all secret fields populated; the existing 101 crypto
tests confirm correctness is preserved. (That the bytes are *observably* zero
post-drop is not testable in safe Rust — reading dropped memory is UB; a Miri run
is the proper verification, R-3. `zeroize` itself guarantees the volatile write
is not optimized away.)

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
  length-prefixed decoding, **fuzzed** (`fuzz/fuzz_targets/`) and **Kani-proven**
  for decoder bounds. Highest-value place for an external fuzzing campaign.
- **Invite/descriptor parsing** (`descriptor.rs`): parses attacker-influenceable
  `talkrypt://` URIs; covered by parser fuzzing.
- **Identity resolution** (`contacts.rs`, `engine.rs::handle_identity`): verifies
  attacker-supplied cert chains; the binding check (leaf == authenticated peer)
  is the anti-replay linchpin.
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

- **Zeroization:** `dropping_active_session_runs_zeroize_drop` (exercises the
  F-3 drop path with root + both chain keys + a non-empty skipped-key map).

Gaps: the zeroize *wipe* is not memory-verified in safe Rust (Miri, R-3); no
timing/side-channel tests (F-9); CVE scanning not automated (F-2).

---

## 7. Recommendations for the official audit

| ID | Priority | Recommendation |
| --- | --- | --- |
| R-1 | Done | `cargo audit` + `cargo deny` wired into CI (`.github/workflows/audit.yml`, push/PR + weekly) via `scripts/audit-deps.sh` + `deny.toml`. Keep the ignore list reviewed. (F-2, F-13) |
| R-2 | High | Commission an independent cryptographic review of the ratchet, handshake, and identity-chain logic — the properties in §3 are the audit's core. (F-1) |
| R-3 | Low | F-3 zeroization is implemented; add a Miri run in CI to *verify* the wipe (safe Rust can't observe post-drop bytes). |
| R-4 | Medium | Timing side-channel review of the AEAD and signature paths; document constant-time status. (F-9) |
| R-5 | Medium | Power-on KAT self-tests for AES-GCM, ML-KEM, ML-DSA, hash, KDF (also a FIPS prerequisite). (COMPLIANCE §5.1) |
| R-6 | Low | External fuzzing campaign on the wire codec and descriptor parser beyond the bundled harness. |
| R-7 | Low | Sign and notarize desktop packages once a release identity exists; sign the `.deb`. (F-8) |

---

## 8. Conclusion

Within the stated threat model, talkrypt's design and implementation appear
**internally consistent and adequate** against the in-scope adversaries — *as
judged by the project itself*. The dominant, unresolved risk is **F-1: no
independent verification.** No property in this document should be relied upon
for high-stakes or classified use until an external audit confirms it. This
self-audit is a starting point for that audit, not a substitute for it.
