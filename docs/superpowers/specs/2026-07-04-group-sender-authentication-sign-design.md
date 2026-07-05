# Group Hardening — Sender Authentication (SIGN) + On-Demand PCS

> **DECIDED DIRECTION (2026-07-04):** *harden the existing, already-post-quantum TreeKEM* with
> **audited components + standard MLS patterns**, rather than build novel unaudited crypto. The
> groups already run **ML-KEM-1024 + ML-DSA-87** (verified in `crypto/hybrid.rs`); nothing to migrate
> on the PQ axis. This doc fixes the two real gaps: **(1) forgeable attribution** (G1/G2 — this spec's
> §2–6) and **(2) no on-demand post-compromise healing** (the missing MLS `Update` op — §11).
> Sequenced work: **① this hardening (now) → ② evaluate OpenMLS + PQ ciphersuite (#74) → ③ document
> the novel decentralized PQ-DCGKA path (#73)**. Single-committer / host-coordinated is the audited
> reality for PCS; the decentralized-multi-committer vision is deferred to #73 as a documented design.

**Goal:** Make group/relayed attribution **cryptographically unforgeable** (no member forges as
another — G1; no relay injects/rewrites attribution — G2; no forged membership commits — G3-auth) via
**per-identity ML-DSA-87 signatures** on every group/relayed message + **signed commits**, verified
against **per-identity signing keys**; and add the standard MLS **`Update` self-rekey** so members
**heal on demand** (PCS), not only on membership change.

**Audited-components posture:** signing/verify use the existing `ml-dsa` (ML-DSA-87) crate; the KEM is
`ml-kem` (ML-KEM-1024). Both may optionally be moved to the **formally-verified `libcrux-ml-kem` /
`libcrux-ml-dsa`** crates already present in the tree (pulled by nym) for maximal assurance — a
drop-in primitive swap, no protocol change.

**Why signatures are the load-bearing fix:** authentication is orthogonal to key agreement. Per-sender
signatures are **self-verifying** (valid to anyone holding the signer's pubkey, regardless of epoch or
transport), so they close G1/G2 on the *existing* tree and would compose with any future CGKA (#74/#73).

---

## 1. Threat model closed by SIGN

From the external review + our own map (`crates/crypto/src/treekem.rs`, `crates/core/src/engine.rs`):

- **G1 — member forges as member.** Group message keys are `sender_chain(epoch_secret, leaf)`;
  `epoch_secret` is shared by all members and `leaf` is a public header field, so any member derives
  any other member's chain and sends messages `decrypt` attributes to that leaf. No signature today.
- **G2 — relay forges attribution.** The Chat-injection half was closed by PR #1
  (`Frame::Chat` now requires `role == None`). The **residual**: `Frame::Roster` (engine.rs member
  arm) is an unauthenticated wholesale overwrite, and `GroupMsg` attribution is roster+leaf based, so
  a malicious relay can still poison who a genuine message is attributed to.
- **G3-auth — forged commits.** Commits are applied with no signature/authorization: any member (or
  relay) can inject an eviction/re-key. (PR #1 fixed the *DoS* half of G3/G4; **authorization** is
  open.)

**What SIGN guarantees after the fix:** a displayed attribution (a safety-number / name over a
message) means *the holder of that identity's signing key authored this exact ciphertext in this
chat* — unforgeable by any other member or relay. Membership changes are only valid if signed by the
authorized committer.

**What SIGN does NOT guarantee (documented):** PCS (self-healing after key compromise — Sub-projects
2/3); metadata privacy; deniability (ML-DSA signatures are non-deniable — see §8).

---

## 2. Per-identity, root-derived signing keys

The signing key MUST be **per-identity, never the device/account key** — otherwise every identity a
device presents is linkable by a shared signature key, destroying pseudonyms / segmented identities /
opsec-clean. And it MUST be **root-derived** (deterministic, recoverable), not random-and-stored.

```
seed_i    = mac_kdf(root_seed, DOMAIN, context_i)          // 32 bytes, PQ KDF (KMAC/HKDF)
key_i     = IdentityKeyPair::from_secret_bytes(seed_i)     // ML-DSA-87 keygen is deterministic
                                                            //   (identity.rs from_secret_bytes/from_seed)
```
- **Recoverable** — regenerate any identity's key from the one `root_seed`; no per-key backup; a
  linked device holding the root is the same identity.
- **Deterministic** — the same identity → the same key across sessions/devices, so it's stably
  recognizable where recognition is wanted.
- **Unlinkable** — different `context_i` → pseudorandom, independent-looking keys (KDF outputs are
  indistinguishable from random; ML-DSA public keys reveal no shared origin), so an observer cannot
  tell two of a user's identities share a root.

**Two flavors, both root-derived:**
- **Account-linked identity** — `context_i` is a defined **segment path**; the derived key is
  certified via the existing chain `IdentityChain::device(account, …).extend(…, key_i.public(), …)`
  (`account.rs`). Presenting that chain proves account linkage — **opt-in** (governed by the opsec
  policy, Sub-spec B). Reuses the existing account→device→segment cert tree; the *only* new crypto is
  the deterministic derivation of the segment seed (segment keys are random today).
- **Unlinkable pseudonym** — `context_i` is an unanchored/ephemeral context; the derived key is bare
  (no chain), anchored to nothing. Still root-derived (recoverable), just uncorrelatable.

`root_seed` custody = the account seed at any custody tier (existing model), or a device-local
pseudonym root. This is exactly the **segmented-identities / signature-subtree** model already in
`account.rs`, extended with deterministic derivation.

---

## 3. Signing-key distribution via signed presence

To verify a sender's signature a receiver needs that sender's **per-identity signing public key**
(ML-DSA-87 vk = 2592 bytes). Distributing it per-message is wasteful; instead distribute it **once**
via a **signed presence** and cache it, so each message carries only a compact key-id + signature.

- A member announces `IdentityPresence { key_id, signing_pubkey (2592B), context_binding,
  self_sig, [optional cert_chain] }` once on join / on identity change:
  - `key_id` = a short stable id (e.g. first 16 bytes of `SHA3-256(signing_pubkey)`).
  - `self_sig` = the identity key signing over `(signing_pubkey ‖ chat_context)` — proves possession
    and binds the presence to this chat (no cross-chat replay).
  - `cert_chain` (optional) present iff the identity is account-linked (opt-in disclosure).
- Receivers verify `self_sig` (and the chain if present), then cache `key_id → signing_pubkey`
  (+ resolved identity/tier). Attribution/display key = `signing_pubkey.fingerprint()` — the safety
  number, and the anchor for a Sub-spec A name.

**This is the same "presence" primitive as Sub-spec A** (self-declared names). SIGN owns the
security-critical core (the per-identity signing key + its signed distribution); **Sub-spec A's names
become a display layer on top of it** — so SIGN re-sequences *before* names. A pseudonym with no name
still emits an `IdentityPresence` (needed to verify its message signatures); a named identity's
`NamePresence` carries the same `signing_pubkey`.

Presence rides inside the encrypted session (pairwise `Frame`) / under the group epoch key
(group payload), inheriting confidentiality + the existing gossip fan-out + SHA-256 dedup — a relay
never sees a signing pubkey in the clear, and can't strip a presence without the message signatures
then failing to verify (fail-closed: unresolved sender → shown as unverified, never mis-attributed).

---

## 4. Per-message signatures (closes G1 + G2-attribution)

Every **group** message (`GroupMsg`) and **relayed** frame carries a per-identity signature; pairwise
`Frame::Chat` is unchanged (already mutually authenticated by the ratchet handshake).

- **Sender** (engine layer — `TreeKemGroup::encrypt` has *no* signing key, so this lives in
  `engine.rs` where `Inner` holds the per-identity key): after building the group ciphertext
  `gct = epoch ‖ leaf ‖ n ‖ ct`, compute `msg_sig = key_i.sign(SIG_DOMAIN ‖ chat_context ‖ gct)` and
  send `SignedGroupMsg { key_id, gct, msg_sig }` in place of the raw `GroupMsg(gct)`.
- **Receiver** (`handle_group_msg`): look up `signing_pubkey` by `key_id` (from cached presence);
  verify `msg_sig` over `(SIG_DOMAIN ‖ chat_context ‖ gct)`; **only then** decrypt + attribute to
  `signing_pubkey.fingerprint()`. A missing/failed key_id or bad signature ⇒ drop (fail-closed);
  never fall back to the roster/leaf for attribution.
- **Attribution becomes self-verifying and committer-independent:** the signature proves authorship
  by the holder of `key_id`'s key, so a rewritten `Frame::Roster` **cannot forge attribution** (the
  roster is now advisory display, not a trust input) and a relay **cannot inject** a message (no valid
  member signature). This closes **G1** and the **G2 attribution/roster residual** together, and works
  identically across the gossip mesh / bridged islands (a cross-island sender's key travels with its
  presence, not a per-island committer).

**Overhead:** +`key_id` (16B) + `msg_sig` (4627B) per group/relayed message. Real but acceptable for a
security-first channel; scoped to group/relayed only (pairwise unchanged). Cover-traffic/padding
already exists. (No KEM ciphertext here, so mKEM compression is not applicable to SIGN; it's a Layer-2
concern for PQ commit bandwidth.)

---

## 5. Signed commits + committer pinning (closes G3-auth + G2-roster integrity)

Membership changes must be authorized so a member/relay can't forge an eviction or re-key.

- The **committer** (the group's authority — `GroupRole::Host` / the sequencing committer) signs each
  `Commit` (and any `Roster` snapshot it emits) with its **committer identity key**:
  `commit_sig = committer_key.sign(COMMIT_DOMAIN ‖ chat_context ‖ commit_bytes)`.
- Members **verify `commit_sig` against a pinned committer identity** before applying a commit; an
  unsigned/wrong-signer commit is rejected. This makes eviction/re-key committer-only (G3-auth) and
  makes any `Frame::Roster` the committer emits authenticated (G2-roster integrity).
- **Pinning the committer — the relayed-mode anchor problem.** Today a *directly*-joined member
  authenticates the host via the handshake, but the full `IdentityPublic` is discarded (only the fp is
  kept), and a *relayed* member authenticates the **relay**, not the host — so there is **no committer
  anchor**. SIGN adds the **committer's identity public key (or its fingerprint) to the
  `ChatDescriptor`** (the invite), so every joiner — direct or relayed — pins the same committer
  identity out-of-band from the invite. This is a **descriptor field + version bump** (v1→v2 on main;
  note the paused Sub-spec A branch also bumped to v2 for `NameTrustPolicy` — reconcile field order at
  implementation). Retain the committer `IdentityPublic` in `Inner` (widen `Peer`/`Inner` beyond the
  bare fp).

For the **gossip/mesh (availability) mode** — multiple committers, no single authority — commits are
still each committer-signed, and a member pins the committer(s) it knows; cross-island membership it
can't verify is surfaced as unverified (no PCS in this mode anyway; that's the documented tradeoff).
Single-committer PCS groups (Sub-project 2) have exactly one pinned committer.

---

## 6. Wire & plumbing summary

- **New/changed frames (all in-session, NOT the KAT-locked descriptor except the committer field):**
  `SignedGroupMsg { key_id: [u8;16], gct: Vec<u8>, msg_sig: Vec<u8> }` (replaces raw `GroupMsg` on the
  group path); commits gain `commit_sig`; a new `IdentityPresence` payload (or extend Sub-spec A's
  `NamePresence`) carries `signing_pubkey + self_sig`. `Routed` attribution (`from`) becomes advisory
  — verification is by `msg_sig`, not `Routed.from`.
- **`ChatDescriptor`:** add `committer_identity: IdentityPublic` (or 48-byte fp) + version bump;
  back-compat: a v1 invite has no committer pin ⇒ SIGN groups require v2 (a v1 group can't be
  attribution-verified — surface as legacy/unverified).
- **Engine plumbing:** `Inner` holds the node's **per-identity signing key** (derived per §2 for the
  chat's chosen identity) and the **pinned committer `IdentityPublic`**; signing/verification happen
  in `engine.rs` (`send_marked` group branch, `handle_group_msg`, `handle_commit`, the relayed reader
  arms), NOT in `crates/crypto` `TreeKemGroup` (which stays a pure ratchet).
- **Crypto crate:** add the deterministic segment-seed derivation (`mac_kdf(root, ctx) →
  from_secret_bytes`) and reuse `IdentityKeyPair::sign`/`IdentityPublic::verify` (sigs are `Vec<u8>`).

---

## 7. Testing

- **Unit (crypto/core):** deterministic derivation (same root+ctx → same key; different ctx →
  independent keys); presence self_sig verify (valid / forged / wrong-context); per-message sig verify
  (valid / forged / wrong key_id / wrong chat_context); commit_sig verify (valid / wrong signer /
  unsigned).
- **Integration (`LoopbackFabric`):**
  - **G1:** a malicious member forging another's `sender_leaf` produces a message with **no valid
    `msg_sig`** for that identity ⇒ dropped, never attributed. (Invert the existing
    `member_can_forge_group_message_as_another_member` demo → now fails to forge.)
  - **G2:** a relay injecting a `SignedGroupMsg` with a spoofed key_id/attribution ⇒ signature verify
    fails ⇒ dropped; a relay rewriting `Frame::Roster` ⇒ attribution unchanged (self-verifying).
  - **G3-auth:** a member/relay injecting an unsigned or wrong-signer `Commit` ⇒ rejected; only the
    pinned committer's signed commit evicts/re-keys.
  - **Gossip:** a cross-island sender's message verifies via its presence-distributed key (no
    committer dependency); dedup unaffected.
  - **Unlinkability:** two identities from the same root produce signatures/pubkeys with no efficient
    linkage (sanity: distinct fingerprints, no shared bytes).
- **On-device:** two Android emulators over Nym — a message from A verifies on B and shows A's
  safety-number/name; a tampered/injected frame is dropped.

---

## 8. Security considerations

- **Fail-closed attribution:** an unverifiable message is dropped or shown as *unverified*, never
  mis-attributed. This is the core invariant.
- **Deniability lost:** ML-DSA signatures are non-repudiable — a signed message cryptographically
  proves authorship. This is a deliberate trade for unforgeable attribution; **no post-quantum
  deniable group scheme exists** (survey). If deniability is later required it's a separate research
  item, not a SIGN tweak. Flag for the user.
- **Signing-key compromise = impersonation going forward** (until the identity's key rotates), NOT
  past-message exposure (confidentiality is the separate ML-KEM layer). Standard signature-key threat.
  PCS (healing) is Sub-projects 2/3.
- **Overhead / DoS:** verification is per-message ML-DSA verify (fast); the 4627-byte signature is a
  bandwidth cost, bounded and scoped to group/relayed. Presence rate-limits (Sub-spec A) apply.
- **Relay confidentiality unchanged:** the relay still sees only ciphertext + signatures (no
  plaintext, no signing seeds).

---

## 9. Relationship to the other sub-projects & Sub-spec A

- **Sub-spec A (self-declared names, #65):** SIGN provides the per-identity signing key + its signed
  distribution (`IdentityPresence`); Sub-spec A's `NamePresence` **is** that presence with a display
  label attached. SIGN therefore lands *before* names; names become a thin display layer. Reconcile
  the shared presence/descriptor changes at implementation (both touch presence + descriptor version).
- **Sub-project 2 (MLS-PQ PCS, #74):** consumes SIGN's per-identity signatures for authentication; adds
  the single-committer MLS-PQ tree for FS+PCS. Per-chat mode = PCS-strict vs mesh.
- **Sub-project 3 (PQ-DCGKA, #73):** consumes SIGN's signatures; adds decentralized PCS (research).
- **G3/G4 DoS (#72) and L1 (#71):** already done via PR #1.

## 10. Non-goals (deferred / tracked)

- Decentralized multi-committer PCS → #73 (novel, documented-only for now).
- Forward-secrecy hardening beyond the existing ML-KEM ratchets + the §11 `Update` op → fold into #74.
- Metadata privacy, deniability → separate future items (documented in §8).
- Multi-recipient KEM (mKEM) commit compression → an OpenMLS/#74 (PQ commit bandwidth) concern.

---

## 11. On-demand PCS — the MLS `Update` operation (task #75)

**Gap:** `TreeKemGroup` today exposes only `add`/`remove` (`crypto/treekem.rs:548/572`) — there is **no
`Update`**. So the group only re-keys (heals) when membership changes; a member who suspects
compromise **cannot proactively re-key to heal.** That's weak PCS.

**Fix (standard MLS pattern — audited/textbook):** add a self-rekey operation.
```rust
// crates/crypto/src/treekem.rs
/// Re-key ONLY the caller's own leaf→root path with fresh ML-KEM entropy, without any
/// membership change. The resulting Commit, applied by every member, advances the epoch and
/// heals a compromise of this member's prior path secrets (post-compromise security). This is
/// the MLS `Update` proposal+commit, self-authored.
pub fn update(&mut self) -> Result<Commit> {
    // No proposals; just rekey_path over an empty proposal set (fresh secrets leaf→root),
    // exactly like add/remove do after applying their proposals.
    self.rekey_path(Vec::new())
}
```
- **Confidentiality/PCS:** `rekey_path` already generates fresh secrets leaf→root and ML-KEM-encrypts
  each to the copath (the existing add/remove machinery) — so an `Update` injects fresh entropy up the
  caller's path; an adversary holding the *old* path secrets cannot derive the new epoch secret. This
  is exactly MLS post-compromise security, on the existing ML-KEM tree. No new crypto — reuses
  `rekey_path`.
- **Engine wiring:** `Core::update_group(&self)` builds the `Update` commit and routes it
  (`Route::Broadcast`); the **commit is signed** (SIGN §5, `commit_sig`) so members verify it came from
  the leaf that owns that path (an unauthorized `Update` for someone else's path is rejected).
  Triggers: **on-demand** (user "heal now" / app resume) and **optional periodic** self-update (bounds
  the compromise window — a coordination-free FS/PCS improvement, per-chat cadence like Sub-spec A's).
- **Single-committer note:** in a host-coordinated group the host sequences commits; a member's
  `Update` is a proposal the host commits (or, in the current direct model, a member re-keys its own
  path and broadcasts — the signed commit + epoch ordering (`pending_commits`) keep members
  consistent). Concurrency across islands (mesh mode) is the #73 concern; single-committer PCS is the
  audited target here.

**Testing (adds to §7):** post-compromise heal — capture epoch-N key material for member M; M sends an
`Update`; assert the epoch-N material **cannot** derive the epoch-N+1 secret (M healed). An `Update`
commit with a `commit_sig` from a non-owner of the path ⇒ rejected. `Update` with no membership change
leaves the roster unchanged.
