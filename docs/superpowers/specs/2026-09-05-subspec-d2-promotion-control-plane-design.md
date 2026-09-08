# Sub-spec D2 — Promotion control plane (ephemeral → persistent room transition)

**Status:** design for review.
**Scope:** Rust core (`crates/core/src/engine.rs`, `treekem.rs`, `descriptor.rs`) + a thin
FFI/app surface. Depends on **D1** (store-and-forward delivery) for what "persistent" does,
and feeds **D3** (retention contract) at the consent step.
**Parent:** #48. This is the coordinated, consented, re-keyed transition that opts a live
ephemeral room into a persistent one — the `PROMOTE` wire signal + member consent + member
picker + target tier.

## Goal

Turn a live **ephemeral** room into a **persistent** successor: a stable/reconnectable room
whose picked members carry over, gated by member consent (their ephemeral expectation is
being changed), with a re-key at the boundary. Ephemeral chats stay ephemeral unless
promoted; promotion is deliberate and authenticated.

## Trust model — every step rides the per-sender ML-DSA leaf signature

The group-hardening core already authenticates *who* speaks per-leaf (G1/G2 fix,
`treekem.rs` `encrypt_signed`/`decrypt_verified`, modelled by `GroupAuth.fst`). Promotion
reuses that: a `Promote` proposal and each `Consent` response are **signed under the
sender's tree-bound leaf key** over a **new domain-separated transcript**, so
`GroupAuth.fst`'s theorems extend by construction.

## Wire additions

Two `Frame`s (tags **13/14**, reserved ahead of D1's 15–18):

| tag | frame | payload |
|---|---|---|
| 13 | `Promote` | signed blob: `target_tier: u8` ‖ `retention_mode: u8` ‖ `consent_rule: u8` ‖ `n_picked: u8` (≤ `MAX_PICKED`) ‖ `n_picked × [u8;48]` account fps ‖ `onion_len: u8` ‖ onion bytes ‖ `epoch: u32` ‖ `sig` |
| 14 | `Consent` | signed blob: `promote_id: [u8;32]` ‖ `decision: u8` (accept/decline) ‖ `leaf: u32` ‖ `epoch: u32` ‖ `sig` |

- **`promote_id` = SHA-256 of the canonical `Promote` body** (binds a consent to exactly one
  proposal; injective, replay-resistant).
- The **picked list is a fixed-capacity `[[u8;48]; MAX_PICKED]` + count** (not an uncapped
  `Vec` like `Roster`), so `Promote::decode` stays in the **Kani-provable flat class**.
- Signatures are verified with a new `PROMOTE_CONTEXT` transcript (see below).

## Transcripts (domain separation — preserves GroupAuth Thms 2/3/6)

Add, next to `sig_transcript`/`pop_transcript` in `treekem.rs`:

```
promote_transcript(epoch, leaf, body)  = PROMOTE_CONTEXT | epoch | leaf | body
consent_transcript(epoch, leaf, pid, d) = CONSENT_CONTEXT | epoch | leaf | pid | d
```

`PROMOTE_CONTEXT` / `CONSENT_CONTEXT` are **new constants, distinct from `SIG_CONTEXT` and
`POP_CONTEXT`** (Thm 6 `PopDomainSep` requires this or cross-protocol signature replay
becomes possible). Both encodings are **injective** (length-prefixed) — Thm 2 `Transcript-
Injective`. New `TreeKemGroup` methods `sign_promote`/`verify_promote`,
`sign_consent`/`verify_consent` mirror `encrypt_signed`/`decrypt_verified`, so the receiver
verifies **under `leaf_sig_keys[leaf]`, fail-closed on unknown leaf** (Thms 1/3).

## Consent rules — all three modes (per the design decision)

`consent_rule ∈ { Unanimous, OptInSuccessor, HostMandate }`:

- **Unanimous** (safest default): every picked member must return `Consent{accept}` (verified,
  fresh, distinct-leaf) before promotion commits; any decline or a timeout **aborts**. Nobody's
  ephemeral expectation is overridden.
- **OptInSuccessor:** the successor room is created; each picked member individually joins it by
  returning `Consent{accept}` (which triggers their add into the successor); non-consenters are
  simply not added — they stay in / drop from the ephemeral room. More states, more flexible.
- **HostMandate:** the host converts the room; a picked member that returns `Consent{decline}`
  (or times out) is **removed** from the successor (a `Proposal::Remove`), never silently
  carried. Fastest, least consensual — surfaced clearly in the UI as such.

The per-member accept prompt reuses the **L1 `ApprovalFn`** primitive (`linking.rs:163`,
fail-closed default DENY, bounded offer window) — the existing "member must approve" hook —
rather than the automatic access-policy gate.

## The re-key (PCS boundary — preserves GroupAuth Thms 7/8)

Once the consent rule is satisfied, the committer performs a **coordinated re-key** that IS
the ephemeral→persistent boundary:

1. `Proposal::Remove` for every **un-picked** member (member picker) + for **decliners** under
   HostMandate.
2. A group `sig_update` (`treekem.rs` `update()`), rotating the KEM path **and** each leaf
   signing key, **PoP'd** (Thm 4) and **rebinding `leaf_sig_keys`** exactly like `apply_commit`
   (Thm 7 `rotation_rebinds`, Thm 8 `auth_pcs` — pre-promotion compromised keys stop verifying).
3. Broadcast the resulting `Frame::Commit` + `Frame::Roster` (the existing add/remove/commit
   fan-out in `engine.rs`), reusing `commit_update`'s anti-leaf-hijack proposer check.

Reuse the existing machinery (`self_update` `engine.rs:1148`, `commit_update`
`treekem.rs:915`, `handle_commit`/`handle_update_proposal`) — the promotion commit is a
batch of familiar proposals, not a new crypto primitive.

## Target tier + persistence wiring

- `target_tier ∈ { PersistentLocal, Shared, AlwaysOn }` (the app's 3-tier model,
  `ChatModels.kt`). Carried in the `Promote` payload; the successor's descriptor is bumped and
  the tier persisted for reconnect.
- On the wire the Rust `Persistence` enum stays 2-valued (`Ephemeral|Persistent`); the finer
  tier is app-level (#47 `ALWAYS_ON`). If the successor needs a **stable onion**, it is created
  with `OnionPersistence::Persistent{state_dir}` (`arti.rs`) and re-advertised.
- **Descriptor grows to v6**: append a `promotion: Option<PromotionMeta>` field under
  `if version >= 6` (same append-only discipline as v4 `message_padding` / v5 `vouch_policy`),
  carrying the target tier + successor onion so a rejoining member reconnects to the persistent
  room. v1–v5 invites decode with `promotion = None`.

## Data flow

1. Promoter (host, or any member if chat policy allows) builds + signs `Promote{tier, retention,
   consent_rule, picked, onion}`; broadcasts `Route::Broadcast`.
2. Each picked member verifies the signature (leaf key + `PROMOTE_CONTEXT`), shows the consent
   prompt (with the **retention mode** from D3 so they know what they're agreeing to), and
   returns a signed `Consent`.
3. Host tallies consents per `consent_rule`; on satisfaction, commits the re-key (removes +
   `sig_update`) and marks the room persistent (enables D1 Layer-0 outbox via
   `set_persistence`).
4. Members apply the commit in epoch order; the successor is now persistent + reconnectable.
5. Abort path (Unanimous decline/timeout): promoter emits a signed `Promote`-abort; room stays
   ephemeral; no re-key.

## FV-preservation contract

1. `Promote`/`Consent` are signed under the leaf key with **new domain-separated injective
   transcripts** → `GroupAuth.fst` Thms 1–3/6 extend; the re-key uses `sig_update`/PoP/rebind →
   Thms 4/7/8 hold. Add F* lemmas mirroring the existing ones if the transcripts warrant, else
   argue parametricity (the accept predicate is unchanged shape).
2. `Promote::decode`/`Consent::decode` use fixed-capacity arrays (`MAX_PICKED`) → **Kani
   `*_never_panics` proofs** in the PR.
3. The consent-tally / re-key orchestration (heap) → exhaustive property test: promotion commits
   **iff** the consent rule is met over *verified distinct-leaf* consents; a forged/replayed/
   stale-epoch/duplicate consent never counts; an un-picked member is never in the successor.

## FFI + app surface

- `Core::propose_promote(chatId, tier, retention, consent_rule, picked)`,
  `Core::respond_promote(promote_id, accept)`; `FfiEvent::PromoteProposed{by, tier, retention,
  picked}` + `FfiEvent::Promoted{chatId}` / `FfiEvent::PromoteAborted`.
- App: a promote sheet (tier + retention + consent-rule + member picker) and a consent prompt.
  The member-picker + tier UI is where **#9's dark-neon design system** folds in (verified with
  a Gradle build).

## Testing

- Core unit: sign/verify promote + consent under each transcript; the three consent rules
  (unanimous accept/decline/timeout; opt-in partial; host-mandate removal); descriptor v6
  round-trip.
- `LoopbackFabric` integration: host + 3 members, promote picking 2, unanimous → successor has
  exactly those 2 re-keyed + persistent; decliner under host-mandate is removed; un-picked member
  absent.
- Kani: `promote_decode_never_panics`, `consent_decode_never_panics`.
- Adversarial: forged consent (wrong leaf), replayed consent (old `promote_id`/epoch),
  non-member `Promote` — all rejected; the property test above.

## Out of scope

Delivery mechanics (D1); the retention/history treatment (D3); Backend-1 ZK. Assumes D1 exists
so "mark persistent" has teeth.
