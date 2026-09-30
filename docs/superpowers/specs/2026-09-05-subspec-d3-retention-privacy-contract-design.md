# Sub-spec D3 — Retention-privacy contract (the ephemeral backlog on promotion)

**Status:** design for review.
**Scope:** `crates/core` (a retention tag on the D2 `Promote` payload + local sealing
behavior) + the app consent prompt. Tightly coupled to **D2**'s consent step.
**Parent:** #48. Governs what happens to the **ephemeral backlog** when a room goes
persistent — the privacy lever, so promotion never silently retroactively persists messages
people believed were ephemeral.

## Goal

When an ephemeral room is promoted (D2), decide what happens to the messages that were
exchanged *while it was ephemeral*, and disclose that choice to members before they consent.
The default protects the ephemeral expectation; carrying history is opt-in and local.

## First principle: promotion authorizes RETENTION, never TRANSMISSION

The critical safety rule: **history is never shipped to anyone**. "Carry" means each
consenting member seals **their own already-received copy**; it never sends backlog to
members who weren't there (that would leak, and would fabricate history for latecomers). So
retention is a **local, per-member** action authorized by the promotion, not a data transfer.

## The three retention modes (`retention_mode` in the D2 `Promote` payload)

- **Fresh (default):** the persistent successor begins **at the promotion boundary**. The
  ephemeral past stays ephemeral — dropped from memory as it always would be. Strongest
  privacy, cleanest PCS story (nothing pre-re-key is retained).
- **Carry:** each consenting member **seals their own in-memory backlog** for this chat into
  the persistent store (the D1/Phase-1 seal). No member gains messages they didn't already
  have. A member who declines (or wasn't present) simply has nothing to carry.
- **CarryFromPoint:** like Carry, but only messages **after a chosen marker** (a message id /
  timestamp the promoter sets) are sealed; earlier ephemeral history is dropped. A middle
  ground — keep the recent thread, forget the older ephemeral part.

## Disclosure + consent (rides D2)

The `retention_mode` is part of the signed `Promote` body, so it is **authenticated and
shown verbatim in every member's consent prompt** (D2 step 2). A member consents to a
*specific* retention contract; changing it means a new `Promote` (new `promote_id`). This
makes the ephemeral-expectation change **explicit and agreed**, matching Sub-spec C's ethics
posture (additive, consented, never silent).

## Ethics invariants (test-enforced, mirroring Sub-spec C §0.5)

1. **Default-safe:** absent an explicit choice, `Fresh` — no retroactive persistence.
2. **Consented:** a member's backlog is sealed only if *that member* consented to a
   Carry/CarryFromPoint promotion; decline ⇒ nothing sealed for them.
3. **No fabrication / no transmission:** carrying never sends history to another member; a
   member only ever retains what they already received (no backfill to latecomers).
4. **Recoverable:** a persistent chat can be returned to ephemeral / its sealed history
   deleted (the existing Delete affordance erases the sealed blob).

## Wire / FV

- No new frame — `retention_mode: u8` is one field already in D2's `Promote` payload (D2's
  Kani `promote_decode_never_panics` covers it; it's a small enum tag, flat).
- No new decoder, no group-auth change. Retention is app/seal-layer behavior gated by the
  authenticated tag.

## Data flow

1. Promoter picks `retention_mode` in the promote sheet (D2).
2. It rides the signed `Promote`; each member sees it in the consent prompt.
3. On a satisfied promotion: `Fresh` → persistent store starts empty at the boundary; `Carry`
   → each consenting member seals its existing history via the D1 store; `CarryFromPoint` →
   seals only post-marker messages.
4. Delete/return-to-ephemeral erases the sealed history (invariant 4).

## Testing

- Core unit: each mode's local sealing behavior (Fresh seals nothing pre-boundary; Carry seals
  the member's own backlog; CarryFromPoint respects the marker); the four ethics invariants as
  explicit tests (esp. "decline ⇒ nothing sealed" and "no backfill to a latecomer").
- Integration: promote with each mode across members with different backlogs; verify each
  member's persistent store contains exactly its own authorized subset and nothing from others.

## Out of scope

Delivery (D1); the promotion protocol itself (D2). This sub-spec is only the retention
semantics + disclosure that ride D2's consent.
