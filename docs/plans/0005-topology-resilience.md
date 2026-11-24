# Plan 0005 — Topology resilience: relay chains, hub-dropout, presumptive peering, multi-hub, no-hub

Status: DESIGN LOCKED (2026-11-24). Built on the known-good tag
`known-good-2026-11-24-pre-topology` (commit 21f029d). NOT certified / NOT audited.

## Goal

Decouple message delivery from any single hub, and make the group connectivity robust:

1. **hub-peer-peer-peer** — a relay chain hanging off the hub: members relay content
   (and, where needed, control-plane) along member↔member peer links.
2. **hub-dropout-peer-peer** — the group keeps delivering content after the hub goes
   offline, over the remaining peer graph.
3. **presumptive peering (conservative, queue-only)** — a joiner/peer may form a
   pairwise link and have a neighbor QUEUE its backlog before the hub confirms, so hub
   delay never delays delivery once confirmed. **No group key is released before the
   committer's real Welcome.**
4. **multi-hub** — connect to several hubs; the committer model is a **per-room
   configurable policy** (consensus-selectable), never two live committers.
5. **no-hub peer-peer** — pure P2P (already `P2PMesh`); included for completeness/tests.

## Hard invariants (these constrain every feature; see threat notes)

- **I1 Single committer per epoch.** TreeKEM membership changes are serialized by exactly
  one committer. Multi-hub = N relays of the one committer's frames (active-active, dedup)
  OR a standby promoted only via a signed, epoch-fenced handoff. **Never two live
  committers** (would fork epochs — the "race with the missing hub").
- **I2 No premature key.** The group key is released ONLY by the committer's authenticated
  Welcome, after it validates the invite-bound KeyPackage. Presumptive peering queues
  opaque backlog; a later-rejected joiner never held the key.
- **I3 Provisional ∉ trust.** An unconfirmed (not host-signed-roster) member has no leaf,
  so it accrues zero attribution / vouch / sybil weight. Vouches naming it are rejected or
  deferred until confirmation. (Holds the existing `trust≠access`, additive-only invariant.)
- **I4 DoS-bounded relay.** Before shuttling a KeyPackage a relay checks the invite-token
  binding (cheap, in the descriptor root); unbound → dropped, not propagated. Then
  per-neighbor token-bucket + global cap on unconfirmed-join traffic, a bounded provisional
  queue with eviction, and a hop-limit (TTL) + SeenSet dedup on relayed control frames, so
  one injection cannot fan out unboundedly. Unconfirmed members cannot produce group
  content (no key → dropped at decrypt-verify), so a flood degrades to bounded pending
  KeyPackages / pairwise dials.
- **I5 Relay cannot forge.** Relayed control frames are opaque, endpoint-authenticated
  (Welcome encrypted to joiner; Commit validated by the key schedule; Roster host-signed —
  F-17; KeyPackage validated by the committer on add). Intermediate relays forward bytes
  only; the recipient verifies. Consistent with the existing A-1 "signature is the
  authority" bridging result.

## Decisions (owner, 2026-11-24)

- Presumptive posture: **conservative queue-only** (I2), ships in 1.0-line.
- Multi-hub committer model: **per-room configurable policy**, consensus-selectable
  (active-active relay as the safe default; signed standby failover as an opt-in policy a
  room/consensus may choose). Expose as a descriptor/room setting, not a global.
- The existing FV proofs are **archived** (`formal/archive/2026-11-24-pre-topology-overhaul/`)
  and **extended** (not replaced) with the obligations below.

## Build increments (each test-driven, negative-checked, committed)

1. **Control-plane gossip relay + dedup** (engine) — intermediate gossip members re-flood
   opaque authenticated Welcome/Commit/Roster/KeyPackage to other peers, with a control
   SeenSet + TTL; `handle_welcome` must NOT consume the leaf keypair on a non-matching
   Welcome (restore on failure). Enables chain-join and multi-hub-via-relay. Gated by
   gossip mode + I4 admission/rate-limit.
2. **Topology strategies** (crates/topology) — `RelayChain` (connect upstream, host
   downstream, gossip); multi-hub active-active (connect all hubs, dedup) + signed standby
   failover as a policy; resilient hybrid (members interconnect + gossip) for I-presumptive
   + hub-dropout. Room policy selects.
3. **Presumptive queue-only peering** (engine) — pairwise link + neighbor-side bounded
   provisional queue; flush to the group the instant the committer's Welcome/roster
   confirms; invite-token admission + rate-limit (I4). No key before confirm (I2).
4. **Room-configurable multi-hub committer + consensus hook** — descriptor setting; signed
   epoch-fenced handoff for standby promotion (I1); consensus-selection seam.
5. **Tests** — hub-peer-peer-peer (join+deliver along chain), hub-dropout content
   continuity, presumptive queue-then-confirm, multi-hub active-active dedup + failover,
   no-hub P2P; plus DoS-bound tests (flood of unconfirmed → bounded) and I3 (vouch for
   unconfirmed rejected).

## Proof obligations (extend the live `formal/*`, diff vs the archive)

- `EngineAuth.fst` — add: single-committer-per-epoch (I1); control-plane relay preserves
  authorization (a relay cannot cause acceptance of an unauthorized membership change, I5);
  provisional-member state transitions (confirm/reject) with no trust accrual (I3).
- `TreeKemKS.fst` — add: no key release before committer Welcome (I2); standby-failover
  handoff preserves the key-schedule (no epoch fork) (I1).
- `GossipLiveness.fst` — add: control-plane relay + dedup terminates (no infinite flood,
  TTL/SeenSet) and delivers to a connected peer graph even with the hub absent (hub-dropout
  content liveness); rate-limited relay stays bounded under a flood (I4).
- `GroupAuth.fst` / `GroupAuthQROM.ec` — re-confirm: relay/shuttle adds no forgery power
  (I5); provisional members produce no accepted attributed content (I3).

Until an obligation is discharged it is marked in-file as a NEW obligation (assume/admit
with a dated TODO) — honest-scope: never claim proven what is not.
