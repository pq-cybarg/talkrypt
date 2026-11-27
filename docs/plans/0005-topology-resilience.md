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
3. **Presumptive queue-only peering** (engine). Split:
   - **3a (DONE)** — JOINING-member LOCAL outbound queue: a member may `send()` before its
     Welcome; the plaintext is buffered locally (`pending_outbound`, bounded 256), never on
     the wire and never encrypted early (I2), and flushed in order the instant we join
     (`flush_pending_outbound` from `handle_welcome`). Zero new wire/trust surface; DoS is
     local-only. Factored the Host/Member send path into `group_send` (shared by live send
     + flush). Test `presumptive_queue_delivers_messages_composed_before_join` (fails
     without the queue).
   - **3b (NEXT)** — relay-JOIN with correct attribution: let a joiner JOIN through a peer
     (not only the committer directly) for true hub-peer-peer-peer JOIN. This is the
     security-critical part and reuses the existing T-3 primitive (`LeafSigCert`: a device
     certifies its TreeKEM leaf sig key). Design:
       * The joiner sends a self-authenticating join: its `LeafSigCert` (device-signed leaf
         binding) travels WITH the KeyPackage, plus an invite-bound MAC (KDF of
         `invite_token` over the KeyPackage) proving invite possession.
       * A gossip relay forwards KeyPackage + LeafSigCert ONLY if the invite-MAC verifies
         (I4 cheap pre-filter: unbound junk is dropped, not propagated), under a per-neighbor
         token bucket + TTL.
       * The committer attributes the new leaf to the DEVICE identity in the verified
         `LeafSigCert` (not the connection `from`), closing the G2 relay-attribution gap;
         it also validates the invite-MAC before `add`.
       * Welcome is then gossip-relayed back to the joiner (safe — encrypted to the joiner's
         KEM key; only the joiner decrypts), so it reaches a non-adjacent joiner.
     Obligation: prove (EngineAuth) that a relay cannot cause acceptance of a leaf attributed
     to an identity it does not control, and (GossipLiveness) the invite-MAC pre-filter + TTL
     keep a join flood bounded. Implement as its own increment with full reverification; do
     NOT weaken the G1/G2/F-17 posture.
4. **Multi-hub committer + failover.** Split:
   - **4a (DONE)** — GRACEFUL, signed, epoch-fenced committer handoff: the host signs a
     `CommitterHandoff{successor_leaf, from_epoch, sig}` (host leaf key) delegating ROSTER
     (F-17) signing authority; members verify it against leaf 0 and thereafter accept the
     successor's rosters for epochs >= from_epoch, FENCING OUT the old committer (exactly
     one authority per epoch — I1, no split-brain; a revived old host is rejected). Low
     blast radius: new read-only `verify_leaf_sig` + `sign_as_leaf` in crypto, the normal
     leaf-0 F-17 path untouched. Tests: successor roster accepted under delegation; old
     host (leaf 0) fenced at epoch >= from_epoch; non-delegated member rejected; a handoff
     not host-signed is not honored (no self-promotion). F* EngineAuth THEOREM 13 (handoff
     requires host) + 14 (single authority per epoch / old host fenced) discharged.
   - **4b (DONE)** — UNGRACEFUL failover via a host-PRE-AUTHORIZED standby + a strict BFT
     quorum. Chosen model (2026-11-26, default on the maintainer's "continue"): the host
     signs a `StandbyDesignation{standby_leaf, from_epoch}` (so a quorum can only ever
     activate the ONE host-chosen leaf — never an arbitrary/malicious member); members then
     cast `PromotionVote{for_epoch, voter_leaf}` (leaf-signed, counted once), and when
     distinct votes exceed **> 2/3 of the roster** the standby is activated via the same
     epoch-fenced delegation as 4a (so 4a's single-authority/I1 carries over). A minority
     (< 1/3) can neither reach the quorum nor pick the leaf. Tests: BFT quorum (4/5)
     activates, sub-quorum (3/5) does not; a full quorum WITHOUT a host designation promotes
     no one. F* EngineAuth THEOREM 15 (standby requires host) + 16 (activation needs
     designation + quorum) + 17 (a minority cannot promote), all discharged.
   - **4c (DONE)** — committing TAKEOVER: the activated successor processes joins and
     produces COMMITS, not just rosters. `TreeKemGroup::apply_commit_with(commit, delegate)`
     authorizes a commit against the SOLE committer for the epoch (host, or the epoch-fenced
     delegate), verifying the committer's own leaf key — the commit analogue of the roster
     gate (NOT mechanical: it touches the F-17 commit authority, the crown jewel; `apply_commit`
     stays a `…_with(_, None)` wrapper so all existing callers are untouched). Engine: a single
     `is_active_committer` flag (host holds it at creation; `record_delegation` TRANSFERS it so
     exactly one node processes joins / signs rosters — the old host steps down, no
     double-commit); join gates + `signed_roster_frame` key off it. Tests: crypto
     `apply_commit_with_gates_the_delegated_committer` (non-authorized committer rejected,
     delegate accepted); engine `delegated_successor_processes_a_new_join` (a new member joins
     THROUGH the successor and every member applies the successor's add-commit, epoch in
     lock-step). F* EngineAuth THEOREM 18 (commit authority is a single leaf per epoch; old
     host fenced) discharged. **Increment 4 is now fully complete.**
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
