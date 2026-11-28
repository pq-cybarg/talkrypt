module GossipLiveness

/// Machine-checked (F*) model of the gossip mesh's LIVENESS-ENABLING properties —
/// the relay/forward flooding in `core::relay` + `core::engine::SeenSet` (SECURITY-
/// AUDIT R-2 target; task #121).
///
/// Honest scope. Full temporal liveness ("every message eventually reaches every
/// member") depends on a NETWORK assumption — fair scheduling and the absence of a
/// permanent partition — which is outside what F*/Kani (safety/termination tools) can
/// establish. What IS provable, and is proven here, is the gossip LOGIC that makes
/// liveness possible and rules out the anti-liveness failure modes:
///   1. DEDUP SOUNDNESS — the `SeenSet` forwards every NOVEL frame (no message loss)
///      and drops only genuine duplicates; a second sight of the same frame is
///      dropped, so flooding is LOOP-FREE and TERMINATES (no rebroadcast storm).
///   2. EVENTUAL DELIVERY UNDER CONNECTIVITY — modeling the flood as reachability,
///      every node reachable from the source in the mesh graph is delivered the frame
///      (a reachability induction over the forwarding rule). Connectivity itself is
///      the stated network assumption.
///
/// Together these are the provable core of gossip liveness; the remaining temporal
/// guarantee under adversarial scheduling / partition is an explicit assumption.

(* ==================== PART 1: SeenSet dedup soundness ==================== *)

type gid = nat                 // a frame's gossip-id (SHA-256 fingerprint, `gossip_id`)
type seen = gid -> bool        // the dedup membership (abstracting the HashSet in SeenSet)

/// `SeenSet::insert` (engine.rs:1089): record `x`; return `true` if NEW (caller
/// forwards) or `false` if already seen (caller drops). We model the unbounded
/// membership; the real set is capped (CAP=4096, FIFO-evicted) which only ever makes
/// it FORGET old ids — so it can re-forward a long-ago frame (a safe re-delivery), but
/// it never suppresses a frame it has not currently remembered. (The cap is a memory
/// bound, not a correctness element, so the model takes the membership as given.)
let insert (s:seen) (x:gid) : (bool & seen) =
  if s x then (false, s)
  else (true, (fun y -> y = x || s y))

/// THEOREM 1 (NOVEL FRAME IS FORWARDED — no message loss from dedup). A frame whose
/// id the relay has not seen is ALWAYS accepted (insert returns `true`), so dedup
/// never silently drops a genuinely new frame.
let thm_novel_is_forwarded (s:seen) (x:gid)
  : Lemma (requires ~(s x))
          (ensures fst (insert s x) == true)
  = ()

/// THEOREM 2 (DUPLICATE IS DROPPED). A frame already in the seen set is dropped
/// (insert returns `false`) — exactly the duplicates are suppressed, nothing else.
let thm_duplicate_is_dropped (s:seen) (x:gid)
  : Lemma (requires s x == true)
          (ensures fst (insert s x) == false)
  = ()

/// THEOREM 3 (LOOP FREEDOM / TERMINATION). After a frame is accepted once, seeing it
/// again is dropped — so a frame circulating a cross-connected mesh is forwarded by a
/// node at most once, and the flood cannot loop forever. (The second insert on the
/// post-insert set returns `false`.)
let thm_forward_once_no_loop (s:seen) (x:gid)
  : Lemma (ensures (let (_, s') = insert s x in fst (insert s' x) == false))
  = ()

/// THEOREM 4 (INSERT REMEMBERS). After accepting `x`, it is in the seen set — the
/// state monotonically accumulates, so dedup is stable across the flood window.
let thm_insert_remembers (s:seen) (x:gid)
  : Lemma (ensures (let (_, s') = insert s x in s' x == true))
  = ()

(* ============ PART 2: eventual delivery under connectivity ============ *)

type node = nat                          // a mesh participant / relay
type adjacency = node -> node -> prop    // an edge (connectivity) relation

/// A path through the mesh graph from `a` to `c` (a witness of connectivity). `PNil`
/// is the empty path a~>a; `PCons` prepends an edge.
noeq type path (adj:adjacency) : node -> node -> Type =
  | PNil  : (a:node) -> path adj a a
  | PCons : (a:node) -> (b:node) -> (c:node) -> adj a b -> path adj b c -> path adj a c

/// The flood's reachable/delivered closure under the forwarding rule: the source has
/// the frame; and if `u` has it and `u` is adjacent to `v`, then `v` receives it (the
/// `forward_loop` sends the still-encrypted frame to each neighbor). There is no rule
/// that loses the frame — delivery is monotone (Theorem-3 loop-freedom bounds the work
/// but never drops a delivery).
noeq type delivered (adj:adjacency) (src:node) : node -> Type =
  | DSrc : delivered adj src src
  | DHop : (u:node) -> (v:node) -> delivered adj src u -> adj u v -> delivered adj src v

/// Extend a delivery along a path: if `u` has the frame and there is a path `u ~> v`,
/// then `v` has it too. (Induction on the path.)
let rec deliver_along_path (adj:adjacency) (src u v:node)
      (du:delivered adj src u) (p:path adj u v)
  : Tot (delivered adj src v) (decreases p)
  = match p with
    | PNil a            -> du                                   // u == v
    | PCons a b c e rest -> deliver_along_path adj src b c (DHop u b du e) rest

/// THEOREM 5 (EVENTUAL DELIVERY UNDER CONNECTIVITY — the liveness core). Every node
/// reachable from the source in the mesh graph is delivered the frame. So, GIVEN a
/// connected mesh (the network assumption), the flood reaches every member — no node
/// is permanently starved by the forwarding logic itself.
let thm_reachable_is_delivered (adj:adjacency) (src v:node) (p:path adj src v)
  : delivered adj src v
  = deliver_along_path adj src src v DSrc p

/// THEOREM 6 (DELIVERY IS MONOTONE / STABLE). A delivered node stays delivered and can
/// extend delivery to any further neighbor — the flood never retracts a delivery, so
/// progress is one-way (a prerequisite for liveness: no node loses a frame it had).
let thm_delivery_monotone (adj:adjacency) (src u v:node)
      (du:delivered adj src u) (e:adj u v)
  : delivered adj src v
  = DHop u v du e

(* ======== PART 3: control-plane relay instance (increments 1 & 3b) ======== *)
(* Added 2026-11-25 (plan 0005). The topology-resilience work added a CONTROL-PLANE   *)
(* relay: a gossip bridge re-floods Commit/Roster/Welcome (`relay_control`) and MAC-    *)
(* gated JoinRequests (`relay_join_request`) to peers other than the source, each       *)
(* deduped by the `ctl_seen` set. This is the SAME forward rule and the SAME dedup       *)
(* abstraction as PART 1/2, instantiated on a different frame class and seen set — so    *)
(* Theorems 1-6 apply to it UNCHANGED. We make that application explicit here.           *)

/// `ctl_seen` is another instance of the `seen` dedup abstraction; `relay_control` /
/// `relay_join_request` insert the frame's id and forward only on `true`. Thus:
///   * loop-freedom + termination of the control-plane flood == THEOREM 3, and
///   * eventual delivery of a control frame to every connected member == THEOREM 5,
/// re-exported below so the control-plane relay is covered by proof, not assertion.

/// COROLLARY 7 (CONTROL-PLANE RELAY IS LOOP-FREE / TERMINATES). A Commit/Roster/Welcome/
/// JoinRequest frame is forwarded by a ctl-relay node at most once — the ctl flood cannot
/// storm. Direct instance of Theorem 3 on the `ctl_seen` set.
let thm_ctl_relay_loop_free (s:seen) (x:gid)
  : Lemma (ensures (let (_, s') = insert s x in fst (insert s' x) == false))
  = thm_forward_once_no_loop s x

/// COROLLARY 8 (CONTROL-PLANE FRAME REACHES EVERY CONNECTED MEMBER). Given connectivity,
/// a control frame floods to every node reachable from the committer — so a chain-only or
/// multi-hop member DOES receive the Commit/Roster/Welcome that keeps it in sync (the
/// liveness core for hub-peer-peer-peer and hub-dropout). Instance of Theorem 5.
let thm_ctl_frame_reaches_reachable (adj:adjacency) (src v:node) (p:path adj src v)
  : delivered adj src v
  = thm_reachable_is_delivered adj src v p

/// HONEST SCOPE — JOIN DoS BOUND (plan 0005 I4). Loop-freedom (above) + the invite-MAC
/// pre-filter (EngineAuth THEOREM 10: a non-invite-holder's join is rejected before any
/// relay-forward or commit) bound WHICH join frames propagate. The remaining QUANTITATIVE
/// bound — that the token-bucket rate limiter caps join work per unit time even from
/// invite-holders — is a rate property outside F*'s safety/termination scope (like the
/// temporal-liveness caveat in the module header), and is an explicit assumption, backed
/// by the `TokenBucket` unit tests rather than this proof.
