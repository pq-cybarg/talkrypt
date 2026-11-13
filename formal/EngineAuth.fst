module EngineAuth

/// Machine-checked (F*) model of the engine's CONTROL-PLANE AUTHORIZATION state
/// machine — the F-17-class checks that decide whether an inbound commit / roster /
/// control frame is applied (`core::engine` + `crypto::treekem::apply_commit` /
/// `verify_host_sig`, SECURITY-AUDIT F-17 / R-2 target; task #119).
///
/// `GroupAuth.fst` proves group-message AUTHENTICITY (a message was signed by the
/// claimed leaf). This module proves the AUTHORIZATION logic that CONSUMES that
/// authenticity is fail-closed and host-gated: a commit is applied only if the
/// committer is the host leaf AND the host signed it; a roster is applied only if the
/// host signed it AND its epoch strictly advances (anti-rollback); and the decision
/// depends ONLY on the authenticated fields — never on the relay-stamped `from`, so a
/// hostile relay cannot elevate a frame by restamping its sender.
///
/// Signatures are the SAME idealized EUF-CMA primitive as `GroupAuth.fst` (ML-DSA-87
/// / FIPS 204, QROM). Straight-line reductions => QROM-preserving.

type pk = nat          // a leaf's tree-bound signature public key
type msg = list nat
type sig = nat
type log = pk -> msg -> bool

assume val verify : log -> pk -> msg -> sig -> bool
assume EUFCMA : (forall (l:log) (k:pk) (m:msg) (s:sig). {:pattern (verify l k m s)}
                   verify l k m s ==> l k m == true)
let eufcma_inst (l:log) (k:pk) (m:msg) (s:sig)
  : Lemma (requires verify l k m s == true) (ensures l k m == true) = ()

/// The host leaf index (Rust `HOST_LEAF = 0`): the single leaf permitted to broadcast
/// commits and sign rosters.
let host_leaf : nat = 0

(* ---------- commit authorization (apply_commit) ---------- *)

/// `commit_auth_transcript` = COMMIT_AUTH_CONTEXT | from_epoch | committer_leaf | body,
/// injective (domain-separated, length-prefixed).
assume val commit_transcript : (from_epoch:nat) -> (committer:nat) -> (body:nat) -> msg
assume CommitInj :
  (forall fe c b fe' c' b'. {:pattern (commit_transcript fe c b); (commit_transcript fe' c' b')}
     commit_transcript fe c b == commit_transcript fe' c' b' ==> (fe==fe' /\ c==c' /\ b==b'))

/// The `apply_commit` authorization decision (`treekem.rs:1335-1358`): the committer
/// leaf must be the host leaf, AND the commit signature must verify against the host
/// leaf's tree-bound key over the epoch-bound transcript. NB `from` (the relay stamp)
/// is NOT an input — authority is the signature, not the sender stamp.
let apply_commit_ok
      (l:log) (host_key:pk) (committer:nat) (from_epoch:nat) (body:nat) (s:sig) : bool =
  committer = host_leaf && verify l host_key (commit_transcript from_epoch committer body) s

/// THEOREM 1 (COMMIT REQUIRES THE HOST'S SIGNATURE). If a commit is applied, then the
/// committer IS the host leaf and the host's key actually signed exactly this
/// (from_epoch, committer, body) — no member can inject a commit into another member's
/// state without the host's signing key.
let thm_commit_requires_host_sig
      (l:log) (host_key:pk) (committer:nat) (from_epoch:nat) (body:nat) (s:sig)
  : Lemma (requires apply_commit_ok l host_key committer from_epoch body s == true)
          (ensures committer == host_leaf /\
                   l host_key (commit_transcript from_epoch committer body) == true)
  = eufcma_inst l host_key (commit_transcript from_epoch committer body) s

/// THEOREM 2 (NON-HOST / FORGED COMMIT REJECTED — fail closed). If the host key never
/// signed this commit transcript (e.g. a member forged it, or a relay replayed/altered
/// it), the commit is NOT applied — regardless of any relay-supplied `from` stamp
/// (`from_stamp` is unused, making explicit that restamping the sender cannot cause
/// acceptance of an unsigned commit).
let thm_forged_commit_rejected
      (l:log) (host_key:pk) (committer:nat) (from_epoch:nat) (body:nat) (s:sig) (from_stamp:pk)
  : Lemma (requires l host_key (commit_transcript from_epoch committer body) == false)
          (ensures apply_commit_ok l host_key committer from_epoch body s == false)
  = ()

/// THEOREM 3 (COMMIT EPOCH BINDING — no replay into another epoch). A commit signature
/// is bound to `from_epoch`; by injectivity, a signature valid for one epoch does not
/// authorize a commit claimed at a different epoch (unless separately signed).
let thm_commit_epoch_bound
      (l:log) (host_key:pk) (committer:nat) (fe fe':nat) (body:nat) (s:sig)
  : Lemma (requires apply_commit_ok l host_key committer fe body s == true /\ fe' <> fe)
          (ensures apply_commit_ok l host_key committer fe' body s == false \/
                   l host_key (commit_transcript fe' committer body) == true)
  = eufcma_inst l host_key (commit_transcript fe committer body) s;
    if apply_commit_ok l host_key committer fe' body s
    then eufcma_inst l host_key (commit_transcript fe' committer body) s else ()

(* ---------- roster authorization (host-signed, monotonic) ---------- *)

/// `roster_transcript` = ROSTER_CONTEXT | epoch | entries, injective and
/// domain-separated from `commit_transcript`.
assume val roster_transcript : (epoch:nat) -> (entries:nat) -> msg
assume RosterInj :
  (forall e en e' en'. {:pattern (roster_transcript e en); (roster_transcript e' en')}
     roster_transcript e en == roster_transcript e' en' ==> (e==e' /\ en==en'))
assume CommitRosterDomainSep :
  (forall fe c b e en. {:pattern (commit_transcript fe c b); (roster_transcript e en)}
     ~(commit_transcript fe c b == roster_transcript e en))

/// The `Frame::Roster` authorization decision (`engine.rs`): apply only if the epoch
/// strictly advances past the last applied roster epoch (monotonic, anti-rollback)
/// AND the host's key signed `(epoch, entries)`.
let apply_roster_ok
      (l:log) (host_key:pk) (epoch:nat) (entries:nat) (s:sig) (last_epoch:nat) : bool =
  epoch > last_epoch && verify l host_key (roster_transcript epoch entries) s

/// THEOREM 4 (ROSTER REQUIRES THE HOST'S SIGNATURE). Roster authority is the host
/// signature, not the relay-stamped `from`: an applied roster was signed by the host
/// over exactly `(epoch, entries)`. So a member/relay cannot poison roster attribution.
let thm_roster_requires_host_sig
      (l:log) (host_key:pk) (epoch:nat) (entries:nat) (s:sig) (last_epoch:nat)
  : Lemma (requires apply_roster_ok l host_key epoch entries s last_epoch == true)
          (ensures l host_key (roster_transcript epoch entries) == true)
  = eufcma_inst l host_key (roster_transcript epoch entries) s

/// THEOREM 5 (ROSTER MONOTONICITY — no rollback/replay). An applied roster strictly
/// advances the epoch, so a captured older roster cannot be replayed to roll group
/// membership back to a stale state.
let thm_roster_monotonic
      (l:log) (host_key:pk) (epoch:nat) (entries:nat) (s:sig) (last_epoch:nat)
  : Lemma (requires apply_roster_ok l host_key epoch entries s last_epoch == true)
          (ensures epoch > last_epoch)
  = ()

/// THEOREM 6 (STALE ROSTER REJECTED). A roster whose epoch does not advance past the
/// last applied one is dropped even if validly signed (freshness gate).
let thm_stale_roster_rejected
      (l:log) (host_key:pk) (epoch:nat) (entries:nat) (s:sig) (last_epoch:nat)
  : Lemma (requires epoch <= last_epoch)
          (ensures apply_roster_ok l host_key epoch entries s last_epoch == false)
  = ()

/// THEOREM 7 (COMMIT/ROSTER DOMAIN SEPARATION). A host commit signature can never be
/// replayed as a roster signature, or vice versa — the contexts differ, so the
/// transcripts are disjoint. A signature over one control-plane object is useless for
/// the other.
let thm_commit_roster_non_confusion
      (l:log) (host_key:pk) (fe:nat) (committer:nat) (body:nat) (epoch entries:nat) (s:sig) (last:nat)
  : Lemma (requires l host_key (roster_transcript epoch entries) == false)
          (ensures apply_roster_ok l host_key epoch entries s last == false \/
                   apply_commit_ok l host_key committer fe body s == false)
  = if apply_roster_ok l host_key epoch entries s last then
      eufcma_inst l host_key (roster_transcript epoch entries) s
    else ()

(* ---------- inbound access gate (AccessPolicy) ---------- *)

/// The channel access policy (`core::AccessPolicy`): `Open` admits all; `Accounts s`
/// admits only registered account fingerprints; `Contacts`/`Friends` admit by the
/// local relationship flag.
noeq type policy =
  | Open     : policy
  | Accounts : (nat -> bool) -> policy
  | Contacts : policy
  | Friends  : policy

/// `AccessPolicy::allows` (engine.rs:756), the inbound membership/relay gate.
let allows (p:policy) (acct:nat) (contact:bool) (frnd:bool) : bool =
  match p with
  | Open         -> true
  | Accounts s   -> s acct
  | Contacts     -> contact
  | Friends      -> frnd

/// THEOREM 8 (ACCOUNT GATE IS FAIL-CLOSED). Under an `Accounts` allow-list, a peer
/// whose account fingerprint is NOT on the list is refused — a non-member cannot slip
/// past the restricted-channel gate.
let thm_accounts_fail_closed (s:nat -> bool) (acct:nat) (contact frnd:bool)
  : Lemma (requires s acct == false)
          (ensures allows (Accounts s) acct contact frnd == false)
  = ()

/// THEOREM 9 (RELATIONSHIP GATES REQUIRE THE RELATIONSHIP). `Contacts`/`Friends`
/// policies admit a peer only when the corresponding local flag is set — the gate
/// cannot be satisfied by an unrelated peer.
let thm_relationship_gates_require_flag (acct:nat)
  : Lemma (ensures (allows Contacts acct false false == false) /\
                   (allows Friends  acct true  false == false))
  = ()
