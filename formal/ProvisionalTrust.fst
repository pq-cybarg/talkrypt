module ProvisionalTrust

/// Machine-checked (F*) model of invariant I3 (plan 0005): a PROVISIONAL member — one not
/// yet seated in the host-signed roster — accrues NO trust / vouch / sybil weight. Vouches
/// and trust resolve a target through the roster (leaf -> fingerprint, SECURITY-AUDIT F-17),
/// so an identity absent from it is weightless until the committer CONFIRMS it (adds its
/// roster leaf). This upholds the sub-spec-C vouching ethics (trust != access, additive-only)
/// against the presumptive/relay-join paths: an unconfirmed joiner cannot be vouched into
/// trust, nor can it manufacture sybil weight, before the committer admits it.
///
/// Models engine `handle_vouch` / the roster attribution gate: a vouch naming a target is
/// counted only when that target is a confirmed roster member.

type fp = nat          // a device fingerprint

/// The host-signed roster as a membership predicate: `r x` iff fingerprint `x` is seated
/// (a confirmed member). The real roster is a leaf -> fp map; "confirmed" == fp is a value.
type roster = fp -> bool

let confirmed (r:roster) (x:fp) : bool = r x

/// A vouch for `target` COUNTS toward trust only if the target is a confirmed member
/// (`handle_vouch` resolves the target's roster leaf; a provisional target has none, so the
/// vouch is rejected/deferred).
let vouch_counts (r:roster) (target:fp) : bool = confirmed r target

/// Trust weight accumulated for `target` from a list of vouchers, counting ONLY vouches that
/// count. (Weighting/coloration is richer in the real sub-spec C; here each counted voucher
/// contributes 1 — enough to state the provisional-is-weightless property.)
let rec trust_weight (r:roster) (target:fp) (vouchers:list fp) : nat =
  match vouchers with
  | []        -> 0
  | _ :: rest ->
    (if vouch_counts r target then 1 else 0) + trust_weight r target rest

/// THEOREM 1 (PROVISIONAL MEMBER HAS ZERO TRUST — I3). If `target` is NOT confirmed (absent
/// from the host-signed roster), its accumulated trust weight is 0 no matter how many
/// vouchers name it — an unconfirmed identity cannot accrue trust or sybil weight.
let rec thm_provisional_zero_trust (r:roster) (target:fp) (vouchers:list fp)
  : Lemma (requires ~(confirmed r target))
          (ensures trust_weight r target vouchers == 0)
          (decreases vouchers)
  = match vouchers with
    | []        -> ()
    | _ :: rest -> thm_provisional_zero_trust r target rest

/// THEOREM 2 (NONZERO TRUST IMPLIES CONFIRMED — contrapositive). Any positive trust weight
/// implies the target IS a confirmed roster member. So every unit of trust/sybil weight is
/// backed by a committer-confirmed seat; provisional identities contribute none.
let thm_trust_implies_confirmed (r:roster) (target:fp) (vouchers:list fp)
  : Lemma (requires trust_weight r target vouchers > 0)
          (ensures confirmed r target)
  = if confirmed r target then ()
    else thm_provisional_zero_trust r target vouchers

/// Confirmation is the ONLY way to flip a target from provisional to vouchable: it is a
/// host-signed roster addition (F-17). Model it as updating the membership predicate.
let confirm (r:roster) (x:fp) : roster = fun y -> y = x || r y

/// THEOREM 3 (VOUCHABILITY REQUIRES CONFIRMATION). A target becomes vouch-counting exactly
/// when it is confirmed; before `confirm` it counts for nothing, after it does — so trust
/// strictly follows committer confirmation, never precedes it.
let thm_vouchable_iff_confirmed (r:roster) (x:fp)
  : Lemma (ensures vouch_counts (confirm r x) x == true /\
                   (~(confirmed r x) ==> vouch_counts r x == false))
  = ()
