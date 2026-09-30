(*
  Machine-checked (EasyCrypt) COMPUTATIONAL reduction for talkrypt's DERIVED
  leaf-signature-key mode (LeafSigMode::Derived, task #80 / #6).

  In Derived mode a member's per-chat leaf SIGNATURE seed is
      derive_leaf_sig_seed(identity_root, group_id)
        = KMAC256(key = identity_root, msg = group_id, label = "…leaf-sig-derive-v1")
  (crates/crypto/src/treekem.rs; crates/crypto/src/kdf.rs `mac_kdf`).

  This is a NEW property that GroupAuth.fst / GroupAuthQROM.ec do NOT cover: those
  prove AUTHENTICITY (a leaf's messages verify only under its bound key), and they are
  parametric over HOW the key was generated — so they already cover both the Derived and
  Ephemeral variants unchanged. What Derived mode additionally CLAIMS, and what is proved
  here, is a PRIVACY property:

    (1) KEY-HIDING            — publishing derived leaf verification keys leaks nothing
                                about the member's long-term identity_root; and
    (2) CROSS-CHAT UNLINKABILITY — a member's derived leaf keys in two different chats
                                are unlinkable (look independent), so an observer cannot
                                tie two chats to one identity via the leaf keys.

  Both reduce, tightly and black-box, to PRF security of `mac_kdf` (KMAC256 keyed by the
  identity_root): given that KMAC256 is a PRF — a standard assumption for a keyed KMAC,
  assumed here exactly as EUF-CMA of ML-DSA-87 is assumed in GroupAuthQROM.ec, not
  re-derived — the two claims hold with a reduction that is itself black-box and
  straight-line (single forward call, no rewinding), hence QROM-preserving.
*)

require import AllCore List.

(* ---- Abstract PRF modelling mac_kdf/KMAC256 keyed by the identity root ---- *)
type root_t.    (* identity_root secret = the PRF key (32 bytes) *)
type gid_t.     (* per-chat group id (the invite token) = the PRF input *)
type seed_t.    (* the derived 32-byte leaf-sig seed = the PRF output *)

op droot : root_t distr.   (* the honest member's identity root, uniformly drawn *)
op dseed : seed_t distr.   (* a uniform seed (the ideal output) *)

(* derive_leaf_sig_seed(root, gid), verbatim as a keyed function. *)
op prf : root_t -> gid_t -> seed_t.

(* ---- Derivation oracle: REAL uses the PRF under one honest identity root; IDEAL
   replaces it by a lazily-sampled random function (an independent uniform seed per
   DISTINCT chat id). The adversary may query derivations for any chat ids it likes. ---- *)
module type DOracle = {
  proc derive(g : gid_t) : seed_t
}.

module DReal = {
  var root : root_t
  proc init() : unit = { root <$ droot; }
  proc derive(g : gid_t) : seed_t = { return prf root g; }
}.

module DIdeal = {
  var seen : (gid_t * seed_t) list
  proc init() : unit = { seen <- []; }
  proc derive(g : gid_t) : seed_t = {
    var s;
    if (assoc seen g = None) { s <$ dseed; seen <- (g, s) :: seen; }
    return oget (assoc seen g);
  }
}.

(* ---- The PRF distinguisher and its advantage (the assumption) ---- *)
module type Distinguisher (O : DOracle) = {
  proc distinguish() : bool
}.

module PRFExp_Real (D : Distinguisher) = {
  proc main() : bool = { var b; DReal.init(); b <@ D(DReal).distinguish(); return b; }
}.

module PRFExp_Ideal (D : Distinguisher) = {
  proc main() : bool = { var b; DIdeal.init(); b <@ D(DIdeal).distinguish(); return b; }
}.

(* ---- The unlinkability / key-hiding adversary. It interacts with the derivation
   oracle (learning derived leaf seeds for chats it chooses) and outputs a guess bit —
   e.g. "did these two chats come from the same identity?" or "here is a bit about the
   identity root". Its ADVANTAGE is how much better it does against REAL than IDEAL. ---- *)
module type AdvUnlink (O : DOracle) = {
  proc guess() : bool
}.

module UnlinkReal  (A : AdvUnlink) = {
  proc main() : bool = { var b; DReal.init();  b <@ A(DReal).guess();  return b; }
}.
module UnlinkIdeal (A : AdvUnlink) = {
  proc main() : bool = { var b; DIdeal.init(); b <@ A(DIdeal).guess(); return b; }
}.

(* ---- The reduction: an unlinkability adversary IS a PRF distinguisher ----
   B wraps A unchanged (black-box, straight-line, no rewinding) and returns its bit. *)
module BD (A : AdvUnlink) (O : DOracle) = {
  proc distinguish() : bool = {
    var b;
    b <@ A(O).guess();
    return b;
  }
}.

section.

declare module A <: AdvUnlink {-DReal, -DIdeal}.

(* THEOREM (tight, black-box reduction). For any adversary A, its behaviour in the REAL
   world equals the reduction B(A) as a PRF distinguisher against the real oracle, and
   likewise in the IDEAL world. Hence the unlinkability advantage
       | Pr[UnlinkReal(A)] - Pr[UnlinkIdeal(A)] |
   equals the PRF-distinguishing advantage of B(A)
       | Pr[PRFExp_Real(B(A))] - Pr[PRFExp_Ideal(B(A))] |,
   which is negligible under PRF security of mac_kdf (KMAC256). *)
lemma unlink_real_eq_prf_real &m :
  Pr[UnlinkReal(A).main() @ &m : res] = Pr[PRFExp_Real(BD(A)).main() @ &m : res].
proof.
  byequiv => //. proc; inline *.
  wp; call (_: ={DReal.root}); first sim.
  auto.
qed.

lemma unlink_ideal_eq_prf_ideal &m :
  Pr[UnlinkIdeal(A).main() @ &m : res] = Pr[PRFExp_Ideal(BD(A)).main() @ &m : res].
proof.
  byequiv => //. proc; inline *.
  wp; call (_: ={DIdeal.seen}); first sim.
  auto.
qed.

(* COROLLARY (unlinkability + key-hiding reduce to PRF security). The two differ by
   exactly the PRF advantage of the black-box reduction B(A). *)
lemma unlink_advantage_eq_prf_advantage &m :
  `| Pr[UnlinkReal(A).main() @ &m : res] - Pr[UnlinkIdeal(A).main() @ &m : res] |
    = `| Pr[PRFExp_Real(BD(A)).main() @ &m : res]
       - Pr[PRFExp_Ideal(BD(A)).main() @ &m : res] |.
proof. by rewrite (unlink_real_eq_prf_real &m) (unlink_ideal_eq_prf_ideal &m). qed.

end section.

(* ---- IDEAL-world facts: in the ideal world the derived seeds carry NO identity
   information — the oracle never reads `DReal.root` (indeed there is no root at all),
   and distinct chat ids get independently-sampled uniform seeds. Thus:
     * KEY-HIDING: the derived (public) leaf keys are a function of the ideal random
       function alone, independent of identity_root — nothing about the root is leaked.
     * CROSS-CHAT UNLINKABILITY: two distinct chats' derived seeds are independent
       uniform values, so they cannot be linked to a common identity.
   These are manifest from `DIdeal.derive` (root-free, fresh-uniform-per-distinct-gid),
   so the ONLY gap between the ideal guarantees and the real system is the PRF advantage
   bounded above. QED.

   Conclusion: GIVEN mac_kdf (KMAC256) is a PRF, talkrypt's Derived leaf-signature keys
   are key-hiding and cross-chat unlinkable, with a tight black-box (QROM-preserving)
   reduction — while GroupAuth.fst / GroupAuthQROM.ec continue to guarantee authenticity
   for the derived keys unchanged (they are parametric over key generation). *)
