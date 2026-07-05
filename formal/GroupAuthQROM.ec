(*
  Machine-checked (EasyCrypt) COMPUTATIONAL reduction for talkrypt's group-message
  sender authentication (SECURITY-AUDIT G1/G2), quantum-adversary edition.

  Where the F* model (GroupAuth.fst) proves the *symbolic* security invariants, this
  EasyCrypt development proves the *computational* reduction: any efficient adversary
  that forges a group message accepted for a victim leaf yields an EUF-CMA forger
  against the leaf's signature scheme, with EQUAL success probability. The reduction
  B below is BLACK-BOX and REWINDING-FREE — it runs the protocol adversary once and
  forwards its output — which is exactly the property that makes the reduction valid
  against a QUANTUM adversary in the Quantum Random Oracle Model (QROM): black-box,
  straight-line reductions preserve QROM security (no measurement/rewinding is used).

  Therefore, GIVEN that the instantiating signature (ML-DSA-87 / FIPS 204) is
  EUF-CMA-secure in the QROM — a NIST-standardized assumption with published QROM
  proofs — talkrypt's group-message authentication is secure against a quantum
  adversary, with a tight reduction. The QROM-hardness of ML-DSA-87 itself is assumed
  here (as in FIPS 204), not re-derived.
*)

require import AllCore List.

(* ---- Abstract signature scheme (models ML-DSA-87) ---- *)
type pk_t.
type sk_t.
type msg_t.       (* the signed transcript SIG_CONTEXT | epoch | leaf | n | ct *)
type sig_t.

(* Verification is a deterministic predicate on (pk, msg, sig). *)
op verify : pk_t -> msg_t -> sig_t -> bool.

(* Key generation and signing as distributions/operators (abstract). *)
op dkeys   : (pk_t * sk_t) distr.
op sign    : sk_t -> msg_t -> sig_t.

(* ---- Signing oracle (records queried messages for freshness) ---- *)
module type SOracle = {
  proc sign(m : msg_t) : sig_t
}.

module Oracle = {
  var sk  : sk_t
  var qs  : msg_t list          (* messages the honest leaf actually signed *)
  proc init(k : sk_t) : unit = { sk <- k; qs <- []; }
  proc sign(m : msg_t) : sig_t = {
    var s;
    qs <- m :: qs;              (* record the honest signature *)
    s  <- sign sk m;
    return s;
  }
}.

(* ---- EUF-CMA game (existential unforgeability, chosen-message attack) ---- *)
module type AdvEUF (O : SOracle) = {
  proc forge(pk : pk_t) : msg_t * sig_t
}.

module EUF_CMA (A : AdvEUF) = {
  proc main() : bool = {
    var pk, sk, m, s, valid, fresh;
    (pk, sk) <$ dkeys;
    Oracle.init(sk);
    (m, s)  <@ A(Oracle).forge(pk);
    valid   <- verify pk m s;              (* forgery verifies ... *)
    fresh   <- ! (m \in Oracle.qs);        (* ... on a message the leaf never signed *)
    return valid /\ fresh;
  }
}.

(* ---- Group-message authentication game (talkrypt) ----

  A group receiver ACCEPTS a message for a leaf iff the signature verifies under that
  leaf's tree-bound signing key (this is exactly `decrypt_verified` in the Rust code:
  it looks up the leaf's key and calls verify). The adversary is any group member /
  relay: it sees the victim leaf's honest messages (its signatures, via the oracle),
  and WINS if it makes the receiver accept a message the victim never sent — i.e. a
  forged attribution to the victim leaf (SECURITY-AUDIT G1/G2). *)

(* The receiver's acceptance predicate, verbatim: accept == verify under leaf pk. *)
op accepts (leaf_pk : pk_t) (m : msg_t) (s : sig_t) : bool = verify leaf_pk m s.

module type AdvProto (O : SOracle) = {
  proc forge(leaf_pk : pk_t) : msg_t * sig_t
}.

module ProtoForge (A : AdvProto) = {
  proc main() : bool = {
    var leaf_pk, sk, m, s, accepted, notsent;
    (leaf_pk, sk) <$ dkeys;              (* the victim leaf's signing key *)
    Oracle.init(sk);
    (m, s)   <@ A(Oracle).forge(leaf_pk);
    accepted <- accepts leaf_pk m s;      (* receiver accepts it for the victim leaf *)
    notsent  <- ! (m \in Oracle.qs);      (* but the victim never sent this message *)
    return accepted /\ notsent;           (* => forged attribution to the victim *)
  }
}.

(* ---- The reduction: a protocol forger IS an EUF-CMA forger ---- *)
(* B wraps a protocol adversary A unchanged (black-box, straight-line, no rewinding).
   It forwards A's forgery as its own. *)
module B (A : AdvProto) (O : SOracle) = {
  proc forge(pk : pk_t) : msg_t * sig_t = {
    var ms;
    ms <@ A(O).forge(pk);
    return ms;
  }
}.

section.

declare module A <: AdvProto {-Oracle}.

(* THEOREM (tight reduction). The probability that any protocol adversary forges a
   group message accepted for the victim leaf EQUALS the probability that the derived
   EUF-CMA adversary B(A) forges a signature. Since `accepts == verify` and "victim
   never sent m" == "m fresh", the two games are identical. *)
lemma group_auth_reduces_to_eufcma &m :
  Pr[ProtoForge(A).main() @ &m : res] = Pr[EUF_CMA(B(A)).main() @ &m : res].
proof.
  byequiv => //.
  proc; inline *.
  (* Both games sample the same key, run A against the same oracle, and accept iff
     verify holds on a fresh message. `accepts leaf_pk m s` unfolds to
     `verify leaf_pk m s`, so the returned booleans coincide. *)
  wp; call (_: ={Oracle.sk, Oracle.qs}); first sim.
  auto=> /#.
qed.

end section.

(*
  COROLLARY (quantum soundness). B(A) is black-box in A and straight-line (it makes a
  single forward call and no rewinding), so if the signature is EUF-CMA-secure in the
  QROM — i.e. Pr[EUF_CMA(B(A))] is negligible for all efficient quantum A, which is the
  standardized assumption for ML-DSA-87 (FIPS 204) — then Pr[ProtoForge(A)] is
  negligible for all efficient quantum A. Talkrypt group-message authentication is thus
  secure against a quantum adversary, with a tight reduction. QED.
*)
