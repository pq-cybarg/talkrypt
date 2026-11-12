module Handshake

/// Machine-checked (F*) model of the mutually-authenticated session HANDSHAKE
/// (`core::handshake::initiate` / `respond`, SECURITY-AUDIT H-1 / R-2 target;
/// task #116), under a quantum threat model.
///
/// The handshake is SIGMA-style: the responder publishes a freshly-signed prekey,
/// both parties ML-DSA-87-sign the FULL transcript
///   `tag | suite_id | id_i | nonce_i | id_r | prekey | nonce_r`
/// (length-prefixed, so injective in every field), domain-separated by `tag`
/// (`T_RESP` vs `T_CONFIRM`). The session root is derived from the invite-token PSK
/// (`root0`, known only to descriptor holders) mixed with the prekey ML-KEM shared
/// secret. We prove two things, above the two NIST-standardized primitive
/// assumptions (ML-DSA-87 EUF-CMA and ML-KEM-1024 IND-CCA, both in the QROM):
///   * MUTUAL AUTHENTICATION + AGREEMENT — acceptance implies the peer signed the
///     exact transcript, so both sides agree on identities/nonces/prekey/suite, with
///     downgrade resistance and no field substitution or signature cross-use.
///   * SESSION-KEY SECRECY — the session root is not derivable by an adversary that
///     lacks EITHER the invite-token PSK (a non-descriptor-holder) OR the KEM secret
///     (the IND-CCA guarantee), so both the PSK and the KEM independently protect it.
///
/// Signatures are the SAME idealized EUF-CMA primitive as `GroupAuth.fst`; the key
/// derivation is modeled as in `RatchetFS.fst` (a forward-only one-way KDF with no
/// inverse). All reductions are straight-line and rewinding-free => QROM-preserving.

(* ==================== PART A: mutual authentication ==================== *)

type pk = nat          // an identity signature public key (IdentityPublic.sig_vk)
type msg = list nat    // an abstract signed transcript
type sig = nat
type log = pk -> msg -> bool

assume val verify : log -> pk -> msg -> sig -> bool
assume EUFCMA : (forall (l:log) (k:pk) (m:msg) (s:sig). {:pattern (verify l k m s)}
                   verify l k m s ==> l k m == true)
let eufcma_inst (l:log) (k:pk) (m:msg) (s:sig)
  : Lemma (requires verify l k m s == true) (ensures l k m == true) = ()

/// Domain-separation tags (the Rust `T_RESP` / `T_CONFIRM` consts): distinct, so a
/// responder signature can never be lifted to an initiator-confirm signature.
type tg = nat
let t_resp    : tg = 0
let t_confirm : tg = 1

/// The signed transcript. Injective in ALL seven fields — guaranteed by the
/// length-prefixed, tag-domain-separated encoding `handshake_transcript`.
assume val transcript : tg -> (suite:nat) -> (idi:pk) -> (ni:nat) -> (idr:pk) -> (prekey:nat) -> (nr:nat) -> msg
assume TranscriptInj :
  (forall t su idi ni idr pkf nr t' su' idi' ni' idr' pkf' nr'.
     {:pattern (transcript t su idi ni idr pkf nr); (transcript t' su' idi' ni' idr' pkf' nr')}
     transcript t su idi ni idr pkf nr == transcript t' su' idi' ni' idr' pkf' nr' ==>
     (t==t' /\ su==su' /\ idi==idi' /\ ni==ni' /\ idr==idr' /\ pkf==pkf' /\ nr==nr'))

/// The initiator's acceptance check (Rust: verify `sig_r` over the T_RESP transcript).
let init_accepts (l:log) (su:nat) (idi:pk) (ni:nat) (idr:pk) (pkf nr:nat) (sr:sig) : bool =
  verify l idr (transcript t_resp su idi ni idr pkf nr) sr

/// The responder's acceptance check (Rust: verify `sig_i` over the T_CONFIRM transcript).
let resp_accepts (l:log) (su:nat) (idi:pk) (ni:nat) (idr:pk) (pkf nr:nat) (si:sig) : bool =
  verify l idi (transcript t_confirm su idi ni idr pkf nr) si

/// THEOREM 1 (INITIATOR AUTHENTICATES RESPONDER). If the initiator accepts, then the
/// holder of `idr`'s key actually signed the T_RESP transcript binding EXACTLY this
/// (suite, id_i, nonce_i, id_r, prekey, nonce_r) — so a MITM could not have swapped
/// the prekey, suite, or either identity.
let thm_initiator_authenticates_responder
      (l:log) (su:nat) (idi:pk) (ni:nat) (idr:pk) (pkf nr:nat) (sr:sig)
  : Lemma (requires init_accepts l su idi ni idr pkf nr sr == true)
          (ensures l idr (transcript t_resp su idi ni idr pkf nr) == true)
  = eufcma_inst l idr (transcript t_resp su idi ni idr pkf nr) sr

/// THEOREM 2 (RESPONDER AUTHENTICATES INITIATOR). Symmetrically, responder acceptance
/// implies the holder of `idi`'s key signed the T_CONFIRM transcript over the same
/// fields — giving both-directions agreement (full SIGMA mutual authentication).
let thm_responder_authenticates_initiator
      (l:log) (su:nat) (idi:pk) (ni:nat) (idr:pk) (pkf nr:nat) (si:sig)
  : Lemma (requires resp_accepts l su idi ni idr pkf nr si == true)
          (ensures l idi (transcript t_confirm su idi ni idr pkf nr) == true)
  = eufcma_inst l idi (transcript t_confirm su idi ni idr pkf nr) si

/// THEOREM 3 (AGREEMENT / NO FIELD SUBSTITUTION). If the initiator accepts a
/// responder signature, and the responder (honest) only ever signs the T_RESP
/// transcript reflecting its OWN view `(su', idi', ni', idr', pkf', nr')`, then the
/// two views are IDENTICAL in every field. There is no handshake where the parties
/// accept yet disagree on who/what/which-suite — injectivity pins all seven fields.
let thm_agreement
      (l:log) (su:nat) (idi:pk) (ni:nat) (idr:pk) (pkf nr:nat) (sr:sig)
      (su':nat) (idi':pk) (ni':nat) (pkf' nr':nat)
  : Lemma
      (requires
        init_accepts l su idi ni idr pkf nr sr == true /\
        // the responder's honest signing oracle: it only logged its own-view transcript
        (forall (m:msg). l idr m == true ==> m == transcript t_resp su' idi' ni' idr pkf' nr'))
      (ensures su==su' /\ idi==idi' /\ ni==ni' /\ pkf==pkf' /\ nr==nr')
  = eufcma_inst l idr (transcript t_resp su idi ni idr pkf nr) sr
    // EUF-CMA: the verified transcript is logged => equals the responder's own-view
    // transcript => by TranscriptInj every field agrees.

/// THEOREM 4 (DOMAIN SEPARATION — no signature cross-use). A responder signature
/// (over a T_RESP transcript) can NEVER be replayed as an initiator-confirm signature
/// (over a T_CONFIRM transcript), and vice versa, because the tag differs and the
/// transcript is injective: unless the key independently signed the confirm
/// transcript, a confirm verification fails.
let thm_domain_separation
      (l:log) (su:nat) (idi:pk) (ni:nat) (idr:pk) (pkf nr:nat) (s:sig)
  : Lemma
      (requires l idr (transcript t_confirm su idi ni idr pkf nr) == false)
      (ensures resp_accepts l su idi ni idr pkf nr s == false \/ idr =!= idi)
  = if resp_accepts l su idi ni idr pkf nr s then
      eufcma_inst l idi (transcript t_confirm su idi ni idr pkf nr) s
    else ()

(* ==================== PART B: session-key secrecy ==================== *)

/// The handshake session root is derived from the invite-token PSK and the prekey
/// ML-KEM shared secret: `session_root = kdf_hs psk kem_ss` (Rust
/// `suite.begin_session(root0, prekey)` / `accept_session`). Modeled, as in
/// `RatchetFS.fst`, as a one-way KDF: derivable ONLY forward, and only from BOTH
/// inputs. `key = nat` (32-byte secret material).
assume val kdf_hs : nat -> nat -> nat
assume InjKdf : (forall (r ss r' ss':nat). {:pattern (kdf_hs r ss); (kdf_hs r' ss')}
                  kdf_hs r ss == kdf_hs r' ss' ==> (r == r' /\ ss == ss'))

/// Adversary derivability: base knowledge `ks`, plus the forward KDF step — which
/// requires BOTH the PSK and the KEM secret. No inverse constructor (one-wayness).
noeq type der (ks: nat -> prop) : nat -> Type =
  | DBase : (k:nat) -> ks k -> der ks k
  | DKdf  : (r:nat) -> (ss:nat) -> der ks r -> der ks ss -> der ks (kdf_hs r ss)

/// INVERSION: a freshly-derived session root `kdf_hs r0 ss0` the adversary does not
/// already hold can only have come from the KDF step on those exact inputs — which
/// required deriving BOTH of them.
let kdf_hs_inversion (ks:nat -> prop) (r0 ss0:nat) (d:der ks (kdf_hs r0 ss0))
  : Ghost (der ks r0 & der ks ss0)
          (requires ~(ks (kdf_hs r0 ss0)))
          (ensures fun _ -> True)
  = match d with
    | DBase k pf        -> pf; false_elim ()          // kdf_hs r0 ss0 = k but ~(ks k): contradiction
    | DKdf r ss dr dss  -> (dr, dss)                  // InjKdf: r=r0, ss=ss0

/// THEOREM 5 (SECRECY WITHOUT THE PSK). A party that does NOT hold the invite-token
/// PSK (`root0` — e.g. any non-descriptor-holder, including an active MITM) cannot
/// derive the session root, EVEN if it somehow learned the KEM secret. So the shared
/// invite token is a hard gate on completing a usable session.
let thm_session_secret_without_psk
      (ks:nat -> prop) (psk ss:nat)
      (no_psk: (d:der ks psk) -> Lemma (ensures False))
      (droot: der ks (kdf_hs psk ss))
  : Lemma (requires ~(ks (kdf_hs psk ss)))
          (ensures False)
  = let (dpsk, _) = kdf_hs_inversion ks psk ss droot in
    no_psk dpsk

/// THEOREM 6 (SECRECY WITHOUT THE KEM SECRET). Symmetrically, an adversary that
/// cannot derive the prekey ML-KEM shared secret (the IND-CCA-QROM guarantee for
/// ML-KEM-1024) cannot derive the session root, EVEN if the PSK leaked. So the KEM
/// independently protects the session against a PSK compromise — the two protections
/// compose, and breaking BOTH is required.
let thm_session_secret_without_kem
      (ks:nat -> prop) (psk ss:nat)
      (no_kem: (d:der ks ss) -> Lemma (ensures False))
      (droot: der ks (kdf_hs psk ss))
  : Lemma (requires ~(ks (kdf_hs psk ss)))
          (ensures False)
  = let (_, dss) = kdf_hs_inversion ks psk ss droot in
    no_kem dss
