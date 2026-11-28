module RatchetFS

/// Machine-checked (F*) model of the PAIRWISE Double Ratchet's two secrecy
/// guarantees — FORWARD SECRECY and POST-COMPROMISE SECURITY (SECURITY-AUDIT R-2
/// target; task #115), for `crypto::ratchet` / `crypto::kdf`.
///
/// The KDF steps are the Rust `kdf_ck` / `kdf_rk` (HKDF/KMAC256 over SHA-384):
///   * symmetric chain step  `kdf_ck(ck)  = (next_ck ck, mk_of ck)`
///   * root ratchet step      `kdf_rk(root, ikm) = (rk_root root ikm, rk_chain root ikm)`
/// They are modeled as IDEALIZED ONE-WAY PRFs: an adversary can only compute them
/// in the FORWARD direction (there is no inverse). We make that precise with an
/// inductive DERIVABILITY relation `der ks k` — the set of keys an adversary who
/// knows the base set `ks` can compute — whose ONLY generators are the forward KDF
/// steps. The absence of any "invert" constructor IS the one-wayness assumption
/// (the computational analogue is PRF-security of HKDF, a standard assumption).
///
/// FORWARD SECRECY: a message key from an earlier chain position is NOT derivable
/// from any key the adversary learns later (the chain only moves forward — proven
/// via a generation-index that no forward step can decrease).
/// POST-COMPROMISE SECURITY: after a root step that mixes a fresh KEM shared secret
/// the adversary does not hold, the new root is NOT derivable from the compromised
/// old root (proven by inversion: the new root can only come from the root step,
/// which required deriving that secret).
///
/// Everything is straight-line from the idealization, so (as in `GroupAuth.fst`)
/// the results are QROM-preserving — they hold against a quantum adversary to the
/// same degree HKDF/SHA-384 is a quantum-secure PRF.

(* ---------- key material + idealized one-way KDF steps ---------- *)

type key = nat   // abstract symmetric key material (a 32-byte chain/root/mk seed)

/// `kdf_ck` outputs: the next chain key, and the message-key seed at this position.
assume val next_ck : key -> key
assume val mk_of   : key -> key
/// `kdf_rk` outputs: the new root, and the chain key seeded by the root step. Both
/// are functions of (root, ikm) where `ikm` is the fresh DH+KEM hybrid secret.
assume val rk_root  : key -> key -> key
assume val rk_chain : key -> key -> key

/// Generation index = position along the ratchet. Each forward step keeps or
/// advances it; NONE decreases it (this is what "the ratchet only moves forward"
/// means at the key-schedule level). `mk_of` is the leaf at the current position
/// (same gen); `next_ck` advances the symmetric chain; the root step opens a new
/// epoch (strictly later), so both its outputs sit at a strictly greater gen.
assume val gen : key -> nat
assume GenNext    : (forall (k:key).            {:pattern (gen (next_ck k))}    gen (next_ck k)    == gen k + 1)
assume GenMk      : (forall (k:key).            {:pattern (gen (mk_of k))}      gen (mk_of k)      == gen k)
assume GenRkRoot  : (forall (r ikm:key).        {:pattern (gen (rk_root r ikm))} gen (rk_root r ikm) == gen r + 1)
assume GenRkChain : (forall (r ikm:key).        {:pattern (gen (rk_chain r ikm))} gen (rk_chain r ikm) == gen r + 1)

/// Range distinctness + injectivity of the root step's output, used for the PCS
/// inversion (a fresh new-root can ONLY have come from the root step). Guaranteed
/// in the implementation by HKDF domain separation (distinct `info` labels /
/// output slices) and collision-resistance.
assume DistinctRootNext  : (forall (r ikm k:key).       {:pattern (rk_root r ikm); (next_ck k)}
                             ~(rk_root r ikm == next_ck k))
assume DistinctRootMk    : (forall (r ikm k:key).       {:pattern (rk_root r ikm); (mk_of k)}
                             ~(rk_root r ikm == mk_of k))
assume DistinctRootChain : (forall (r ikm r' ikm':key). {:pattern (rk_root r ikm); (rk_chain r' ikm')}
                             ~(rk_root r ikm == rk_chain r' ikm'))
assume DistinctChainNext : (forall (r ikm k:key).       {:pattern (rk_chain r ikm); (next_ck k)}
                             ~(rk_chain r ikm == next_ck k))
assume DistinctChainMk   : (forall (r ikm k:key).       {:pattern (rk_chain r ikm); (mk_of k)}
                             ~(rk_chain r ikm == mk_of k))
assume InjRoot : (forall (r ikm r' ikm':key).           {:pattern (rk_root r ikm); (rk_root r' ikm')}
                   rk_root r ikm == rk_root r' ikm' ==> (r == r' /\ ikm == ikm'))
assume InjChain : (forall (r ikm r' ikm':key).          {:pattern (rk_chain r ikm); (rk_chain r' ikm')}
                   rk_chain r ikm == rk_chain r' ikm' ==> (r == r' /\ ikm == ikm'))

(* ---------- adversary derivability (forward closure; no inverse) ---------- *)

/// `der ks k` — a derivation that an adversary whose base knowledge is `ks`
/// (a predicate on keys) can compute `k`. The constructors are EXACTLY the forward
/// operations available: take a known base key, or apply a KDF step to already-
/// derived keys. There is deliberately NO constructor to invert a KDF step — that
/// omission is the one-wayness assumption. "Not derivable" is expressed as
/// "any derivation yields False".
noeq type der (ks: key -> prop) : key -> Type =
  | DBase : (k:key) -> ks k -> der ks k
  | DNext : (k:key) -> der ks k -> der ks (next_ck k)
  | DMk   : (k:key) -> der ks k -> der ks (mk_of k)
  | DRk1  : (r:key) -> (ikm:key) -> der ks r -> der ks ikm -> der ks (rk_root r ikm)
  | DRk2  : (r:key) -> (ikm:key) -> der ks r -> der ks ikm -> der ks (rk_chain r ikm)

(* ================= FORWARD SECRECY ================= *)

/// No forward step DECREASES the generation. Hence anything an adversary can derive
/// from a base set of keys all at generation >= nn is itself at generation >= nn.
let rec gen_lower (ks:key -> prop) (nn:nat) (k:key) (d:der ks k)
  : Lemma (requires (forall (b:key). ks b ==> gen b >= nn))
          (ensures gen k >= nn)
          (decreases d)
  = match d with
    | DBase k0 _        -> ()                       // ks k0 => gen k0 >= nn (base hypothesis)
    | DNext k0 d'       -> gen_lower ks nn k0 d'     // gen (next_ck k0) = gen k0 + 1
    | DMk k0 d'         -> gen_lower ks nn k0 d'     // gen (mk_of k0)   = gen k0
    | DRk1 r ikm dr _   -> gen_lower ks nn r dr      // gen (rk_root r ikm) = gen r + 1
    | DRk2 r ikm dr _   -> gen_lower ks nn r dr      // gen (rk_chain r ikm) = gen r + 1

/// THEOREM 1 (FORWARD SECRECY). Let the adversary learn ONLY keys at generation
/// >= nn (e.g. it compromises the session at ratchet step nn, obtaining the current
/// and all future keys). Then the MESSAGE KEY of any earlier position `c`
/// (gen c < nn) is NOT derivable: there is no derivation of `mk_of c`. Past
/// messages stay secret under a later compromise.
let thm_forward_secrecy (ks:key -> prop) (c:key) (nn:nat) (d:der ks (mk_of c))
  : Lemma (requires (forall (b:key). ks b ==> gen b >= nn) /\ gen c < nn)
          (ensures False)
  = gen_lower ks nn (mk_of c) d   // yields gen (mk_of c) = gen c >= nn, contra gen c < nn

/// THEOREM 2 (CHAIN-KEY FORWARD SECRECY). The same for the earlier CHAIN key
/// itself: a chain key at an earlier position is not recoverable from later keys,
/// so an attacker cannot wind the chain backward to re-derive old message keys.
let thm_chain_key_forward_secrecy (ks:key -> prop) (c:key) (nn:nat) (d:der ks c)
  : Lemma (requires (forall (b:key). ks b ==> gen b >= nn) /\ gen c < nn)
          (ensures False)
  = gen_lower ks nn c d

(* ================= POST-COMPROMISE SECURITY ================= *)

/// INVERSION: the only way to derive a value of the form `rk_root r0 ikm0` that the
/// adversary does not already hold as a base key is via the root step `DRk1` on
/// those exact arguments — which required deriving `ikm0`. Every other constructor
/// is ruled out by the range-distinctness axioms; `InjRoot` pins the arguments.
let rk_root_inversion (ks:key -> prop) (r0 ikm0:key) (d:der ks (rk_root r0 ikm0))
  : Ghost (der ks ikm0)
          (requires ~(ks (rk_root r0 ikm0)))
          (ensures fun _ -> True)
  = match d with
    | DBase k pf        -> pf; false_elim ()         // k = rk_root r0 ikm0 but ~(ks k): contradiction
    | DNext k _         -> false_elim ()             // rk_root .. = next_ck k: DistinctRootNext
    | DMk k _           -> false_elim ()             // rk_root .. = mk_of k:   DistinctRootMk
    | DRk2 r ikm _ _    -> false_elim ()             // rk_root .. = rk_chain ..: DistinctRootChain
    | DRk1 r ikm _ dikm -> dikm                      // InjRoot: r=r0, ikm=ikm0; return der ks ikm0

/// THEOREM 3 (POST-COMPROMISE SECURITY — the healing property). Suppose the
/// adversary compromised the old root (and anything else — captured in `ks`), but
/// the root step mixed a FRESH KEM shared secret `ikm` the adversary cannot derive
/// (`ikm_secret`: every derivation of `ikm` is absurd), and the fresh new root is
/// not already known to the adversary (`~(ks (rk_root old ikm))`). Then the NEW
/// ROOT is NOT derivable — the session heals, and messages after the ratchet step
/// are secret again despite the earlier compromise.
let thm_post_compromise_security
      (ks:key -> prop) (old ikm:key)
      (ikm_secret: (d:der ks ikm) -> Lemma (ensures False))
      (dnew: der ks (rk_root old ikm))
  : Lemma (requires ~(ks (rk_root old ikm)))
          (ensures False)
  = let dikm = rk_root_inversion ks old ikm dnew in   // a derivation of ikm would exist...
    ikm_secret dikm                                    // ...but ikm is secret: contradiction

/// THEOREM 4 (PCS FOR THE ROOT-STEP CHAIN KEY). The chain key produced by the same
/// healing root step is likewise not derivable without the fresh secret — so the
/// first post-ratchet sending chain (and its message keys) are secret too.
let rk_chain_inversion (ks:key -> prop) (r0 ikm0:key) (d:der ks (rk_chain r0 ikm0))
  : Ghost (der ks ikm0)
          (requires ~(ks (rk_chain r0 ikm0)))
          (ensures fun _ -> True)
  = match d with
    | DBase k pf        -> pf; false_elim ()
    | DNext k _         -> false_elim ()             // rk_chain .. = next_ck k
    | DMk k _           -> false_elim ()             // rk_chain .. = mk_of k
    | DRk1 r ikm _ _    -> false_elim ()             // rk_chain .. = rk_root ..: DistinctRootChain
    | DRk2 r ikm _ dikm -> dikm

let thm_pcs_chain_key_secret
      (ks:key -> prop) (old ikm:key)
      (ikm_secret: (d:der ks ikm) -> Lemma (ensures False))
      (dnew: der ks (rk_chain old ikm))
  : Lemma (requires ~(ks (rk_chain old ikm)))
          (ensures False)
  = let dikm = rk_chain_inversion ks old ikm dnew in
    ikm_secret dikm
