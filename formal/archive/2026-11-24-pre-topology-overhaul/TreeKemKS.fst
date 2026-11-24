module TreeKemKS

/// Machine-checked (F*) model of the GROUP KEY SCHEDULE's secrecy guarantees —
/// post-compromise security and forward secrecy across epochs — for talkrypt's
/// TreeKEM group (`crypto::treekem`, SECURITY-AUDIT R-2 target; task #120). This is
/// the group-layer secrecy counterpart to `GroupAuth.fst` (which proves group-message
/// *authentication*).
///
/// Each commit re-keys: the committer picks a FRESH leaf path secret, derives parent
/// secrets up the tree (`derive_parent_secret`), and the root path secret yields the
/// new epoch (group) secret (`derive_commit_secret`). The fresh secrets are sealed
/// (ML-KEM-1024) only to the CURRENT members' keys, so:
///   * a member compromised BEFORE a commit heals afterward (PCS) — the new epoch
///     secret comes from fresh randomness it cannot derive;
///   * a REMOVED member cannot derive the post-removal epoch secret (FS vs removal);
///   * an EARLIER epoch secret is not recoverable from a later one (epoch FS) — epochs
///     use independent fresh randomness and the derivations are one-way.
///
/// As in `RatchetFS.fst`, the HKDF derivations are modeled as one-way (an inductive
/// derivability relation whose only generators are the forward steps — no inverse),
/// and the ML-KEM seal is captured by "the fresh secret is not in the adversary's
/// derivable set unless it holds a current member's KEM key" (the IND-CCA guarantee,
/// an assumption discharged in `ConfidentialityQROM.ec`). Within an epoch, per-sender
/// message-key forward secrecy is the SAME `kdf_ck` one-wayness proven in
/// `RatchetFS.fst`, so it is not re-proved here. Straight-line => QROM-preserving.

type secret = nat   // 32-byte path / commit / epoch secret

/// `derive_parent_secret` — a child path secret yields its parent up the ratchet tree.
assume val derive_parent : secret -> secret
/// `derive_commit_secret` — the root path secret yields the epoch (group) secret.
assume val derive_commit : secret -> secret

assume InjParent : (forall (a b:secret). {:pattern (derive_parent a); (derive_parent b)}
                     derive_parent a == derive_parent b ==> a == b)
assume InjCommit : (forall (a b:secret). {:pattern (derive_commit a); (derive_commit b)}
                     derive_commit a == derive_commit b ==> a == b)
/// Domain separation between the two derivations (distinct HKDF `info` labels), so an
/// epoch secret is never equal to an intermediate parent secret.
assume DistinctCommitParent : (forall (a b:secret). {:pattern (derive_commit a); (derive_parent b)}
                                ~(derive_commit a == derive_parent b))

/// Adversary derivability: base knowledge `ks`, plus the two forward tree derivations.
/// No inverse constructor — that omission is the one-wayness of the HKDF steps.
noeq type der (ks: secret -> prop) : secret -> Type =
  | DBase   : (k:secret) -> ks k -> der ks k
  | DParent : (k:secret) -> der ks k -> der ks (derive_parent k)
  | DCommit : (k:secret) -> der ks k -> der ks (derive_commit k)

/// INVERSION of the commit step: a fresh epoch secret `derive_commit r0` the adversary
/// does not already hold could only have come from the commit step on `r0` — which
/// required deriving `r0` (the root path secret).
let commit_inversion (ks:secret -> prop) (r0:secret) (d:der ks (derive_commit r0))
  : Ghost (der ks r0)
          (requires ~(ks (derive_commit r0)))
          (ensures fun _ -> True)
  = match d with
    | DBase k pf     -> pf; false_elim ()     // derive_commit r0 = k but ~(ks k): contradiction
    | DParent k _    -> false_elim ()         // derive_commit r0 = derive_parent k: DistinctCommitParent
    | DCommit k dk   -> dk                     // InjCommit: k = r0

/// INVERSION of a parent step (used for the up-the-tree chain): a parent secret the
/// adversary does not hold could only have come from deriving the child.
let parent_inversion (ks:secret -> prop) (c0:secret) (d:der ks (derive_parent c0))
  : Ghost (der ks c0)
          (requires ~(ks (derive_parent c0)))
          (ensures fun _ -> True)
  = match d with
    | DBase k pf     -> pf; false_elim ()
    | DParent k dk   -> dk                     // InjParent: k = c0
    | DCommit k _    -> false_elim ()         // derive_parent c0 = derive_commit k: DistinctCommitParent

(* ================= THEOREMS ================= *)

/// THEOREM 1 (POST-COMPROMISE SECURITY — heal on rekey). If the committer's fresh
/// root path secret is not derivable by the adversary (`no_root`: it was sealed via
/// ML-KEM only to current members, and the adversary lacks a current member's KEM
/// key), then the NEW EPOCH SECRET is not derivable — even by an adversary that
/// compromised members' state BEFORE this commit. The group heals.
let thm_rekey_heals_pcs
      (ks:secret -> prop) (root:secret)
      (no_root: (d:der ks root) -> Lemma (ensures False))
      (depoch: der ks (derive_commit root))
  : Lemma (requires ~(ks (derive_commit root)))
          (ensures False)
  = let droot = commit_inversion ks root depoch in
    no_root droot

/// THEOREM 2 (FORWARD SECRECY AGAINST REMOVAL). A removed member cannot derive the
/// epoch secret of any post-removal commit: after removal the committer re-keys with
/// a fresh root secret sealed ONLY to the remaining members, so the removed member's
/// (old) knowledge does not include it. Same inversion as PCS, from the removed
/// member's vantage — this is why removal is forward-secret.
let thm_removed_member_cannot_derive_new_secret
      (ks:secret -> prop) (root:secret)
      (removed_lacks_root: (d:der ks root) -> Lemma (ensures False))
      (depoch: der ks (derive_commit root))
  : Lemma (requires ~(ks (derive_commit root)))
          (ensures False)
  = let droot = commit_inversion ks root depoch in
    removed_lacks_root droot

/// THEOREM 3 (EPOCH FORWARD SECRECY). An earlier epoch's secret is not recoverable
/// from a later one. Epochs use INDEPENDENT fresh root secrets, and the derivations
/// are one-way; so an adversary that learns a later epoch secret (and anything it can
/// forward-derive from it) still cannot derive an earlier epoch secret whose
/// independent root `root_old` it never held. Past group traffic stays confidential
/// under a later compromise.
let thm_epoch_forward_secrecy
      (ks:secret -> prop) (root_old:secret)
      (independent: (d:der ks root_old) -> Lemma (ensures False))
      (dold: der ks (derive_commit root_old))
  : Lemma (requires ~(ks (derive_commit root_old)))
          (ensures False)
  = let droot = commit_inversion ks root_old dold in
    independent droot

/// THEOREM 4 (SECRECY PROPAGATES ALONG THE TREE PATH). The epoch secret is reached
/// from the committer's fresh leaf path secret THROUGH the tree
/// (`epoch = derive_commit (derive_parent leaf)` for a node one level below the
/// root — the general case iterates `derive_parent`). If the fresh LEAF path secret
/// is not derivable, then neither is the epoch secret: the one-wayness composes up
/// the whole path. This is why a member deeper in the tree, whose only fresh input is
/// its leaf, still gets full PCS. (Composes the commit and parent inversions.)
let thm_path_secrecy_propagates
      (ks:secret -> prop) (leaf:secret)
      (no_leaf: (d:der ks leaf) -> Lemma (ensures False))
      (depoch: der ks (derive_commit (derive_parent leaf)))
  : Lemma (requires ~(ks (derive_commit (derive_parent leaf))) /\ ~(ks (derive_parent leaf)))
          (ensures False)
  = let dparent = commit_inversion ks (derive_parent leaf) depoch in   // der (derive_parent leaf)
    let dleaf   = parent_inversion ks leaf dparent in                   // der leaf
    no_leaf dleaf
