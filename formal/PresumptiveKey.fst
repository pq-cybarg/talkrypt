module PresumptiveKey

open FStar.List.Tot

/// Machine-checked (F*) model of the PRESUMPTIVE QUEUE-ONLY / NO-PREMATURE-KEY invariant
/// (plan 0005, I2; increment 3a). A member that is still JOINING holds no group key: it
/// BUFFERS its outbound messages locally — never encrypting them and never putting group
/// content on the wire — and the key is obtained ONLY from a valid committer Welcome, after
/// which the buffer is flushed in composition order. So a later-rejected joiner (whose
/// Welcome is not valid for it) never holds the group key, and nothing it composed was
/// encrypted or sent early.
///
/// This models the engine seam: `send_marked` (buffers into `pending_outbound` while the
/// group is None), `handle_welcome` (keys ONLY on a valid `join_with_welcome`, restoring the
/// pending leaf key otherwise), and `flush_pending_outbound` (delivers the buffer on join).
///
/// Honest scope: this is the control-flow / state-machine invariant. The cryptographic fact
/// that the Welcome itself is confidential (ML-KEM-1024) and authenticated lives in the
/// EasyCrypt/TreeKEM developments; here we prove that the ENGINE never produces group
/// ciphertext, or transitions to "keyed", except through that Welcome.

type msg = nat

/// A member's keying state: still joining (no key; carries the local outbound buffer), or
/// keyed (holds the group key).
noeq type kstate =
  | NoKey : list msg -> kstate
  | Keyed : kstate

/// What a send puts on the wire: nothing (held locally) or a group ciphertext. `Encrypted`
/// can ONLY be produced in the `Keyed` state — that is the property under test.
noeq type wire =
  | Buffered  : wire
  | Encrypted : msg -> wire

/// `send` (engine `send_marked`): in `NoKey` BUFFER (append to the queue, emit nothing on
/// the wire); in `Keyed` ENCRYPT (emit the group ciphertext).
let do_send (s:kstate) (m:msg) : (kstate & wire) =
  match s with
  | NoKey q -> (NoKey (q @ [m]), Buffered)
  | Keyed   -> (Keyed, Encrypted m)

/// `receive_welcome` (engine `handle_welcome`): the ONLY transition into `Keyed`, and only
/// when the Welcome is VALID for us (`join_with_welcome` succeeds). On keying, the buffered
/// queue is flushed (returned, in order). An invalid/not-ours Welcome leaves us unkeyed and
/// does not touch the buffer (the pending leaf key is restored, borrow-not-consume).
let receive_welcome (s:kstate) (valid:bool) : (kstate & list msg) =
  match s with
  | NoKey q -> if valid then (Keyed, q) else (NoKey q, [])
  | Keyed   -> (Keyed, [])

(* ======================== invariants ======================== *)

/// THEOREM 1 (NO PREMATURE CIPHERTEXT, I2). While unkeyed, a send emits NOTHING on the wire
/// (only buffers) — no group content is ever encrypted before the key is held.
let thm_no_premature_ciphertext (q:list msg) (m:msg)
  : Lemma (ensures snd (do_send (NoKey q) m) == Buffered)
  = ()

/// THEOREM 2 (KEY ONLY VIA A VALID WELCOME, I2). From `NoKey`, becoming `Keyed` happens iff
/// the Welcome is valid; an invalid (not-ours / later-rejected) Welcome keeps us unkeyed. So
/// holding the key implies having received a valid committer Welcome.
let thm_key_only_via_valid_welcome (q:list msg) (valid:bool)
  : Lemma (ensures Keyed? (fst (receive_welcome (NoKey q) valid)) == valid)
  = ()

/// THEOREM 3 (FLUSH DELIVERS THE BUFFER IN ORDER). Keying flushes EXACTLY the buffered
/// messages, in composition order — nothing lost, nothing sent before the key.
let thm_flush_in_order (q:list msg)
  : Lemma (ensures snd (receive_welcome (NoKey q) true) == q)
  = ()

/// A whole run of sends starting unkeyed with buffer `q`, collecting the wire outputs.
let rec sends_unkeyed (q:list msg) (ms:list msg) : Tot (kstate & list wire) (decreases ms) =
  match ms with
  | []        -> (NoKey q, [])
  | m :: rest ->
    let (s', w) = do_send (NoKey q) m in
    (match s' with
     | NoKey q' -> let (sf, ws) = sends_unkeyed q' rest in (sf, w :: ws)
     | Keyed    -> (Keyed, [w]))   // unreachable: do_send on NoKey yields NoKey — total anyway

let rec all_buffered (ws:list wire) : bool =
  match ws with
  | []     -> true
  | w :: r -> Buffered? w && all_buffered r

/// THEOREM 4 (NO ENCRYPTION UNTIL KEYED — over an arbitrary run). Starting unkeyed, after
/// ANY sequence of sends with no Welcome, EVERY wire output is `Buffered`: a joining member
/// cannot, by any sequence of sends, emit group ciphertext before it is keyed.
let rec thm_no_encrypt_until_keyed (q:list msg) (ms:list msg)
  : Lemma (ensures all_buffered (snd (sends_unkeyed q ms)) == true) (decreases ms)
  = match ms with
    | []        -> ()
    | m :: rest -> thm_no_encrypt_until_keyed (q @ [m]) rest

/// THEOREM 5 (UNKEYED RUN STAYS UNKEYED). No sequence of sends alone ever makes us keyed —
/// only a valid Welcome does (Theorem 2). So the two transitions are the only ways to key.
let rec thm_sends_never_key (q:list msg) (ms:list msg)
  : Lemma (ensures NoKey? (fst (sends_unkeyed q ms))) (decreases ms)
  = match ms with
    | []        -> ()
    | m :: rest -> thm_sends_never_key (q @ [m]) rest
