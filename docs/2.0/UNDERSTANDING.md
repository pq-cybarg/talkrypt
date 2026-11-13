# talkrypt 2.0 — understanding & synthesis

**Status: my (the implementer's) synthesized understanding of the 2.0 direction,
written for review/correction. 2.0 is DEFERRED: it is not started and MUST NOT
start until 1.0 is finished, tested across all routes, and shipped. Nothing here is
built, scheduled, or independently verified — not certified, not audited, not
proven. Every "property" named below is a GOAL UNDER EVALUATION, never a guarantee
(see [`CHARTER.md`](CHARTER.md) §2).**

This is the companion to [`vision.md`](vision.md) (the captured problem statement)
and [`CHARTER.md`](CHARTER.md) (the governance/gate). Where those record *what was
said* and *how work is governed*, this records *what I understand the shape of the
thing to be* — so that when 2.0 is eventually picked up, the design conversations
start from a correct shared model, and so the user can catch any misunderstanding
now.

---

## 1. The thesis (why 2.0 exists at all)

1.0's security model is **post-quantum asymmetric-first**: ML-KEM-1024 key
establishment, ML-DSA-87 identity, a Double Ratchet, TreeKEM groups — all run over
Tor/Nym. Its threat model protects **content, linkage, and membership** against a
network observer, a quantum store-now-decrypt-later adversary, MITM, malicious
peers, and endpoint key theft.

The 2.0 thesis is that **asymmetric cryptography is itself a detectable signal**.
A key exchange, a signature, a large structured ciphertext, a protocol handshake —
these *look like cryptographic communication*, and that observability is a threat
in its own right for a user whose adversary cares not (only) about the content but
about the **fact and pattern of encrypted communication**. 1.0 answers "they can't
read it"; 2.0 asks "can they even tell it's happening, or tell these two things
apart, or fingerprint the technique?"

The claimed route to that is **symmetric cryptography with out-of-band key
sharing**: if the keys arrive by a channel the on-wire observer never sees (QR, NFC,
courier, pre-shared, a different transport), there need be **no on-wire key
agreement and no distinctive handshake**, and the ciphertext need not be shaped like
anything in particular. From there, 2.0 generalizes to a regime where **the
cryptographic technique itself is chosen, mixed, rotated, and compartmentalized per
chat** — "polymorphic" crypto.

**The central hazard, and why the gate is strict:** low-observability /
covert-channel / custom-crypto claims **fail silently**. A user who trusts an
unverified low-observability goal that a side channel or technique-fingerprint later
betrays is worse off than a user who knew they were observable. So 2.0's bar is not "does it
work" but "has it been *proven* (FV), *independently evaluated*, and *actively
attacked* (pentest) — and until then every claim is a goal, not a fact."

## 2. What actually changes from 1.0 (the paradigm shift)

| Dimension | 1.0 | 2.0 goal (under evaluation) |
| --- | --- | --- |
| Primary primitive | PQ asymmetric (ML-KEM/ML-DSA) | symmetric + OOB keying is first-class; asymmetric becomes one option among many |
| Key establishment | on-wire handshake (invite-token PSK + KEM) | optionally **no on-wire** establishment — keys delivered out of band / over a side channel |
| Technique | one negotiated suite per chat | an **assembled, per-chat, time-rotating** set of techniques ("polymorphic") |
| Observability posture | content-confidential; transport-metadata via Tor/Nym | the *technique and the fact of comms* are themselves targets to obscure |
| Trust root | account ML-DSA key certifies devices | can be a **quorum** (Shamir k-of-n) rather than a single key |
| Components | fixed stack | **fragmentable, compartmentalized** stack with per-fragment provenance/entropy/timing assessment |
| Control | user picks a suite | user- and optionally **MCP/AI-controlled** reconfiguration, including scheduled rotation |

The through-line: 1.0 is "one strong construction, applied uniformly"; 2.0 is "a
*space* of constructions, assembled and varied per chat under policy, with the
variation itself as a defensive property (raising fingerprinting cost) — if it can
be shown to actually do that."

## 3. The eight components, and how they compose

The vision decomposes into eight tracked components (#123–#130). Two are
**foundations** that everything else plugs into; the rest layer on top.

```
        (foundation)                         (foundation)
   #123 symmetric OOB-keyed            #124 fragment / compartment
        covert channel                      component model + assessment
         |        \                          /        |
         |         \                        /         |
   #125 side-channel /            #126 per-feature     |
        split keying              side-channel routing |
          \                          /                 |
           \                        /                  |
            +--------> #129 polymorphic technique assembly <----+
                                   |
                        #130 MCP/AI reconfiguration surface

   (independent quorum track)
   #127 Shamir k-of-n quorum  ---->  #128 intermittent-quorum
        (foundation)                       overlapping onion layers
```

- **#123 Symmetric OOB-keyed covert channel (foundation).** A symmetric cipher whose
  key is shared entirely out of band, so there is no on-wire asymmetric handshake to
  fingerprint. This is the atom of the "undetected comms" goal. Design questions I
  carry: which symmetric construction (AEAD choice, nonce discipline with no on-wire
  negotiation, rekey/ratchet without a handshake), how OOB key material is imported
  (QR/NFC/courier/pre-shared), and how ciphertext framing avoids a talkrypt-shaped
  fingerprint.
- **#124 Fragment/compartment component model (foundation).** The stack becomes an
  assembly of **vetted, swappable fragments**, each with: SBOM/provenance, crypto
  primitive choice, entropy source + **entropy assessment**, and **timing-analysis
  posture**. This is the substrate that makes "polymorphic assembly" auditable rather
  than a pile of unassessed custom crypto. The **assessment harness** is the
  deliverable as much as the model: a way to record and check each fragment's four
  dimensions (this is what the per-component assessment record in
  `components/TEMPLATE.md` operationalizes).
- **#125 Side-channel-delivered / split keying** (needs #123). A chat's keying rides
  a *different route* than its traffic, and the split is **chat-specific** (each chat
  defines its own keying side channel + policy). Builds on #123's OOB-keying by making
  the "out of band" an in-system, policy-driven *other transport leg*.
- **#126 Per-feature side-channel routing** (needs #124). Generalize "a feature's data
  can ride a different route": keying, confirmation hints, presence, metadata, decoys
  — each independently routable. This is #125 lifted from "keying" to "any feature",
  and it is where decoy/cover traffic would live.
- **#127 Shamir k-of-n quorum (foundation, independent track).** Gate a conversation's
  key on a quorum of participants (web-of-trust-like): enough must contribute for
  comms to proceed. Independent of the covert-channel track; it changes the *trust
  root*, not the *observability*.
- **#128 Intermittent-quorum overlapping onion layers** (needs #127). The hard
  problem #127 surfaces: intermittently-connected shareholders break a naive quorum.
  The proposed shape is **multiple coexisting secret-shared conversations** arranged
  onion-like, overlapping when the relevant users are online, so a reachable subset
  keeps a narrower conversation alive and fuller conversations unlock as more
  participants coincide. This is the deepest open research in 2.0 (see §5).
- **#129 Polymorphic technique assembly** (needs #123, #124, #126). The headline: a
  chat's cryptographic construction is **assembled from fragments under user control**,
  and **built to assume rotation/evolution** (the technique set changes over the
  chat's life by schedule/event/policy). "Polymorphic" = the observable technique
  differs per chat and over time, with the goal of raising fingerprinting/attack cost.
- **#130 MCP/AI-controllable reconfiguration surface** (needs #129). The assembly is
  reconfigurable through a controlled MCP/AI surface. This is powerful and dangerous:
  it is a control plane over the crypto itself, so its own authorization, auditability,
  and failure modes are a first-class security problem, not a convenience feature.

## 4. Architecture — where 2.0 attaches, and what 1.0 must preserve

2.0 is explicitly **not** a rewrite of the engine from inside; it attaches at seams
that mainline's multi-bearer design already keeps clean. My understanding of the
three load-bearing seams:

- **`Transport` leg model** — the plug point where covert / side-channel bearers
  attach. A "leg" is one route; 2.0's side channels (OOB keying, decoys, per-feature
  routing) are additional legs with their own observability posture.
- **`BearerSet` / capability selection** — where a **per-chat compartmentalized
  bearer + technique policy** lives. This is the natural home for "this chat uses
  technique assembly X over bearer legs Y, rotating on schedule Z."
- **Framed-leg fragmentation** — where **fragmentable component routing** attaches
  (a frame can be split and routed per-fragment).

So the mainline obligation (and a thing to verify as part of finishing 1.0) is: the
multi-bearer `Transport`/`BearerSet`/framed-leg abstractions stay clean and do **not
foreclose** these — and mainline should *not try to build on them* speculatively.
The `docs/multibearer-linking-spec` branch's spec is where that seam is defined.

The 2.0 "assembly" itself I understand as a **policy object per chat**: (set of
fragments + their config) × (bearer-leg routing per feature) × (rotation schedule),
where each fragment is assessed (§3 #124) and the whole is honest-scope-worded (a
goal under evaluation). The MCP/AI surface (#130) is a controller that edits that
policy object under constraints.

## 5. The hard problems (where I expect the real difficulty)

1. **Covert claims are unfalsifiable-by-construction without a defined observer.**
   An "undetectable" goal (never a guarantee) means nothing until the observer model
   and the cover distribution are pinned. Every covert component needs a *falsifiable*
   property ("an observer
   with capability C cannot distinguish these frames from cover distribution D better
   than ε") that a pentest can actually attack. This is a prerequisite, not a detail.
2. **Custom / assembled crypto is a downgrade risk.** Replacing one well-analyzed
   construction with a *space* of assembled ones multiplies the ways to be subtly
   wrong (nonce reuse across rotation, weak fragment combinations, rotation that
   leaks a boundary). The fragment-assessment model (#124) and FV per assembly are
   the mitigations, but the combinatorics are the danger.
3. **FS/PCS across polymorphic rotation.** 1.0's FS/PCS are now machine-checked for a
   *fixed* ratchet/TreeKEM. When the technique set rotates, the forward/backward
   secrecy *across* a rotation boundary becomes a new obligation — does a compromise
   at technique T_i expose T_{i-1}? This is the 2.0 analogue of the RatchetFS/TreeKemKS
   proofs and will need its own FV.
4. **Intermittent-quorum key relationships (#128).** How layers nest, how keys relate
   across overlapping secret-shared conversations, and FS/backward-secrecy across
   intermittent overlaps are genuinely open. A naive design risks either a layer key
   unlocking more than intended, or no reachable subset ever proceeding.
5. **The MCP/AI control surface is an attack surface on the crypto itself (#130).**
   A controller that can reconfigure the construction can also *mis*configure it
   (downgrade, disable a side channel, force a weak assembly). Its authorization,
   audit trail, and safe-default/fail-closed behavior are security-critical.
6. **No on-wire handshake still needs rekey/replay/ordering discipline (#123).** OOB
   keying removes the handshake but not the need for nonce uniqueness, forward
   secrecy, replay resistance, and ordering — now without an on-wire negotiation to
   carry them. That discipline has to come from the OOB material + a handshake-free
   ratchet.

## 6. The gate, restated in my own terms

Every component passes three gates before it may influence mainline, recorded in its
assessment record (`components/TEMPLATE.md`) and partly CI-enforced
(`ci/honest-scope-check.sh`, `2.0-gate.yml`):

1. **FV** — the security-relevant logic is machine-checked (the `formal/` tradition:
   F\*/EasyCrypt for secrecy/auth/authorization by reduction to assumed primitives;
   Kani for decoder totality). For 2.0 this specifically means a *falsifiable
   property* (§5.1) reduced to a stated assumption.
2. **Independent security evaluation** — reviewed by someone who did not build it.
3. **Penetration test** — actively attacked against its stated property; results
   worded "not broken by the tests performed", never as an absolute.

And the **honest-scope invariant** rides over all of it: a low-observability or
certification property is never a guarantee — only a goal under evaluation, until
independently broken-or-not, and even then worded honestly (CHARTER.md §2).

## 7. Relationship to 1.0 — and the deferral

**2.0 is deferred until 1.0 is finished, tested across all routes, and shipped.**
That is the current priority and the correct order: 2.0 reopens the threat model at
the root and is research-grade; it should not divert a 1.0 that is close to
shippable. What 1.0 owes 2.0 is narrow and already noted — keep the multi-bearer
`Transport`/`BearerSet`/framed-leg seams clean (§4) and don't build on them
speculatively. Beyond preserving that seam, finishing 1.0 is independent of 2.0.

When 2.0 is picked up, the sequence is: brainstorm **#123** and **#124** first (the
foundations), each into its own design doc then a numbered TDD plan, behind feature
flags, with assessment records filled as FV/eval/pentest complete — exactly the
workflow in `CHARTER.md` §4.

## 8. Open questions I would want answered before brainstorming #123/#124

- **Observer model:** who is the covert-channel adversary (on-path passive? active?
  the transport operator? a global passive observer?), and what is the cover
  distribution frames must blend into? (Determines the falsifiable form of every
  low-observability goal — none of which is a guarantee until tested.)
- **OOB channels to support first (#123):** QR / NFC / pre-shared file / courier —
  which one(s) for the first primitive, and what's the key-rotation story without an
  on-wire handshake?
- **Fragment granularity (#124):** what is the smallest independently-assessed/swapped
  unit — a primitive (cipher/KDF), a layer (keying/framing/transport), or a whole
  construction? This sets the assessment-harness shape.
- **Quorum trust vs. existing account model (#127):** does the quorum *replace* the
  account→device chain for a chat, or compose with it?
- **Rotation policy source (#129/#130):** schedule, event, or external controller —
  and what is the fail-closed default if the controller is unavailable or hostile?
- **How much is research vs. product:** which components are meant to ship as opt-in
  features vs. remain research artifacts that inform the architecture?

---

*Correct me where this diverges from intent. When 1.0 has shipped and 2.0 is picked
up, this document is the starting model for the #123/#124 design conversations.*
