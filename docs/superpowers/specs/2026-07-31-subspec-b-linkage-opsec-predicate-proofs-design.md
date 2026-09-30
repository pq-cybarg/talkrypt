# Sub-spec B — Identity-Linkage Disclosure, Opsec Modes & Zero-Knowledge Predicate Proofs — Design

> Feature #58 family, **Sub-spec B** (task #66). Builds on Sub-spec A (names/CQ/trust-render surface,
> shipped). Decorates A's `NameRender` `tint` slot (`Tint::Isolated`) and extends the identity model.
> **Status:** design draft for review. Scope confirmed by the user as "full Sub-spec B in one pass" at
> the *design* level; the build is deliberately **staged** (see §9) because part of B is novel
> post-quantum cryptography that must be externally reviewed before it ships — consistent with the
> project's standing rule (FIPS/NIST-audited primitives + cryptographer review before ship) and with
> task #73 ("novel decentralized PQ crypto — document properly, don't ship unreviewed").

---

## 0. What this delivers (the user's intent, verbatim-grounded)

A person holds **multiple identities** (Sub-spec A leading names, backed by the existing
account→device→**segment** ML-DSA signature trees — `crates/crypto/src/account.rs`,
`belongs_to_account`). Sub-spec B governs two things in tension:

1. **Linkage disclosure** — which of *your* identities are provably one person/account, and **how much
   of that you reveal**, under a user-chosen opsec policy.
2. **Sybil resistance with a way out** — one person can wear N unlinked identities to fake headcount;
   viewers get an honest (subtle) **isolated** signal — *but* an apparently-isolated party must have a
   **zero-knowledge way to prove they meet the group's (or a member's) criteria** without revealing who
   they are, and without the verifier revealing the criteria/set. **ZK in both directions.**

Opsec modes (the user's policy for disclosing **their own** linkage):

- **Opsec-clean** — every identity stands alone; emit no linkage proofs. Max unlinkability. Consequence:
  your identities read as **isolated** to others (the `Tint::Isolated` coloration) unless you answer a
  predicate proof.
- **Opsec-selective (groupings)** — disclose linkage *within* a chosen grouping, **without exposing the
  account** or your other groupings.
- **Fully-transparent (+ hide-transparency)** — disclose that your presented identities link to your
  account. **hide-transparency** sub-flag: emit/answer linkage *without* advertising that you chose
  transparency, so the meta-choice isn't itself a fingerprint.

Plus, from A §0/§9: per-chat **show-all-associated-identities vs just-foremost**; the **isolated sybil
tint** (subtle, never a loud warning); **user policy trumps group policy**; **linkage-proof crypto over
the existing segment / account-linking machinery**.

---

## 1. The load-bearing design decision: disclosure ≠ display (user-trumps-group, done right)

Conflating "what a user reveals" with "what a group enforces" is the weak path. Split them:

- **Disclosure** (what linkage proofs / predicate proofs a member *emits*) is controlled **solely by the
  member**. A group can **never compel** disclosure. Opsec-clean always wins. This is `user-trumps-group`
  in the privacy direction, absolutely.
- **Display** (how *unproven / isolated* identities are *rendered to a group's own members*) is a group
  setting. A sybil-averse group may tint isolated identities more prominently, or surface a sybil-count.
  This changes how the group **sees**, never what a member must **say**.
- **Access** is a third, pre-existing lever (`engine::AccessPolicy`). A group MAY *refuse entry* to
  identities that can't satisfy a predicate — that is an access decision, **not compelled disclosure**:
  the would-be member chooses whether to prove-and-enter or stay out. Crucially, the **predicate proof is
  ZK** (§4), so entry is gated on *satisfying* the criteria, not on *revealing* identity.

So the member's answer to "prove you meet our criteria" is always **optional and zero-knowledge**: they
may prove (and gain display trust / access) without deanonymizing, or decline (and wear the isolated
tint / stay out). That reconciliation is what makes B fit for a dissident/resistance threat model.

---

## 2. The `Claim` / predicate-proof abstraction (one seam, pluggable backends)

Everything the user described is one shape: **a prover asserts a predicate; a verifier learns only
pass/fail; identity is revealed only as much as the predicate strictly requires.** Model it as a single
core seam with swappable proof backends, so audited primitives ship and novel crypto is isolated.

```rust
/// A statement a prover wants a verifier to accept about the prover's identity/credentials,
/// revealing no more than the predicate requires. Bound to a chat context to stop cross-chat replay.
struct Claim {
    predicate: Predicate,
    context: [u8; 32],   // SHA3-256(invite_token ‖ channel ‖ claim-domain) — as in Sub-spec A
}

enum Predicate {
    // --- Backend 0: audited ML-DSA cert proofs (ship now) ---
    LinkedToAccount { account_fp: [u8; 48] },      // "these leaves share THIS account" (transparent)
    Grouping { grouping_pub: MlDsaPublic },        // "these leaves share this grouping key" (account-hidden)
    DerivedFromNamed { ancestor_fp: [u8; 48] },    // "I descend from THIS specific known identity"

    // --- Backend 1: PQ zero-knowledge (feature `zk`, review-gated — §4) ---
    MemberOfKnownSet { set_commitment: [u8; 32] },  // "you know me" — ∈ verifier's set, which one hidden
    DerivedFromKnownSet { set_commitment: [u8; 32] },// "derived from SOMEONE you know" — ancestor hidden
    Attribute { policy: PolicyId },                  // "I meet this arbitrary criterion" (e.g. SCI level)
    And(Vec<Predicate>), Or(Vec<Predicate>),         // compositions
}

trait ProofBackend {
    fn prove(&self, claim: &Claim, witness: &Witness) -> Result<Proof>;
    fn verify(&self, claim: &Claim, proof: &Proof) -> Verdict;  // Pass | Fail — nothing else leaks
}
```

- **Backend 0 (`MlDsaCertBackend`)** — the claims provable from the existing signature-tree machinery,
  no ZK required. Ships on audited primitives (FIPS 204 ML-DSA-87). Covers transparent linkage, grouping
  disclosure, and "derived from *this named* identity."
- **Backend 1 (`ZkPredicateBackend`)** — the genuinely-ZK claims (hidden set / hidden ancestor / arbitrary
  attribute). Hash-based STARK (§4). Compiled only under the `zk` cargo feature; **off by default**;
  review-gated.

`Verdict` is deliberately two-valued: a verifier never learns *which* set element, *which* ancestor, or
*which* attributes beyond the asked predicate.

---

## 3. Backend 0 — audited linkage disclosure (ship now, ML-DSA only)

### 3a. Transparent linkage — already latent in Sub-spec A
Two A `Presence::Linked` presentations whose chains root at the same `account_fp` are *already* visibly
one account. B adds the **explicit control**: opsec-transparent means "present ≥2 leading names as
`Linked` to the same account and let viewers see the shared root." No new crypto — a UI/policy layer over
A. `hide-transparency` = present the linkage *without* a "transparency mode" flag on the wire (there is no
such flag to hide because linkage is just co-presented `Linked` proofs — the meta-choice is unobservable
by construction).

### 3b. Grouping key — account-hidden, **per-chat-unlinkable** selective linkage (new, ML-DSA)
For opsec-selective, disclose within-grouping linkage **without** revealing the account **and without the
grouping itself becoming a cross-chat linkage vector**:

- A long-term **grouping root secret** `g_root` (32-byte seed), unlinkable to the account (a sibling of a
  segment seed, never certified upward to the account).
- **Per-chat derivation (the fix for cross-chat linkability):** the presented grouping keypair is
  `G_c = ML-DSA-keygen( KDF(g_root, chat_context) )` — deterministic, fresh **per chat**. The same grouping
  therefore presents a **different `G_c.pub` in every chat**, so an observer in two chats cannot link
  "grouping X is in both" from the grouping key. (ML-DSA-87 keygen is seedable; `KDF` = the existing
  `mac_kdf` used for A's derived leaf seeds.)
- Per chat, `G_c` issues `SignedCert(G_c → L_i, "group", iat, exp)` for each grouping identity `L_i`
  (reusing `account.rs::SignedCert::issue`). A member presents `(L_i, cert_i, context, sig_i)` with `sig_i =
  L_i.sign(seq ‖ context)` (as A's `Linked` presence). A viewer verifies every `cert_i` under the **same
  `G_c.pub`** → learns "these N leaves are one grouping (one person) **in this chat**" and nothing about the
  account or the grouping's presence elsewhere. `context`-binding also blocks cross-chat *replay*.
- **Residual linkage is the leaf, not the grouping** (documented, not hidden): if the user reuses the same
  leaf `L_i` (same leading name) across chats, *that leaf* links them — a pre-existing choice, orthogonal to
  B. Full cross-chat unlinkability = per-chat grouping key **and** per-chat (rotating) leaves, the identity
  model's existing "rotating per-conversation" option. B removes the grouping key as a *new* linkage vector.
- **Sybil-count payoff:** distinct people present ≥ `count(distinct account_fp) + count(distinct G_c.pub) +
  count(isolated leaves as worst-case-1-each)`, computed within the chat. The group can display this honestly.
- **B0 realization (one leaf key per session).** talkrypt runs **one device leaf key per `Core`/session**;
  the user's several identities in a chat are several *sessions* (pseudonyms/segments). So `g_root` is a
  **persistent, user-held secret shared across the user's sessions** (set via `Core::set_grouping_root`,
  app-persisted — NOT derived from any single session's device key, which would only link same-device
  sessions). Each session presents **its own** leaf certified under the shared per-chat `G_c`
  (single-member `GroupingProof`); a viewer **aggregates** all leaves it sees bearing the same `G_c.pub`
  into one grouping. Unset `g_root` → an ephemeral per-session key (a grouping of one; harmless).

**Why a fresh per-chat key, not the account:** the account root is the linkable secret. A per-chat grouping
key discloses *multiplicity* ("one person holds these, here") while hiding *which* person **and** not
leaking the grouping across chats — exactly opsec-selective. Limitation: grouping membership is *asserted by
the holder* (proves "co-controlled by whoever holds `g_root`"), not tied to an external attribute — the
correct semantics for "these are my alts, grouped." A grouping *tied to* an external predicate is a Backend-1
`Attribute` claim, not a grouping key.

### 3c. Derived-from-named
"I descend from `ancestor_fp`" = present the `IdentityChain` segment path ending at a leaf whose ancestor
is `ancestor_fp`; verify with `belongs_to_account`-style chain check. Reveals the ancestor (that's the
point of the *named* variant). The *hidden*-ancestor variant is Backend 1.

### 3d. Isolated tint (rendering)
`Tint::Isolated` is applied by the viewer to any presented identity for which **no** linkage/predicate is
verifiable in this chat — not a contact/friend account (existing `contacts.rs`), not a grouping proof,
not a passing predicate. Inference from absence; there is deliberately **no "I am isolated" crypto**
(can't prove a negative). Subtle coloration via A's documented tint-precedence function (A reserved this
hook). Group display policy may amplify it.

---

## 4. Backend 1 — PQ zero-knowledge predicate proofs (feature `zk`, VERIFICATION-GATED)

This is the novel layer. It is designed here concretely; it does **not** ship enabled until it clears
**formal verification by the author** (§9). Grounded in the 2024–2026 PQ-ZK survey
(`docs/research/pq-zk-survey.md`, committed alongside).

### 4a. Primitive selection — Winterfell (FRI STARK), chosen on a properties basis
- **Commitment scheme decides PQ-ness.** Only **hash/FRI** commitments are post-quantum; all pairing/EC
  (Groth16, PLONK-KZG, Halo2-IPA, Nova-folding, BBS+, BLS) are Shor-broken and **excluded**.
- **Chosen base: `Winterfell` (hash-based FRI STARK).** Because the author will **formally verify** this
  layer, the selection is driven by *provable properties*, not third-party audit coverage — and on
  properties Winterfell is the right baseline for these three predicates:
  - **Exact knowledge soundness (negligible error).** A predicate like "my key descends from an identity in
    this set" is used for access control; a *relaxed* extractor (as in standard lattice Σ-protocols, which
    only witness a relaxed relation R̄ with γ≈√dim slack — eprint 2022/141, 2019/747) is a **genuine
    semantic hazard**: R̄ need not correspond to a real ancestor. Winterfell proves the relation you wrote.
  - **One conservative, falsifiable assumption (CRHF only).** No structured MSIS/MLWE, and — critically —
    no *non-falsifiable knowledge assumption*. Succinct arbitrary-NP arguments are barred from falsifiable
    assumptions in the plain model (Gentry–Wichs); lattice systems that match STARK succinctness must take
    knowledge k-R-ISIS (eprint 2022/941) or new q-type ROM assumptions (vanishing-SIS, eprint 2023/1405).
    FRI sidesteps this — it is a ROM/hash construction from the start.
  - **Arbitrary-NP / Turing-complete AIR** — all three claims are *general computation over hashes +
    signature checks*, exactly where lattice ZK is weakest (must arithmetize foreign ops, paying slack or
    exotic assumptions) and where an AIR is native with exact soundness.
  - **Single soundness object** (RS-proximity/FRI + Merkle) with active Lean 4 blueprints → **the most
    tractable to formally verify**, which is the deciding factor given the author verifies it personally.
  - Plonky3 (Least-Authority-audited, PQ-pure) and un-wrapped SP1/RISC Zero remain fallbacks if the
    self-verification plan changes; their default Groth16-over-BN254 wrap is quantum-broken (hard exclusion).
- **Narrow exception — reach for lattice ZK only when the statement is *intrinsically* about ML-DSA/ML-KEM
  key material** (e.g. proving knowledge of an ML-DSA-87 secret, or relations among ML-KEM ciphertexts),
  where nativity beats simulating the lattice verifier inside a STARK — *and* the app tolerates the relaxed
  relation. None of B's three predicates fall here; noted for completeness / future statements.
- **Proximity test is a swappable, still-PQ component — target STIR/WHIR, not stock FRI.** The low-degree
  test underneath the STARK (FRI → STIR → WHIR) is interchangeable and all hash-based (CRHF → PQ; the
  assumption class does not change). The newer tests are strictly better on the axes that matter here:
  - **STIR** (Arnon–Chiesa–Fenzi–Yogev, 2024) — reduces query complexity (~O(λ + log²N) vs FRI's
    O(λ·log N)) → smaller arguments, cheaper verify, and a *higher* soundness margin per query.
  - **WHIR** (2024/25) — Reed–Solomon (constrained-RS) proximity with **super-fast verification** (µs-scale)
    and a tighter, more current soundness analysis; unifies multilinear + univariate IOPs.
  - **Motivation is also defensive:** plain **FRI's above-Johnson soundness lost its theorem (late 2025)**
    (eprint 2026/858), so leaning on the *newest* proximity analysis (STIR/WHIR) rather than a regressed
    FRI bound is the conservative call. Maturity caveat: STIR/WHIR have reference Rust implementations but
    are newer than FRI — acceptable here precisely because the author formally verifies the chosen test
    rather than trusting an audit. **Plan: integrate WHIR (fallback STIR) as the proximity layer;** stock
    Winterfell's FRI is the reference/fallback if WHIR integration slips, at the cost of the regressed bound.
- **All three claim archetypes reduce to one circuit family: Merkle / cert-chain membership.**
  - `MemberOfKnownSet` ("you know me") — **ZK in both directions**, done via verifier-issued witnesses:
    - *Prover hides which element:* the circuit proves a Merkle authentication path from the prover's
      committed leaf to the published `set_commitment` root, revealing neither the leaf nor the index (ZK
      masking, §4b.1).
    - *Verifier hides the set from the prover:* the verifier does **not** hand the prover the tree. At the
      moment the verifier "gets to know" a party, it privately issues that party a **membership witness**
      (its authentication path in the current epoch tree — sibling hashes only, which leak no set contents).
      The prover later proves membership against the **published root** (a hiding commitment) using its
      privately-held witness. Neither side learns the other's private data; the verifier learns only
      pass/fail. This is the VC/anonymous-credential-via-Merkle pattern the research flagged as the *only*
      PQ-practical route (full "private set membership where neither party is pre-provisioned" is research-
      only PQ and explicitly out of scope).
    - *Set churn:* add/remove rotates the root → an **epoch** counter is bound into `context`; witnesses are
      re-issued per epoch (or via a hash/Merkle **accumulator** with an update path). Revocation = drop from
      the next epoch tree. Epoch monotonicity prevents proving membership against a stale root.
  - `DerivedFromKnownSet` ("derived from someone you know"): prove a valid cert-chain from the prover's key
    up to *some* member of a whitelisted ancestor set (epoch Merkle root, issued as above), revealing
    neither the ancestor nor the prover's key. **Direct prior art: zk-X509 "CA-anonymous chain membership."**
    Reuses the same witness-issuance + epoching as `MemberOfKnownSet`.
  - `Attribute` (SCI level / arbitrary): prove possession of an issuer-signed credential whose attributes
    satisfy a policy circuit, revealing only pass/fail. The credential is a §4c attestation (issuer =
    whoever certifies the attribute, e.g. an SCI authority key); the circuit checks issuer-sig validity +
    the attribute predicate, hiding the credential itself.

### 4b. Three sharp risks written into the design (non-negotiable review items)
1. **STARKs are not zero-knowledge by default.** Succinct ≠ ZK. ZK requires witness-polynomial + quotient
   masking with preserved degree bounds and FRI-folding entropy care (Haböck–Kindi, eprint 2024/1037). The
   design MUST select a ZK-enabled configuration and include a test that the proof leaks nothing about the
   witness (statistical masking check). No off-the-shelf crate is assumed ZK.
2. **Arithmetization-friendly hashes — choose the SECURE one, layer the rest.** Poseidon/Poseidon2 are
   under active algebraic (Gröbner/resultant) cryptanalysis. **Rescue-Prime is NOT interchangeable**:
   its *bidirectional full-round* structure resists those attacks, so it is the **in-circuit
   arithmetization hash**. The **commitment/Merkle layer uses SHA3/SHAKE** (Keccak sponge →
   length-extension resistant; SHA-384 likewise, truncated) — talkrypt already standardizes on
   SHA3/Keccak, consistent. Field = **KoalaBear** (31-bit) — chosen for **mobile device limits** (cheap arithmetic + low memory
   on phone CPUs); the KoalaBear-*Poseidon* cryptanalysis is moot since we use Rescue-Prime. Round counts are a verification obligation (min-degree analysis).
3. **Proximity-test soundness is a moving target — pin the analysis, don't copy a default.** Plain FRI's
   above-Johnson soundness lost its theorem (late 2025; eprint 2026/858 restores an unconditional bound at
   ~one extra query round). This is a primary reason to target **STIR/WHIR** (§4a) whose current analyses
   are tighter — but *whichever* test is chosen, the concrete query count / soundness parameters are a
   **formal-verification obligation**, derived and machine-checked, never a copied library default.

### 4c. Attestation layer (the "one-time proof → cheap attest" pattern)
- **Verifiable-credential shape:** a verifier who *ran* a Backend-1 proof once issues an **ML-DSA-87
  attestation** `Attn = Sign_verifier( claim.context ‖ predicate_id ‖ subject_leaf ‖ epoch )`. Peers who
  cannot re-run the STARK verify the cheap ML-DSA attestation instead.
- **Quorum:** trust a predicate for a subject when **k distinct** attestors have signed it. **No compact PQ
  threshold/aggregate signature exists at scale** (BLS is broken; PQ threshold ML-DSA is ≤~6 parties,
  research) — so a quorum is **k separate ML-DSA signatures** (linear size, acceptable for small k).
- This *is* Sub-spec C's vouching mechanism generalized (web-of-trust over verified predicates). B and C
  **share** the attestation type; C adds vouch-count *thresholds → tint*. Designed once here.

### 4d. Predicate-gated delivery ("SCI messages don't arrive until you prove status")
- **Do NOT use attribute-based encryption.** PQ ABE / predicate encryption is research-only, no audited
  Rust, MB-scale keys — excluded.
- **Predicate epoch key `K_P` (group-managed sub-key), not per-recipient KEM.** The decentralized mechanism
  reuses TreeKEM's existing per-member key distribution — there is **no trusted party**:
  1. **Bootstrap.** The first member to gate on predicate `P` generates a fresh symmetric `K_{P,0}` and
     sends it, **encrypted per-recipient to each already-qualified member's device key (ML-KEM-1024)**, to
     every member who holds a valid quorum attestation for `P` (§4c) — exactly how TreeKEM hands a new
     member the epoch secret. (`K_{P,0}` itself is derived from the group epoch secret so it inherits the
     group's forward secrecy.)
  2. **Send.** A gated message is AEAD-encrypted under the current `K_{P,e}` and broadcast on the normal
     group path. Satisfiers decrypt; non-satisfiers hold no `K_{P,e}` and see a **padded, unopenable frame,
     indistinguishable from ordinary padding** under talkrypt's frame-indistinguishability posture — they
     learn a gated frame *exists*, not its predicate or content. Untagged traffic flows normally.
  3. **Admit.** When a member newly proves `P` (earns a quorum attestation), any current `K_{P,e}` holder
     ML-KEM-encrypts `K_{P,e}` to them — a one-frame add, TreeKEM-style.
  4. **Revoke + FS.** When a member loses `P` (attestation revoked / expired), rotate to `K_{P,e+1}` (KDF
     ratchet from `K_{P,e}` ‖ new-epoch) and redistribute only to remaining holders — a predicate-scoped
     epoch bump, so a removed member cannot read future gated traffic (post-compromise security for the
     gate). The epoch counter binds into the message AAD to stop cross-epoch replay.
- **prove-then-KEM is the entry gate to `K_P`, not the message cipher:** you present a passing ZK proof or
  quorum attestation for `P` → a holder KEM-wraps `K_{P,e}` to you. This keeps the hot path (sending a gated
  message) a single symmetric AEAD, and confines the expensive ZK/KEM work to the rare admit event.
- **Honest limit:** this hides *content + predicate* from non-satisfiers, not the *existence* of gated
  traffic (padding-indistinguishable) — matching the current posture, not perfect metadata-hiding.
- Honest limit: a non-satisfying member still observes that *a* gated message exists (a padded frame it
  can't open), just not its predicate or content — matching talkrypt's existing frame-indistinguishability
  posture, not perfect metadata-hiding.

---

## 5. Wire format & propagation

Reuse Sub-spec A's `Frame::Presence` (pairwise) / group-payload-behind-`GroupMsg` duality, adding claim +
attestation payload kinds (append-only tags; old clients drop via `_ => None`):

```rust
enum LinkagePayload {
    GroupingProof { grouping_pub, members: Vec<(leaf, cert, sig)> },   // §3b
    Claim { claim: Claim, proof: Proof },                             // §2 (backend-tagged)
    Attestation { attn: MlDsaAttestation },                          // §4c
}
```
- Rides **inside** the encrypted session (pairwise) / under the group epoch key (group) — never cleartext,
  never in the invite (same confidentiality guarantee as A).
- `context`-bound; `seq`-monotone (reuse A's anti-replay); viewer-enforced rate limits (reuse A).
- **Descriptor:** the group's *display* policy (§6) and any *access* predicate (§1) are chat-creation
  settings → `ChatDescriptor` v2→**v3** (append-only, v1/v2 decode with defaults; new KAT vector; matches
  A's v1→v2 precedent). Member *disclosure* is never in the descriptor (it's per-member, per-moment).

---

## 6. Client surfaces (core → FFI → Android/desktop/CLI)

**Core:** `Core::set_opsec_mode(OpsecMode)`, `Core::define_grouping(&[NameId]) -> GroupingId`,
`Core::present_grouping(GroupingId)`, `Core::show_all_identities(bool)` (per chat),
`Core::prove_claim(Predicate)`, `Core::attest(subject, predicate)`, `Core::set_group_display_policy(...)`
(host), `Core::set_delivery_predicate(Option<Predicate>)` for a message. New `Event::Linkage { subject,
kind, verdict }` and `Event::Attestation { .. }`. `NameRender.tint` gains `Isolated` population + the
group-amplification hook.

**FFI/Android/desktop/CLI:** opsec-mode picker (clean/selective/transparent + hide-transparency toggle);
grouping editor over the name book; per-chat show-all toggle; isolated tint in bubbles/roster; sybil-count
readout; "prove you meet criteria" prompt (ZK) when gated; host controls for group display policy +
optional access/delivery predicate. CLI mirrors: `/opsec`, `/grouping`, `/showall`, `/prove`, `/attest`,
`/gate`. The `zk` (Backend 1) controls are visible only in a `zk`-feature build and marked experimental.

---

## 7. Testing

- **Backend 0 (ships):** grouping cert issue/verify (valid / wrong grouping key / wrong context / revoked);
  account-hidden property (grouping proof reveals no account_fp); transparent linkage; derived-from-named;
  isolated-tint inference (no-linkage → Isolated, contact → not); sybil-count math; descriptor v1/v2/v3
  round-trip + KAT; disclosure-vs-display (group policy cannot force a member's emission); access-predicate
  gate admits/denies without leaking identity.
- **Backend 1 (behind `zk`, pre-review):** each claim archetype proves-and-verifies; **ZK/masking leak
  test** (proof statistically independent of witness); soundness negative tests (wrong witness fails);
  context-binding (cross-chat replay fails); attestation quorum (k-of-n); prove-then-KEM (satisfier derives
  key, non-satisfier cannot; gated frame indistinguishable from padding to non-satisfier).
- **Integration (`LoopbackFabric`):** 3-member group — selective grouping disclosure resolves for a
  non-host member; an isolated member proves `MemberOfKnownSet` in ZK and gains an attestation that a third
  member (who can't re-verify) accepts; predicate-gated message reaches only the satisfier.

---

## 8. Security considerations

- **User-trumps-group is absolute for disclosure** (§1); groups get display + access levers only.
- **Backend 0 rests entirely on FIPS-final ML-DSA-87 / SHA3** — no new trust assumptions.
- **Backend 1 introduces new assumptions** (FRI/hash soundness, ZK masking correctness, AF-hash
  cryptanalysis) → **must not ship enabled without external review** (§9). This is the crux honesty gate.
- Cross-chat replay (context binding), within-chat replay/reorder (seq), confidentiality (rides encrypted),
  grief resistance (viewer-enforced limits) — all inherited from A.
- **Metadata honesty:** predicate-gated delivery hides *content + predicate* from non-satisfiers, not the
  *existence* of a gated frame (padding-indistinguishable, matching current posture).

---

## 9. Staging & the review gate (how "full B in one pass" ships responsibly)

- **Phase B0 (build now, audited):** the `Claim` seam + `MlDsaCertBackend` (transparent/grouping/derived-
  from-named), opsec modes, show-all/foremost, isolated tint + display-vs-disclosure split, sybil-count,
  access-predicate gating over Backend 0, all surfaces, descriptor v3. Ships on ML-DSA-87 — no new crypto
  assumptions. This is a complete, useful feature by itself.
- **Phase B1 (design complete here; build behind `zk` feature; VERIFICATION-GATED):** the Winterfell ZK
  backend, attestation quorum, prove-then-KEM predicate-gated delivery. Implemented off-by-default with full
  tests, then **formally verified by the author** — the machine-checked soundness of the FRI/STARK object
  (Lean 4 STARK-soundness blueprints), the added ZK-masking property (§4b.1), and the circuit relations for
  each predicate — before it is ever a ship default. This is the audit-before-ship gate for novel crypto
  (#73), discharged by formal proof rather than eyeball review. The three sharp risks (§4b) are explicit
  verification obligations; an external cryptographer pass on the *formalization* remains advisable.
- **Vouching (Sub-spec C, #67)** consumes the shared attestation layer defined in §4c.

This delivers the *whole* design (nothing deferred vaguely, the hard crypto specified concretely) while
refusing to ship unaudited novel crypto — the responsible reading of "don't take the weak path."

---

## 10. Open questions for the reviewer / next brainstorm
- Grouping revocation (a leaf leaves a grouping) — dynamic accumulator vs. epoch-rotate the grouping key.
- Quorum parameter `k` and attestor-eligibility policy (who may attest — any member, or only account-linked?).
- Circle-STARK (stwo, M31) vs Plonky3 (BabyBear/KoalaBear) once ZK-masking configs mature — perf/audit tradeoff.
- Whether `DerivedFromKnownSet` should also hide the *set size* (leaks a little about the verifier's graph).
