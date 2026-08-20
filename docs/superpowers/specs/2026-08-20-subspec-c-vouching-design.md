# Sub-spec C — Vouching + Weighted Vouch-Threshold Coloration — Design

> Feature #58 family, **Sub-spec C** (task #67). Fills the reserved `Tint::Vouched` render slot
> (Sub-spec A reserved it; B fills `Tint::Isolated`; C fills `Tint::Vouched`). Builds on the shipped
> A (names/CQ/trust-render surface) and B0 (linkage/opsec + the `Predicate`/attestation seam).
> **Status:** design draft for review.

**Goal:** Let members **vouch** for each other (web-of-trust; ML-DSA-signed, PQ-unforgeable, account-bound),
and render a **distinct "more-trusted" tint** when a subject clears a **weighted, multi-scope** vouch
threshold. The whole thing rests on **audited ML-DSA-87** — no zero-knowledge, **not gated on Backend-1 /
formal verification**; it's a B0-sized, immediately-buildable feature that reuses B's §4c attestation type.

---

## 0. Intent (from the user)
- Vouch **targets** are plural — account, name↔account binding, and bare leaf are **all supported**
  (different use cases: account = durable trust; name-binding = "this callsign really is them here"; leaf =
  minimal, for opsec-clean pseudonyms).
- The threshold is a **weighted config**, set at **multiple scopes** (user *and* chat), not a flat count.
- Voucher eligibility is plural — **direct / contacts-only / transitive** are all expressible.

## 0.5 Ethics & threat model — HARD INVARIANTS (this must NOT become a social-credit system)

**Threat model:** threat actors, governments, criminals, dystopian surveillance actors, and foreign &
domestic intelligence/infosec operators. C is a **trust HINT**, never a reputation currency, gate, or
punishment. The following are non-negotiable invariants; every mechanism below is constrained by them and
tests must enforce them.

1. **Strictly additive, non-exclusionary — there are NO negative vouches.** There is no downvote, distrust,
   flag, or "de-vouch as attack." A vouch only ever *adds* a positive "more-trusted" hint. **Absence of
   vouches = neutral**, rendered exactly as A/B leave it — never "distrusted," never dimmed, never
   excluded. This is the structural reason C cannot isolate anyone: the worst a hostile mob (or a
   government running N sock-puppets) can do is *withhold* vouches, which leaves the target **neutral and
   fully able to participate**, not isolated.

2. **Trust ≠ credit ≠ access — separable by construction.** The vouch score is **display-only in C and
   NEVER gates participation**. It does not affect who can join, speak, or read. (Access control is B's
   separate, explicit, per-chat *opt-in* `access_predicate` — and even there it is the host's deliberate
   choice, not a global score.) Wiring the vouch tint to access is **out of scope and cautioned against**;
   if a future feature ever gates on vouches it must be per-chat opt-in, reversible, and clearly marked —
   never a default or a global standing.

3. **Always recoverable; anyone can catch up.** Vouch state is **per-chat/context-scoped, epoch-superseding,
   and revocable** — there is **no permanent or cross-chat record**, so a fresh or re-keyed identity starts
   **neutral, not behind**. Any eligible member may vouch anyone (no gatekeeping of who *can be* vouched).
   **Hyperinflation of trust cannot cause permanent isolation:** because the tint is additive-only, an
   inflated environment only makes the tint *less informative*, never makes a newcomer *worse than neutral*
   — the catch-up path (earn vouches like everyone else) is always open. Thresholds SHOULD be relative
   (percentage of eligible) and/or capped so an inflated absolute bar can't strand newcomers; the
   non-exclusion invariant (1) is the ultimate backstop.

4. **The measure must not be exploitable or manipulable.**
   - *Inflation / sock-puppets:* N sybil accounts cast N vouches, so raw count is not trusted — the
     **weighting** (a viewer counts its own friends/contacts more than strangers) and **eligibility**
     (contacts-only) are the defenses, and **B's grouping/sybil-count deflates** colluding vouchers (a
     grouping proof reveals several "vouchers" are one person → their weighted contribution collapses).
   - *Coercion:* a coerced vouch is **revocable**, and being additive-only it can only inflate someone, not
     isolate a target.
   - *Weaponization to isolate:* structurally impossible (invariant 1) — no negative signal exists.
   - *Surveillance / social-graph mapping:* vouches ride **inside the encrypted / group-epoch channel**,
     are **per-chat context-scoped** (no cross-chat graph is built), and never appear in cleartext or the
     invite. **Anonymous vouching** ("prove ≥ threshold vouchers without revealing which") is a **Backend-1
     ZK follow-up** (`MemberOfKnownSet` over the voucher set) for when metadata-resistance must be stronger.

## 1. The vouch (audited ML-DSA attestation)

A **Vouch** is B's §4c attestation specialized to identity trust — signed by the voucher's **account key**
(so it is PQ-unforgeable and account-bound; a pseudonym with no account cannot vouch):

```rust
struct Vouch {
    target: VouchTarget,
    context: [u8; 32],   // chat_context(invite_token ‖ channel) — as A/B; scopes the vouch to THIS chat
    epoch: u64,          // supersede/anti-replay per (voucher, target)
    sig: Vec<u8>,        // voucher ACCOUNT ML-DSA sig over (target ‖ context ‖ epoch)
    voucher: AccountPub, // the voucher's account public (verifier binds it to a presented identity chain)
}

enum VouchTarget {
    Account([u8; 48]),                                   // durable: vouch the account key
    NameBinding { account: [u8; 48], name_tag: [u8; 8] },// "this name (A's name_tag) really is this account here"
    Leaf([u8; 48]),                                      // minimal: vouch a bare per-chat leaf (no account)
}
```
- **Unforgeable + account-bound:** the sig requires the voucher's account private key; the verifier accepts
  a vouch only from an account it has *seen a valid identity chain for* in this chat (reuse
  `handle_identity`/`resolve_chain` — the voucher must have presented that account), so a vouch can't be
  attributed to an account that never spoke.
- **Anti-abuse (viewer-enforced):** dedup by **distinct voucher account** (one effective vouch per voucher
  per target); **no self-vouch** (voucher account == target account is dropped); `epoch` monotonic per
  (voucher, target); a voucher may **revoke** (higher-epoch empty/withdraw vouch) — reuses the existing
  `Revocation` pattern for the account-signed unforgeability.
- **Context-bound:** a vouch made in chat X does not count in chat Y (the `context` differs), matching B's
  grouping/linkage anti-replay.

## 2. Weighted, multi-scope evaluation (the load-bearing generalization)

Not "≥ k vouches" but a **weighted score ≥ threshold**, computed under a policy composed from two scopes.

```rust
/// How much a single vouch counts, from the VIEWER's perspective.
struct VouchWeighting {
    friend: u32,     // a vouch from one of the viewer's friends
    contact: u32,    // ...from a contact
    stranger: u32,   // ...from an account-linked member the viewer doesn't know
    // transitive vouches (if enabled) decay by depth: effective = base_weight >> (depth-1)
}

enum VoucherEligibility {
    AnyLinked,                 // any account-linked member may vouch
    ContactsOfViewer,          // only the viewer's own contacts/friends' vouches count
    Transitive { depth: u8 },  // web-of-trust: vouches chain, bounded depth, decayed weight
}

struct VouchPolicy {
    eligibility: VoucherEligibility,
    weighting: VouchWeighting,
    threshold: Threshold,      // Count(u32 weighted-score) | Percent(u8 of eligible weighted-max)
}
```

- **Chat scope (baseline, in the descriptor v4):** the host sets a `VouchPolicy` conveyed to all members
  (eligibility + a default weighting + threshold). This is the *chat's* notion of "more-trusted".
- **User scope (local, overrides):** the viewer may set **their own** `VouchWeighting` and `threshold`
  (e.g. "only my friends' vouches count, and I need weighted ≥ 5"), computed **locally** over the vouch set
  it has collected. **Precedence — user-trumps-group in the protective direction:** the viewer's effective
  decision may be **stricter** than the chat baseline (require more), never forced weaker — a subject is
  tinted `Vouched` for a viewer only if it clears the viewer's *effective* (max of user/chat strictness)
  weighted threshold. (Mirrors A's "user may render stricter, never weaker" and B's disclosure≠display.)
- **`Percent` denominator:** the weighted-max over the *eligible* voucher set present (distinct
  account-linked members under the eligibility rule) — well-defined per viewer, per moment.

**Decision:** `weighted_score(subject) = Σ over distinct eligible vouchers v: weight(v)` (transitive
vouches decayed by depth); if `weighted_score ≥ effective_threshold` → `Tint::Vouched`, and the render
carries the **weighted count / score** as a badge (e.g. "✳ vouched · 5").

## 3. Render (fills the reserved `Tint::Vouched` slot)

`resolve_render` (A's surface, extended by B) gains a `vouch_score`/`vouched: bool` input; precedence:

```
Vouched (cleared threshold)  >  Verified (Linked/RegistryConfirmed)  >  Isolated (B)  >  Default
```
i.e. a name that is BOTH verified and vouched shows the **Vouched** tint (the stronger, peer-corroborated
signal) with the verified badge retained. `caveat`/badge carries the weighted vouch count. A subject below
threshold renders exactly as B/A leave it (no regression).

## 4. Wire + propagation

A `Vouch` rides the **existing signed paths** (pairwise `Frame::Presence` / signed group `GroupMsg`) behind
a new `VOUCH_SENTINEL = 0xF7` (distinct from A's `0xF5` presence, B's `0xF6` linkage), reusing the
propagation + dedup + seq machinery. `handle_vouch(inner, voucher_fp, bytes)`:
1. decode; verify the voucher account sig over (target ‖ context ‖ epoch); bind `voucher` to an account the
   viewer has authenticated this chat (else drop); reject self-vouch; enforce epoch monotonicity per
   (voucher, target); honor revocations.
2. record `vouches: (target) → map<voucher_account_fp, (epoch, weight-relevant relationship)>`.
3. recompute the subject's weighted score under the effective policy; if the `Vouched` state changed, emit
   `Event::Vouch { subject, weighted_score, vouched: bool }`.

**Descriptor v4** (append-only, v1–v3 back-compat + fuzz round-trip guard, as v2/v3): carries the chat
`VouchPolicy` baseline (eligibility tag + default weighting + threshold). v1/v2/v3 invites decode with a
default (vouching off / threshold ∞ → never tinted).

## 5. Client surfaces (core → FFI → CLI → Android/desktop)
- Core: `Core::vouch_for(VouchTarget)`, `Core::revoke_vouch(VouchTarget)`, `Core::set_vouch_weighting(...)`,
  `Core::set_vouch_threshold(...)` (user scope), `Core::set_chat_vouch_policy(...)` (host → descriptor),
  `Core::vouch_score(subject) -> u32`; `Event::Vouch { subject, weighted_score, vouched }`.
- FFI/CLI/Android/desktop: a "Vouch for" action on a roster member; the Vouched tint + weighted-count badge
  on names/bubbles; host vouch-policy control in the New-Chat advanced foldout; user weighting/threshold in
  settings. CLI: `/vouch <fp>`, `/unvouch <fp>`, `/vouchpolicy ...`, `/vouches` (list). Mirror B0's surface wiring.

## 6. Security considerations
- **Unforgeable + account-bound** (ML-DSA account sig; voucher must have presented that account) — a sybil
  with no account cannot vouch, and vouches can't be attributed to a silent account.
- **Sybil resistance is honest, not absolute:** N sybil accounts can cast N vouches — so the **weighting**
  (a viewer trusts its friends' vouches more) and **eligibility** (contacts-only) are the real defenses,
  and the UI is honest that stranger-vouches are weak. This composes with **B's grouping/sybil-count**: a
  grouping proof reveals that several "vouchers" are one person, deflating their weighted contribution.
- **Self-vouch dropped; distinct-voucher dedup; context + epoch binding; revocable.** All viewer-enforced.
- **Transitive web-of-trust is depth-bounded + weight-decayed** to cap amplification; direct-only is the
  conservative default.
- Confidentiality: vouches ride inside the encrypted/group-epoch channel — never cleartext, never in the invite.

## 7. Testing
- Unit: `Vouch` encode/decode + KAT; account-sig verify (valid/forged/self-vouch/wrong-context/revoked);
  weighted-score math (count + percent, per-relationship weights, transitive decay); descriptor v4
  round-trip + v1–v3 default + re-encode fuzz-guard; render precedence (Vouched > Verified > Isolated).
- Integration (`LoopbackFabric`): a 3-member group where two members vouch a third → the third clears the
  threshold and a fourth viewer sees `Tint::Vouched` with the weighted count; user-stricter-than-chat
  (viewer requires more → NOT tinted though chat baseline is met); a sybil grouping (via B) deflates the
  weighted score; revocation drops the tint.
- Adversarial (like the B hardening PRs): forged voucher sig / self-vouch / cross-chat replay / stale-epoch
  all rejected; no unforgeable-vouch bypass.

## 8. Staging
- **All of C is buildable on audited ML-DSA now** (no ZK, no Backend-1 gate) — ship it as one B0-sized
  plan: vouch type + verification, weighted multi-scope evaluation, `Tint::Vouched` render, descriptor v4,
  propagation, surfaces, tests. It **shares the attestation type** defined in B design §4c (so if/when
  Backend-1 lands, ZK-predicate attestations and identity vouches use one mechanism).

## 9. Out of scope / follow-ups
- Global (cross-chat) reputation aggregation — C is per-chat/context-scoped by design.
- ZK "vouch without revealing which voucher" — that's a Backend-1 predicate (`MemberOfKnownSet` over the
  voucher set), a follow-up once B1 is verified.
- Richer transitive web-of-trust policies (trust metrics beyond depth-decay).
