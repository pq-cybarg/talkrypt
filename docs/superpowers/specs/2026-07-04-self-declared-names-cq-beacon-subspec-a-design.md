# Self-Declared Names + CQ Name Beacon — Sub-spec A Design

> Feature #58, decomposed. This is **Sub-spec A** (the foundation). Sub-specs B and C
> are scoped at the end and get their own brainstorm → spec → plan cycles.

**Goal:** Let a participant broadcast a self-declared "callsign" (name) that renders over
their messages to **every** member of a chat — pairwise or group — with honest trust tiers
(bare / account-linked / registry-confirmed) and a periodic "CQ" beacon, without ever letting
an unverified name be mistaken for a verified one.

**Status:** design approved through the interactive brainstorm (mechanism, trust display,
multi-name, architecture Approach 1, Sections 1–3 explicitly; 4–6 presented). Awaiting spec review.

---

## 0. Context & decomposition

Feature #58 ("self-declared callsigns + CQ name beacon") grew, during brainstorming, into a
family of trust/identity features. It is decomposed into three sub-projects, each independently
shippable, built in order:

- **Sub-spec A (this doc):** self-declared *leading* name + CQ beacon + trust display. Delivers
  working software on its own.
- **Sub-spec B (future):** multi-identity **linkage disclosure** & opsec modes — user-level
  policy `Opsec-clean` / `Opsec-selective (groupings)` / `Fully-transparent (+ hide-transparency)`;
  an **isolated-identity** sybil marking (subtle coloration, not a loud warning); per-chat
  *show-all-associated-identities* vs *just-foremost*; **user policy trumps group policy**; needs
  linkage-proof crypto over the existing segment / account-linking machinery.
- **Sub-spec C (future):** **vouching** (web-of-trust; signed, PQ-unforgeable, account-bound) +
  chat-configurable **vouch count/percentage thresholds** → a distinct "more-trusted" name tint.

A is the layer B and C decorate: A renders the single **leading** name (the identity you signed
in as); B decides what shows *around* it and how isolation is marked; C tints it by vouch count.
So **A must expose an extensible name-render surface** (badge + color slot) that B and C plug
into without touching rendering plumbing.

### Settled requirements (from the user, verbatim intent)
- Declare a name **up front and mid-chat**; a user has **multiple names**; optionally
  **registry-backed** for verification (one or several registries, cross-compared).
- A **continuous "CQ CQ this is <name>"**-style periodic beacon so all participants see a
  self-declared (or registry-backed) name over your messages.
- **All three** emission modes available (event-driven, periodic timer, name-on-every-message).
- **All three** trust-display policies available as a **per-chat setting chosen at creation**,
  **Signal-style default**, tucked in a collapsed "advanced" foldout.
- Multi-name: a **name book**; **one leading name active per chat** (= your sign-in identity),
  **switchable mid-chat**. (Showing *other* identities alongside it is Sub-spec B.)

---

## 1. Codebase grounding (what exists today)

- **Self-declared label today = `username: Option<String>`** inside `Presentation { chain, username }`
  (`crates/core/src/contacts.rs`), sent as `Frame::Identity` (tag 6) — the *first frame inside the
  encrypted session* — and verified by `handle_identity` (`crates/core/src/engine.rs`), which
  **binds** `chain.leaf().fingerprint() == authenticated transport-peer fp`, verifies the chain via
  `contacts::resolve_chain`, checks pinned contacts, and emits `Event::Identity`.
- **Identity presentation is pairwise-only.** In `engine.rs`, `Frame::Identity` is handled for
  `GroupRole::None` (full path → `Event::Identity`) and for `GroupRole::Host` **only** to record
  access admission (`handle_group_member_identity`, ~engine.rs:1291-1296). **Group *members* never
  receive another member's name** — group attribution is purely `Roster` (leaf→fingerprint). Since
  all Nym chats are now TreeKEM groups, this is the core gap #58 closes.
- **Group message crypto is sender-key, NOT per-sender-signed** (`crates/crypto/src/treekem.rs`):
  `encrypt`/`decrypt` derive a per-sender chain `sender_chain(epoch_secret, leaf)` from the shared
  `epoch_secret`; `sender_leaf(ct)` reads the claimed leaf from the framing for roster attribution.
  **Every member knows `epoch_secret`, so any member can derive any other member's sender chain and
  forge another member's `sender_leaf`.** Group attribution is therefore sound against *outsiders*
  but **spoofable by a malicious insider.** (Full per-sender signatures = the MLS-PQ upgrade in
  `docs/plans/0002-mls-pq.md`, out of scope here.) **This is the decisive security fact for A.**
- **Group broadcast + gossip + dedup already exist**: `handle_group_msg` decrypts, attributes via
  `sender_leaf`→`roster`, emits `Event::Message`, then fans out (committer) / re-floods (gossip),
  with `SeenSet` SHA-256 dedup (`gossip_id`). Presence reuses this path wholesale.
- **`Frame` enum** (`engine.rs`) uses tags 0–8; `decode` falls through unknown tags to `None`
  (append-only-safe). `Frame::Chat` (tag 0) is the pairwise message; `Frame::GroupMsg` (tag 4) is
  the group message. **Presence mirrors this dual.**
- **"Beacon" is already taken**: `crates/crypto/src/beacon.rs` + `crates/core/src/advert.rs` are the
  *crypto-scheme* advertisement subsystem. **This feature must NOT reuse the `beacon` name.** We use
  **`Presence`** (types/frames) and **"CQ"** (user-facing verb).
- **Registry cross-compare** (`crates/crypto/src/account.rs::cross_compare`, `core/src/registry.rs`)
  already verifies a username → account agrees across independent registries; a hostile registry can
  omit but never fabricate a name. Registry-confirmed tier reuses this.
- **`ChatDescriptor`** (`crates/core/src/descriptor.rs`) is version-gated (`DESCRIPTOR_VERSION = 1`)
  and KAT-locked; it already carries an advisory display field (`channel_marking`).

---

## 2. Data model & trust tiers

**Name book** (per device, persisted by each client):
```rust
struct NameBook { entries: Vec<NameEntry>, default: Option<NameId> }
struct NameEntry {
    id: NameId,             // stable local id
    label: String,          // the callsign, bounded ≤ 48 chars, NFC-normalized, control-stripped
    backing: NameBacking,
}
enum NameBacking {
    Bare,                             // self-asserted, no key — cosmetic, insider-spoofable
    Account { chain: IdentityChain }, // rooted at your ML-DSA account; leaf = this device key
}
```
Registry-confirmation is **not stored** — it is a *viewer-side* elevation: on receiving an
`Account`-backed name, a viewer may `cross_compare` that account against *their* trusted registries
and raise the display tier if the name agrees.

**Leading name per chat:** at host/join you select one `NameEntry` as the chat's leading identity
(your sign-in identity). Default = no name (today's unlinkable pseudonym) unless set. Switchable
mid-chat (fires a fresh CQ). Stored per session / `ChatMeta`.

**Three display tiers (resolved at the viewer):**

| Tier | Sender proves | Insider-forgeable? | Badge |
|------|---------------|--------------------|-------|
| **Bare** | nothing — a cosmetic label | **Yes** | (none / "unverified") |
| **Account-linked** | device-key signature + cert chain to an ML-DSA account | **No** (PQ) | 🔗 |
| **Registry-confirmed** | account-linked **and** name cross-compares across the viewer's registries | **No** | ✓ |

The trust display is honest that only 🔗/✓ resist a malicious group member; bare names are
convenience labels. This is *why* the collision policies (§5) exist.

---

## 3. Wire format & propagation

One payload type, delivered by two thin adapters mirroring `Frame::Chat` (pairwise) vs
`Frame::GroupMsg` (group).

```rust
enum NamePresence {
    Bare   { seq: u64, label: String },
    Linked { seq: u64,
             presentation: Presentation, // chain: account→device leaf; username = Some(label)
             context: [u8; 32],          // binds to THIS chat
             sig: Vec<u8> },             // device-leaf sig over (seq ‖ label ‖ context)
}
```
- **`seq`** — monotonic per sender; the viewer keeps the highest seq per identity → later
  re-declaration supersedes, stale replays drop.
- **`context`** — SHA-256 of this chat's identity (descriptor invite-token ‖ channel). Prevents a
  signed `Linked` presence from being replayed into a *different* chat to impersonate.
- **`sig`** — the **device leaf key** signs `(seq ‖ label ‖ context)`. This is the
  insider-unforgeability anchor: spoofing the group `sender_leaf` does not yield a valid device
  signature for someone else's account.

**Delivery:**
- **Pairwise (`GroupRole::None`):** new `Frame::Presence(Vec<u8>)` at **tag 9**, sent directly over
  the encrypted pairwise session (like `Frame::Chat`); bound to the authenticated transport-peer fp,
  reusing `handle_identity`'s binding.
- **Group (Host/Member):** presence becomes a new **group-payload kind** inside the existing
  `Frame::GroupMsg` envelope. The group plaintext (today decoded by `marking::decode_payload`)
  becomes a tagged union `GroupPayload::{ Chat { marking, text } | Presence(NamePresence) }`.
  `handle_group_msg` dispatches: `Chat → Event::Message` (unchanged), `Presence → verify → Event::Name`.
  Presence thus inherits the entire existing path: committer fan-out + gossip re-flood + `SeenSet`
  SHA-256 dedup + `sender_leaf` attribution.

**Group verification, on `Presence(Linked)`:**
1. `presentation.chain` verifies and roots at a known account (`resolve_chain`).
2. `sig` verifies under the chain's device-leaf public key over `(seq ‖ label ‖ context)`.
3. `context` matches this chat.
4. The chain leaf is not revoked (checked against stored `Revocation`s, as `handle_identity` does).
5. Cache `account_fp → { label, tier: Linked, seq }`; associate with the sender; emit `Event::Name`.
   Registry-confirmed is an async client-side elevation via `cross_compare`.

`Presence(Bare)` in a group caches `roster[sender_leaf] → { label, tier: Bare, seq }` — honestly
`Bare`, because that attribution is the spoofable sender-key.

**Back-compat:** `Frame::Presence` tag 9 is append-only (old clients ignore via `_ => None`); the
group-payload union tag likewise falls through. Group presence auto-dedups via existing `gossip_id`.
No descriptor bump for presence itself. (The per-chat `NameTrustPolicy` in §5 *does* bump the
descriptor — that is a separate, deliberate change.)

---

## 4. Emission / cadence (the CQ beacon)

Always-on correctness plus two optional amplifiers; the three user-requested modes compose.

**1. Event-driven (baseline — on whenever a leading name is set):**
- **On join/host:** announce eagerly after session/group entry — following the existing
  eager-vs-reactive rule (a ratchet responder presents reactively after its first decrypt) so no
  presentation is silently dropped.
- **On roster-grow:** re-announce when a new leaf appears (member) or is admitted (host); **debounced**
  to coalesce join bursts.
- **On manual change:** switching the leading name emits a presence with `seq+1`.

**2. Periodic CQ timer (optional, configurable):** slow re-beacon every N minutes. **Default off;**
enabled → sane default (5 min) with an enforced **minimum floor**. Catches reconnects / late joiners
without roster-grow detection. Per-user setting, per-chat override.

**3. On-message name-id (optional):** stamp `seq` + truncated `SHA-256(label ‖ context)` onto each
outgoing `Chat`/`GroupMsg`. A viewer holding the matching cached name renders it immediately;
otherwise renders the safety-number and awaits a presence. Also detects staleness (name-tag ≠ cached
tag → cache stale). Makes a name reliably ride "over every message."

**Anti-spam / bounds (all viewer-enforced — a hostile sender cannot grief):**
- **seq monotonicity** — drop `seq ≤ last seen` per sender.
- **Per-sender rate floor** — accept ≤ ~1 presence / sender / few seconds; drop excess.
- **Roster-grow debounce.**
- **Label hygiene** — length cap, NFC-normalize, strip control chars; confusable-fold computed for §5.
- **Periodic floor** — minimum timer interval enforced regardless of the setting.

**Convergence:** event-driven covers joins/roster changes; on-message-id covers "I missed your
presence but you just spoke"; periodic covers "you went idle and I reconnected." Until a trigger
fires, an unresolved peer shows as their safety-number — never a wrong name.

---

## 5. Trust-render surface & `NameTrustPolicy`

**Extensible render surface (the hook B and C plug into):**
```rust
struct NameRender {
    label: Option<String>,   // None → safety-number only
    tier: NameTier,          // Bare | Linked | RegistryConfirmed
    badge: Badge,            // derived from tier
    tint: Tint,              // COLOR SLOT — A sets tier-default; B (isolation) & C (vouch) override
    caveat: Option<String>,  // e.g. a collision warning
    safety_number: String,   // always available on tap/hover
}
enum NameTier { Bare, Linked, RegistryConfirmed }
```
A owns the `tint` slot and populates only the **tier-default** color. A documented precedence
function computes the final tint, with explicit no-op hooks reserved for B (isolation coloration)
and C (vouch-threshold tint). B and C fill the hooks later without touching rendering plumbing.

**Per-chat policy (creation-time, advanced foldout, Signal default):**
```rust
enum NameTrustPolicy { SignalStyle, WarnOnCollision, SuppressColliding }   // default SignalStyle
```
It is a chat-creation setting → conveyed to all participants via the `ChatDescriptor`, requiring a
**`DESCRIPTOR_VERSION` bump 1 → 2**: v2 encodes the policy; v1 invites decode with policy defaulting
to `SignalStyle`; a v2 KAT vector is added alongside the existing v1 KAT. A viewer MAY locally choose
a **stricter** rendering than the chat baseline, never weaker — honoring "user policy trumps group"
in the protective direction.

**Collision detection:** compute a confusable-fold per label — v1 = NFKC + Unicode case-fold + strip
combining marks (so "Аlice" with a Cyrillic А collides with "Alice"); a full Unicode-confusables
skeleton is a noted refinement. When a lower-tier label collides with a higher-tier (Linked /
RegistryConfirmed) name held by a *different* account currently present in the chat:
- **SignalStyle** — show both with badges; no active warning (safety numbers do the work).
- **WarnOnCollision** — the lower-tier one gets ⚠ `claims to be <name> — unverified, does not match
  the verified <name>`.
- **SuppressColliding** — the colliding lower-tier label is not rendered as that name; replaced by
  its safety-number label + a suppression note.

---

## 6. Client surfaces (core → FFI → Android / desktop / CLI)

**Core (`crates/core`):**
- `Core::set_leading_name(Option<NameEntry>)` — set/replace this chat's leading name (fires presence).
- `Core::announce_presence()` — force a CQ now.
- `Core::set_presence_cadence(PresenceCadence { periodic: Option<Duration>, on_message_id: bool })`.
- `Core::set_name_trust_policy(NameTrustPolicy)` — host, at creation (→ descriptor).
- `Event::Name { from, account_fingerprint: Option<[u8;48]>, label: Option<String>, tier, seq,
  caveat: Option<String> }` — emitted when a peer's resolved name changes; generalizes `Event::Identity`.
- `NameBook` type + encode/decode for client reuse (persistence stays a client concern).

**FFI (`crates/ffi`):** expose `NameEntry` / `NameBacking`, the setters, name-book load/save helpers,
and `FfiEvent::Name { …, tier, caveat, safety_number }`. Host/join gain optional leading-name +
cadence + policy (or set post-construct).

**Android:** name-book screen (add/edit bare/linked/registry names), leading-name picker at host/join
+ a mid-chat switch, CQ toggles (periodic on/off + interval; on-message-id on/off), trust-policy in
the New Chat **advanced foldout**, and message bubbles rendering `NameRender` (label + badge + tint +
tap-for-safety-number + caveat). Name book in SharedPreferences (EncryptedSharedPreferences noted as
hardening, mirroring the nym mnemonic follow-up).

**Desktop (egui):** the same surfaces in the desktop UI.

**CLI:** `/name new|list|use <id>`, `/cq` (manual beacon), `/cq periodic <mins>|off`,
`host/join --name <id>`, `host --name-policy signal|warn|suppress`; names print with a tier glyph.

---

## 7. Testing

- **Unit (core/crypto):** `NamePresence` encode/decode round-trip + KAT; seq supersession; signature
  verify (valid / forged / wrong-context / revoked-leaf); confusable-fold collisions; each
  `NameTrustPolicy` render outcome; rate-limit + debounce; descriptor v1↔v2 round-trip + default.
- **Integration (`LoopbackFabric`):** 3-member group — a **member** announces a Linked name and the
  *other member* (not just the host) resolves it (proves the group gap is closed); gossip bridges two
  transport islands and a name propagates **exactly once** (dedup); **insider-spoof test** — a member
  forging another's `sender_leaf` cannot produce a valid Linked presence, so the bare attribution
  stays Bare/flagged; mid-chat re-declaration supersedes.
- **On-device:** two Android emulators over Nym (reusing the existing harness) — A sets a callsign, B
  sees it over A's messages; B switches name mid-chat, A sees the change; periodic CQ toggle verified.

---

## 8. Security considerations (explicit)

- **Group attribution is insider-spoofable** (sender-key crypto). Only signed **Account-linked** and
  **Registry-confirmed** names resist a malicious member. Bare names are cosmetic; the UI is honest
  about this via tier badges, and the `WarnOnCollision` / `SuppressColliding` policies exist precisely
  to stop a bare name impersonating a verified one. A full fix (per-sender signatures) is the MLS-PQ
  upgrade in `docs/plans/0002-mls-pq.md`, deliberately out of scope for A.
- **Replay across chats** is prevented by the `context` binding in a `Linked` presence.
- **Replay / reorder within a chat** is prevented by per-sender `seq` monotonicity.
- **Confidentiality:** presence rides inside the encrypted session (pairwise) or under the group epoch
  key (group) — names are never in cleartext or in the invite; a non-member relay/directory cannot
  read them.
- **Grief resistance:** all cadence/anti-spam limits are viewer-enforced.
- **Homoglyph impersonation** is mitigated by the confusable-fold collision check (v1 NFKC+casefold;
  full confusables table a refinement).

---

## 9. Out of scope for A — eventual features (tracked in the task list)

None of these are excluded; they are all planned follow-on work, each tracked as its own task so it
isn't lost. They are simply out of scope for Sub-spec A, which must ship working on its own.

- Showing **multiple identities** at once / linkage disclosure / opsec modes / isolation sybil marking
  / show-all-vs-foremost / user-trumps-group linkage precedence → **Sub-spec B** (task #66).
- **Vouching** and vouch-threshold coloration → **Sub-spec C** (task #67).
- Over-the-air **pre-session** discovery beacon: carry a self-declared name in
  `NearbyDiscovery.Peer.name` so BLE / Wi-Fi Direct advertise a callsign *before* any session exists.
  A is strictly *in-session*; this extends the nearby-discovery layer built earlier. → **its own task**.
- Replacing the sender-key group crypto with **per-sender signatures (MLS-PQ)** so group message
  attribution is insider-unforgeable end to end (`docs/plans/0002-mls-pq.md`). This would upgrade every
  group name tier — not just the signed presence — to insider-unforgeable. → **its own task**.
