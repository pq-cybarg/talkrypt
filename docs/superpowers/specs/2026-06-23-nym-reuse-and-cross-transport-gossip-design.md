# Nym credential reuse + cross-transport gossip — design

**Goal:** Let users reach the Nym mixnet *without entering a wallet mnemonic into
talkrypt*, reuse existing Nym tooling, and let chats that span different
transports (Nym + Tor + LAN) merge into one conversation via gossip — without
duplicate messages.

Three features, built as verifiable phases.

---

## Phase B — Ticketbook import (no mnemonic in talkrypt)

**Why:** A NYM wallet mnemonic controls funds; typing it into a chat app is a
heavy trust ask. A **ticketbook** is a spend-limited bandwidth credential — far
less sensitive. The user mints/exports it with Nym's *own* tooling (`nym-cli`),
where the mnemonic stays, and hands talkrypt only the ticketbook.

**Design:**
- `NymTransport::connect_with_ticketbook(state_dir, ticketbook_bytes)` —
  persistent `StoragePaths` + credentials mode; deserialize an
  `IssuedTicketBook`; `BandwidthImporter::import_ticketbook`; then
  `connect_to_mixnet()` (spends the stored credential, **no `acquire`**, so no
  on-chain purchase and no mnemonic).
- FFI: `nym_import_ticketbook(state_dir, ticketbook_b64) -> Result<()>` (import
  once), and `host_nym`/`join_nym` already key paid-vs-free off persistent
  storage — paid now means "a ticketbook is present," not "a mnemonic was given."
- Android: a "Import Nym credential" file picker; desktop: a path/env.
- Mnemonic path stays as an advanced fallback, **de-emphasized**. Free ephemeral
  mixnet (no credential at all) remains the default.

**Safety:** the wallet seed never enters talkrypt; only a bounded bandwidth
credential does. A leaked ticketbook costs at most its remaining bandwidth.

---

## Phase A′ — Unified message-level Nym protocol (SDK ⇄ nym-client interop)

**Problem:** the standalone `nym-client` exposes a localhost WebSocket
(`127.0.0.1:1977`, `{type:"send", recipient, message, withReplySurb}`) — true
mixnet addressing, autodetectable cross-platform. But the embedded SDK uses its
**Stream module**, whose on-mixnet framing is a different (unspecified) dialect.
A WS peer and an SDK peer could not talk over the same `nym:` address.

**Decision (per user): unify so both interoperate.** Define **talkrypt's own
minimal stream-over-datagrams framing** carried as raw mixnet *messages*, used
identically by:
- `NymTransport` (embedded) — switch from the Stream module to the SDK's
  message API (`send_plain_message` / `wait_for_messages` + SURBs).
- `NymWsTransport` (autodetect `:1977`) — the same framing over the WS JSON.

**Framing (`tk-nym/1`):** each datagram = `stream_id(16) ‖ seq(u32) ‖ flags(u8)
‖ payload`. flags: SYN (open), DATA, FIN. Reassembly orders by `seq` per
`stream_id`; replies route via SURBs so the dialer's address stays hidden. This
yields the same `Stream`/`FrameReader`/`FrameWriter` our `Transport` trait needs,
and is wire-identical regardless of embedded-vs-WS — so they interoperate.

**Autodetect:** probe `127.0.0.1:1977`/1978 for a nym-client WS at startup; if
present, offer it as a `Scheme::Nym` leg (desktop). Android stays embedded.

**Safety:** the talkrypt content frame (ML-KEM-1024 + ML-DSA-87 Double Ratchet /
group epoch) is unchanged and rides *inside* the payload — the nym framing only
chunks/orders ciphertext. The mixnet still sees only ciphertext + routing.

---

## Phase G — Cross-transport gossip mesh with dedup

**Scenario:** A↔B over Nym, B↔C over Tor (B multi-homed). The user wants {A,B}
and {B,C} to become one chat: A's message reaches C and vice-versa, bridged
through B, **without duplicates** even when multiple bridge paths exist.

**This rides the existing group substrate, which makes it E2E-safe for free.**
talkrypt already has TreeKEM group chats where messages are encrypted under a
**group epoch key** and a relay forwards the (still-encrypted) `Routed` frame
without reading it (`Route::Broadcast`, `new_relayed_group`). So a frame is *one
ciphertext any member can decrypt* — flooding that same ciphertext across every
transport a node is connected on needs **no per-hop re-encryption** and leaks no
plaintext to relays. Cross-transport bridging = a multi-homed node forwarding
the epoch ciphertext between its Nym peers and its Tor peers.

**Design — turn star-relay into epidemic gossip:**
1. **Frame ID for dedup:** add `msg_id: [u8;16]` to `Routed` (random, stamped by
   the *originator*, immutable across hops).
2. **Seen-set:** per `Core`, a bounded LRU/time-windowed `HashSet<[u8;16]>` of
   recently-forwarded ids.
3. **Forward rule:** on receiving a `Route::Broadcast` frame whose `msg_id` is
   new: record it, deliver locally if a member, and **re-broadcast to every peer
   except the one it arrived on**. If already seen: drop (kills loops + the
   duplicate the user called out). Optional hop `ttl` as a belt-and-suspenders
   bound.
4. **Multi-homed reach:** `MultiTransport` already lets a node host/dial on Nym +
   Tor + LAN at once, so "forward to every peer" naturally spans transports.

**Safety / threat model (explicit):**
- **Confidentiality:** preserved end-to-end — only group members (who hold the
  epoch key) decrypt; relays/bridges forward ciphertext blind. Adding transports
  or hops does not widen who can read.
- **Authenticity:** each frame is signed/ratcheted by its originator; a relay
  cannot forge, only forward or drop. Dedup uses the immutable `msg_id`.
- **Availability/trust:** a bridge node *can* withhold/drop (it's a router) — the
  same trust any relay node carries; gossip's multiple paths actually *reduce*
  this (a message can arrive via another bridge). No new confidentiality trust.
- **Amplification/loops:** bounded by the seen-set + optional ttl; a node never
  forwards the same `msg_id` twice.
- **Metadata:** dedup `msg_id` is random and per-message (no linkage); it is
  inside the epoch ciphertext envelope where possible, else only a relay-routing
  tag, never tied to identity.

**Out of scope (now):** partition healing/anti-entropy beyond live flooding;
store-and-forward for offline members; gossip of membership changes (commits
already propagate via the committer). These are follow-ups.

---

## Build order
1. **B** — ticketbook import (independent; no engine/crypto changes).
2. **A′** — unified `tk-nym/1` framing + `NymWsTransport` + autodetect.
3. **G** — `Routed.msg_id` + seen-set + gossip forward; cross-transport bridge.
Each phase: compiles, unit-tested, desktop + Android verified before the next.
