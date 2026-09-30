# Sub-spec D1 — Serverless store-and-forward (offline message delivery)

**Status:** design for review.
**Scope:** Rust core + transport (`crates/core`, `crates/transport`), with FFI surface for
the app tiers. No app UI in this spec (the UI to *opt a room in* is Sub-spec D2).
**Parent:** #48 "ephemeral→persistent promotion." This is the delivery *engine* — what
"persistent" actually means functionally: messages survive participants being offline. D2
(promotion control plane) and D3 (retention contract) build on it.

## Goal

talkrypt has **no server**, and users must be able to **turn their phones off**. Today a
message sent to an offline recipient is simply lost: the relay/host forwards live only
(`relay.rs` drops frames for peers not currently connected; `engine.rs` `pending` is an
online-only pre-ratchet buffer). This sub-spec adds **serverless store-and-forward** so a
message reaches its recipient when they come back — with **no plaintext ever visible to a
holder** (E2E preserved) and **no metadata leak beyond what the relay already sees**.

## First principle: holders store opaque, authenticated ciphertext only

Every stored item is an already-encrypted frame (`Routed{to, from, inner}` where `inner`
is group-AEAD or DR ciphertext). A holder (keeper/anchor/replica) has **no group key**, so
it cannot read content — exactly the blind-`RelayHub` trust boundary (`relay.rs:9-12`) we
already ship. Store-and-forward changes *when* a frame is delivered, never *who can read it*.

## Architecture — four layers on the existing primitives

All four **drive the `KeepAlive` policy that already exists as stubs** in
`crates/server/src/keepalive.rs` (`AlwaysOn` / `ClientAnchored` / `ReplicatedFailover`,
each a `should_publish(ctx) -> bool` with no I/O yet). This sub-spec gives them storage +
delivery I/O. Reused primitives (do not reinvent): the signed `RouteDescriptor` gossip +
`reconnect()` reachability layer (`engine.rs:961-1030`), `SeenSet`/`gossip_id` =
SHA-256(ciphertext) dedup (`engine.rs:517-552`), the `Routed`/`Route` envelope
(`engine.rs:337-372`), persistent-onion `state_dir` (`transport/src/arti.rs:47-54`), and
the blind `RelayHub` forwarding core (`relay.rs`).

### Layer 0 — Persistent outbox (the foundation; always on for persistent chats)

The sender is the first line of defense. On send, in a persistent chat, the frame is
**persisted to a sealed on-disk outbox** keyed by its `gossip_id`, alongside the target
`Route`. It stays until a **`Frame::DeliveryAck`** (new, tag 13) for that `gossip_id`
arrives. `reconnect()` (already the partition-heal trigger) and peer-online events flush the
outbox: re-send every un-acked frame to now-reachable targets. Dedup at the receiver uses
the existing `SeenSet` (`gossip_id`), so a re-send is idempotent — a receiver that already
processed it just re-acks.

- **No loss whenever anyone bridges the gap.** If sender and receiver are ever online in
  overlapping windows (directly or via any relay), delivery completes.
- **Storage:** `outbox/<chatId>/<gossip_id>.tkf` = `seal_secret(Routed encoding)` via the
  Phase-1 seal seam (hardware-wrapped where available). Bounded: a per-chat cap
  (`MAX_OUTBOX_FRAMES`, default 4096) and a TTL (`OUTBOX_TTL`, default 30 days); on
  overflow, oldest un-acked dropped with a `log()`-style event (never silent).
- **`DeliveryAck`** carries `Vec<[u8;48] gossip-id-prefix>`? No — carries a fixed-capacity
  batch of acked `gossip_id`s (see wire, below), signed at the transport/pairwise layer it
  already rides (no new group-auth surface: an ack only clears *your own* outbox).

### Layer A — Group keeper (an online member buffers for offline members)

Extend the blind `RelayHub`/an online member so that when it would forward a `Routed` to a
target that is **not currently connected**, it instead **persists** the frame in a
per-recipient bounded queue and delivers it when that recipient reconnects (detected via the
existing route gossip / accept loop). The keeper holds only ciphertext. Drives
`KeepAlive::AlwaysOn`. Bounded per-recipient queue (`MAX_KEEP_PER_PEER`), TTL, sealed at
rest. Multiple keepers are fine (dedup by `gossip_id` prevents double-delivery; the receiver
acks once).

### Layer B — Personal anchor mailbox (self-hosted availability)

A user optionally runs an **always-on device** (desktop, or a phone in `ALWAYS_ON` mode from
#47) that hosts a **persistent-onion mailbox** endpoint. The mailbox is advertised as one of
the user's routes via the existing signed `RouteDescriptor` (`advertise_routes`). Senders
that can't reach the user's phone drop the sealed frame at the user's **anchor onion**
(`Frame::MailboxPut`, tag 14); the phone, on wake, **pulls** from *its own* anchor
(`Frame::MailboxFetch`, tag 15) and acks. Drives `KeepAlive::ClientAnchored`. The anchor is
the user's own trusted device, so it may hold slightly richer routing metadata (recipient =
self) but still **no plaintext**.

### Layer C — Replicated queue (survive everyone-offline)

*k* online members (a small quorum, default k=3, configurable) **replicate** the pending
queue and run **anti-entropy** on reconnect: on connect, two replicas exchange the set of
`gossip_id`s they hold for still-offline recipients and pull what they're missing; a
`gossip_id` is GC'd across replicas once a `DeliveryAck` for it is observed. Survives all
members being offline simultaneously (delivery waits, no loss) with no single designated
node. Drives `KeepAlive::ReplicatedFailover`. Highest complexity → built last.
`Frame::QueueSync` (tag 16) carries a bounded batch of `(gossip_id, recipient_fp)` digests.

## Wire additions (FV-preserving — see the contract below)

New `Frame` tags (13+ free, unknown-tag-safe; `engine.rs:221` decode `_ => None`). Coherent
allocation across the #48 sub-specs: **13/14 are reserved for D2** (`Promote`/`Consent`), so
D1 takes **15–18**:

| tag | frame | payload (all flat / bounded) |
|---|---|---|
| 15 | `DeliveryAck` | `count: u8` (≤ `MAX_ACK`) then `count × [u8;32]` gossip-ids |
| 16 | `MailboxPut` | `recipient: [u8;48]` ‖ `frame_len: u32` ‖ opaque sealed frame bytes |
| 17 | `MailboxFetch` | `since: [u8;32]` cursor (0 = all) — returns a stream of frames |
| 18 | `QueueSync` | `count: u8` (≤ `MAX_SYNC`) then `count × ([u8;32] gossip-id ‖ [u8;48] recipient)` |

Every new decoder returns **flat / fixed-capacity** types (arrays of `[u8;N]` + `u32` length
prefixes for the single opaque blob) — the `bounded::decode` shape — so each gets a **Kani
`*_never_panics` proof** in the same PR. No new nested `Vec<Struct{String,Vec}>`. The wire
`Reader`/`Writer`/`MAX_FRAME` and its three frozen Kani harnesses are untouched.

## FV-preservation contract (this sub-spec's hard gate)

1. Never edit `crates/wire/src/lib.rs` codec or its Kani harnesses.
2. New frames use tags 13–16 (free) / `Route` tags 3+; decoders follow the
   `bounded::decode` + `DecodeTotality.fst` template (fixed arrays, bound-check-before-index,
   no nested heap) and ship a Kani proof or an explicit fuzz+50k-property test.
3. Store-and-forward touches **delivery timing + storage**, not the group-auth protocol, so
   `GroupAuth.fst` / `GroupAuthQROM.ec` are unaffected (a keeper still holds only ciphertext;
   `DeliveryAck` clears only the acker's own outbox and is not a group-attribution signal).
4. The queue GC / anti-entropy *logic* (HashMap/Vec heap) is CBMC-intractable → covered by
   an exhaustive property test (like the antibody invariant), asserting: no frame is
   delivered after its `DeliveryAck`, no un-acked frame is GC'd before TTL, dedup by
   `gossip_id` is idempotent.

## Data flow (Layer 0 + A, the MVP)

1. Send in a persistent chat → append sealed frame to `outbox/<chat>/<gid>.tkf`; attempt live
   send.
2. Target offline → an online keeper persists the `Routed` in `keep/<recipient>/<gid>.tkf`.
3. Recipient reconnects → keeper replays its queued frames; recipient processes (dedup via
   `SeenSet`) and emits `DeliveryAck([gid…])`.
4. Ack reaches sender + keeper → both delete `<gid>` from outbox/queue.
5. TTL/cap enforcement runs on a debounced timer; drops are surfaced as a system event.

## FFI + app surface (thin)

- `Core::set_persistence(chatId, on)` — enables Layer 0 outbox for a chat (D2 flips this on
  promotion). `Core::keeper_mode(on)` — opt in as a group keeper. `Core::anchor(onion,
  state_dir)` — register a personal anchor. `Core::replica_quorum(k)` — Layer C.
- `FfiEvent::Delivered{gossip_id}` and `FfiEvent::OutboxDropped{chatId, count}` so the app can
  render delivery receipts + surface capped drops.

## Testing

- **Core unit:** outbox seal→persist→flush→ack→delete round-trip; cap/TTL eviction; keeper
  buffer-and-replay; dedup idempotency; the exhaustive delivery-safety property test.
- **`LoopbackFabric` integration:** host + 2 members, member B offline while A sends →
  B reconnects → receives, acks, sender outbox drains. Everyone-offline (Layer C) → all
  return staggered → each message delivered exactly once.
- **Kani:** `delivery_ack_decode_never_panics`, `mailbox_put_decode_never_panics`,
  `queue_sync_decode_never_panics` (flat/bounded harnesses).
- **On-device (Seeker + A23):** turn phone B off mid-conversation; turn back on hours later;
  confirm the backlog arrives; kill the app and confirm the outbox survives restart.

## Sequencing (this sub-spec)

Spec covers all four layers so the seams (`KeepAlive` driver, the `Routed` envelope, the ack
protocol) are right. **First implementation plan delivers L0 + LA** (the MVP that makes "turn
your phone off" work). L B (anchor) and L C (replicated) are later plans against this spec.

## Out of scope (other sub-specs)

The coordinated **promotion** that opts a room into persistence (D2); the **retention**
contract for the ephemeral backlog (D3); the app UI. This sub-spec assumes a chat is already
marked persistent and provides the delivery guarantee.
