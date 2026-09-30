# Mesh messaging — carry chat frames over a LoRa broadcast — Design

**Status:** design + core build (engine wiring + tests + docs). FFI host-callback
surface and real-radio validation follow (device-gated). Builds on the merged mesh
bearer (`crates/transport/src/mesh`, PR #53).

**Goal:** let an established talkrypt group's chat **messages** ride a LoRa mesh
(Meshtastic / Meshcore) as an additional broadcast path — off-grid or as
resilience — carrying the *same* opaque, self-authenticating group frames the
engine already produces, with no change to the security model.

## Why this is small and safe (grounded in the current engine)

A group chat message is already a **self-contained, self-authenticating frame**:
- `Core::send` → `send_marked` seals + signs once via `grp.encrypt_signed(payload)`
  and produces `Frame::GroupMsg(ct)` (`engine.rs:1994`), dispatched with
  `route(inner, frame, Route::Broadcast)` (`engine.rs:2007`).
- Inbound, `handle_group_msg(inner, from, gct)` (`engine.rs:4468`) validates with
  `grp.decrypt_verified(&gct)` — a valid **per-sender ML-DSA-87 signature**
  (claimed leaf → roster fp → device key) **and** group-AEAD decryption, failing
  closed (`engine.rs:4482`). The `from` handle is **not** used for authentication.
- Dedup is already flood-safe: `handle_group_msg` calls
  `seen.insert(gossip_id(&gct))` first and drops duplicates (`engine.rs:4474`);
  `SeenSet` is a bounded LRU (`engine.rs:1023`). This is exactly the property a
  broadcast mesh needs — every node hears every frame, often several times.

So a `Frame::GroupMsg` received from **any** source — including an anonymous mesh
broadcast — validates and processes identically to one from a connected peer. The
mesh layer only ever moves opaque sealed bytes (the standing backend invariant).

## Architecture — mirror the beacon wiring

`Core::start_local_presence` (`engine.rs:2175`) is the precedent: advertise a
sealed blob, spawn a task that scans + feeds an event. Mesh messaging mirrors it:

```
Core::send ─ route(Broadcast) ─┬─ peer fan-out (Tor/LAN, unchanged)
                               └─ mesh tee: fragment Frame::GroupMsg → MeshNode::send   [outbound]

MeshNode::subscribe ─ reassemble (kind=Frame) ─ Frame::decode ─ GroupMsg ─ handle_group_msg  [inbound]
                                                                              │ (self-auth + SeenSet)
                                                                              └─ Event::Message
```

**Dual-homed bridging falls out for free.** The gossip re-forward inside
`handle_group_msg` (`engine.rs:4554-4560`) iterates connected peers directly (not
via `route`), skipping the source. So:
- A node on **mesh + Tor** that `send`s tees to both (via `route`).
- A frame **received over mesh** is re-forwarded to that node's **Tor** peers by
  the gossip loop (bridging the mesh island to the Tor island), but **not**
  re-teed to mesh (the re-forward doesn't call `route`) — no redundant mesh flood.
- `SeenSet` collapses the inevitable broadcast echoes.

### Outbound tee (in `route`)

Only `Route::Broadcast` **`Frame::GroupMsg`** frames are teed to mesh (the actual
chat content) — conserving scarce airtime. Control-plane broadcasts (commits,
roster) and `Route::Peer` frames (e.g. `DeliveryAck`) are **not** teed: in this
slice, **group membership/commits ride the primary transport**; mesh is a message
overlay for an already-established group. (Full mesh-native membership is a future
slice — see Out of scope.)

The tee transmits `frame.encode()` (the raw self-authenticating `Frame`), **not**
the pairwise-Double-Ratchet-wrapped or `Routed`-wrapped bytes — mesh is broadcast,
there is no pairwise session or single relay.

### Inbound (in `start_mesh_messaging`)

A spawned task subscribes to the `MeshNode`, reassembles `kind=Frame` fragments,
`Frame::decode`s the result, and for `Frame::GroupMsg(ct)` calls
`handle_group_msg(inner, MESH_SOURCE_FP, ct)`. `MESH_SOURCE_FP` is a documented
sentinel `[u8;48]` (no connected peer): it is only ever compared for the
echo-skip (`fp != from`, so we correctly forward to *all* real peers) and used as
the `DeliveryAck` target `Route::Peer(sentinel)` (a harmless no-op — no such peer)
and as an attribution fallback that never fires for a validly-signed frame.

### Frame `kind` — sharing the channel with the beacon

Beacon CQ blobs and message frames share the mesh channel + talkrypt magic. The
merged fragment header reserved byte 3 (`flags`, always 0) is formalized as a
`kind` discriminator so the two carries ignore each other:

```text
byte 3  kind:  0 = Advert (beacon CQ)   [unchanged: existing beacon fragments are already 0]
               1 = Frame  (chat message)
```

`fragment(kind, msg_id, payload, mtu)`, `parse_fragment` exposes `kind`, and
`Reassembler` gains an optional kind filter (`Reassembler::for_kind`). `MeshBeacon`
uses `Advert`; mesh messaging uses `Frame`. Fully backward-compatible on the wire.

## Public surface

```rust
impl Core {
    /// Carry this group's chat messages over a mesh node, in addition to the
    /// primary transport. Outbound GroupMsg broadcasts are fragmented + sent on
    /// `policy.channel`; inbound frames are reassembled and processed by the same
    /// self-authenticating path as any peer frame. Idempotent-ish: call once.
    pub async fn start_mesh_messaging(&self, node: Arc<dyn MeshNode>, policy: MeshPolicy);
}
```

`Inner` gains `mesh_tx: Mutex<Option<MeshTx>>` (`MeshTx { node, channel, msg_id:
AtomicU16 }`), default `None`; set by `start_mesh_messaging`, read by the `route`
tee.

## Security invariants

1. **No new trust.** Frames remain self-authenticating (group AEAD + per-sender
   ML-DSA); mesh delivery adds no authority. A forged/foreign mesh packet either
   fails `parse_fragment` (→ ignored) or fails `decrypt_verified` (→ dropped, not
   forwarded).
2. **Opaque bytes only.** The mesh carries `frame.encode()` of an already-sealed
   `GroupMsg`; the mesh layer never sees keys or plaintext.
3. **Flood-safe.** `gossip_id`/`SeenSet` dedup every path; broadcast echoes and
   mesh↔Tor bridging cannot loop or double-process.
4. **Airtime-bounded.** Only `GroupMsg` content is teed; membership/control stays
   on the primary transport in this slice.

## Testing (over `MockMeshNode`, no hardware)

- **frag:** `kind` round-trips; `Advert`/`Frame` fragments don't cross-feed a
  kind-filtered `Reassembler`; existing frag tests updated for the new param.
- **engine (the key test):** two `Core`s joined in a group over loopback, both
  `start_mesh_messaging` on a shared `MockMeshFabric`; sender `send`s; assert the
  receiver surfaces `Event::Message` with the correct text and verified `from`
  (the signed leaf's fp, not the mesh sentinel). A **mesh-only** variant: drop the
  loopback peer link, confirm the message still arrives purely over mesh.
- **dedup:** the same frame heard twice over mesh surfaces once.
- **negative:** a foreign / malformed mesh packet on the channel produces no
  `Event::Message` and no panic.

## Out of scope (documented next slices)

- **FFI host-callback surface** (`MeshNodeBackend` + `FfiMeshNode.deliverPacket`,
  `TalkryptClient::start_mesh_messaging`) — mirrors the `FfiBeacon` staging (core
  first, FFI next); no host has a real `MeshNode` backend yet (device-gated).
- **Mesh-native membership/commits** (DCGKA/control plane over broadcast) — this
  slice assumes the group is established over the primary transport.
- Real Meshtastic/Meshcore adapter implementation + on-radio validation.
