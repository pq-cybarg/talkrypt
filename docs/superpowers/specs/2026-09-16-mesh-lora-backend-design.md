# Mesh (LoRa) Backend — Meshtastic / Meshcore — Design

**Status:** design + testable core. Real-radio adapters are device-gated (no
LoRa node in the dev loop; validated on hardware later).

**Goal:** let talkrypt ride Meshtastic and Meshcore LoRa mesh networks as another
local bearer, carrying talkrypt's own PQ + AES-sealed ciphertext end-to-end
("encapsulation"), while also being able to *read* everything else on the mesh —
recognising and decrypting other talkrypt nodes' traffic when we hold the keys,
and surfacing foreign/plaintext traffic clearly labelled as **not** talkrypt-
secured. One `MeshNode` seam; Meshtastic and Meshcore adapters plug in behind it.

## Why this shape (user constraints, verbatim intent)

- **Scope A (build now):** LoRa as a talkrypt bearer — our own ciphertext over
  the mesh, full E2E PQ preserved.
- **Scope B (build now, security-walled):** "we should have control of the
  encryption. Any unencrypted messages should show up for us. If anyone else is
  using Talkrypt on the chat we should recognize it and decrypt the message
  accordingly (if possible / we have the appropriate keying)." We only control
  **what we send** — we cannot control the Meshtastic/Meshcore chats.
- **Two carry modes:**
  1. **Encapsulation (default):** talkrypt sealed frames fragmented and carried
     inside mesh packets. Always meets our standard regardless of the network's
     per-channel crypto box. "It should always be able to meet our standard even
     in their boxed cryptographic shapes per channel."
  2. **Downgrade (opt-in):** send native mesh messages under *their* crypto
     (Meshcore AES-128 shared key; Meshtastic AES-256-CTR per channel / PKC DMs).
     This is **below our standard** — user must allow **every time** or enable it
     in settings. "keep in mind that if we obey their structure, any other keying
     mechanisms we have will fail" — native mode is explicitly outside PQ.
- **Both stacks behind one seam** (`MeshNode`): a Meshtastic adapter and a
  Meshcore adapter implement the same trait.

### The mesh security reality (why encapsulation is the default)

From meshtastic.org/docs/overview/encryption: AES-256-CTR per channel with the
header sent in the clear; default primary key is the well-known `AQ==`; **no
PFS** (harvest-now-decrypt-later), **no channel-message integrity** (tamper /
known-plaintext injection), **no channel authentication** (sender id is a
forgeable hardware MAC). DMs use non-PQ PKC. Meshcore's baseline is an AES-128
shared key. None of this meets talkrypt's CNSA-2.0 / PQ bar. So talkrypt's own
seal is always the real security envelope; the mesh's own crypto, if present, is
just an outer wrapper we neither need nor trust. Native/downgrade mode exists
only for deliberate interop and is gated behind explicit consent.

## Architecture (one seam, testable core, device-gated adapters)

```
core (advert / engine)                     ← unchanged: hands opaque sealed blobs
        │  Arc<dyn LocalBeacon>            (and, later, Arc<dyn Transport>)
        ▼
  MeshBeacon  ─── implements LocalBeacon ──┐
        │                                   │  fragment / reassemble + classify
        ▼                                   ▼
     MeshCarry (frag.rs + policy)  ── uses ── Arc<dyn MeshNode>
                                                    │
                    ┌───────────────────────────────┼───────────────────────────┐
                    ▼                                ▼                           ▼
             MockMeshNode                   MeshtasticNode                 MeshcoreNode
        (in-memory fabric, tests)        (protobuf, BLE/serial)      (serial companion, BLE)
                                          — device-gated adapter —    — device-gated adapter —
```

- **`MeshNode` seam** (`mesh/mod.rs`): the common denominator of both stacks as
  seen from the phone/desktop — connect to a node over BLE/serial, send one
  packet's worth of application bytes on a channel, subscribe to inbound packets.
  MTU-aware. The node firmware has already de-radioed packets, so we deal in
  application payloads, never raw LoRa symbols.

- **`MeshCarry` + fragmentation** (`mesh/frag.rs`): mesh packets carry only
  ~200-240 usable bytes. A talkrypt sealed frame (a CQ beacon is a few hundred
  bytes; a handshake frame is multi-KB) is fragmented across N packets with a
  small, flat, self-describing header and reassembled on the far side. The
  fragment **header decoder is flat + bounded** (Kani-provable, following the
  `talkrypt_wire` decoder convention); the reassembly buffer is bounded (anti-DoS)
  and is runtime-only (not a Kani target — nested heap, per the FV posture).

- **Classification / ingest (Scope B):** every inbound packet is classified:
  - starts with the talkrypt-over-mesh magic → reassemble → `MeshHeard::Talkrypt`
    (opaque blob; core opens it with our keys if we hold them; otherwise we learn
    only "a talkrypt node is here").
  - otherwise → `MeshHeard::Foreign` (channel + raw payload), surfaced **only if**
    the policy enables reading foreign traffic, and always labelled as **not**
    talkrypt-secured.

- **`MeshPolicy`:** the transmit channel index, `read_foreign: bool`, and
  `native_send: NativeSend { Off | AskEachTime | Allowed }` — the downgrade gate.

- **`MeshBeacon`** (`mesh/beacon.rs`): implements the existing `LocalBeacon`
  seam over a `MeshNode` + `MeshPolicy`. `advertise(blob)` fragments the sealed CQ
  and transmits it; `scan()` reassembles talkrypt fragments and yields `Seen`. It
  slots straight into `MultiBeacon` next to BLE / Wi-Fi — a build packages the mesh
  radio like any other plugin. No core change.

- **Adapters** (`mesh/adapters.rs`, feature `mesh-radio`, leave-behind):
  - **Meshtastic:** the `ToRadio`/`FromRadio` protobuf API over BLE (Nordic UART
    style) / serial / TCP; send a `MeshPacket` with `portnum=PRIVATE_APP` on the
    configured channel; receive `FromRadio.packet`. MTU ≈ 233 bytes of `Data`.
  - **Meshcore:** the serial/BLE companion frame protocol; send/receive channel
    messages; MTU ≈ 184-230 depending on build. Baseline AES-128 shared key.
  Both are documented and compile behind the feature but are **not run** here (no
  device); they are correct-by-construction ports validated on hardware later.

## Wire format — talkrypt-over-mesh fragment (flat, bounded)

Fixed 10-byte header, then the chunk. No nested/length-prefixed heap fields, so
the decoder is a straight-line bounded parse (Kani-friendly).

```text
byte 0     MAGIC0 = 0xA7          two-byte magic distinguishes talkrypt fragments
byte 1     MAGIC1 = 0x6D ('m')     from arbitrary foreign mesh bytes
byte 2     version = 1
byte 3     flags   (reserved = 0)
bytes 4-5  msg_id      (u16 BE)    per-sender rolling id grouping one message's fragments
bytes 6-7  frag_index  (u16 BE)    0-based
bytes 8-9  frag_count  (u16 BE)    total fragments (≥1); index < count enforced
bytes 10.. chunk                   payload slice (≤ mtu - 10)
```

- Encoder: `fragment(msg_id, payload, mtu) -> Vec<Vec<u8>>` splits `payload` into
  `ceil(len / (mtu-10))` fragments (bounded: a payload needing > `MAX_FRAGMENTS`
  is rejected — a talkrypt frame that big does not belong on LoRa).
- Decoder: `parse_fragment(&[u8]) -> Option<Fragment>` — flat: checks magic +
  version, reads the five scalar fields, validates `frag_index < frag_count` and
  `frag_count >= 1`, returns the chunk range. Never indexes out of bounds; returns
  `None` for anything that is not a well-formed talkrypt fragment (so foreign
  bytes classify as `Foreign`, never crash).
- `Reassembler`: bounded map keyed by `(from, msg_id)` → per-message slot holding
  `frag_count`, a received-bitset, and the accumulated chunks. Completes when all
  fragments are in; enforces a max in-flight message count and max buffered bytes
  (evicting oldest), and a consistent `frag_count`/length per key. Runtime-only.

## Security invariants (unchanged + new)

1. **Backend moves opaque bytes only** — `MeshBeacon`/`MeshCarry` never see keys
   or plaintext; they fragment/reassemble already-sealed bytes. Same invariant as
   BLE/Wi-Fi.
2. **Encapsulation always meets our standard** — our seal is applied by core
   before the blob reaches the mesh layer; the mesh's own per-channel crypto is an
   untrusted outer wrapper. talkrypt security does not depend on it.
3. **Foreign traffic is never mistaken for secure** — classification is explicit;
   `Foreign` is surfaced (if enabled) with a non-talkrypt / downgraded label and
   never enters the talkrypt-secured message path.
4. **Downgrade is consented** — native/plaintext send requires
   `NativeSend::Allowed` (setting) or `AskEachTime` (per-message prompt); default
   `Off`. Sending native means our PQ keying does **not** apply, by construction.
5. **Bounded reassembly** — fixed caps on in-flight messages, fragments per
   message, and buffered bytes; a flood of partial fragments cannot exhaust memory.

## Testing

- `frag.rs` unit tests: encode→decode round-trip across MTUs; single-fragment;
  boundary sizes (exact multiple, +1); reject over-`MAX_FRAGMENTS`; reject
  malformed / short / wrong-magic / bad-version / index≥count; reassembler
  completes in order and out of order; reassembler bounds (eviction, byte cap);
  duplicate fragment idempotent.
- Kani proof: `parse_fragment` never panics and returns in-bounds ranges for all
  ≤N-byte inputs (mirrors `talkrypt_wire`'s bounded-decoder proofs).
- `beacon.rs` integration (over `MockMeshNode`): advertise a large sealed CQ →
  fragmented across many mesh packets → scanner reassembles → `Seen.blob` equals
  the original; foreign packets on the same channel do not surface as beacons;
  two nodes on one fabric see each other but not themselves.
- Classification tests: talkrypt magic → `Talkrypt`; other bytes → `Foreign`;
  `read_foreign=false` suppresses `Foreign`; `NativeSend::Off` refuses native send.

## Out of scope (documented next slices)

- **`MeshTransport` (connection-oriented `Transport` over broadcast LoRa):** the
  `Stream`/`Listener` model maps poorly onto a connectionless, ~200-byte, seconds-
  latency broadcast medium. The reusable datagram carry (`MeshCarry` + frag) built
  here is the substrate; a datagram-style `Transport` (route-id-filtered) is a
  follow-up once the beacon path is validated on hardware.
- **Meshtastic MQTT gateway** ingest (internet-side mesh bridge).
- **Region/duty-cycle-aware pacing** and airtime budgeting for the real adapters.
