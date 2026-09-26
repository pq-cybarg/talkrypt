# Mesh (LoRa) backend — Meshtastic & Meshcore

talkrypt can ride a LoRa mesh (Meshtastic / Meshcore) as another **local bearer**,
alongside BLE and Wi-Fi. It carries talkrypt's own PQ + AES-sealed ciphertext
end-to-end over the mesh ("encapsulation"), and it can also **read everything
else** on the mesh: it recognises other talkrypt nodes' traffic and hands their
opaque blob to the core to open (when you hold the keys), and surfaces
foreign / plaintext mesh traffic **clearly labelled as not talkrypt-secured**.

Everything below the "device-gated" line is built and tested today over an
in-memory mock node; the two real-radio adapters are documented, correct-by-
construction ports validated on hardware later (there is no LoRa node in the dev
loop). See the design in
[`docs/superpowers/specs/2026-09-16-mesh-lora-backend-design.md`](superpowers/specs/2026-09-16-mesh-lora-backend-design.md).

## Why encapsulation is the default (the mesh security reality)

LoRa mesh crypto does **not** meet talkrypt's CNSA-2.0 / PQ bar. Per
[Meshtastic's own docs](https://meshtastic.org/docs/overview/encryption/):
AES-256-CTR per channel with a **cleartext header**, a well-known default key
(`AQ==`), **no PFS** (harvest-now-decrypt-later), **no channel-message integrity**
(tamper / known-plaintext injection), and **no channel authentication** (the
sender id is a forgeable hardware MAC); DMs use non-PQ public-key crypto.
Meshcore's baseline is a shared AES-128 key. None of this is talkrypt's standard.

So talkrypt's **own seal is always the real security envelope.** The mesh's own
crypto, if enabled, is just an untrusted outer wrapper we neither need nor trust.
This is why encapsulation is the default and always meets our standard "even in
their boxed cryptographic shapes per channel."

## The one seam: `MeshNode`

Both stacks look the same from the phone/desktop side: a BLE / serial link to a
node, a "send this payload on this channel" call, and an inbound packet stream.
That is the whole seam (`talkrypt_transport::mesh::MeshNode`):

```rust
#[async_trait]
pub trait MeshNode: Send + Sync {
    fn mtu(&self) -> usize;                                    // usable bytes/packet
    async fn send(&self, channel: u8, payload: &[u8]) -> Result<()>;
    async fn subscribe(&self) -> Result<MeshInbox>;           // inbound packets
}
```

A LoRa packet carries only ~200-240 usable bytes, so talkrypt fragments a sealed
frame across many packets and reassembles it on the far side
(`mesh::frag`). The fragment header is flat, fixed-offset, and **Kani-proven
total** (never panics / never reads out of bounds on hostile input); the
reassembler is bounded (hard caps on in-flight messages and buffered bytes) so a
flood of partial fragments cannot exhaust memory.

## Presence: `MeshBeacon` (a drop-in `LocalBeacon`)

`mesh::MeshBeacon` implements the existing `LocalBeacon` seam over a `MeshNode`, so
it slots straight into `MultiBeacon` next to BLE / Wi-Fi — no core change:

```rust
use talkrypt_transport::{MultiBeacon, mesh::{MeshBeacon, MeshPolicy}};

let mesh = MeshBeacon::new(node /* Arc<dyn MeshNode> */, MeshPolicy::default());
let beacons = MultiBeacon::new()
    .with(Arc::new(mesh))
    .with(Arc::new(ble_backend))
    .with(Arc::new(wifi_backend));
```

`advertise(blob)` fragments the opaque sealed CQ and transmits it; `scan()`
reassembles nearby peers' fragments back into whole beacons. A peer with the
invite recovers the CQ; everyone else sees mere fragments.

## Reading the mesh: classification & the downgrade gate

Every inbound packet is classified by `mesh::MeshIngest` against a `MeshPolicy`:

```rust
pub struct MeshPolicy {
    pub channel: u8,           // where our encapsulated fragments are transmitted
    pub read_foreign: bool,    // surface non-talkrypt traffic? (default: false)
    pub native_send: NativeSend, // Off (default) | AskEachTime | Allowed
}

pub enum MeshHeard {
    Talkrypt { blob, source },              // reassembled, opaque → core opens it
    Foreign  { channel, payload, source },  // NOT talkrypt-secured; label downgraded
}
```

- **Talkrypt-over-mesh** fragments reassemble into an opaque `blob` for the core to
  open with your keys (if you hold them; otherwise you learn only "a talkrypt node
  is here").
- **Foreign** traffic is surfaced **only** when `read_foreign` is set, and must be
  shown clearly as **not** talkrypt-secured — it never enters the secured path.
- **Native / downgrade send** (transmitting under the *mesh's* own crypto, below
  our standard, so our PQ keying does not apply) requires explicit consent:
  `NativeSend::Allowed` (a settings opt-in) or `AskEachTime` (a per-message
  prompt). Default is `Off` — a talkrypt user is not automatically a plaintext
  mesh chat client.

## Security invariants

1. **Opaque bytes only** — the mesh layer fragments/reassembles already-sealed
   bytes; it never sees keys or plaintext (same invariant as BLE / Wi-Fi).
2. **Encapsulation always meets our standard** — our seal is applied by the core
   before the blob reaches the mesh; the mesh's per-channel crypto is untrusted.
3. **Foreign is never mistaken for secure** — classification is explicit; foreign
   traffic is labelled downgraded and kept out of the secured path.
4. **Downgrade is consented** — native send is gated; default off.
5. **Bounded reassembly** — fixed caps defeat partial-fragment memory floods.

---

## The real serial adapters (`feature = "mesh-radio"`)

`talkrypt_transport::mesh` ships two native USB-serial `MeshNode` adapters (behind
`feature = "mesh-radio"`; off by default so the base build has no serial/udev
dependency). Their pure codecs are unit-tested with golden vectors; the serial I/O
is validated on hardware.

- **`MeshtasticSerial`** (`mesh::meshtastic`) — the Stream API framing
  (`0x94 0xC3 <len16> <pb>`) + a hand-written minimal Meshtastic protobuf codec
  (no `prost`/`protoc`). Sends `ToRadio { packet: MeshPacket { to: BROADCAST,
  channel, decoded: Data { portnum: PRIVATE_APP, payload } } }`; receives
  `FromRadio { packet }` and surfaces the `PRIVATE_APP` payload. `PRIVATE_APP`
  carries arbitrary binary, so fragments ride raw. Field numbers verified against
  `meshtastic/protobufs`. MTU 200. **Primary, fully-verified adapter.**
- **`MeshcoreSerial`** (`mesh::meshcore`) — the companion protocol
  (`CMD_SEND_CHANNEL_TXT_MSG` 0x03 / `PACKET_CHANNEL_MSG_RECV` 0x08 / `_V3` 0x11,
  layouts verified against the companion protocol doc). Its channel message is a
  UTF-8 *text* field, so fragments are **base64-wrapped** for text-safety; MTU 120
  (`base64(120) ≤ 160`). The serial OUTER framing (`[type][len16 LE][payload]`) is
  firmware-dependent — see `mesh::meshcore` module docs; **validate on your node.**

```rust
# #[cfg(feature = "mesh-radio")]
use talkrypt_transport::mesh::{MeshtasticSerial, MeshPolicy};
let node = MeshtasticSerial::open("/dev/tty.usbserial-0001", 115200).await?;
core.start_mesh_messaging(node, MeshPolicy { channel: 0, ..Default::default() }).await;
```

Everything above the adapters — beacon, messaging, fragmentation, classification —
works unchanged over them; that is the point of the seam.

### Run a bilateral test on hardware (CLI)

With two USB LoRa nodes flashed with Meshtastic (or a T-Deck + a dongle), on the
same LoRa channel/region, build the CLI with the feature and attach a node to each
side of a normal chat — messages then flow over LoRa in addition to the primary
transport:

```sh
# Node A (host):
cargo run -p talkrypt-cli --features mesh-radio -- \
    host --group --channel '#field' --mesh-serial /dev/tty.usbserial-A

# Node B (join), using the invite A printed:
cargo run -p talkrypt-cli --features mesh-radio -- \
    join 'talkrypt://…' --group --mesh-serial /dev/tty.usbserial-B
```

Flags: `--mesh-serial <port>` (required to enable), `--mesh-kind meshtastic|meshcore`
(default `meshtastic`), `--mesh-baud` (default 115200), `--mesh-channel` (default 0).
Establish the group once over the primary transport (LAN/Tor); after that, messages
also ride the mesh, and a mesh-only peer (primary transport unplugged) still
receives them.

## Messaging: chat frames over the mesh

Beyond the CQ beacon, an established group's **chat messages** can ride the mesh
as an additional broadcast path (off-grid or resilience):

```rust
core.start_mesh_messaging(node /* Arc<dyn MeshNode> */, MeshPolicy::default()).await;
```

This carries the *same* self-authenticating group frames the engine already
produces — `Frame::GroupMsg`, sealed under the group epoch and signed with a
per-sender ML-DSA-87 leaf key. Because a group frame validates (group AEAD +
signature) and dedups (`gossip_id`/`SeenSet`) independently of its source, a frame
received from an anonymous mesh broadcast is processed exactly like a peer frame —
no new trust, no dependency on a connected peer. It mirrors `start_local_presence`:

- **Outbound:** every `Route::Broadcast` `Frame::GroupMsg` is fragmented
  (`kind = Frame`) and transmitted on `policy.channel`, in addition to the normal
  peer fan-out. Only chat content is teed — control-plane frames (commits, roster)
  stay on the primary transport to conserve LoRa airtime.
- **Inbound:** a task reassembles `Frame`-kind fragments and feeds each recovered
  `GroupMsg` into the engine's self-authenticating group path → `Event::Message`.
- **Bridging for free:** a node on both mesh and Tor/LAN re-forwards a
  mesh-received frame to its connected peers (and vice versa), bridging the two
  islands; `SeenSet` prevents loops and re-processing of the broadcast echoes.

The beacon (`kind = Advert`) and messaging (`kind = Frame`) share one mesh channel
and ignore each other's fragments via the header `kind` byte.

### From a host language (phone ↔ node over BLE)

The FFI exposes messaging as a callback backend, mirroring the beacon FFI: the
host implements the mesh link in its own language (e.g. a phone talking to a
T-Deck / Meshtastic node over BLE) and talkrypt drives it.

- Implement `MeshNodeBackend` (`mtu() -> u32`, `send(channel, payload)`) in
  Kotlin/Swift.
- Call `client.startMeshMessaging(backend, channel)` → returns an `FfiMeshNode`
  handle. talkrypt now fragments + transmits this chat's outbound group frames via
  your `send`.
- From your radio's receive callback, push each inbound packet in with
  `ffiMeshNode.deliverPacket(channel, payload, from)`. talkrypt reassembles
  talkrypt fragments and surfaces recovered group frames as `FfiEvent.Message`;
  non-talkrypt bytes are dropped. Same opaque-bytes invariant.

### Native (desktop / CLI ↔ USB-serial LoRa)

A Rust build links a `MeshNode` adapter directly — no FFI. See the device-gated
serial adapters below.

**Scope:** this carries chat CONTENT for an already-established group; group
**membership/commits** ride the primary transport (mesh-native membership is a
future slice). Airtime reality: a signed group frame is a few KB, so it fragments
into ~20-30 mesh packets — usable for text, not a Tor-speed experience.

## Out of scope (next slices)

- **Mesh-native membership/commits** (control plane over broadcast).
- A connection-oriented `Transport` over broadcast LoRa (the datagram carry is the
  substrate; the `Stream`/`Listener` model maps poorly onto a connectionless
  ~200-byte, seconds-latency medium).
- Meshtastic MQTT-gateway ingest and region/duty-cycle-aware airtime pacing.

See also [`docs/plugins/backend-plugins.md`](plugins/backend-plugins.md) for the
general backend-plugin model both seams share.
