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

## Device-gated: the real adapters

The Meshtastic and Meshcore `MeshNode` adapters live in
`talkrypt_transport::mesh::adapters` (behind `feature = "mesh-radio"` when a device
is in the loop). They are documented ports, not yet compiled/run here:

- **Meshtastic** — BLE (Nordic-UART) / USB serial / TCP; the `ToRadio` /
  `FromRadio` protobuf stream. Send bytes as a `MeshPacket { Data { portnum:
  PRIVATE_APP, payload } }` on the channel; receive `FromRadio.packet`. Usable
  `Data.payload` MTU ≈ 233 bytes. Needs a protobuf codec (`prost`) + a BLE/serial
  handle.
- **Meshcore** — BLE / USB serial companion protocol; send/receive channel
  messages; MTU ≈ 184-230. Baseline AES-128 shared key (treated as an untrusted
  outer wrapper).

Once either adapter is implemented, the rest of talkrypt — beacon, fragmentation,
classification — works unchanged. That is the point of the seam.

## Out of scope (next slices)

- A connection-oriented `Transport` over broadcast LoRa (the datagram carry built
  here is the substrate; the `Stream`/`Listener` model maps poorly onto a
  connectionless ~200-byte, seconds-latency medium).
- Meshtastic MQTT-gateway ingest and region/duty-cycle-aware airtime pacing.

See also [`docs/plugins/backend-plugins.md`](plugins/backend-plugins.md) for the
general backend-plugin model both seams share.
