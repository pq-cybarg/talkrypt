# iOS — leave-behind reference code

talkrypt has **no committed iOS app target yet**. `scripts/build-ios.sh` builds the
Rust core + FFI as an `.xcframework` with uniffi **Swift** bindings, ready to drop
into an app; the files here are reference Swift that a future iOS app would use,
mirroring the Android implementations.

> **Not built, not tested.** There is no iPhone in the dev loop and the iOS
> Simulator has no real Bluetooth, so this code has not been compiled against the
> generated bindings or run. Validate on a physical device once an iOS app target
> exists. Treat it as a correct-by-construction port of the Android code, not a
> shipped feature.

## Files

- **`BeaconBackend.swift`** — CoreBluetooth implementation of the FFI
  `LocalBeaconBackend` seam (SUB-SPEC A / #68 pre-session CQ beacon). The peer of
  Android's `BleBeaconBackend`
  (`android/app/src/main/kotlin/com/talkrypt/app/BleBeacon.kt`): `advertise(blob:)`
  publishes a GATT service (`CBPeripheralManager`) serving the opaque, already-sealed
  beacon blob and advertises the beacon service UUID; scanning (`CBCentralManager`)
  reads a nearby peer's blob and hands it up for `FfiBeacon.deliverBeacon(...)`. The
  beacon service/characteristic UUIDs match Android's (…0003 / …0004) so the two
  platforms interoperate over the air. Upholds the non-negotiable backend invariant:
  it only ever moves opaque sealed bytes, never keys or plaintext.

- **`MeshtasticBackend.swift`** — CoreBluetooth implementation of the FFI
  `MeshNodeBackend` seam (#68 mesh messaging over a Meshtastic LoRa node). The peer
  of Android's `MeshtasticBleBackend`
  (`android/app/src/main/kotlin/com/talkrypt/app/MeshtasticBle.kt`): `send(channel:payload:)`
  wraps the opaque fragment as a `PRIVATE_APP` `ToRadio` protobuf **using the
  verified Rust codec over the FFI** (`meshtasticEncodeToradio` — no Swift protobuf)
  and writes it to the node's ToRadio characteristic; on the FromNum notification it
  drains FromRadio and hands each `meshtasticParseFromradio` payload up for
  `FfiMeshNode.deliverPacket(...)`. Meshtastic BLE UUIDs (service `6ba1b218…`,
  ToRadio `f75c76d2…`, FromRadio `2c55e69e…`, FromNum `ed9da18c…`) verified against
  meshtastic.org and identical to Android's. Same opaque-bytes invariant.

## Wiring (in a future iOS app)

```swift
// Presence beacon:
let backend = BleBeaconBackend()
let beacon = try client.startLocalPresence(backend: backend, policy: .full)
backend.startScanning { blob, source in
    try? beacon.deliverBeacon(blob: blob, source: source)
}

// Mesh messaging over a Meshtastic node:
let mesh = MeshtasticBleBackend()
let node = try client.startMeshMessaging(backend: mesh, channel: 0)
mesh.startReceiving { channel, payload, from in
    node.deliverPacket(channel: channel, payload: payload, from: from)
}
```

## Still to port (when the iOS app is built)

- Hardware-backed at-rest sealing via the **Secure Enclave** (the iOS peer of
  Android's `KeystoreWrapper` — implement the FFI `HardwareKeyWrapper` callback with
  a SecureEnclave-protected key; note the same PQC-not-in-secure-elements caveat, so
  `qromSafe()` returns false).
- A Wi-Fi/Bonjour beacon backend (the peer of Android's NSD `WifiBeaconBackend`),
  using `NWListener`/`NWBrowser` (Network framework) for the `_talkrypt-beacon._tcp`
  service.
