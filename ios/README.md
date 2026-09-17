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

## Wiring (in a future iOS app)

```swift
let backend = BleBeaconBackend()
let beacon = try client.startLocalPresence(backend: backend, policy: .full)
backend.startScanning { blob, source in
    try? beacon.deliverBeacon(blob: blob, source: source)
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
