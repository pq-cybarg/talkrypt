# Backend plugins — bring your own transport & beacon

talkrypt's networking is defined by two small, object-safe seam traits in the
`talkrypt-transport` crate. **Anything that can move opaque bytes between devices can be a
backend.** You implement the trait in your own crate, compile it into *your* build of
talkrypt, and inject it — the core drives whatever you plug in and never needs to know how
your radio works. BlueZ, Android/Apple BLE, Wi-Fi Direct/Aware, a serial link over USB-C, a
LoRa or packet-radio modem, a carrier pigeon with a QR code — all A-OK.

The two seams:

| Seam | Trait | Carries | Compose many with |
|------|-------|---------|-------------------|
| **Data transport** (sessions/messages) | `talkrypt_transport::Transport` | opaque end-to-end ciphertext frames | `MultiTransport` |
| **Presence beacon** (pre-session discovery) | `talkrypt_transport::LocalBeacon` | opaque, pre-sealed beacon blobs | `MultiBeacon` |

## Non-negotiable invariant

**A backend only ever sees opaque bytes.** Both traits move ciphertext the core has already
sealed (E2E ciphertext for `Transport`; PQ + AES-256-GCM sealed beacon blobs for
`LocalBeacon`). A plugin must **never** try to interpret, log, or persist payloads, and it
never touches keys or plaintext. It is a dumb pipe. This is what lets any backend — however
sketchy the medium — be safe: confidentiality/authenticity live above the seam.

Also: be **best-effort and panic-free**. A radio being off/unavailable must return an error
or no-op, never panic — `MultiTransport`/`MultiBeacon` tolerate a dead leg and use the others.

## Writing a beacon backend (`LocalBeacon`)

```rust
use async_trait::async_trait;
use talkrypt_transport::{beacon::BeaconScan, LocalBeacon, Result, Seen};

pub struct MyBleBeacon { /* handles to your radio */ }

#[async_trait]
impl LocalBeacon for MyBleBeacon {
    async fn advertise(&self, blob: Vec<u8>) -> Result<()> {
        // Start/replace a BLE advertisement (or Wi-Fi Aware publish, or a USB-C frame you
        // TX however you like) carrying `blob` verbatim. Opaque bytes — do not parse.
        Ok(())
    }
    async fn stop(&self) -> Result<()> {
        // Stop advertising / go dark.
        Ok(())
    }
    async fn scan(&self) -> Result<BeaconScan> {
        // Return a BeaconScan whose `next()` yields each nearby beacon you observe as
        // `Seen { blob, source }`. `source` is a coarse handle (MAC/adv-id) for dedup or
        // signal only — never an identity. Build one via the constructor helper the crate
        // exposes, or wrap your own mpsc receiver.
        todo!()
    }
}
```

`Seen { blob, source }` is what a scanner surfaces; the app opens `blob` with
`talkrypt_core::advert::open_advertisement(&descriptor, &blob)` — an invite-holder recovers
the scheme, anyone else gets only "a device is beaconing".

### Beacon backends from a host language (Kotlin / Swift, over the FFI)

A radio backend usually lives in the host app (Android BLE, CoreBluetooth), not in Rust.
The FFI exposes a callback interface so the host implements the backend in its own language:

- Implement `LocalBeaconBackend` (`advertise(blob)`, `stop()`) in Kotlin/Swift.
- Call `client.startLocalPresence(backend, policy)` → returns an `FfiBeacon` handle. talkrypt
  now advertises this chat's sealed beacon via your `advertise` and scans.
- From your radio's scan callback, push each observed beacon in with
  `ffiBeacon.deliverBeacon(blob, source)`. talkrypt decrypts those matching the chat invite
  and emits `BeaconSeen`. (Scan is push-style because a callback can't return a stream.)

Same opaque-bytes invariant: the host backend never sees plaintext or keys.

## Writing a data-transport backend (`Transport`)

Implement `talkrypt_transport::Transport` (`listen` → `Listener`, `dial` → `Stream`,
`status`, `local_endpoint`) plus `Stream`/`FrameWriter`/`FrameReader` for your medium. See
`crates/transport/src/tcp.rs` and `loopback.rs` for reference implementations, and
`arti.rs` (Tor) / `nym.rs` for real-network ones.

## Packaging & selecting plugins at build time

Your plugins are just crates that depend on `talkrypt-transport`. In *your* build of a
talkrypt host (the CLI/desktop/FFI binary), add the ones you want as dependencies —
feature-gate them if you like — and compose them at startup:

```rust
use std::sync::Arc;
use talkrypt_transport::{MultiBeacon, MultiTransport, Scheme};

// Presence: advertise/scan on every radio you shipped. Absent plugins simply aren't added.
let beacons = MultiBeacon::new()
    .with(Arc::new(my_ble::MyBleBeacon::new()?))
    .with(Arc::new(my_wifi_aware::Publisher::new()?))
    .with(Arc::new(my_usb_c_radio::Link::open("/dev/ttyACM0")?));
// -> pass `Arc::new(beacons)` wherever the engine takes an `Arc<dyn LocalBeacon>`.

// Data: MultiTransport routes by endpoint scheme across the transports you shipped.
let transport = MultiTransport::new()
    .with(Scheme::Onion, tor)
    .with(Scheme::Tcp, tcp);
```

Because selection is *your* dependency graph + a few `.with(...)` calls, each build ships
exactly the backends its builder chose — no central registry, no upstream permission. A
minimal build might ship only loopback; a field build might ship BLE + Wi-Fi + a custom RF
link. The `MultiBeacon`/`MultiTransport` bags handle fan-out, merge, and de-duplication so
the rest of talkrypt is unchanged regardless of what's plugged in.

## Testing your plugin

Drive it with the in-memory references — `LoopbackBeaconFabric` (presence) and
`LoopbackFabric` (transport) — which implement the same seams, so your integration tests run
with zero hardware. See `crates/transport/src/beacon.rs` tests for the pattern, including
`MultiBeacon` fan-out/merge/dedup.
