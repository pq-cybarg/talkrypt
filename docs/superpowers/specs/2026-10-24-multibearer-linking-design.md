# Multi-bearer device linking (and chat) — Design

**Status:** design (approved). Builds directly on the existing
`talkrypt_transport::Transport` abstraction, `MultiTransport` (multi-homed
scheme-dispatch), and the already-designed `MeshTransport`
([`2026-09-27-mesh-transport-design.md`](2026-09-27-mesh-transport-design.md)).
NOT certified / NOT audited.

**Goal:** let device linking — and, by reuse, chat — run over every bearer the
running device/OS/peripherals can offer: LAN/TCP, Tor onion, Nym mixnet,
mesh/LoRa (Meshtastic/Meshcore), BLE/Bluetooth, Wi-Fi Direct, and NSD/mDNS
discovery — selected at runtime by what the device can actually do. Confirmation
stays strictly out of band (compare the account safety number by hand); no
transport ever carries the confirmation.

## Why this is mostly composition, not new abstraction

The hard parts already exist:

- **`Transport` is the universal seam** — `listen` / `dial(Endpoint)` /
  `status` / `local_endpoint`, exchanging opaque framed ciphertext. The engine
  and `LinkHost`/`LinkClient` are generic over `Arc<dyn Transport>`.
- **`MultiTransport` already multi-homes** Tor + Nym + LAN: `dial` routes by the
  endpoint `Scheme` (`.onion` → Tor leg, `nym:` → Nym leg, else TCP), and
  `listen` fans every leg's inbound into one accept queue. A multi-homed invite
  is already `[onion, nym:…, host:port]`.
- **`MeshTransport` already turns a lossy broadcast datagram bearer into a
  reliable `Transport`** (per-connection `conn_id`, stop-and-wait ARQ, flat
  Kani-provable packet decode, distinct magic for coexistence). This is the
  template for every datagram bearer.

So "link over every route" reduces to four well-bounded additions, each an
independently testable `Transport` leg or a thin selector above the existing
machinery. `LinkHost`/`LinkClient` and the engine do not change.

## Bearer taxonomy

| Tier | Bearers | Transport status |
|---|---|---|
| **Stream** | LAN/TCP, Tor onion (`ArtiTransport`), Nym (`NymTransport`), Wi-Fi-Direct socket | exist (Wi-Fi Direct = TCP on the P2P interface once the link is up) |
| **Framed datagram** | mesh/LoRa (`MeshTransport` over `MeshNode`), BLE GATT | mesh exists; BLE reuses the pattern |
| **Discovery** | NSD/mDNS, Wi-Fi Direct peer discovery, BLE advertising | not a data transport — they *establish* a Tier-1/2 pipe, then it is opaque |

## Components (new)

### 1. `FfiTransport` — foreign-transport seam (FFI)
A UniFFI **callback interface** the host app implements so platform-only radios
carry a core session. The core calls out; the app supplies the bytes.

```text
// Rust side (talkrypt-ffi): a `Transport` impl that forwards to a
// host-provided callback object.
trait ForeignBearer {               // implemented in Kotlin/Swift
    fn dial(endpoint: String) -> ForeignStream        // errors are typed
    fn listen() -> ForeignListener
    fn local_endpoint() -> String
    fn status() -> BearerStatus
}
trait ForeignStream  { send(frame: Vec<u8>); recv() -> Option<Vec<u8>>; close() }
trait ForeignListener { accept() -> Option<ForeignStream> }
```

- **Android** backs `ForeignBearer` with BLE (GATT) and Wi-Fi Direct (it owns the
  P2P-socket handoff). The *framing/reliability* for a datagram radio (BLE) lives
  on the app side **or** the app exposes a `MeshNode`-shaped datagram seam and the
  core wraps it in the existing reliable-framing layer — chosen per bearer; BLE
  starts app-framed (simplest), can migrate to core-framed later.
- **Desktop** uses native Rust legs only (no `FfiTransport`); it has no portable
  BLE-peripheral / Wi-Fi-Direct stack.
- The seam is a `Transport` like any other, so `MultiTransport` can include it.

### 2. BLE bearer
On Android: a `ForeignBearer` over a GATT service (advertise + connect + a
write/notify characteristic pair as the byte pipe), with app-side chunking
(GATT MTU ~180-512 B). The link/chat ciphertext is opaque inside. BLE as a Rust
desktop bearer is out of scope (no portable stack) and omitted by capability.

### 3. `BearerSet` — capability probe + leg selection
A per-device probe that enumerates the legs this build/OS/peripherals can
construct, and assembles the `MultiTransport` (or a single leg) for an offer:

- compile-time: `tor` / `nym` feature flags gate those legs;
- runtime: mesh present iff a serial node is attached (desktop) or the FFI mesh
  bearer is available; BLE/Wi-Fi-Direct present iff the host registered an
  `FfiTransport`; LAN always;
- a bearer that is absent is simply omitted — never an error, never a panic.

`BearerSet::offer_transport(prefs) -> (Arc<dyn Transport>, Vec<Endpoint>)` returns
the multi-homed transport plus the endpoint list to advertise in the link URI.

### 4. Linking integration (`/link`) + carry-vs-rendezvous
`replcmd`'s `/link` grows bearer selection (reusing `BearerSet`):

- `/link offer [--bearer tor,nym,lan,mesh,ble,wifidirect|all] [--rendezvous]`
  builds the selected `MultiTransport`, runs `LinkHost` on it, and emits a
  **multi-homed** link URI advertising every leg's endpoint.
- `/link accept <uri>` dials whichever advertised endpoint the accepting device
  can reach (scheme-dispatched by `MultiTransport`, same as chat).
- **Carry** (default, `--no-rendezvous`): the full cert handshake runs over the
  chosen leg — works off-grid over LoRa/BLE alone (slow: a multi-KB PQ handshake
  over LoRa is minutes; documented, with progress).
- **Rendezvous** (`--rendezvous`): over a slow leg the offer sends only a tiny
  signed bootstrap advertising a fast endpoint (onion/LAN) + the one-time invite
  token; the handshake then runs over the fast leg. The token is a *rendezvous*
  secret, not an auth secret — authentication is still the PQ handshake, and
  confirmation is still the out-of-band safety-number comparison.

## Data flow (offer, `--bearer all`)

1. `BearerSet` probes → legs `[arti?, nym?, mesh?, ble?, tcp]`.
2. `offer_transport` builds a `MultiTransport` of the available legs; for Tor the
   `.onion` is learned after bind (existing pattern), mesh/BLE endpoints are their
   bearer labels.
3. `LinkHost::new(account, …, Arc<MultiTransport>, &desc, …).auto_approve()`; the
   listener fans every leg into one accept queue (existing `MultiTransport`).
4. Emit multi-homed URI `talkrypt://…[onion, nym:…, host:port, mesh:…, ble:…]`.
5. New device `/link accept`: `MultiTransport` dials the first reachable
   advertised endpoint; `LinkClient::request` runs the unchanged handshake; cert
   chain saved; both sides print the account safety number for OOB comparison.

## Security invariants (unchanged + new)

- **Confirmation is never carried.** Only the safety number compared by hand
  defeats MITM; no bearer, token, or side-channel substitutes for it.
- **The account key never crosses any bearer** — only a signed device cert.
- **Offers stay one-time, single-use, short-TTL, auto-approve-guarded** exactly as
  today, regardless of bearer.
- **Every attacker-reachable decoder is typed-error + fuzzed** (repo rule) — the
  BLE framing decoder and any new bootstrap decoder get a fuzz target, like
  `MeshTransport`'s `parse_packet`.
- **Per-leg isolation:** one leg failing to bind/dial degrades the offer to the
  remaining legs; it never fails the whole offer or panics.
- **Rendezvous token ≠ authorization.** A captured rendezvous bootstrap lets an
  attacker *reach* the fast endpoint but not pass the PQ handshake or forge the
  safety number.

## Error handling

- Framed-leg (mesh/BLE) timeouts: bounded retransmit then a typed `BearerError`;
  the leg drops out of the `MultiTransport`, others continue.
- Capability probe: absent bearer → omitted leg (never a hard error).
- FFI bearer: a host callback that throws → typed error surfaced as a dead leg;
  the core never unwinds across the FFI boundary.
- Carry-mode over LoRa: progress surfaced to the UI; a user-cancelable long op.

## Testing

- `FramedTransport`/mesh pattern already tested against a drop-mock; reuse for BLE
  framing (loss/reorder/dup) via a mock datagram fabric.
- `MultiTransport` leg selection + scheme-dispatch over the new legs.
- `BearerSet` capability matrix (feature-flag × platform × peripheral-present).
- End-to-end `/link offer`→`accept` over a **loopback framed leg** (no hardware).
- Rendezvous: bootstrap decode + "slow leg advertises fast leg, handshake runs on
  fast leg" integration.
- Fuzz targets for the BLE framing decoder and the rendezvous bootstrap decoder.
- FFI: a mock `ForeignBearer` in a Rust test driving a full link over the seam.

## Decomposition (build order — each its own plan)

- **P1 — Stream-leg linking.** `BearerSet` (stream legs only) + `/link offer
  --bearer tor,nym,lan|all` emitting multi-homed URIs over `MultiTransport`;
  accept auto-dials. Feature-gated. *Highest value, lowest risk; no new protocol.*
- **P2 — Mesh leg in linking.** Wire `MeshTransport` as a `BearerSet` leg; carry
  mode over LoRa; progress UI. (`MeshTransport` itself already exists.)
- **P3 — FFI foreign-transport seam + Android BLE/Wi-Fi-Direct.** `FfiTransport`,
  the UniFFI callback interface, Android `ForeignBearer` for BLE + Wi-Fi Direct,
  bindings regen.
- **P4 — Capability negotiation polish + rendezvous mode.** Full `BearerSet`
  probe across all legs, `--rendezvous` bootstrap, per-platform route picker UX.

## Forward-compatibility seams (not built here — see the 2.0 vision note)

This design deliberately leaves clean seams for the separately-tracked 2.0
research ([`docs/research/2026-10-24-polymorphic-crypto-2.0-vision.md`](../../research/2026-10-24-polymorphic-crypto-2.0-vision.md)):
the `Transport` leg model is exactly where covert/side-channel bearers would plug
in; `BearerSet`/capability selection is where per-chat compartmentalized bearer
policy would live; framed-leg fragmentation is where fragmentable/compartmentalized
component routing would attach. None of that is in scope here; this spec stays a
transport-plumbing change over the existing engine.

## Out of scope (explicit)

- Any change to the PQ handshake, cert format, or the engine.
- Session migration / mid-session bearer hopping (YAGNI for linking).
- Desktop BLE-peripheral / Wi-Fi-Direct (no portable stack).
- The 2.0 polymorphic-crypto / covert-channel / Shamir / split-keying work — that
  is a separate branch, separately brainstormed, FV + security-eval + pentest
  gated. Captured only as a vision note so it isn't lost.
