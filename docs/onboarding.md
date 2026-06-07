# In-person onboarding, pairing & access control

How two people who are physically together (or who just want a private,
no-server channel) get talkrypt onto their devices, pair, and start a chat that
**persists after they leave** — plus how to lock a channel down.

Everything here is post-quantum (ML-DSA-87 identities, ML-KEM-1024 KEM, AES-256,
SHA-3/Argon2id); elliptic curve is never load-bearing.

## 1. Get the app onto a friend's device (P2P, no app store)

**Mobile → mobile, over Wi-Fi/hotspot.** On the talkrypt Android app, tap
**Share app (P2P over Wi-Fi)**. The app starts a tiny local HTTP server that
serves *its own APK* and shows a URL + QR. The friend (same Wi-Fi or your
hotspot) scans the QR or opens the URL in a browser, downloads `talkrypt.apk`,
and installs it (they allow "install unknown apps" once). No store, no internet.
Implementation: `android/.../ApkShareServer.kt`.

**Desktop / anything, portable binary.** The CLI is pure-Rust with no C deps, so
it builds as a single fully-static binary you can hand to anyone:

```
bash scripts/build-portable.sh --list     # see targets
rustup target add x86_64-unknown-linux-musl
bash scripts/build-portable.sh            # -> dist/talkrypt-<target>
```

The musl build needs nothing on the target machine — copy it over (USB, AirDrop,
the mobile share, any channel) and it runs. Universal macOS and Windows `.exe`
targets are included.

## 2. Start a chat that persists (QR + deep link)

**Host shows a QR; friend scans it with any camera.** When you host a chat (CLI
`talkrypt host …`, or the Android app's *Host*), talkrypt prints/shows a QR of
the `talkrypt://…` invite. The other phone scans it with its **normal camera**
— Android recognizes the `talkrypt://` link, opens the app via its deep-link
intent filter, and **auto-joins**. No in-app scanner or typing required.

The invite descriptor is a stable token, so the chat keeps working after you
part ways — it persists. (Text entry is always available too: paste the
`talkrypt://` URI into *Join*.)

## 3. Pair devices under one account (link)

To make a new device show up as *the same account* to your friends (so they
don't have to re-verify), link it. The primary (which holds the account key)
certifies the new device; the account key never leaves the primary.

```
# On the device holding the account key:
talkrypt link-offer --account ~/.talkrypt/account.key --username alice
#   -> prints a one-time linking URI + QR

# On the NEW device (scan/paste that URI):
talkrypt link-accept '<uri>' --device ~/.talkrypt/device.key \
                             --chain-out ~/.talkrypt/chain.bin

# Then chat AS the account on the new device:
talkrypt host --device ~/.talkrypt/device.key --chain ~/.talkrypt/chain.bin --username alice
```

Friends who pinned Alice's account now accept the new device automatically,
because the device certificate is signed by Alice's account key (PQ-unforgeable).
Verify the account safety number out of band once. See `docs/identity-accounts.md`.

## 4. Lock the channel down (access control)

These compose — use either or both.

**Password-gated channel.** Add `--password '<secret>'` on `host` and `join`.
The password is mixed into the session root via **Argon2id** and is **never put
in the invite URI**, so capturing the `talkrypt://` link alone doesn't grant
access — a joiner needs both the link *and* the password (shared out of band).
A wrong/absent password yields a different root, so frames fail to decrypt
(fail-closed). The password itself never crosses the wire.

**Registry-restricted channel.** Run a username registry only you know
(`talkrypt registry …`), have members register on it, then host with
`--require-registry '<registry-uri>'`. Only accounts registered on that registry
are heard; everyone else (and pseudonyms) is silenced and disconnected. The
registry's address never appears in the invite. Build: `AccessPolicy` in
`crates/core/src/engine.rs`, registry in `crates/core/src/registry.rs`.

**Overlap.** `host --password … --require-registry …` requires *both* the
out-of-band password *and* membership in your registry — two independent gates.

## Zero-touch nearby discovery (BLE + Wi-Fi Direct)

For hands-free pairing with no QR or typing, the host broadcasts its invite and a
nearby phone finds it. **Find nearby host** on the start screen scans; the host
auto-broadcasts when you start a chat. Two transports run together:

- **Bluetooth LE** (`BleNearby.kt`) — the low-power "who's nearby" beacon. The
  host opens a GATT server with a readable characteristic holding the invite and
  advertises the talkrypt service UUID; the scanner connects, raises the MTU, and
  reads the invite (offset/blob reads, so invites larger than one MTU arrive in
  full). Permissions: BLUETOOTH_ADVERTISE/SCAN/CONNECT (API 31+) or
  BLUETOOTH(_ADMIN) + fine location (pre-31), requested at runtime.
- **Wi-Fi Direct** (`WifiDirectNearby.kt`) — higher bandwidth, forms its own
  network with no router (also suits the APK transfer). `discoverPeers()` + a
  `WIFI_P2P_PEERS_CHANGED` receiver; on connection the group owner serves the
  invite over a socket the scanner reads. Permissions: NEARBY_WIFI_DEVICES
  (API 33+, `neverForLocation`) or fine location (pre-33), plus CHANGE_WIFI_STATE.

What crosses the air is only the `talkrypt://` invite (a one-time token); the
chat still runs over the authenticated, AEAD-encrypted session and can be
password- or registry-gated. Discovery is convenience, **never** a trust anchor —
the safety-number / account checks still apply.

> The host now binds its chat to the device's LAN/hotspot address (not loopback),
> so a QR- or nearby-discovered invite is actually dialable from the other phone.

## What's done vs. next

Done + tested at the core/CLI layer (Rust): QR chat-start (terminal QR + deep
link), device linking, password channels, registry-restricted channels, portable
builds. Done in the Android app (compiles; **not** runtime-tested on the locked
Seeker): text-entry fix, `talkrypt://` deep-link auto-join, invite-QR display,
P2P APK share, LAN-address hosting, and **BLE + Wi-Fi Direct nearby discovery**.

**Over Tor:** the CLI runs over real onion services with `--tor` (build with
`--features tor`), and the Android app has a "Route over Tor" toggle that uses
the FFI's `host_tor`/`join_tor` (host publishes a `.onion`, put in the invite;
peers dial it). The shipped `.so` includes Tor only when built with
`TALKRYPT_TOR=1 bash android/build-apk.sh` (Arti is a heavy cross-compile);
without it the toggle errors clearly at runtime.

Next increments: an in-app camera scanner (the OS camera + deep link already
covers scan-to-join, so this is optional polish) and a graphical
linking/friends/segment manager. These need on-device validation.

NOT certified / NOT audited — see the project README.
