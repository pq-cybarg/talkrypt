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

## What's a skeleton vs. done

Done + tested at the core/CLI layer (Rust): QR chat-start (terminal QR + deep
link), device linking, password channels, registry-restricted channels, portable
builds. Done in the Android app: the text-entry fix, `talkrypt://` deep-link
auto-join, invite-QR display, and the P2P APK share server.

Next increments (scaffolding / not yet built): an in-app camera scanner (the OS
camera + deep link already covers scan-to-join, so this is optional polish);
BLE / Wi-Fi Direct nearby discovery to auto-exchange invites without a QR; and a
graphical linking/friends/segment manager in the app. These need platform
permissions and on-device validation.

NOT certified / NOT audited — see the project README.
