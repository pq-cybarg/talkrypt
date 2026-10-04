# Emulator ↔ real-hardware test bridge (round-robin via the Mac host)

Feasibility + recipe for bilateral talkrypt testing that mixes **Android
emulators** (behind the AVD user-mode NAT) with **real USB-attached devices**,
bridged through the Mac host both can reach. Investigation for task #46.

## The reachability facts (why this works)

- **Emulator → Mac host:** every AVD can reach the host loopback at the fixed
  NAT alias **`10.0.2.2`** (the emulator's view of the host's `127.0.0.1`). So an
  emulator connecting to `10.0.2.2:9779` lands on a listener bound to the Mac's
  `127.0.0.1:9779`. (Proven already for the two-emulator LAN bridge; see memory
  `emulator-lan-bridge`.)
- **Mac host → real device:** `adb -s <serial> forward tcp:<L> tcp:<D>` maps the
  Mac's `127.0.0.1:<L>` to the device's `<D>`. One distinct `<L>` per device.
- **Real device → Mac host:** `adb -s <serial> reverse tcp:<D> tcp:<M>` maps the
  device's `localhost:<D>` to the Mac's `127.0.0.1:<M>` (the reverse direction, if
  a real device must initiate toward the mesh).

Composed: a **relay on the Mac** accepts connections from emulators (via
`10.0.2.2`) and from devices (via `reverse`), and forwards each to a real device
(via `forward`). The Mac is the rendezvous both NAT domains share.

## Round-robin relay

`scripts/test/roundrobin-bridge.py` is a stdlib asyncio TCP relay: each **new
connection** is spliced to the **next backend** in a rotating pool and pinned
there for the connection's life (connection-level rotation, so a talkrypt session
isn't torn mid-stream). With N emulator-origin connections and M device backends,
sessions fan round-robin across the devices — the "round-robin rotation" idea from
the task.

```
python3 scripts/test/roundrobin-bridge.py \
    --listen 127.0.0.1:9779 \
    --backends 127.0.0.1:19001,127.0.0.1:19002
```

## Recipe

`scripts/test/hw-bridge.sh` wires the adb forwards and launches the relay:

```sh
# Two real phones on talkrypt LAN port 9779, bridged for emulator access:
bash scripts/test/hw-bridge.sh SM02G4061972692,ZY227KJ4 9779
#   -> adb forward tcp:19001 -> phone1:9779
#   -> adb forward tcp:19002 -> phone2:9779
#   -> relay on 127.0.0.1:9779 round-robins across them
```

Then on each **emulator**, host/join talkrypt pointing at `10.0.2.2:9779`
(the emulator's alias for the Mac relay). Join via deep link to bypass fragile UI
nav (see `emulator-lan-bridge`):

```sh
adb -s emulator-5556 shell am start -a android.intent.action.VIEW \
    -d "<talkrypt-invite-uri>" com.talkrypt.app
```

## What this is good for / limits

- **Good for:** exercising the LAN transport across the emulator/real-HW boundary
  without a physical LAN both can join; load-spreading test traffic across a device
  pool; cheap CI-ish bilateral runs on one Mac.
- **Transport-layer only:** the relay is a dumb byte splice. talkrypt's E2E crypto
  is unchanged and unseen by the relay (it only sees ciphertext) — this does NOT
  weaken the security model, it just moves bytes.
- **Not a product feature:** this is a *test harness*. It is not the hosting/relay
  path the app ships (that's the onion/gossip/Nym transports). Keep it under
  `scripts/test/`.
- **Connection-level rotation caveat:** round-robin pins per connection, so a
  single long-lived session always hits one backend; rotation only spreads
  *distinct* sessions. For a specific A↔B pairing, point the relay at a single
  backend (the intended peer) rather than a pool.

## Validation status

Design + scripts written and self-checked (Python import + rotation unit check;
`bash -n`). The round-robin *real-device* fan-out still needs attached hardware to
run end-to-end (Seeker unplugged per memory `test-hardware-and-emulation`).

**Emulator ↔ Mac-native session: VERIFIED (2026-10).** The underlying
reachability primitive — an Android emulator reaching a Mac-native talkrypt host —
was proven directly: `target/debug/talkrypt host --listen <Mac-LAN-IP>:9779`
(the CLI advertises the `--listen` value **verbatim** in the invite, so bind the
Mac's routable LAN IP, which the emulator reaches via its NAT — `0.0.0.0`/
`127.0.0.1` are *not* usable from the guest), then deep-link-join on the emulator
(`am start -a VIEW -d "<invite>" com.talkrypt.app` → tap "Join as pseudonym").
Result: a connected pairwise session (host `* peer connected`, emulator
`● online · connected`) with **bidirectional messages delivered and correctly
attributed** (Mac→emulator and emulator→Mac). This confirms the emulator→Mac-host
leg every bridge topology above depends on.

**Group (TreeKEM) cross-device also verified — and surfaced + fixed a real FFI
bug.** Repeating the test against a `talkrypt host --group` host initially failed:
the emulator connected at the transport layer but never became a keyed group
member (`1 members`, no group messages crossing), while a Mac-native
`talkrypt join --group` against the same host worked — isolating the fault to the
FFI join path. Root cause: `TalkryptClient::join`/`join_tor` always built a
*pairwise* `Core::new`, ignoring the invite's `desc.group`, so a group invite was
silently joined pairwise and never performed the TreeKEM member-add. Fixed to
branch on `desc.group` → `Core::new_group(.., false)` (mirroring the CLI/desktop).
After rebuilding the APK and re-testing: the emulator joins as a keyed TreeKEM
member and **signed group messages flow both ways with correct attribution**
(`decrypt_verified` per-leaf ML-DSA). Tip for the on-device retest: `adb shell pm
clear com.talkrypt.app` for a clean slate between runs — stale session state
caused spurious non-connects.
