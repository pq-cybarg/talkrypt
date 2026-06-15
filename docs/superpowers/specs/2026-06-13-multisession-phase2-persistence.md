# Multi-session chats — Phase 2 design (persistence tiers)

**Status:** DELIVERED — 2a (reconnect) in commit 5903bd1, 2b (always-on service +
boot reconnect) in commit 89f6d49 (`SessionHub`, `ChatNet`, `ChatEvents`,
`ChatService`, `BootReceiver`; verified on-device).
**Builds on:** Phase 1 (`Sessions`, `ChatStore`, chat list, per-room history).
**Scope:** Android app only. The Rust core/FFI already expose what's needed
(`hostTor`/`joinTor` take a per-call `stateDir`; reconnect = re-host/re-join).

## Goal

Make the persistence tier *mean* something at runtime:

- **Ephemeral** — as today: live while the app is open, never persisted.
- **Persistent (local)** — history sealed (Phase 1); now also **reconnects**: a
  saved-but-disconnected chat comes back **live** when you open it (or via an
  explicit Reconnect), instead of read-only.
- **Always-on** — stays connected **even when the app is backgrounded/killed**,
  via a foreground `ChatService`, and **reconnects after reboot**.

Delivered in two increments: **2a (reconnect)** then **2b (always-on service)**.

## Increment 2a — reconnect

### Per-chat Tor onion dirs
Today all Tor chats share one `filesDir/tor` state dir, so multiple persistent
onion hosts would collide on one identity. Change to **per-chat**:
`torDir(chatId) = filesDir/tor/<chatId>`. A host chat reuses its dir → the same
`.onion` across reconnects/restarts. `ChatMeta` already stores `onion`.

### Reconnect a disconnected chat
`reconnect(lc)` (off the main thread), driven by `meta.role`:
- **Host** — `hostTor(channel, posture, torDir(id))` if `onion != null`, else
  `host(lan:9779, channel, posture)`; re-apply `presentAccount` + `loadContacts`
  + `setAccessMode(access)`. A Tor re-host yields the same `.onion`; a LAN
  re-host yields a fresh `inviteUri` (update `meta`).
- **Join** — `joinTor(inviteUri, torDir(id))` if `onion != null`, else
  `join(inviteUri)`; re-present account.
On success: set `lc.client`, refresh the row's live dot, persist meta.

### When reconnect fires
- **Lazy on open:** tapping a disconnected (`client == null`) persistent chat
  shows it immediately (history) and kicks off `reconnect` in the background;
  the live dot lights when connected. Avoids bootstrapping every onion on launch.
- **Manual:** the chat overflow (⋯) and a disconnected row offer **Reconnect**.
- **Always-on:** auto-reconnected by the service (2b), not lazily.

A `sendMessage` to a disconnected chat triggers `reconnect` first (then the send
retries once connected), instead of just toasting "reopen to reconnect".

## Increment 2b — always-on foreground service

### Process-shared sessions
Move the `Sessions` instance to a process singleton (`SessionHub.sessions`) so
the Activity **and** the service share one set of live clients. The Activity
renders from it; the service keeps the process (hence the clients) alive.

### `ChatService` (foreground)
A started, foreground `Service` with a persistent notification
("talkrypt — N chat(s) active"). Responsibilities:
- own the **poll loop** (moved off the Activity) so events are drained even with
  no UI; the Activity, when visible, renders from the same `Sessions`;
- **reconnect all `ALWAYS_ON` chats** on start;
- run only while ≥1 chat is `ALWAYS_ON`. Promoting a chat to always-on starts it;
  demoting/closing the last always-on chat stops it.

Foreground type: `dataSync` (API 34+). The notification is required by Android
and is also honest — the user can see talkrypt is holding connections.

### Boot reconnect
A `BootReceiver` (`RECEIVE_BOOT_COMPLETED`) starts `ChatService` after reboot if
any saved chat is `ALWAYS_ON`, which reconnects them.

### Manifest additions
`FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`, `POST_NOTIFICATIONS`
(API 33 runtime prompt), `RECEIVE_BOOT_COMPLETED`; the `<service>` and
`<receiver>`.

### Tier selection
The new-chat **PERSISTENCE** spinner's "Always-on" option becomes real (no longer
downgraded). The chat overflow lets you change a chat's tier (Ephemeral ↔
Persistent ↔ Always-on); changing to/from Always-on starts/stops the service.

## Honest limits (carried from the design discussion)
- "Survive app kill" keeps the **session** alive only while the **process** is;
  Android may still kill a foreground service under extreme pressure, and the
  user can force-stop. After a real teardown, the chat **reconnects** (fresh
  session to the same `.onion`) — it does not **resume** the exact ratchet (that
  would require sealing evolving session state, weakening forward secrecy; out of
  scope, per §3b of SECURITY-AUDIT).
- A **joined** always-on chat can only reconnect if the host's `.onion` is up.
- LAN (non-Tor) chats aren't reachable after the host moves networks; persistence
  is meaningful mainly for Tor/onion chats. The UI notes this.

## Testing
- **JVM unit tests:** `reconnect` target selection (host-vs-join, onion-vs-LAN)
  as a pure function over `ChatMeta` → an enum/plan, so it's testable without the
  native lib; `SessionHub` singleton identity; service start/stop predicate
  (`anyAlwaysOn(sessions)`).
- **Emulator:** host a **Persistent** chat → kill app → reopen → open the chat →
  it reconnects (live dot). Create an **Always-on** chat → background the app →
  confirm the foreground notification persists and the poll loop runs. (Tor
  bootstrap + multi-peer exchange remain manual where a second peer is needed.)

## Out of scope (Phase 3)
Ephemeral→persistent promotion + member picker + the three promotion modes.
