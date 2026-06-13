# Multi-session chats — Phase 1 design

**Status:** approved direction; Phase 1 spec for review.
**Scope:** Android app only (`crates/ffi` + `android/`). The Rust core is unchanged
in Phase 1 (it already supports everything we need; see *Core mapping*).

## Goal

Turn the Android client from a **single live chat** (one `client`, "leaving"
drops it, no way back) into a **Telegram-style multi-chat client**: many chats
stay live at once, a chat list is the home, Back returns to the list while the
chat keeps running, and every chat's history is saved at rest.

This is the **foundation** for Phase 2 (per-chat persistence tiers) and Phase 3
(ephemeral→persistent promotion). Phase 1 builds the data model and seams those
phases extend; it does **not** add a foreground service, persistent-onion
reconnect, or promotion (those are Phases 2–3). Where a Phase 1 field exists only
to be filled later (e.g. `persistence` tier), the spec says so.

## First principle: a chat is a multi-party room

The local user is **one of several** participants in any chat (group/TreeKEM,
hub, or multi-peer P2P). Every part of the model reflects this:

- A chat has a **roster** (the members seen so far), not a single peer.
- Every stored message is **attributed to its sender** (fingerprint + resolved
  account/username/contact status), because many people speak in one room.
- The chat-list row shows **membership** (e.g. "4 members") and the **last
  sender**, not a 1:1 "other person."
- "You" is just one roster entry; outgoing messages are attributed to self.

## Core mapping (why Phase 1 is app-only)

| Need | Already in the core / FFI |
| --- | --- |
| Independent concurrent sessions | each `TalkryptClient` is self-contained; today the app just keeps one |
| Multi-party rooms + sender attribution | `FfiEvent.Message{from,channel,text,marking}`, `FfiEvent.Identity{accountFingerprint,username,contact,friend}`, `Connected`/`Disconnected{fingerprint}` |
| Groups | TreeKEM (`--group`), hub/p2p topologies |
| History encryption at rest | the FFI **seal** API (`seal_secret`/`unseal_secret`, `HardwareKeyWrapper`) we just shipped |
| Stable address (Phase 2) | persistent onion (`hostTor` + persistent state dir) |
| Membership/allow-lists (Phase 3) | `setAccessMode`, `allow`/`deny`, account allow-list |

## Architecture

### Session manager (replaces the single `client`)

A process-lifetime `Sessions` object owns all live chats:

```
Sessions
  chats: LinkedHashMap<String /*chatId*/, LiveChat>   // insertion = recency
  active: String?                                      // chatId currently on screen, or null (list)
```

```
LiveChat
  meta:    ChatMeta
  client:  TalkryptClient?          // null = not currently connected (saved-only)
  history: MutableList<ChatMsg>     // in memory; sealed to disk for kept chats
  roster:  LinkedHashMap<String /*fp*/, Member>   // who's in the room
  unread:  Int
```

```
ChatMeta (serializable; the persisted record)
  id:          String        // stable: sha256(inviteUri) for joins; sha256(onion|listen|channel) for hosts
  title:       String        // channel (e.g. "#general") or a chosen name
  role:        Host | Join
  group:       Boolean
  posture:     String        // pq-pure | hybrid | pq-pure-compact
  access:      String        // open | contacts | friends   (host)
  inviteUri:   String?       // for re-share / reconnect
  onion:       String?       // set when hosted/joined over Tor (Phase 2 reconnect)
  persistence: Ephemeral | PersistentLocal | AlwaysOn   // Phase 1 implements Ephemeral + PersistentLocal; AlwaysOn is Phase 2
  safety:      String        // safety-number prefix for the header
  createdAt, lastActivityAt: Long
```

```
ChatMsg (serializable)
  kind:    Message | System | Action-note
  sender:  String?           // fingerprint of sender; null for system lines
  display: String?           // resolved username/contact label at receive time
  mine:    Boolean
  text:    String
  marking: String?           // classification banner if present
  ts:      Long

Member
  fp: String; display: String?; contact: Boolean; friend: Boolean; connected: Boolean
```

### One poll loop drains every live chat

Today `poll()` loops on the single `client`. Phase 1: a single `ui.postDelayed`
loop iterates **all** `LiveChat`s with a non-null client, drains `pollEvent()`
for each, and for every event:

- append a `ChatMsg`/update the **roster** on that `LiveChat`;
- if that chat is `active` (on screen) → render the bubble/system line live;
- else → increment `unread` and refresh its row in the list if visible;
- mark `lastActivityAt`; schedule a debounced seal-to-disk for kept chats.

Per-chat `pollEvent` failures are caught and surface as a system line in that
chat only — one chat erroring never stops the others.

### Persistence at rest (Phase 1)

- **Kept chats** (`PersistentLocal`): each chat is one sealed blob
  `chats/<id>.tkc` = `seal_secret(JSON{meta, history, roster})`, plus an index
  file `chats/index` listing ids + `lastActivityAt` for fast list rendering.
- **Encryption:** reuse the FFI **seal** seam. The sealing key is wrapped by an
  **Android Keystore / StrongBox** `HardwareKeyWrapper` (the one we built), so
  history is hardware-gated at rest with **no passphrase prompt**. If no secure
  element, it falls back to a device-key software seal. (This is the first real
  consumer of the hardware-backed sealing work.)
- **Ephemeral chats:** never written to disk; history lives in memory only and is
  dropped when the chat is closed or the app exits.
- Writes are debounced (e.g. 1–2 s after activity) and on `onPause`.

## UI / screens

### Chat list (new home) — `chatListScreen()`

Replaces `setupScreen()` as the launch screen. Telegram-style:

- Header: "talkrypt" + the custody/identity pill (kept from today).
- A scrolling list of chat rows, sorted by `lastActivityAt` desc. Each row:
  - leading glyph — `#` in an accent tile for a group, a person glyph for a
    direct/2-party chat;
  - **title**, then a muted second line: last message preview prefixed by its
    **sender** ("alice: hey") + member count for groups;
  - right: relative time, an **unread badge**, and a small **live dot** if the
    chat's client is connected.
  - tap → `chatScreen(chatId)`; long-press → row menu (Rename · Leave (disconnect,
    keep history) · Delete (disconnect + erase) · Re-share invite).
- A floating **+** → `newChatScreen()`.
- The current utility entries (Contacts · Anchors · Linked devices · Segments ·
  Find nearby · Share app) move behind an **overflow (⋯)** in the header so the
  home stays chat-first.
- Empty state: a friendly "No chats yet — tap + to host or join."

### New chat — `newChatScreen()`

Today's `setupScreen()` host/join/posture/access/Tor controls, minus the moved
utility buttons. Adds a **persistence selector** so the user picks the tier per
chat at creation: **Ephemeral** (memory only) or **Persistent** (sealed history,
reconnectable). **Always-on** appears as a third choice but is disabled/"coming
soon" in Phase 1 (it needs the Phase 2 foreground service); the selector and the
`persistence` field exist now so Phase 2 only flips it on. On successful
host/join it creates a `LiveChat`, adds it to `Sessions`, persists meta (and
history if kept), and opens `chatScreen(id)`.

### Chat — `chatScreen(chatId)`

The existing chat UI, parameterized by `chatId` (renders that `LiveChat`'s
history/roster; the input sends via that chat's client). Header gains:

- a **← back** button (left of the title) → return to the chat list; **the chat
  stays live** (client keeps polling, unread accrues).
- subtitle shows **member count + safety prefix + tier** (e.g. "4 members ·
  safety 1A2B3C4D · persistent").
- an overflow (⋯) for Leave / Delete / Re-share / Members.

### Back navigation

`onBackPressed()` (and the header ←):
- on a chat → go to chat list (do **not** disconnect);
- on `newChatScreen`/a utility subscreen → go to chat list;
- on the chat list → exit the app (default).

A `nav(view, kind)` helper centralizes `setContentView` + a small back-state enum
so system-back and header-back agree.

## Data flow

1. **Host/Join** (in `newChatScreen`) → builds a `TalkryptClient` (as today) →
   `Sessions.open(meta, client)` → persist → `chatScreen(id)`.
2. **Poll loop** updates every live chat's history/roster/unread + debounced seal.
3. **Switch chats**: tap a row → set `active=id`, render its history, clear its
   unread. Back → `active=null`, show the list.
4. **Leave** (row/overflow): drop the `TalkryptClient` (set `client=null`; the
   Arc drops → connection torn down) but keep `meta`+sealed history; the row
   stays as a reconnectable saved chat (reconnect = re-host/re-join from
   `inviteUri`/`onion`; full reconnect UX lands in Phase 2, but Phase 1 supports
   re-open of a saved chat by re-running host/join with the stored params).
5. **Delete**: drop client + erase the sealed blob + remove from index/list.
6. **App exit**: ephemeral chats vanish; kept chats are already sealed.

## Error handling

- A `pollEvent`/send failure is shown as a system line in the affected chat only.
- Seal/unseal failure: the chat still opens (history empty + a one-line warning);
  never crashes the list.
- A chat whose client is null renders history read-only with a "disconnected —
  reopen to reconnect" affordance.
- Corrupt/unreadable chat blob: skipped in the index with a logged warning, never
  blocks the list.

## File structure

New Kotlin (under `android/app/src/main/kotlin/com/talkrypt/app/`):
- `Sessions.kt` — the session manager + `LiveChat`, `Member` (in-memory state).
- `ChatModels.kt` — `ChatMeta`, `ChatMsg` + JSON (de)serialization (hand-rolled,
  no new deps — match the app's dependency-light style).
- `ChatStore.kt` — seal/unseal of per-chat blobs + the index, over the FFI seal
  API and an Android-Keystore `HardwareKeyWrapper`.

Modified:
- `MainActivity.kt` — `setupScreen()`→`newChatScreen()`; add `chatListScreen()`;
  `chatScreen()`→`chatScreen(chatId)`; `poll()`→`pollAll()`; `startHost`/`doJoin`
  create sessions; `onBackPressed()` + `nav()`; utilities behind overflow.

## Testing

- **FFI (Rust):** add a test that **two `TalkryptClient`s run concurrently** (host
  two chats, join both, exchange messages on each without interference) — proves
  the multi-session assumption at the core boundary. Lives in `crates/ffi`.
- **Kotlin (JVM unit tests):** add a `test/` source set for pure logic —
  `ChatModels` round-trip (serialize→deserialize equals), `Sessions` recency
  ordering + unread accounting, `ChatStore` seal→unseal round-trip against a mock
  `HardwareKeyWrapper`. No Android framework needed for these.
- **On-device (Seeker) manual checklist:** host chat A; from the list start join
  chat B; confirm both show "live", messages land in the right chat, unread
  badges accrue while viewing the other, Back keeps both alive, kill+reopen shows
  the kept chats with history, ephemeral chat is gone.

## Out of scope (Phase 2/3)

Foreground service / survive-app-kill; persistent-onion auto-reconnect on boot;
sealed *session* (ratchet) resume; ephemeral→persistent promotion + member
picker + the three promotion modes. Phase 1 only ensures the data model carries
the `persistence` tier and `onion`/`inviteUri` so those phases slot in.
