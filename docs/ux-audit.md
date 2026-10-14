# UI/UX audit — TUI, desktop, Android (2026-10)

A cross-client UX breakdown before the security pentest pass. Each client was
read end-to-end; findings cite `file:line`. Severity: **blocker** (user hits a
wall or is actively misled) / **major** (significant friction or missing core
feedback) / **minor** / **polish**.

> Scope: this is a UX audit of the *clients*, not the crypto core. The engine
> (`crates/core`, `crates/crypto`) is comparatively mature; the gap is that the
> clients expose only a fraction of it, and surface state inconsistently. NOT
> certified / NOT audited (project-wide).

## Maturity at a glance

| Client | Threads network off UI? | Onboarding (QR) | Per-msg delivery state | Stable identity | Feature parity w/ CLI | Verdict |
|---|---|---|---|---|---|---|
| **Android** | ✅ `thread{}`+`ui.post` | ✅ scan + show | ❌ (detached "✓ delivered") | ✅ sealed seed | ~70% | strongest; one pass from shippable |
| **Desktop** | ✅ worker thread + prewarmed Tor | ✅ QR-first | ❌ (`Delivered` swallowed) | ❌ regenerated each launch | ~30% | good bones, demo-grade |
| **TUI** | ⚠️ `.await?` on join, blank screen | ❌ no QR at all | ❌ (ignored) | n/a | ~15% | toy skeleton (~360 LoC) |

## Cross-cutting themes (fix once, helps all three)

1. ~~**Delivery state is never shown.**~~ **FIXED (Rust clients; Android enabled).** `Core::send` now returns the message's `gossip_id`, so a client can correlate a later `Event::Delivered { gossip_id }` to the exact message. **Desktop** renders per-bubble state — `·` sent / `✓✓` delivered (on ack) / `✗` failed (on `OutboxDropped`), tracked via `Session.sent_index` (gid → bubble). **TUI** marks own lines `· → ✓✓` on delivery and surfaces drops as an explicit `✗` line. (Honest nuance: acks exist only on the group/persistent path; a pairwise 1:1 chat has no ack, so `·` sent is terminal there — not a false `✓✓`.) The FFI `send` now returns the hex `gossip_id` too, so the **Android** per-bubble treatment is a bindings-regen + Kotlin follow-up (same model).
2. **Errors live in one transient status slot and vanish.** Desktop funnels *every* event (send fail, join fail, bad invite, vouch, name, CQ) into one `status: String` that the next event overwrites (`main.rs:674,781-785`); TUI overwrites its rich status bar with bare `"peers: N"` on the first event (`main.rs:201`); Android uses 2s `Toast.LENGTH_SHORT` for raw Rust errors (`MainActivity.kt:2040,1209,...`). Users miss failures. **Fix:** a persistent, re-readable error surface (inline on the failed action + a small log), and route raw FFI errors through a friendly mapper (Android already has `ChatNet.friendlyError` — extend its use).
3. **Connect/bootstrap feedback is inconsistent.** Desktop + Android *join* do this well (live Tor bootstrap %); but **host-over-Tor is a frozen form** on Android (`MainActivity.kt:1996-2042`, only a toast) and the TUI shows a blank screen while `establish().await?` runs (`main.rs:117`). **Fix:** give host the same connecting/progress screen as join; give the TUI any "connecting…" indication.
4. **Clients expose a fraction of the trust model.** None surface a persistent **safety-number / verification** screen (desktop `main.rs:604-606` transient; TUI device-only `main.rs:217`; identity model, contacts, friends, vouching, device-linking, usernames all CLI-only). For an E2EE product, verification being decorative text rather than an actionable screen is a security-UX gap.
5. **Everything is dark-theme-only, jargon-labelled, un-timestamped.** "pq-pure/hybrid/pq-pure-compact" posture labels appear raw in all three with no explanation; no message timestamps anywhere; no light theme / font scaling.

## Per-client blockers & majors (the actionable short list)

### Desktop (`crates/desktop/src/main.rs`)
- ~~**BLOCKER — "Persistence" dropdown is dead.**~~ **FIXED** — persistence is now wired end-to-end: `Cmd::Host` carries `persistence` + a seal passphrase; a Persistent/Always-on chat opens a passphrase-sealed `SealedFileStore` (AES-256-GCM, Argon2id KEK) as both the outbox and history store, sets `Persistence::Persistent` on the descriptor, calls `set_persistence(true)` (+ `keeper_mode(true)` for Always-on), and redisplays retained history on reopen. The passphrase field appears when persistence ≠ Ephemeral; wrong passphrase fails closed. (Default is now Ephemeral — the old "Persistent" default was a dead no-op.)
- ~~**BLOCKER — "contacts"/"friends" access locks out everyone**~~ **FIXED** — the desktop now loads a persisted contact list (`contacts.tsv`) into every `Core` and offers an **Add contact / Add friend** affordance on a peer that has presented its account (via `add_seen_contact` → saved), so `restrict_to_contacts`/`restrict_to_friends` has a real, user-built set to admit.
- ~~**MAJOR — ephemeral identity every launch**~~ **ADDRESSED as a choice** — identity is now user-selectable: **Ephemeral** (fresh each launch, nothing on disk — the privacy-first default and an opsec feature, not a bug) or a named **persistent persona** (0600 seed under `identities/<name>.key`, stable across launches → stable safety numbers + working contacts). A **first-run modal** makes the choice explicitly; multiple personas allow **compartmentalizing associate groups** (mutually unlinkable), and **Burn** secure-erases a persona's seed on request. (Device-linking remains CLI-only.)
- **MAJOR — transcript height math clips the composer** (`:1064` reserves 52px under ~90px of controls); no `min_inner_size` (`:1208-1213`) so the window drags arbitrarily small.
- **MAJOR — no way to leave/close/delete a chat** (`:941,969` only push); dead chats accumulate forever.

### Android (`android/app/src/main/kotlin/...`) — strongest client
> Validation note: the APK (with regenerated uniffi bindings for this round's FFI
> changes) **builds, installs, launches, and runs with no talkrypt crash** on the
> `tk_phone` emulator. Deeper functional UI automation was blocked by the
> swiftshader emulator destabilizing (`system_server` crashed, `DeadSystemException`
> cascade) — an environment artifact, not the app. Fixes below are compiled +
> code-reviewed; on-device functional retest pending a stable device/emulator.
- ~~**MAJOR — host-over-Tor frozen form**~~ **FIXED** — `startHost` now shows the live `connectingScreen(...)` (same Tor-bootstrap % as join) for a Tor/Nym host instead of a toast on the unchanged form, and returns to the list on failure.
- ~~**MAJOR — no double-submit guard**~~ **FIXED (host/join)** — an `inFlight` guard rejects a second Host/Join tap while the first is bootstrapping (reset in a `finally`), so no duplicate sessions/listeners. (Spawn-anchor/Link still to guard — follow-up.)
- ~~**MAJOR — `REQ_BLE` has no handler** + grant races first use~~ **FIXED** — `ensureBlePermissions(onGranted)` defers the beacon/mesh start until the grant resolves (stashed in `pendingBle`), and a new `REQ_BLE` branch in `onRequestPermissionsResult` resumes it. First beacon/mesh tap no longer silently fails.
- **MAJOR — main-thread unseal / ML-DSA reconstruct** in `settingsScreen`/`anchorsScreen`/`segmentsScreen`/`joinPreflightScreen`/`restrictedHostScreen` → ANR/jank. *Still open* (follow-up: move onto the `thread{}`+`ui.post` pattern the chat-list header already uses).
- **MAJOR — camera-denial dead-end** (`QrScanActivity.kt`) and **scanner accepts any QR then rejects it** — *still open* (follow-up).
- **Per-bubble delivery state** — the FFI `send` now returns the hex `gossip_id` (bindings regenerated), so the Android per-bubble treatment is unblocked — *Kotlin render still to do*.
- **MAJOR — no localization**: all strings hardcoded English — *still open*.

### TUI (`crates/tui/src/{main,app}.rs`) — toy skeleton
> **RESOLVED (2026-10)** — all blockers + the resize/scrollback/status majors fixed; see `crates/tui` tests `newest_line_visible_despite_a_long_wrapped_line`, `scrolling_up_reveals_older_then_end_returns_to_newest`, `push_qr_renders_block_rows_for_an_invite`.
- ~~**BLOCKER — Ctrl-C types a literal `c`**~~ **FIXED** — the input thread now forwards full `KeyEvent`s; Ctrl-C/Ctrl-D quit (the footer advertises it).
- ~~**BLOCKER — no QR / invite onboarding**~~ **FIXED** — host (and `/invite`) render the invite as a scannable Unicode-half-block QR via `App::push_qr` (same `qrcode` crate as the CLI).
- ~~**MAJOR — resize doesn't redraw**~~ **FIXED** — `Event::Resize` is forwarded as a redraw signal, so the layout refreshes immediately.
- ~~**MAJOR — wrapped lines hide newest messages / no scrollback**~~ **FIXED** — the pane pre-wraps to visual rows and windows the tail (newest always visible); PgUp/PgDn/Home/End scroll, with a "[scrolled]" status hint.
- ~~**MAJOR — status bar destroyed after first event**~~ **FIXED** — the rich prefix (topology · address · suite) is stable; only the live `peers:` count updates.
- **MAJOR — command surface is ~5 of the CLI's ~40** — *still open* (deliberately deferred): contact/username/access/vouch/account-verify operations remain CLI-only; a dedicated follow-up (not a blocker to basic usability, which this pass restored).

## Recommended fix order (highest leverage first)

1. **Delivery/failure state per message + retry** — all three clients, driven off the already-emitted core `Delivered`/`OutboxDropped` events. (Theme 1.)
2. **Persistent, re-readable error surface** + friendly FFI-error mapping. (Theme 2.)
3. **Desktop: remove the two traps** — either wire `persistence` through to the descriptor and load/persist contacts, or remove the dead "Persistent/Always-on" and "contacts/friends" options until backed. (Desktop blockers.)
4. **Desktop: persist identity** (reuse the CLI's account load/save) so verification/contacts become possible at all. (Desktop major #3.)
5. **Android: host-over-Tor progress screen + double-submit guards + move unseal/ML-DSA off the main thread + add the `REQ_BLE` handler.** (Android majors.)
6. **TUI: fix Ctrl-C quit, resize redraw, and render the invite QR** (reuse `print_qr`). (TUI blockers/major.)
7. **A verification/safety-number screen** shared in spirit across clients. (Theme 4.)
8. Polish: timestamps, light theme, posture-label help text. (Theme 5.)

## What each client already does right (preserve)
- **Desktop:** non-blocking worker thread; prewarmed Tor with live bootstrap %; per-session QR; online/offline has a text label not just color.
- **Android:** off-main-thread FFI throughout; real Tor-bootstrap % + Cancel with stale-generation guard; draft/scroll preserved via in-place updates; honest "Sealing degraded" custody disclosure; fail-closed sealing that never clobbers an unreadable seed.
- **TUI:** monochrome log is incidentally friendly to no-color/screen-reader terminals; safe tiny-terminal math (no panic).
</content>
</invoke>
