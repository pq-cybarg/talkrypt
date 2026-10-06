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

1. **Delivery state is never shown.** All three optimistically echo on `send() == Ok` and then **ignore `Delivered`/`OutboxDropped`**: TUI `main.rs:189-190,221-224`, desktop `main.rs:519,618-619`, Android `MainActivity.kt:2237-2241` + `ChatEvents.kt:88-90`. A dropped/undelivered message looks identical to a delivered one. **This is the single highest-value fix:** thread a per-message state (`sending → delivered | failed`) from the core event into each bubble, with a retry affordance.
2. **Errors live in one transient status slot and vanish.** Desktop funnels *every* event (send fail, join fail, bad invite, vouch, name, CQ) into one `status: String` that the next event overwrites (`main.rs:674,781-785`); TUI overwrites its rich status bar with bare `"peers: N"` on the first event (`main.rs:201`); Android uses 2s `Toast.LENGTH_SHORT` for raw Rust errors (`MainActivity.kt:2040,1209,...`). Users miss failures. **Fix:** a persistent, re-readable error surface (inline on the failed action + a small log), and route raw FFI errors through a friendly mapper (Android already has `ChatNet.friendlyError` — extend its use).
3. **Connect/bootstrap feedback is inconsistent.** Desktop + Android *join* do this well (live Tor bootstrap %); but **host-over-Tor is a frozen form** on Android (`MainActivity.kt:1996-2042`, only a toast) and the TUI shows a blank screen while `establish().await?` runs (`main.rs:117`). **Fix:** give host the same connecting/progress screen as join; give the TUI any "connecting…" indication.
4. **Clients expose a fraction of the trust model.** None surface a persistent **safety-number / verification** screen (desktop `main.rs:604-606` transient; TUI device-only `main.rs:217`; identity model, contacts, friends, vouching, device-linking, usernames all CLI-only). For an E2EE product, verification being decorative text rather than an actionable screen is a security-UX gap.
5. **Everything is dark-theme-only, jargon-labelled, un-timestamped.** "pq-pure/hybrid/pq-pure-compact" posture labels appear raw in all three with no explanation; no message timestamps anywhere; no light theme / font scaling.

## Per-client blockers & majors (the actionable short list)

### Desktop (`crates/desktop/src/main.rs`)
- **BLOCKER — "Persistence" dropdown is dead.** Built at `:926`, stored at `:705/:734`, but `Cmd::Host` has no persistence field and the descriptor hardcodes `Persistence::Ephemeral` (`:406-411`); `self.persistence` is never read. User picks "Persistent", silently gets ephemeral → data-loss lie.
- **BLOCKER — "contacts"/"friends" access locks out everyone.** Host calls `restrict_to_contacts()`/`restrict_to_friends()` (`:426-427`) but no contacts are ever loaded (and identity is fresh each launch), so **every joiner is silently rejected**. Offered as a normal choice at `:925`.
- **MAJOR — ephemeral identity every launch** (`:413,419,497,501`): fingerprints/safety numbers change each session; contacts/verification can never work. No account load/save or device-linking (CLI has them).
- **MAJOR — transcript height math clips the composer** (`:1064` reserves 52px under ~90px of controls); no `min_inner_size` (`:1208-1213`) so the window drags arbitrarily small.
- **MAJOR — no way to leave/close/delete a chat** (`:941,969` only push); dead chats accumulate forever.

### Android (`android/app/src/main/kotlin/...`) — strongest client
- **MAJOR — host-over-Tor frozen form** (`MainActivity.kt:1996-2042`): join gets a live bootstrap screen (`:2158-2193`), host gets only a toast.
- **MAJOR — no double-submit guard**: Host/Join/Spawn-anchor/Link buttons stay enabled during the in-flight `thread{}` (`:324,2040,1645,1198,1782`) → double sessions/listeners.
- **MAJOR — main-thread unseal / ML-DSA reconstruct** in `settingsScreen` (`:924`), `anchorsScreen` (`:1594,1602`), `segmentsScreen` (`:1356-1363`), `joinPreflightScreen` (`:2058`), `restrictedHostScreen` (`:1711`) → ANR/jank on cold start. (Chat-list header does it off-thread at `:396-399` — follow that pattern.)
- **MAJOR — BLE permission grant races first use** (`:553-563,595-620`) **and `REQ_BLE` has no handler** in `onRequestPermissionsResult` (`:1526-1530`) → first beacon/mesh tap always silently fails.
- **MAJOR — camera-denial dead-end** (`QrScanActivity.kt:120,155`): deny → permanent black screen, no rationale / settings / retry.
- **MAJOR — scanner accepts any QR then rejects it** (`QrScanActivity.kt:240-241` finishes on first decode; caller toasts "Not a talkrypt QR" `:241`) — should keep scanning until a `talkrypt://` payload.
- **MAJOR — no localization**: all strings hardcoded English, no `strings.xml`, RTL in `configChanges` but no resources.

### TUI (`crates/tui/src/{main,app}.rs`) — toy skeleton
- **BLOCKER — Ctrl-C types a literal `c`** (`main.rs:139,205` read only `k.code`): the universal quit reflex inserts a char; only `Esc`/`/quit` exit, unadvertised.
- **BLOCKER — no QR / invite onboarding**: host dumps the URI as plain scrollback text (`main.rs:100-102`), join shows nothing; the CLI's `print_qr()` is not used. The in-person QR join the product centers on is absent.
- **MAJOR — resize doesn't redraw** (`Event::Resize` dropped at `main.rs:138`): screen stays garbled until the next keypress.
- **MAJOR — wrapped lines hide newest messages** (`app.rs:57-60` counts logical not visual rows) and **no scrollback** (no PageUp/Down); history is unreachable.
- **MAJOR — command surface is ~5 of the CLI's ~40** (`main.rs:213-219`): no contact/username/access/vouch/verify-account operations.

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
