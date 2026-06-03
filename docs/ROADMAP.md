# Platform roadmap (planned — not built)

> **Status: PLANNED.** Nothing in this document is implemented yet. It records
> the intended platform matrix so it isn't lost; each item is future work. What
> *is* built today is in [`PLATFORMS.md`](PLATFORMS.md) (Rust core + `uniffi`
> FFI, CLI/TUI, the documented Android/Tauri integration paths).
>
> This roadmap was imported from sibling planning notes; the bracketed
> `#NNN` / `APP-*` codes are roadmap item IDs carried over as stable
> references. Paths/names are normalized to talkrypt. See
> **"Reconcile with the current architecture"** at the end — several items
> (a separate Go helper, custody tiers, entropy-source companions, a web app)
> are *additions to or departures from* the single-Rust-core/`uniffi` design and
> need an explicit decision before work starts.

## Desktop OS — native helper as a separate sidecar (Unix socket / Named Pipe)

A local helper process exposes OS-privileged operations (key storage, etc.) to
the app over a local IPC channel:

- **macOS** — Unix socket at `~/Library/Application Support/talkrypt/helper.sock`.
- **Linux** (single static binary, all distros) — Unix socket at
  `$XDG_RUNTIME_DIR/talkrypt/helper.sock` (fallback `/tmp/talkrypt-$UID/helper.sock`).
- **Windows 10+** — Named Pipe `\\.\pipe\talkrypt-helper-<SID>` with an SDDL ACL;
  discovery file under `%LOCALAPPDATA%\talkrypt`.

### Desktop Linux — first-class packaging targets (#532, #533, #295)

Architectures: **amd64, arm64, armv7** (#532).

- Debian / Ubuntu / Pop!_OS / Mint / elementary / Devuan / PureOS
- Fedora / RHEL / openSUSE
- Arch + derivatives (AUR)
- NixOS / Guix
- Alpine + postmarketOS
- Void
- Slackware
- Gentoo
- Tails, Whonix, Qubes, Parrot, Kali, BlackArch, CAINE
- Raspberry Pi OS / Raspbian
- Trisquel

## Mobile — OS hardware key-store bridges (architecturally distinct; **not** the pipe sidecar)

- **iOS** (#296) — Secure Enclave + Keychain bridge.
- **Android** (#297) — StrongBox / Keymaster / Keystore bridge.
- **GrapheneOS** — covered under Android (#297); benefits from stricter
  sandboxing. TRNG / StrongBox entropy source surfaced separately in #409.

## Radio / IoT class

- **#298 APP-STREAM-IOT** — single-channel radio/IoT clients (LoRa / Meshtastic /
  HF / BLE).
- **#299 APP-VOICE-BRIDGE-STREAM** — voice/video bridge for radio/IoT
  single-channel clients.

## Browser-extension variants

- **#300 APP-WEB-EXT-FRAG** — fragmented/sharded webpage-channel mode.
- **#301 APP-WEB-EXT-AMBIENT-TOKEN** — ambient-token identity federation
  (site-token → talkrypt identity).
- **#302 APP-WEB-EXT-ISOLATION** — isolated cryptographic worker inside an MV3
  extension.
- **#303 APP-FED-WEBPAGE-NORMAL** — cross-mode federation between
  webpage-channel users and normal talkrypt users.
- **#304 APP-FILTERED-FRAMEWORK** — generalized filtered-access-mode framework.

## Web app

Carried in the source roadmap as an existing reference React 19 / Vite /
Tailwind v4 implementation ("not a port"). **talkrypt has no web app today** —
this is an imported item to reconcile, not a current component.

## Companion / bridge platforms (entropy-source class, #431–#437)

- **#431** — native messaging host on Chrome / Edge / Firefox.
- **#432** — localhost companion (Ledger-Live pattern).
- **#436** — Android companion bridge.
- **#437** — iOS companion bridge.

## Cross-cutting

- **#305 APP-PQ-PARITY** — PQ + custody-tier parity audit across every platform
  variant above. **Audit primitive built** (`talkrypt_helper::parity`):
  platforms self-report `Capabilities` (PQ identity? which custody tiers?), and
  `audit()` produces a verdict — **PQ parity is a hard requirement** (any
  non-PQ platform fails), while **custody-tier differences are surfaced, not
  failed** (a phone's Secure Enclave legitimately beats a headless desktop; the
  gap is reported). Each platform contributes via `local_report`; aggregating
  the set across machines (CI) and adding the non-desktop reporters is the
  remaining work.

## Political filter — packaging inclusion policy (#533)

First-class Linux packaging is **gated** on each distro's public commitment to
**never implement government-mandated age verification or identity
attestation**. The deliverable of #533 is the tiering, not yet finalized:

- **Tier 1** — signed packages + CI.
- **Tier 2** — community recipes.
- **Tier 3** — source-build-only.

## Reconcile with the current architecture (open decisions)

These items diverge from the shipped design and need an explicit call before
implementation — flagged here rather than silently adopted:

1. **Separate helper process vs. single Rust core. → RESOLVED: option (a).**
   The desktop helper is a **Rust crate (`crates/helper`, `talkrypt-helper`)
   that reuses the audited core** — no second-language reimplementation, so the
   audit surface stays unified. It speaks a small length-prefixed protocol over
   an owner-only Unix socket (macOS/Linux; `chmod 0600` in a `0700` dir) and
   performs only IPC + custody: sealing via `talkrypt_server::keystore`
   (Argon2id + AES-256-GCM), identities via `talkrypt_crypto::IdentityKeyPair`
   (ML-DSA-87), invite parsing via `talkrypt_core::ChatDescriptor`. The Windows
   Named-Pipe transport is **deliberately gated off** until it carries an SDDL
   ACL bound to the current SID (a default-DACL pipe is connectable by any local
   user) — the helper refuses to expose an under-protected pipe rather than ship
   an insecure default. Tested end-to-end over a real Unix socket.
2. **Custody tiers / key-custody. → FOUNDATION IN PLACE.** A `CustodyTier`
   model now exists (`talkrypt_helper::custody`): `SoftwareSealed <
   OsKeystore < HardwareBacked`, ordered, with a `Capabilities` protocol op so
   every platform reports the tiers it supports plus whether identities are PQ
   (the #305 "PQ + custody-tier parity" hook). The desktop helper reports
   exactly `SoftwareSealed` today (Argon2id + AES-256-GCM); the stronger tiers
   are explicit slots reported as *unsupported* so a parity audit sees the gap
   honestly. **Remaining:** the actual OS-keystore bridge (Keychain / DPAPI /
   Secret Service) and hardware-backed bridges (Secure Enclave / StrongBox /
   TPM), and mirroring the tier model on the mobile/FFI side.
3. **Entropy-source companions (#431–#437).** The "entropy-source class" framing
   implies companions feed RNG/entropy or hold custody. Their trust model and
   how they interact with the PQ KEM/RNG must be specified — a companion that
   influences key generation is security-critical, not a mere shell.
4. **Web app / browser extensions.** In-browser crypto (MV3 worker, webpage
   channels) is a materially different threat model from native; the isolation
   guarantees (#302) and federation (#303) need their own design + the same
   non-certification/non-audit caveats as the rest of the project.

Until these are decided, treat the matrix above as *direction*, and every
platform claim as subject to the project-wide **NOT CERTIFIED / NOT AUDITED**
disclaimer (see the README).
