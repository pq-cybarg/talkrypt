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
  variant above (every platform must reach the same post-quantum + key-custody
  guarantees, or document the gap).

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

1. **Separate helper process vs. single Rust core.** The desktop "Go sidecar"
   pattern adds a second implementation/language for OS-keystore access. talkrypt's
   stated principle is *one audited core, thin shells* ([`PLATFORMS.md`](PLATFORMS.md)) —
   a second binary in another language widens the audit surface and the
   "divergent, separately-buggy" risk the core was meant to avoid. Options:
   (a) implement the helper in Rust reusing `talkrypt-core`; (b) keep a minimal
   non-crypto helper (key-store shuttle only, no protocol/crypto) in whatever
   language; (c) adopt the sidecar as specified. Decision needed.
2. **Custody tiers / key-custody.** #305 references "custody-tier parity," and
   mobile/desktop bridges imply hardware-backed key custody (Secure Enclave,
   StrongBox, TPM). talkrypt today seals long-term keys with Argon2id +
   AES-256-GCM at rest; hardware custody and a defined tier model are new and
   unspecified.
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
