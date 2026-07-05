# CLAUDE.md

## Project overview

talkrypt is a minimalist, IRC-like, post-quantum end-to-end encrypted chat that
runs over Tor (Arti) onion services, with optional Nym mixnet transport.
Messages are sealed with a PQ Double Ratchet (ML-KEM-1024 / ML-DSA-87, CNSA 2.0
algorithm set); the transport sees only ciphertext.

**NOT CERTIFIED / NOT ACCREDITED / NOT AUDITED.** The README banner is the
controlling statement: talkrypt is not FIPS-validated, not CSfC-accredited, not
NSA-approved, not independently audited. Never add or strengthen
certification/compliance claims in code, docs, or UI strings — "CNSA-aligned"
means algorithm choice only. Preserve the honest-scope wording wherever you
touch it.

## Repo layout

- `crates/wire` — length-prefixed wire codecs (`talkrypt-wire`)
- `crates/crypto` — PQ primitives, Double Ratchet, TreeKEM, beacons
- `crates/transport` — LAN / Tor (Arti, `tor` feature) / Nym (`nym` feature) transports
- `crates/core` — engine: sessions, identity chains, gossip mesh
- `crates/topology`, `crates/server` — group/relay topology and server
- `crates/cli` — the `talkrypt` binary (demo / host / join)
- `crates/tui`, `crates/desktop`, `crates/helper` — TUI, desktop app, OS helper
- `crates/ffi` — UniFFI bindings (`talkrypt_ffi` cdylib + `uniffi-bindgen` bin) for Android/iOS
- `android/` — Kotlin app (Gradle); consumes the generated `uniffi.talkrypt` bindings
- `fuzz/` — cargo-fuzz package (excluded from the workspace; built only via `cargo fuzz`)
- `docs/` — design/spec docs; `docs/plans/` holds numbered TDD implementation plans
- `scripts/` — packaging, release, artifact verification (`verify.sh` checks SHA-256 **and** SHA3-256)
- `ci/` — FIPS-posture checks (`fips-compliance-check.sh`, `fips.Dockerfile`)
- `third-party/` — vendored source-patched crates (`rsa`, `sqlx-sqlite`, `superboring`) wired via `[patch.crates-io]`; read their `TALKRYPT-PATCH.md`/Cargo.toml rationale before touching

## Common commands

```sh
cargo build                            # workspace build (default: no tor/nym)
cargo test                             # whole workspace
cargo test -p talkrypt-crypto          # one crate
cargo clippy --workspace --all-targets
cargo fmt --all                        # / --check
cargo deny check                       # deny.toml; scripts/audit-deps.sh wraps auditing

# CLI (binary name: talkrypt, crate talkrypt-cli)
cargo run -p talkrypt-cli -- demo      # in-process two-party proof, no network
cargo run -p talkrypt-cli --features tor -- host
cargo run -p talkrypt-cli --features tor -- join <talkrypt://uri>

# Fuzzing (from repo root; targets listed in fuzz/README.md)
cargo fuzz run wire_reader

# Android APK (needs SDK+NDK, cargo-ndk, JDK; builds .so → uniffi Kotlin → Gradle)
bash android/build-apk.sh                          # LAN-only
TALKRYPT_TOR=1 TALKRYPT_NYM=1 bash android/build-apk.sh   # with Tor and/or Nym
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

Rust MSRV is 1.95 (workspace `rust-version`). Cross-compiling the FFI `.so`
requires the rustup toolchain (Homebrew rust lacks Android targets).

## Feature flags

- `tor` — real Tor via Arti (heavy dependency tree; off by default)
- `nym` — Nym mixnet transport (pins a nymtech/nym git revision; drags in the
  sqlx-sqlite/superboring patches)
- `fips` — inner-layer AES via the FIPS-validated aws-lc-rs backend (backend
  validation only; the app itself is still not validated — keep it worded that way)
- `markings` (cli) — gates *originating* classification handling-markings
- `fuzzing` (crypto) — exposes crate-private codecs to fuzz targets only

## Architecture notes

- **FFI**: `crates/ffi` exports the engine over UniFFI; `android/build-apk.sh`
  runs cargo-ndk for `aarch64-linux-android`, then `uniffi-bindgen` to generate
  Kotlin, then Gradle. Rust API changes that touch FFI must regenerate bindings.
- **Android app style**: deliberately AndroidX-free and Compose-free —
  programmatic platform Views and Camera2 directly. Do not add AndroidX/Compose
  dependencies. Kotlin unit tests live in `android/app/src/test/kotlin`.
- **Attacker-reachable decoders** (anything parsing bytes before signature/AEAD
  checks) must return typed errors, never panic; each has a fuzz target — add
  one for any new decoder (see `fuzz/README.md`).
- Key docs: `docs/DESIGN.md` (architecture), `docs/WIRE.md` (wire format),
  `docs/ROADMAP.md`, `docs/SECURITY-AUDIT.md` (numbered R-* recommendations,
  referenced from code comments), `docs/android/README.md` (custody bridge),
  `SECURITY.md`.

## Conventions

- Commit messages: conventional-ish `type(scope): summary`, e.g.
  `feat(nym): …`, `fix(android): …`, `docs(names): …`, `ci(audit): …`.
- Features start as design + numbered TDD implementation plans in `docs/` /
  `docs/plans/` before code.
- Security-review culture: code comments cite `SECURITY-AUDIT.md` items (e.g.
  "R-8"); dependency patches are vendored in `third-party/` with written
  rationale; crates are `publish = false` — keep it that way.
- No certification/compliance claims, ever; honest-scope disclaimers accompany
  anything FIPS/CSfC-adjacent (see `ci/fips-compliance-check.sh` header for tone).
