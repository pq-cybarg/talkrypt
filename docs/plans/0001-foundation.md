# talkrypt — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** A minimalist, IRC-like, end-to-end encrypted chat with post-quantum forward secrecy, carried over Tor (Arti) onion services, runnable from a CLI/TUI and fully testable offline.

**Architecture:** One portable, I/O-free Rust core (`talkrypt-core`) plus trait-based plugins for crypto (`CryptoSuite`), transport (`Transport`), topology (`Topology`), and server keep-alive (`KeepAlive`). Front-ends (CLI, TUI) and later platform shells (Android/desktop) are thin layers over the core. Real crypto via RustCrypto (ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA-384). Real Tor via Arti behind a `tor` feature; a `LoopbackTransport` makes the whole stack testable with zero network.

**Tech Stack:** Rust 1.95, Cargo workspace, tokio, ml-kem 0.3, ml-dsa 0.1, x25519-dalek 2, aes-gcm 0.10, hkdf 0.12, sha2 0.10, argon2, zeroize, subtle, proptest; ratatui+crossterm (TUI); clap (CLI); arti-client + tor-hsservice (feature `tor`).

---

## Build order (phases produce working, testable software at each step)

1. **Workspace + wire codec** — compiles, round-trip tested.
2. **talkrypt-crypto** — Identity, suite trait/registry, Hybrid PQ Double Ratchet (the security heart), property-tested. *This is the phase that must be exactly right.*
3. **talkrypt-transport** — `Transport` trait + `LoopbackTransport`, tested.
4. **talkrypt-core** — session/channel protocol state machine over traits, integration-tested on loopback.
5. **talkrypt-topology** — P2P / Hub / Hybrid.
6. **talkrypt-cli** — runnable two-instance E2E chat over loopback (real demo).
7. **ArtiTransport (`tor` feature)** — ephemeral + persistent onions, client-auth, anti-censorship PTs.
8. **talkrypt-server** — `KeepAlive`: AlwaysOn / ClientAnchored / ReplicatedFailover.
9. **talkrypt-tui** — ratatui front-end.
10. **Hardening** — PQ-Noise + MLS-PQ suites, fuzz targets, kani harness, KAT vectors, docs, honesty banner, FIPS feature.

Phases 1–6 are the priority: they yield a real, tested, runnable PQ-encrypted chat. 7–10 layer on real Tor, server modes, the TUI, and the remaining suites/hardening against the same seams.

---

## Phase 1 — Workspace + wire codec

### Task 1.1: Create the workspace

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/wire/Cargo.toml`, `crates/wire/src/lib.rs`

- [ ] **Step 1:** Write root `Cargo.toml`:

```toml
[workspace]
resolver = "2"
members = ["crates/*"]

[workspace.package]
edition = "2021"
license = "Apache-2.0"

[workspace.dependencies]
zeroize = "1"
subtle = "2"
rand_core = { version = "0.6", features = ["getrandom"] }
sha2 = "0.10"
hkdf = "0.12"
aes-gcm = "0.10"
x25519-dalek = { version = "2", features = ["static_secrets"] }
ml-kem = "0.3"
ml-dsa = "0.1"
thiserror = "1"
proptest = "1"
```

- [ ] **Step 2:** `crates/wire/src/lib.rs` — length-prefixed codec with `put_bytes`/`get_bytes` (u32-len-prefixed), `Writer`/`Reader`. Reject lengths over a `MAX_FRAME` bound.
- [ ] **Step 3:** Test: round-trip of `[Vec<u8>; n]`; oversized length errors; truncated input errors.
- [ ] **Step 4:** `cargo test -p talkrypt-wire`.
- [ ] **Step 5:** Commit `feat: workspace + length-prefixed wire codec`.

---

## Phase 2 — talkrypt-crypto (security heart)

Concrete construction (final, not illustrative):

- **Identity:** `IdentityKeyPair { sig: ml_dsa::KeyPair<MlDsa87>, kem_id: x25519 static secret }`. Fingerprint = `SHA-384(sig_pub || x25519_pub)`.
- **Prekey bundle:** signed `(x25519_prekey_pub, mlkem1024_encap_key)` with ML-DSA-87.
- **Hybrid KEM step:** initiator does `x25519 DH` AND `ML-KEM-1024 encapsulate`; `secret = HKDF-SHA384(salt=root, ikm = dh_ss || mlkem_ss)`. Responder mirrors with decapsulate.
- **Root/chain KDF:** `HKDF-SHA384`; `(root', chain) = KDF_RK(root, hybrid_ss)`; `(chain', mk) = KDF_CK(chain)`.
- **AEAD:** AES-256-GCM, nonce = 96-bit counter (per message key, so never reused), AAD = serialized header `{ dh_pub, mlkem_ct, pn, n, sender_fp }`.
- **Skipped keys:** `BTreeMap<(pubkey, n), MessageKey>` bounded by `MAX_SKIP = 1000`.
- All secret types `#[derive(Zeroize, ZeroizeOnDrop)]`; comparisons via `subtle::ConstantTimeEq`.

### Task 2.1: Identity + fingerprint
- [ ] Test: generate identity; fingerprint is 48 bytes, stable, differs across identities; sign/verify round-trip; tampered message fails verify.
- [ ] Implement `Identity`, `IdentityPublic`, `fingerprint()`, `sign()/verify()` using `ml-dsa`.
- [ ] `cargo test -p talkrypt-crypto identity`. Commit.

### Task 2.2: HKDF KDF helpers
- [ ] Test KAT-style: fixed inputs → fixed `KDF_RK`/`KDF_CK` outputs (lock the construction); chain keys differ from message keys (domain separation).
- [ ] Implement `kdf_rk`, `kdf_ck`, `kdf_mk` with distinct HKDF `info` labels (`"tk-rk"`,`"tk-ck"`,`"tk-mk"`).
- [ ] Test + commit.

### Task 2.3: Hybrid KEM (X25519 + ML-KEM-1024)
- [ ] Test: `encapsulate(peer) -> (ct, ss)`; `decapsulate(ct) -> ss'`; `ss == ss'`; secret if either branch's inputs swapped still differs (hybrid binding).
- [ ] Implement `HybridKem` combining dalek DH and ml-kem encap/decap via HKDF-SHA384.
- [ ] Test + commit.

### Task 2.4: Double Ratchet state machine
- [ ] Test: Alice↔Bob session; encrypt/decrypt round-trip; out-of-order delivery (deliver msg 3 before 1,2) decrypts; replay of a consumed message fails; `MAX_SKIP` exceeded errors; a new ratchet step changes the DH/KEM public (post-compromise recovery property).
- [ ] Implement `Session { root, send_chain, recv_chain, dh_self, mlkem_self, skipped }`, `ratchet_encrypt`, `ratchet_decrypt`, header (de)serialization via `talkrypt-wire`.
- [ ] proptest: arbitrary interleavings of sends both directions always decrypt in order with no key reuse.
- [ ] `cargo test -p talkrypt-crypto`. Commit `feat: hybrid PQ double ratchet`.

### Task 2.5: CryptoSuite trait + registry + descriptor
- [ ] Test: register the `tk.dr.*` suite; look up by id; unknown id → descriptive error; a suite below the primitive floor is rejected unless overridden.
- [ ] Implement `CryptoSuite` trait, `SuiteDescriptor { id, version, params }`, `SuiteRegistry`, and wrap Task 2.4 as suite `tk.dr.x25519+mlkem1024.aes256gcm.sha384.mldsa87`.
- [ ] Test + commit.

---

## Phase 3 — talkrypt-transport

### Task 3.1: Transport trait + LoopbackTransport
- [ ] Test: two endpoints registered on a shared loopback fabric; `dial` then bidirectional framed send/recv; dial of unknown endpoint errors; transport carries opaque bytes only.
- [ ] Implement `Transport`, `Endpoint`, `Stream` (async read/write of frames), `LoopbackFabric` + `LoopbackTransport` (in-memory channels), `TransportStatus`.
- [ ] `cargo test -p talkrypt-transport`. Commit.

---

## Phase 4 — talkrypt-core

### Task 4.1: Session manager + events
- [ ] Test: `Core::new(identity, suite, transport)`; establish session to a peer endpoint over loopback; send "hello"; peer receives a `Message` event with decrypted plaintext + verified sender fingerprint.
- [ ] Implement `Core`, `Event` enum (`Message`, `PeerJoined`, `Error`, `TorStatus`), inbound dispatch loop, outbound `send(channel, text)`.
- [ ] Commit.

### Task 4.2: Channels + ChatDescriptor
- [ ] Test: build a `ChatDescriptor`; encode to `talkrypt://` URI and back (round-trip); a descriptor with unknown suite id yields a human-readable "enable suite X vY" error; QR-payload encode is valid base32.
- [ ] Implement `ChatDescriptor`, URI codec, channel registry, invite-token first-contact authentication binding.
- [ ] Commit.

---

## Phase 5 — talkrypt-topology

### Task 5.1: Topology trait + P2P + Hub + Hybrid
- [ ] Test (loopback): P2P 3-peer mesh — message from A reaches B and C decrypted. Hub — one relay endpoint fans ciphertext to members; relay never sees plaintext (assert payload undecryptable at relay). Hybrid — rendezvous via hub, message via P2P.
- [ ] Implement `Topology` trait and the three impls; Hub uses sender-keys distributed over pairwise ratchets.
- [ ] Commit.

---

## Phase 6 — talkrypt-cli (runnable demo)

### Task 6.1: CLI front-end
- [ ] Test: integration test spawns two `Core`s on a shared loopback fabric and drives `/create`, `/join`, `/msg` through the command parser; asserts the message arrives decrypted.
- [ ] Implement `clap` command parser, REPL loop, command set (`/create`, `/invite`, `/join`, `/msg`, `/verify`, `/server`, `/quit`), status line.
- [ ] Manual run doc: two terminals over loopback exchange messages.
- [ ] Commit `feat: runnable CLI E2E chat over loopback`.

---

## Phase 7 — ArtiTransport (`tor` feature)

### Task 7.1: Tor-backed transport
- [ ] Pin exact `arti-client`/`tor-hsservice` versions; record API + PQ-handshake + ephemeral/persistent onion + client-auth surface and fallbacks in `docs/arti-notes.md`.
- [ ] Implement `ArtiTransport`: bootstrap `TorClient`, host ephemeral onion (`listen`), `dial` a `.onion`, enable PQ circuit handshake by config, configure bridges/pluggable transports.
- [ ] Network-gated `#[ignore]` integration test: bootstrap, host ephemeral onion, self-connect, exchange a frame.
- [ ] Commit `feat: real Tor transport via Arti (feature=tor)`.

---

## Phase 8 — talkrypt-server (persistent onion + keep-alive)

### Task 8.1: Encrypted persistent HS identity + restricted discovery
- [ ] Test: seal/unseal onion secret key with Argon2id-derived key; wrong passphrase fails; sealed blob has no plaintext key bytes; client-auth keypair generated and embedded in descriptor.
- [ ] Implement persistent key store + onion client-authorization wiring.
- [ ] Commit.

### Task 8.2: KeepAlive trait + three strategies
- [ ] Test: trait dispatch selects AlwaysOn / ClientAnchored / ReplicatedFailover by config; AlwaysOn republish-on-expiry loop fires; ClientAnchored publishes only with ≥1 anchor; ReplicatedFailover surviving-backend logic.
- [ ] Implement the three strategies + service generators (systemd unit / launchd plist emitters).
- [ ] Commit.

---

## Phase 9 — talkrypt-tui

### Task 9.1: ratatui front-end
- [ ] Test: render-to-buffer test of the layout (channel list / message view / input / status bar) given a fixed `Core` state.
- [ ] Implement ratatui+crossterm app over the same `Core` API as the CLI; identical command set.
- [ ] Commit.

---

## Phase 10 — Hardening

- [ ] **PQ-Noise suite** (`tk.noise.*`): implement + tests; register.
- [ ] **MLS-PQ suite** (`tk.mls.*`): implement group CGKA + tests; register.
- [ ] **Fuzz:** `cargo-fuzz` targets for wire parser and descriptor parser.
- [ ] **Kani:** harness proving header parse never indexes out of bounds on hostile input.
- [ ] **KAT vectors:** committed test vectors for KDF + AEAD.
- [ ] **FIPS feature:** `--features fips` routes crypto through `aws-lc-rs`; banner reflects backend.
- [ ] **Docs:** `README.md` with honesty banner (§0 of design), threat model, build/run, anti-censorship config; `--version` prints banner.
- [ ] Commit.

---

## Self-review notes

- Spec coverage: every design section maps to a phase (topology→P5, suites/custom→P2/P10, transport+anti-censorship→P3/P7, persistent server+3 keep-alives→P8, descriptor→P4.2, FS/PQ ratchet→P2.4, honesty/FIPS→P10, front-ends→P6/P9, testing→every phase + P10).
- Type consistency: `Session`, `CryptoSuite`, `SuiteDescriptor`, `Transport`, `Endpoint`, `Stream`, `Core`, `Event`, `ChatDescriptor`, `Topology`, `KeepAlive` named once and reused.
- Custom-suite loading = compile-time registration (registry in Task 2.5); WASM deferred.
- Crate name prefix: published crate names are `talkrypt-*`; workspace dir names under `crates/` are unprefixed (`wire`, `crypto`, …) with `package.name = "talkrypt-<x>"`.
