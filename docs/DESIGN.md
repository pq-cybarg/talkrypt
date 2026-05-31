# talkrypt — Design Specification

A minimalist, IRC-like, fully end-to-end-encrypted chat with post-quantum
forward secrecy, carried over Tor (via Arti) using ephemeral or persistent
onion services, with built-in anti-censorship transport options.

---

## 0. Honesty & compliance framing (read first)

These terms are used precisely throughout this document:

- **CNSA 2.0 algorithm-aligned** — the cryptographic primitives are the ones
  named by the Commercial National Security Algorithm Suite 2.0 (ML-KEM-1024,
  ML-DSA-87, AES-256-GCM, SHA-384/512). This is an *algorithm selection*
  claim, not a certification claim.
- **CSfC architecture-aligned** — the system can be deployed as two
  independent, layered encryption tunnels (E2E payload encryption *inside* a
  Tor/onion transport), mirroring the Commercial Solutions for Classified
  layered model. This is an *architecture* claim.
- **FIPS-capable** — with `--features fips`, all cryptographic operations are
  routed through a crypto backend (`aws-lc-rs`) that ships a FIPS 140-3
  validated module. The *binary you build* is **not** itself a validated
  module.

**Not claimed, and explicitly disclaimed in README and `--version`:** this
software is **not** FIPS-140-validated, **not** CSfC-accredited, and **not**
NSA-approved. Those are external laboratory / agency processes that source code
cannot satisfy on its own. The honesty banner ships in the binary.

Defense-in-depth consequence: post-quantum confidentiality of **message
content** is guaranteed at the E2E layer and does **not** depend on whether the
underlying Tor circuit negotiated a PQ handshake. Circuit-layer PQ (when the
pinned Arti version supports it) is an additional, independent layer.

---

## 1. Scope

### First deliverable (this spec)

Complete, tested, documented, runnable:

- `talkrypt-core` — protocol state machine, sessions, channels (no I/O).
- `talkrypt-crypto` — `CryptoSuite` trait + registry; three built-in suites;
  custom-suite plugin API; CNSA 2.0 mapping; FIPS backend toggle.
- `talkrypt-transport` — `Transport` trait; real `ArtiTransport` (ephemeral +
  persistent onions, anti-censorship transports) and `LoopbackTransport`.
- `talkrypt-topology` — `Topology` trait: P2P, Hub, Hybrid.
- `talkrypt-server` — persistent-server mode with three pluggable keep-alive
  strategies.
- `talkrypt-tui` — ratatui front-end.
- `talkrypt-cli` — line-oriented REPL front-end.

### Later sub-projects (architected for, not built here)

- `talkrypt-ffi` (uniffi) → Android app (incl. Solana Seeker, A23, GrapheneOS).
- Tauri desktop shell (macOS / Windows 10 / Linux variants).

Both are thin shells over the identical `talkrypt-core`. No security-critical
logic is reimplemented per platform.

### Non-goals

- No central account system, no phone numbers, no directory of users.
- No plaintext ever touches the transport, disk, or any log.
- No telemetry, analytics, crash reporting, or phone-home of any kind.

---

## 2. Architecture

```
talkrypt-core        protocol state machine, sessions, channels — zero I/O, 100% testable
talkrypt-crypto      CryptoSuite trait + registry; suites are plugins (incl. user-defined)
talkrypt-transport   Transport trait: ArtiTransport (real Tor) + LoopbackTransport (offline)
talkrypt-topology    Topology trait: P2P | Hub | Hybrid
talkrypt-server      KeepAlive trait: AlwaysOn | ClientAnchored | ReplicatedFailover
talkrypt-tui         ratatui front-end  ─┐
talkrypt-cli         line REPL          ─┼─ thin shells over core
talkrypt-ffi         uniffi → Android    ─┤   (later sub-projects)
(tauri shell)        desktop             ─┘
```

Cargo workspace. Dependency direction is strictly downward: front-ends →
core → {crypto, transport, topology}. `core` depends on the *traits*, never on
concrete Arti or concrete suites, so it stays I/O-free and fully unit-testable.

Key trait sketches (illustrative, not final signatures):

```rust
// talkrypt-crypto
trait CryptoSuite {
    fn descriptor(&self) -> SuiteDescriptor;            // id, version, params
    fn new_identity(&self, rng) -> Identity;
    fn begin_session(&self, ours, theirs_prekey) -> Session;     // initiator
    fn accept_session(&self, ours, init_msg) -> (Session, ...);  // responder
    fn encrypt(&self, sess: &mut Session, pt, ad) -> Ciphertext;
    fn decrypt(&self, sess: &mut Session, ct, ad) -> Result<Plaintext>;
}

// talkrypt-transport
trait Transport {
    async fn listen(&self) -> Result<Listener>;   // yields incoming Streams
    async fn dial(&self, ep: &Endpoint) -> Result<Stream>;
    fn status(&self) -> TransportStatus;           // for UI status bar
}

// talkrypt-topology
trait Topology {
    async fn join(&self, desc: &ChatDescriptor, t: &dyn Transport) -> Session set;
    async fn send(&self, channel, msg);            // fan-out per topology
    fn on_recv(&self, ...) -> Vec<Event>;
}

// talkrypt-server
trait KeepAlive {
    async fn run(&self, svc: OnionService) -> never; // publish + self-heal
}
```

---

## 3. Chat Descriptor (the shareable invite)

When a chat is *generated*, its configuration is encoded into a portable
descriptor and shared as a `talkrypt://` URI and/or QR code:

```
version           u16
topology          P2P | Hub | Hybrid
persistence       Ephemeral | Persistent          (Hub/Hybrid only)
suite_id          e.g. "tk.dr.x25519+mlkem1024.aes256gcm.sha384.mldsa87"
suite_params      opaque, suite-defined bytes
endpoints         one or more .onion addresses (+ client-auth pubkey)
invite_token      one-time pre-shared secret for authenticated first contact
channel           initial channel name(s)
```

- A peer whose build **understands** `suite_id` joins seamlessly.
- A peer **missing** that suite receives a human-readable error naming the
  exact suite id + version it must enable — satisfying "users know the type if
  they hold a local config of the valid format."
- Descriptors carry the onion **client-authorization public key** so the
  service is reachable only by descriptor holders (restricted discovery).

---

## 4. Identity & trust model

- Long-term identity = ML-DSA-87 signing keypair + a KEM identity key.
- **Fingerprint** = SHA-384 over the public identity, rendered as a grouped
  "safety number" for out-of-band verification.
- **First-contact authentication** uses the descriptor's `invite_token`
  (authenticates the initial handshake, defeating first-contact MITM) and is
  confirmable later by comparing safety numbers out of band (TOFU + verify).
- Prekey bundles are signed with ML-DSA-87.

---

## 5. Cryptographic suites

`CryptoSuite` is a trait with a registry. Suite IDs are namespaced strings so
custom suites never collide with built-ins.

### Built-in suites

1. **`tk.dr.*` — Hybrid PQ Double Ratchet** (default, recommended for 1:1).
   - Asymmetric ratchet: each step performs **both** X25519 DH **and**
     ML-KEM-1024 encapsulation; the two shared secrets are concatenated and run
     through HKDF-SHA384. Secure if *either* primitive holds (true hybrid).
   - Symmetric ratchet: per-chain KDF → per-message keys ⇒ **per-message
     forward secrecy**; new asymmetric steps ⇒ **post-compromise recovery**.
   - AEAD: AES-256-GCM; the message header (counter, ratchet public keys,
     sender fingerprint) is bound as associated data.
   - Skipped-message keys cached with a hard bound (replay/out-of-order safe).

2. **`tk.noise.*` — PQ-Noise session** (simpler; session-granularity FS).
   - Hybrid PQ Noise (IK/XX-style) handshake establishes a session key;
     forward secrecy is per-session (rekey on reconnect). Good for short-lived
     ephemeral sessions where per-message ratcheting is overkill.

3. **`tk.mls.*` — MLS-PQ** (heavyweight group messaging).
   - RFC 9420 continuous group key agreement with a PQ-hybrid ciphersuite.
     Strongest large-group story.

### Custom suites (`tk.x.<name>`)

Third parties register their own `CryptoSuite` implementation plus a
`SuiteDescriptor`. Personalized mechanisms are first-class: a custom suite is
selectable at chat generation and announced via the descriptor exactly like a
built-in. The registry refuses to load a suite whose advertised primitives fall
below a configurable floor unless explicitly overridden, so "custom" can't
silently mean "weak."

### CNSA 2.0 mapping

| Role            | Algorithm        |
|-----------------|------------------|
| KEM (PQ)        | ML-KEM-1024      |
| KEM (classical) | X25519 (hybrid)  |
| Signature       | ML-DSA-87        |
| AEAD            | AES-256-GCM      |
| Hash / KDF      | SHA-384 / HKDF-SHA384 |
| Passphrase KDF  | Argon2id         |

### FIPS toggle

- Default backend: RustCrypto crates.
- `--features fips`: route all crypto through `aws-lc-rs` (FIPS 140-3 validated
  module). Same APIs; selected at build time. Banner reflects the active
  backend.

---

## 6. Topologies

Selected at chat creation, encoded in the descriptor.

- **P2P** — every peer hosts its own onion; messages flow peer-onion to
  peer-onion. Channels are a small full mesh of pairwise ratchet sessions; the
  sender broadcasts to each peer. Documented practical member ceiling (mesh
  cost is O(N) per message); recommended for small groups.
- **Hub** — one onion acts as the IRC-like relay. The hub fans out messages but
  sees **ciphertext only**. Channel keying uses **sender-keys**: each member
  holds a rotating symmetric sender chain, distributed to other members over
  pairwise ratchet sessions; rotation gives forward secrecy. The hub learns
  who-connects-to-it metadata; restricted discovery limits this exposure.
- **Hybrid** — hub handles presence / channel discovery / key-exchange
  rendezvous; actual messages flow P2P as sealed-sender pairwise ciphertext.

---

## 7. Transport & anti-censorship

`Transport` trait with two implementations:

- **`ArtiTransport`** (production):
  - Builds Tor circuits via `arti-client`; when the pinned Arti version
    supports a PQ-hybrid circuit handshake, it is enabled by config. If not, E2E
    content remains PQ-secure regardless (§0).
  - Hosts onion services via `tor-hsservice`:
    - **Ephemeral** — fresh keypair per session, never persisted.
    - **Persistent** — see §8.
  - **Anti-censorship** — bridges and pluggable transports (e.g. obfs4,
    Snowflake) configured through the config file / descriptor, for reaching
    Tor where it is blocked ("accessibility for anti-censorship").
- **`LoopbackTransport`** (tests/offline): in-process registry mapping fake
  onion addresses to in-memory streams. Enables full protocol + crypto + UI
  testing with **zero** network.

Wire framing: length-prefixed frames; payload is opaque E2E ciphertext. The
transport sees only ciphertext + onion routing — never plaintext, never keys.

---

## 8. Persistent server mode (`--server`)

Optional stable `.onion` that survives restarts, with non-identifying
keep-alive.

- **Encrypted-at-rest HS identity** — the onion secret key is sealed with an
  Argon2id-derived key (passphrase) or the OS keystore. The same `.onion`
  returns across reboots. Never stored in plaintext.
- **Restricted discovery** — onion-service client authorization: only holders
  of the descriptor's auth key can resolve/reach the service. It is
  non-enumerable and does not advertise its operator. This is the
  "non-identifying" core.
- **No metadata logging** — server keeps no on-disk record of who connected or
  when; operational logs (if enabled at all) are opt-in and content-free.

### Keep-alive strategies — `KeepAlive` trait, chosen at server init

1. **AlwaysOn** — long-lived daemon. Ships generators for a `systemd` unit
   (Linux), a `launchd` plist (macOS), and a documented service wrapper.
   Re-publishes the HS descriptor before expiry; auto-reconnects through Tor
   churn with capped exponential backoff. Stable address, full uptime;
   host-opsec is the operator's responsibility, software footprint is minimal.
2. **ClientAnchored** — stable address (persisted key), but the service is
   published only while at least one designated *anchor* client is online. No
   dedicated infrastructure to tie to an identity; reachable only when an
   anchor is up.
3. **ReplicatedFailover** — one onion identity served by N independent backend
   instances behind an OnionBalance-style frontend, so no single host is
   essential or identifying and the service survives any one host dying. Most
   resilient and most non-identifying; most operational setup.

---

## 9. Front-ends

Both call identical core APIs.

- **TUI (ratatui)** — panes: channel list, message view, input line, status bar
  (Tor bootstrap/onion status, active suite, peer fingerprints).
- **CLI (REPL)** — line-oriented, scriptable, easiest to test.

Shared command set:

```
/create [--topology P2P|Hub|Hybrid] [--persistent] [--suite <id>]
/invite                         show this chat's descriptor (URI + QR)
/join <descriptor>              import a descriptor and join
/msg <channel> <text>           (or bare line in the focused channel)
/verify <peer>                  show/compare safety number
/server <AlwaysOn|ClientAnchored|ReplicatedFailover>
/quit
```

---

## 10. Error handling

- `thiserror` per crate; no `unwrap`/`panic` on attacker-reachable paths.
- Decryption failures are **uniform** (no secret-dependent branching or error
  text); constant-time comparisons for secrets.
- Replay / out-of-order handled by the bounded skipped-key cache.
- Tor bootstrap / onion publication status is surfaced to the UI, never logged
  with identifying detail.

---

## 11. Threat model

**In scope (mitigated):**

- Network/metadata adversary — Tor + restricted-discovery onions protect
  routing metadata; E2E protects content.
- Endpoint key compromise — Double Ratchet provides forward secrecy and
  post-compromise recovery.
- Harvest-now-decrypt-later — PQ-hybrid KEM at the E2E layer.
- First-contact MITM — invite token + out-of-band safety-number verification.

**Out of scope (documented honestly):**

- Compromise of an endpoint *while in use* (screen capture, keylogger, RAM
  scraping of live session) — no software prevents reading plaintext on a
  fully owned device.
- Global passive adversary performing long-term traffic-confirmation against
  Tor itself.
- The operational security of any host the user chooses to run a persistent
  server on.
- Certification status (§0).

---

## 12. Testing strategy

- **Unit + property tests** (`proptest`) for the ratchet: encrypt/decrypt
  round-trip, arbitrary out-of-order delivery, key-separation invariants.
- **Known-answer vectors** for KDF and AEAD.
- **Loopback integration tests** — full 1:1 and group conversations end to end,
  no network, deterministic.
- **`cargo-fuzz`** targets on the wire-format parser and the descriptor parser.
- **`kani`** harness on header-parse bounds (no out-of-bounds on hostile input).
- **Network-gated real-Arti integration test** (`--ignored` / feature flag):
  bootstrap, host an ephemeral onion, connect, exchange a message.
- CI runs everything except the network-gated test by default.

---

## 13. Opsec & build hygiene (applies to every artifact)

- No author identity, no machine paths, no tooling fingerprints in any file.
- Ephemeral by default; **no metadata logging**; secrets encrypted at rest.
- Release builds stripped; no telemetry/analytics/phone-home; reproducible
  builds targeted where the toolchain allows.
- License left to the repository owner.

---

## 14. Open items for the implementation plan

- Pin exact Arti version and confirm current PQ-handshake + ephemeral/persistent
  onion + client-auth API surface; record fallbacks if an API is unavailable.
- Decide custom-suite loading mechanism (compile-time registration vs. a
  sandboxed WASM plugin host) — affects the security boundary; default to
  compile-time registration for the first deliverable, WASM noted as a later
  option.
- Finalize sender-keys rotation cadence and the P2P member ceiling number.
