# talkrypt

A minimalist, IRC-like, **post-quantum end-to-end encrypted** chat that runs
over Tor (via [Arti](https://gitlab.torproject.org/tpo/core/arti)) onion
services. Messages are sealed with a hybrid PQ Double Ratchet; the transport
sees only ciphertext.

```
$ talkrypt demo          # in-process proof: two parties, real PQ crypto, no network
$ talkrypt host          # create a chat, print a talkrypt:// invite, start chatting
$ talkrypt join <uri>    # join from an invite
```

## Honesty first

talkrypt uses the **CNSA 2.0** algorithm set and is **architecturally**
compatible with the CSfC layered model. It is **not**:

- FIPS-140-validated,
- CSfC-accredited, or
- NSA-approved.

Those are external laboratory / agency processes that source code cannot
self-certify. What you get is a clean, auditable implementation that uses the
right algorithms and can be built against a FIPS-validated backend. Use it
accordingly. The same banner prints with `talkrypt version`.

## Cryptography (CNSA 2.0 aligned)

| Role            | Algorithm                                          |
|-----------------|----------------------------------------------------|
| KEM (PQ)        | ML-KEM-1024 (FIPS 203) — primary                   |
| KEM (classical) | X25519 — hybrid half, defense-in-depth only        |
| Signature/auth  | ML-DSA-87 (FIPS 204) — pure PQ, no EC              |
| AEAD            | AES-256-GCM                                         |
| Hash / KDF      | SHA3-384 / HKDF (or SHA-384 via `cnsa-sha2`)        |
| Passphrase KDF  | Argon2id (persistent-key sealing)                  |

The asymmetric ratchet step runs **both** an X25519 DH and an ML-KEM-1024
encapsulation and KDF-combines them, so confidentiality holds if *either*
primitive is unbroken — and harvest-now-decrypt-later is defeated by the PQ
half. Per-message keys give **forward secrecy**; fresh ratchet steps give
**post-compromise recovery**.

### Elliptic curve is never load-bearing

Identity and authentication are **pure post-quantum** (ML-DSA-87 — no EC key).
The only EC in the E2E layer is X25519 as the *classical half* of the hybrid
KEM, which strengthens (never weakens) security: breaking X25519 leaves content
protected by ML-KEM-1024. Tor's own onion/circuit keys (ed25519 / x25519 ntor)
protect *anonymity*, independent of E2E content confidentiality. The default
hash is **SHA3-384** (Keccak — the same family ML-KEM/ML-DSA use internally);
`cnsa-sha2` switches to SHA-384 for strict CNSA 2.0 hash alignment.

## Architecture

One portable, I/O-free Rust core; every front-end and transport is a thin shell
over it.

```
crates/wire        bounded length-prefixed codec
crates/crypto      CryptoSuite trait + registry; hybrid PQ Double Ratchet (the security core)
crates/transport   Transport trait: LoopbackTransport (tests), TcpTransport (dev), Arti (planned)
crates/core        ChatDescriptor + invite, authenticated handshake, session engine
crates/topology    P2P / Hub / Hybrid connection strategies
crates/cli         the `talkrypt` binary (demo / host / join REPL)
```

- **Chat descriptor** — a `talkrypt://<base32>` invite (also a QR payload)
  carrying topology, persistence, suite id + params, endpoint(s), a one-time
  invite token, and the channel. A peer missing the named suite is told exactly
  which suite/version to enable.
- **Handshake** — the dialer is initiator, the accepter responder; a signed
  prekey is exchanged (ML-DSA-87), the session root is derived from the invite
  token, and identities are mutually authenticated with pinnable SHA-384
  **safety numbers**.
- **Crypto suites** are registered at **compile time** — a static, auditable
  boundary with no runtime code loading, which is what high-assurance regimes
  require. Custom suites implement the `CryptoSuite` trait and register against
  a security floor.

## Build & run

```
cargo build --workspace
cargo test  --workspace      # 55 tests, fully offline (loopback transport)
cargo run -p talkrypt-cli -- demo
```

Two terminals over TCP (Tor-free, for local testing):

```
# terminal 1
cargo run -p talkrypt-cli -- host --listen 127.0.0.1:9000 --channel '#general'
#   -> prints a talkrypt:// invite URI

# terminal 2
cargo run -p talkrypt-cli -- join 'talkrypt://...'
```

REPL commands: `/invite`, `/verify`, `/peers`, `/quit`.

## Status

Working & tested today (80 tests, fully offline):

- Hybrid PQ Double Ratchet crypto core + suite registry.
- **Three crypto suites:** Double Ratchet (`tk.dr.*`, default), PQ-Noise
  (`tk.noise.*`), and a sender-key **group** scheme (`tk.group.*`).
- Session engine, authenticated handshake, descriptors/invites.
- P2P / Hub / Hybrid topology strategies.
- Loopback + **real TCP** transports, and the **Arti onion transport**
  (`--features tor`): `dial` over Tor, `launch_onion_service` hosting,
  ephemeral + persistent onion key modes. The live onion path is exercised by
  an `#[ignore]` integration test (needs a real Tor bootstrap):
  `cargo test -p talkrypt-transport --features tor -- --ignored`.
- **Persistent-server support**: encrypted-at-rest onion-key sealing
  (Argon2id + AES-256-GCM) and the three keep-alive strategies
  (AlwaysOn / ClientAnchored / ReplicatedFailover).
- **CLI** (`talkrypt`: demo + host/join REPL) and **ratatui TUI**
  (`talkrypt-tui`).
- **FIPS backend** (`--features fips`): routes AES-256-GCM through aws-lc-rs's
  validated module; all crypto tests pass against it.
- **Hardening:** `cargo-fuzz` targets (`fuzz/`) for the wire and descriptor
  parsers; a **Kani** proof harness on the decoder (`cargo kani`).

Planned next (same trait seams, see `docs/plans/`): full RFC 9420 **MLS-PQ**
group suite (the sender-key scheme is shipped today as the lighter option),
anti-censorship pluggable-transport config, and the desktop (Tauri) / Android
(uniffi) shells — all reusing this identical core.

### Running the extras

```
cargo run -p talkrypt-tui -- host --listen 127.0.0.1:9000   # terminal UI
cargo test -p talkrypt-crypto --features fips                # FIPS backend
cargo +nightly fuzz run wire_reader                          # fuzzing (needs cargo-fuzz)
cargo kani -p talkrypt-wire                                  # formal verification (needs Kani)
```

## Security

Threat model and design rationale: [`docs/DESIGN.md`](docs/DESIGN.md).
This software has not been independently audited. Do not rely on it for
high-stakes confidentiality without one.

## License

Apache-2.0 (see crate manifests).
