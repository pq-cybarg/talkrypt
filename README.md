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

| Role            | Algorithm                               |
|-----------------|-----------------------------------------|
| KEM (PQ)        | ML-KEM-1024 (FIPS 203)                  |
| KEM (classical) | X25519 — combined as a **hybrid**       |
| Signature       | ML-DSA-87 (FIPS 204)                    |
| AEAD            | AES-256-GCM                             |
| Hash / KDF      | SHA-384 / HKDF-SHA384                   |
| Passphrase KDF  | Argon2id (persistent-key sealing)       |

The asymmetric ratchet step runs **both** an X25519 DH and an ML-KEM-1024
encapsulation and KDF-combines them, so confidentiality holds if *either*
primitive is unbroken — and harvest-now-decrypt-later is defeated by the PQ
half. Per-message keys give **forward secrecy**; fresh ratchet steps give
**post-compromise recovery**.

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

Working today: the full crypto core, the session engine, P2P/Hub/Hybrid
topology strategies, loopback + TCP transports, and the CLI — all tested and
runnable end to end.

Planned (same trait seams, see `docs/plans/`): the real Arti onion transport
(ephemeral + persistent onions, restricted-discovery client auth,
anti-censorship pluggable transports), the persistent-server keep-alive modes,
the ratatui TUI, the PQ-Noise and MLS-PQ suites, fuzz/Kani harnesses, and the
`fips` backend feature. Desktop (Tauri) and Android (uniffi) shells reuse this
identical core.

## Security

Threat model and design rationale: [`docs/DESIGN.md`](docs/DESIGN.md).
This software has not been independently audited. Do not rely on it for
high-stakes confidentiality without one.

## License

Apache-2.0 (see crate manifests).
