# talkrypt

> # ⚠️ NOT CERTIFIED · NOT ACCREDITED · NOT AUDITED
>
> **Do not use this software to protect real classified, national-security, or
> life-safety information.** talkrypt implements the *algorithms* named by
> CNSA 2.0 and follows the CSfC *layered architecture*, but it carries **no
> certification, validation, or accreditation of any kind**, and it has had **no
> independent security audit, no external cryptographic review, and no
> penetration test.** It is experimental, pre-release software.
>
> Concretely, talkrypt is **NOT**:
>
> - **NOT FIPS 140-validated.** The `--features fips` build *links* a
>   FIPS-validated AES backend (aws-lc-rs), but that validation belongs to the
>   *backend vendor*. talkrypt as a whole is **not** a validated cryptographic
>   module and appears on no validation list.
> - **NOT CSfC-accredited.** It is architecturally compatible with the layered
>   model — nothing more. No Components-List listing, no Capability-Package
>   conformance, no Trusted Integrator, no NSA registration.
> - **NOT NSA-approved**, and not approved or endorsed by any government,
>   agency, or standards body.
> - **NOT certified or authorized for ANY classification level.** The
>   classification-marking feature is **advisory labeling only** — it is not an
>   accreditation and confers no authority to store, process, or transmit
>   classified information at any level.
> - **NOT independently audited or formally verified.** No third party has
>   reviewed this code or its cryptographic design. The bundled fuzzing and a
>   single Kani proof are the authors' own tests, not an audit.
>
> **"CNSA 2.0-aligned" means it uses those algorithms — it does NOT mean
> certified, validated, accredited, or fit for protecting real sensitive data.**
> Treat every security property claimed below as **unverified** until an
> independent audit establishes otherwise. Source code cannot self-certify any
> of these standards; they are external laboratory and agency processes.

A minimalist, IRC-like, **post-quantum end-to-end encrypted** chat that runs
over Tor (via [Arti](https://gitlab.torproject.org/tpo/core/arti)) onion
services. Messages are sealed with a post-quantum Double Ratchet; the transport
sees only ciphertext.

```
$ talkrypt demo          # in-process proof: two parties, real PQ crypto, no network
$ talkrypt host          # create a chat, print a talkrypt:// invite, start chatting
$ talkrypt join <uri>    # join from an invite
```

## Honesty first

See the **NOT CERTIFIED · NOT ACCREDITED · NOT AUDITED** banner at the top — it
is the controlling statement and it is not boilerplate. In short: talkrypt uses
the **CNSA 2.0** algorithm set and is **architecturally** compatible with the
CSfC layered model, but it is **not** FIPS-140-validated, **not**
CSfC-accredited, **not** NSA-approved, **not** authorized for any classification
level, and **not** independently audited. Those are external laboratory / agency
processes that source code cannot self-certify.

A few specifics so nothing is overread:

- **Algorithm alignment ≠ compliance.** Using ML-KEM-1024 / ML-DSA-87 /
  AES-256 is necessary but nowhere near sufficient for any accreditation.
- **Classification levels.** CNSA 2.0 is single-tier and approved (as a
  *standard*) up to TOP SECRET, so talkrypt's parameters are maximal for every
  level — but "covers the level cryptographically" is *not* authorization to
  handle data at that level. That authorization is operational (accredited
  hardware, TEMPEST, personnel, ATO) and outside any source tree.
- **Markings are advisory.** Classification banners/compartments label content;
  they do not enforce anything beyond TreeKEM group membership and never change
  how strongly data is protected.
- **The `fips` feature** swaps in a validated *backend*; it does not make
  talkrypt a validated module.

The same disclaimer prints with `talkrypt version`. Use accordingly.

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

## Documentation

A feature-oriented **[wiki](docs/wiki/Home.md)** covers everything talkrypt does
— [cryptography](docs/wiki/Cryptography.md),
[identity & accounts](docs/wiki/Identity-and-Accounts.md),
[messaging & transport](docs/wiki/Messaging-and-Transport.md),
[key custody](docs/wiki/Key-Custody.md),
[the CLI](docs/wiki/CLI-Reference.md),
[packaging & release](docs/wiki/Packaging-and-Release.md), and
[security assurance](docs/wiki/Security-Assurance.md). Start at
[`docs/wiki/Home.md`](docs/wiki/Home.md), or [Getting Started](docs/wiki/Getting-Started.md).

## Build & run

```
cargo build --workspace
cargo test  --workspace      # ~243 tests, fully offline (loopback transport)
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
- **Crypto suites:** Double Ratchet (`tk.dr.*`, default), PQ-Noise
  (`tk.noise.*`), a sender-key **group** scheme (`tk.group.*`), and a
  **TreeKEM CGKA with dynamic membership** (`crate::treekem`) — the
  cryptographic heart of MLS-PQ: hybrid-PQ node keys, blank-node resolution,
  O(log N) path re-keying, per-epoch group messaging, and **Add / Remove /
  Welcome** with capacity doubling and removal forward-secrecy. (RFC 9420 wire
  framing is the remaining MLS work — see `docs/plans/0002-mls-pq.md`.)
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

- **Anti-censorship:** bridges + pluggable transports (obfs4, snowflake) on the
  Arti transport (`bootstrap_with`) for reaching Tor where it is blocked.
- **Shared FFI** (`talkrypt-ffi`, uniffi): one binding (`TalkryptClient`) that
  the Android app and a desktop shell both consume — verified end to end. See
  [`docs/PLATFORMS.md`](docs/PLATFORMS.md) for Android (cargo-ndk, GrapheneOS /
  Solana Seeker sideload) and desktop (Tauri / native) integration.
- **CSfC alignment:** `talkrypt csfc` preflight + [`docs/CSFC.md`](docs/CSFC.md).

Planned next (scoped in `docs/plans/`): complete the **MLS-PQ** suite on the
TreeKEM core (`0002-mls-pq.md` — RFC 9420
wire framing, suite registration), and the GUI bundles for Android/desktop (the
Rust core + FFI they sit on are built and tested). All reuse this identical
core.

### Running the extras

```
cargo run -p talkrypt-cli -- host --group --channel '#team'  # found a TreeKEM group
cargo run -p talkrypt-cli -- join --group 'talkrypt://...'   # members join via Welcome
cargo run -p talkrypt-tui -- host --listen 127.0.0.1:9000    # terminal UI
cargo test -p talkrypt-crypto --features fips                # FIPS backend
cargo +nightly fuzz run wire_reader                          # fuzzing (needs cargo-fuzz)
cargo kani -p talkrypt-wire                                  # formal verification (needs Kani)
```

**Group chat** (`--group`) founds a TreeKEM group on the host, which coordinates
membership (Add/Welcome) and relays per-epoch-encrypted messages to all members;
verified across processes over TCP.

## Security

Threat model and design rationale: [`docs/DESIGN.md`](docs/DESIGN.md).

**This software has had no independent security audit, no external
cryptographic review, and no penetration test.** The implementation may contain
bugs — including ones that completely break the confidentiality, integrity, or
anonymity properties described above — and none of those properties have been
verified by anyone outside this project. **Do not rely on talkrypt for
high-stakes confidentiality, classified information, or any situation where
disclosure could cause harm, unless and until it has been independently
audited.** Claims in this README describe *intent and design*, not audited
guarantees.

## License

Apache-2.0 (see crate manifests).
