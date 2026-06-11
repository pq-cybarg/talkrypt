# talkrypt wiki

**talkrypt** is a minimalist, IRC-like, **post-quantum**, end-to-end-encrypted,
forward-secret chat that runs over Tor. The cryptography is pure-Rust
([RustCrypto]) and **PQ by default** — ML-KEM-1024 for key establishment,
ML-DSA-87 for identity, AES-256-GCM for content — aligned with **NSA CNSA 2.0**.
There is no elliptic-curve identity key; the only EC anywhere is an optional,
non-load-bearing X25519 *hybrid* half (defense-in-depth).

This wiki is the feature map. Each page links to the authoritative spec in
`docs/` for the deep detail.

> **Honesty first.** talkrypt is **experimental, pre-release** software. It is
> **NOT** independently audited, **NOT** FIPS-validated, **NOT** CSfC-accredited,
> **NOT** NSA-approved, and **NOT** authorized for classified use. It implements
> the CNSA 2.0 *algorithms*; that is not the same as certification. See
> [Security Assurance](Security-Assurance.md) and `SECURITY.md`.

## Start here

- **[Getting Started](Getting-Started.md)** — install, host a chat, join one, share an invite.
- **[CLI Reference](CLI-Reference.md)** — every `talkrypt` subcommand, flag, and in-chat `/command`.

## Features

| Area | Page | What's in it |
| --- | --- | --- |
| 🔐 Cryptography | **[Cryptography](Cryptography.md)** | ML-KEM-1024, ML-DSA-87, AES-256-GCM, SHA3/KMAC, the Double Ratchet, KEM postures, self-tests, RAM-capture hardening |
| 🪪 Identity | **[Identity & Accounts](Identity-and-Accounts.md)** | ML-DSA identities, safety numbers, account→device→segment chains, device linking, username registries, contacts/friends |
| 💬 Messaging | **[Messaging & Transport](Messaging-and-Transport.md)** | invites/QR, P2P/Hub/Hybrid topologies, groups (TreeKEM), Tor/Arti + TCP, the wire format, replay/MITM defenses |
| 🗝️ Key custody | **[Key Custody & Storage](Key-Custody.md)** | custody tiers, at-rest sealing, hardware-backed sealing (StrongBox/Secure Enclave/TPM), the desktop helper |
| 🏷️ Classification | **[Classification & Compliance](Classification-and-Compliance.md)** | markings, CNSA 2.0, FIPS posture, CSfC alignment, the honesty posture |
| 💻 Platforms | **[Platforms & Clients](Platforms-and-Clients.md)** | CLI, TUI, the FFI, Android, iOS, the desktop helper, the roadmap |
| 📦 Packaging | **[Packaging & Release](Packaging-and-Release.md)** | build scripts, every artifact, dual SHA-256 + SHA3-256 hashing, the verifiers |
| 🛡️ Assurance | **[Security Assurance](Security-Assurance.md)** | the self-audit (F-1…F-15 / R-1…R-8), fuzzing, Miri, dependency scanning, the threat model |

## In one paragraph

You create a chat and get a `talkrypt://…` invite (also a QR). A peer joins with
it; a one-time invite token + an out-of-band [safety number](Identity-and-Accounts.md)
defeat first-contact MITM. Every message is sealed with a [Double
Ratchet](Cryptography.md) (per-message forward secrecy + post-compromise
recovery) whose asymmetric step is a hybrid PQ KEM. Groups re-key per epoch with
[TreeKEM](Messaging-and-Transport.md). Your long-term identity is an
[ML-DSA-87 key](Identity-and-Accounts.md) that certifies your devices; you can
present it, stay pseudonymous, or rotate per conversation. It runs over a
[Tor onion service](Messaging-and-Transport.md) with restricted discovery, and
your keys are held at the strongest [custody tier](Key-Custody.md) your device
offers.

[RustCrypto]: https://github.com/RustCrypto
