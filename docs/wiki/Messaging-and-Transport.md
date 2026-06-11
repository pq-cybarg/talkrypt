# Messaging & Transport

How a chat is described, joined, routed, and carried. Deep specs:
`docs/DESIGN.md`, `docs/WIRE.md`. Source: `crates/core/`, `crates/transport/`,
`crates/topology/`, `crates/wire/`, `crates/crypto/treekem.rs`.

## Invites (chat descriptors)

A chat is a **descriptor** serialized to a `talkrypt://<base32>` URI (also a QR):
it encodes version, [topology](#topologies), persistence (ephemeral/persistent),
[suite](Cryptography.md) id + params, endpoint(s) (`.onion` + a client-auth
key), a one-time **invite token**, the initial channel, a group flag, and an
optional [classification marking](Classification-and-Compliance.md). A peer
missing the named suite gets a precise error telling them which suite to enable.

The **invite token** is a one-time pre-shared secret that seeds the session root
key, so only descriptor-holders can complete a handshake — the first-contact MITM
defense. An optional **channel password** is mixed into the root via Argon2id and
shared out-of-band, so capturing the link alone still can't join.

## Handshake

A dialer and a responder exchange signed prekeys (ML-DSA-87) and derive the
session root from the invite token + authenticated peer fingerprints (HKDF).
Wrong root ⇒ different keys ⇒ frames fail to decrypt **uniformly** (no partial
plaintext). Post-handshake, peers compare [safety
numbers](Identity-and-Accounts.md) out of band to confirm no MITM.

## Topologies

| Topology | How it routes | The relay sees |
| --- | --- | --- |
| **P2P** | every peer hosts its own onion and dials the others (full mesh) | n/a — no relay |
| **Hub** | one onion relays (IRC-like); members use rotating **sender keys** | ciphertext only + connection metadata |
| **Hybrid** | hub for rendezvous/presence; messages flow P2P | rendezvous metadata only |

A non-member **RelayHub** (`relay.rs`) can forward opaque ciphertext without ever
holding the group key.

## Groups (TreeKEM)

Group chats use a **TreeKEM** continuous group key agreement (`treekem.rs`,
RFC-9420-inspired with PQ nodes: ML-KEM-1024 + X25519 hybrid keys):
epoch-sequenced **Add/Remove/Welcome** commits, O(log N) path re-keying per
epoch, and **removal forward secrecy** (a removed member can't read future
messages). Sender attribution is roster-based. (It's a custom PQ construction,
not MLS-wire-conformant — no MLS interop by design; see `docs/CONFORMANCE.md`.)

## Transports

- **Tor / Arti onion services** (production) — in-process onion via `arti-client`
  + `tor-hsservice`. **Ephemeral** (fresh keypair per session, never persisted)
  or **persistent** (stable `.onion`, key sealed at rest). **Restricted
  discovery** via onion **client authorization**: only holders of the
  descriptor's auth key can resolve/reach the service — non-enumerable, doesn't
  advertise the operator. Censorship circumvention via bridges + pluggable
  transports (obfs4, Snowflake).
- **TCP** (`tcp.rs`) — the default development transport.
- **Loopback** (`loopback.rs`) — in-process; full protocol + crypto testing with
  zero network.

Persistent servers offer keep-alive strategies (always-on daemon,
client-anchored, replicated failover) and keep **no metadata logs** of who
connected when (`docs/DESIGN.md §8`).

## Wire format

Length-prefixed frames bounded by `MAX_FRAME` (16 MiB) — no allocation on a
hostile length prefix, and the decoder is **fuzzed + Kani-proven** for bounds
([Security Assurance](Security-Assurance.md)). A Double-Ratchet message is
`header ‖ AEAD(ciphertext)` with the header (ratchet public, KEM ciphertext,
counters) bound as AEAD associated data. Full grammar: `docs/WIRE.md`.

## Replay & integrity defenses (summary)

- Per-message counter + bounded skipped-key cache → replays rejected.
- AEAD binds the header as AAD → tampering or misrouting fails the open.
- Decrypt-on-clone → a forged frame never corrupts session state.
- Uniform failure → no oracle from *why* a decrypt failed.
