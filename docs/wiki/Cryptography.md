# Cryptography

talkrypt's cryptography is **pure-Rust** ([RustCrypto]) and **post-quantum by
default**. Deep specs: `docs/POSTURE.md`, `docs/COMPLIANCE.md`, `docs/WIRE.md`,
`docs/SECURITY-AUDIT.md`. Source: `crates/crypto/`.

## Algorithm set (CNSA 2.0)

| Role | Algorithm | Standard | Source |
| --- | --- | --- | --- |
| KEM (key establishment) | **ML-KEM-1024** (Category 5) | FIPS 203 | `hybrid.rs` |
| Signature / identity | **ML-DSA-87** (Category 5) | FIPS 204 | `identity.rs` |
| AEAD (content) | **AES-256-GCM** | FIPS 197 + SP 800-38D | `aead.rs` |
| Hash / KDF (default) | **SHA3-384 + KMAC256** | FIPS 202 / SP 800-185 | `hash.rs`, `kdf.rs` |
| Hash / KDF (`cnsa-sha2`) | **SHA-384 + HKDF** | FIPS 180-4 / RFC 5869 | `hash.rs`, `kdf.rs` |
| Passphrase KDF | **Argon2id** (m=19 MiB, t=2, p=1) | RFC 9106 | `seal.rs`, `descriptor.rs` |
| Hybrid KEM half | **X25519** (non-load-bearing) | RFC 7748 | `hybrid.rs` |

**No EC identity.** Authentication is post-quantum end to end. The only elliptic
curve anywhere is the optional X25519 *hybrid* half of the ratchet's KEM step,
which is strictly defense-in-depth — see [EC is never load-bearing](#postures).

## The Double Ratchet

Each pairwise conversation runs a **Double Ratchet** (`ratchet.rs`):

- **Forward secrecy** — message keys come off a one-way KDF chain and are deleted
  after use, so compromising the current state does not reveal past messages.
- **Post-compromise recovery** — every asymmetric ratchet step injects fresh KEM
  entropy, so the session *heals* after a key leak.
- **Hybrid asymmetric step** — the step runs **both** an X25519 DH and an
  ML-KEM-1024 encapsulation; the two shared secrets are KDF-combined, so
  confidentiality holds if *either* primitive is unbroken.
- **Replay + ordering** — a per-message counter with a bounded skipped-key cache
  (`MAX_SKIP = 1000`) accepts out-of-order delivery and rejects replays.
- **Crash-safe** — decryption runs against a *clone* of the session state and
  commits only on success, so a failed/forged frame can't corrupt the session.

Two lighter schemes exist alongside it: a **PQ-Noise** session handshake
(`noise.rs`) and a **sender-key group** scheme (`group.rs`) for hub relaying.
Groups proper use [TreeKEM](Messaging-and-Transport.md).

## Postures

A *posture* trades wire size against metadata exposure. All three keep the full
PQ guarantee; they differ only in the X25519 hybrid half and padding
(`docs/POSTURE.md`).

| Posture | What's on the wire | Use |
| --- | --- | --- |
| **PQ-pure** (default) | ML-KEM-1024 only, **padded** to the hybrid length | PQ-pure, yet frame-size-indistinguishable from hybrid |
| **Hybrid** | ML-KEM-1024 **+ X25519** | Defense-in-depth (EC catastrophe insurance) |
| **PQ-pure compact** | ML-KEM-1024 only, unpadded (36 B smaller) | Smallest; frame size *reveals* the posture to a relay |

**Frame indistinguishability:** padded PQ-pure is byte-length-identical to
hybrid, and the filler is shaped to look like an X25519 public key (top bit
cleared), so an observer of the cleartext ratchet key cannot tell a padded
PQ-pure key from a hybrid one. The compact posture is dropped from `--features
fips` builds.

## Schemes & beacons

A *scheme* is a complete construction (suite id + opaque params), identified by a
`SHA3-256` **scheme fingerprint**. A chat can **advertise** its scheme via an
**always-encrypted** beacon (`beacon.rs`) — never cleartext — either as a bare
fingerprint or a full, adoptable definition. The suite **registry** (`suite.rs`)
rejects any scheme whose *declared parameters* fall below the CNSA floor
(ML-KEM-1024 / AES-256-GCM / ≥384-bit hash / ML-DSA-87), not just its
self-declared tag — and the AEAD key type (`&[u8; 32]`) structurally bars an
AES-128 key.

## Assurance built into the crypto

- **Power-on self-tests (POST)** + **per-keygen pairwise consistency tests
  (PCT)** run at startup/keygen and **abort** on failure (`selftest.rs`).
  Known-answer tests use **official NIST vectors**: AES-256-GCM and SHA-384/
  SHA3-384 (NIST), ML-DSA-87 keyGen (FIPS-204 reference), and ML-KEM-1024
  keyGen/encaps/decaps (NIST **FIPS-203 ACVP**).
- **Constant-time posture** — uniform AEAD failure, ML-KEM implicit rejection,
  constant-time ML-DSA verify, and a `subtle::ConstantTimeEq` identity-chain key
  comparison. No secret-dependent branches in talkrypt's own code
  (`SECURITY-AUDIT.md §3a`).
- **Zeroization on drop** — all transient symmetric secrets and the identity
  seed are wiped on drop, **Miri-verified** (`SECURITY-AUDIT.md F-3 / R-3`).
- **RAM-capture hardening** — the identity seed lives in an `mlock`'d,
  `MADV_DONTDUMP`, zeroize-on-drop `LockedBox`; `harden_process` disables core
  dumps and marks the process non-dumpable (`mem.rs`, `SECURITY-AUDIT.md §3b`).
  See [Key Custody](Key-Custody.md) for the at-rest and hardware story.

More on testing/fuzzing/Miri: [Security Assurance](Security-Assurance.md).

[RustCrypto]: https://github.com/RustCrypto
