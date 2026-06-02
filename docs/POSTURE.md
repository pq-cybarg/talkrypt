# Crypto posture & schemes

talkrypt lets each chat select its **KEM posture**, identifies every crypto
**scheme** by a stable fingerprint, and advertises a scheme only through
encrypted **beacons**. This document explains the model and the privacy
properties.

## KEM postures

The asymmetric ("DH") ratchet step and TreeKEM node keys use a selectable
`KemProfile { posture, pad_pure }`. Identity and authentication are **ML-DSA-87
(pure post-quantum) in every posture** — the posture only concerns key
establishment.

| Posture | KEM | EC? | Suite id token | When |
|---|---|---|---|---|
| **PQ-pure (default)** | ML-KEM-1024 only | none | `mlkem1024+pad` | Strict CNSA 2.0; zero elliptic curve. Padded on the wire (see below). |
| **Hybrid** | ML-KEM-1024 + X25519 | non-load-bearing | `mlkem1024+x25519` | IETF defense-in-depth: confidentiality holds if *either* primitive is unbroken. Always available in every build. |
| **PQ-pure compact** | ML-KEM-1024 only | none | `mlkem1024` | Pure with no wire padding — 36 bytes smaller, but the posture is visible to a relay by frame size. |

Why PQ-pure by default: NSA CNSA 2.0 prescribes *pure* ML-KEM/ML-DSA, not
hybrids. Against a quantum adversary a hybrid's security already rests entirely
on ML-KEM (X25519 falls to Shor's); the hybrid only hedges a *classical* break
of ML-KEM before quantum computers exist. Both are offered; hybrid is one flag
away (`--posture hybrid`) and can never be removed from a build.

The X25519 half, when present, is the **only** elliptic curve in talkrypt and is
never load-bearing.

## Wire indistinguishability (padding)

A relay carrying ciphertext can fingerprint a chat by **frame size**. A hybrid
ratchet public key is 36 bytes larger than a bare PQ-pure one (it carries the
32-byte X25519 public + a 4-byte length prefix). So padded PQ-pure (the default)
writes 36 filler bytes in the X25519 slot:

- **Length-identical** to hybrid (both 1608 bytes for the ratchet public).
- **Shape-identical**: the filler's high bit is cleared, matching a real X25519
  u-coordinate (`< 2^255−19`), so it is content-indistinguishable too.
- **Inert**: the filler never enters key derivation — PQ-pure IKM is the ML-KEM
  shared secret alone (locked by test). It is cosmetic wire bytes, not a key.

Result: a relay cannot tell a padded-PQ-pure chat from a hybrid chat. The
compact variant trades this away for bandwidth. Padding is a per-chat setting,
default on.

The posture is bound into the session root key via the suite id, so a posture
**mismatch between peers fails closed** (different roots, no shared key).

## Schemes & fingerprints

A *scheme* is a complete construction: a suite id plus opaque params. Its
identity is `scheme_hash = SHA3-256(len(id)‖id‖len(params)‖params)` (stable
across the `cnsa-sha2` build). To participate in a chat, a receiver must hold a
**registered scheme whose fingerprint matches** the chat's
(`SuiteRegistry::get_by_scheme_hash`); a miss means "this build lacks that
scheme, cannot join." Custom schemes are added deliberately, out of band.

Posture is **optional in an invite**: a blank suite id resolves to the protocol
default (PQ-pure), so a minimal/private invite need not state anything, and a
blank-posture invite interoperates with an explicit-default one.

## Beacons (always encrypted)

A *beacon* advertises a chat's scheme. **A beacon is never sent in cleartext** —
it is always post-quantum + AES-256-GCM protected:

- **Broadcast / server advertisement** (`seal_broadcast`): AES-256-GCM under a
  key derived from the chat root. AES-256 under a 256-bit key is
  quantum-resistant, so no asymmetric step is needed; only descriptor holders
  can open it, so a relay that stores it for discovery holds **opaque
  ciphertext** and learns nothing.
- **To-recipient** (`seal_to_recipient`): the PQ HPKE (ML-KEM-1024 +
  AES-256-GCM) to one peer's public key.

A beacon's granularity is the sender's choice: a bare **fingerprint** (the
receiver must already hold a matching scheme) or the **full definition** (suite
id + params, adoptable only after *explicit* receiver confirmation — a sender
must never silently dictate a peer's crypto).

Publication is layered and never forced: (1) peers must agree on the posture
(it's in the private invite, bound into the root); (2) the invite field is
optional; (3) the beacon / server advertisement is **opt-in, default off**.
Private users emit no beacon and the relay learns nothing.

## Using it

```sh
# Default (PQ-pure, padded, zero EC):
talkrypt host --channel '#general'

# Hybrid defense-in-depth:
talkrypt host --posture hybrid

# Require an explicit choice (mandatory-posture setting; no silent default):
talkrypt host --require-posture --posture pq-pure

# Publish a sealed scheme advertisement (opt-in; prints an opaque blob):
talkrypt host --advertise full        # or: fingerprint | off (default)

# Joining resolves the chat's scheme by fingerprint; a scheme this build
# doesn't have registered is refused:
talkrypt join talkrypt://...
```

The TUI (`talkrypt-tui host --posture ...`) and the FFI
(`TalkryptClient.host(listen, channel, posture)`) expose the same selection.

**Build gating** (`offered_profiles`): every build offers padded PQ-pure (the
default) and hybrid; the posture-leaking *compact* variant is dropped from
`--features fips` builds. `--features cnsa-sha2` switches the hash token
(`sha3-384` → `sha384`) in every suite id.
