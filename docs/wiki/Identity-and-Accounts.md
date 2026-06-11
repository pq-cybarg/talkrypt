# Identity & Accounts

Identity in talkrypt is **post-quantum** (ML-DSA-87) and **hierarchical**: an
account certifies devices, devices mint contextual segments. Deep spec:
`docs/identity-accounts.md`. Source: `crates/crypto/identity.rs`,
`crates/crypto/account.rs`, `crates/core/{contacts,linking,registry}.rs`.

## Identity & safety numbers

Your long-term identity is an **ML-DSA-87** signing key (`identity.rs`). Its
public **fingerprint** is `SHA3-384(public_key)`, rendered as a grouped **safety
number** for out-of-band comparison — the defense against first-contact MITM. A
changed safety number is a signal to re-verify. There is no EC identity key; the
hybrid X25519 half lives only in the per-session ratchet
([Cryptography](Cryptography.md)).

## The account → device → segment chain

```
username ── account key (ML-DSA-87) ── device keys (ML-DSA-87, one per device)
                                              └── segment keys (unlinkable sub-identities)
```

- An **account key** is your durable identity; it **certifies** device keys with
  signed certificates: `Sign_account(device_pubkey ‖ label ‖ valid_from ‖ expiry)`.
- A **device key** is held in the device's [custody tier](Key-Custody.md) and
  never exported. Forging a device cert requires the account private key
  (ML-DSA-87 existentially unforgeable) — so impersonation is infeasible even for
  a quantum adversary.
- **Revocation** — the account key signs a revocation for a lost/compromised
  device; it propagates in-band and via a directory transparency log, so a leaked
  device key is refused thereafter.

## Privacy tiers (segments)

The same device can present at different linkabilities:

- **Linked** — attach the account cert → you resolve *as* your account/username.
- **Pseudonym** — present a bare device key, no cert → unlinkable to your account.
- **Rotating** — a fresh uncertified key per conversation → unlinkable across your
  own chats.

Segments are **contextual sub-identities** that all belong to one account yet
authenticate with **distinct leaf keys**, so they're mutually unlinkable at the
session/transport layer while a contact who pinned the account still recognizes
each as that account.

## Contacts, friends, and access (three separate things)

- **Contact** — *you* unilaterally pin an account key (from an invite QR, a
  verified directory, or a safety-number check). Recognition, not permission.
- **Friend** — an elevated label on a contact (your view of closeness). Still
  unilateral, not mutual.
- **Access** — a **separate grant** (`/access`, `/allow`, `/deny`) that gates who
  may join a channel. Being a contact or friend never auto-grants access, and a
  non-contact can be admitted. Resolution is impersonation-proof: a peer is
  recognized as account *A* iff `verify_ML-DSA(A, device_cert)` holds and the cert
  isn't revoked/expired.

Inside an encrypted session, the first frame after the mutual-auth handshake
carries a signed **Presentation** (account→device chain + username), bound to the
authenticated device fingerprint so it can't be replayed into another session.

## Device linking

`talkrypt link-offer` (primary, holds the account key) ↔ `talkrypt link-accept`
(new device) — the primary signs a device certificate for the new device's key
and sends only the cert; the account key never leaves the primary. Afterwards,
contacts see all your linked devices as the same account. See
[CLI Reference](CLI-Reference.md).

## Username registries

Usernames are display labels over account keys. Discovery is layered:

- **Self-asserted (default)** — no registry; trust comes from the safety number.
- **Directory-backed (opt-in)** — a Tor-onion or key-transparency directory maps
  `username → account key`, preventing silent key substitution. A **signed
  username claim** means a hostile registry can omit a name but never fabricate
  one.
- **Multi-registry cross-compare** — register on several directories; a name
  resolves only if **every** registry agrees on the same account key, so
  equivocation is detected and refused (`/resolve <name> <uri> <uri> …`).
