# Identity & accounts — design

How a person identifies as a **username account** that abstracts over many
per-device ML-DSA signing keys (phone, desktop, browser, …); how they **friend**
each other with impersonation protection; how they **optionally** link devices to
resolve as one user — while preserving the option of device-separation privacy
and even rotating on-device identities. Everything here is **pure post-quantum**
(ML-DSA-87 signatures, ML-KEM KEM); elliptic curve is never load-bearing.

This is a design proposal, not yet implemented. It builds on what exists today:
a per-device `IdentityKeyPair` (ML-DSA-87) authenticated in the handshake, with
out-of-band **safety numbers**.

## Three layers

```
   username (optional, human-readable)        ← discovery / display
        │  bound to ↓
   ACCOUNT key  (ML-DSA-87, long-term)         ← "who you are" to friends
        │  signs device certificates ↓
   DEVICE keys  (ML-DSA-87, one per device/browser, held in StrongBox /
        │        Secure Enclave / TPM / Keychain custody — never exported)
        │  used in ↓
   session handshake + double ratchet          ← the actual chat
```

- A **device key** is what authenticates a live session today. It lives in the
  device's strongest custody tier (the StrongBox/Keychain/TPM work) and never
  leaves the device.
- An **account key** is a long-term ML-DSA-87 keypair that *certifies* device
  keys. A **device certificate** is
  `Sign_account( device_pubkey ‖ device_label ‖ valid_from ‖ expiry ‖ epoch )`.
  Presenting a device + its cert proves "this device belongs to account A,"
  verifiable by anyone holding account A's public key.
- A **username** is a label bound to the account key (binding options below).

The account key is the stable identity; device keys are disposable and
revocable; the username is convenience on top.

## 1. Identifying as a username account

Two binding models — pick per deployment (this is an open decision):

- **Keyless / self-asserted (default, most private).** Identity *is* the account
  public key; the username is just a display label you advertise in your invite.
  Trust comes from verifying the account key's **safety number** out of band, not
  from the name. No registry, no central trust anchor — fits the no-server,
  anti-censorship posture. (This is essentially Signal's historical model,
  lifted to the account key.)
- **Directory-backed (optional, for name discovery).** A directory maps
  `username → account_pubkey`, served over a Tor onion or a **key-transparency
  log** (CONIKS/Keybase-style). The transparency log is what makes name-based
  discovery safe: it prevents the directory from silently handing different
  contacts different keys for the same name (see *anti-equivocation*).

Either way the account key — not the name — is the cryptographic identity.

## 2. Friending (impersonation-proof)

To friend someone you obtain and **pin** their **account public key** (via an
invite QR/URI, or a directory lookup you then verify by safety number). You
store `(username, account_pubkey, account_safety_number)`.

When you later talk to one of their devices, that device presents its **device
certificate**. You accept the device as "your friend A" iff:

```
verify_ML-DSA( account_pubkey_of_A, device_cert )  == valid
   AND  device_cert not revoked  AND  not expired
```

**Why an impersonator can't pretend to be a friend:** forging a device cert that
validates under A's account key requires A's ML-DSA-87 *private* key. ML-DSA-87
is post-quantum existentially-unforgeable, so no attacker (even with a quantum
computer) can mint a device that your client will accept as A. A friend is a
**pinned account key**; only devices A actually certified pass. This is the hard
requirement, met cryptographically.

Defense-in-depth (as today): the **account safety number** is compared out of
band on first friend; if A's account key ever changes, the client warns
("safety number changed") and requires re-verification — preventing silent
key substitution.

## 3. Linking devices (opt-in) — resolving as the same user

When the user *wants* devices to resolve as one account:

1. The new device generates its own device key (in its custody tier).
2. It sends the device pubkey + label to a device that holds the **account key**
   (the "primary"), over an authenticated channel (QR pairing or an existing
   session).
3. The primary signs a **device certificate** and returns it (plus the account
   public key).
4. The new device now presents that cert in handshakes → friends see all the
   user's devices as the same account.

The **account private key does not live on every device** (that would be a
single fat point of compromise). Options for where it lives (open decision):

- **Primary device only** — simplest; new-device linking needs the primary.
- **Sealed + recovery phrase** — the account key is sealed at rest (TPM/Keychain
  custody, or an Argon2id-wrapped recovery phrase) so a lost primary is
  recoverable.
- **Hardware token** — the account key on a security key / the companion device
  (ties into the entropy/custody companions in `entropy-companions.md`).

**Revocation:** the account key signs a revocation for a lost/compromised device
cert; revocations propagate in-band on next contact and/or via the directory's
transparency log. A revoked device is rejected even if its key leaks.

## 4. The privacy options you asked for

Linkage is **selective and opt-in per contact/conversation** — a device decides
whether to attach its account cert:

- **Linked** — attach the account cert → you resolve as your account/username.
- **Standalone pseudonym** — present only the bare device key, *no* account cert
  → you appear as a separate, unlinkable identity. A contact who never receives
  the cert cannot tie this device key to your account.
- **Rotating on-device** — the device mints a fresh, uncertified identity key per
  conversation (or per session) → unlinkable even across your own chats on the
  same device (forward-anonymity).

So the same person can show their account identity to close friends, a stable
pseudonym to a working group, and a rotating throwaway to a public channel —
from one device. Unlinkability holds at the *crypto* layer because device/
pseudonym keys are independent and the account cert is only ever attached when
the user opts in; network-level unlinkability is the outer Tor layer's job.

Important: opting into a pseudonym **does not weaken** a friend's impersonation
protection — a pseudonym simply isn't certified under any account, so it can
never *claim* to be a friended account. Claiming account A still requires A's
valid cert (§2).

## Putting it on the wire

- The handshake/descriptor gains an **optional** `device_cert` field. Absent →
  bare device key (pseudonym/rotating). Present → the peer verifies it against a
  pinned (or directory-resolved) account key and resolves the account.
- Friends list = pinned account keys + safety numbers (+ optional usernames).
- All certs/sigs are ML-DSA-87; account and device fingerprints use SHA3-384 (as
  today's safety numbers). No EC anywhere in this layer.

## Open decisions (for the maintainer)

1. **Username discovery:** keyless/self-asserted (identity = key) vs a
   directory + **key-transparency log** for name lookup. (Recommend: keyless by
   default; transparency-log directory as an opt-in for name discovery.)
2. **Account-key custody:** primary-device-only vs sealed+recovery-phrase vs
   hardware token. (Recommend: sealed + recovery phrase, reusing the custody
   tiers, so loss is recoverable without putting the key on every device.)
3. **Default linkage:** per-contact opt-in (recommend) vs linked-by-default.
4. Whether to ship **rotating per-conversation** identities in v1 or after the
   account/friend core.

NOT certified / NOT audited — see the project README.
