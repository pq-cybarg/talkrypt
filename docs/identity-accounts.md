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

The certificate chain is sent **inside the established encrypted session**, not
in the plaintext handshake. The account↔device linkage is *sensitive* — it says
which devices belong to which account — so it must inherit the session's AEAD
confidentiality and forward secrecy, never travel in the clear over the
app-layer handshake. (Constraint: *security for all communications of secure
material must be ensured.*)

Concretely (`crates/core/src/engine.rs`, `crates/core/src/friends.rs`):

- After the mutual-auth handshake completes and the ratchet/Noise session is up,
  a node that has called `Core::present_identity(chain, username)` sends a
  `Frame::Identity` — an encoded `Presentation { chain, username }` — as the
  **first frame inside the encrypted channel**. A pseudonym presents nothing.
- The receiver **binds** the chain to the device it already authenticated:
  `chain.leaf().fingerprint()` must equal the peer's handshake-verified
  fingerprint. This stops anyone replaying a friend's real chain over their own
  session. It then verifies the chain and checks its account root against the
  pinned `FriendStore`, emitting `Event::Identity { from, account_fingerprint,
  username, friend }`. `friend` is true only for a pinned account — and that is
  unforgeable without the account's ML-DSA private key.
- Friends list (`FriendStore`) = pinned account keys + fingerprints (+ optional
  usernames). `Core::pin_friend` is the trust decision; resolution is pure
  verification against it.
- Presentation is gated to plain **pairwise** mode (`GroupRole::None`,
  non-relayed); group/relayed pairwise channels carry coordination/`Routed`
  envelopes, not friending.
- All certs/sigs are ML-DSA-87; account and device fingerprints use SHA3-384 (as
  today's safety numbers). No EC anywhere in this layer.

The same surface is exposed over the FFI (`crates/ffi`): `pin_friend(account_pubkey,
username)`, `present_identity(chain_bytes, username)`, and an `FfiEvent::Identity`
variant — so the mobile/desktop apps friend and resolve accounts with the one
shared core.

## Decisions (settled)

1. **Username discovery — keyless default + opt-in registries.** Identity is the
   account key; the username is a self-asserted label. Optionally a user
   *registers* on one or more **registries** — a persistent channel (onion) or a
   custom host following the registry protocol; a user can **spawn a registry
   from a device**, and later multiplatform apps can host them. Users may
   register on **more than one**, giving redundancy against any single host being
   attacked and **unforgeability via cross-compare** (`account::cross_compare`):
   a name resolves only if every registry agrees on the same self-signed account
   key. Registration is entirely opt-in.
2. **Account-key custody — all options.** The account key is an ordinary
   ML-DSA-87 `IdentityKeyPair`, so its 32-byte seed can live at any custody tier:
   sealed + recovery phrase, primary-device-only, or a hardware token/companion.
3. **Linkage — per-contact opt-in**, with three presentation modes (linked /
   standalone pseudonym / rotating per-conversation).
4. **Segmented identities / signature trees.** A device may hold multiple
   segmented identities — sub-keys it certifies under itself (`account → device →
   segment`) — so one device can present different, mutually-unlinkable
   identities in different contexts. Modeled by the general `IdentityChain`
   (any-length path from the account root to a leaf).

## Status

The cryptographic core is **built + tested** (`crates/crypto/src/account.rs`):
`Cert`/`SignedCert`/`IdentityChain` (signature trees), `belongs_to_account`
(impersonation-proof friend check), `cross_compare` (multi-registry agreement),
`UsernameClaim`/`SignedClaim`.

The **engine integration is built + tested** (`crates/core/src/friends.rs`,
`crates/core/src/engine.rs`): a live session resolves a peer's device to an
account by verifying an `IdentityChain` it presents inside the encrypted channel,
bound to the authenticated device, checked against a pinned `FriendStore`, and
surfaced as `Event::Identity`. Covered by unit tests (binding, impostor, expired,
segmented, wire roundtrip) and an end-to-end engine test
(`friending_resolves_account_over_engine`). Exposed over the FFI for the apps.

The **registry is built + tested** (`crates/core/src/registry.rs`): a
`RegistryServer` serves `register`/`resolve`/`list` over the same authenticated,
AEAD-encrypted session as chat (a shared registry descriptor supplies the
handshake root); a `RegistryClient` publishes a self-signed `SignedClaim` and
resolves names; `resolve_across` runs `cross_compare` over claims gathered from
several registries so a name resolves only if every registry agrees. Each stored
binding is signed by the account key, so a hostile registry can omit or refuse a
name but never fabricate one. Tested over loopback (roundtrip, name-taken
refusal, multi-registry agreement + equivocation detection).

The **CLI is interactive** (`crates/cli`): a `registry` subcommand hosts a
directory; `host`/`join` link to a username account (`--account`/`--username`)
or stay a pseudonym, and the in-session REPL drives friending (`/friend trust` a
just-seen account after an out-of-band safety-number check — TOFU without
pasting a 2592-byte key), account management (`/account`, `/username`,
`/pseudonym`), and registry use (`/register`, `/resolve` with cross-compare).
Presentation is **ratchet-aware**: the initiator presents eagerly; the responder
presents reactively once its session is send-ready (a responder cannot send
before receiving the initiator's first frame).

**Remaining integration:** in-person device pairing / chat-start over QR (and
optionally BLE/Wi-Fi), and graphical friends/linking/segment management in the
mobile/desktop apps.

NOT certified / NOT audited — see the project README.
