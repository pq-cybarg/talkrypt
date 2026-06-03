# Entropy-source companions — trust model (design, #3 / #431–#437)

Companion apps (a browser native-messaging host, a localhost companion in the
Ledger-Live pattern, a phone companion) are described in the roadmap as an
"entropy-source class." A component that influences key generation is
**security-critical**, so its trust model must be settled *before* code. This
document proposes that model. It is design, not implementation.

## The governing principle: a companion is NEVER load-bearing

This mirrors talkrypt's rule that elliptic curve is never load-bearing
([`POSTURE.md`](POSTURE.md)) and that markings/labels are advisory: **a
companion can only ever *strengthen* security, never weaken it.** Concretely:

> The OS CSPRNG (`getrandom`) remains the sole *trusted* randomness source.
> Companion-supplied entropy is **mixed in**, never substituted. If *either*
> the OS CSPRNG or the companion input is good, the result is strong.

This is the standard robust-combiner construction. For a 32-byte draw:

```
seed = KMAC256(key = os_random(32), msg = companion_bytes, label = "talkrypt/v1/entropy-mix")
```

(`KMAC256` is the SHA-3 build's `mac_kdf`; HKDF-SHA384 under `cnsa-sha2`.)
Because the OS entropy is the *key*, an attacker who fully controls
`companion_bytes` — or who MITMs the companion channel and injects
attacker-chosen bytes — **cannot** reduce the seed's entropy below the OS
CSPRNG's: the output is a PRF keyed by secret OS randomness the attacker does
not know. A *faulty* companion (stuck/biased/zero output) is equally harmless.

### What a companion must NOT be allowed to do

- **Be the sole RNG.** If `getrandom` is unavailable, key generation fails
  closed — it never falls back to "companion only."
- **Replace or downgrade** the PQ KEM/signature or the AEAD. Companions feed
  entropy or hold custody; they never select algorithms.
- **Silently become load-bearing.** Any mode where a companion *is* required
  (see custody below) must be explicit, opt-in, and documented as such.

## Transport

Per the project rule that all such transmission is PQ + AES encrypted and
never cleartext (see [`POSTURE.md`](POSTURE.md) beacons), the app↔companion
channel is:

- **Authenticated** — the companion is pinned (its public key recorded on first
  pairing); an unpinned/changed companion is rejected.
- **Encrypted** — ML-KEM-1024 + AES-256-GCM (reuse `crypto::mls::hpke` /
  `crypto::beacon`), so a local eavesdropper sees nothing.

Even with a perfectly secure channel, the *mixing* property above means trust
in the companion's honesty is not required for the entropy use case.

## Two companion roles (keep them distinct)

1. **Entropy supplement (default, non-load-bearing).** The companion provides
   additional bytes mixed as above. A TRNG/secure-element source (e.g. the
   Solana Seeker) is a good supplement. Recommended default; safe even if the
   companion is hostile.

2. **Custody device (opt-in, explicitly load-bearing).** The companion *holds*
   or *wraps* key material (Ledger pattern) → maps to the `HardwareBacked`
   custody tier ([custody tiers](ROADMAP.md)). This **is** load-bearing: losing
   or compromising the companion affects availability/custody. It must be an
   explicit user choice with the trade-off stated, never a silent default. The
   messaging keys remain PQ; the companion wraps them (a wrapping key may be EC
   on existing hardware — the same non-load-bearing-EC caveat applies, and it
   protects custody at rest, not the messaging confidentiality).

## Open decision for the maintainer

Default posture is **role 1 (entropy supplement, non-load-bearing)** — it is
safe regardless of companion trust and needs no new trust assumptions. Role 2
(custody) should be enabled per-user only, with the trade-off surfaced. Confirm
this split before implementation; the mixing primitive and the pinned+encrypted
channel are then straightforward to build on existing crypto.

NOT certified / NOT audited — see the project README.
