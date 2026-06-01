# Security

## What protects what

talkrypt nests two independent layers (see `docs/CSFC.md`):

- **Inner — end-to-end content.** Post-quantum hybrid crypto: ML-KEM-1024 +
  X25519 KEM, ML-DSA-87 authentication, AES-256-GCM, SHA3-384/HKDF.
- **Outer — transport/anonymity.** Tor onion services via Arti (with optional
  bridges + pluggable transports for anti-censorship).

A break in either layer does not by itself expose message **content**: the
inner PQ layer protects content even if Tor is broken; ML-KEM protects content
even if X25519 is broken.

## Per-suite guarantees

| Suite | FS | Post-compromise | Notes |
|---|---|---|---|
| `tk.dr.*` Double Ratchet (default) | per-message | yes | best for 1:1 |
| `tk.noise.*` PQ-Noise | per-message within session | no | lighter, ordered sessions |
| `tk.group.*` sender-keys | per-message | by re-keying | simple groups |
| `treekem` TreeKEM CGKA | per-message (per epoch) | yes (per commit) | O(log N) group re-key |

## Cryptographic posture

- **Authentication & identity: pure post-quantum** (ML-DSA-87). No EC identity
  key. Elliptic curve appears only as the X25519 half of the hybrid KEM —
  defense-in-depth, never solely load-bearing.
- **Harvest-now-decrypt-later** is mitigated by the ML-KEM half.
- **First-contact MITM** is mitigated by the invite-token PSK and confirmed by
  out-of-band **safety-number** (SHA3-384 fingerprint) comparison.
- **Decryption is uniform-failure** and decrypt runs on cloned state, so
  replays/forgeries cannot corrupt a session.
- **Keys at rest** (persistent onion key) are sealed with Argon2id +
  AES-256-GCM; the ML-DSA seed is held in zeroizing memory.

## In scope (mitigated)

Network/metadata adversary (Tor + restricted-discovery onions); endpoint key
compromise (ratchet FS + PCS); store-and-decrypt-later (PQ); first-contact MITM
(token + safety numbers); hostile wire input (bounded codec, fuzzed, Kani-proven
decoder, uniform AEAD failure).

## Out of scope / known limitations

- **No independent audit.** Do not use for high-stakes confidentiality without
  one.
- **Not FIPS-validated / not CSfC-accredited / not NSA-approved** — those are
  external lab/agency processes (see the banner and `docs/CSFC.md`).
- **Endpoint compromise while running** (keylogger, screen capture, RAM
  scraping of a live session) — no software prevents reading plaintext on a
  fully owned device.
- **Global passive traffic-confirmation against Tor** itself.
- **Group membership flows (Add/Remove/Welcome) for the TreeKEM suite** are not
  yet implemented (the key-agreement core is — see `docs/plans/0002-mls-pq.md`);
  use sender-key groups for dynamic membership today.
- **Transient symmetric secrets** in live session state are not all
  zeroized-on-drop yet; long-term secrets are.
- **GUI bundles** (Android APK, desktop) are integration-documented, not built
  in CI; the Rust core + FFI they depend on are built and tested.

## Reporting

This is pre-release software. Report issues privately to the repository owner;
do not file public issues for suspected vulnerabilities.
