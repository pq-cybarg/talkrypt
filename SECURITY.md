# Security

## What protects what

talkrypt nests two independent layers (see `docs/CSFC.md`):

- **Inner — end-to-end content.** Post-quantum crypto: ML-KEM-1024 KEM
  (PQ-pure by default — zero EC; optional `+X25519` hybrid), ML-DSA-87
  authentication, AES-256-GCM, KMAC256/SHA3 (or SHA-384 via `cnsa-sha2`).
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

- **No independent audit, cryptographic review, or penetration test.** None of
  the properties in this document have been verified by anyone outside this
  project; the implementation may contain bugs that completely break them. Do
  not rely on talkrypt for high-stakes confidentiality or classified
  information without an independent audit. The bundled fuzzing/Kani harness is
  the authors' own testing, not an audit.
- **Not FIPS-validated / not CSfC-accredited / not NSA-approved / not authorized
  for any classification level.** Those are external lab/agency processes that
  source code cannot self-certify (see the README banner and `docs/CSFC.md`).
  Classification *markings* are advisory labels only — not authorization.
  "CNSA 2.0-aligned" means *uses those algorithms*, not certified or fit for
  real classified/high-stakes use.
- **Endpoint compromise while running** (keylogger, screen capture, RAM
  scraping of a live session) — no software prevents reading plaintext on a
  fully owned device.
- **Global passive traffic-confirmation against Tor** itself.
- **TreeKEM group chat** is integrated through the engine: dynamic
  Add/Remove/Welcome (removal forward-secrecy), epoch-sequenced commits
  (concurrent joins converge), roster-based sender attribution, descriptor-driven
  selection, and a **non-member relay** (`RelayHub`) that forwards ciphertext
  without holding the group key. The wire format is **frozen + KAT-locked**
  (`docs/WIRE.md`).
- **Not RFC 9420 conformant** (`docs/CONFORMANCE.md`): talkrypt's group layer is
  a post-quantum construction with its own compact wire format, so it does not
  interoperate with standard MLS. A classical/standardized-PQ ciphersuite, MLS
  TLS-presentation framing, and the official interop test vectors remain future
  work.
- **Transient symmetric secrets** in live session state are not all
  zeroized-on-drop yet; long-term secrets are.
- **GUI bundles** (Android APK, desktop) are integration-documented, not built
  in CI; the Rust core + FFI they depend on are built and tested.

## Reporting

This is pre-release software. Report issues privately to the repository owner;
do not file public issues for suspected vulnerabilities.
