# RFC 9420 (MLS) conformance — mapping & honest divergence

**Bottom line:** talkrypt's group chat implements the *mechanisms* of MLS
(TreeKEM CGKA, Add/Remove/Welcome, an epoch key schedule) but is **not** an
RFC 9420-conformant implementation, and cannot interoperate with one. This is
deliberate and is stated plainly here rather than papered over.

## Why it is not RFC 9420 conformant

1. **Ciphersuite.** RFC 9420 defines specific *classical* ciphersuites
   (e.g. X25519 / Ed25519 / AES-128-GCM / SHA-256). talkrypt uses a
   **post-quantum** construction — ML-KEM-1024 + X25519 (hybrid KEM), ML-DSA-87
   signatures, AES-256-GCM, SHA3-384 — which is **not a registered MLS
   ciphersuite**. By design, a chat is PQ or it is nothing; that choice is
   incompatible with the RFC's wire-level ciphersuite identifiers.
2. **Wire framing.** talkrypt uses its own compact length-prefixed format
   (`WIRE.md`), not the RFC's TLS-presentation-language framing
   (`MLSMessage` / `FramedContent` / `PublicMessage` / `PrivateMessage`,
   KeyPackage with `Credential`/`Capabilities`/`LeafNode` signatures, the exact
   `GroupInfo`/`GroupSecrets` Welcome layout).
3. **Interop verification.** True conformance is demonstrated against the MLS
   working group's published **test vectors** and a second implementation.
   Those are not available to this build offline, so any "interop verified"
   claim would be unverifiable — and is therefore not made.

## Structural mapping

| RFC 9420 concept | talkrypt equivalent | Notes |
|---|---|---|
| Ratchet tree (left-balanced) | `treekem::Node{lo,span}` range tree | range ids stay stable across doubling |
| Blank node + resolution | `is_blank` + `resolution()` | same algorithm |
| Update path | `rekey_path` + copath-resolution encryption | hybrid KEM per node |
| KeyPackage | `KeyPackage{leaf_public}` | no Credential/Capabilities/signature |
| Welcome (GroupSecrets/GroupInfo) | `Welcome{public, occupied, epoch, your_leaf, commit}` | secret encrypted to joiner leaf key |
| Commit + Proposals (Add/Remove) | `Commit{proposals, pub_updates, path, ciphertexts}` | Add/Remove only |
| Epoch key schedule | `derive_commit_secret` + per-sender chains | HKDF over SHA3-384 |
| Sender data / framing | engine `Frame` + `Routed` | talkrypt-compact, not MLS framing |
| Delivery Service (untrusted) | `RelayHub` | non-member relay, holds no group key |

## What true RFC 9420 conformance would require

- A **classical RFC ciphersuite** alongside the PQ one (or adoption of a future
  standardized PQ-MLS ciphersuite when one is registered).
- Implementing the **TLS-presentation wire format** for all MLS objects and the
  exact key-schedule labels (`"MLS 1.0 ..."`).
- Passing the published **tree-math, key-schedule, message, and welcome test
  vectors**, and an interop run against another implementation.

These are scoped as future work in `docs/plans/0002-mls-pq.md`. Until then,
talkrypt's group layer is a self-contained, versioned, KAT-locked PQ protocol
(`WIRE.md`) — not MLS-on-the-wire.
