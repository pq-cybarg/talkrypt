# RFC 9420 (MLS) conformance — status, mapping & honest divergence

## What is RFC 9420 conformant **today** (proven vs official vectors)

`talkrypt-crypto::mls` implements standards-track MLS components and validates
them against the MLS working group's **official test vectors**
(`mlswg/mls-implementations`), ciphersuite 1
(`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`):

| Component | Vector file | Status |
|---|---|---|
| Tree math (log2/level/root/left/right/parent/sibling) | `tree-math.json` | ✅ passes (n=1,2,4,8) |
| `ExpandWithLabel`, `DeriveSecret`, `RefHash` + varint encoding | `crypto-basics.json` | ✅ passes |
| Epoch key schedule (extract → welcome/epoch → all 9 derived secrets) | `key-schedule.json` | ✅ passes |
| Secret tree (leaf descent, handshake/application ratchet keys+nonces, sender-data key/nonce) | `secret-tree.json` | ✅ passes |

These are real RFC 9420 conformance results, in CI as `#[test]`s. The **entire
MLS key-derivation hierarchy** — tree math → key schedule → secret tree →
per-message keys — is working and validated against official vectors, **not**
deferred.

## What remains for full protocol conformance

The standards-track *wire/message* layers build on the proven key hierarchy
above and are the next increment: **message-protection** framing
(`MLSMessage`/`FramedContent`, Ed25519 sign/verify, AES-128-GCM AEAD),
**Welcome**/`GroupInfo`/`GroupSecrets` (HPKE DHKEM-X25519), the TreeKEM
**update-path** under the RFC ciphersuite, and an **interop** run against
another implementation. Each has an official vector file to validate against the
same way.

## Note on the PQ group (`treekem.rs`)

talkrypt's *shipped, default* group is post-quantum (ML-KEM-1024 + X25519,
ML-DSA-87, SHA3-384) — deliberately **not** an RFC 9420 ciphersuite, so it does
not interoperate with classical MLS. The `mls` module above is the standards
path; the two coexist. The text below maps concepts between them.

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
