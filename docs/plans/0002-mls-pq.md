# MLS-PQ (TreeKEM) group suite — scoped plan

> **Status: TreeKEM CGKA + dynamic membership BUILT (`crate::treekem`); RFC 9420
> wire conformance remains.** Implemented and tested: range-identified tree with
> blank-node **resolution**, hybrid-PQ node keys, path re-keying, epoch key
> schedule + per-epoch group messaging, and **Add / Remove / Welcome** with
> capacity doubling. Verified: founder→add convergence, multi-member messaging,
> capacity doubling, and **removal forward-secrecy** (a removed member cannot
> derive or decrypt the post-removal epoch).
>
> **Done:** phases 1–4 + Welcome/membership. **Remaining:** RFC 9420 wire
> framing + proposal batching, epoch transcript-hash binding, suite registration
> as `tk.mls.*`, and conformance against RFC test vectors. Sender-key groups
> (`tk.group.*`) remain the lighter option.

## Why a second group suite

| Property | Sender-keys (shipped) | TreeKEM-PQ (this plan) |
|---|---|---|
| Forward secrecy | ✅ per-message | ✅ per-message |
| Post-compromise security (group) | ❌ (rotate by redistributing keys) | ✅ continuous group key agreement |
| Cost to add/remove a member | O(N) pairwise redistribution | O(log N) tree update |
| Standards conformance | Signal-style, ad hoc | RFC 9420 (MLS) target |

## Target construction

A **TreeKEM** ratchet tree where every node holds a hybrid PQ KEM keypair
(ML-KEM-1024 + X25519), reusing `talkrypt-crypto::hybrid`:

- **Leaves** = members; **internal nodes** = derived key pairs shared by their
  subtree. The **root secret** seeds the group's epoch key schedule.
- **Update path:** when a member commits a change, it re-keys the path from its
  leaf to the root, encapsulating each new node secret to the *copath*
  resolution using the hybrid KEM. Cost O(log N).
- **Epoch key schedule:** HKDF (over `crate::hash::Hash`, SHA3-384) derives the
  epoch's encryption/handshake/membership secrets from the root + a confirmed
  transcript hash, exactly as in `tk.dr.*`/`tk.noise.*`.
- **Add / Remove / Update / Commit** proposals; blank nodes + unmerged-leaves
  bookkeeping per RFC 9420 §7.

## Phased implementation

1. **Ratchet tree** — array-encoded binary tree, node/leaf indices, copath and
   resolution algorithms. Pure data structure, property-tested against the
   RFC's tree-math test vectors.
2. **Hybrid TreeKEM node keys** — generate/encap/decap per node via
   `hybrid::RatchetSecret`; update-path generation + application.
3. **Key schedule + epochs** — epoch secret derivation, confirmation tag,
   transcript hash; forward secrecy + PCS tests.
4. **Proposals & commits** — Add/Remove/Update/Commit; member join via Welcome.
5. **Wire format** — MLS message framing (or a talkrypt-compact variant first,
   RFC 9420 framing second), fuzzed.
6. **Suite registration** — `tk.mls.mlkem1024+x25519.aes256gcm.sha3-384` in the
   `SuiteRegistry`, selectable per chat descriptor like every other suite.
7. **Interop (stretch)** — validate against RFC 9420 test vectors and, if
   feasible, another MLS implementation.

## Integration

Drops in behind the existing seams: a new `CryptoSuite` (group variant), chosen
at chat creation and announced in the `ChatDescriptor`. The engine's per-peer
session model extends to a per-group session; the Hub topology fans out the
single MLS ciphertext (it already relays opaque bytes). No transport or
identity changes required.

## Risks / why it's separate

RFC 9420 is large and easy to get subtly wrong (tree blanking, parent-hash
validation, double-join, epoch desync). It warrants its own spec, its own
adversarial review, and conformance vectors before being trusted — hence a
dedicated sub-project rather than a bolt-on.
