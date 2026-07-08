# OpenMLS pure-PQ ciphersuite spike (task #81)

Empirical verification for the [OpenMLS evaluation](../openmls-pq-evaluation.md): does
OpenMLS's pure post-quantum ciphersuite
`MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87` (ML-KEM-1024 + ML-DSA-87) actually run a
full group lifecycle end-to-end?

**This is a throwaway reference crate, not part of the talkrypt workspace** (it pulls
OpenMLS from git and is kept here only as a migration reference). It is intentionally
NOT wired into the Cargo workspace.

## Result: PASSED ✅

```
ciphersuite = MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
signature_algorithm = MLDSA87
[ok] created group under PQ ciphersuite, epoch 0
[ok] added bob, epoch 1
[ok] bob joined, epoch 1
[ok] bob received: "hello bob (pq)"
[ok] bob self-update applied; epochs a=2 b=2
[ok] alice received (post-rekey): "hi alice, rekeyed"
[ok] removed bob; alice group size = 1

SPIKE PASSED: full lifecycle under MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87
```

Every core talkrypt feature verified natively: group create, add member, Welcome/join,
encrypted application messages (both directions), **member self-update (on-demand PCS —
the T-4 equivalent, native to MLS)**, and member removal.

## Setup facts (for the migration record)

- **Pin:** `openmls`, `openmls_rust_crypto`, `openmls_basic_credential`, `openmls_traits`
  from `github.com/openmls/openmls` **branch `main`, rev `6b743b8b`** (openmls 0.8.1-git,
  basic_credential 0.5.0-git). The PQ suites are **not in the crates.io 0.8.1 release** —
  git-main only.
- **Feature flag `draft-ietf-mls-pq-ciphersuites` must be enabled on `openmls`,
  `openmls_rust_crypto`, AND `openmls_basic_credential`.** Gotcha the spike caught:
  without it on `openmls_basic_credential`, the ciphersuite resolves and the provider's
  `supports()` returns Ok, but `SignatureKeyPair::new(MLDSA87)` panics with
  `UnsupportedSignatureScheme` — source-reading alone would have missed this.
- **Primitives:** ML-DSA via RustCrypto `ml-dsa 0.1.1`, ML-KEM via `ml-kem 0.3.2` — the
  **same crates talkrypt already depends on** — plus libcrux SHA-3 helpers.
- **Footprint:** ~113 unique crates (~326 build units) for this minimal spike vs.
  talkrypt's small in-house `treekem.rs`. Validate against the Android/FFI/desktop targets
  before committing.

## API shape used (OpenMLS 0.8.x)

`SignatureKeyPair::new(cs.signature_algorithm())` · `BasicCredential::new(bytes)` +
`CredentialWithKey` · `KeyPackage::builder().build(cs, provider, signer, cwk)` ·
`MlsGroup::builder().ciphersuite(cs).build(...)` · `add_members` / `remove_members` ·
`merge_pending_commit` · `StagedWelcome::new_from_welcome(...).into_group(...)` ·
`create_message` / `process_message` → `ProcessedMessageContent::ApplicationMessage` ·
`self_update(provider, signer, LeafNodeParameters::default())`.

## To reproduce

```
cargo run   # from this directory (needs network for the git deps)
```
