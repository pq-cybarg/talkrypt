# talkrypt wire format (talkrypt-mlspq wire v1)

This is the **frozen, versioned** byte format for talkrypt messages. It is a
compact length-prefixed encoding (not RFC 9420 TLS-presentation framing — see
[`CONFORMANCE.md`](CONFORMANCE.md)). Encodings are locked by **known-answer
tests** (KATs) so any accidental change fails CI.

## Primitives (`talkrypt-wire`)

- All integers are **big-endian**.
- `u8` — one byte. `u32` — four bytes.
- `bytes(x)` — a `u32` length prefix followed by `x` raw bytes. A length above
  `MAX_FRAME` (16 MiB, the jumbo-frame ceiling) is rejected before allocation.

KAT: `put_u32(0xDEADBEEF) = DE AD BE EF`; `put_bytes("hi") = 00 00 00 02 68 69`.

## Identity & keys

- **Hybrid public key** `RatchetPublic`: `bytes(x25519_pub[32]) ‖ bytes(mlkem1024_ek[1568])` → **1608 bytes**.
  KAT (`derive_deterministic([7;32])`, default SHA-3/KMAC256 build): SHA3-256 =
  `3876ca2f820da022654cbefd2e47648a1d72ba25af704710baf16948cdd47895`.
- **Identity public** (handshake): `bytes(ml_dsa87_vk) ‖ bytes(x25519_id[32])` —
  note: identity authentication is ML-DSA-87 only; there is no X25519 identity
  key (the field is reserved/zero in current builds).
- **Fingerprint**: `Hash(ml_dsa87_vk)` (SHA3-384 → 48 bytes).

## Chat descriptor (the invite)

`u32 version ‖ u8 topology ‖ u8 persistence ‖ bytes(suite_id) ‖
 bytes(suite_params) ‖ u32 n_endpoints ‖ (bytes(endpoint))* ‖
 bytes(invite_token) ‖ bytes(channel) ‖ u8 group`

URI form: `talkrypt://` + lowercase RFC 4648 base32 (no padding) of the above.
KAT (canonical descriptor): see `descriptor_uri_kat`.

Tags: topology `{P2P=0, Hub=1, Hybrid=2}`; persistence `{Ephemeral=0,
Persistent=1}`.

## Double Ratchet message

`bytes(header) ‖ bytes(aead_ciphertext)`, where
`header = bytes(ratchet_pub) ‖ bytes(mlkem_ct) ‖ u32 pn ‖ u32 n` and is bound as
AEAD associated data. AEAD = AES-256-GCM; nonce derived per message key.

## TreeKEM (group) messages

- **KeyPackage**: a `RatchetPublic` (1608 bytes).
- **Node** `(lo, span)`: `u32 lo ‖ u32 span`.
- **Commit**: `u32 n_proposals ‖ (proposal)* ‖ u32 n_pub ‖ (node ‖ bytes(pub))* ‖
  u32 n_path ‖ (node)* ‖ u32 n_ct ‖ (node ‖ node ‖ bytes(blob))* ‖ u32 new_capacity`.
  Proposal: `u8 tag` (`Add=0`: `u32 leaf ‖ bytes(pub)`; `Remove=1`: `u32 leaf`).
- **Welcome**: `u32 capacity ‖ u32 n_pub ‖ (node ‖ bytes(pub))* ‖
  u32 n_occupied ‖ (u8)* ‖ u32 epoch ‖ u32 your_leaf ‖ bytes(commit)`.
- **Group message**: `u32 epoch ‖ u32 sender_leaf ‖ u32 n ‖ bytes(aead_ct)`;
  AAD binds `(epoch, sender_leaf, n)`.

## Engine frames (inside the pairwise channel)

`u8 tag ‖ payload`:
`Chat=0` (`bytes(channel) ‖ bytes(text)`), `KeyPackage=1` (`bytes`),
`Welcome=2` (`bytes`), `Commit=3` (`u32 from_epoch ‖ bytes`),
`GroupMsg=4` (`bytes`), `Roster=5` (`u32 n ‖ (u32 leaf ‖ bytes(fp[48]))*`).

## Relay envelope (relayed group mode)

`Routed = u8 to_tag ‖ [bytes(peer_fp[48]) if to_tag==Peer] ‖ bytes(from_fp[48]) ‖ bytes(inner_frame)`.
`to_tag`: `Broadcast=0, Peer=1, Committer=2`. The relay reads only the envelope;
the inner group payload stays encrypted to keys it does not hold.

## Versioning

The descriptor's `version` gates the whole format. A breaking change bumps it;
decoders reject unknown versions. The KATs above are the regression anchor.
