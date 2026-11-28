# Archived formal proofs — pre-topology-overhaul snapshot (2026-11-24)

These are **verbatim copies** of `formal/*` as of the known-good build tagged
`known-good-2026-11-24-pre-topology` (commit 21f029d), taken BEFORE the topology /
control-plane resilience overhaul (hub-peer-peer-peer relay chains, hub-dropout
content continuity, conservative presumptive queue-only peering, room-configurable
multi-hub committer with consensus, no-hub P2P).

They are preserved as **valuable research** in their own right: each proves the
security model of the pre-overhaul engine, and the overhaul must not silently
invalidate them. The live `formal/*` files are EXTENDED (not replaced) with the new
proof obligations listed in `docs/plans/0005-topology-resilience.md` §"Proof
obligations"; this archive is the baseline those extensions are diffed against.

## What each file proves (as archived)

- `RatchetFS.fst` — pairwise Double Ratchet forward secrecy + post-compromise security.
- `Handshake.fst` — initiator/responder handshake authentication.
- `IdentityChain.fst` — identity-chain / device-certificate verification logic.
- `EngineAuth.fst` — engine authorization & control-plane state machine. **Directly
  affected by the overhaul** (new control-plane relay, admission, single-committer
  invariant, provisional-member state).
- `TreeKemKS.fst` — TreeKEM group key-schedule PCS/FS. **Affected** (multi-hub
  committer / failover must preserve the single-committer-per-epoch invariant; no
  premature key release).
- `GossipLiveness.fst` — transport/gossip liveness. **Directly affected** (control-plane
  relay + dedup, hub-dropout content continuity, relay rate-limiting/TTL).
- `GroupAuth.fst` / `GroupAuthQROM.ec` — group-message sender authentication (G1/G2),
  symbolic + computational (EUF-CMA / quantum). **Affected** (provisional members must
  accrue no attribution/trust; relay must not enable forgery).
- `ConfidentialityQROM.ec` — per-message confidentiality (ML-KEM-1024 IND-CCA-QROM).
- `LeafSigDeriveUnlink.ec` — derived leaf-signature-key unlinkability.
- `DecodeTotality.fst` — decoder totality (attacker-reachable parsers never panic).

Compiled artifacts (`*.eco`) and the `decoder-totality/` harness are NOT copied here
(regenerable from source via `formal/Makefile`).
