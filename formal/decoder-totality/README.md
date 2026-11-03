# Nested-heap decoder totality — Aeneas → F\* pipeline

Lands a **machine-checked totality proof** (no panic / no overflow / no OOB on any
input) for the nested-heap decoders that **Kani/CBMC provably cannot** discharge:

- `LinkageProof`, `LinkagePayload`, `NamePresence` (`crates/core/src/linkage.rs`)
- `Marking` (`crates/core/src/*`)
- the embedded `IdentityChain(Vec<SignedCert{String, Vec<u8>, Vec<u8>}>)` they hold

Why Kani can't: the **nested-heap return type** blows up the bounded model checker
(~34M clauses even with stub sub-decoders) — see `docs/fv-heap-decoder-spike.md`.
A representative instance was already **proven total in Verus** (`4 verified, 0
errors`); this directory lands the proof **in-repo, in CI, against the real
decoders** via the **Aeneas → F\*** route, which reuses the F\* toolchain already
proving `formal/GroupAuth.fst`.

## Status

| Step | State |
| --- | --- |
| Proof-of-possibility (Verus, representative shape) | **Done** (spike doc) |
| Charon (Aeneas frontend) supply-chain CVEs | **Cleared** — `cargo update`, `cargo audit` exit 0 (see below) |
| Build Charon + Aeneas | **VM step** (`build-in-vm.sh`) — NOT on the opsec host |
| Extract decoders → LLBC → F\* model | VM step |
| Discharge totality in F\* + wire into `formal/` CI | VM step → commit the `.fst` here |

## The Charon CVE fix (host-safe — reproduced, audit exit 0)

The spike skipped Aeneas because Charon's dep graph carried CVEs. They are **all in
transitive networking crates** (`quinn-proto`, `rustls`, `rustls-webpki`, `bytes`,
`crossbeam-epoch`) — Charon never opens a network connection while extracting our
decoders — and **every one has a patched point-release**. A plain `cargo update`
clears them:

```
cd charon/charon && cargo update
# bytes 1.10.1->1.12.1, crossbeam-epoch 0.9.18->0.9.21, quinn-proto 0.11.16->0.11.19,
# rustls 0.23.31->0.23.46, rustls-webpki 0.103.4->0.103.16, rustls-pki-types ->1.15.1,
# quinn ->0.11.12, quinn-udp ->0.5.16, tokio-rustls ->0.26.6, hyper-rustls ->0.27.10,
# webpki-roots ->1.0.11
cargo audit            # => 0 vulnerabilities (exit 0)
```

Residual: **8 advisory _warnings_ only** — `unmaintained` (ansi_term, atomic-polyfill,
bitmaps, difference, im) and `unsound` (sized-chunks, im). These are dev/ergonomics
deps (terminal colors, test-diffing, immutable collections); none is exploitable in
a local, offline code-extraction tool, so they are accepted (documented here) rather
than chased. Re-audit any time with `scripts/` + the pinned toolchain.

`cargo update` and `cargo audit` run **no build scripts** (lockfile resolution +
RustSec DB lookup only), so clearing the CVE gate is safe on the opsec host. Only
the subsequent **build** executes third-party build scripts — that is the VM step.

## Opsec boundary (why the build is a VM step)

Per `docs/fv-heap-decoder-spike.md` and the project opsec posture, source FV tools
are built **in a throwaway VM**, never on the opsec-sensitive host: a source build
runs hundreds of third-party build scripts. Charon also needs a pinned nightly
(`rust-toolchain`: `nightly-2026-09-17` + `rustc-dev`/`llvm-tools`/`rust-src`) and an
OCaml/dune toolchain. `build-in-vm.sh` is written to run **inside that VM**; it must
not be run on the host.

## Extraction targets

The proof obligation is **totality of the public `decode` entry points** on
attacker-chosen bytes (they run before any crypto verification):

- `linkage::LinkageProof::decode(&[u8]) -> Option<LinkageProof>`
- `linkage::LinkagePayload::decode(&[u8]) -> Option<LinkagePayload>`
- `presence::NamePresence::decode(...)`
- `Marking::decode(...)`
- transitively: `IdentityChain::decode`, `SignedCert::decode`

The `decode_with` dependency-injection seam already in `linkage.rs` makes the
compositional argument explicit (wrapper total **iff** wire reads + sub-decoders
total), so the F\* obligation decomposes cleanly.

## Pipeline (run `build-in-vm.sh` in the VM)

1. Clone Charon, `cargo update` (clears CVEs), build `charon` + `charon-driver`.
2. Build Aeneas (OCaml) against this Charon.
3. `charon` the decoder crate → LLBC; `aeneas -backend fstar` → `*.fst` model
   (heap disappears via the borrow-checker → pure-functional translation).
4. Prove `decode` total in F\* (add `thm_decode_total` lemmas); drop the `.fst`
   into `formal/` and add it to the `Makefile` `fstar` target + `formal.yml` CI.
5. Flip `linkage.rs:301` "diagnosed, not landed" → "landed (Aeneas→F\*)" and update
   `SECURITY-AUDIT.md` §5 + `docs/fv-heap-decoder-spike.md`.

## Alternative that needs no VM (recorded for the decision)

The **bounded heap-free buffer** route (spike §Recommendation 3): refactor the wire
types to fixed-capacity (`heapless`/`arrayvec`, capped by the already-enforced
`MAX_FRAME`). The decoders then become **flat**, and the **Kani already in CI**
verifies them directly (as it does for `VouchTarget`) — no Charon, no Aeneas, no VM.
Cost: a source change to security-critical decoders (+ re-run their fuzz targets).
This is the fastest path to an *actually-landed in-CI proof on this host*; the
Aeneas→F\* route above is the *zero-source-change* path once a VM is available.
