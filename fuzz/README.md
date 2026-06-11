# talkrypt fuzz harness

Coverage-guided fuzzing of every attacker-reachable decoder, via
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). This is
recommendation **R-6** of `docs/SECURITY-AUDIT.md`.

## Why these targets

Anything that parses bytes an attacker controls — before any signature or AEAD
check has run — must never panic or over-read; it may only return `Ok` or a
typed error. Each target asserts that invariant, and for the structured codecs
also a **round-trip** (`decode → encode → decode` agrees), which catches
parser/serializer disagreement.

| Target | Surface | Entry point |
| --- | --- | --- |
| `wire_reader` | length-prefixed wire primitives | `talkrypt_wire::Reader` |
| `descriptor_parser` | `talkrypt://` invite/chat URIs | `ChatDescriptor::from_uri` |
| `identity_chain` | account→device→segment cert chain | `IdentityChain::decode` |
| `signed_claim` | account-signed claim (e.g. username) | `SignedClaim::decode` |
| `revocation` | account-signed device revocation | `Revocation::decode` |
| `presentation` | a peer's self-introduction | `talkrypt_core::Presentation::decode` |
| `ratchet_header` | per-message DR header, all 3 KEM profiles | `ratchet::fuzz_header_roundtrip` |
| `beacon_body` | always-encrypted scheme beacon | `beacon::fuzz_beacon_roundtrip` |
| `suite_scheme` | scheme fingerprint + registry match | `scheme_hash` / `get_by_scheme_hash` |

The two crate-private codecs (`ratchet::Header`, `beacon::BeaconBody`) are
reached through thin wrappers exposed only under `talkrypt-crypto`'s `fuzzing`
feature, so nothing extra ships in a normal build.

## Running

Requires a nightly toolchain and `cargo install cargo-fuzz`.

```sh
cargo +nightly fuzz list                       # show targets
cargo +nightly fuzz build                      # build all (ASan + libFuzzer)
cargo +nightly fuzz run ratchet_header         # fuzz one, indefinitely
cargo +nightly fuzz run ratchet_header -- -max_total_time=60   # bounded
```

A crash is written to `artifacts/<target>/crash-*`; replay it with
`cargo +nightly fuzz run <target> artifacts/<target>/crash-*`, and minimize with
`cargo +nightly fuzz tmin <target> <artifact>`.

## Regression corpus

Inputs that once crashed are kept under `corpus/<target>/` as permanent seeds so
every future run re-exercises them. Current entries:

- `corpus/ratchet_header/regression-short-x25519-field` — the input that found
  **F-14** (a too-short X25519/pad field panicked the receiver via an
  out-of-range slice index in `hybrid.rs::to_32`). Fixed by the fallible
  `try_to_32`; regression-tested in `hybrid.rs`.
