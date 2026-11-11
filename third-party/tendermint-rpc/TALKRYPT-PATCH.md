# Vendored, patched `tendermint-rpc` 0.40.4 — reqwest 0.11 → 0.13

This is a **local, source-patched copy of `tendermint-rpc` 0.40.4**, applied to the
talkrypt workspace via `[patch.crates-io]` in the root `Cargo.toml`. Because it is a
`[patch]`, the change is applied automatically to **every build and `cargo install`**
of this workspace — there is no separate step to forget.

## Why it exists

`tendermint-rpc` is pulled in transitively, **only** under the `nym` feature, by
Nym's cosmos / zk-nym bandwidth-credential path:

```
nym-sdk → nym-client-core → nym-bandwidth-fetcher → nym-credentials
        → nym-api-requests → cosmrs 0.22 → tendermint-rpc 0.40.4
```

(`nym-api-requests` and `nym-validator-client` also depend on `tendermint-rpc`
0.40.4 **directly**, so the patch — being on the crates.io name — covers every
path at once.)

Upstream `tendermint-rpc` 0.40.4 declares its optional HTTP-client dependency as
**`reqwest = "0.11.20"`**. reqwest 0.11 drags in a stack of crates that now carry
RustSec advisories:

| Crate (via reqwest 0.11) | Advisory |
| --- | --- |
| `rustls 0.21.12` | RUSTSEC-2026-0346 (`Debug` leaks TLS secrets), RUSTSEC-2026-0349 (ServerHello downgrade) |
| `rustls-webpki 0.101.7` | RUSTSEC-2026-0098, -0099, -0104 (name-constraint / CRL parsing), -0382 (distrusted intermediates) |
| `h2 0.3.27` | RUSTSEC-2026-0258 (unbounded empty DATA frames) |

None of these is on talkrypt's load-bearing crypto path — the content layer is
ML-KEM-1024 + ML-DSA-87 via RustCrypto, riding **above** the transport, and the
affected crates are **absent from both the default and the `tor` build**. They are
reached only as an HTTP **client** talking to a Nym API / Cosmos RPC endpoint when
the `nym` transport is enabled. Still: honest-scope means we fix what we can, and
these are fixable without losing any feature.

## The change

The **only** change versus upstream 0.40.4 is in `Cargo.toml`:

```diff
 [dependencies.reqwest]
-version = "0.11.20"
-features = ["rustls-tls-native-roots"]
+version = "0.13"
+features = ["rustls"]
 optional = true
 default-features = false
```

reqwest 0.13 rides the **modern TLS stack already present in this workspace** —
`rustls 0.23`, `rustls-webpki 0.103`, `h2 0.4` — none of which carries these
advisories. Its `rustls` feature is the drop-in successor to 0.11's
`rustls-tls-native-roots`: it selects the aws-lc-rs crypto provider plus
`rustls-platform-verifier` (the modern replacement for `rustls-native-certs`),
which is **exactly what Nym's own `reqwest 0.13.4` already uses** for its other
HTTP clients. So rather than adding a second reqwest major, this **unifies** the
tree onto one reqwest — the entire reqwest-0.11 subtree (reqwest 0.11.27, rustls
0.21.12, rustls-webpki 0.101.7, h2 0.3.27, hyper 0.14, tokio-rustls 0.24,
rustls-pemfile 1.0, sct, the old `windows-sys 0.48` fan-out, …) disappears from the
lockfile.

**No source change was required.** The 14 `reqwest::` call-sites in
`src/client/transport/http.rs` + `src/error.rs` use only API that is stable across
reqwest 0.11 → 0.13 (`ClientBuilder::new().user_agent().timeout().proxy().build()`,
`Proxy::https/http`, `Url`, `Client`, `Request`, `StatusCode`, `header`,
`reqwest::Error`). The crate compiles verbatim against reqwest 0.13.

## Why not just bump upstream / nym

`tendermint-rpc` has **no reqwest-0.12/0.13 release** (0.40.4 is current and still
on reqwest 0.11), and Nym's `develop` branch still pins `cosmrs 0.22` →
`tendermint-rpc 0.40.4` (its workspace `Cargo.toml` comment even acknowledges the
old TLS drag). So there is nothing newer to move to; we patch locally **until
upstream moves**, at which point this vendored copy should be dropped and the
advisory re-checked.

## Residual

This patch does **not** clear `crypto-bigint 0.5.5` (RUSTSEC-2026-0387,
constant-time variability). That crate comes from `cosmrs 0.22 → ecdsa 0.16 →
elliptic-curve 0.13`, whose `^0.5` requirement no released `elliptic-curve` has yet
moved off (the fix is only in crypto-bigint `>= 0.7.6`). It is on the
cosmos-transaction **signing** path (only exercised by `NymTransport::connect_paid`,
which signs with a wallet mnemonic to mint a zk-nym credential), not the mixnet
content path. Tracked separately; see `deny.toml`.

## Re-vendoring / updating

The copy is verbatim `tendermint-rpc` 0.40.4 from crates.io with only the
`Cargo.toml` reqwest dep edited (marked with a `TALKRYPT PATCH` comment). To refresh
for a new upstream version: re-copy the crate, re-apply the one-line reqwest bump,
rebuild `--features nym`, and re-run `scripts/audit-deps.sh`.
