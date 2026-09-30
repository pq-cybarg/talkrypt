# FV sandbox — hardened, ephemeral container for third-party verification tools

Formal-verification tools that reach where Kani/CBMC cannot (Verus, Prusti, Creusot,
Aeneas) are large third-party builds. A supply-chain audit found their hygiene is
**very uneven** — e.g. Prusti's build tree carries 25 CVEs including a `libgit2-sys`
**arbitrary-code-execution** advisory (see `docs/fv-heap-decoder-spike.md`). Running
those on an opsec-sensitive host is unacceptable. This sandbox contains them: a
**one-time, throwaway, airgapped, capability-stripped** container so even a malicious
build script executes in an ephemeral jail, never on the host, never touching
talkrypt's source or dependency graph.

## What it proves (verified)

Runs **Verus** on a representative nested-heap decoder (the `Vec<Struct{String,Vec}>`
return shape that made Kani/CBMC blow up to ~34M clauses):

```
$ ./hardened-run.sh
verification results:: 4 verified, 0 errors      # inside the hardened container
```

That is **totality** (no panic / overflow / OOB, for all inputs) — the exact
obligation Kani could not discharge — proven reproducibly, in isolation.

## Hardening posture (NIST SP 800-190 / CIS Docker Benchmark aligned)

Build phase (`Dockerfile`) — the only phase with network:
- minimal base **pinned by digest** (not a mutable tag); non-root user (UID 10001,
  `/usr/sbin/nologin`); pinned tool versions; `curl --retry`; apt caches purged.
- the file to verify is **COPIED in** at build time (no host bind mount at run time).

Run phase (`hardened-run.sh`) — zero privilege, zero network:
- `--rm` (ephemeral; the writable layer is destroyed) · `--network=none` (airgapped)
- `--cap-drop=ALL` · `--security-opt=no-new-privileges` · default seccomp filter
- `--read-only` rootfs · writable areas only as size-capped `--tmpfs` (RAM, `noexec,nosuid`)
- `--user 10001` (non-root) · `--memory` / `--pids-limit` / `--cpus` (anti-DoS / fork-bomb)
- no host mounts, no secrets, no env injection.

## Repeatable / one-time / throwaway

`./hardened-run.sh` builds once (cached thereafter) and runs a fresh `--rm` container
each time — nothing persists between runs. To verify a different harness, bake it into
the image (`COPY`) and pass its path: `./hardened-run.sh /home/fv/other.rs`.

## Extending to the CVE-carrying tools (Creusot / Prusti / Aeneas)

This is exactly what the sandbox is for. Add the tool's install to the `Dockerfile`
build phase (network available there); its CVE-laden dependency build then runs **inside
the container**, isolated. Vet each with `cargo audit` first (Creusot came back clean;
Charon/Prusti did not) and prefer official prebuilt binaries where they exist. The
`--platform=linux/amd64` line is only needed for Verus's x86-only binary; native-arm64
tools can drop it. **Requires a `trixie`-or-newer base** (Verus needs glibc ≥ 2.39).
