# 0004 — `talkrypt-keyvault`: an agent-isolated signing microapp

**Status:** in progress. **Supersedes** the plaintext `.release-keys/*.seed` custody
from [0003](0003-release-cosigning.md) with passphrase-sealed seeds unsealed only
inside a hardened, isolated process.

## Why

The release signing seed is a long-lived offline root secret. Two gaps in 0003:

1. **At rest it was plaintext** (`.release-keys/ml-dsa.seed`). Anyone who reads the
   file has the release identity.
2. **Interactive use would leak through the operator's terminal.** If a script
   prompts for a passphrase in a terminal that another party (an automation agent,
   a screen recorder, a `script(1)` log) observes, the passphrase and the
   Argon2id-derived key are exposed the moment they are typed.

Gap 2 is the sharp one: on this project the build scripts are frequently driven by
an **automation agent that can read everything in the terminal it controls**. So
the secret path must leave that terminal entirely.

## Threat model

Trusted: the operator's **physical I/O** (keyboard, screen, mouse) when not being
recorded, and the **keyvault process's own address space** while it runs.

Untrusted: **everything else on the machine**, explicitly including
- the automation agent and anything it can see (its controlled TTY, piped
  stdin/stdout, env it sets, files it reads);
- other non-root local userspace processes (snooping RAM, swap, core dumps,
  `ptrace`, `/proc`).

**Out of scope** (documented, not defended): root / kernel implants, hardware
keyloggers, a compromised display server capturing the window, side channels
below the process boundary. This matches the operator's stated model ("treat the
machine as untrusted *except* that my physical I/O is not being recorded"). No
certification is claimed; this is honest-scope hardening, not an evaluated
boundary.

## Design

One **vault engine** (library) behind two **front-ends**, so the secret-handling
code is written and verified once:

```
                 talkrypt-relsign (lib)            reused app crypto
                 ┌───────────────────────┐         crypto::aead  (AES-256-GCM)
   seal/unseal ──┤ Argon2id + AES-256-GCM │ ───────  crypto::kdf   (mac_kdf)
   sign/verify ──┤ ML-DSA-87 + SLH-DSA    │ ───────  IdentityKeyPair, fips205
                 └───────────┬───────────┘          crypto::mem   (harden/mlock)
                             │
        ┌────────────────────┴────────────────────┐
        ▼                                          ▼
  keyvault GUI (eframe popup)            keyvault TUI (reads /dev/tty)
  launched BY the scripts;               operator launches in their OWN
  passphrase via the window's            terminal; passphrase via /dev/tty,
  own input, not my stdin.               never the agent-driven stdin.
        └───────── public outputs only ───────────┘
                 dist/SHA384SUMS.sig, .slh.sig, RELEASE_PUBKEY*.hex
```

The agent (or any script) only ever provides the **public** `SHA384SUMS` and reads
back the **public** signatures + pubkeys. The passphrase, the Argon2id output, and
the raw seed never touch a file or any fd outside the vault, and are zeroized on
every exit path.

### Sealed-seed format (`.seed.enc`)

Reuses the project's `TKS1` construction (see `core/src/seal.rs`): Argon2id over a
random 16-byte salt → 32-byte key; AES-256-GCM over a random 12-byte nonce; the
full header (magic, version, KDF params, salt, nonce, signing algo, **public
key**) bound as AEAD AAD so nothing can be altered or stripped. The public key is
stored in the cleartext header so `pubkey`/verify setup needs **no** passphrase.
Argon2id work factor is raised for a high-value offline key (m=256 MiB, t=3, p=1,
stored in the header for forward-compat) — stronger than the per-message m=19 MiB.

### Hardening (vault process)

`mlock` the seed/key pages (no swap) · `setrlimit(RLIMIT_CORE,0)` +
`prctl(PR_SET_DUMPABLE,0)` / `PT_DENY_ATTACH` (no core dump, anti-`ptrace`) · refuse
to start if already traced (`TracerPid`) · `zeroize` on every drop and error path ·
constant-time tag/compare on the auth path · no logging, no clipboard, no echo ·
reuse `crypto::mem::{harden_process, deny_debugger, LockedBox}`.

## Formal-verification obligations

1. `unseal(seal(seed, pw)) == seed` for all seeds/passphrases (round-trip).
2. Wrong passphrase / tampered header or ciphertext ⇒ `Err`, **never** a partial or
   wrong seed (fail-closed) — decoder is total on arbitrary bytes (Kani, like the
   wire decoders).
3. The seed buffer is zeroized on **all** control-flow paths (success, every error,
   panic-unwind via `Drop`).
4. No secret-bearing buffer is passed to any writer except the AEAD sealer.
5. Constant-time on the tag-comparison path (inherited from the AEAD backend).

## Deliverables / sequencing

- **A.** ✅ **DONE (#129).** `relsign` → lib+bin; sealed-seed `seal/unseal` +
  `sign/pubkey/verify` + the KDF seam (Argon2id/PBKDF2) + QRL-2.0 seeds; unit tests
  (round-trip, fail-closed, no-plaintext-in-blob, the KDF×algo matrix).
- **D.** ✅ **DONE (#128).** FV: formal spec (`docs/FORMAL-SEAL.md`) + Kani proofs
  (`read_kdf`/`header_parse_model` totality + KDF-codec roundtrip) + type-enforced
  `Zeroizing` (P7) + the core at-rest KDF seam; `formal.yml` wired. (FV before the
  front-ends, per the sequencing decision.)
- **B.** ✅ **DONE.** `talkrypt-keyvault` crate: hardened core (`crypto::mem`
  no-core-dump / non-dumpable / anti-ptrace, `Zeroizing` secrets) + **TUI** `/dev/tty`
  front-end (keygen + sign) — the max-isolation path. Verified: an agent with no
  controlling terminal is refused (no leak); a human at a real terminal gets the full
  keygen→sign→verify, the mnemonic shown only on screen (pty-driven test).
- **C.** ✅ **DONE.** **GUI** eframe popup front-end (feature `gui`, default) over the
  same engine — keygen + sign; the passphrase is typed into the window and the
  mnemonic shown in the window, so a terminal-scraping agent sees nothing. Builds with
  `--no-default-features` as a lean TUI-only signer (no windowing deps) for headless
  release hosts.
- **E.** ✅ **DONE (#131).** `release-keygen-build-sign.sh` mints SEALED keys via the
  vault; `release-build-sign.sh` co-signs `SHA384SUMS` through the vault (terminal
  passphrase, no env secret); legacy plaintext seeds still work. Verified end-to-end.

NOT FIPS-validated · NOT CSfC-accredited · NOT NSA-approved · NOT audited.
