# Getting Started

A five-minute tour. Full command detail: [CLI Reference](CLI-Reference.md).
Onboarding extras (mobile, QR, P2P sharing): `docs/onboarding.md`.

## Install

- **From source** (works everywhere): `cargo build --release -p talkrypt-cli`,
  then run `target/release/talkrypt`.
- **Prebuilt packages**: download a [release artifact](Packaging-and-Release.md)
  for your platform, then **verify it** before use:
  ```sh
  bash verify.sh            # checks SHA-256 AND SHA3-256 (macOS/Linux/WSL)
  pwsh ./verify.ps1         # same, on Windows / cross-platform
  ```
  - macOS: open the `.dmg`, drag `talkrypt.app` to Applications (ad-hoc signed —
    right-click → Open the first time).
  - Debian/Ubuntu: `sudo apt install ./talkrypt_<v>_<arch>.deb` (or the
    `talkrypt-static` build).
  - Windows: unzip and run `talkrypt.exe` from a terminal.
  - Android: `adb install -r talkrypt-<v>-android-arm64.apk`, or sideload it.

## Try it offline

```sh
talkrypt demo        # a two-party PQ conversation, in-process, no network
```

## Host a chat and invite someone

```sh
talkrypt host --channel '#general'
```

This prints a `talkrypt://…` invite (and a QR). Share it out of band. Your peer:

```sh
talkrypt join 'talkrypt://…'
```

Type a line and press enter to send it. Type `/help` for the in-chat commands.

**Confirm there's no MITM:** both sides run `/verify` and compare the **safety
number** out of band (read it aloud, or scan). Matching numbers ⇒ no
person-in-the-middle. See [Identity & Accounts](Identity-and-Accounts.md).

## Over Tor

Build with the `tor` feature, then add `--tor` to `host`/`join`. The host becomes
a Tor **onion service** with restricted discovery (only invite-holders can
reach it); the joiner needs `--tor` to dial the `.onion`. See
[Messaging & Transport](Messaging-and-Transport.md).

## Use an account identity

```sh
talkrypt host --account ~/.talkrypt/account.key --username alice
```

Now peers can recognize you across chats and devices. Add a second device with
`talkrypt link-offer` / `link-accept`, stay anonymous with `/pseudonym`, or
publish your name on a [registry](Identity-and-Accounts.md) with `/register`.

## Next

- [Cryptography](Cryptography.md) — what's protecting your messages.
- [Key Custody](Key-Custody.md) — how your keys are stored.
- [Security Assurance](Security-Assurance.md) — what's tested, and what isn't.
- ⚠️ talkrypt is **experimental, pre-release, unaudited** software — see the
  [honesty posture](Classification-and-Compliance.md).
