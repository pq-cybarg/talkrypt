# CLI Reference

The shipped client is the **`talkrypt`** CLI (and the [`talkrypt-tui`](Platforms-and-Clients.md)
terminal UI). Run `talkrypt --help` for the live list; this page documents every
subcommand and the in-chat `/commands`. Source: `crates/cli/src/main.rs`.

## Subcommands

| Command | Purpose |
| --- | --- |
| `talkrypt demo` | A two-party PQ conversation in-process — no network. Proof of concept. |
| `talkrypt host` | Create a chat, print a `talkrypt://` invite + QR, enter the chat REPL. |
| `talkrypt join <uri>` | Join a chat from an invite, enter the REPL. |
| `talkrypt link-offer` | Offer to link a new device to your account (you hold the account key). |
| `talkrypt link-accept <uri>` | Accept a link offer on a new device; save the account→device chain. |
| `talkrypt registry` | Host a username directory (maps `username → account key`). |
| `talkrypt version` | Build banner + honesty disclaimer. |
| `talkrypt csfc` | Print the [CSfC](Classification-and-Compliance.md) architectural preflight checklist. |

### `talkrypt host`

Create a chat and host it. Key flags:

- `--listen HOST:PORT` — bind address (default `127.0.0.1:9000`).
- `--endpoint ADDR` — the address advertised in the invite (when it differs from `--listen`).
- `--channel #name` — initial channel.
- `--topology p2p|hub|hybrid` — see [topologies](Messaging-and-Transport.md).
- `--group` — found a [TreeKEM](Messaging-and-Transport.md) group (this node coordinates).
- `--posture pq-pure|hybrid|pq-pure-compact` — [KEM posture](Cryptography.md); `--require-posture` forces peers to match.
- `--advertise off|fingerprint|full` — sealed [scheme beacon](Cryptography.md) granularity (default off).
- `--password PASS` — an out-of-band [channel password](Messaging-and-Transport.md) (Argon2id-mixed into the root; never in the invite).
- `--account PATH` / `--username NAME` — present an [account identity](Identity-and-Accounts.md).
- `--device PATH` / `--chain PATH` — present a linked device + its account chain.
- `--require-registry URI` — only accounts registered on this [registry](Identity-and-Accounts.md) may join.
- `--classification LEVEL` / `--caveat …` / `--compartment …` — [markings](Classification-and-Compliance.md) (needs the `markings` build feature).
- `--tor` — host as a [Tor onion service](Messaging-and-Transport.md) (needs the `tor` build).

### `talkrypt join <uri>`

Join from a `talkrypt://` invite. Flags: `--group`, `--account PATH`,
`--username NAME`, `--device PATH`, `--chain PATH`, `--password PASS`, `--tor`
(required to dial a `.onion`).

### `talkrypt link-offer` / `link-accept`

[Device linking](Identity-and-Accounts.md): the primary (account-holding) device
runs `link-offer --account PATH` and shows a one-time URI/QR; the new device runs
`link-accept <uri> --device PATH --chain-out PATH`. The account key never leaves
the primary — only a signed device certificate is sent.

### `talkrypt registry`

Host a username [directory](Identity-and-Accounts.md): `--listen HOST:PORT`,
`--channel #name`, `--tor`. Clients `/register` and `/resolve` against it, and can
cross-compare multiple registries to detect equivocation.

## In-chat `/commands`

Inside a `host`/`join` session (type a bare line to send it to the focused channel):

```
/help                          show this help
/whoami                        show your device + account identity
/verify                        show safety numbers (compare out of band)
/invite                        print this chat's invite URI
/peers                         connected peer count

account:
/account new [path]            generate an account, link this session, save seed
/account load <path>           load an account seed and link this session
/account save [path]           save the current account seed
/username <name>               set the advertised username (re-presents)
/pseudonym                     drop the account (become unlinkable)

contacts (recognition — unilateral, NOT access):
/contact add <fp> [name]       recognize a just-seen account (by fp prefix)
/contacts                      list contacts
/friend <fp>                   label a contact a friend  (/unfriend to clear)
/revoke <device-fp>            (account holder) revoke + broadcast a lost device

access (a SEPARATE grant — no contact/friend/mutual needed):
/access open|contacts|friends  set who may join this channel
/allow <fp>                    admit one specific account
/deny <fp>                     revoke an account's access

registry (username discovery):
/register <registry-uri>       publish username->account to a registry
/resolve <name> <uri>[ <uri>…] [add]   cross-compare a name; `add` saves it as a contact
/quit                          leave
```

**Recognition vs. access are deliberately separate.** Marking someone a contact
or friend (`/friend`) is *your* unilateral view; it never grants them access.
Channel admission is the `/access` / `/allow` / `/deny` grant. See
[Identity & Accounts](Identity-and-Accounts.md).

## TUI

`talkrypt-tui host --listen … [--topology …] [--channel …] [--posture …]` and
`talkrypt-tui join <uri>` open a [ratatui](https://github.com/ratatui-org/ratatui)
interface (channel list, message view, input, status bar). Source:
`crates/tui/src/main.rs`.
