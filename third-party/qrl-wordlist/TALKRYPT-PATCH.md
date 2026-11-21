# Vendored QRL mnemonic wordlist

`wordlist.txt` is the Quantum Resistant Ledger (QRL) 4096-word mnemonic list,
extracted verbatim from **theQRL/qrllib** (`src/qrl/wordlist.cpp`, the canonical
`std::array<std::string, 4096>`). 4096 words = 12 bits per word.

**Why vendored here (a data file, not a crate):** `talkrypt-keyvault` /
`talkrypt-relsign` encode signing-seed backups as QRL-2.0-style mnemonics so an
operator can transcribe a key to paper/metal and so the phrase is recognizable to
anyone familiar with the QRL ecosystem. We embed the list with `include_str!` for a
hermetic build (no network, reproducible) rather than depend on a QRL crate.

**Provenance / license:** sourced from theQRL/qrllib (QRL project, released under
the MIT License). The list is plain lowercase-ASCII English words; it carries no
code. We redistribute the word data unmodified. If exact QRL interop is ever
dropped, this file can be swapped for an independently-generated 4096-word list of
the same shape (see `docs/plans/0004-keyvault.md`).

Integrity: 4096 unique lowercase-ASCII words, one per line, first `aback`, last
`zurich`.
