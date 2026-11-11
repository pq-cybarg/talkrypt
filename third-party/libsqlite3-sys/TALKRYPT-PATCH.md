# Vendored, patched `libsqlite3-sys` 0.37.0 — bundled SQLite 3.51.3 → 3.54.1

Local, source-patched copy of `libsqlite3-sys` 0.37.0, applied via `[patch.crates-io]`.
In the graph under the **`tor`** feature (Arti's `tor-dirmgr` → `rusqlite` → bundled
SQLite, for the on-disk directory cache) and the **`nym`** feature (nym's
`sqlx-sqlite`). Because `libsqlite3-sys` declares `links = "sqlite3"`, the whole
workspace shares exactly ONE copy — this one.

## Why

`libsqlite3-sys` bundles the SQLite C amalgamation when built with `bundled`
(which both `rusqlite` and `sqlx-sqlite` enable). Version 0.37.0 bundles **SQLite
3.51.3**, which is affected by **RUSTSEC-2026-0459 / CVE-2026-119375**: SQLite before
3.54.0 can return uninitialized page-cache memory when a database file is opened
together with a sibling write-ahead-log (`-wal`) whose page size differs from the
database's — a crafted pair can make ordinary queries return stale process memory.

The fix is SQLite ≥ 3.54.0, which `libsqlite3-sys` first bundled in **0.39.0** (ships
with `rusqlite` 0.41). But **no released Arti accepts it**: `tor-dirmgr` (through 0.48)
caps `rusqlite < 0.41`, and nym's `sqlx-sqlite` 0.9.0 caps `libsqlite3-sys < 0.38` —
and `links = "sqlite3"` forbids two versions coexisting. A clean version bump would
require vendoring the entire Arti + sqlx SQLite stack.

## The change

Keep the crate **version 0.37.0** (so Arti's `rusqlite ^0.37` AND nym's `sqlx-sqlite`
range both resolve against the single shared copy) and swap only the bundled SQLite:

- `sqlite3/sqlite3.c`, `sqlite3/sqlite3.h`, `sqlite3/sqlite3ext.h` — replaced
  **verbatim** with the SQLite **3.54.1** amalgamation (lifted from `libsqlite3-sys`
  0.39.1, the upstream crate that bundles the patched SQLite).
- `sqlite3/bindgen_bundled_version.rs` + `..._ext.rs` — the five version constants
  (`SQLITE_VERSION`, `SQLITE_VERSION_NUMBER`, `SQLITE_SOURCE_ID`, `SQLITE_SCM_BRANCH`,
  `SQLITE_SCM_TAGS`) updated 3.51.3 → 3.54.1. The FFI *declarations* are left at
  0.37.0's — SQLite never removes or changes existing C symbols, so those declarations
  are a strict subset of the 3.54.1 C API and link unchanged (rusqlite/sqlx only call
  long-stable functions).

Net effect: the actually-compiled SQLite is now **3.54.1**, so the vulnerability is
eliminated at the source. Because advisory tooling matches by crate **version**
(0.37.0 is still in the affected range 0.6.0–0.38.2), the advisory is **documented**
in `deny.toml` + `scripts/audit-deps.sh` as FIXED-LOCALLY (the same pattern as the
vendored `rsa` Marvin mitigation) — recorded, not silently ignored.

## Re-vendoring

Drop this the moment Arti bumps `rusqlite` to 0.41 (libsqlite3-sys 0.39) AND nym's
`sqlx-sqlite` accepts it — then a plain version bump supersedes the amalgamation swap.
To refresh the bundled SQLite: copy `sqlite3.{c,h}` + `sqlite3ext.h` from a newer
`libsqlite3-sys`, update the five version constants, rebuild `--features tor` (and
`nym`), and re-run `scripts/audit-deps.sh`.
