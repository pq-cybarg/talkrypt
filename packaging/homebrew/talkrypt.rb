# Homebrew formula for the talkrypt CLI/TUI (and key-custody helper).
#
# This is a from-source formula: it compiles the pure-Rust workspace with the
# system Rust toolchain, so there are no prebuilt-binary trust concerns and no C
# dependencies to vendor. Ship it via a tap:
#
#   brew tap <you>/talkrypt && brew install talkrypt
#
# PLACEHOLDERS to fill at release time (kept empty here because this project is
# distributed opsec-clean, with no canonical public URL baked into the source):
#   - url:    the release source tarball (e.g. a tagged archive)
#   - sha256: `shasum -a 256` of that tarball
# Until those are set, install from a local checkout with:
#   brew install --build-from-source ./packaging/homebrew/talkrypt.rb
# or just `cargo build --release` and use scripts/package.sh.
class Talkrypt < Formula
  desc "Post-quantum end-to-end encrypted chat (CLI/TUI) over Tor"
  homepage ""               # set to the canonical project URL at release
  license "Apache-2.0"
  version "0.1.0"

  url ""                    # release source tarball URL (placeholder)
  sha256 ""                 # tarball sha256 (placeholder)

  depends_on "rust" => :build

  def install
    # The CLI is the primary product; the TUI and helper ship alongside it.
    system "cargo", "install", "--locked", "--path", "crates/cli", "--root", prefix
    system "cargo", "install", "--locked", "--path", "crates/tui", "--root", prefix
    system "cargo", "install", "--locked", "--path", "crates/helper", "--root", prefix
  end

  def caveats
    <<~EOS
      talkrypt is experimental, pre-release software.
      It is NOT FIPS-validated, NOT CSfC-accredited, NOT NSA-approved, and NOT
      independently audited. Do not use it to protect real classified,
      national-security, or life-safety information.

      Quick start:
        talkrypt host           # create a chat, print a talkrypt:// invite + QR
        talkrypt join <uri>     # join from an invite
        talkrypt --help         # all commands and flags
    EOS
  end

  test do
    # The version banner prints the algorithm suite and the honesty disclaimer.
    assert_match "ML-KEM-1024", shell_output("#{bin}/talkrypt version")
  end
end
