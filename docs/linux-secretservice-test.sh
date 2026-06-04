#!/usr/bin/env bash
# Faithfully test the Linux Secret Service custody tier in a container with a
# real gnome-keyring daemon on a session D-Bus. Run from the repo root:
#
#   docker run --rm -v "$PWD:/work" -w /work \
#     -e CARGO_TARGET_DIR=/cargo-target rust:1-bookworm \
#     bash docs/linux-secretservice-test.sh
#
# CARGO_TARGET_DIR is set OFF the mounted tree so the Linux build artifacts do
# NOT collide with the host's (macOS) target/.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq gnome-keyring dbus libdbus-1-3 >/dev/null

# A session bus + an unlocked secrets keyring (empty password), then the test.
exec dbus-run-session -- bash -c '
  set -e
  eval "$(printf "\n" | gnome-keyring-daemon --unlock --components=secrets)"
  export GNOME_KEYRING_CONTROL SSH_AUTH_SOCK
  cargo test -p talkrypt-helper --test secretservice -- --nocapture
'
