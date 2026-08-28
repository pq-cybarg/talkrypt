# Hardened, ephemeral FV sandbox for running third-party formal-verification tools
# (some of which carry CVEs in their build trees — e.g. Prusti's libgit2-sys ACE) in
# ISOLATION from the host. Build phase (this file) has network to fetch pinned tools;
# the RUN phase is airgapped + capability-stripped (see hardened-run.sh).
#
# Hardening posture (NIST SP 800-190 / CIS Docker Benchmark aligned):
#   - minimal base, pinned by DIGEST (not a mutable tag)
#   - non-root user (high UID), no shell login, no sudo
#   - all fetches in the build layer; run phase is --network=none
#   - no host secrets, no host bind mounts at run time (the file to verify is COPIED in)
#   - run phase drops ALL capabilities + no-new-privileges + read-only rootfs + tmpfs
#
# Target: linux/amd64 (Verus ships an x86-linux binary only). On arm64 hosts this runs
# under emulation — verification is seconds, so emulation cost is acceptable.

# debian:trixie-slim (pin the digest for your platform before use; the tag is a
# convenience default). Reproduce with: docker buildx imagetools inspect debian:bookworm-slim
FROM --platform=linux/amd64 debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

# Pinned tool versions (single source of truth).
ARG VERUS_VER=0.2026.08.23.fbbbbcf
ARG RUST_TOOLCHAIN=1.97.1

# Minimal build deps; clean apt caches in the same layer.
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl unzip gcc libc6-dev; \
    rm -rf /var/lib/apt/lists/*

# Non-root user (high UID, no login shell, no home writes needed at run time).
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin fv
USER fv
WORKDIR /home/fv
ENV PATH=/home/fv/.cargo/bin:/home/fv/verus:$PATH \
    RUSTUP_HOME=/home/fv/.rustup \
    CARGO_HOME=/home/fv/.cargo

# rustup + Verus's build-matched toolchain (minimal + the components Verus links).
RUN set -eux; \
    curl -fsSL --retry 6 --retry-delay 4 --retry-all-errors https://sh.rustup.rs -o /tmp/rustup.sh; \
    sh /tmp/rustup.sh -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}" \
        -c rust-src -c rustc-dev -c llvm-tools; \
    rm -f /tmp/rustup.sh

# Verus (pinned) — official verus-lang release.
RUN set -eux; \
    curl -fsSL --retry 6 --retry-delay 4 --retry-all-errors -o /tmp/verus.zip \
      "https://github.com/verus-lang/verus/releases/download/release/${VERUS_VER}/verus-${VERUS_VER}-x86-linux.zip"; \
    unzip -q /tmp/verus.zip -d /home/fv; \
    mv /home/fv/verus-x86-linux /home/fv/verus; \
    rm -f /tmp/verus.zip

# The verification target is COPIED in at build time (no host mount at run time).
COPY --chown=fv:fv verus_decode.rs /home/fv/verus_decode.rs

# Default: run the proof. Overridable for other harnesses.
ENTRYPOINT ["/home/fv/verus/verus"]
CMD ["/home/fv/verus_decode.rs"]
