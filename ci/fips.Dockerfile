# FIPS-hardened Node.js for the `compliance` CI job — built only from FREE,
# openly available pieces (no Chainguard/RHEL subscription):
#
#   * stock Node 20 (bundles OpenSSL 3.0.19, dynamically loadable providers), and
#   * the OpenSSL **FIPS provider** built from the SAME 3.0.19 source — the FIPS
#     module of the validated OpenSSL 3.0 family (CMVP cert #4282 lineage) —
#     activated via openssl.cnf so Node's `crypto` / `crypto.subtle` (Web Crypto)
#     run through the FIPS module.
#
# Building the provider from the exact version Node bundles keeps the module and
# Node's libcrypto ABI/version matched, so `crypto.getFips() === 1` and a
# non-approved primitive (MD5) is refused. Verified by ci/fips-subtle-check.mjs.
FROM node:20-bookworm-slim

ARG OPENSSL_VERSION=3.0.19
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential perl curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Build + install ONLY the FIPS provider (make install_fips runs `fipsinstall`,
# which self-tests the module and writes fipsmodule.cnf with its MAC).
RUN set -eux; \
    curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" -o /tmp/o.tgz; \
    mkdir -p /tmp/o; tar -xzf /tmp/o.tgz -C /tmp/o --strip-components=1; \
    cd /tmp/o; \
    ./Configure enable-fips --prefix=/opt/ssl --openssldir=/opt/ssl/ssl; \
    make -j"$(nproc)"; \
    make install_sw install_fips; \
    find /opt/ssl -name fips.so; \
    rm -rf /tmp/o /tmp/o.tgz

# openssl.cnf: load the FIPS + base providers and make fips the default for all
# algorithm fetches (so Node's crypto uses the FIPS module).
RUN MODDIR="$(dirname "$(find /opt/ssl -name fips.so | head -1)")"; \
    { \
      echo 'config_diagnostics = 1'; \
      echo 'openssl_conf = openssl_init'; \
      echo '.include /opt/ssl/ssl/fipsmodule.cnf'; \
      echo '[openssl_init]'; \
      echo 'providers = provider_sect'; \
      echo 'alg_section = algorithm_sect'; \
      echo '[provider_sect]'; \
      echo 'fips = fips_sect'; \
      echo 'base = base_sect'; \
      echo '[base_sect]'; \
      echo 'activate = 1'; \
      echo '[algorithm_sect]'; \
      echo 'default_properties = fips=yes'; \
    } > /opt/ssl/openssl.cnf; \
    echo "MODDIR=$MODDIR" > /opt/ssl/moddir.env

# Point Node's OpenSSL at the FIPS config + provider module directory.
ENV OPENSSL_CONF=/opt/ssl/openssl.cnf
ENV OPENSSL_MODULES=/opt/ssl/lib/ossl-modules
WORKDIR /work
