# SIPhon container image WITH opt-in extension modules (SMPP, HTTP, SIGTRAN).
#
# This builds the `siphon-bin` package — a drop-in `siphon` binary that composes
# optional extension crates behind cargo features. It is SEPARATE from the root
# Dockerfile (which builds the plain siphon-sip binary): siphon-bin git-deps the
# published siphon-sip lib + the extension crates, so the build context is just
# this package directory (no root tree needed).
#
# Build (context = this directory). FEATURES defaults to the package's own
# default feature set, so this gets you the `http` namespace:
#   docker build -f siphon-bin/Dockerfile -t siphon-ext siphon-bin/
#
# Add modules with the FEATURES build-arg — they are additive on top of the
# default, so `FEATURES=smpp` gives you http + smpp:
#   docker build -f siphon-bin/Dockerfile --build-arg FEATURES=smpp -t siphon-smpp siphon-bin/
#   docker build -f siphon-bin/Dockerfile --build-arg FEATURES=full -t siphon-all  siphon-bin/
#
# The SIGTRAN module needs kernel SCTP: async-sctp links libsctp (hence
# libsctp-dev in the builder and libsctp1 in the runtime below), and the
# container needs the sctp module loaded on the HOST plus NET_ADMIN-ish
# capabilities to open SCTP sockets — `--sysctl`-free but not namespace-free.
# Run with host networking for SIGTRAN, same as for SIP.
#
# The image bakes NO default script/config (the SMPP handler lives in your
# script, e.g. siphon-smpp's examples/echo.py). Mount siphon.yaml + smpp.yaml +
# your script at runtime.

# ── Builder ──────────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS builder

# Empty = the package default (`http`). Anything here is additive on top of it.
ARG FEATURES=

# libsctp-dev is unconditional: the `sigtran` feature's async-sctp dep links
# libsctp, and a build-arg-conditional apt step would fail only at link time,
# deep into a long build.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
        libsctp-dev \
        xz-utils \
        git \
    && rm -rf /var/lib/apt/lists/*

# uv + free-threaded CPython 3.14t (same interpreter as the plain image, for the
# no-GIL embedded-Python hot path). Wired as the canonical python3 so pyo3's
# build.rs picks it up.
ENV UV_INSTALL_DIR=/usr/local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV UV_PYTHON_INSTALL_DIR=/opt/python
RUN uv python install 3.14t && \
    ln -sfn "$(uv python find 3.14t)" /usr/local/bin/python3.14t && \
    ln -sfn /usr/local/bin/python3.14t /usr/local/bin/python3 && \
    ln -sfn /usr/local/bin/python3.14t /usr/local/bin/python
ENV PYO3_PYTHON=/usr/local/bin/python3.14t

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
# Copy the package (Cargo.lock pins the resolved git SHAs for reproducibility).
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
RUN cargo build --release ${FEATURES:+--features "${FEATURES}"}

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        libsctp1 \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Bring the python-build-standalone interpreter + site-packages over wholesale
# and expose it to the dynamic linker (the binary links libpython).
COPY --from=builder /opt/python /opt/python
RUN PY_BIN=$(find /opt/python -type f -name python3.14t -perm -u+x | head -n1) && \
    PY_PREFIX=$(dirname $(dirname "$PY_BIN")) && \
    ln -sfn "$PY_BIN" /usr/local/bin/python3.14t && \
    ln -sfn "$PY_BIN" /usr/local/bin/python3 && \
    ln -sfn "$PY_BIN" /usr/local/bin/python && \
    echo "$PY_PREFIX/lib" > /etc/ld.so.conf.d/python3.14t.conf && \
    ldconfig

COPY --from=builder /build/target/release/siphon /usr/local/bin/siphon

ENV PYTHON_GIL=0
ENV PYTHONFAULTHANDLER=1

# SIP (5060/udp+tcp, 5061/tls) + SMPP (2775/tcp, the smpp.yaml default) +
# SIGTRAN (2905/sctp, the M3UA well-known port).
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 5061/tcp
EXPOSE 2775/tcp
EXPOSE 2905/sctp

WORKDIR /etc/siphon

# Mount siphon.yaml (with the `extensions.<module>` pointers), the per-module
# configs (smpp.yaml / http.yaml / sigtran.yaml), and your script. Run with host
# networking in production to avoid SIP NAT issues.
ENTRYPOINT ["/usr/local/bin/siphon"]
CMD ["--config", "/etc/siphon/siphon.yaml"]
