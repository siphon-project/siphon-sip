# SIPhon container image WITH opt-in extension modules (SMPP, HTTP).
#
# This builds the `siphon-bin` package — a drop-in `siphon` binary that composes
# optional extension crates behind cargo features — with `--features smpp` by
# default. It is SEPARATE from the root Dockerfile (which builds the plain
# siphon-sip binary): siphon-bin git-deps the published siphon-sip lib + the
# extension crates, so the build context is just this package directory (no root
# tree needed).
#
# Build (context = this directory):
#   docker build -f siphon-bin/Dockerfile -t siphon-smpp siphon-bin/
#
# Override the enabled modules with the FEATURES build-arg, e.g. HTTP only, or
# every module at once via the `full` aggregate:
#   docker build -f siphon-bin/Dockerfile --build-arg FEATURES=http -t siphon-http siphon-bin/
#   docker build -f siphon-bin/Dockerfile --build-arg FEATURES=full -t siphon-ext  siphon-bin/
#
# The image bakes NO default script/config (the SMPP handler lives in your
# script, e.g. siphon-smpp's examples/echo.py). Mount siphon.yaml + smpp.yaml +
# your script at runtime.

# ── Builder ──────────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS builder

ARG FEATURES=smpp

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
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
RUN cargo build --release --features "${FEATURES}"

# ── Runtime ──────────────────────────────────────────────────────────────────
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
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

# SIP (5060/udp+tcp, 5061/tls) + SMPP (2775/tcp, the smpp.yaml default).
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 5061/tcp
EXPOSE 2775/tcp

WORKDIR /etc/siphon

# Mount siphon.yaml (with an `extensions.smpp` pointer), smpp.yaml, and your
# script. Run with host networking in production to avoid SIP NAT issues.
ENTRYPOINT ["/usr/local/bin/siphon"]
CMD ["--config", "/etc/siphon/siphon.yaml"]
