# SIPhon container image.
#
# Python: free-threaded CPython 3.14t (PEP 703) installed via uv. Siphon's
# Rust hot loop calls into embedded Python on every SIP request — the
# persistent-attach optimization in src/server.rs (PyGILState_Ensure +
# PyEval_SaveThread per worker) only pays off on no-GIL CPython. With a
# regular GIL'd 3.14 the workload is GIL-limited and the README baseline
# is unreachable. PyO3 0.28 auto-detects Py_GIL_DISABLED — no extra
# feature flags needed.

# ── Chef base ────────────────────────────────────────────────────────────────
FROM debian:trixie-slim AS chef

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        build-essential \
        pkg-config \
        libssl-dev \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*
# NOTE: the default build excludes SIP/Diameter-over-SCTP (the `sctp` Cargo
# feature is off by default), so libsctp-dev is not needed. To build an
# SCTP-capable image, add `libsctp-dev` here, `libsctp1` to the runtime stage,
# and pass `--features sctp` to the `cargo build` below.

# uv: standalone Python installer + project manager. Pulls
# python-build-standalone binaries (no apt python needed).
ENV UV_INSTALL_DIR=/usr/local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# Install free-threaded CPython 3.14t to a known location so the runtime
# stage can copy it deterministically. Wire it as the canonical `python3`
# so pyo3's build.rs picks it up automatically.
ENV UV_PYTHON_INSTALL_DIR=/opt/python
RUN uv python install 3.14t && \
    ln -sfn "$(uv python find 3.14t)" /usr/local/bin/python3.14t && \
    ln -sfn /usr/local/bin/python3.14t /usr/local/bin/python3 && \
    ln -sfn /usr/local/bin/python3.14t /usr/local/bin/python
ENV PYO3_PYTHON=/usr/local/bin/python3.14t

# Runtime python packages that scripts commonly need. Installed into the
# free-threaded interpreter's site-packages so they ride along when the
# runtime stage copies /opt/python.
RUN uv pip install --system --python /usr/local/bin/python3.14t \
        --break-system-packages \
        httpx \
        redis \
        aioboto3 \
        prometheus_client \
        opentelemetry-api \
        opentelemetry-sdk

# Rust toolchain.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

RUN cargo install cargo-chef

WORKDIR /build

# ── Plan dependencies ────────────────────────────────────────────────────────
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
# benches/ holds the criterion [[bench]] targets declared in Cargo.toml; cargo
# validates those files exist (they are explicit targets, unlike auto-discovered
# tests/), so the manifest won't parse without them even though the image never
# runs them.
COPY benches/ benches/
RUN cargo chef prepare --recipe-path recipe.json

# ── Build dependencies (cached until Cargo.toml/lock change) ─────────────────
FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

# Build the real binary
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY benches/ benches/
RUN cargo build --release

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:trixie-slim

# Runtime shared libraries needed by the siphon binary
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Bring the python-build-standalone install (interpreter + site-packages)
# over wholesale, then expose its interpreter and shared libs to the
# dynamic linker.
COPY --from=builder /opt/python /opt/python
RUN PY_BIN=$(find /opt/python -type f -name python3.14t -perm -u+x | head -n1) && \
    PY_PREFIX=$(dirname $(dirname "$PY_BIN")) && \
    ln -sfn "$PY_BIN" /usr/local/bin/python3.14t && \
    ln -sfn "$PY_BIN" /usr/local/bin/python3 && \
    ln -sfn "$PY_BIN" /usr/local/bin/python && \
    echo "$PY_PREFIX/lib" > /etc/ld.so.conf.d/python3.14t.conf && \
    ldconfig

# SIPhon binary
COPY --from=builder /build/target/release/siphon /usr/local/bin/siphon

# Default scripts and config
COPY scripts/ /etc/siphon/scripts/
COPY examples/ /etc/siphon/examples/
COPY siphon.yaml /etc/siphon/siphon.yaml

# Free-threaded interpreters print a runtime warning unless this is set.
ENV PYTHON_GIL=0
# Print the C stack on a fatal signal so we never have to chase a silent SIGSEGV.
ENV PYTHONFAULTHANDLER=1

# SIP ports
# 5060 UDP/TCP — standard SIP
# 5061 TCP     — SIP over TLS
EXPOSE 5060/udp
EXPOSE 5060/tcp
EXPOSE 5061/tcp

WORKDIR /etc/siphon

# Run with host network mode for production to avoid NAT issues with SIP.
# Example:
#   docker run --network host -v ./siphon.yaml:/etc/siphon/siphon.yaml \
#              -v ./scripts:/etc/siphon/scripts siphon
ENTRYPOINT ["/usr/local/bin/siphon"]
CMD ["--config", "/etc/siphon/siphon.yaml"]
