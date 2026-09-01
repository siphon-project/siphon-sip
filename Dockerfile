# SIPhon container image.
#
# What it builds: the `siphon-bin` package, NOT the root `siphon-sip` one. Both
# produce an artifact called `siphon` with the same CLI and the same
# siphon.yaml, but siphon-bin additionally composes the opt-in extension crates,
# so the official image ships the scriptable `http` namespace (siphon-bin's
# default feature) alongside the `ui` dashboard. smpp/sigtran stay off — see
# siphon-bin/Dockerfile for an image with those compiled in.
#
# The siphon-sip git dep is patched to this checkout (see the builder stage), so
# an image built at tag vX.Y.Z contains that tag's lib. Without the patch cargo
# would resolve the SHA pinned in siphon-bin/Cargo.lock and the image would
# silently drift from the release.
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
        git \
    && rm -rf /var/lib/apt/lists/*
# git is load-bearing: siphon-bin reaches the extension crates through git
# dependencies, and cargo shells out to git to fetch them.
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
# The recipe is taken from the ROOT siphon-sip package, not from siphon-bin.
# That is deliberate. Once siphon-sip is patched to a path dependency (below),
# the chain siphon-bin -> siphon-http -> siphon-sip runs THROUGH first-party
# source, and cargo-chef cannot cache-separate that: cooking siphon-bin's graph
# would need the real siphon-sip source present, which would invalidate the
# cooked layer on every src/ edit and defeat the point. Cooking siphon-sip's own
# dependency graph instead keeps the expensive third-party bulk (tokio, pyo3,
# axum, reqwest, hickory, rustls, …) cached behind a layer that only moves when
# Cargo.toml/Cargo.lock move.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
# benches/ holds the criterion [[bench]] targets declared in Cargo.toml; cargo
# validates those files exist (they are explicit targets, unlike auto-discovered
# tests/), so the manifest won't parse without them even though the image never
# runs them.
COPY benches/ benches/
# The ETSI X1 schemas are `include_str!`-embedded by src/li/x1/schema.rs,
# so they are build inputs, not runtime data.
COPY schemas/ schemas/
RUN cargo chef prepare --recipe-path recipe.json

# ── Build dependencies (cached until Cargo.toml/lock change) ─────────────────
FROM chef AS builder
# One target dir shared by the cook below and the siphon-bin build further down.
# Without this they are /build/target and /build/siphon-bin/target, the cooked
# artifacts are invisible to the build that needs them, and the whole dependency
# graph compiles from scratch.
ENV CARGO_TARGET_DIR=/build/target
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --features ui --recipe-path recipe.json

# Build the real binary — the siphon-bin composition (see the file header).
# Two features are in play and they are different kinds of thing:
#   `http`  — a siphon-bin DEFAULT feature, so it needs no flag here. Compiles
#             in the scriptable `http` namespace; it stays inert until
#             siphon.yaml carries an `extensions.http` entry.
#   `ui`    — a passthrough to siphon-sip's own feature, hence explicit. The
#             EXPERIMENTAL operator dashboard, served only when
#             `admin.ui.enabled` is set. `ui/` is a single self-contained HTML
#             file baked in by rust-embed (no Node/build step).
# Drop `--features ui` on both the cook and build lines for a leaner image; add
# `--features smpp` / `sigtran` (plus their system deps) to compile in more.
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY benches/ benches/
# The ETSI X1 schemas are `include_str!`-embedded by src/li/x1/schema.rs,
# so they are build inputs, not runtime data.
COPY schemas/ schemas/
COPY ui/ ui/
COPY siphon-bin/ siphon-bin/
COPY scripts/ scripts/
# Repoint siphon-sip at this checkout, so the image contains the lib from the
# tree it was built from rather than the main-branch SHA pinned in
# siphon-bin/Cargo.lock. The script asserts the patch actually applied — cargo
# treats an unused [patch] as a warning and would otherwise build the git copy.
RUN scripts/pin-siphon-sip-to-tree.sh
WORKDIR /build/siphon-bin
RUN cargo build --release --features ui

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

# SIPhon binary (built from siphon-bin, so `http` is compiled in — see header)
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
