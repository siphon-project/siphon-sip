# Getting started

Run SIPhon and confirm it answers a call. The fastest path is Docker Compose —
no toolchain, no build. If you only read one page before deploying, read this
one, then head to the [Cookbook](cookbook/index.md) for a working script for your
role.

## Quickstart (Docker Compose) — recommended

You need [Docker](https://docs.docker.com/engine/install/) with the Compose
plugin. Nothing else.

```bash
git clone https://github.com/siphon-project/siphon-sip.git
cd siphon-sip
docker compose up -d
docker compose logs -f
```

That's it. The repo ships a working [`siphon.yaml`](https://github.com/siphon-project/siphon-sip/blob/main/siphon.yaml)
and [`scripts/proxy_default.py`](https://github.com/siphon-project/siphon-sip/blob/main/scripts/proxy_default.py),
so `docker compose up -d` starts a working proxy out of the box, pulling the
published `ghcr.io/siphon-project/siphon-sip:latest` image.

The [`docker-compose.yaml`](https://github.com/siphon-project/siphon-sip/blob/main/docker-compose.yaml)
**bind-mounts your config and scripts from the repo directory**:

```yaml
    volumes:
      - ./siphon.yaml:/etc/siphon/siphon.yaml:ro
      - ./scripts:/etc/siphon/scripts:ro
```

So you edit `siphon.yaml` or `scripts/*.py` on the host and SIPhon
**hot-reloads** them — no rebuild, no restart. Make it yours by editing those two
files; jump to [Verify it's up](#verify-its-up) to confirm it's answering.

!!! note "Host networking vs. Docker Desktop"
    The compose file uses `network_mode: host` because SIP is sensitive to NAT
    rewriting of the `Via`/`Contact` addresses — on Linux the ports bind
    directly on the host and the addresses stay real. **Docker Desktop
    (macOS/Windows) has no host networking**: delete the `network_mode: host`
    line and uncomment the `ports:` block in `docker-compose.yaml` instead.

To run your own build instead of the published image, comment out `image:` and
uncomment `build: { context: . }` in the compose file, then
`docker compose up -d --build`.

## Verify it's up

Send an `OPTIONS` keepalive and expect a `200 OK`. With
[`sipsak`](https://github.com/nils-ohlmeier/sipsak):

```bash
sipsak -s sip:ping@127.0.0.1:5060
```

The compose file also has a built-in healthcheck that pings SIP `OPTIONS`, so:

```bash
docker compose ps        # STATUS shows "healthy" once it's answering
```

If you enabled the admin/metrics endpoints in `siphon.yaml`, `curl` them:

```bash
curl -s http://127.0.0.1:9090/metrics        # Prometheus metrics
curl -s http://127.0.0.1:8080/admin/health   # liveness
```

## Other ways to install

Prefer a native binary or a package? All of these produce the same `siphon`
binary; only the Compose quickstart needs no build toolchain.

### Prerequisites (for the build/package paths)

- **Linux** is the primary target (that's where the transports, `nf_tables`
  firewall, and IPsec paths are exercised). macOS works fine for development.
- **Rust 1.80 or newer**, installed with [rustup](https://rustup.rs). Do **not**
  use the `rustc` from `apt`/`dnf` — the distro package is usually too old to
  build the crate, and that is the single most common install failure.
- **Python 3.12+ with dev headers** (`python3-dev` / `python3-devel`). The
  scripting layer embeds CPython, so the headers and a shared `libpython` must
  be present at build time. Python 3.12 is enough to run SIPhon; the
  free-threaded **3.14t** build is a performance option, not a requirement (see
  [below](#python-312-vs-314t)).

### cargo install (from crates.io)

```bash
# build toolchain + Python headers
sudo apt update
sudo apt install -y build-essential python3-dev pkg-config

# current Rust from rustup (NOT apt's rustc)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# build and install the binary
PYO3_PYTHON=python3 cargo install siphon-sip
```

!!! warning "Ubuntu 24.04 / Debian: the two things that trip people up"
    Almost every failed build is one of these:

    1. **`rustc` is too old.** `apt`'s Rust predates what the crate needs. Install
       [rustup](https://rustup.rs) and make sure `rustc --version` reports 1.80+
       (`which rustc` should point into `~/.cargo`, not `/usr/bin`).
    2. **`python3-dev` is missing.** Without the Python headers and shared
       library, the build can't link CPython and fails with a PyO3/`libpython`
       error. `sudo apt install python3-dev` fixes it. Keep `PYO3_PYTHON=python3`
       set so the build targets the interpreter you expect.

    SIPhon uses **rustls** end-to-end, so you do **not** need OpenSSL headers.

Optional backends and transports are behind cargo features:

```bash
cargo install siphon-sip --features redis-backend,postgres-backend
# SIP/Diameter-over-SCTP is Linux-only and off by default:
sudo apt install -y libsctp-dev
cargo install siphon-sip --features sctp
```

### Prebuilt `.deb` / `.rpm`

Prebuilt packages are attached to each
[GitHub Release](https://github.com/siphon-project/siphon-sip/releases). They
install the binary to `/usr/bin/siphon`, a default config to
`/etc/siphon/siphon.yaml`, example scripts to `/etc/siphon/scripts/`, and a
systemd unit.

```bash
sudo dpkg -i siphon_*.deb        # Debian / Ubuntu
sudo rpm -i siphon-*.rpm         # Fedora / RHEL / Rocky

sudo vim /etc/siphon/siphon.yaml # edit to match your network
sudo systemctl enable --now siphon
journalctl -u siphon -f
```

The service runs as an unprivileged `siphon` user and is not auto-enabled on
install — you enable it explicitly. Building the packages yourself, and the
from-source path, are covered in the
[README](https://github.com/siphon-project/siphon-sip#installation).

### Running a native binary directly

```bash
siphon --config /etc/siphon/siphon.yaml
# or, from a source checkout:
PYO3_PYTHON=python3 cargo run --release -- --config siphon.yaml
```

## Python 3.12 vs 3.14t

SIPhon runs on any Python **3.12 or newer**. Scripts run under a real CPython
interpreter, so you get the whole standard library (`re`, `json`, `asyncio`, …)
and any pip package you install. (The prebuilt Docker image already bundles a
free-threaded 3.14t interpreter, so the Compose quickstart is fast by default.)

The performance numbers in the README are measured on **free-threaded Python
3.14t**, which removes the GIL so handler threads run in genuine parallel.
That's what you want for a high-throughput node, but it is not needed to get
started, and nothing about the scripting API changes between the two. For a
native build, install a free-threaded interpreter (for example with
`uv python install 3.14+freethreaded`) and point `PYO3_PYTHON` at it when you're
tuning for throughput.

## Next steps

- **[Cookbook](cookbook/index.md)** — a complete, working starting point for each
  role: [registrar](cookbook/registrar.md), [stateful proxy](cookbook/proxy.md),
  [load balancer](cookbook/load-balancer.md), [SBC / B2BUA](cookbook/sbc.md),
  [number normalization](cookbook/number-normalization.md), and more.
- **[Deployment & operations](deployment.md)** — real topologies, graceful drain,
  health probes, capacity planning.
- **[Migrating from Kamailio / OpenSIPS](migrating-from-kamailio-opensips.md)** —
  if you already run one of those, start here.

Stuck on install? Open a
[Discussion](https://github.com/siphon-project/siphon-sip/discussions) with your
OS, whether you used Compose or a native build, and the exact error.
