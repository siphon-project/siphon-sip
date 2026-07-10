<p align="center">
  <img src="assets/banner.svg" alt="SIPhon" width="600">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/Python_3.14t-3776AB?logo=python&logoColor=white" alt="Python 3.14t">
  <img src="https://img.shields.io/badge/Tokio-async-blue" alt="Tokio">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <a href="https://crates.io/crates/siphon-sip"><img src="https://img.shields.io/crates/v/siphon-sip.svg?logo=rust" alt="crates.io"></a>
  <a href="https://pypi.org/project/siphon-sip/"><img src="https://img.shields.io/pypi/v/siphon-sip.svg?logo=pypi&logoColor=white" alt="PyPI"></a>
  <a href="https://github.com/siphon-project/siphon-sip/actions/workflows/ci.yaml">
    <img src="https://github.com/siphon-project/siphon-sip/actions/workflows/ci.yaml/badge.svg" alt="CI">
  </a>
</p>

<p align="center">
  <a href="#why-siphon">Why SIPhon?</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#installation">Installation</a> &middot;
  <a href="#usage">Usage</a> &middot;
  <a href="#configuration">Configuration</a> &middot;
  <a href="#scripting">Scripting</a> &middot;
  <a href="#hybrid-proxysbc-mode">Hybrid Mode</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#testing">Testing</a> &middot;
  <a href="#performance-targets">Performance</a>
</p>

---

## Why SIPhon?

SIPhon exists because of Kamailio and OpenSIPS — not in spite of them.

These two projects are giants. They carry the world's phone calls. They've been battle-tested across thousands of deployments, from small PBX setups to carrier-grade IMS cores handling millions of subscribers. The depth of their SIP knowledge, encoded in decades of C code and mailing list threads, is extraordinary. If you run voice infrastructure today, you almost certainly depend on one of them, directly or indirectly.

This project is a love letter to that work.

But after years of writing Kamailio route scripts — debugging `$avp(s:...)` expansions, tracing `failure_route` chains, grepping through C modules to understand why `t_relay()` behaves differently with `record_route()` before vs. after — a question kept coming back: **what if we could keep the architecture but rethink the interface?**

Kamailio and OpenSIPS got the hard parts right: stateful proxy logic, transaction state machines, registrar semantics, dialog tracking. What they didn't get — because it wasn't a priority in 2001 — was a developer experience that modern engineers expect. Their config languages are powerful but opaque. Testing requires a running instance and SIPp. IDE support is nonexistent. Type errors surface at runtime in production.

SIPhon takes the lessons learned from these platforms and rebuilds the surface layer:

- **Rust replaces C** — memory safety, zero-cost abstractions, and `cargo test` instead of Valgrind
- **Python replaces the config language** — real functions, real imports, real debuggers, real test frameworks
- **YAML replaces `modparam()`** — one file, one schema, documented inline
- **Hot-reload replaces restarts** — edit a script, save, done

And then there's the B2BUA.

Kamailio and OpenSIPS are proxies at heart. OpenSIPS has `b2b_entities` and `b2b_logic` — but it's bolted on. Building a real B2BUA call flow means fighting the abstraction at every step: managing two legs with a scripting model designed for single-transaction proxy hops, juggling `b2b_server_new` / `b2b_client_new` / `b2b_bridge` calls with opaque entity IDs, and hoping the state machine does what you think it does. Most teams give up and reach for FreeSWITCH or Asterisk instead — and now they're running two pieces of software, two config languages, two deployment pipelines, and a fragile SIP handoff between them.

SIPhon treats the B2BUA as a first-class citizen. For SBC, gateway, and session control use cases — anything that isn't a full PBX — there's no reason the proxy and B2BUA can't live in the same binary with the same scripting language. The `@b2bua.on_invite` / `@b2bua.on_answer` / `@b2bua.on_bye` decorators give you a proper call object with two fully independent SIP dialogs, media anchoring, header manipulation, and forking — all in Python, all testable with the mock SDK, all hot-reloaded. Each B-leg gets its own Call-ID and From-tag by default, so the two dialogs are fully decoupled — proper topology hiding out of the box. You can build an SBC, a OCSBC-style topology-hiding gateway, or a recording-enabled session controller in under 100 lines of readable code. No entity IDs, no `dlg_val` hacks, no praying that the timer module fires in the right order.

```python
from siphon import b2bua, log, gateway

@b2bua.on_invite
def on_invite(call):
    call.media.anchor(engine="rtpengine")
    call.remove_headers_matching("^X-")
    gw = gateway.select("carriers")
    call.dial(gw.uri, timeout=30)

@b2bua.on_bye
def on_bye(call, initiator):
    call.media.release()
    log.info(f"Call {call.id} ended by {initiator}")
```

The protocol engine underneath is faithful to the same RFCs that Kamailio implements. The transaction state machines follow RFC 3261 section 17. The registrar implements RFC 3261 section 10. The proxy follows RFC 3261 section 16. If you've worked with Kamailio or OpenSIPS, the concepts map directly — `request.relay()` is `t_relay()`, `registrar.save()` is `save("location")`, `request.fork()` is `t_load_contacts()` plus `t_next_contacts()`. The difference is that these are now Python method calls with type annotations, docstrings, and tab completion.

This isn't a replacement for Kamailio or OpenSIPS. It's what happens when someone who spent years using them asks: what would I build if I started today, knowing what I know now?

## Features

| Feature | Standard | Status |
|---------|----------|--------|
| **SIP Parser** | RFC 3261 | Unit tests, RFC 4475 torture tests, proptest roundtrips |
| **Stateful Proxy** | RFC 3261 §16 | Unit + integration tests, SIPp scenarios |
| **Transaction State Machines** | RFC 3261 §17 | Unit tests (INVITE client/server, non-INVITE client/server) |
| **Parallel/Sequential Forking** | RFC 3261 §16.7 | Unit + integration tests |
| **Record-Route / Loose Route** | RFC 3261 §16.6, RFC 3261 §16.12 | Unit tests |
| **B2BUA Engine** | RFC 3261 §6 | Unit + integration tests |
| **Registrar** | RFC 3261 §10 | Unit + integration tests, SIPp REGISTER scenarios |
| **GRUU** | RFC 5627 | Unit tests |
| **Service-Route** | RFC 3608 | Unit tests |
| **Digest Authentication** | RFC 2617 / RFC 7616 | Unit + integration tests |
| **AKAv1-MD5 Authentication** | RFC 3310, 3GPP TS 33.203 | Unit tests (Milenage test vectors) |
| **UDP Transport** | RFC 3261 §18 | SIPp load tests |
| **TCP Transport** | RFC 3261 §18 | Unit tests, connection pool |
| **TLS Transport** | RFC 5246 (TLS 1.3) | Unit tests |
| **WebSocket (WS/WSS)** | RFC 7118 | Unit tests |
| **SCTP Transport** | RFC 4168 | Unit tests (opt-in `sctp` feature) |
| **NAT Traversal (rport)** | RFC 3581 | Unit tests |
| **Outbound / Flow Tokens** | RFC 5626 | Unit tests |
| **DNS SRV/NAPTR** | RFC 3263 | Unit + integration tests |
| **ENUM** | RFC 6116 | Unit tests |
| **PRACK (Reliable Provisionals)** | RFC 3262 | Parser tests |
| **Session Timers** | RFC 4028 | Parser tests |
| **RTPEngine Media Anchoring** | — (RTPEngine NG protocol) | Unit + integration tests |
| **SDP Codec Filtering** | RFC 4566 | Unit + integration tests |
| **Gateway / Load Balancing** | — | Unit + integration tests |
| **Diameter Base Protocol** | RFC 6733 | Unit + integration tests |
| **Diameter Cx (HSS)** | 3GPP TS 29.228/229 | Unit + integration tests |
| **Diameter Rx (PCRF)** | 3GPP TS 29.214 | Unit tests |
| **Diameter Ro (OCS)** | 3GPP TS 32.299 | Unit tests |
| **Diameter Rf (OFCS)** | 3GPP TS 32.299 | Unit tests |
| **Diameter Sh (HSS data)** | 3GPP TS 29.329 | Unit tests |
| **Presence / SUBSCRIBE / NOTIFY** | RFC 6665, RFC 3856 | Unit + integration tests |
| **PIDF** | RFC 3863 | Unit tests |
| **Resource List Server** | RFC 4662, RFC 4826 | Unit tests |
| **Watcher Info** | RFC 3857, RFC 3858 | Unit tests |
| **CDR** | — | Unit + integration tests (file/syslog/http/postgres) |
| **Lawful Intercept (X1/X2/X3)** | ETSI TS 103 221-1, ETSI TS 102 232 | Unit + integration tests |
| **SIPREC** | RFC 7865, RFC 7866 | Unit + integration tests |
| **Initial Filter Criteria (iFC)** | 3GPP TS 29.228 | XML parser, trigger point matching, ISC routing to AS; S-CSCF production |
| **IPsec SA Management** | 3GPP TS 33.203 | Unit tests |
| **Milenage Key Derivation** | 3GPP TS 35.206 | Unit tests (3GPP test vectors) |
| **5G SBI (Npcf, Nchf)** | 3GPP TS 29.512, TS 29.594 | Unit tests |
| **Outbound REGISTER (Registrant)** | RFC 3261 §10.2 | Unit tests |
| **Rate Limiting** | — | Unit tests |
| **IP ACLs** | — | Unit tests |
| **HEP/Homer Tracing** | HEPv3 (draft-botero-sipclf-00) | Unit tests |
| **Prometheus Metrics** | — | Unit tests |
| **Admin HTTP API** | — | Unit + integration tests |
| **Hot-Reload Python Scripting** | — | SIPp scenarios |
| **Graceful Shutdown** | — | Unit tests |


## Installation

### Prerequisites

SIPhon requires **Python 3.12+** at runtime for scripting support. For optimal performance, use **Python 3.14t** (free-threaded) which eliminates the GIL entirely. (The pure-Python test SDK, `siphon-sip`, runs on Python 3.10+ — script unit tests don't need the proxy's runtime.)

### Option 1: cargo install (from crates.io)

```bash
# Requires Rust 1.80+ and Python 3.12+ development headers
cargo install siphon-sip

# Or with optional backends
cargo install siphon-sip --features redis-backend,postgres-backend
```

**SCTP transport is off by default.** SIP/Diameter-over-SCTP (RFC 4168) links
the `libsctp` system library and is Linux-only, so it is gated behind the `sctp`
Cargo feature. Enable it explicitly (and install `libsctp-dev` first on Linux):

```bash
cargo install siphon-sip --features sctp
```

#### Optional extension modules (SMPP, …)

Protocol extensions that aren't part of the core SIP datapath live in their own
crates and are composed into a drop-in `siphon` binary by the separate
[`siphon-bin`](siphon-bin/) package, each behind its own off-by-default cargo
feature. The plain `cargo install siphon-sip` binary is unaffected; build the
extension binary only if you need one:

```bash
# SMPP 3.4 (scriptable `smpp` namespace: @smpp.on_pdu / @smpp.on_bind)
cargo build -p siphon-bin --release --features smpp

# …or as a container image (operator mounts siphon.yaml + smpp.yaml + script):
docker build -f siphon-bin/Dockerfile -t siphon-smpp siphon-bin/
```

Point siphon at the extension's config from `siphon.yaml`:

```yaml
extensions:
  smpp: /etc/siphon/smpp.yaml
```

If `extensions.smpp` is present but the binary was built without `--features
smpp`, it is skipped with a loud warning (same contract as `sctp`).

### Option 2: Docker

```bash
docker pull ghcr.io/siphon-project/siphon-sip:latest

# Or build locally
docker build -t siphon .
```

> **Note:** the published Docker image is the default build — it does **not**
> include SCTP. If you need SIP/Diameter-over-SCTP, build a custom image with the
> `sctp` feature (add `libsctp-dev`/`libsctp1` and `cargo build --features sctp`
> to the [Dockerfile](Dockerfile)).

### Option 3: Debian/Ubuntu (.deb)

```bash
# Build the .deb package (requires cargo-deb)
cargo install cargo-deb
PYO3_PYTHON=python3 cargo deb

# Install the package
sudo dpkg -i target/debian/siphon_*.deb
```

This installs the binary to `/usr/bin/siphon`, the default config to `/etc/siphon/siphon.yaml`, example scripts to `/etc/siphon/scripts/`, and a systemd unit file.

Pre-built `.deb` packages are also available from [GitHub Releases](https://github.com/siphon-project/siphon-sip/releases).

### Option 4: Fedora/RHEL/Rocky (.rpm)

```bash
# Build the .rpm package (requires cargo-generate-rpm)
cargo install cargo-generate-rpm
PYO3_PYTHON=python3 cargo build --release
cargo generate-rpm

# Install the package
sudo rpm -i target/generate-rpm/siphon-*.rpm
```

Pre-built `.rpm` packages are also available from [GitHub Releases](https://github.com/siphon-project/siphon-sip/releases).

### From source

```bash
git clone https://github.com/siphon-project/siphon-sip.git
cd siphon-sip

# Build and install
PYO3_PYTHON=python3 cargo build --release
sudo cp target/release/siphon /usr/local/bin/

# Copy default config and scripts
sudo mkdir -p /etc/siphon/scripts
sudo cp siphon.yaml /etc/siphon/
sudo cp scripts/proxy_default.py /etc/siphon/scripts/
```

## Usage

### Running SIPhon

```bash
# With default config location
siphon --config /etc/siphon/siphon.yaml

# Or from the source directory
PYO3_PYTHON=python3 cargo run -- --config siphon.yaml
```

### systemd (deb/rpm installs)

The `.deb` and `.rpm` packages include a systemd unit file. After installing:

```bash
# Edit config to match your environment
sudo vim /etc/siphon/siphon.yaml

# Start and enable
sudo systemctl enable --now siphon

# Check status / logs
sudo systemctl status siphon
journalctl -u siphon -f
```

The service runs as the `siphon` user with sandboxed permissions. It is not auto-enabled on install — you must explicitly enable it.

### Docker

```bash
# SIP needs host networking to avoid NAT issues with Via/Contact headers
docker run --network host \
  -v ./siphon.yaml:/etc/siphon/siphon.yaml \
  -v ./scripts:/etc/siphon/scripts \
  siphon
```

### Docker Compose (with SIPp tests)

```bash
docker compose -f sipp/docker-compose.yaml up -d siphon
docker compose -f sipp/docker-compose.yaml run --rm sipp-options
docker compose -f sipp/docker-compose.yaml run --rm sipp-register
```

## Configuration

SIPhon uses a single YAML file. Here's a minimal setup:

```yaml
listen:
  udp:
    - "0.0.0.0:5060"
  tcp:
    - "0.0.0.0:5060"

domain:
  local:
    - "example.com"

script:
  path: "scripts/proxy_default.py"
  reload: auto        # hot-reload on file change via inotify

registrar:
  backend: memory
  default_expires: 3600

auth:
  realm: "example.com"
  backend: static
  users:
    alice: "secret"
    bob: "secret"

log:
  level: info
  format: pretty      # or json for log aggregators
```

See [`siphon.yaml`](siphon.yaml) for the full reference with all options documented.

## Scripting

Routing logic lives in Python scripts that are hot-reloaded without restarts. Here's the default proxy script:

```python
from siphon import proxy, registrar, auth, log

DOMAIN = "example.com"

@proxy.on_request
def route(request):
    # OPTIONS keepalive
    if request.method == "OPTIONS" and request.ruri.is_local:
        request.reply(200, "OK")
        return

    # In-dialog requests follow the route set
    if request.in_dialog:
        if request.loose_route():
            request.relay()
        else:
            request.reply(404, "Not Here")
        return

    # REGISTER with digest authentication
    if request.method == "REGISTER":
        if not auth.require_digest(request, realm=DOMAIN):
            return
        registrar.save(request)   # save() sends the 200 OK itself
        return

    # Look up registered contacts and fork
    contacts = registrar.lookup(request.ruri)
    if not contacts:
        request.reply(404, "Not Found")
        return

    request.record_route()
    request.fork([c.uri for c in contacts])
```

If you've written Kamailio config, this maps directly:

| Kamailio | SIPhon | Notes |
|----------|--------|-------|
| `t_relay()` | `request.relay()` | Stateful forwarding |
| `save("location")` | `registrar.save(request)` | Store contacts |
| `lookup("location")` | `registrar.lookup(uri)` | Fetch contacts |
| `t_load_contacts()` / `t_next_contacts()` | `request.fork(targets)` | Parallel or sequential |
| `record_route()` | `request.record_route()` | Insert Record-Route |
| `loose_route()` | `request.loose_route()` | Process Route headers |
| `www_authorize()` | `auth.require_www_digest()` | 401 challenge |
| `proxy_authorize()` | `auth.require_proxy_digest()` | 407 challenge |
| `ds_select_dst()` | `gateway.select(group)` | Destination selection |
| `$ru` | `request.ruri` | Request-URI (object, not string) |
| `$fU` | `request.from_uri.user` | From user part |
| `xlog()` | `log.info()` | Structured logging via tracing |

### Python API highlights

```python
# Request inspection
request.method              # "INVITE", "REGISTER", etc.
request.ruri.user           # URI user part
request.ruri.is_local       # matches domain.local
request.from_uri            # SipUri object
request.call_id             # str
request.in_dialog           # bool
request.source_ip           # observed source address

# Request actions
request.reply(code, reason)
request.relay()                                 # forward to next hop
request.relay("sip:target@host:port")           # explicit destination
request.fork(targets, strategy="parallel")      # parallel/sequential forking
request.record_route()
request.set_header(name, value)
request.remove_header(name)

# Registrar
registrar.save(request)
registrar.lookup(uri)       # -> list[Contact]
registrar.is_registered(uri)

# Auth
auth.require_www_digest(request, realm)    # 401 challenge (REGISTER)
auth.require_proxy_digest(request, realm)  # 407 challenge (INVITE)

# Gateway routing
gateway.select("carriers")                  # weighted round-robin
gateway.select("pool", key=request.call_id) # hash-based sticky sessions

# Cache (async, backed by Redis or local LRU)
result = await cache.fetch("cnam", key)

# Logging (goes through Rust's tracing)
log.info("Processing call from " + request.from_uri.user)
```

Both sync and async handlers are supported — async is auto-detected at registration time.

### What the framework handles automatically

The Rust core enforces these before any Python script runs — **do not duplicate them in scripts**:

| Behavior | RFC | What happens |
|----------|-----|-------------|
| **Max-Forwards == 0** | RFC 3261 §16.3 | Automatic `483 Too Many Hops` |
| **Max-Forwards decrement** | RFC 3261 §16.6 | Decremented on `relay()` / `fork()` (default 70 if absent) |
| **CANCEL matching** | RFC 3261 §9.2 | Forwarded to the INVITE's relay target — never reaches Python |
| **Retransmission absorption** | RFC 3261 §17 | Handled by the transaction layer |
| **ACK for non-2xx** | RFC 3261 §17.2.1 | Absorbed by the server transaction |

Scripts only need to handle policy decisions: authentication, routing, header manipulation, and request disposition (`reply()`, `relay()`, `fork()`).

### Included example scripts

| Script | Role | Description |
|--------|------|-------------|
| `scripts/proxy_default.py` | Residential proxy | Auth, registration, forking |
| `scripts/b2bua_default.py` | Basic B2BUA | Two-leg call handling |
| `examples/proxy_gateway.py` | Proxy + gateway | PSTN breakout with carrier failover |
| `examples/proxy_rtpengine.py` | Proxy + RTPEngine | Media anchoring for NAT traversal |
| `examples/b2bua_gateway.py` | SBC + gateway | B2BUA with carrier routing |
| `examples/b2bua_rtpengine.py` | SBC + RTPEngine | Full SBC with media anchoring |
| `examples/ims_pcscf.py` | IMS P-CSCF | IPsec, AKA auth, media anchoring ([config](examples/ims_pcscf.yaml)) |
| `examples/ims_icscf.py` | IMS I-CSCF | Diameter Cx UAR/LIR, S-CSCF discovery ([config](examples/ims_icscf.yaml)) |
| `examples/ims_scscf.py` | IMS S-CSCF | AKA auth, registrar, iFC, Service-Route ([config](examples/ims_scscf.yaml)) |

### Hybrid proxy/SBC mode

A single script can use both `@proxy.on_request` and `@b2bua.on_invite` decorators — there's no mode switch or config flag. The dispatcher routes automatically: INVITEs go to the B2BUA handler, everything else goes to the proxy handler. This lets you build a topology-hiding SBC with media anchoring for calls while keeping lightweight proxy handling for REGISTER, OPTIONS, and other non-INVITE traffic — all in one process, one script, one deployment:

```python
from siphon import proxy, b2bua, registrar, auth, rtpengine, log

@proxy.on_request
def route(request):
    if request.method == "OPTIONS" and request.ruri.is_local:
        request.reply(200, "OK")
        return

    if request.method == "REGISTER":
        if not auth.require_digest(request, realm="example.com"):
            return
        registrar.save(request)   # save() sends the 200 OK itself
        return

    request.reply(405, "Method Not Allowed")

@b2bua.on_invite
async def on_invite(call):
    call.media.anchor()
    await rtpengine.offer(call)

    contacts = registrar.lookup(call.ruri)
    if not contacts:
        call.reject(404, "Not Found")
        return

    call.remove_headers_matching("^X-")
    call.dial([c.uri for c in contacts])

@b2bua.on_bye
async def on_bye(call, initiator):
    await rtpengine.delete(call)
    log.info(f"[{call.call_id}] ended by {initiator}")
```

No entity IDs, no separate B2BUA process, no SIP handoff between a proxy and a media server. The proxy handles registration and keepalives at line rate while the B2BUA handles calls with full header sanitization and media anchoring.

## Testing Your Scripts

SIPhon ships a pure-Python mock SDK (`siphon-sip` on PyPI, imported as `siphon_sdk`) for unit-testing routing scripts without the Rust binary:

```bash
pip install siphon-sip
```

```python
from siphon_sdk import SipTestHarness

harness = SipTestHarness(local_domains=["example.com"])
harness.load_script("scripts/proxy_default.py")

def test_options_keepalive():
    result = harness.send_request("OPTIONS", "sip:example.com")
    assert result.action == "reply"
    assert result.status_code == 200

def test_register_requires_auth():
    result = harness.send_request("REGISTER", "sip:example.com",
                                  from_uri="sip:alice@example.com")
    assert result.status_code == 401
```

See [sdk/README.md](sdk/README.md) for the full testing guide, async handler support, and B2BUA testing.

## Architecture

```
                    +-----------------+
                    |   Python Script |  <-- hot-reloaded
                    |   (policy only) |
                    +--------+--------+
                             |  PyO3 (GIL-free)
                             v
+----------+    +-------------------------+    +----------+
|          |    |      SIPhon Core        |    |          |
| UDP/TCP  |--->|  Parser  | Transaction  |--->| UDP/TCP  |
| TLS/WS   |    |  Dialog  | Registrar   |    | TLS/WS   |
| Listener |    |  Proxy   | B2BUA       |    | Sender   |
+----------+    +-------------------------+    +----------+
   inbound         Rust (Tokio async)           outbound
```

### Module structure

```
src/
  sip/           # RFC 3261 parser, message builder, URI handling
  transaction/   # Transaction state machines (RFC 3261 sec 17)
  dialog/        # Dialog state tracking
  transport/     # UDP, TCP, TLS, WebSocket, SCTP, flow tokens, rate limiting
  proxy/         # Stateful proxy with forking support
  b2bua/         # Back-to-back UA engine
  registrar/     # AoR store (memory/Redis/PostgreSQL), GRUU
  script/        # PyO3 engine, Python API modules
  diameter/      # Diameter protocol (Cx, Ro, Rx, Rf, Sh)
  rtpengine/     # RTPEngine NG control protocol
  gateway/       # Destination groups, load balancing, health probing
  presence/      # SUBSCRIBE/NOTIFY, PIDF, Resource Lists
  dns/           # SRV/NAPTR/ENUM resolution (RFC 3263)
  cdr/           # Call detail records (file/syslog/http/postgres)
  nat/           # NAT traversal (rport, contact rewriting, keepalive)
  auth/          # Digest authentication
  cache/         # Named cache backends (Redis + local LRU)
  media/         # SDP codec filtering
  li/            # Lawful Intercept (ETSI X1/X2/X3, SIPREC)
  metrics/       # Prometheus metrics
  admin/         # HTTP admin API
  config.rs      # YAML config (serde_yml)
  dispatcher.rs  # Message routing and dispatch
  error.rs       # Error types (thiserror)
  shutdown.rs    # Graceful shutdown coordinator
```

### Design principles

- **Transport is Rust-only** — Python never touches raw sockets
- **State machines are Rust-only** — Python decides policy, Rust enforces protocol
- **Scripts compile once** — bytecode cached at startup, zero per-request compilation
- **No GIL** — free-threaded Python 3.14t with `#[pymodule(gil_used = false)]`
- **No per-request allocations** on the hot path where avoidable

### Scaling, HA & operations

A single SIPhon node handles tens of thousands of calls per second, so you run more
than one node for **redundancy**, not throughput — and you get it the proven SIP way
(a front load balancer + DNS SRV + a shared Redis registrar), not a clustering
engine. The operator docs ([docs/](docs/)) cover this end to end:

- **[docs/scaling-and-redundancy.md](docs/scaling-and-redundancy.md)** — what state
  is node-local vs. Redis-shared, what the Redis backend actually buys you
  (durability + boot snapshot, not live cross-node sync), and why SIPhon ships no
  `clusterer`/DMQ equivalent.
- **[docs/deployment.md](docs/deployment.md)** — concrete topologies (single node,
  redundant pair / N nodes, IMS), the operations runbook (graceful drain, probes,
  metrics/alerts, capacity), and a light Kubernetes shape.
- **[docs/migrating-from-kamailio-opensips.md](docs/migrating-from-kamailio-opensips.md)**
  — a concept map for porting routes, plus how to translate `clusterer`/`dmq_usrloc`
  topologies.
- **[docs/handler-execution-model.md](docs/handler-execution-model.md)** — the
  handler pool, blocking contract, and liveness guarantees.

Runnable reference deployments (a front-LB + 2-backend demo with a failover-proof
script, and Kubernetes manifests) live in **[deploy/](deploy/)**.

## Testing

SIPhon follows strict TDD practices across multiple test layers:

```bash
# Run all tests (unit + integration + RFC 4475 torture)
PYO3_PYTHON=python3 cargo test

# Run a specific test module
PYO3_PYTHON=python3 cargo test --test rfc4475_tests
PYO3_PYTHON=python3 cargo test --test integration_tests

# SIPp functional tests (requires Docker)
docker compose -f sipp/docker-compose.yaml run --rm sipp-options
docker compose -f sipp/docker-compose.yaml run --rm sipp-register
```

| Test Layer | Location | What it covers |
|-----------|----------|---------------|
| Unit tests | `src/*/mod.rs` (inline `#[cfg(test)]`) | Individual functions and types |
| Integration | `tests/integration/` | Cross-module workflows |
| RFC 4475 | `tests/rfc4475/` | SIP torture test messages |
| Property | `tests/proptest/` | `parse(serialize(x)) == x` |
| Functional | `sipp/` | End-to-end SIPp scenarios |

## Performance targets

| Mode | Target | Notes |
|------|--------|-------|
| Proxy | 10,000 calls/sec | 8-core machine |
| B2BUA | 5,000 calls/sec | 8-core machine |
| Script | 0 compiles/request | Bytecode cached at startup |

### Current baseline

Reference machine: AMD Ryzen AI 9 HX 370 (24 logical cores), 128 GB RAM, Linux 6.17, free-threaded Python 3.14t.

`scale_test.sh` arguments are `TOTAL_CALLS TARGET_CPS NUM_UACS`:
- **TOTAL_CALLS** — total INVITE→200→ACK→BYE→200 transactions to drive
- **TARGET_CPS** — aggregate call-per-second rate SIPp tries to launch (split evenly across UACs)
- **NUM_UACS** — how many parallel SIPp UAC instances; each gets its own SIPp UAS peer (one UAC ≈ ~1250 cps SIPp ceiling, so peaks ≥ 5k cps require multiple pairs). Each UAS binds a distinct loopback IP so the proxy fans load across them.

`MODE=b2bua` swaps `scripts/proxy_default.py` for `scripts/b2bua_default.py` so the same call flow runs through the B2BUA path instead of the stateful proxy.

`TRANSPORT=tcp` switches the SIPp UAC/UAS to TCP. The proxy listens on UDP and TCP simultaneously on `:5060`.

**Peak CPU%** is `pidstat -u` on the siphon process — 100 % = one fully-saturated logical core, so 493 % ≈ 5 cores out of 24 available. **Peak RSS** is the resident-set high-water mark (`pidstat -r`) seen during the run.

| Mode  | Transport | Test                  | Peak CPS | Peak CPU% | Peak RSS |
|-------|-----------|-----------------------|---------:|----------:|---------:|
| Proxy | UDP       | `1000 250 1`          |      250 |       20% |    114 MB |
| Proxy | UDP       | `5000 1000 4`         |    1 004 |       57% |    190 MB |
| Proxy | UDP       | `20000 5000 4`        |    4 964 |      208% |    465 MB |
| Proxy | UDP       | `40000 10000 8`       |    9 888 |      370% |    836 MB |
| Proxy | TCP       | `1000 250 1`          |      250 |       19% |     92 MB |
| Proxy | TCP       | `5000 1000 4`         |    1 004 |       47% |    121 MB |
| Proxy | TCP       | `20000 5000 4`        |    4 960 |      161% |    220 MB |
| Proxy | TCP       | `40000 10000 8`       |    9 928 |      323% |    356 MB |
| B2BUA | UDP       | `1000 250 1`          |      250 |       20% |    106 MB |
| B2BUA | UDP       | `5000 1000 4`         |    1 004 |       53% |    121 MB |
| B2BUA | UDP       | `20000 5000 4`        |    4 948 |      190% |    140 MB |
| B2BUA | UDP       | `40000 10000 8`       |    9 912 |      358% |    162 MB |
| B2BUA | TCP       | `1000 250 1`          |      250 |       20% |    100 MB |
| B2BUA | TCP       | `5000 1000 4`         |    1 004 |       50% |    111 MB |
| B2BUA | TCP       | `20000 5000 4`        |    4 972 |      173% |    130 MB |
| B2BUA | TCP       | `40000 10000 8`       |    9 912 |      321% |    150 MB |

### Headroom

Above the design target of 10 000 cps, siphon stays clean well past 2× the
spec. Routing Python handlers through a fixed worker pool (instead of tokio's
elastic `spawn_blocking` path) cut scheduling overhead and lifted the clean
ceiling from ~28k to ~32k cps, at lower CPU than before:

| Test (proxy UDP, free-threaded) | Peak CPS | Peak CPU% | Peak RSS |
|---------------------------------|---------:|----------:|---------:|
| `140000 28000 28`               |   27 916 |      957% |   2.7 GB |
| `160000 32000 32`               |   31 904 |    1 052% |   3.0 GB |

Beyond ~32k the benchmark rig (64 SIPp processes on a 24-core box) saturates
before siphon does — siphon still has CPU headroom at that point.

### Per-message microbenchmarks (criterion)

The SIPp table above measures **aggregate throughput**. Criterion microbenches in
[`benches/`](benches/) isolate the **per-message / per-call costs** that
throughput averages over, so a hot-path change is visible directly instead of
diluted into a CPS figure.

```sh
PYO3_PYTHON=python3 cargo bench            # all hot paths
PYO3_PYTHON=python3 cargo bench --bench sip_hot_path   # just one
```

One bench file per hot path — covering the work siphon repeats on every message,
call, or auth:

| Bench file | What it measures |
|------------|------------------|
| `sip_hot_path`     | RFC 3261 parse (INVITE ±SDP, REGISTER, 200 OK), serialize, roundtrip, header read + copy-on-write mutate, transaction-key extraction (§17) |
| `sdp_hot_path`     | SDP parse, codec filter, serialize, and the per-call parse→filter→serialize rewrite |
| `diameter_codec`   | Diameter AVP encode + message decode — a representative IMS Cx MAR (per registration/charging transaction) |
| `rtpengine_bencode`| rtpengine NG bencode encode/decode of an `offer` (per media-anchored call) |
| `crypto`           | Milenage AKA vector generation and digest response assembly (MD5 / SHA-256 / AKAv1-MD5). Benches the constructions siphon *owns*, not the vendored hash/cipher primitives |

**Regression policy.** New code on the per-message dispatch / parse / transaction
/ serialize path ships a criterion bench in the same change; code that carries no
per-message cost (config, persistence, scripting glue) does not. The hard gate —
**>10% slower than [`benches/baseline.json`](benches/baseline.json) fails** — runs
at release cut on the reference machine via
[`scripts/bench_regression.sh`](scripts/bench_regression.sh) (wired into
[`scripts/cut-release.sh`](scripts/cut-release.sh)), **not** in normal CI, because
absolute timings on shared CI runners are too noisy to gate on. CI only proves the
benches compile. If a number improves, re-baseline to lock the new floor
(`scripts/bench_regression.sh --save`); never raise the baseline to pass a
regression. The baseline is hardware-specific — regenerate it on the same machine
as the table above.

## Roadmap

- [x] SIP parser (RFC 3261)
- [x] Stateful proxy with forking
- [x] B2BUA engine
- [x] Registrar (memory + Redis/PostgreSQL backends)
- [x] Digest authentication
- [x] Python scripting with hot-reload
- [x] Transport: UDP, TCP, TLS, WebSocket, SCTP
- [x] RTPEngine media anchoring
- [x] SIPREC call recording
- [x] Diameter Cx/Ro/Rx/Rf/Sh (IMS)
- [x] ENUM lookup
- [x] Gateway routing with failover
- [x] DNS SRV/NAPTR resolution
- [x] Presence (SUBSCRIBE/NOTIFY, PIDF, RLS)
- [x] CDR (file, syslog, HTTP, PostgreSQL)
- [x] Lawful Intercept (ETSI X1/X2/X3, SIPREC)
- [x] Prometheus metrics + admin API
- [x] Graceful shutdown
- [x] IPsec SA management (P-CSCF)
- [x] Initial Filter Criteria (iFC) — full ISC routing to AS
- [x] SBI interfaces (5G Npcf, Nchf)
- [x] AKAv1-MD5 / Milenage authentication
- [x] Full IMS core roles (P-CSCF, I-CSCF, S-CSCF) — see `examples/ims_*.{py,yaml}`
- [ ] ESL/ARI-style external control interface for B2BUA
- [ ] RTP-to-WebSocket streaming for AI/ML processing

Release history is tracked in [CHANGELOG.md](CHANGELOG.md).

## Acknowledgments

SIPhon stands on the shoulders of [Kamailio](https://www.kamailio.org/) and [OpenSIPS](https://opensips.org/). Their decades of work defining how SIP proxies should behave — from transaction handling semantics to registrar storage patterns to the idea that routing logic should be scriptable — is the foundation this project builds on. If SIPhon's architecture feels familiar, that's by design.

IMS IPsec and AKA testing leans on [carstenbock/sipp_ipsec](https://github.com/carstenbock/sipp_ipsec), Carsten Bock's SIPp fork that teaches the UE simulator sec-agree and IPsec. It drives the VoLTE REGISTER + AKA + IPsec sec-agree flows under [`sipp/ipsec/`](sipp/ipsec/), and it's the harness the P-CSCF is validated against.

## Platform Partner

<p align="center">
  <a href="https://cellact.nl/"><img src="assets/partners/cellact-arnacon.png" alt="Cellact and Arnacon — SIPhon Platform Partner" width="360"></a>
</p>

SIPhon's continued development is backed by **[Cellact](https://cellact.nl/)** and its
Web3 telecom project **[Arnacon](https://www.arnacon.com/)** as a **Platform Partner**.
Arnacon is their decentralized take on telephony: encrypted calls and messaging tied to an
identity you own instead of a carrier-issued number. Their support helps drive the SIPhon
roadmap forward.

## Commercial Support

SIPhon is MIT-licensed and free to use in production. If you'd like a hand getting it
there — deployment design, IMS/VoLTE integration, custom scripting, performance tuning,
or an SLA-backed support contract — commercial support is available from
**[Real Time Telecom B.V.](https://realtime-telecom.nl)**, run by SIPhon's maintainer.

Reach out via [realtime-telecom.nl](https://realtime-telecom.nl) to talk specifics.

## Sponsors

Ongoing development is backed by **[Real Time Telecom B.V.](https://realtime-telecom.nl)**,
SIPhon's founding sponsor, with **[Cellact / Arnacon](https://www.arnacon.com/)** as a
[Platform Partner](#platform-partner). Need a particular feature built or fast-tracked? Feature
sponsorship is welcome — use the **Sponsor** button on the repository, or get in touch
through RTT.

## License

MIT
