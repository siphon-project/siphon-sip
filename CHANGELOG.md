# Changelog

All notable changes to SIPhon are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is lockstep across
the `siphon-sip` crate and the `siphon-sip` Python SDK, driven by the git tag.

## [Unreleased]

### Added
- **Outbound TLS client certificate (mutual TLS).** New `tls.client_certificate`
  and `tls.client_private_key` (PEM chain + key). When set, siphon presents that
  client certificate on outbound TLS connections whose peer requests one — for
  upstream SIP trunks that require client-certificate / mutual TLS (e.g.
  Microsoft Teams Direct Routing). Previously the outbound pool presented no
  client certificate, so such peers aborted the handshake with
  `CertificateUnknown`. Both fields must be set together (or neither); a
  one-sided setting or an unreadable/unparseable file is a hard startup error
  (fail closed). Server-certificate verification is unchanged (still permissive).
- **Hostname-based outbound TLS SNI.** Outbound TLS handshakes now present the
  resolved target hostname as SNI / certificate name instead of the destination
  IP literal. RFC 6066 forbids SNI for an IP literal, so IP-based next hops
  emitted none and hostname-vhost front-ends could not route the handshake; the
  hostname now flows from the resolved SIP URI (relay, fork, and gateway TLS
  health probe) through to the connection pool. Bare-IP next hops are unchanged
  (still no SNI).

## [1.1.1] — 2026-07-02

### Security
- **Bump `quick-xml` 0.37 → 0.41** to address RUSTSEC-2026-0194 (quadratic
  runtime when checking a start tag for duplicate attribute names) and
  RUSTSEC-2026-0195 (unbounded namespace-declaration allocation in `NsReader`,
  a memory-exhaustion DoS). siphon parses XML on the presence (PIDF/reginfo),
  iFC, SIPREC-metadata, and Sh paths — some of it from remote peers — so the
  parser hardening matters. No API or behavioural change (the reginfo / iFC /
  SIPREC parsers keep identical decode + entity-unescape semantics).

## [1.1.0] — 2026-07-02

### Added
- **Supply-chain documentation + `SECURITY.md`.** A new **Supply chain & SBOM**
  docs page documents the per-release SBOM (SPDX 2.3 + CycloneDX 1.4, attached to
  each GitHub Release), how to consume it with Grype / Trivy / Dependency-Track,
  how to reproduce it with `cargo sbom`, and the scheduled `cargo-deny` advisory /
  license / source audit. A root `SECURITY.md` adds a private vulnerability-
  reporting policy (GitHub private reporting, coordinated disclosure) — previously
  absent. No behavioural change; documents supply-chain artifacts that already
  ship at release.
- **SDK mocks for the extension namespaces (`smpp`, `http`).** The `siphon-sip`
  Python SDK now mocks the namespaces injected by the opt-in extensions, so
  `from siphon import smpp` / `from siphon import http` resolve under pytest and
  carry full type hints + docstrings for script authoring. Two new harnesses —
  `siphon_sdk.smpp_testing.SmppTestHarness` and
  `siphon_sdk.http_testing.HttpTestHarness` — dispatch mock binds / PDUs and
  HTTP requests into a script's handlers and capture the results, mirroring
  `SipTestHarness`. This lets SMPP/HTTP scripts be unit-tested with a single
  `pip install siphon-sip`, no running SMSC or listener required. The mocks
  track the extension runtimes (siphon-smpp, siphon-http), which each ship a CI
  check that fails if their namespace surface drifts from these mocks. The docs
  **Extensions** page and nav now link the per-extension documentation sites.
- **HTTP extension wired into `siphon-bin` (`--features http`).** The second
  opt-in extension module alongside SMPP: when `extensions.http` in `siphon.yaml`
  points at an `http.yaml`, `siphon-bin` registers the scriptable `http`
  namespace and the HTTP runtime, so scripts can serve inbound HTTP
  (`@http.route`, `@http.middleware`, `@http.on_startup`) and make outbound calls
  (`http.Client`) from the same asyncio loop they use for SIP. `http.Client` is a
  **pooled, Rust-backed (reqwest) client whose calls run entirely on siphon's
  Tokio runtime and yield the asyncio driver loop while in flight** — so a script
  that only needs outbound HTTP on the hot path (a REST lookup per INVITE, a
  provisioning callback) should enable this feature and use `http.Client` rather
  than a synchronous Python client that blocks its driver loop for the whole
  round-trip. A new `full` aggregate feature (`--features full`) enables every
  extension module at once. The HTTP module is pinned to **siphon-http v1.0.1**;
  with the feature off, an `extensions.http` block still parses and is skipped
  with a loud warning (same contract as SMPP and the `sctp` feature). Documented
  under **Extensions** in the docs site.
- **Opt-in extension binary (`siphon-bin`)** — a new standalone package that
  builds a drop-in `siphon` binary composing optional extension modules behind
  cargo features (all off by default). The first module is **SMPP 3.4**
  (`--features smpp`): when `extensions.smpp` in `siphon.yaml` points at an
  `smpp.yaml`, it registers the scriptable `smpp` namespace and the SMPP runtime
  so scripts can handle `@smpp.on_pdu` / `@smpp.on_bind`. With a module's feature
  off, its `extensions.<name>` block still parses and is skipped with a loud
  warning (same contract as the `sctp` feature). The plain `siphon` binary from
  `cargo install siphon-sip` is unchanged; operators who want extensions build
  `siphon-bin` (e.g. `cargo build -p siphon-bin --release --features smpp`, or
  the `siphon-bin/Dockerfile` image). Documented under **Extensions** in the
  docs site. The `ext/` layer is structured so further modules (HTTP, …) plug in
  behind their own features. The SMPP module is pinned to **siphon-smpp v1.2.1**,
  which adds a per-ESME-session inbound ingress rate cap (`server.max_msg_per_sec`
  with a `pace` / `reject` over-rate action).
- **`siphon::install_allocator!()` — one-line jemalloc + page-decay setup.** A
  `#[global_allocator]` and jemalloc's `_rjem_malloc_conf` config symbol only
  take effect in the final binary crate (the language honors `#[global_allocator]`
  only in the binary root, and jemalloc's weak `_rjem_malloc_conf = NULL` default
  means a library-provided definition isn't reliably linked), so both must be
  emitted in `main.rs`. The new macro does exactly that in one line:
  `siphon::install_allocator!();` installs jemalloc as the global allocator plus
  siphon's page-decay tuning
  (`background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0`), with siphon
  owning the `tikv-jemallocator` version (re-exported, so there's no
  `links = "jemalloc"` version skew and no separate dependency to add). Pass a
  literal to override the decay config
  (`siphon::install_allocator!("dirty_decay_ms:0")`). A read-only boot probe
  (`siphon::metrics::jemalloc_is_active`) now logs a loud WARN at startup if
  jemalloc isn't the active allocator — so the system allocator running
  unexpectedly (RSS bloat, `siphon_memory_*` gauges reading jemalloc's idle
  footprint) shows up in logs rather than a memory post-mortem. See
  `examples/embed_with_allocator.rs`. siphon's own binary is unchanged.
- **ISDN-AddressString AVPs decode to E.164 in scripts** — MSISDN (701),
  SC-Address (3300), SGSN-Number (1489) and MME-Number-for-MT-SMS (1645) are
  now dictionary-typed `ISDNAddressString` (3GPP TS 29.002 §17.7.8) instead of
  raw `OctetString`. `req.get_avp("MSISDN")` now returns the decoded E.164
  digit string (e.g. `"31612345678"`) rather than raw `0x91`+TBCD bytes, and
  setting one of these AVPs from a digit string (`set_avp` / the generic
  `diameter.send_request(msisdn=…)` kwargs) now TBCD-encodes it correctly on
  the wire — previously the generic path shipped raw ASCII, which conformant
  HSSes rejected. Two new script helpers cover raw/unknown AVPs and
  hand-built messages: `diameter.decode_isdn_address(value)` (accepts bytes or
  an already-decoded str — idempotent) and
  `diameter.encode_isdn_address(digits, ton_npi=0x91)`.
- **Generic Diameter server mode** — the Diameter stack was client-only
  (originate toward HSS/PCRF); it now also accepts inbound Diameter from
  authenticated peers, runs the CER/CEA handshake and the DWR/DWA watchdog, and
  dispatches each inbound request to Python. Transport direction is independent
  of request direction (RFC 6733 §2.1): incoming **and** outgoing connections,
  TCP + SCTP, and a node that dials out (`diameter.connect_to`) can still serve
  inbound requests over that connection. New Python server API:
  `@diameter.on_inbound_cer` (advertise CEA identity), `@diameter.on_request`
  with optional `"App:CMD"` filter (`req.answer(code)` / `req.reject(code)` /
  `await req.forward_to(peer)`; unhandled → `3002`), `@diameter.on_reply`
  (central answer-AVP rewrite — topology hiding, Origin / Result-Code mapping),
  `@diameter.on_request_completed` (post-answer event hook), and
  `diameter.peer_pool(target)` (round-robin / weighted / sticky with
  Route-Record loop detection → `3005` and per-call timeout). Two Rust-only
  admission gates run before any Python: source-IP CIDR ACL + Origin-Host
  validation. A lossless AVP tree (`DiameterMsg` / `Avp`) sits alongside the
  JSON decode path for byte-faithful relay that preserves unknown AVPs and flags
  verbatim. Config is flat single-domain
  (`diameter.{listen, origin_host, clients, servers, connect_to}`) or an
  explicit per-domain map; `diameter.event_sink` writes per-transaction events
  (file / none; clickhouse / kafka feature-gated). Ships an **S6a dictionary**
  (TS 29.272: command codes 316–324, AVPs 1400–1450 / 1635, AIR / ULR / PUR
  builders + parsers) and examples (`examples/diameter_server.{py,yaml}`,
  `examples/hss_s6a.py`).
- **glibc allocator instrumentation** — new `siphon_glibc_*` Prometheus gauges
  (`system_bytes`, `in_use_bytes`, `free_bytes`, `mmap_bytes`, `arena_count`)
  sourced from `malloc_info(3)`, aggregated across all arenas. This surfaces the
  C-side / CPython-raw-domain memory pool (incl. `libsctp`) that jemalloc
  (`siphon_memory_*`) and CPython's mimalloc (`siphon_python_allocated_blocks`)
  cannot see; because Rust runs on jemalloc, glibc's arenas hold only the C
  side, so the gauges isolate it cleanly. Deliberately uses `malloc_info` rather
  than `mallinfo2`, which reports the main arena only. Sampled on the dispatcher
  cleanup tick; no-op off glibc. `SIGUSR2` dumps the full `malloc_info` XML to
  the log for call-site attribution.
- **`memory:` config block** for allocator runtime tuning:
  `memory.glibc.arena_max` (`mallopt(M_ARENA_MAX)`, caps the number of arenas)
  and `memory.glibc.trim_interval_secs` (periodic `malloc_trim(0)`). The gauges
  above are always-on; both knobs default off — measure first, bound only if the
  pool proves to be arena retention rather than a leak.
- **`siphon_sbi_npcf_app_sessions_active` gauge** — active N5/Npcf app-sessions
  created by this NF and not yet deleted (a steady climb under flat call rate is
  a stranded-session leak), backed by a new per-replica app-session registry on
  `NpcfClient` that inserts on create and removes on delete.
- **HTTP admin API is now served**, behind a new optional `admin.listen`. It was
  implemented but never started, so only `/metrics` was exposed at runtime.
  Endpoints: `/admin/health` (liveness), `/admin/ready` (readiness — returns 503
  while the process is draining on SIGTERM, so a load balancer / Kubernetes
  deschedules it before it stops accepting new INVITEs), `/admin/stats`,
  `/admin/registrations[/{aor}]` (inspect / force-unregister), and `/metrics`.
  Off by default (no `admin.listen` ⇒ unchanged behaviour).
- **Operator documentation for scaling, redundancy and deployment** (`docs/`):
  `scaling-and-redundancy.md` (what state is node-local vs. Redis-shared, what the
  Redis backend actually provides, and why SIPhon ships no clusterer/DMQ-style
  replication engine), `deployment.md` (single-node / redundant-pair / N-node
  with a front LB + DNS SRV / IMS topologies, an operations runbook, and a light
  Kubernetes shape), and `migrating-from-kamailio-opensips.md`.
- **Reference deployments** (`deploy/`): a front-LB + 2-backend + Redis HA demo
  (docker-compose + a host-binary `validate.sh` that proves restart recovery from
  Redis), and Kubernetes manifests with a `kind` kill-a-pod failover drill
  (`validate-kind.sh`).
- **Release-cut HA failover gate** — `cut-release.sh` now runs the Redis-registrar
  failover validation as a mandatory gate (skip with `FAILOVER_OK=1`), alongside
  the existing perf/mem and criterion regression gates.

### Changed
- **Synchronous Python executor pool ceiling is now memory-aware by default.**
  The pool's default `max`/`core` worker counts were derived only from the host
  CPU count (`core = max(8, 2×CPUs)`, `max = max(32, 4×core)`), which scaled the
  pool's memory ceiling with the *box's* core count rather than the NF's memory
  budget. Combined with a per-worker heap that is ~8 MB on free-threaded CPython
  3.14t (not the ~2 MB the comment assumed), an un-cpu-limited NF on a 16-core
  host defaulted to `core=32/max=128` ≈ 1 GB of pool heap, so memory-constrained
  IMS NFs hit their cgroup limit under churn. The default ceiling is now the
  **minimum** of that CPU-derived cap and a memory budget (~30 % of the
  container's cgroup memory limit — v2 `memory.max`, v1 `memory.limit_in_bytes`,
  falling back to host RAM — divided by the ~10 MB conservative per-worker heap),
  and `core` is capped the same way so the pool no longer *starts* at 32 workers
  on a big box. On a 512 MB NF the ceiling resolves to ~15 (was 32/128); on
  256 MB to ~7. The resolved `core`/`max` and which bound won (`cpu`/`memory`/
  `override`) are logged at startup. The `script.sync_pool_size` /
  `script.sync_pool_max` overrides still take precedence when set.
- **SCTP is now an opt-in build feature, off by default.** SIP-over-SCTP
  (RFC 4168) and Diameter-over-SCTP link the `libsctp` system library, which
  only exists on Linux. Moving them behind the `sctp` Cargo feature lets the
  default build — including the official Docker image and the prebuilt release
  packages (`.deb` / `.rpm` / tarball) — drop the `libsctp-dev` / `libsctp1`
  dependency and build cleanly on macOS and Windows.
  - **To enable SCTP:** build with `--features sctp` (on Linux, install
    `libsctp-dev` first). The official Docker image and release binaries do
    **not** include SCTP — you must build it yourself.
  - **No config or scripting-API breakage:** the `Transport::Sctp` variant and
    the `listen.sctp` config block still exist, so existing configs parse
    unchanged whether or not the feature is enabled.
  - **When built without SCTP:** a configured `listen.sctp` listener is skipped
    with a warning, and a Diameter peer set to `transport: sctp` fails at
    connect with `ErrorKind::Unsupported` (no silent fallback to TCP).
  - CI builds and tests both configurations (default and `--features sctp`).

### Removed
- **Dropped the no-op `nat.force_rport` and `nat.fix_register` config keys.** Both
  were accepted but never consumed by the runtime. Their intended behaviour is
  already covered: responses are always routed symmetrically to the request's
  source address (RFC 6314, so rport is effectively unconditional), and every
  `registrar.save()` records the observed source (`Contact.received` /
  `Contact.flow`) for NAT/MT routing. REGISTER-side fixups remain available as the
  explicit script methods `request.fix_nated_register()` / `fix_nated_contact()`.
  Removal is backward-compatible — existing `siphon.yaml` files carrying either
  key still parse (the keys are ignored, exactly as before). `nat.fix_contact`,
  `nat.keepalive`, and `nat.crlf_keepalive` are unchanged.

### Fixed
- **Premature `100 Trying` on non-INVITE transactions over UDP (RFC 4320 §4.2).**
  The non-INVITE auto-100 (MESSAGE/SUBSCRIBE/OPTIONS/BYE) fired after the short
  INVITE-style delay (~200ms), violating RFC 4320 §4.2, which forbids a 100 to a
  non-INVITE over an unreliable transport before the UAC's Timer E is reset to T2
  (≈3.5s with default timers). The most visible symptom was a `100 Trying` for an
  in-dialog BYE that the peer answers in milliseconds. The auto-100 delay over
  UDP is now derived from T1/T2 (Timer E → T2); over a reliable transport, where
  RFC 4320 permits a 100 at any time, the configured
  `transaction.auto_emit_100_trying_delay_ms` still applies. INVITE 100 Trying
  behavior is unchanged.

### Performance
- `SipHeaders` now stores one `IndexMap<String, (String, Vec<String>)>` (lowercase
  key → original-cased name + values) instead of two parallel maps. This removes a
  per-header key-clone + hash-insert on the parse path, halves the copy-on-write
  clone, and serializes in a single pass. Criterion microbenches: SIP parse −30%,
  serialize −50%, full parse→serialize roundtrip −33%, first header write −20%.
  No public API change; serialized output is byte-identical (RFC 4475 + proptest
  roundtrips unchanged).

### Internal
- Per-module steady-state memory-leak guards for the control-plane paths the
  SIP mem-leak test never exercised, each gating on the production store
  draining back to baseline: rtpengine (`pending` correlation map on the success
  and timeout paths), diameter (`pending` map through the real connection
  reader, sequential and under concurrent in-flight load), and SBI/N5
  (`NpcfClient` app-session store across create → delete).
- Criterion microbenchmarks for the per-message / per-call hot paths, one bench
  file per path: `sip_hot_path` (parse/serialize/header/txn-key), `sdp_hot_path`
  (parse/filter/serialize), `diameter_codec` (AVP encode + message decode),
  `rtpengine_bencode` (NG offer encode/decode), and `crypto` (Milenage AKA +
  digest response assembly). They isolate the individual costs the SIPp
  throughput baseline averages over.
- Release-cut regression gate (`scripts/bench_regression.sh`, wired into
  `scripts/cut-release.sh`): fails on >10% slowdown vs the committed
  `benches/baseline.json`. Self-contained (reads criterion's own `estimates.json`,
  no `critcmp`/`jq`). CI proves the benches compile; the hard timing gate runs at
  release cut on fixed hardware, where absolute timings are meaningful.

### Documentation
- Added a **Transports & networking** guide (docs site, under *Running in
  production*): transport listeners (UDP/TCP/TLS/WS/WSS/SCTP), WebSocket/WebRTC
  (RFC 7118) and the signaling-vs-media split, RFC 5626 flow tokens and
  connection reuse, `advertised_address` for behind-NAT / load-balancer
  deployments, client NAT traversal, inter-transport routing, and IPv4/IPv6
  interworking.

## [1.0.0] — 2026-06-26

First stable release. A love letter to Kamailio and OpenSIPS — their proven
architecture, rebuilt with a Rust core and free-threaded Python 3.14t scripting.
The developer writes business logic; SIPhon owns the protocol.

### Core
- RFC 3261 SIP parser (RFC 4475 torture tests, proptest roundtrips, fuzzing)
- Stateful proxy (§16) with parallel/sequential forking (§16.7)
- Transaction state machines (§17), dialog tracking, Record-Route / loose routing
- First-class, scriptable B2BUA (§6) — proxy and B2BUA in a single binary

### Transports
- UDP, TCP, TLS 1.3, WebSocket (WS/WSS), SCTP
- NAT traversal (rport, RFC 3581), Outbound / flow tokens (RFC 5626)

### Registrar & auth
- AoR store with memory / Redis / PostgreSQL backends, GRUU, Service-Route
- Digest auth (RFC 2617 / 7616) with timestamp-bound nonces and AoR-to-user binding
- AKAv1-MD5 / Milenage (RFC 3310, 3GPP TS 33.203 / 35.206)

### IMS & 5G
- Diameter Cx / Rx / Ro / Rf / Sh; Initial Filter Criteria (iFC) with ISC routing
- IPsec SA management for P-CSCF; 5G SBI Npcf (N5) + Nbsf PCF discovery
- Runnable P-CSCF / I-CSCF / S-CSCF examples

### Media & routing
- RTPEngine NG media anchoring, SDP codec filtering, media injection
- Gateway load balancing with health probing, DNS SRV/NAPTR (RFC 3263), ENUM
- Presence (SUBSCRIBE/NOTIFY, PIDF, RLS), outbound REGISTER

### Observability & compliance
- Prometheus metrics (built-in + custom), HEP/Homer tracing, CDR, admin HTTP API
- Lawful Intercept (ETSI X1/X2/X3) + SIPREC (RFC 7865 / 7866), graceful shutdown

### Scripting
- Free-threaded Python 3.14t (no GIL), hot-reload, sync + async handlers
- `siphon-sip` mock SDK on PyPI for unit-testing scripts (imported as `siphon_sdk`)

### Performance
- Design targets — Proxy 10k cps, B2BUA 5k cps (8-core). Stays clean past
  31.9k cps on the reference box with zero failures and zero retransmits across
  all 16 baseline rows.

[1.0.0]: https://github.com/siphon-project/siphon-sip/releases/tag/v1.0.0
