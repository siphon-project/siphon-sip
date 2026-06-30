# Changelog

All notable changes to SIPhon are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is lockstep across
the `siphon-sip` crate and the `siphon-sip` Python SDK, driven by the git tag.

## [Unreleased]

### Added
- **Native `siphon-rtp` media backend (JSON-over-TCP) — experimental.** siphon
  can now drive the in-house `siphon-rtp` media engine over its native control
  protocol — a persistent TCP connection carrying length-prefixed JSON frames —
  as an alternative to the rtpengine NG/bencode-over-UDP engine. The siphon-rtp
  engine is pre-release, so this backend is **experimental**; rtpengine remains
  the recommended production backend. Select it per deployment:
  ```yaml
  media:
    backend: siphon-rtp            # default: rtpengine
    siphon_rtp:
      address: "127.0.0.1:8080"
      control_secret: "${SIPHON_RTP_CONTROL_SECRET}"   # optional
      timeout_ms: 2000
  ```
  - Reliable transport with request/response correlation, an optional
    shared-secret auth handshake, and automatic reconnect with backoff (siphon
    boots even when the engine is down; commands issued before the connection is
    up wait for it, up to their timeout).
  - **Server-pushed events** (DTMF, media-timeout) arrive on the same control
    connection and flow through the existing event path, so
    `@rtpengine.on_dtmf` handlers work unchanged regardless of backend.
  - The Python `rtpengine` scripting API and all media profiles are **unchanged**
    — only the transport underneath differs.
  - **Full HA / load-balancing parity with rtpengine:** `media.siphon_rtp`
    accepts either a single `address` or an `instances:` list with weights, using
    weighted round-robin plus per-call-id connection affinity (every command for
    a call stays on one connection). Per-instance health is probed and exported
    alongside the existing rtpengine health metrics.
  - **Backward compatible:** the default backend remains `rtpengine`; existing
    `media.rtpengine` configs are untouched. SIPREC/MPTY subscriptions are not
    yet implemented on `siphon-rtp` and surface a clear engine error there.
  - Depends on the published `siphon-rtp-proto` crate (the shared wire contract).
- **Classic `rtpproxy` media backend (text-over-UDP).** siphon can now drive a
  classic `rtpproxy` relay (the Sippy/Kamailio/OpenSIPS media proxy) as a third
  media-control backend — for migrating an existing deployment to siphon while
  keeping its in-place rtpproxy. Select it per deployment:
  ```yaml
  media:
    backend: rtpproxy             # default: rtpengine
    rtpproxy:
      address: "127.0.0.1:22222"  # rtpproxy -s udp:<addr>
      timeout_ms: 1000
      retries: 2                  # UDP retransmits (same cookie); default 2
  ```
  - Speaks the classic cookie-prefixed `U`/`L`/`D`/`V` protocol over UDP, with
    cookie-keyed request/response correlation and **idempotent retransmits** for
    reliability over UDP (rtpproxy de-duplicates by cookie).
  - rtpproxy only allocates a relay port, so **siphon rewrites the SDP itself**
    (`c=`/`m=`), per media stream, including multi-stream offers (media-id tag
    suffix) and held media (`m=… 0`, left untouched).
  - The Python `rtpengine` scripting API and media profiles are **unchanged** —
    `rtpengine.offer/answer/delete/ping` and `call.media` map onto rtpproxy. The
    profile's NAT `direction` (e.g. `["internal","external"]`) and `asymmetric`
    flag map to rtpproxy bridge/symmetry modifiers; IPv6 is detected per stream.
  - **HA / load-balancing parity with rtpengine:** `media.rtpproxy` accepts a
    single `address` or an `instances:` list with weights (weighted round-robin
    plus per-call-id affinity); per-instance health is probed (`V`) and exported
    alongside the existing rtpengine health metrics.
  - **Backward compatible:** the default backend remains `rtpengine`. The
    rtpengine-only verbs (announcements, DTMF injection, gating, SIPREC/MPTY) are
    not available on rtpproxy and surface a clear engine error there; rtpproxy
    pushes no async events, so the `media.events` listener is unused.
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
