# Changelog

All notable changes to SIPhon are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is lockstep across
the `siphon-sip` crate and the `siphon-sip` Python SDK, driven by the git tag.

## [Unreleased]

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

### Internal
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
