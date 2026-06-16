# SIPhon Feature Readiness Matrix

## Overview

This document tracks the maturity of every SIPhon feature across three readiness levels. SIPhon runs in production today in a residential SIP registrar/proxy role and a 3GPP IMS deployment exercising Diameter Cx/Sh/Rx, iFC, IPsec, and 5G SBI policy control. Features validated on live traffic are marked Production.

| Readiness | Meaning |
|-----------|---------|
| **Production** | Running on live traffic today |
| **Implemented** | Code-complete, unit/integration tested, not yet production-deployed |
| **Planned** | Partially wired or design-only |

---

## Core SIP Engine

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Stateful proxy (RFC 3261 §16) | **Production** | `script: @proxy.on_request` | Full transaction state machines; ICT Timer A RFC-compliant (capped at T2, fires in Proceeding, cancelled on final response) |
| B2BUA (RFC 3261 §6) | **Production** | `script: @b2bua.on_invite` | Two-leg call control, per-leg Call-ID + From-tag, topology hiding |
| Parallel forking | **Production** | `request.fork()` | Used for AS→subscriber delivery |
| Sequential forking | Implemented | `request.fork(strategy="sequential")` | |
| Record-Route / Loose Route | **Production** | `request.record_route()` | Mid-dialog routing proven |
| CANCEL propagation | **Production** | Core | Matched to transaction automatically |
| In-dialog sequential routing | **Production** | `request.loose_route()` | End-to-end 2xx ACK follows the dialog route set (top remaining Route after self-consumption, else R-URI), not the cached INVITE next-hop — correct through non-Record-Routing hops (transparent iFC AS, I-CSCF). RFC 5923 connection reuse: when the route-set next hop still resolves to the peer the dialog was established with, in-dialog requests (B2BUA BYE/re-INVITE/UPDATE/PRACK/2xx-ACK, proxy 2xx-ACK) keep the established connection/address instead of re-resolving — so a load-balanced trunk behind one DNS name (load-balanced Record-Route) is not re-shuffled (RFC 3263 §4.2) onto a sibling member that holds no dialog state; still resolves fresh for a genuinely divergent next hop. Validated proxy/B2BUA × UDP/TCP, 0 failures/retransmits |
| Call transfer (REFER, RFC 3515) | Implemented | B2BUA `@b2bua.on_refer` | |
| Session timers (RFC 4028) | Implemented | `session_timer:` | UAC/UAS/B2BUA refresher modes |
| PRACK (RFC 3262) | Implemented | Core | Reliable provisional responses; B2BUA terminates 100rel per-leg — auto-PRACKs a reliable-provisional B-leg and strips `Require:100rel`/`RSeq` toward a non-100rel A-leg (framework-auto, preset-independent) |

## Transports

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| TCP | **Production** | `listen.tcp` | AS-facing; RFC 3261 §18.3 stream framing with Content-Length extraction; outbound distributor falls back to the `ConnectionPool` when an `OutboundMessage` arrives without a matching inbound connection (covers UAC fire-and-forget paths like in-dialog NOTIFY from `subscribe_state.notify()` whose Route header points at a destination with no live inbound socket — previously the message was built but silently dropped at the connection-map lookup) |
| TLS | **Production** | `listen.tls` | Subscriber-facing, TLS 1.3 validated; RFC 3261 §18.3 stream framing |
| TLS 1.3 | **Production** | `tls.method: TLSv1_3` | |
| TLS 1.2 | Implemented | `tls.method: TLSv1_2` | |
| mTLS (client cert verification) | Implemented | `tls.verify_client: true` | |
| UDP | **Production** | `listen.udp` | |
| WebSocket (WS) | Implemented | `listen.ws` | RFC 7118, browser/WebRTC clients |
| Secure WebSocket (WSS) | Implemented | `listen.wss` | |
| SCTP | Implemented | `listen.sctp` | RFC 4168, IMS inter-node |
| Per-socket advertised address | **Production** | `listen.tls[].advertise` | |
| Global advertised address | Implemented | `advertised_address:` | Fallback for 0.0.0.0 binds |
| DSCP/ToS marking | Implemented | `listen.dscp` | RFC 4594 signaling QoS; default CS3 (24); per-listener override |

## Registrar

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Redis backend | **Production** | `registrar.backend: redis` | Persistent across restarts |
| Memory backend | Implemented | `registrar.backend: memory` | Ephemeral |
| PostgreSQL backend | Implemented | `registrar.backend: postgres` | |
| Python custom backend | Implemented | `registrar.backend: python` | |
| Expires control (default/min/max) | **Production** | `registrar.{default,min,max}_expires` | |
| Max contacts per AoR | **Production** | `registrar.max_contacts` | |
| Redis TTL slack | **Production** | `registrar.redis.ttl_slack_secs` | Race condition buffer |
| GRUU (RFC 5627) | Implemented | | |
| Service-Route (RFC 3608) | **Production** | | Via `registrar.set_service_routes()` / `service_route()` |
| Registration state change hooks | **Production** | `@registrar.on_change` | Callbacks on insert/delete/expire |
| Outbound registration (registrant) | **Production** | `registrant:` | UAC REGISTER to upstream trunks |
| Proxy-side binding cache | Implemented | `registrar.save_proxy(request, reply)` | P-CSCF caches what S-CSCF granted; reads Expires from reply (not request), bypasses local `max_expires` cap, +32 s Timer F grace, no auto-200 OK (proxy relays upstream's response) |
| Path-token MT routing (RFC 3327 / TS 24.229 §5.2.7.2) | Implemented | `request.add_pcscf_path(token)`, `registrar.save(flow_token=)`/`save_proxy(flow_token=)`, `registrar.lookup_by_token(token)`, `request.relay(flow=binding.flow)`, `ipsec.path_host` | P-CSCF mints opaque token, embeds in Path userpart; binding stores token + captured inbound flow (source addr, listener local addr, accepted-connection id); MT routing bypasses DNS resolution and egresses from the same listener that received the REGISTER. UDP flow survives restart; TCP/TLS/WS/WSS bound to accepting instance lifetime. Via on flow-relay derives from `flow.local_addr` so IPSec port pairs are preserved (TS 33.203 §7.4). |
| AS-side contact capture (TS 24.229 §5.4.2.1.2) | Implemented | `registrar.save_as_contact(aor, reply)`, `Contact.params`, `Contact.kind` | S-CSCF script caches the AS's `Contact:` URI and RFC 3840 feature tags (`+g.3gpp.smsip`, `+g.3gpp.icsi-ref`, …) from the 3PR 200 OK; tags surface in `registrar.reginfo_xml(...)` as `<unknown-param>` children per RFC 3680 §5.3.2 so reg-event NOTIFY watchers see the iFC-matched capability set. AS contacts are excluded from `registrar.lookup()` (routing-side never picks them as MT targets) and cascade-clear when the last UE binding deregs/expires. |
| Contact-header parameter passthrough (RFC 3840) | Implemented | `Contact.params` | Every non-typed Contact-header parameter (anything outside `tag`/`q`/`expires`/`+sip.instance`/`reg-id`) round-trips through save → backend persistence → lookup → reg-event NOTIFY. Lowercased at parse time per RFC 3261 §19.1; values preserved verbatim. |

## Authentication

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Digest auth — 401 (UAS) | **Production** | `auth.require_digest()` | REGISTER challenges |
| Digest auth — 407 (proxy) | **Production** | `auth.require_proxy_digest()` | INVITE challenges |
| HTTP backend (HA1 lookup) | **Production** | `auth.backend: http` | REST credential lookup |
| Static users backend | Implemented | `auth.backend: static` | Inline config credentials |
| Diameter Cx backend (HSS) | **Production** | `auth.backend: diameter_cx` | 3GPP TS 29.228 |
| AKA / AKAv1-MD5 (HSS-backed) | **Production** | `auth.require_ims_digest()` | 3GPP TS 33.203 via Cx MAR/MAA |
| AKA / AKAv1-MD5 (local Milenage) | Implemented | `auth.aka_credentials` | 3GPP TS 35.206 — local key derivation without HSS |
| SHA-256 digest (RFC 7616) | Implemented | | |
| Anti-spoofing (from=auth check) | **Production** | Script logic | `auth_user == from_uri.user` |

## STIR/SHAKEN (Caller-ID Attestation)

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Sign — Authentication Service | Implemented | `stir.sign()`, `stir:` signing block | ES256 PASSporT + RFC 8224 Identity header (RFC 8225, ATIS-1000074) |
| Verify — Verification Service | Implemented | `stir.verify()`, `stir:` verification block | x5u fetch + full cert-chain validation to STI-CA anchors, sets `verstat` |
| Attestation levels A/B/C | Implemented | `stir.sign(attestation=…)` | ATIS-1000074 §5.2.3; default via `default_attestation` |
| Diverted-call PASSporT (`div`) | Implemented | `stir.sign_div()` | RFC 8946 — forwarded/retargeted calls |
| Cert chain + freshness | Implemented | `stir.verification.freshness_secs`, `trust_anchors` | EC P-256 chain to STI-CA root; PASSporT `iat` window |
| Permissive rollout mode | Implemented | `stir.verification.permissive` | x5u/infra failures → `No-TN-Validation` instead of `…-Failed` |
| x5u certificate cache | Implemented | `stir.verification.cache_ttl_secs` | In-memory; honours `Cache-Control: max-age` |
| `verstat` stamping | Implemented | `stir.apply_verstat()` | ATIS-1000074 §5.3.1 — P-Asserted-Identity / From |
| RCD (Rich Call Data) | Planned | | Caller name/logo PASSporT — follow-up |
| OCSP/CRL revocation, RSA STI-CA | Planned | | EC P-256 chains only in v1 |

## Security

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Rate limiting (per source IP) | **Production** | `security.rate_limit` | Window + ban duration |
| Scanner UA blocking | **Production** | `security.scanner_block` | sipvicious, friendly-scanner, etc. |
| Trusted CIDRs (bypass rate limit) | **Production** | `security.trusted_cidrs` | |
| Failed auth ban | **Production** | `security.failed_auth_ban` | Threshold + ban duration |
| APIBan integration | **Production** | `security.apiban` | Community IP blocklist polling |
| IP ACLs (allow/deny CIDR lists) | Implemented | Transport-level ACL | |
| Preloaded Route rejection | **Production** | Script logic | Anti-abuse for Route header |

## NAT Traversal

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Force rport (RFC 3581) | **Production** | `nat.force_rport: true` | |
| Fix Contact (observed source) | **Production** | `nat.fix_contact: true` | |
| Fix REGISTER Contact | **Production** | `nat.fix_register: true` | |
| Fix NATed Contact (script) | **Production** | `request.fix_nated_contact()` | |
| NAT keepalive (OPTIONS ping) | Implemented | `nat.keepalive` | Configurable interval + failure threshold |
| CRLF keepalive (RFC 5626 §4.4.1) | Implemented | `nat.crlf_keepalive` | TCP/TLS/pool connection keep-alive; outbound probe + inbound peer-ping/pong responder |
| Stale contact eviction on restart | **Production** | Core | Evicts connection-oriented contacts + on_change notify |
| Outbound flow tokens (RFC 5626) | Implemented | | Via/Route flow tokens |

## Media

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| RTPEngine integration (NG protocol) | **Production** | `media.rtpengine` | Single or multi-instance |
| RTPEngine load balancing | Implemented | `media.rtpengine.instances[]` | Weighted distribution |
| Built-in profile: SRTP↔RTP | Implemented | `srtp_to_rtp` | SRTP UE ↔ RTP core |
| Built-in profile: WS↔RTP | Implemented | `ws_to_rtp` | WebSocket UE ↔ RTP core |
| Built-in profile: WSS↔RTP | Implemented | `wss_to_rtp` | DTLS-SRTP/AVPF + ICE ↔ RTP |
| Built-in profile: RTP passthrough | Implemented | `rtp_passthrough` | IMS-internal |
| Custom media profiles | Implemented | `media.profiles` | User-defined NG flags |
| SDP manipulation (`sdp` namespace) | Implemented | None | Parse/modify/apply SDP from Python scripts |
| SDP attribute get/set/remove | Implemented | None | Session and media-level `a=` attributes |
| SDP codec filtering | Implemented | None | `filter_codecs()` / `remove_codecs()` |
| SDP media section removal | Implemented | None | `remove_media("video")` |

## Gateway Routing & Load Balancing

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Destination groups | **Production** | `gateway.groups` | |
| Round-robin algorithm | **Production** | `algorithm: round_robin` | |
| Weighted algorithm | Implemented | `algorithm: weighted` | |
| Hash-based algorithm | Implemented | `algorithm: hash` | |
| SIP OPTIONS health probing | **Production** | `gateway.groups[].probe` | Configurable interval + failure threshold |
| Priority-based failover tiers | Implemented | `destinations[].priority` | |
| Dynamic group management | Implemented | Python `gateway.add_group()` / `gateway.remove_group()` | |
| Destination up/down marking | Implemented | Python `gateway.mark_up()` / `gateway.mark_down()` | |

## Call Detail Records

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| CDR generation | Implemented | `cdr:` | |
| File backend (JSON-lines) | Implemented | `cdr.backend: file` | With rotation |
| Syslog backend | Implemented | `cdr.backend: syslog` | UDP syslog |
| HTTP webhook backend | Implemented | `cdr.backend: http` | POST with optional auth header |
| REGISTER event inclusion | Implemented | `cdr.include_register` | Off by default |
| Script-injected extra fields | Implemented | | |

## SIP Tracing

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| HEP v3 over UDP | **Production** | `tracing.hep` | Homer integration |
| HEP over TCP | Implemented | `tracing.hep.transport: tcp` | |
| HEP over TLS | Implemented | `tracing.hep.transport: tls` | With CA cert + SNI |
| Custom agent ID | **Production** | `tracing.hep.agent_id` | |
| Error log suppression | **Production** | `tracing.hep.error_log_interval` | Configurable interval |

## Metrics & Monitoring

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Prometheus endpoint | **Production** | `metrics.prometheus` | |
| Request/response counters | **Production** | `siphon_requests_total` / `siphon_responses_total` | |
| Active registrations gauge | **Production** | `siphon_registrations_active` | |
| Active transactions gauge | **Production** | `siphon_transactions_active` | |
| Active dialogs gauge | **Production** | `siphon_dialogs_active` | |
| Active connections (by transport) | **Production** | `siphon_connections_active` | |
| Request duration histogram | **Production** | `siphon_request_duration_seconds` | |
| Script execution counters | **Production** | `siphon_script_executions_total` | |
| Uptime gauge | **Production** | `siphon_uptime_seconds` | |
| Admin API — health | Implemented | `GET /admin/health` | Liveness/readiness probe |
| Admin API — stats | Implemented | `GET /admin/stats` | Aggregate counters |
| Admin API — registrations | Implemented | `GET/DELETE /admin/registrations` | List, detail, force-unregister |

## Logging

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| JSON structured logging | **Production** | `log.format: json` | |
| Pretty (human-readable) logging | Implemented | `log.format: pretty` | |
| File logging | **Production** | `log.file` | With logrotate support |
| Log level control | **Production** | `log.level` | debug/info/warn/error |

## Python Scripting

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Script loading | **Production** | `script.path` | |
| Hot-reload via inotify | **Production** | `script.reload: auto` | |
| Hot-reload via SIGHUP | Implemented | `script.reload: sighup` | |
| Proxy handlers (on_request/on_reply/on_failure) | **Production** | `@proxy.*` | on_request + on_reply proven |
| B2BUA handlers | **Production** | `@b2bua.*` | on_invite, on_early_media, on_answer, on_failure, on_bye, on_refer |
| Registrar hooks | **Production** | `@registrar.on_change` | |
| Auth API | **Production** | `auth.require_digest()` etc. | |
| Gateway API | **Production** | `gateway.select()` etc. | |
| Cache API | **Production** | `cache.fetch()` | Redis-backed |
| Cache list / TTL / existence ops | Implemented | `cache.list_push/list_pop_all/expire/exists` | Redis-backed FIFO queue ops (atomic LRANGE+DEL drain), per-key TTL, presence check; degrades silently when Redis is unreachable |
| Presence API | **Production** | `presence.*` | Used for reg-event SUBSCRIBE/NOTIFY |
| Outbound SUBSCRIBE (RFC 6665 watcher) | Implemented | `proxy.subscribe_state.send/find/refresh` | Originate SUBSCRIBE, capture dialog state from 200 OK, correlate inbound NOTIFY by tags |
| Reginfo XML parser (RFC 3680) | Implemented | `presence.parse_reginfo(xml)` | Watcher-side parser for `application/reginfo+xml` NOTIFY bodies |
| Lawful intercept API | Implemented | `li.*` | |
| Logging API | **Production** | `log.*` | |
| Async handler support | **Production** | | Auto-detected by runtime |
| Custom metrics API | **Production** | `metrics.counter/gauge/histogram` | Script-defined Prometheus metrics |
| Timer routes | Implemented | `@timer.every()`, `timer.set()`/`cancel()` | Periodic callbacks via Tokio; one-shot cancellable timers keyed by string |
| Mock SDK for testing | Implemented | `siphon-sdk` | Test scripts without Rust binary |
| Extension API (host namespaces, tasks, custom handler kinds) | Implemented | `extensions:`, `register_namespace`/`register_task`, `_siphon_registry.register("custom.kind", …)` | Open extension surface for custom transports / sinks; `ScriptHandle::handlers_for` + `call_handler` dispatch into script handlers from host extensions |

## Dialog Management

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Memory backend | **Production** | Default | In-process, ephemeral |
| Redis backend | Implemented | `dialog.backend: redis` | Persistent across restarts |
| PostgreSQL backend | Implemented | `dialog.backend: postgres` | |

## Named Cache

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Redis-backed cache | **Production** | `cache[].url` | |
| Local LRU tier | Implemented | `cache[].local_ttl_secs` | Two-tier: local + Redis |

## Presence

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| SUBSCRIBE/NOTIFY (RFC 6665) | **Production** | Python `presence` API | reg-event package; `presence.terminate()` + auto-GC on terminated NOTIFY drops dialog state per RFC 6665 §4.4.1 |
| PIDF (RFC 3863) | Implemented | | |
| Resource List Server (RFC 4662) | Implemented | | |
| Watcher Info (RFC 3857/3858) | Implemented | | |

## Server Identity

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Custom Server header | **Production** | `server.server_header` | |
| Custom User-Agent header | **Production** | `server.user_agent_header` | |

## Transaction Timers

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Non-INVITE timeout | **Production** | `transaction.timeout_secs` | |
| INVITE timeout | **Production** | `transaction.invite_timeout_secs` | |

## DNS Resolution

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| SRV lookup (RFC 3263) | Implemented | Core | With A/AAAA fallback; weighted-random RFC 2782 selection per call |
| A/AAAA load distribution (RFC 3263 §4.2) | Implemented | Core | Fisher-Yates shuffle on every A-only resolution so callers picking `.next()` distribute uniformly across equal-cost records |
| NAPTR support | Implemented | Core | |
| ENUM (RFC 6116) | Implemented | Core | |

---

## 3GPP / IMS / Telco

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Diameter Cx (HSS auth) | **Production** | `auth.backend: diameter_cx` | MAR/SAA, SAR/SAA, UAR/UAA, LIR/LIA |
| Diameter Sh (HSS user data) | **Production** | `diameter` | `sh_udr` for repository data, `@on_pnr` for profile pushes |
| Diameter Ro (online charging) | Implemented | `diameter` | CCR/CCA |
| Diameter Rf (offline charging) | Implemented | `diameter`, `rf:` | ACR/ACA wired through `diameter.rf_acr_start/interim/stop/event` (TS 32.299 §6.2.2) — kwargs-style Python API, mandatory AVPs (`Service-Context-Id`, `Event-Timestamp`, `User-Name`, `Termination-Cause`, `Acct-Interim-Interval`), full IMS-Information sub-AVPs (`User-Session-Id`, `Time-Stamps`, `Inter-Operator-Identifier`, `Application-Server`, `IMS-Visited-Network-Identifier`), TS 32.260 IMS Service-Context-Id default. SMS-Information envelope (TS 32.299 §7.2.79) — passing any SMS-specific kwarg (`originator_address`, `recipient_address`, `sm_message_type`, `sms_node`, `sm_user_data_header`, `reply_path_requested`, `sm_service_type`, `sms_result`, SCCP/Client/MTC-IWF Address fields, `sm_discharge_time`, `data_coding_scheme`, …) switches the wire to `Service-Information → SMS-Information` so CDR collectors render calling/called party + message type on the SMS tab; can coexist with IMS-Information for hybrid records. `rf:` config block + `RfChargingService` runtime emits ACR-EVENT automatically on registrar state change. CDR auto-stamps `rf_session_id` / `rf_result_code` from auto-emitted records. B2BUA + proxy ACR-START/INTERIM/STOP auto-emit on call lifecycle is the next layer on the same infrastructure. |
| Diameter Rx (policy/QoS) | **Production** | `diameter` | AAR/AAA, STR/STA, `@on_rar` + `@on_asr`. `diameter.rx_aar(media_components=[…])` takes a list of TS 29.214 §5.3.7 `MediaComponent` dicts with per-flow IPFilterRules + Flow-Usage (RTCP marker) — pair with `qos.media_flows_from_sdp(offer, answer, direction)` to derive the full 5-tuple from an SDP offer/answer rather than emitting a wildcard `permit in 17 from <UE> to any` that any non-permissive PCEF would either drop or open globally. |
| Diameter S6c (SMS-over-Diameter, SMSC↔HSS) | Implemented | `diameter` | `s6c_srr` to discover served-node, `s6c_rsr` for delivery status, `@on_alr` for HSS reachability alerts (TS 29.336). MSISDN / SC-Address / SGSN-Number / MME-Number-for-MT-SMS encoded as ISDN-AddressString (TS 29.002 §17.7.8 — ToN/NPI 0x91 + TBCD digits); inbound parser is lenient on missing ToN/NPI prefix for non-conformant peers. |
| Diameter SGd (SMS-over-NAS, SMSC↔MME) | Implemented | `diameter` | `sgd_tfr` to deliver SMS-DELIVER TPDU to UE, `@on_ofr` for incoming MO-SMS (TS 29.338). SC-Address on the wire uses ISDN-AddressString (TS 29.002 §17.7.8), matching S6c. |
| Diameter generic API (spec-name addressing) | Implemented | `diameter.send_request("Send-Routing-Info-for-SM-Request", application="S6c", **avps)`, `@diameter.on_command(name, application=…)` | Open API for apps and addons; AVPs encoded by dictionary type, snake_case ↔ kebab-case kwargs, 3-letter acronym aliases (SRR/ALR/TFR/…) |
| Diameter peer management | **Production** | `diameter.peers` | Failover + round-robin across HSS/DRA peers |
| AKA authentication (Milenage, local) | Implemented | `auth.aka_credentials` | 3GPP TS 35.206 — local key derivation without HSS |
| AKA authentication (HSS-backed) | **Production** | `auth.require_ims_digest()` | 3GPP TS 33.203 via Cx MAR/MAA |
| IPsec SA management (P-CSCF) | Implemented | `ipsec` | Shared protected client/server ports; SAs installed via direct XFRM netlink (Phase 3) with `ip xfrm` shell-out as fallback backend |
| IPsec sec-agree primitives (script-driven) | Implemented | `siphon.ipsec`, `request.parse_security_client()`, `reply.take_av()` | 3GPP TS 33.203 §6 + RFC 3329; HMAC-SHA-1-96 / HMAC-MD5-96 / HMAC-SHA-256-128 with NULL or AES-CBC-128; Annex H key derivation; registration-tied lifetimes; IPv6; multi-instance SPI partitioning; multi-protocol XFRM selectors (TS 33.203 §7.2 — one SPI pair covers both ESP-over-UDP and ESP-over-TCP, required for iOS UEs mixing REGISTER/TCP with MO MESSAGE/UDP) |
| IPsec SA hard-lifetime repin on grant | Implemented | `pending.activate(hard_lifetime_secs=…)` | XFRM_MSG_UPDSA on all four SAs; tightens kernel lifetime from the placeholder (UE's `Expires` ask, often 600000 s) to the registrar's grant on the 200 OK to auth REGISTER (3GPP TS 33.203 §7.4); kernel preserves `add_time` so deadline = original install + new value |
| IPsec stale-pair cleanup on re-REGISTER | Implemented | `pending.activate()` (automatic) | UE picks a fresh random `port_uc` on every REGISTER (TS 24.229 §5.1.1.2); without this, the manager's `(ue_addr, port_uc)`-keyed bookkeeping accumulated one entry per refresh and the prior pair's four XFRM policies leaked into the kernel forever. After enough cycles a new `port_uc` collided with a leaked selector and policy install hit `EEXIST`, breaking the registration. Activate now fire-and-forgets `cleanup_other_pairs_for_ue` to tear down every prior pair for the same UE address; the new pair (different `port_uc` by construction) installs cleanly. |
| Initial Filter Criteria (iFC) | **Production** | `isc` | XML trigger-point matching + per-user profile storage from Cx SAR |
| IMS P-CSCF role | **Production** | Example `examples/ims_pcscf.{py,yaml}` | |
| IMS I-CSCF role | **Production** | Example `examples/ims_icscf.{py,yaml}` | |
| IMS S-CSCF role | **Production** | Example `examples/ims_scscf.{py,yaml}` | |
| 5G SBI — Npcf (policy) | **Production** | `sbi` | N5 app-session for VoNR QoS; NRF discovery, OAuth2. `sbi.create_session(media_components=[…])` shapes the request into TS 29.514 §5.6.2.4 `medSubComps` with `flowDescriptions` + `flowUsage` so PCF gating works on real UPFs, not just lab boxes; same dict shape as `diameter.rx_aar`. |
| 5G SBI — Nchf (charging) | Implemented | `sbi` | |

## Lawful Intercept / Recording

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| LI master switch + audit log | Implemented | `lawful_intercept` | |
| ETSI X1 admin interface | Implemented | `lawful_intercept.x1` | HTTPS + mTLS + bearer token |
| ETSI X2 IRI delivery | Implemented | `lawful_intercept.x2` | TCP/TLS to mediation device |
| ETSI X3 CC delivery | Implemented | `lawful_intercept.x3` | RTPEngine mirror reception |
| SIPREC recording (RFC 7866) | Implemented | `lawful_intercept.siprec` | SIP Recording Server integration |

---

## Summary

| Category | Production | Implemented | Total |
|----------|-----------|-------------|-------|
| Transports | 4 (UDP, TCP, TLS, TLS 1.3) | 5 (WS, WSS, SCTP, mTLS, TLS 1.2) | 9 |
| Registrar | 7 (Redis, expires, max contacts, hooks, TTL slack, Service-Route, registrant) | 3 (memory, PG, Python, GRUU) | 10 |
| Authentication | 6 (HTTP/HA1, digest 401/407, anti-spoof, Diameter Cx, IMS AKA) | 3 (static, local Milenage AKA, SHA-256) | 9 |
| Security | 5 (rate limit, scanner, trusted CIDR, fail ban, APIBan) | 1 (IP ACLs) | 6 |
| NAT | 5 (rport, fix contact, fix register, script fixup, stale eviction) | 3 (keepalive, CRLF keepalive, flow tokens) | 8 |
| Media | 1 (RTPEngine NG) | 6 (LB, 4 profiles, custom profiles) | 7 |
| Gateway routing | 3 (groups, round-robin, probes) | 4 (weighted, hash, failover, dynamic) | 7 |
| CDR | 0 | 5 (file, syslog, HTTP, register events, extra fields) | 5 |
| Tracing | 3 (HEP v3 UDP, agent ID, error suppression) | 2 (TCP, TLS) | 5 |
| Metrics | 8 (Prometheus, all gauges/counters/histograms) | 3 (admin health, stats, registrations) | 11 |
| Scripting | 14 (proxy, B2BUA, registrar, auth, gateway, cache, presence, logging, metrics, async, ...) | 3 (LI, timer, SDK) | 17 |
| 3GPP/IMS | 10 (Cx, Sh, Rx, peer mgmt, IMS AKA HSS-backed, IPsec, iFC, P/I/S-CSCF, Npcf) | 4 (Ro, Rf, local Milenage AKA, Nchf) | 14 |
| LI/Recording | 0 | 5 (X1, X2, X3, SIPREC, audit) | 5 |
| **Totals** | **~66** | **~42** | **~109** |
