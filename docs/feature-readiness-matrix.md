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
| B2BUA (RFC 3261 §6) | **Production** | `script: @b2bua.on_invite` | Two-leg call control, per-leg Call-ID + From-tag, topology hiding. The `call.fork`/`call.dial` `timeout=` (default 30s) is now enforced: a B-leg INVITE sent fire-and-forget (no client transaction, so no Timer B) that never produces a final 2xx — dead/partitioned trunk — is failed within `timeout`..`timeout+30s` by the orphan sweep (`fail_b2bua_call_on_timeout`): CANCEL pending legs, `@b2bua.on_failure(408)`, `408 Request Timeout` to the A-leg, teardown. Previously the call leaked until the 24h orphan backstop. Unit-tested in `take_timed_out_calls_only_unanswered_past_deadline`. Outbound auth-retry 2xx ACK: a B-leg INVITE to an authenticating trunk (401/407 → credentialed CSeq-2 retry) is superseded in place (`replace_b_leg`), which drops the failed leg's actor handle so that actor emits `CallEvent::Terminated` onto the SHARED per-call classification channel. The dispatcher block-recvs that channel per response; consuming the stale `Terminated` desynced the stream so the retry leg's 200 OK was misclassified as the prior 18x's provisional — `set_winner` and the deferred B-leg ACK (RFC 3261 §14.1 late-ACK) were skipped, so the trunk's 200 OK retransmitted unacked and the call collapsed into a BYE storm ~5 s after answer (all outbound PSTN to an authenticating trunk). Fixed by `recv_b_leg_classification_event` skipping `Terminated` lifecycle events when reading a response classification (regression-tested in `dispatcher::tests::b_leg_200_classifies_as_answered_after_auth_retry_supersede`). Outbound retry member affinity (RFC 5923): the 401/407 credentialed re-INVITE and the RFC 4028 422 higher-Session-Expires re-INVITE are fresh pre-dialog transactions (new branch + CSeq, no To-tag), so the in-dialog connection-reuse path did not cover them — they re-resolved the trunk hostname and the RFC 3263 §4.2 A/AAAA shuffle could land the retry on a *different* member of a multi-member trunk (one DNS name) than the one that issued the nonce, drawing a second 401 on a strict trunk (auth loop) or splitting one INVITE transaction across two members (fragile CANCEL/BYE/session-timer correlation). Both retries now reuse the failed leg's established destination/transport/connection_id (`select_b2bua_retry_destination`) so the whole transaction stays on the nonce-issuing member; falls back to fresh DNS resolution only when the leg has no recorded destination (regression-tested in `dispatcher::tests::b2bua_retry_reuses_established_member_not_resolved_sibling`) |
| Parallel forking | **Production** | `request.fork()` | Used for AS→subscriber delivery |
| Sequential forking | Implemented | `request.fork(strategy="sequential")` | |
| Record-Route / Loose Route | **Production** | `request.record_route()` | Mid-dialog routing proven |
| CANCEL propagation | **Production** | Core | Matched to transaction automatically. Proxy-forwarded CANCEL reuses the INVITE branch + sent-by on the topmost Via per RFC 3261 §9.1/§16.10, so the downstream proxy/UAS matches CANCEL→INVITE (§17.2.3) and tears the alerting branch down — fixed a defect where `handle_cancel_via_session` minted a fresh branch, making the CANCEL unmatchable downstream so the callee kept ringing after the caller abandoned (regression-tested in `dispatcher::tests::proxy_cancel_via_*`). B2BUA CANCEL path (`build_cancel_from_invite`) builds the correct per-leg branch; additionally fixed a defect where a 401/407 digest or RFC 4028 422 retry on an outbound INVITE *appended* a fresh B-leg instead of superseding the failed one, so a caller CANCEL during alerting fanned out to the dead pre-auth transaction too (→ a spurious 481, RFC 3261 §9.1). Retries now replace the leg in place (`CallActorStore::replace_b_leg`), so CANCEL targets only the live branch (regression-tested in `b2bua_auth_retry_supersedes_failed_leg_for_single_cancel`). 2xx-after-CANCEL glare (RFC 3261 §9.1): when the callee answers a B-leg INVITE in the cancel window, the B2BUA used to drop the racing 200 OK as an unknown branch (the call was already removed), leaving the callee retransmitting 200 OK then BYEing the half-open dialog. `handle_b2bua_cancel` now preserves still-pending B-legs as `zombie_cancelled` entries (32 s window); the racing 2xx is ACKed (§13.2.2.4) and immediately BYEd (§15) by `handle_zombie_cancelled_2xx`. |
| In-dialog sequential routing | **Production** | `request.loose_route()` | End-to-end 2xx ACK follows the dialog route set (top remaining Route after self-consumption, else R-URI), not the cached INVITE next-hop — correct through non-Record-Routing hops (transparent iFC AS, I-CSCF). RFC 5923 connection reuse: when the route-set next hop still resolves to the peer the dialog was established with, in-dialog requests (B2BUA BYE/re-INVITE/UPDATE/PRACK/2xx-ACK, proxy 2xx-ACK) keep the established connection/address instead of re-resolving — so a load-balanced trunk behind one DNS name (load-balanced Record-Route) is not re-shuffled (RFC 3263 §4.2) onto a sibling member that holds no dialog state; still resolves fresh for a genuinely divergent next hop. Validated proxy/B2BUA × UDP/TCP, 0 failures/retransmits |
| UAC-originated pre-loaded Route | **Production** | `proxy.send_request(headers={"Route": "<sip:host;lr>"})` | Next-hop selection for a script-originated out-of-dialog request now follows RFC 3261 §8.1.2 / §16.4: when the `headers` carry a `Route` (a pre-loaded route set) and no explicit `next_hop`, the request is sent to the first `Route` entry's `;lr` loose-route target — the R-URI stays in the Request-Line and the Route rides along. Previously the Route was carried but ignored, and the destination was always resolved from the R-URI's home domain, so a script pre-loading the serving S-CSCF (e.g. MMTel-AS reg-event SUBSCRIBE/refresh/UN-SUBSCRIBE) took an extra I-CSCF hop + Cx LIR/LIA per operation. Precedence: explicit `next_hop` > first `Route` URI > R-URI. Regression-tested end-to-end (`send_request_python_kwargs_preserve_body_and_content_type` scenarios 5–6) + unit-tested (`resolve_send_target_*`, `route_next_hop_*`, `parse_first_route_uri_*`) |
| Call transfer (REFER, RFC 3515) | Implemented | B2BUA `@b2bua.on_refer` | |
| Cancel teardown hook | Implemented | `@proxy.on_cancel` / `@b2bua.on_cancel` | Fires once when a relayed (proxy) or B2BUA INVITE is CANCELled before a final response (RFC 3261 §9) — the only script teardown signal for a cancelled-before-answer call, which neither `on_reply`/`on_failure` (proxy: the 487 is generated at the transaction layer, never reaching a reply handler) nor `on_bye` (b2bua: no dialog was ever established) deliver. Receives the original INVITE (proxy `fn(request)`) / the Call (b2bua `fn(call)`); fire-and-forget, does not gate the 487. Exists to release per-call resources no BYE will ever clear (Diameter Rx/N5 QoS sessions, rtpengine media anchors). The B2BUA hook fires only in Calling/Ringing, so a 2xx that wins the cancel/answer glare (independently ACK+BYE'd by `handle_zombie_cancelled_2xx`) never triggers it — no answered call is torn down. Engine-registration unit tests (`script::engine::tests::{proxy,b2bua}_on_cancel_decorator_registers_handler`) + SDK dispatch tests (`sdk/tests/test_on_cancel.py`). |
| Reply-time proxy reject | Implemented | `reply.reject(code, reason)` (in `@proxy.on_reply`) | Fail an in-progress proxied INVITE from the reply context — the proxy-side equivalent of B2BUA `call.reject()`, needed because IMS P-CSCF media authorization (N5 `sbi.create_session` / Rx `diameter.rx_aar`) runs at answer time, when the negotiated SDP is available, and a failure must reject the leg (e.g. `503`) rather than proceed medialess. On a **provisional (1xx)** — typically a reliable `183` in the VoLTE preconditions / early-media flow where the SDP answer rides the provisional — records the reject and returns `True`; the dispatcher then sends `code reason` upstream to the UAC via the server transaction (retransmission + UAC-ACK absorption) and CANCELs every pending downstream branch (reusing `cancel_fork_branches`, RFC 3261 §9). The straggler `487` the CANCEL draws back is absorbed via a new `ProxySession.final_response_sent` guard (the single-target relay path has no fork-aggregator `final_forwarded` to dedup it), so no second final reaches the UAC. On a **final (≥200)** — UAS already answered — it is a no-op returning `False` (a proxy cannot retract a 2xx); the script branches on the bool (log + `reply.relay()`, best-effort). Takes precedence over `relay()`. Unit-tested (`script::api::reply::tests` decision logic + `proxy::session::tests` flag) + SDK-mirrored/tested (`reply.reject`, `sdk/tests/test_reply_reject.py`). End-to-end SIPp-validated (`sipp/reject_{uac,uas}.xml` + `reject_proxy.py`): caller gets `100`→`503 Media Authorization Failed` (To-tag added, 183 suppressed), UAS gets the CANCEL on the INVITE's Via branch (RFC 3261 §9.1) and its `487` is ACKed and absorbed — both endpoints 1 Successful / 0 Failed / 0 Retrans / 0 Unexpected, siphon 0 WARN/ERROR. SIPp validation also surfaced + fixed a pre-existing loop: a non-compliant ACK (fresh branch instead of the INVITE's, §17.1.1.3) carrying the 503's To-tag + an R-URI pointing at the proxy was matched by `by_dialog_key` and relayed to the proxy's own address in `handle_ack_via_session`, stacking a Via per hop until the datagram exceeded the 8192-byte UDP buffer (truncated → parse-error drop). Two guards: (1) reject now drops the dead `by_dialog_key` entry (`ProxySessionStore::remove_dialog_key` — a rejected INVITE forms no dialog), and (2) `handle_ack_via_session` reuses the existing `is_own_address` loop check to silently drop an ACK whose resolved next-hop is one of our own listeners (RFC 3261 §16.3). |
| Session timers (RFC 4028) | Implemented | `session_timer:` | UAC/UAS/B2BUA refresher modes |
| PRACK (RFC 3262) | Implemented | Core | Reliable provisional responses; B2BUA terminates 100rel per-leg — auto-PRACKs a reliable-provisional B-leg and strips `Require:100rel`/`RSeq` toward a non-100rel A-leg (framework-auto, preset-independent) |

## Transports

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| TCP | **Production** | `listen.tcp` | AS-facing; RFC 3261 §18.3 stream framing with Content-Length extraction; outbound distributor falls back to the `ConnectionPool` when an `OutboundMessage` arrives without a matching inbound connection (covers UAC fire-and-forget paths like in-dialog NOTIFY from `subscribe_state.notify()` whose Route header points at a destination with no live inbound socket — previously the message was built but silently dropped at the connection-map lookup). **Wedge-hardened (all stream transports):** the per-listener outbound distributor routes with a non-blocking `try_send` instead of `send().await`. A single non-reading peer (toll-fraud scanner that never ACKs its 401s, or a stream peer whose far end stalls) fills its bounded per-connection channel; an awaiting send parked there while holding the `connection_map` shard read guard, stalling outbound for **every** connection (head-of-line) and blocking the accept loop's `insert` on the same shard — accept stops, the backlog fills, the engine wedges (no logs) until restart. `try_send` keeps the guard only for the synchronous send and sheds a backed-up peer. Reproduced + regression-guarded black-box on a real container at `--cpus 0.5` by `scripts/wedge_test.sh` (`run-tests.sh --wedge`) — probe times out pre-fix, answered post-fix. **Outbound `ConnectionPool` establishment hardened:** the connect is bounded by a fail-fast timeout (`TCP_CONNECT_TIMEOUT`, 5 s) so a doomed ESP-over-TCP send to a UE whose IPsec SA was just torn down (no SYN-ACK, no RST) can no longer block the PyExecutor worker indefinitely and trip the script-executor watchdog → process abort; and concurrent first-sends to the same destination coalesce onto one connection under a per-destination lock, so the fixed protected source port (`pcscf_port_c`) cannot hit `EADDRNOTAVAIL`/`EADDRINUSE` on a second `bind`/`connect` of the same 4-tuple. Regression-guarded by `connect_fails_fast_to_blackhole` and `concurrent_sends_coalesce_onto_one_connection` in `transport::pool` |
| TLS | **Production** | `listen.tls` | Subscriber-facing, TLS 1.3 validated; RFC 3261 §18.3 stream framing; outbound distributor wedge-hardened with non-blocking `try_send` (see TCP) |
| TLS 1.3 | **Production** | `tls.method: TLSv1_3` | |
| TLS 1.2 | Implemented | `tls.method: TLSv1_2` | |
| mTLS — inbound (verify client cert) | Implemented | `tls.verify_client: true`, `tls.client_ca` | Client certificate required and verified against the `tls.client_ca` PEM bundle; applies to `listen.tls` **and** `listen.wss` (shared TLS block). Fails closed at startup if `verify_client` is set without `client_ca` (previously `verify_client` was silently ignored on the SIP listener — read only by the X1 LI interface). TLS handshake bounded by a 10 s timeout (half-open-handshake / slowloris defense). |
| mTLS — outbound (present client cert) | Implemented | `tls.client_certificate`, `tls.client_private_key` | Siphon presents this client certificate on outbound TLS connections whose peer requests one — for upstream SIP trunks requiring client-certificate / mutual TLS (e.g. Teams Direct Routing), which previously aborted the handshake with `CertificateUnknown` because the outbound pool presented no client cert. Both fields must be set together or neither; a one-sided setting or an unreadable/unparseable file is a hard startup error (fail closed). Server-certificate verification is unchanged (permissive). Unit-tested against a real handshake (mandatory-mTLS server built with `rcgen`): matching identity succeeds, no identity is rejected. |
| Outbound TLS SNI (RFC 6066) | Implemented | automatic | Outbound TLS handshakes present the resolved target hostname as SNI / certificate name instead of the destination IP literal (rustls sends no SNI for an IP). The hostname flows from the resolved SIP URI through relay, fork, and the gateway TLS health probe into the connection pool; bare-IP next hops send no SNI (unchanged). |
| UDP | **Production** | `listen.udp` | |
| WebSocket (WS) | Implemented | `listen.ws` | RFC 7118, browser/WebRTC clients; outbound distributor wedge-hardened with non-blocking `try_send` (see TCP). MT routing (INVITE → WS-registered UE) works via RFC 5626 §5.3 connection reuse: every binding captures its inbound flow (no `flow_token=` needed), `registrar.lookup()` returns it as `contact.flow`, and `request.fork(contacts)` / `request.relay(flow=)` / `call.fork(contacts)` / `call.dial(flow=)` route over the captured connection on both proxy and B2BUA. Connections register in a unified cross-transport `StreamConnections` registry (also backs `Flow.is_alive`); `send_to_target` has a WS/WSS arm that reuses the connection and drops (no caller-echo) on miss. |
| Secure WebSocket (WSS) | Implemented | `listen.wss` | Outbound distributor wedge-hardened with non-blocking `try_send` (see TCP). MT routing via connection reuse — same flow-based path as WS (see the WS row). |
| SCTP | Implemented | `listen.sctp` | RFC 4168, IMS inter-node; outbound distributor wedge-hardened with non-blocking `try_send` (see TCP) |
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
| Bind AoR to authenticated user | Implemented | `registrar.enforce_auth_aor_match` | Rejects (403) a REGISTER whose AoR (To-URI user) ≠ the authenticated digest user — anti account-takeover / forced-deregister. Checked **before** the force-clear so a spoofed AoR can't first wipe the victim's bindings. Default off (IMS deployments authorize via the implicit registration set, where the public identity ≠ private auth identity). |
| Redis TTL slack | **Production** | `registrar.redis.ttl_slack_secs` | Race condition buffer |
| GRUU (RFC 5627) | Implemented | | |
| Service-Route (RFC 3608) | **Production** | | Via `registrar.set_service_routes()` / `service_route()` |
| Registration state change hooks | **Production** | `@registrar.on_change` | Callbacks on insert/delete/expire |
| Liveness — flow-failure dereg (RFC 5626 §4.2.2) | Implemented | `registrar.liveness.enabled` | TCP/TLS/WS/WSS connection close (peer FIN/RST, read error, idle timeout, or CRLF-keepalive failure) deregisters the bindings that arrived on that connection. Transport notifies the registrar over a close channel → `Registrar::unregister_flow(connection_id)`, which uses a `ConnectionId → AoR` reverse index (`connection_index`) to drop only the affected bindings (O(bindings-for-that-connection), scanner-churn-safe) and emit `Deregistered`. Default off. |
| Liveness — IPsec idle dereg (UDP + TCP/TLS/WS) | Implemented | `registrar.liveness.{enabled,keepalive_interval_secs,idle_multiplier,probe_timeout_ms}` | Detects a dead UE on the production Gm without a SIP de-REGISTER, on **any** SIP transport — the XFRM SA use-time is the liveness signal, so a TCP+IPsec registration whose UE silently dies (radio loss, no FIN/RST) is reaped on the same ~`idle_multiplier × keepalive_interval` window as a UDP UE, rather than waiting for the CRLF-keepalive timeout (minutes). The 30 s sweep polls kernel XFRM SA inbound use-time (one `XFRM_MSG_GETSA` netlink dump — no per-packet hot-path cost; the UE's RFC 6223 keepalive keeps the SA warm); eligibility is by SA match (UE IP), which naturally excludes non-IPsec bindings. A suspect binding is probed with one OPTIONS over its actual transport (stream probes ride the captured inbound connection); no answer → deregister. SA teardown (`sweep_expired`) also drops the matching binding. EPC-independent backstop for SMF crash / PCRF-no-Rx-ASR / silent radio loss. Idle-probe path needs kernel XFRM + lab validation. Default off. |
| Liveness — network dereg cascade | Implemented | `registrar.liveness.dereg_mode: network_dereg\|local_only` | Removing a binding emits `Deregistered` → `@registrar.on_change` (the authoritative/S-CSCF path; the script sends the terminated reg-event NOTIFY). For a P-CSCF cache binding (carries a `flow_token`) under `network_dereg`, also synthesizes a de-REGISTER (`Expires: 0`) on the UE's behalf routed via the stored Service-Route so the registrar of record clears it too. `local_only` skips the upstream REGISTER. Network-dereg routing needs a split P-CSCF/S-CSCF lab to validate end-to-end. |
| Outbound registration (registrant) | **Production** | `registrant:` | UAC REGISTER to upstream trunks |
| IMS UE registration (soft-UE, AKA + IPsec sec-agree) | Implemented | `registration.add(auth="aka", k=, opc=, ipsec=True, ue_port_c=, ue_port_s=)` or YAML `registrant.entries[].{auth: aka, aka:, ipsec:}` | siphon registers INTO an IMS core as a handset: IMS-AKAv1-MD5 (RFC 3310 — RES is the binary digest password) over IPsec sec-agree (3GPP TS 33.203). Milenage `f1*`/`f5*`/AUTS re-sync (TS 35.208 Test Set 1 vectors). Initial REGISTER offers `Security-Client` (UE SPIs/ports + `Require: sec-agree`); the 401 records `Security-Server`; the protected re-REGISTER echoes `Security-Verify` and egresses from the UE protected client port over the four UE-side SAs (`create_ue_sa_pair` — same netlink + CK/IK derivation as the P-CSCF, only the four XFRM policy directions mirror via `SaRole`); the protected 200 OK tightens the SA hard-lifetime to the granted Expires + Timer-F grace. Service-Route / P-Associated-URI captured for MO routing; AUTS re-sync is a fallback (a fresh stateless UE never emits it). Message construction unit-tested against 3GPP/RFC vectors; the kernel SA install is root-gated. **NOT yet validated end-to-end against a live P-CSCF.** Example: `examples/ims_ue_b2bua.{py,yaml}`. |
| IMS UE B2BUA bridge (plain SIP ↔ IMS) | Implemented | `examples/ims_ue_b2bua.py`, `call.dial(flow=, route=)`, `registration.flow()`/`service_route()` | Bidirectional B2BUA over the soft-UE registration. MT (IMS→tester): the protected-port A-leg bridges to a plain-SIP tester; A-leg responses egress back over the SA via inbound-flow pinning. MO (tester→IMS): dials the B-leg over the UE→P-CSCF SA flow (`registration.flow(impu, ue_ip)` → `call.dial(flow=)`, sourced from the UE protected client port), carrying the captured Service-Route (`registration.service_route(impu)` → `call.dial(route=)`) and asserting the IMPU via `P-Preferred-Identity` (intra-trust preset preserves P-*). Direction detected by `call.source_ip == pcscf`. SDK-tested both directions (`sdk/tests/test_ims_ue_b2bua.py`); needs live-core + root validation. |
| Proxy-side binding cache | Implemented | `registrar.save_proxy(request, reply)` | P-CSCF caches what S-CSCF granted; reads Expires from reply (not request), bypasses local `max_expires` cap, +32 s Timer F grace, no auto-200 OK (proxy relays upstream's response) |
| Path-token MT routing (RFC 3327 / TS 24.229 §5.2.7.2) | Implemented | `request.add_pcscf_path(token)`, `registrar.save(flow_token=)`/`save_proxy(flow_token=)`, `registrar.lookup_by_token(token)`, `request.relay(flow=binding.flow)`, `ipsec.path_host` | P-CSCF mints opaque token, embeds in Path userpart; binding stores token + captured inbound flow (source addr, listener local addr, accepted-connection id); MT routing bypasses DNS resolution and egresses from the same listener that received the REGISTER. UDP flow survives restart; TCP/TLS/WS/WSS bound to accepting instance lifetime. Via on flow-relay derives from `flow.local_addr` so IPSec port pairs are preserved (TS 33.203 §7.4). |
| AS-side contact capture (TS 24.229 §5.4.2.1.2) | Implemented | `registrar.save_as_contact(aor, reply)`, `Contact.params`, `Contact.kind` | S-CSCF script caches the AS's `Contact:` URI and RFC 3840 feature tags (`+g.3gpp.smsip`, `+g.3gpp.icsi-ref`, …) from the 3PR 200 OK; tags surface in `registrar.reginfo_xml(...)` as `<unknown-param>` children per RFC 3680 §5.3.2 so reg-event NOTIFY watchers see the iFC-matched capability set. AS contacts are excluded from `registrar.lookup()` (routing-side never picks them as MT targets) and cascade-clear when the last UE binding deregs/expires. |
| Contact-header parameter passthrough (RFC 3840) | Implemented | `Contact.params` | Every non-typed Contact-header parameter (anything outside `tag`/`q`/`expires`/`+sip.instance`/`reg-id`) round-trips through save → backend persistence → lookup → reg-event NOTIFY. Lowercased at parse time per RFC 3261 §19.1; values preserved verbatim. |

## Authentication

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Digest auth — 401 (UAS) | **Production** | `auth.require_digest()` | REGISTER challenges |
| Digest auth — 407 (proxy) | **Production** | `auth.require_proxy_digest()` | INVITE challenges |
| HTTP backend (HA1 lookup) | **Production** | `auth.backend: http` | REST credential lookup; optional per-username TTL cache (`auth.http.cache_ttl_secs`) flattens registration storms so repeat REGISTERs skip the blocking fetch |
| Static users backend | Implemented | `auth.backend: static` | Inline config credentials |
| Diameter Cx backend (HSS) | **Production** | `auth.backend: diameter_cx` | 3GPP TS 29.228 |
| AKA / AKAv1-MD5 (HSS-backed) | **Production** | `auth.require_ims_digest()` | 3GPP TS 33.203 via Cx MAR/MAA |
| AKA / AKAv1-MD5 (local Milenage) | Implemented | `auth.aka_credentials` | 3GPP TS 35.206 — local key derivation without HSS |
| SHA-256 digest (RFC 7616) | Implemented | | |
| Anti-spoofing (from=auth check) | **Production** | Script logic | `auth_user == from_uri.user` (caller-ID/From); the registrar-side AoR/To equivalent is `registrar.enforce_auth_aor_match` |
| Digest nonce replay protection (RFC 7616 §3.3) | Implemented | `auth.nonce_secret`, `auth.nonce_ttl_secs` | Nonces are timestamp-bound (`{unix_secs:016x}.{tag}`) and rejected once older than the TTL (default 3600 s), bounding captured-`Authorization` replay from "forever" to the window. Cross-instance safe with **no shared state** (correct behind round-robin DNS where a re-REGISTER may land on a different node). Optional shared `nonce_secret` adds HMAC-SHA256 integrity so a node rejects nonces the cluster never issued — must be identical on every instance behind the domain. Applies to the static + HTTP backends; the IMS/AKA paths use single-use HSS vectors. |

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
| Rate limiting (per source IP) | **Production** | `security.rate_limit` | PIKE-style fixed-window per-source-IP limiter. More than `max_requests` within `window_secs` → ban the source for `ban_duration_secs` (default 3600); every further request is dropped silently (no response — no fingerprinting). Enforced in the dispatcher on every inbound **request** before transaction/dialog/script processing, via the process-global `crate::security::SecurityFilter` (opt-in, installed only when configured). `trusted_cidrs` are exempt. 60s prune bounds the maps under scanner churn. Metric: `siphon_rate_limited_total`. Unit- + integration-tested (`security::tests`, `tests/integration/security_tests.rs`) |
| Scanner UA blocking | **Production** | `security.scanner_block` | Drops any inbound request whose `User-Agent` matches a configured signature (case-insensitive substring — sipvicious, friendly-scanner, VaxSip, sipcli, …). Silent drop in the dispatcher (no response), `trusted_cidrs` exempt, same `SecurityFilter` path as rate limiting. When `failed_auth_ban` is also configured, a match over a **connection-oriented** transport (TCP/TLS/WS/WSS/SCTP — source validated by the handshake) escalates to a strong-weight auto-ban so the scanner's other probes are dropped at the ACL too; a match over UDP is only dropped (spoofable source → no reflected ban). Metric: `siphon_scanner_blocked_total`. Unit- + integration-tested |
| Trusted CIDRs (bypass rate limit + scanner block) | **Production** | `security.trusted_cidrs` | Sources matching any CIDR bypass both the rate limiter and the scanner-UA block in `SecurityFilter` (own infra: AS/trunks/monitoring). Also exempted by `failed_auth_ban`'s auto-ban store. Invalid CIDRs are ignored. |
| Failed auth ban (auto-ban) | **Production** | `security.failed_auth_ban` | Per-source-IP auto-ban for toll-fraud scanners, fed by **weighted** failure signals so high-confidence abuse bans faster than a bare probe (`strong_signal_weight`, default 3, vs weight 1). **Weight-1 (low-confidence):** an auth challenge (401/407) not followed by a success; a non-ACK INVITE server-transaction timeout (RFC 3261 §17.2.1 Timer H); a failed/timed-out TLS/WSS/WS handshake. **Strong-weight (high-confidence):** present-but-invalid digest credentials or a forged/stale/replayed nonce (kept weight-1 over UDP, where the source is spoofable → reflected-ban-safe); non-SIP/unparseable bytes on a TCP/TLS stream (HTTP probe, TLS record on the plaintext port, binary garbage, over-long header block — never an incomplete-but-plausible frame, empty connection, or CRLF keepalive); a `scanner_block` User-Agent hit over a connection-oriented transport (UDP scanner UAs are dropped, not banned). A successful auth resets the source's count, so a legit challenge→succeed (or stale-nonce retry) client never accumulates. `threshold` weighted failures within `window_secs` → ban for `ban_duration_secs` (default 10 / 600 / 3600). `trusted_cidrs` are exempt (own infra: BGCF/trunks/monitoring/health-check LBs) — client-transaction (relay-target) timeouts are also deliberately *not* counted, so a non-answering trunk is never banned. Enforced at **accept/recv** on every transport via `TransportAcl::is_allowed` (dropped before any SIP parsing). Process-global store (`crate::security::AutoBanStore`, opt-in), lazy ban-expiry + 60s prune. Metrics: `siphon_banned_ips`, `siphon_auth_failures_total`, `siphon_credential_failures_total`, `siphon_handshake_failures_total`, `siphon_malformed_messages_total`. Unit-tested (`security::tests`, `transport::tcp::tests`) |
| APIBan integration | **Production** | `security.apiban` | Community IP blocklist polling |
| IP ACLs (allow/deny CIDR lists) | Implemented | Transport-level ACL | |
| Preloaded Route rejection | **Production** | Script logic | Anti-abuse for Route header |

## NAT Traversal

| Feature | Readiness | Config | Notes |
|---------|-----------|--------|-------|
| Symmetric response routing (rport, RFC 3581/6314) | **Production** | always on | Responses always go to the request source; no `force_rport` knob needed |
| Fix Contact (observed source) | **Production** | `nat.fix_contact: true` | Rewrites the Contact on responses |
| REGISTER source capture | **Production** | automatic in `registrar.save()` | Stored as `Contact.received` / `Contact.flow` for MT routing |
| Fix NATed Contact / REGISTER (script) | **Production** | `request.fix_nated_contact()` / `fix_nated_register()` | Explicit REGISTER-side fixups |
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
| Source-membership predicate | Implemented | Python `request.from_gateway()` / `call.from_gateway()` | `ds_is_from_list()` / `ds_is_in_list()` equivalent; IP-only match against all resolved group addresses, cached + refreshed on probe cycle. Trust signal on TCP/TLS/WS/WSS, direction hint on UDP |

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
| Proxy handlers (on_request/on_reply/on_failure) | **Production** | `@proxy.*` | on_request + on_reply proven. Per-relay `request.relay(on_reply=…)` / `request.relay(on_failure=…)` callbacks now fire correctly on the free-threaded build: the dispatcher response path lifted the stored `on_reply`/`on_failure` `Py<…>` callbacks out of the session read-guard with a bare `Clone` on a Python-executor worker that was not inside a `Python::attach` scope. Under free-threaded CPython (3.14t, pyo3 0.28) `Py::clone` panics ("Cannot clone pointer into Python heap without the thread being attached") unless the thread is attached, unwinding the worker mid-relay — which truncated the in-flight relayed request and failed every call that armed a per-relay callback (blocked reply-driven MMTel behaviours: CFNR / busy-on-200 OK marking). Fixed by `ProxySession::clone_relay_callbacks`, which clones through a `Python` token (`clone_ref`) under `Python::attach`, matching the request path's discipline (`script::handle::call_handler`). Regression-tested in `proxy::session::tests::clone_relay_callbacks_from_unattached_worker_thread` (clones the callbacks from a freshly spawned, never-attached OS thread). |
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
| Mock SDK for testing | Implemented | `siphon-sip` (imports as `siphon_sdk`) | Test scripts without Rust binary |
| Extension API (host namespaces, tasks, custom handler kinds) | Implemented | `extensions:`, `register_namespace`/`register_task`, `_siphon_registry.register("custom.kind", …)` | Open extension surface for custom transports / sinks; `ScriptHandle::handlers_for` + `call_handler` dispatch into script handlers from host extensions |
| Elastic handler pool (grow + bounded queue + watchdog) | **Production** | `script.sync_pool_size` / `sync_pool_max`, `executor_queue_capacity`, `handler_stall_abort_secs` | Pool grows core→max under blocking load and never reaps (no wedge, no heap leak); bounded queue load-sheds at the cap; deadlock-aware liveness watchdog aborts (→ supervisor restart) on zero forward progress while work is pending, at any pool fill (catches low-concurrency deadlocks). Blocking Rust-API calls release the interpreter (`py.detach`) to avoid the free-threaded GC stop-the-world deadlock. Regression-guarded by `pool_grows_under_blocking_load`, `detached_blocking_does_not_stall_gc`, and `run-tests.sh --http-auth`. Metrics: `siphon_pyexec_*`. See [handler-execution-model.md](handler-execution-model.md) |

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
| Diameter Sh (HSS user data) | **Production** | `diameter` | `sh_udr` for repository data; inbound PNR (profile push) handled via `@diameter.on_request` (`req.command_name == "PNR"`) |
| Diameter Ro (online charging) | Implemented | `diameter` | CCR/CCA |
| Diameter Rf (offline charging) | Implemented | `diameter`, `rf:` | ACR/ACA wired through `diameter.rf_acr_start/interim/stop/event` (TS 32.299 §6.2.2) — kwargs-style Python API, mandatory AVPs (`Service-Context-Id`, `Event-Timestamp`, `User-Name`, `Termination-Cause`, `Acct-Interim-Interval`), full IMS-Information sub-AVPs (`User-Session-Id`, `Time-Stamps`, `Inter-Operator-Identifier`, `Application-Server`, `IMS-Visited-Network-Identifier`), TS 32.260 IMS Service-Context-Id default. SMS-Information envelope (TS 32.299 §7.2.79) — passing any SMS-specific kwarg (`originator_address`, `recipient_address`, `sm_message_type`, `sms_node`, `sm_user_data_header`, `reply_path_requested`, `sm_service_type`, `sms_result`, SCCP/Client/MTC-IWF Address fields, `sm_discharge_time`, `data_coding_scheme`, …) switches the wire to `Service-Information → SMS-Information` so CDR collectors render calling/called party + message type on the SMS tab; can coexist with IMS-Information for hybrid records. `rf:` config block + `RfChargingService` runtime emits ACR-EVENT automatically on registrar state change. CDR auto-stamps `rf_session_id` / `rf_result_code` from auto-emitted records. B2BUA + proxy ACR-START/INTERIM/STOP auto-emit on call lifecycle is the next layer on the same infrastructure. |
| Diameter Rx (policy/QoS) | **Production** | `diameter` | AAR/AAA, STR/STA; inbound RAR/ASR handled via `@diameter.on_request` (`req.command_name`). `diameter.rx_aar(media_components=[…])` takes a list of TS 29.214 §5.3.7 `MediaComponent` dicts with per-flow IPFilterRules + Flow-Usage (RTCP marker) — pair with `qos.media_flows_from_sdp(offer, answer, direction)` to derive the full 5-tuple from an SDP offer/answer rather than emitting a wildcard `permit in 17 from <UE> to any` that any non-permissive PCEF would either drop or open globally. |
| Diameter S6c (SMS-over-Diameter, SMSC↔HSS) | Implemented | `diameter` | `s6c_srr` to discover served-node, `s6c_rsr` for delivery status; inbound ALR (HSS reachability alert) handled via `@diameter.on_request` (TS 29.336). MSISDN / SC-Address / SGSN-Number / MME-Number-for-MT-SMS encoded as ISDN-AddressString (TS 29.002 §17.7.8 — ToN/NPI 0x91 + TBCD digits); inbound parser is lenient on missing ToN/NPI prefix for non-conformant peers. |
| Diameter SGd (SMS-over-NAS, SMSC↔MME) | Implemented | `diameter` | `sgd_tfr` to deliver SMS-DELIVER TPDU to UE; inbound OFR (MO-SMS) handled via `@diameter.on_request` (TS 29.338). SC-Address on the wire uses ISDN-AddressString (TS 29.002 §17.7.8), matching S6c. |
| Diameter S6a (MME↔HSS, LTE attach/auth) | Implemented | `diameter.s6a_air/s6a_ulr/s6a_purge_ue` (client); `@diameter.on_request` + `req.answer()` (server) | TS 29.272 — **client**: AIR/AIA (E-UTRAN vectors RAND/XRES/AUTN/KASME, SQN resync), ULR/ULA, PUR/PUA. **Server (HSS role)**: siphon transports inbound AIR/ULR/PUR to `@diameter.on_request`; the script builds the answer with `req.answer(code)` + grouped-AVP construction. siphon does NOT implement S6a semantics or Milenage — the script owns subscriber data + auth-vector crypto (see `examples/hss_s6a.py`). Relayable by a server-mode script. Dictionary AVPs 1400–1450/1635 + command codes 316–324. |
| Diameter generic answer + grouped AVPs (server) | Implemented | `req.answer(result_code)`, `DiameterRequest/DiameterAnswer.{get,set,insert}_avp` | Application-agnostic inbound serving: build a local answer envelope and construct/read arbitrarily nested **Grouped** AVPs from Python (`list` of `(code, value[, vendor])` child tuples; values may nest). Lets a script serve any Diameter application (HSS/PCRF/OCS) on the inbound listener — siphon transports, Python decides. |
| Diameter serve-on-outbound (dial-out + serve) | Implemented | `diameter.connect_to` | A server NF that **initiates** the connection (e.g. an HSS dialling an upstream) but **answers** the requests relayed back over it. siphon sends the CER, then routes inbound requests to `@diameter.on_request` exactly like the listener path — transport direction is independent of request direction (RFC 6733 §2.1). Works without `diameter.listen`. TCP + SCTP. |
| Diameter generic API (spec-name addressing) | Implemented | `diameter.send_request("Send-Routing-Info-for-SM-Request", application="S6c", **avps)` (originate); `@diameter.on_request` + `req.command_name` (serve) | Outbound origination by spec name (AVPs encoded by dictionary type, snake_case ↔ kebab-case kwargs, 3-letter acronym aliases SRR/ALR/TFR/…). Inbound serving is the single unified `@on_request` hook — the old per-command `@on_command` was removed. |
| Diameter peer management | **Production** | `diameter.peers` | Failover + round-robin across HSS/PCRF peers |
| Diameter server mode | Implemented | `diameter.listen`, `diameter.clients`, `diameter.servers`, `@diameter.on_inbound_cer`, `@diameter.on_request`, `@diameter.on_reply`, `@diameter.on_request_completed` | Accepts inbound Diameter (TCP + SCTP), runs CER/CEA + the DWR/DWA watchdog, and dispatches each inbound request to Python — siphon transports, the script decides (answer locally or relay). Two Rust-only admission gates (source-IP CIDR ACL + Origin-Host validation, both before any Python), lossless AVP tree (`DiameterRequest`/`DiameterAnswer` get/set/remove/insert/iter), `req.forward_to(peer)` relay with Route-Record loop detection (3005) + per-call timeout, `@diameter.on_reply` for central answer-AVP rewrite (topology hiding, Origin/Result-Code mapping), `diameter.peer_pool(target)` (round-robin / weighted / sticky over state-as-truth liveness), `diameter.config` snapshot (no YAML hot-reload), `diameter.event_sink` (file/none; clickhouse/kafka feature-gated). `None`→3002. Inbound **and** outbound TCP+SCTP (`peer::connect_with_transport`). The ClickHouse/Kafka sinks are follow-ups. See `examples/diameter_server.{py,yaml}`. |
| AKA authentication (Milenage, local) | Implemented | `auth.aka_credentials` | 3GPP TS 35.206 — local key derivation without HSS |
| AKA authentication (HSS-backed) | **Production** | `auth.require_ims_digest()` | 3GPP TS 33.203 via Cx MAR/MAA |
| IPsec SA management (P-CSCF) | Implemented | `ipsec` | Shared protected client/server ports; SAs installed via direct XFRM netlink (Phase 3) with `ip xfrm` shell-out as fallback backend |
| IPsec sec-agree primitives (script-driven) | Implemented | `siphon.ipsec`, `request.parse_security_client()`, `reply.take_av()` | 3GPP TS 33.203 §6 + RFC 3329; HMAC-SHA-1-96 / HMAC-MD5-96 / HMAC-SHA-256-128 with NULL or AES-CBC-128; Annex H key derivation; registration-tied lifetimes; IPv6; multi-instance SPI partitioning; multi-protocol XFRM selectors (TS 33.203 §7.2 — one SPI pair covers both ESP-over-UDP and ESP-over-TCP, required for iOS UEs mixing REGISTER/TCP with MO MESSAGE/UDP) |
| IPsec SA hard-lifetime repin on grant | Implemented | `pending.activate(hard_lifetime_secs=…)` | XFRM_MSG_UPDSA on all four SAs; tightens kernel lifetime from the placeholder (UE's `Expires` ask, often 600000 s) to the registrar's grant on the 200 OK to auth REGISTER (3GPP TS 33.203 §7.4); kernel preserves `add_time` so deadline = original install + new value |
| IPsec SA hard-lifetime repin on REGISTER refresh | Implemented | automatic in `registrar.save_proxy`/`save` | 3GPP TS 33.203 §7.4: an IPsec-protected REGISTER **refresh** extends the bound SA pair's hard lifetime to the granted binding lifetime (granted Expires + 32 s Timer-F grace). IR.92 refreshes carry no AKA challenge (200-without-401 → no `PendingSA` → `activate` never fires), so this registrar hook is the only path that moves the SA forward on a refresh; without it an actively-refreshing UE's SA aged out at last-AKA + grace and was reaped + network-de-REGISTERed (live VoLTE/VoNR outage). The re-pin adds elapsed-since-install to the kernel `hard_add_expires_seconds` because XFRM_MSG_UPDSA preserves `add_time` (`IpsecManager::update_sa_pair_lifetime` keyed off `SecurityAssociationPair::created_at`), so the kernel deadline actually advances rather than staying pinned to the original install. Unit-tested (`ipsec::tests` elapsed-math + anchor-stability via mock kernel); needs root + live-core validation. |
| IPsec stale-pair cleanup on re-REGISTER | Implemented | `pending.activate()` (automatic) | UE picks a fresh random `port_uc` on every REGISTER (TS 24.229 §5.1.1.2); without this, the manager's `(ue_addr, port_uc)`-keyed bookkeeping accumulated one entry per refresh and the prior pair's four XFRM policies leaked into the kernel forever. After enough cycles a new `port_uc` collided with a leaked selector and policy install hit `EEXIST`, breaking the registration. Activate now fire-and-forgets `cleanup_other_pairs_for_ue` to tear down every prior pair for the same UE address; the new pair (different `port_uc` by construction) installs cleanly. |
| Initial Filter Criteria (iFC) | **Production** | `isc` | XML trigger-point matching + per-user profile storage from Cx SAR |
| IMS P-CSCF role | **Production** | Example `examples/ims_pcscf.{py,yaml}` | |
| IMS I-CSCF role | **Production** | Example `examples/ims_icscf.{py,yaml}` | |
| IMS S-CSCF role | **Production** | Example `examples/ims_scscf.{py,yaml}` | |
| 5G SBI — Npcf (policy) | Implemented | `sbi` | N5 app-session for VoNR QoS. `sbi.create_session(media_components=[…])` builds the spec-correct TS 29.514 `AppSessionContext`: request data nested under **`ascReqData`** (a flat body left the PCF reading `ueIpv4` as null → session created but never bound), `medComponents`/`medSubComps` as **maps** keyed by `medCompN`/`fNum` (not arrays) with the exact wire names `medCompN`/`medType`/`fStatus`/`codecs`/`fDescs`/`flowUsage` and hyphenated `ENABLED-UPLINK`/`ENABLED-DOWNLINK` so PCF gating works on real UPFs; same dict shape as `diameter.rx_aar`. The created `appSessionId` is taken from the `201` `Location` header (it is not a body field); modify is an `application/merge-patch+json` PATCH. Per-call `pcf_uri=` addresses a session at a discovered PCF instead of the static `npcf_url`; create returns `app_session_uri` and update/delete accept it for replica-independent teardown. Wire format corrected after a live open5gs trace exposed the missing envelope; message-level + SDK tested (axum body-capture asserts the `ascReqData` envelope and `medComponents` map on the wire), live re-validation against the open5gs PCF pending. Inbound PCF event notifications (`@sbi.on_event`, TS 29.514 `EventsNotification`) are now passed to the script **verbatim** as a dict — previously they were projected through a lossy typed struct that dropped the required `evSubsUri` correlation key and `422`'d (silently lost) any notification carrying `flows` (the spec shape is `{medCompN, fNums}`, not `{flowId}`). |
| 5G SBI — Nbsf (PCF discovery) | Implemented | `sbi.discover_pcf_binding`, `sbi.bsf_url` | Nbsf_Management `pcfBindings` lookup keyed on the UE IP (TS 29.521) — the reliable 5G-vs-4G discriminator a P-CSCF uses to pick N5 vs Rx per session. `200`→binding dict (incl. ready-to-use `pcf_uri`), `404`→`None` (4G), `5xx`/timeout→`sbi.BsfError`. Message-level + SDK tested (axum mock); not yet validated against a live open5gs BSF. |
| 5G SBI — SCP indirect communication | Implemented | `sbi.communication: indirect` | Spec-compliant indirect routing via the SCP (TS 29.500 §6.10). Npcf Model C emits `3gpp-Sbi-Target-apiRoot` (the PCF known from the BSF binding); Nbsf Model D (delegated discovery) emits `3gpp-Sbi-Discovery-target-nf-type: BSF` / `service-names: nbsf-management` / `requester-nf-type` (default `AF`). `direct` (default) is byte-identical to today. Header-level tested (axum mock); not yet validated against a live SCP. |
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
