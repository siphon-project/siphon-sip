# Changelog

All notable changes to SIPhon are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is lockstep across
the `siphon-sip` crate and the `siphon-sip` Python SDK, driven by the git tag.

## [Unreleased]

_Codename: bjorn._

### Added
- **CORS for the `/metrics` and admin HTTP endpoints.** A browser dashboard
  served from a different origin can now `fetch()` the Prometheus `/metrics`
  listener and/or the admin API — previously the browser hid the response
  because no `Access-Control-Allow-Origin` header was sent. Opt in per endpoint
  with `metrics.prometheus.cors.allowed_origins: [ ... ]` and/or
  `admin.cors.allowed_origins: [ ... ]` (full origins including scheme and
  port; a single `"*"` allows any origin, but an explicit list is recommended
  — the admin API can force-unregister AoRs and lift bans). Omitting the block
  emits no CORS headers, so same-origin callers and Prometheus scrapers are
  unaffected. The layer also answers CORS preflight (`OPTIONS`) requests, so a
  dashboard that sends custom headers or hits the admin `DELETE` routes works.
- **Scripts can `import` sibling `.py` helper modules.** A script's own directory
  is now added to the Python `sys.path`, so `import helpers` resolves a
  `helpers.py` sitting next to the main script — no `sys.path.insert` boilerplate.
  A new `script.include_paths: [ ... ]` config lists extra directories to add for
  helper libraries shared across scripts (e.g. a common `/etc/siphon/lib`).
  Helper modules hot-reload on change just like the main script: the file watcher
  now reacts to any `*.py` change in a watched directory, and stale helper modules
  are dropped from `sys.modules` on reload so the new source is re-imported. Only
  absolute imports are supported (the script is not a package, so `from . import`
  does not work), and the "no cross-request module state" rule applies to helper
  modules too.
- **`gateway.groups[].source_networks` + `call.source_ip_in(cidr_list)`** — source
  membership for a peer that sends SIP from a whole published subnet, not only the
  IPs its signalling FQDNs resolve to. `from_gateway` matches the source IP against
  a group's *resolved destination addresses* (it tracks DNS) — correct for a
  fixed-IP trunk, but it silently misses a peer whose inbound can arrive from any
  address in a documented range: the FQDNs resolve to a moving subset, so
  `from_gateway` flaps as DNS rotates and rejects a legitimate source it just
  hasn't resolved. List those ranges under a group's `source_networks` (CIDR or
  bare IP, IPv4 or IPv6) and they count as members regardless of DNS.
  `call.source_ip_in(["203.0.113.0/24"])` is the B2BUA counterpart of
  `request.source_ip_in` for gating on ranges inline without a gateway group.
  Mirrored in the SDK mock.
- **`presence.refresh(subscription_id, expires)` + `presence.find_by_dialog(call_id, from_tag)`** —
  the two pieces needed to handle an in-dialog SUBSCRIBE (RFC 6665 §4.4.1) as a
  notifier. `find_by_dialog` resolves a subscription id from an in-dialog
  SUBSCRIBE's `(Call-ID, From-tag)` — which a refresh or `Expires: 0`
  un-SUBSCRIBE carries but the original id it does not — and `refresh` resets
  that subscription's timer without recreating the dialog (the store already had
  `refresh_subscription`; it just wasn't exposed). Only subscriptions created
  with `subscribe_dialog` (which store dialog state) are findable; terminated
  ones are skipped so a lingering entry can't shadow a re-SUBSCRIBE that reused
  the Call-ID. Mirrored in the `siphon-sip` SDK mock. The IMS S-CSCF example
  (`examples/ims_scscf.py`) is rewritten to use them: the initial reg-event
  SUBSCRIBE now establishes a real dialog (assigns the notifier To-tag on the
  2xx, RFC 6665 §4.1.3, and stores it via `subscribe_dialog`), and the in-dialog
  branch keys on the dialog to refresh the timer or, on `Expires: 0`, tear the
  subscription down with a terminal NOTIFY — fixing reg-event refresh and
  un-SUBSCRIBE, which previously 404'd for every subscriber.

- **`registrar.lookup_contact(uri)` / `registrar.is_registered_contact(uri)` —
  reverse-lookup a binding by its Contact URI.** `registrar.lookup(uri)` keys on
  the AoR (`user@domain`); these key on the stored **Contact** (user + host +
  port, ignoring URI parameters and default ports). For the terminating edge
  where an upstream registrar-of-record (a PBX in front of siphon) retargets the
  INVITE straight at the cached contact and loose-routes it back, the
  Request-URI / To carry the contact (`sip:1001@203.0.113.7:17514`), not the
  registration domain (`sip:1001@pbx.example`) — so an AoR-keyed `lookup` misses
  even though the binding is present and shows in `/admin/registrations`.
  Matching on the contact recovers it, so a script can guard
  `if not registrar.lookup_contact(str(call.ruri)): call.reject(404, …)` before
  dialing. AS-side capability records are excluded, matching `lookup`.
- **E.164 number normalization for identity headers — the `numbers` namespace,
  `request.rewrite_identities()` / `call.rewrite_identities()`, and
  `call.dial(number_policy=…)` / `call.fork(number_policy=…)`.** One call
  reformats every dialable identity userpart (`From`, `To`,
  `P-Asserted-Identity`, `P-Preferred-Identity`, the Request-URI, and opt-in
  `Referred-By` / `Remote-Party-ID`) into a target shape — `e164` (`+31…`),
  `plain` (`31…`), `international` (`0031…`) or `national` (`0…`) — driven by a
  home numbering plan (`numbering:`) and named, versioned presets
  (`number_policies:`). Display names, tags, hosts, non-numbers and preserved
  service/emergency codes (`preserve_users`) are left untouched; a national form
  of a foreign number falls back to the international access form. The `numbers`
  namespace exposes `numbers.parse(raw, home=None)` returning a `Number` with
  `.e164` / `.plain` / `.international` / `.national` / `.cc` / `.nsn` /
  `.format(...)`. On the B2BUA path, `number_policy=` (or
  `b2bua.default_number_policy`) normalizes the A-leg identity headers that flow
  to the B-leg plus the dial/fork target as the final step before the INVITE is
  built. An opt-in `diversion:` block extends the walk to the `Diversion` (RFC
  5806) and `History-Info` (RFC 7044) family with structured, per-entry rewrites
  that preserve `index`, `reason`, the embedded escaped `cause`, entry ordering,
  and privacy-restricted entries (`respect_privacy`). Mirrored in the
  `siphon-sip` SDK (`numbers` mock + `rewrite_identities` / `number_policy=`).
- **`reply.from_gateway(group)` / `reply.source_ip` / `reply.source_port`** —
  source-membership predicate on the response path, the reply-side counterpart of
  `request.from_gateway` / `call.from_gateway` (Kamailio `ds_is_from_list()` /
  OpenSIPS `ds_is_in_list()`). `reply.from_gateway("carriers")` is `True` when the
  entity that sent the response has a source IP resolving into the named gateway
  group — so a script can tell which trunk actually answered, e.g. in
  `@proxy.on_reply` or `@b2bua.on_answer` / `@b2bua.on_early_media`. The B2BUA
  reply now carries the B-leg peer's observed wire source (previously unset), and
  `reply.source_ip` / `reply.source_port` expose it directly. Same trust
  semantics as the request/call form (handshake-verified on TCP/TLS/WS/WSS, a
  best-effort direction hint on UDP). Returns `False` / `None` where no single
  source applies — e.g. a fork-aggregated `@proxy.on_failure` reply. Mirrored in
  the SDK mock.
- **Media CDR from the engine's end-of-call summary** — on the native
  `siphon-rtp` backend (`siphon-rtp-proto` 0.1.4), the engine now pushes a
  structured `CallSummary` event when it tears a call down. When `cdr.auto_emit`
  is on, siphon writes a `method="MEDIA"` CDR keyed on the SIP Call-ID (so a
  collector joins it to the SIP-side CDR) carrying the per-leg byte/packet
  counters and, where a userspace media actor measured them, the RFC 3550
  loss/jitter and ITU-T G.107 MOS shape — the structured twin of the engine's
  media log, no log scraping. Per-leg figures are flattened under `near_`
  (offerer) / `far_` (answerer) / `leg{n}_` prefixes (`_codec`, `_packets_in`,
  `_bytes_out`, `_packets_dropped`, and when measured `_ssrc`, `_packets_lost`,
  `_loss_percent`, `_jitter_ms`, `_rtt_ms`, `_mos_average`/`_min`/`_max`,
  `_mos_basis`); top-level `media_reason` (`delete` / `media_timeout`) and
  `media_duration_ms` accompany the standard `duration_secs`. Unmeasured fields
  are omitted, not emitted empty. The rtpengine / rtpproxy backends do not
  surface this event, so no media CDR is written there.
- **`call.dial(..., auth_passthrough=True)` / `call.fork(..., auth_passthrough=True)`** —
  relay B-leg authentication to the caller end-to-end instead of siphon answering
  it (RFC 3261 §22.3), for device-driven proxy auth where the endpoint (not siphon)
  holds the credentials — e.g. an extension authenticating to its own PBX through
  the B2BUA. One knob: it copies `Proxy-Authenticate` (B→A) and `Proxy-Authorization`
  (A→B) across the B2BUA, and treats a B-leg `401`/`407` (when the call has no
  `set_credentials()`) as a *non-terminal* challenge — the challenge is forwarded
  to the caller without firing `@b2bua.on_failure`, writing a failure CDR, or
  tearing down the anchored media, so the caller can authenticate and re-INVITE.
  Mutually exclusive with `set_credentials()`; if both are set the stored
  credentials win (siphon answers the challenge itself). Mirrored in the SDK mock.
- **`rtpengine.answer_local(call, profile=None, auto_reject=True)`** — single-leg
  UAS answer for the caller's own offer, with the media engine as the far side
  (IVR / echo / announcement server). Unlike `answer()` it takes the INVITE offer,
  not a peer's reply: there is no far leg, so the engine picks one encodable codec
  from the offer (RFC 3264 §6.1) and returns a real one-codec answer SDP for the
  script to put in its own 2xx. Profile precedence matches `answer()` (explicit
  `profile=` → the profile recorded by a matching `offer` → `rtp_passthrough`).
  When the offer carries no codec the engine can encode, it can't be answered:
  with `auto_reject=True` (default) and a `Call` target a deferred
  `488 Not Acceptable Here` (RFC 3261 §13.3.1.2) is set on the call and the
  coroutine resolves to `None`; with `auto_reject=False` (or a non-`Call` target)
  it raises `ValueError` instead, leaving the response to the script. Native
  `siphon-rtp` backend only (`siphon-rtp-proto` 0.1.3 `AnswerLocal`); rtpengine
  and rtpproxy reject it.
- **`rtpengine` media verbs now accept a `(call_id, from_tag)` tuple or a bare
  `call_id` string** as their target, in addition to a `Request`/`Reply`/`Call`
  object — `play_media`, `stop_media`, `play_dtmf`, `silence_media` /
  `unsilence_media`, `block_media` / `unblock_media`, and `echo`. This lets an
  `@rtpengine.on_dtmf` handler (which is handed `call_id` / `from_tag` strings,
  not a SIP message) drive media directly, e.g. `await rtpengine.play_dtmf((call_id, from_tag), "1")`.
  A bare string uses an empty from-tag (best-effort).
- **`b2bua.terminate(call_id, reason="Normal Clearing") -> bool`** — imperative
  hangup of a B2BUA call by SIP Call-ID. Unlike `call.terminate()` (deferred
  until its own handler returns, so a no-op from an out-of-band event), this acts
  immediately and reads shared Rust dialog state, so it works from an
  `@rtpengine.on_dtmf` / `@rtpengine.on_media_timeout` callback, a timer, or a
  normal handler, and needs no stashed `call` object (cross-worker safe). Sends
  an in-dialog BYE to every leg (a single-leg UAS/IVR call gets just the caller
  leg) and runs the full teardown — Rf ACR-STOP, CDR, SIPREC stop, media
  release, dialog cleanup. Returns `False` (never raises) when the Call-ID is
  unknown or already gone, so an IVR racing a caller-initiated BYE is a clean
  no-op. The BYE carries an RFC 3326 `Reason: Q.850;cause=16` header with the
  supplied text.
- **`call.progress(code, reason, body=None, content_type=None)`** — imperative
  UAS provisional (18x) for a B2BUA call: send a `183 Session Progress` with
  early-media SDP, or a `180 Ringing`, immediately from a handler, without
  answering the call. An 18x with SDP opens an early dialog and carries the same
  UAS To-tag `call.answer()` uses. The handler must still `answer()` / `dial()` /
  `reject()` for a final response.

### Changed
- **`rtpengine.play_media()` now blocks until the prompt finishes by default**
  (`wait=True`), on the native `siphon-rtp` backend. `await rtpengine.play_media(...)`
  returns only once the prompt has fully played out, so an IVR handler can
  sequence `answer → play → echo` with no overlap; the coroutine parks while it
  waits (no worker is held). Pass `wait=False` for fire-and-forget playback
  (music-on-hold / background), which returns as soon as the engine accepts the
  prompt. Backed by the new `Event::PlayFinished` completion event
  (`siphon-rtp-proto` 0.1.2): the play accepts immediately with a `play_id` and
  the engine reports completion asynchronously, correlated by `play_id`. A
  configurable fallback (`media.siphon_rtp.play_timeout_ms`, default 5 min) caps
  the wait so a lost event / dead engine can't hang the call. The rtpengine and
  rtpproxy backends have no completion signal, so they ignore `wait` and return
  on accept as before. Return value is now the actual played duration (or `None`
  when the prompt was stopped / superseded before finishing, or the fallback
  elapsed).

- **`call.answer()` now sends the final 2xx immediately** instead of deferring it
  to when the handler returns. This lets an `async` `@b2bua.on_invite` answer and
  then keep working — e.g. `await rtpengine.play_media(...)` a prompt to
  completion, then `await rtpengine.echo(...)` — without the awaited media
  delaying the 200 OK (the old deferred behavior held the answer until the whole
  coroutine finished, so a prompt played *before* the caller was answered). The
  method stays synchronous (no `await`), and the answer is confirmed with the
  A-leg dialog To-tag as before. Existing answer-then-return scripts are
  unaffected; there is no separate `answer_now()`.

### Fixed
- **HEP/Homer captures no longer report siphon's own side as `0.0.0.0`.** When
  siphon binds to the wildcard address (`listen.udp: 0.0.0.0:5060`, the usual
  production config), every captured leg carried siphon's endpoint as the raw
  bind/recv address — unspecified — so Homer showed `0.0.0.0` as the source of
  outbound messages and the destination of inbound ones (the remote peer rendered
  correctly). The capture path now resolves the local endpoint to the advertised
  address per transport, the same substitution Via/Contact already apply, so a
  leg shows which node/interface it belongs to and IP-based correlation works. The
  SIP on the wire was always correct — this was capture metadata only. Set
  `advertised_address` (or a per-transport `advertise`) for the real IP; without
  it the substitute is loopback, exactly as Via behaves today.
- **B2BUA on a multi-homed host now answers on the socket the call arrived on.**
  When siphon listens on more than one UDP port (e.g. `5060` and `5066`), the
  B2BUA sent every A-leg response (100 Trying, 18x, 2xx, 4xx–6xx, 487, 408, PRACK
  200, and the reliable-1xx / 2xx retransmits) out the *first-configured* UDP
  listener instead of the one the INVITE arrived on, so a peer doing symmetric
  signalling (received on `:5066`) rejected replies sourced from `:5060`. Every
  A-leg reply path now pins the egress socket to the arrival listener. This is
  UDP-only — TCP/TLS/WS/WSS already answer on the accepted connection. Separately,
  the `Contact` siphon advertises to the A-leg (and the stored A-leg dialog
  Contact) carried the default listener's port on *all* transports; it now
  carries the arrival port, so in-dialog requests (ACK/BYE/re-INVITE) reach the
  port the dialog is anchored on (over a stream transport RFC 5923 connection
  reuse had been masking this). siphon-*originated* in-dialog requests to the
  A-leg (framework BYE on `b2bua.terminate` / session-timer teardown, the
  forwarded B→A BYE / re-INVITE / UPDATE) now also carry the arrival port in their
  Via and leave from the arrival socket, and the 200-to-BYE answers on the socket
  the BYE arrived on — so the whole call (setup, hold/re-INVITE, teardown) stays
  on one listener. Single-listener deployments are unaffected (the arrival port
  equals the default), so the performance baseline is unchanged.

- **B2BUA no longer emits a malformed double-port To header on the B-leg
  INVITE.** When topology-hiding the To URI to the dial target, siphon replaced
  only the host token and left the original To port in place — so an inbound To
  carrying siphon's own inbound port (e.g. `callee@pcscf.example:5061`) dialed to
  a next-hop that advertises a port (`gw.example:5060`) produced
  `gw.example:5060:5061`, two ports on one URI (RFC 3261 §19.1.1), which strict
  SBCs reject with `400 Wrong URI`. The default (dial-target) rewrite now
  replaces the whole `host[:port]` authority; the `call.set_to_host()` override
  still rewrites host-only and preserves the original port per its documented
  contract. Only the B2BUA was affected — a proxy does not rewrite To/From.
- **B2BUA no longer emits a spurious `502 Bad Gateway` in response to a caller's
  ACK.** When a B2BUA forwarded a non-2xx final response (e.g. a relayed `407`)
  to the caller and the caller ACKed it, siphon could route that ACK as a fresh
  request and — when its Request-URI failed to resolve — fabricate a `502` back
  to the caller (a response to an ACK, which RFC 3261 §17 forbids). An ACK that
  matches no server transaction, dialog session, or B2BUA call is now dropped
  silently, as required. Surfaced with device-driven proxy auth
  (`auth_passthrough`), where the caller ACKs the forwarded challenge.
- **B2BUA now retransmits the A-leg `2xx` until the caller ACKs** (RFC 3261
  §13.3.1.4), so a single lost `200 OK` on the caller leg no longer leaves the
  call ringing until it CANCELs. The B2BUA has no INVITE server transaction for
  the A-leg (it owns the dialog end-to-end), so the 2xx was previously sent once
  with no UAS-core retransmission; it is now resent on the T1→T2 schedule
  (giving up after 64·T1), cancelled the moment the caller's ACK arrives.
- **Outbound TLS client certificate now hot-reloads alongside the inbound
  acceptor.** Previously a cert renewal only swapped the inbound TLS/WSS *server*
  acceptor (the `SharedTlsAcceptor` read by every accept loop), while the
  outbound connection pool kept the client identity it built once at startup from
  `tls.client_certificate` / `tls.client_private_key`. So on a mutual-TLS trunk
  where siphon *dials* the peer (Microsoft Teams Direct Routing, carrier
  interconnects), a renewed client cert was never presented until a restart — the
  peer rejected the outbound handshake on the stale/expired cert even though the
  "new handshakes use the updated cert" reload had logged. The pool now holds a
  live-swappable connector and a watcher on the client cert/key files rebuilds and
  swaps the identity on change, evicting stale pooled TLS connections so the next
  outbound call re-handshakes with the new cert. No config or scripting-API change.
- **No more spurious `safety-net RTPEngine delete failed: unknown call` WARN on
  every media-timeout teardown.** The media engine owns the call and reaps it on
  media timeout (the reaper removes the call before emitting the timeout event),
  so siphon-sip's own media-session bookkeeping is now dropped when it handles the
  event. The teardown that an `@rtpengine.on_media_timeout` handler drives (e.g.
  `b2bua.terminate`) then finds no record and issues no delete against a call the
  engine already dropped, saving a wasted round-trip and a misleading warning on
  every timeout. Separately, a safety-net delete that returns "call not found"
  (rtpengine `Unknown call-id`, siphon-rtp `unknown call`, rtpproxy `E8`) is now
  logged at `debug` rather than `warn` at all four safety-net delete sites: the
  media was already cleaned, which is exactly what the safety net is for, so this
  also quiets double-BYE / glare and caller-BYE-vs-IVR-terminate races.
- **Compact SIP header forms (RFC 3261 §7.3.3) are now recognized on every
  lookup, not just a few.** Header names are matched by their canonical form, so
  the single-letter compact forms (`v`→Via, `f`→From, `t`→To, `i`→Call-ID,
  `m`→Contact, `c`→Content-Type, `e`→Content-Encoding, `l`→Content-Length,
  `s`→Subject, `k`→Supported, plus the extension forms `o`/`r`/`u`/`x`/`y`/`b`/
  `a`/`d`/`j`) resolve to the same header as their long name throughout the
  stack. Previously only a handful of typed accessors expanded the compact form,
  while the transaction and response-routing layers looked up `Via` literally —
  so a response arriving with a compact `v:` (some registrars/PBXes send all
  headers compact) was dropped with "response has no Via header", stranding the
  transaction and leaving the peer to retransmit its request until it timed out
  (seen against an upstream registrar answering REGISTER `401` with compact
  headers). The on-the-wire header name is preserved verbatim on forwarding
  (compact stays compact); canonicalization affects lookup only.
- **Parser no longer panics on a `Content-Length` that points into the middle of
  a multi-byte UTF-8 body character.** The body was sliced by byte index without
  a char-boundary check, so a message whose `Content-Length` fell mid-character
  aborted the parse thread (a DoS on the parse path, found by fuzzing). The
  parser now degrades to taking the whole remaining input as the body instead of
  panicking; char-boundary-aligned lengths split exactly as before.
- **B2BUA UAS-mode answer now tags the 2xx To header (RFC 3261 §12.1.1).** A
  script that answers an INVITE directly (`call.answer(200, ...)` — MRF /
  announcement / echo / IVR) previously sent a 2xx whose To header was copied
  verbatim from the tagless INVITE, so the caller's dialog had no remote tag. The
  2xx now carries the A-leg dialog's local tag, which also makes a
  siphon-originated in-dialog BYE (from `b2bua.terminate` or session-timer
  expiry) match the caller's dialog instead of being rejected `481`. Bridged
  (`call.dial()`) calls are unchanged.
- **Session-timer expiry (RFC 4028) now completes the call teardown.** Tearing a
  call down on session-timer expiry previously BYE'd both legs but skipped the
  Rf ACR-STOP, the CDR, and the SIPREC stop that an inbound BYE performs, leaking
  those per-call records. It now runs through the same full-teardown funnel as an
  inbound BYE and the new `b2bua.terminate`, and the BYE carries an RFC 3326
  `Reason: Q.850;cause=102` (recovery on timer expiry) header.

- **Registrar liveness no longer network-deregisters an IPsec binding when its
  stream flow closes** (RFC 5626 §4.2.2 flow recovery). A closed TCP/TLS flow
  for an IPsec-protected UE is a recoverable flow failure, not a death signal —
  a VoLTE UE going ECM-IDLE FINs its SIP-over-TCP flow at the radio inactivity
  timer while it stays reachable via paging, so tearing the registration down on
  the FIN made every idle UE uncallable. On a stream close the flow-failure path
  now **retains** (detaches) bindings whose UE source IP still has a live XFRM
  SA — nulling the dead `inbound_connection_id` but keeping the binding, its
  `flow_token` and Service-Route, and emitting no `Deregistered` — and defers
  their liveness to the SA-idle sweep (`idle_multiplier × keepalive_interval` +
  an OPTIONS probe), which reaps only genuinely gone UEs. Non-IPsec stream
  closes (plain TCP, WSS WebRTC) keep the immediate flow-failure deregistration
  and network-dereg cascade unchanged. No config change.
- **SA-idle liveness sweep no longer network-deregisters a live VoLTE UE that
  races an ECM-IDLE → paging window.** Two compounding defects made the sweep
  probe a healthy UE every 30 s and deregister it whenever a probe landed during
  a normal idle→reconnect transition: (1) it aged bindings only on the kernel
  XFRM inbound `use_time`, which on some kernels does not advance on an
  inbound-answered SA, so a UE answering its keepalive/OPTIONS every 30 s still
  looked perpetually idle; and (2) the OPTIONS probe gave up in ~4 s, shorter
  than an idle UE's paging + reconnect (seconds), so a probe sent into a paging
  window false-reaped a live UE. The sweep now folds siphon's own SIP-layer
  last-seen (refreshed on any message arriving on a P-CSCF protected port —
  REGISTER, SUBSCRIBE, in-dialog, and the OPTIONS 200) into its idle test, so a
  UE that just answered anything is not re-probed for a full idle window; and a
  suspect binding must fail its probe on `registrar.liveness.miss_threshold`
  consecutive sweeps (default 2) before it is deregistered, so a UE mid-wakeup
  misses one sweep and survives on the next. The per-attempt probe timeout
  default is raised 2000 → 4000 ms (one paging + reconnect). A genuinely gone UE
  (reboot / airplane mode) still reaps after the grace with the network
  `Expires: 0` de-REGISTER. New knob `registrar.liveness.miss_threshold` (default
  2); no config change required.

## [1.3.0] — 2026-07-10

### Added
- **`rtpengine.echo(target, enabled=True)`** — single-leg IVR echo on the native
  `siphon-rtp` media backend. After offering the leg, `await rtpengine.echo(call)`
  reflects the caller's ingress audio back to itself; `enabled=False` stops it.
  siphon-rtp promotes the plain relay into its processing media path on enable and
  demotes it on disable, and DTMF and media-timeout events keep firing while
  echoing. Native `siphon-rtp` backend only: the rtpengine and rtpproxy backends
  have no echo verb and reject the call with a clear error rather than silently
  no-op'ing. Requires `siphon-rtp-proto` 0.1.1.
- **`send_socket=` egress pin on `request.relay()` / `request.fork()` and
  `call.dial()` / `call.fork()`** — the operator equivalent of Kamailio's
  `force_send_socket()` / OpenSIPS' `$fs`. Selects which of siphon's own
  configured listeners a relayed or dialed request leaves from on a multi-homed
  host (`send_socket="udp:10.0.0.1:5060"`), and advertises that listener's
  address in the outgoing Via so the response returns to the same socket. UDP
  pins the exact `(ip, port)` listener; TCP/TLS bind the source IP with an
  ephemeral source port (the source is now part of the connection-pool key, so a
  source-bound and a default connection to the same peer stay distinct). The pin
  is validated for format at the scripting API (a malformed spec raises
  `ValueError`); a well-formed spec that names no configured listener is logged
  and falls back to default routing rather than dropping the request. It is
  ignored when a captured `flow=` is set (the flow already pins egress) and when
  its transport doesn't match the routed transport. Per-listener UDP egress
  channels are now enabled whenever the host has more than one UDP listener (they
  were previously only enabled under IPsec); a single-listener deployment keeps
  the existing fast path unchanged.
- **Whole-URI setters `set_from_uri` / `set_to_uri` / `set_contact_uri`, plus
  `set_contact_user`, on both `request` (proxy) and `call` (B2BUA).** The
  whole-URI form of the existing `set_*_user` / `set_*_host` setters: replace the
  entire URI inside the header's angle brackets — scheme, user, host, port and
  URI params — in one call, preserving the display name and the dialog-critical
  From/To tag (unlike a raw `set_header("From", "<sip:…>")`, which drops the
  tag). `set_contact_user` rewrites only the Contact userpart (empty string
  clears it). On the B2BUA these mutate the outbound B-leg: `set_from_uri` /
  `set_to_uri` also pin the host (same topology-hiding opt-out as
  `set_from_host` / `set_to_host`); `set_contact_user` injects a userpart into
  siphon's advertised Contact while keeping its host:port (so in-dialog routing
  is unchanged and the userpart rides along — for a downstream that keys a
  tenant/extension off the Contact userpart, the way it does for a REGISTER
  Contact), and `set_contact_uri` replaces the whole Contact for edge/GRUU
  deployments that front siphon. The B-leg Contact stays userless by default
  (RFC 3261 §8.1.1.8 puts no identity in the Contact userpart); these are opt-in.
- **`cache.list_len(name, key)` and `cache.list_len_sum(name, prefix)`.** Two
  async cache-namespace methods for Redis-backed lists. `list_len` returns a
  single list's length (`LLEN`, `0` for a missing key). `list_len_sum` returns
  the summed length of every list whose key matches `{prefix}*`, via a cursor
  `SCAN` (deduped) + pipelined `LLEN` computed server-side in one await; glob
  metacharacters in the prefix are escaped so it matches literally, and an empty
  prefix raises `ValueError`. Both return `None` for unknown or non-Redis-backed
  caches. This gives the live instantaneous depth of a set of sharded per-key
  queues (e.g. summing `ims_queue_*`) — where enqueue/drain counters drift
  upward forever because TTL-expired entries leave the keyspace silently, a
  summed `LLEN` is truthful because expired keys are simply gone.
- **Public Python API reference** at
  [siphon-sip.org/reference](https://siphon-sip.org/reference/). Every scripting
  namespace and object (`request`, `reply`, `call`, `sdp`, the SIP value types,
  and the `proxy`/`registrar`/`auth`/`ipsec`/`diameter`/`sbi`/`rtpengine`/… module
  namespaces) is now rendered on the docs site straight from the `siphon-sip`
  SDK docstrings via `mkdocstrings`, so the reference tracks the code instead of
  drifting. The PyPI `Documentation` link now points there.

### Changed
- **Bump four crypto/ASN.1 dependencies to their current majors** (no behavioural
  change; all validated against the existing known-answer vectors):
  `aes` 0.8 → 0.9 (RustCrypto `cipher` 0.5 — `BlockEncrypt` → `BlockCipherEncrypt`,
  `GenericArray` → `Array` in the Milenage AES-128 block op; the 3GPP TS 35.208
  test-set KATs are byte-identical), `md5` 0.7 → 0.8 (`Context::compute` →
  `finalize`), `x509-cert` 0.2 → 0.3 (its `Certificate` / `TbsCertificate` fields
  became private — the STIR cert code now goes through the accessor methods and
  `get_extension()`), and `rasn-derive` 0.22 → 0.28 to match the already-current
  `rasn` 0.28 (the two had drifted out of lockstep). Supersedes the individual
  Dependabot bumps.
- **Bump the `siphon-bin` SMPP extension to siphon-smpp v1.3.0**, which adds
  Prometheus metrics for the SMPP runtime into siphon's shared `/metrics`
  registry: `siphon_smpp_binds` (gauge, `direction`/`state`) plus
  `siphon_smpp_pdus_total`, `siphon_smpp_throttled_total`,
  `siphon_smpp_bind_reconnects_total`, `siphon_smpp_dispatch_errors_total`,
  `siphon_smpp_dispatch_duration_seconds` (histogram) and
  `siphon_smpp_bind_requests_total`. Only affects builds with `--features smpp`;
  when the host metrics engine isn't initialised every emit path is a no-op, so
  the dispatch hot path reads no clock and touches no metric.

### Fixed
- **OPTIONS 200 and B2BUA responses now advertise `Contact` + `Allow`.** A 2xx
  answer to an inbound OPTIONS (RFC 3261 §11.2 capability response) carried no
  `Contact` and no `Allow`. siphon now adds a `Contact` at its advertised sent-by
  for the transport the OPTIONS arrived on — so a peer that rejects an OPTIONS
  answer with neither `Contact` nor `Record-Route` (Microsoft Teams Direct Routing)
  accepts it — and an `Allow` listing the methods siphon supports. On the B2BUA
  response path the B-leg's `Allow` is stripped (its capabilities are not siphon's
  to relay) and replaced with siphon's own, so a peer that selects its call-transfer
  method from the SBC's `Allow` (Teams does) sees `REFER`/`NOTIFY`. Both are added
  only when absent, so a script-set `Contact`/`Allow` still wins.
- **Single Record-Route now uses the advertised host, not the bind IP.** When
  siphon record-routes a relayed request whose inbound and outbound transport are
  the same, the Record-Route carried the raw bind IP (and `127.0.0.1` when bound to
  `0.0.0.0`) even with an FQDN `advertised_address` set — only the
  transport-bridging *double* Record-Route already used the advertised address. It
  now carries the same host:port as the Via for that transport, so an external peer
  that rejects an IP in Record-Route (Microsoft Teams among them) can route
  in-dialog requests back through siphon.
- **siphon's OPTIONS keepalives now advertise an `Allow` header** listing the SIP
  methods siphon supports (`INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, UPDATE, PRACK,
  SUBSCRIBE, NOTIFY, REFER, MESSAGE, PUBLISH`). A peer that probes the trunk with
  OPTIONS can now discover the supported method set — Microsoft Teams Direct Routing
  selects its call-transfer method from the SBC's advertised `Allow`, so without
  `REFER`/`NOTIFY` here it never hands siphon a REFER even though transfer works.
- **Gateway health prober now fails a `503`, and honors `Retry-After`, for
  Teams Direct Routing datacenter failover.** The OPTIONS prober counted *any*
  response as a successful probe, so a destination answering `503 Service
  Unavailable` was recorded healthy and stayed selectable. A `503` is now
  treated as a probe failure. When it carries a `Retry-After` (RFC 3261 §20.33)
  the destination is marked down immediately and held down for at least that
  cooldown (a new `down_until` deadline on `Destination`); a later successful
  probe does not flip it healthy again before the cooldown elapses. This is the
  Microsoft Teams Direct Routing overload contract: a datacenter that sheds load
  with `503 + Retry-After` is taken out of selection, and the next call's
  `gateway.select()` routes to the next healthy datacenter (an operator override
  via `gateway.mark_up()` clears the cooldown). Other answered codes
  (`500`/`502`/`504` and any non-`503`) still count as healthy, since a peer that
  answers is reachable and OPTIONS is not a real call; only `503` carries the
  "stop sending me traffic" semantics. Within-call re-selection across gateway
  destinations on a live `503` is unchanged (sequential fork still iterates the
  script-supplied target list); marking down affects subsequent calls.
- **Outbound REGISTER honors a `Retry-After` on the failure response.** A
  carrier or Teams registrar that rejects a REGISTER with `503 + Retry-After`
  now schedules the next registration attempt at the server-supplied cooldown
  instead of the local exponential backoff (the backoff state still advances, so
  a later failure without `Retry-After` resumes where it left off). The existing
  re-resolve-to-a-different-IP-on-failure behavior is unchanged.
- **Outbound OPTIONS keepalives now carry a `Contact` header.** The UAC-side
  OPTIONS builder (NAT keepalive, gateway health probe, registrar liveness probe)
  emitted Via/From/To/Call-ID/CSeq only — no Contact. RFC 3261 §11.1 makes
  Contact a MAY on OPTIONS, but some peers require it: Microsoft Teams Direct
  Routing rejects an OPTIONS that carries neither Contact nor Record-Route
  (`Q.850;cause=63;text="…Record-Route and Contact headers are missing"`) because
  it derives the next hop from one of them. The OPTIONS now advertises the local
  reachable address (same host:port as the Via, with `transport=` lowercased), so
  the trunk stays healthy. The host follows `advertised_address` when set — point
  it at the SBC FQDN for peers (Teams among them) that reject an IP in Contact.
- **An FQDN `advertised_address` is now honored across every siphon-originated
  (UAC) Via/From/Contact, not just IP literals.** Previously a non-IP
  `advertised_address` (e.g. `sbc.example.org`) was collapsed to `127.0.0.1` on
  the outbound OPTIONS keepalive/probe headers (including the Contact above), the
  `proxy.subscribe_state` SUBSCRIBE Via/Contact, and the `proxy.send_request`
  auto-Via, and it logged a spurious `advertised_address is not a valid IP, using
  localhost` warning on each probe. The SIP header host now carries the advertised
  value verbatim (RFC 3261 §20.42 permits an FQDN in the Via sent-by), while the
  socket-source resolver still falls back to a local IP; the misleading warning is
  downgraded to `debug`. This also fixes a latent bug where the `subscribe_state`
  and `proxy.send_request` auto-Via sent-by was the *destination* address rather
  than siphon's own, so a peer honoring the Via sent-by could route the response
  away from us. A per-transport `listen.<t>.advertise` (or an IP
  `advertised_address`) already worked and is unchanged.
- **Deterministic default outbound UDP socket on multi-homed hosts.** With more
  than one `listen.udp` entry, the default egress socket for outbound UDP
  (relays, forks, UAC-originated requests, and responses without an explicit
  source pin) was chosen by `HashMap` iteration order — a per-process randomized
  seed — so a packet could leave from a different socket than the Via it
  advertised, and the choice flipped between restarts. The default is now the
  first `listen.udp` listener in configuration order, matching the advertised Via
  sent-by. Single-listener and IPsec deployments are unaffected.

## [1.2.1] — 2026-07-09

### Security
- **Bump `crossbeam-epoch` 0.9.18 → 0.9.20** to address RUSTSEC-2026-0204: an
  invalid pointer dereference in the `fmt::Display` impl for `Atomic`/`Shared`
  when the underlying pointer is null/invalid. Transitive dependency (via
  `crossbeam-deque`); lockfile-only bump, no API or behavioural change.

## [1.2.0] — 2026-07-09

### Added
- **`@rtpengine.on_media_timeout` script hook.** The media engine reaps a call
  whose media went dead (no packets past its inactivity window) and pushes a
  media-timeout event; a handler decorated with `@rtpengine.on_media_timeout`
  (optionally filtered by `call_id` / `from_tag`, same shape as
  `@rtpengine.on_dtmf`) now receives `(call_id, from_tag)` so the script can
  release the per-call state no BYE will clear — Rx/N5 QoS sessions, offline
  charging, dialog/session-store entries. The event is still logged; the hook is
  additive. Delivered by the native **siphon-rtp** backend, which pushes the
  event over its control connection — the rtpengine backend does not emit
  media-timeout events (its NG event log carries only DTMF), so the hook is a
  no-op under rtpengine today. Mirrored in the `siphon-sip` SDK mock
  (`on_media_timeout` + a `fire_media_timeout` test helper).
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
- **B2BUA `call.set_from_host()` / `call.set_to_host()`** — pin the host part of
  the B-leg From / To URI, mirroring `set_from_user` / `set_to_user`. By default
  the B2BUA rewrites the B-leg From host to its own advertised address (topology
  hiding) and the To host to the dial-target host. `set_from_host()` opts a leg
  out of the From host-rewrite so the original domain survives — needed for a
  multitenant SBC whose downstream selects the tenant from the From domain (a
  domainless call would otherwise land in an unauthenticated/default routing
  context). `set_to_host()` pins the To host declaratively (replaces the raw
  `set_header("To", "<sip:…>")` idiom). Only the host changes; scheme/user/port/
  params and tags are preserved. Applies to both `call.dial()` and `call.fork()`.
  Mirrored in the `siphon-sip` SDK mock; new SIPp acceptance scenario
  (`sipp/b2bua_set_host_uas.xml`).
- **Kernel firewall (`security.firewall`).** Mirror SIPhon's bans — the
  confidence-weighted `failed_auth_ban` store and the APIBAN blocklist — into a
  kernel nf_tables set, so abusive sources are dropped in the kernel before they
  reach SIPhon's socket instead of only in the userspace ACL. Self-contained:
  SIPhon programs the set directly over netlink (no `nft` shell-out, no daemon, no
  new dependencies), and the kernel auto-expires each ban via a per-element timeout
  matching the in-memory TTL. Opt-in, Linux-only, needs `CAP_NET_ADMIN`; falls back
  to the userspace ACL with a warning when it's missing. Zero-touch by default:
  SIPhon owns the whole ruleset (table, sets, base chain, and the `saddr @banned
  drop` rules), so `firewall: {}` is all that's needed; set `manage_rule: false` to
  have SIPhon maintain only the sets and reference them from your own ruleset. Two
  new counters make the runtime failure modes observable:
  `siphon_firewall_command_failures_total` (a ban did not reach the kernel — alert
  on it) and `siphon_firewall_commands_dropped_total` (a ban storm outran the
  netlink actor's queue; the userspace ACL still enforces every ban). Also expands
  the security cookbook with the ban-scoring model and adds a Kernel firewall page
  covering `CAP_NET_ADMIN` per runtime, container behaviour, and the
  nftables-vs-XDP tradeoff.
- **Admin API ban management** — `GET /admin/bans` lists the sources currently
  auto-banned by `failed_auth_ban` (with remaining TTL), and
  `DELETE /admin/bans/{ip}` lifts a ban early for an operator clearing a false
  positive. The unban clears the userspace ban and, when the kernel firewall is
  enabled, removes the matching nf_tables element in lockstep so the in-kernel
  drop is lifted too.
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
- **Gateway source-membership predicate — `request.from_gateway(group)` /
  `call.from_gateway(group)`.** Returns `True` when the message's source IP is
  one of the resolved addresses of the named gateway group (configured under
  `gateway.groups`). siphon's equivalent of Kamailio `ds_is_from_list()` /
  OpenSIPS `ds_is_in_list()` — a routing-direction / trust predicate that
  replaces hardcoded source CIDRs. Matches on IP only (source port ignored)
  against every resolved A/AAAA candidate of every destination in the group, so
  a hostname that round-robins across many IPs (e.g. Teams'
  `sip`/`sip2`/`sip3.pstnhub.microsoft.com`) matches on any of them. The member
  set is cached lock-free and refreshed at startup and on each health-probe
  cycle, so the predicate never resolves DNS on the request path. Infallible —
  returns `False` (never raises) for an unknown group, no configured gateway, or
  an unparseable source IP. Security note: on connection-oriented transports
  (TCP/TLS/WS/WSS) the source IP is handshake-verified and trustworthy as an
  authorization signal; on UDP it is spoofable, so `from_gateway` there is a
  best-effort direction hint, not an auth gate.
- **Automatic CDR generation (`cdr.auto_emit`).** With `cdr.auto_emit: true`,
  siphon now writes one CDR per call automatically on the call lifecycle — no
  `cdr.write()` in the script — for both the proxy and B2BUA datapaths. The
  record carries `timestamp_start` (INVITE), `timestamp_answer` (200),
  `timestamp_end` (BYE), `duration_secs`, `response_code`, and
  `disconnect_initiator` (`caller`/`callee`/`timeout`/`error`). Every teardown
  is covered: answered→BYE (either side), B-leg failure, answer-timeout (408),
  and caller CANCEL (487). Default **off**, so manual-only deployments are
  unchanged; manual `cdr.write()` still works and stacks on top. The previously
  **inert** `cdr.include_register` flag is now wired: with `auto_emit`, each
  registrar state change emits a REGISTER CDR (`reg_event` = registered /
  refreshed / deregistered / expired). New `siphon_cdr_sessions` gauge exposes
  the live per-call tracking count (drains to 0 between calls; a steady climb
  is a teardown-hook leak). Per-call state is bounded by the orphan sweep.

### Fixed
- **`cdr.write()` now accepts a B2BUA `Call`, not just a proxy `Request`.**
  Calling `cdr.write(call, extra=…)` from a `@b2bua.on_answer` / `on_bye` /
  `on_failure` / `on_early_media` / `on_cancel` handler previously raised
  `TypeError: 'Call' object is not an instance of 'Request'` — the method was
  typed for `Request` only, so B2BUA scripts had no way to write a CDR. It is
  now polymorphic: a `Call` produces the same record shape as a `Request`
  (method `INVITE`, Call-ID / From / To / R-URI / source IP off the A-leg
  INVITE, plus the same Rf `rf_session_id` / `rf_result_code` auto-stamp), with
  the A-leg's arrival transport threaded through so the `transport` field is
  correct. Passing any other object now raises a clear `TypeError`. Mirrored in
  the SDK mock (`cdr.write(call)`).

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
