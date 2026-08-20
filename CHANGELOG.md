# Changelog

All notable changes to SIPhon are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is lockstep across
the `siphon-sip` crate and the `siphon-sip` Python SDK, driven by the git tag.

## [Unreleased]

### Fixed
- **`cdr.file.rotate_size_mb` actually rotates.** The value was documented,
  parsed and carried into the file backend, then dropped at the write site — so
  a CDR file configured with `rotate_size_mb: 100` grew without bound. It now
  renames the file to `<path>.<UTC timestamp>` once a record takes it past the
  limit, and the next record starts a fresh one; the rename happens after the
  write, never mid-record. `0` disables rotation. Rotated files are kept, never
  deleted: retention belongs to logrotate or whatever ships them, and dropping
  billing records to enforce a size cap would be worse than the unbounded file
  this replaces. The packaged logrotate config names `cdr.jsonl` only, so it
  does not re-rotate the size-rotated siblings.

### Added
- **Inbound REFER on a controlled call is surfaced to the control app as a
  `TransferRequested` event.** When a B2BUA call has been handed to an external
  control app, an in-dialog REFER on that call is no longer run through the
  in-process `@b2bua.on_refer` path — the app owns the transfer decision. siphon
  holds the REFER un-answered, emits `TransferRequested` (payload
  `{refer_to, replaces?, from_tag}` plus the stable id triple) to the owning
  connection, and waits for the app's decision via two new SIP-adapter verbs:
  `accept_refer` (`{target?, next_hop?, mode?}`, `mode` ∈ `terminate` /
  `transparent`) drives the same shipped transfer machinery the script accept path
  uses, and `reject_refer` (`{code?, reason?}`) declines with a final non-2xx. If
  the app never decides, a decision-deadline sweep answers `603 Decline` (the same
  default as no `@b2bua.on_refer` handler) so a REFER is never left pending. An
  uncontrolled call's REFER still runs the Python `@b2bua.on_refer` path unchanged.
  Builds on the single-leg REFER machinery, so a terminate-mode accept on a
  voice-AI / IVR call with no B leg re-dials the target off the A dialog. The SDK
  client facades for the new verbs and event follow separately.
- **RFC 4103 real-time text observability.** A call carrying a plaintext
  `m=text` stream (RTT / T.140, the accessibility and emergency-calling text
  channel, and what an NG112 deployment needs alongside audio) can now be
  observed rather than only relayed. Set `text_events` on a media profile and
  the engine promotes **only** that low-rate stream to its userspace text
  processor, which RED-depacketizes (RFC 2198) and reassembles it and reports
  each recovered increment to a new `@rtpengine.on_text` handler —
  `fn(call_id, from_tag, to_tag, text, direction)`, with the same optional
  `call_id` / `from_tag` filters as `@rtpengine.on_dtmf`. Only non-empty
  increments are reported, so a handler firing always means new characters
  arrived; a duplicate, a reordered packet or an idle keepalive produces
  nothing. A `\ufffd` in the text marks a gap RED redundancy could not repair
  (RFC 4103 §5.3) and is deliberately left in place — a consumer needs to see
  where loss occurred rather than silently reading a shorter message. The audio
  relay/transcode path is untouched (text observability never promotes audio),
  and the flag is inert on a call that negotiated no text. Requires
  `media.backend: siphon-rtp` (`siphon-rtp-proto` 0.2.0); rtpengine and rtpproxy
  reject a `text_events` profile at config load rather than accepting a flag
  they cannot honour and leaving a script waiting on events that can never
  arrive.
- **Per-leg text reception counters in the media CDR** — `text_packets`,
  `text_characters`, `text_missing_markers` and
  `text_recovered_from_redundancy`, prefixed per leg alongside the existing
  loss/jitter/MOS fields. A content-level QoS surface distinct from the
  datapath's packet counters: it reports what the receiver actually recovered,
  including redundancy repair and unrecoverable-loss markers. Absent, not
  zeroed, on a call with no observed text stream — `text_packets=0` would read
  as a text stream that carried nothing, which is a different claim.
- **Cold transfer off a call siphon answered itself.** A voice-AI or IVR call has
  no B leg, so the only way to hand the caller on is an in-dialog REFER on the A
  dialog via the imperative `b2bua.refer(call_id, target)` — `call.refer()` is a
  no-op from `@b2bua.on_invite` (the dialog is not confirmed yet) and
  `@b2bua.on_answer` never fires without a B leg. Now covered end to end by a
  functional scenario, wired into `examples/voice_ai_b2bua.py` as "press 0 for an
  agent", and documented in `docs/cookbook/voice-ai.md`.

### Fixed
- **A challenged REFER was never retried, and its response was dropped
  entirely.** A REFER siphon originates on one of its own legs is allocated a
  fresh Via branch that belongs to no leg, and responses are matched to a call by
  branch — so the 202 was ignored and a 401/407 equally so. A carrier that
  challenges an in-dialog REFER therefore
  killed the transfer silently, with the script still waiting on sipfrag NOTIFYs
  that could never arrive. Such a REFER is now tracked so its response can be
  matched, and a challenge is retried with the credentials from
  `call.set_credentials()` — a new transaction on the same dialog (RFC 3261
  §22.2), capped so a trunk that always challenges cannot loop, and with no ACK
  (REFER is a non-INVITE transaction; §17.1.2). A REFER that cannot be retried
  now clears its subscription and logs at WARN instead of leaving the transfer
  pending forever.

### Fixed
- **A relative `script.path` now resolves against the config file's directory,
  so siphon starts under a supervisor.** It was resolved against the process
  working directory, which is the config directory when you run siphon by hand
  and `/` under systemd. The packaged `siphon.yaml` ships
  `script.path: "scripts/proxy_default.py"`, so the packaged unit looked for
  `/scripts/proxy_default.py`, failed the script load, exited non-zero and
  restart-looped — while the same config started fine from `/etc/siphon`. A
  container `WORKDIR` or an embedding binary that chdirs hit the same trap.
  `script.include_paths` is anchored the same way. The rewrite only applies
  when the config-relative file exists, so a config that relies on the working
  directory keeps resolving as before; this can only make a previously-failing
  config start. `Config::from_str` is unchanged (no file to anchor on), and the
  startup log line prints the resolved path.
- **The packaged systemd unit can write its state and log directories.**
  `ProtectSystem=strict` was paired with `ReadWritePaths=/var/lib/siphon` only,
  while every default write path (`cdr.file.path` at `/var/log/siphon/cdr.jsonl`,
  `lawful_intercept.audit_log`, the `log.file` example) lives under `/var/log`,
  which was read-only and never created. The unit now declares
  `StateDirectory=siphon` and `LogsDirectory=siphon`, so systemd creates both
  owned by the service user, and pins `WorkingDirectory=/etc/siphon`. It also
  documents, as commented lines, the `CAP_NET_ADMIN` + `AF_NETLINK` an IMS
  P-CSCF needs for `ipsec:` sec-agree.
- **A log, CDR, audit or event-sink file whose parent directory is missing now
  creates it.** Opening with `create(true)` creates the file and never the
  directory holding it, so every default path we ship — all of them inside
  `/var/log/siphon` — worked only through the packaged unit, where
  `LogsDirectory=` had already made the directory. Started any other way (a
  tarball install, `cargo install`, a container, by hand) the same config took
  `log.file` down with a process exit and logged an error per record for the CDR
  file, the LI audit log and the Diameter event sink. The directory is created
  only when the open actually fails with `NotFound`, so the happy path is
  unchanged and a permission error still reads as a permission error.
- **The shipped logrotate config is installed, and rotates the paths siphon
  actually writes.** `etc/logrotate.d/siphon` still named `/var/log/siphon.log`
  — a path that is not writable under `ProtectSystem=strict` — and was in no
  package: not the `.deb`, not the `.rpm`, not the release tarball. It now
  covers `/var/log/siphon/*.log` with `copytruncate` (siphon holds those open
  for the process lifetime, and `ExecReload` reloads the Python script, not the
  log file) and rotates `cdr.jsonl` separately *without* `copytruncate`, whose
  copy-then-truncate race can drop a billing record. `.deb` and `.rpm` also
  create `/var/log/siphon` at install time for a by-hand first run.
- **The packaged unit stops restart-looping on a broken config.** siphon exits
  non-zero on a config or script error, and `RestartSec=5s` puts only two starts
  inside systemd's default 10 s window, so the default start limit never tripped
  — a permanently broken config looped forever (a reported install reached
  restart counter 279) instead of failing visibly. The unit now sets
  `StartLimitIntervalSec=300` / `StartLimitBurst=10`, so roughly a minute of
  failed restarts puts the unit in `failed` where `systemctl status` shows it —
  generous enough that a slow-to-appear address still recovers on its own.

### Added
- **In-band DTMF on a controlled call is forwarded to the control plane as a
  `ChannelDtmfReceived` event.** When the media engine detects a DTMF digit on a
  B2BUA call that was handed over to a control app, siphon pushes a
  `ChannelDtmfReceived` event (payload `{digit, duration_ms, volume, from_tag}`)
  to the owning control connection, so an external IVR / AI app collects digits
  from the event stream (there is deliberately no blocking server-side
  `collect_dtmf` verb). This is additive: the in-process `@rtpengine.on_dtmf`
  dispatch still fires unchanged, and it is emitted whether or not any Python
  handler is registered. The event carries the stable id triple
  `{channel, call_id, sip_call_id}` like every other control event, and the SIP
  adapter's `describe` now lists `ChannelDtmfReceived`.
- **SIGTRAN/SS7 extension module.** `siphon-bin` gains a `sigtran` feature that
  composes [siphon-sigtran](https://github.com/siphon-project/siphon-sigtran)
  v1.0.0 into the drop-in `siphon` binary, alongside the existing `smpp` and
  `http` modules (and in the `full` aggregate). It carries MTP3 user traffic
  over kernel SCTP (M3UA / M2PA / SUA), resolves MTP3 routes and SCCP Global
  Title Translation in Rust, and hands locally-addressed dialogues to the script
  for MAP / CAP / INAP termination:

  ```yaml
  # siphon.yaml
  extensions:
    sigtran: /etc/siphon/sigtran.yaml
  ```

  ```python
  from siphon import ss7, gsm_map

  ss7.routes.add(dpc=3000, as_="msc", priority=1)

  @gsm_map.on_operation("mo-forward-sm")
  async def on_mo(dialogue, arg):
      dialogue.reply(gsm_map.mo_forward_sm_res())
      dialogue.end()
  ```

  The four namespaces plus `SigtranError` and the module functions are mounted
  in one pass through `SiphonServer::register_module_extension` (below).

  Build with `cargo build -p siphon-bin --release --features sigtran`. Unlike the
  other modules this one has a system dependency — `async-sctp` links `libsctp`,
  so `libsctp-dev` is needed to build and `libsctp1` to run (both are in the
  `siphon-bin` container image). See
  [Extensions](https://siphon-sip.org/extensions/) and
  [sigtran.siphon-sip.org](https://sigtran.siphon-sip.org/).
- **`SiphonServer::register_module_extension(name, hook)`** — embedding API for
  an extension whose surface is more than one attribute. The hook is handed the
  `siphon` package module itself and mounts its own namespaces, shared types,
  exception and module functions, so `from siphon import a, b, SomeError` all
  resolve; it re-runs on every script load and reload. `register_namespace` /
  `register_namespace_with` remain the right call for the common
  "expose one namespace object" case and keep their built-in-name collision
  check — a module extension picks its own attribute names and is not
  collision-checked.
- **Control-plane header-remove + media-control verbs on the SIP adapter.** The
  `siphon-control.v1` `sip` module gains `remove_header` (remove a header from
  the stored A-leg INVITE, the mirror of `set_header`) plus the media verbs
  `play` / `stop` / `dtmf` / `hold` / `unhold` / `stream_start` / `stream_stop`,
  each bound to the configured media backend and applied against the controlled
  A-leg's anchored media session. `play` is fire-and-forget — the reply confirms
  the backend accepted the command, it does not block on prompt completion — with
  the source as exactly one of `file` / `db_id` / `blob` (base64 over the JSON
  wire). `hold`/`unhold` map to the engine's silence/unsilence (a gentle hold
  that keeps the path up; packet drop stays a future gate verb). `stream_start`/
  `stream_stop` attach/detach an additive WebSocket audio tee (a copy of the live
  audio for transcription / agent-assist / compliance, not a media takeover);
  this is a `siphon-rtp`-backend feature, so on rtpengine/rtpproxy it answers
  `unsupported_verb` rather than a hollow success. Errors are typed, never a
  hang: a call with no anchored media session → `not_found`, a backend that
  cannot perform the op → `unsupported_verb`, any other backend failure →
  `unavailable`. The media call-id + from-tag are resolved from the call's SIP
  Call-ID through the same media-session mapping the dispatcher uses for
  re-INVITE / SIPREC, so a re-anchored transfer is addressed on its real media
  id. Server-side only — the client SDK facade methods are a follow-up (reach the
  verbs meanwhile through the generic `command(verb, args)` escape hatch).
- **`auth.require_proxy_digest()` / `require_www_digest()` / `require_digest()` /
  `verify_digest()` now take a B2BUA `Call` as well as a proxy `Request`, so a
  B2BUA can challenge its own caller.** Registering any `@b2bua.*` handler makes
  the dispatcher route INVITE straight to the B2BUA path, so `@proxy.on_request`
  never sees it — and the digest helpers only accepted a `Request`. There was no
  way to authenticate an INVITE in B2BUA mode at all; the only auth on that path
  was relaying a *downstream* challenge (`call.dial(auth_passthrough=True)`).
  Now:

  ```python
  @b2bua.on_invite
  def new_call(call):
      if not auth.require_proxy_digest(call, realm="example.com"):
          return                      # 407 armed; siphon answers the A-leg
      log.info(f"call from {call.auth_user}")
      call.dial(str(call.ruri))
  ```

  On a `Call` the challenge is armed as the same deferred reject
  `call.reject()` produces, so siphon answers the A-leg INVITE and drops the
  call actor without ever building a B-leg INVITE. On success the caller's
  hop-by-hop `Proxy-Authorization` is stripped from the message the B-leg INVITE
  is built from (RFC 3261 §22.3). Passing anything other than a `Request` or a
  `Call` raises `TypeError` naming both. `require_ims_digest` /
  `require_aka_digest` stay `Request`-only: IMS and AKA digest are REGISTER-time
  procedures and REGISTER never reaches the B2BUA path.
- **`call.auth_user`** — the B2BUA twin of `request.auth_user`, carrying the
  username the A-leg authenticated as (`None` if never challenged). Also stamped
  onto the call's CDR as `auth_user`; a B2BUA call is tracked at INVITE time, so
  a caller authenticated inside `@b2bua.on_invite` previously left the field empty.
- **Raw SIP and SIP-over-WebSocket on one listening socket.** Configure the same
  address under both `listen.tls` and `listen.wss` (or both `listen.tcp` and
  `listen.ws`) and siphon serves both protocols from a single listener,
  classifying each connection from its first line: a SIP start line ends with
  ` SIP/2.0` (RFC 3261 §7.1/§7.2), a WebSocket upgrade ends with ` HTTP/1.1`
  (RFC 6455 §4.1), and the two grammars are disjoint, so the split is exact
  rather than heuristic. One port, one firewall pinhole and one certificate now
  serve a browser UE on WSS and a SIP trunk on TLS — which matters where the
  port is not yours to choose (443 outbound from a guest network, 5061 expected
  to be raw SIP by a carrier). Downstream everything sees the transport the
  connection turned out to speak, so Via/Contact generation, flow capture, MT
  routing and outbound distribution are unchanged; the classification costs one
  step per connection and nothing per message. A peer that connects and stays
  silent (connection reuse, RFC 5923) is treated as raw SIP after two seconds.
  Only `tcp`+`ws` and `tls`+`wss` can share a socket: any other pairing on one
  address (notably plaintext with TLS, where a ClientHello is not a SIP message)
  is now a startup error with a message naming both lists and the address.
- **Worked voice-AI example — a carrier call answered by an AI over a WebSocket.**
  `examples/voice_ai_b2bua.py` + `.yaml` compose the shipped pieces into the
  single-leg shape: identify the carrier by source IP, `rtpengine.answer_local()`
  with the `voice_ai` profile and a per-call `ws_uri`, answer with the SDP the
  engine synthesised, and surface DTMF. There is no B leg — the media engine
  anchors the call with the WebSocket server as the far side. A control-plane
  variant (`examples/voice_ai_control.py` + `voice_ai_control_app.py`) drives the
  same media path with the policy in an external application via
  `call.handover(..., answer=True, ws_uri=...)`. Documented end to end in
  `docs/cookbook/voice-ai.md`, including how to tell a working bridge from a
  call that merely returns audio. Requires a `siphon-rtp` engine of **0.1.5 or
  later**: earlier builds accept `ws_uri` on `answer_local` and silently never
  dial it.
- **Functional coverage for the voice-AI path** — `scripts/run-tests.sh --voice-ai`
  drives a real INVITE through the example against a mock siphon-rtp control
  server (`sipp/siphon-rtp/mock_siphon_rtp.py`, the JSON-over-TCP twin of the
  existing rtpengine NG mock) and asserts the answer SDP is anchored on the
  engine's media address rather than echoing the caller's own `c=` back.
- **`route()` on the control-plane SDK's `sip` facade — all three bindings.**
  Wraps the server's `route` verb (un-parks a handed-over call and dials the
  B-leg via siphon's LCR sequential-failover engine, returning control to
  siphon): `call.route(targets, strategy="sequential", headers=…)` in Python and
  TypeScript, and an async `Call::route(targets, strategy, headers)` on the Rust
  client, where a target is a bare URI or `{uri, next_hop?, headers?, timeout?}`.
  It returns the reply result (`{channel, state: "routing", targets}`) and
  raises/rejects the typed `unsupported_verb` / `bad_request` / `not_found`
  errors like the sibling verbs. The control SDK version is unchanged (its own
  `control-sdk-v*` train cuts the release).
- **`Contact.received` on the SDK mock — the field the engine tells you to
  route on.** `PyContact` exposes it and its doc-comment says to prefer it over
  `uri` (a Contact URI can carry a private/NATed address), but the SDK's
  `Contact` dataclass did not model it: `contact.received or contact.uri`
  raised `AttributeError` under the mocks, and because
  `docs/reference/types.md` renders that dataclass, the field was documented
  nowhere. It is now on the dataclass, `registrar.save()` / `save_proxy()`
  stamp it from the REGISTER's source address in the engine's URI shape, and
  `add_contact()` carries an explicitly-built one through — so the NAT case the
  field exists for (private Contact URI, public source) is finally
  constructible in a test. Additive, defaulting to `None`.

### Changed
- **`siphon-rtp-proto` pinned to 0.2.0** (from 0.1.5). A 0.x minor bump is a
  semver-breaking range, so it is a deliberate move rather than something
  `cargo update` performs: the pin is what makes the engine's newer control
  surface reachable at all. Deployments on `media.backend: siphon-rtp` must run
  a siphon-rtp built from that contract.
- **`Contact.received` is a SIP URI, not a bare `host:port` — the doc-comment
  now says so.** The value has always been
  `sip:<ip>:<port>;transport=<proto>` (the OpenSIPS `received_avp` shape),
  which is what lets `request.fork([c.received or c.uri for c in contacts])`
  work, but the getter's doc-comment described it as "source IP:port". Only
  the comment changed.
- **`request.fix_nated_register()` writes the observed source port into
  `rport=`** instead of a hardcoded `5060`. SDK mock only; the engine already
  used the real port.
- **`tls.method` is now enforced — it used to be parsed and ignored.** The
  setting was deserialized into the TLS config and never read: the acceptor was
  built from a bare `rustls::ServerConfig::builder()`, so a config asking for
  `TLSv1_3` still completed TLS 1.2 handshakes and the documented default
  (`TLSv1_3`) described a floor nothing applied. It is now a **minimum**
  version, applied to the `listen.tls` / `listen.wss` acceptor **and** to
  outbound TLS from the connection pool: `TLSv1_2` negotiates 1.2 or 1.3,
  `TLSv1_3` negotiates 1.3 only and refuses a TLS 1.2 peer in either direction.
  The default is now `TLSv1_2`, which is exactly what siphon has always
  negotiated, so an unset `method` changes nothing. **Anyone who explicitly set
  `method: TLSv1_3` gets the tightening they asked for and will now refuse TLS
  1.2 peers** — check both directions (subscriber clients and upstream trunks)
  before upgrading, or set `TLSv1_2` to keep 1.2 available. Values are validated
  at config load: `TLSv1_2` / `TLSv1_3` in the OpenSSL/Kamailio spellings
  (`TLSv1.2`, `TLSv1.2+`, `1.2`), while TLS 1.0/1.1, SSL and typos are a startup
  error instead of a silently-ignored string.

### Fixed
- **An HTTP probe on a SIP-only TCP/TLS listener was neither dropped nor
  counted.** Stream framing (RFC 3261 §18.3) measures a message by finding
  `\r\n\r\n` and reading `Content-Length` — which a well-formed HTTP request
  also satisfies — so a vulnerability scanner's `GET /phpinfo.php HTTP/1.1` was
  framed as a complete "message", queued to the dispatcher and rejected only by
  the parser: the connection stayed open, the whole attacker-supplied buffer was
  logged at `warn`, and nothing was recorded against the source, so
  `security.failed_auth_ban` never fired no matter how long the scan ran. Only
  an *incomplete* frame was ever classified. Dedicated `listen.tcp` /
  `listen.tls` listeners now classify each connection from its first line —
  the same check a `tcp+ws` / `tls+wss` mux already applied — and close it
  before the framer runs when it is not SIP, counting a strong auto-ban signal
  (a scanner is banned on its fourth probe at the default weights). An HTTP
  request line is not SIP on a listener with no WebSocket half, so it is treated
  like any other non-SIP bytes, and the probe is never answered. A peer that
  connects and sends nothing still serves as raw SIP (connection reuse,
  RFC 5923), and a connect-and-close L4 health check is still never counted as
  abuse. The parse-error log line is now capped, so an unparseable message can
  no longer decide how much it writes into the log, and a TLS peer that
  disappears without `close_notify` — every scanner, and most browsers — logs at
  `debug` instead of `warn`.
- **Extension-module startup diagnostics were being swallowed.** `siphon-bin`
  composes its extension modules at *builder* time, before `SiphonServer::run()`
  installs the tracing subscriber, so every `tracing::error!` / `warn!` in that
  layer went nowhere. A binary whose `extensions.smpp` (or `.http`) pointed at a
  missing or unparseable file started up completely silent with the module
  disabled, and the documented "loud on mismatch" warning for a config block
  whose cargo feature was not compiled in never printed either. Those
  diagnostics now go to stderr, where the rest of siphon's pre-subscriber
  startup output goes, and name the offending path.
- **Every digest challenge but the weakest was dropped on the wire.**
  `auth.require_*_digest` builds one challenge per algorithm — MD5 + SHA-256 +
  SHA-512-256, as RFC 7616 §3.7 asks for — so a single 401/407 serves RFC 2617
  and RFC 7616 clients alike. The response builder copied only the first value,
  so the wire carried MD5 alone and no client could negotiate up from it. All
  values are now copied, as separate header lines.
- **A locally-generated B2BUA final response carried no `To` tag.** RFC 3261
  §8.2.6.2 requires a UAS to tag every response but 100, and siphon is the UAS
  on the A-leg. The 408 ring-timeout path stamped the A-leg dialog's tag but
  `call.reject()` did not, so every script-driven rejection answered a
  dialog-forming INVITE with the request's tagless `To`. Both paths now share one
  helper.
- **The same address under two `listen:` protocols silently half-worked.** Every
  stream listener binds with `SO_REUSEPORT`, so configuring one address under
  both `listen.tls` and `listen.wss` (an entirely reasonable-looking way to ask
  for both on one port) started two listeners that both bound successfully and
  had the kernel distribute arriving connections between them — roughly half of
  the WSS clients landed in the raw-SIP reader and half of the TLS peers in the
  WebSocket handshake, with no error logged anywhere. That configuration now
  does what it reads like (see the multiplexed listener above), and the pairings
  that genuinely cannot share a socket are rejected at startup.
- **Rf ACR-START reported no answer instant, so a CDF could not compute billable
  duration.** `Time-Stamps` (TS 32.299 §7.2.183) is what separates alerting from
  talk time, and the auto-emit path filled neither half correctly: it sampled
  `SIP-Request-Timestamp` at the moment the ACR was built — which for a START is
  the 200 OK, not the INVITE — and never set `SIP-Response-Timestamp` at all.
  Every START therefore carried one timestamp equal to its own `Event-Timestamp`,
  indistinguishable from a record triggered by the INVITE, and a collector
  reading INVITE-to-BYE over-charged every call by its ring time. Both instants
  are now carried from the session that measured them, derived from its monotonic
  clock so a wall-clock step mid-call cannot invent (or negate) ring time.
- **ACR-STOP timestamped the INVITE while reporting the BYE.** `Time-Stamps`
  describes the record's own trigger request, so a STOP whose `Event-Type` says
  BYE must timestamp the BYE — it carried the INVITE instant forward from the
  START instead, leaving the two AVPs describing different events minutes apart.
- **A failed call produced no Rf record whatsoever.** No accounting session is
  opened for an INVITE that never gets a 2xx, and nothing else was emitted
  either, so an unanswered or rejected call was simply absent from the stream —
  and since `Cause-Code` was hard-set to 0 on every STOP, no record anywhere
  distinguished a successful call from a failed one. Unsuccessful session
  establishment now emits ACR-EVENT per TS 32.260 §5.2.2.1, carrying the ICID and
  the SIP status as a negative `Cause-Code` (TS 32.299 §7.2.35). 401/407 are
  excluded — the UA re-sends against a challenge and the retry is the same call
  attempt — while 487 is included, a caller who hung up during alerting being a
  real unsuccessful setup.
- **No IMS ACR carried a `Subscription-Id`**, so every CDR landed with no billable
  subscriber on it and the collector had to resolve the IMPU out-of-band, which
  only works for subscribers it has provisioned. Records now carry one typed
  `Subscription-Id` per served-party identity (RFC 4006 §8.47: `tel:` and bare
  `+E.164` → END_USER_E164, IMPUs → END_USER_SIP_URI), and `rf_acr_*` gained
  `subscription_id` / `subscription_id_type` kwargs — each accepting one value or
  a list — for scripts that hold an IMSI the SIP layer cannot derive.
- **A multi-valued `P-Asserted-Identity` was concatenated into one
  `Calling-Party-Address`.** The whole header value was reduced by taking its
  first `<` and last `>`, so a subscriber asserting an IMPU, a `tel:` alias and an
  IMSI-derived IMPU produced a single unbalanced string
  (`sip:…org>, <tel:…>, <sip:…`) that no consumer can split back apart, and that
  breaks outright on an identity containing a comma. `Calling-Party-Address` is
  0..n (TS 32.299 §7.2.33) and now repeats once per identity, with the list split
  on commas outside angle brackets and quoted display names. The same parse fixes
  a bracketed URI carrying its own parameters, which used to be truncated at the
  first `;`.
- **The served party on a terminating record was the caller.** `User-Name` was
  taken from the calling party regardless of role, so the callee's own record
  identified whoever placed the call. It now follows `Role-Of-Node` per
  TS 32.260 §5.1 — caller on originating, callee on terminating.
- **An intra-node call opened two terminating accounting records and only ever
  stopped one.** `rf_sessions` gains its entry after the CDF answers ACR-START,
  but the dedupe gate ran before the spawn, and the two legs of such a call are
  answered milliseconds apart — so the originating leg's speculative dual-ACR
  terminating record and the terminating leg's own record both passed an empty
  map and opened separate sessions on one ICID. Only one is reachable from the
  BYE; the other never got an ACR-STOP and emitted an ACR-INTERIM every cadence
  tick until the 24h backstop, ~288 junk records per affected call. The key is
  now reserved synchronously for the duration of the round-trip, and released on
  every exit path so a CDF rejection cannot wedge it.
- **The orphan sweep dropped an Rf session's map entry without releasing the
  session.** Its ACR-INTERIM timer and its `siphon_rf_sessions` slot both
  outlived the entry, so a reaped record kept emitting INTERIMs against a call
  nothing was tracking any more. The sweep now claims the stop as it goes.
- **A UAS-mode B2BUA answer carried no `Contact`, so no in-dialog request could
  be addressed to it.** RFC 3261 §12.1.1 / §13.3.1.4 require a dialog-establishing
  response to carry the Contact the UAC builds its remote target from. The
  relayed path set one from the B-leg's 2xx, but `call.answer()` / `call.progress()`
  — every single-leg answer, including every voice-AI call — had no B-leg to copy
  from and set none at all. A well-behaved UAC therefore had nowhere to send ACK,
  BYE, re-INVITE or PRACK: SIPp renders the empty target as `BYE  SIP/2.0`, which
  arrives unparseable, and the call is only released when a timer fires. Host and
  port now resolve exactly as the relayed path resolves them, so the Contact names
  the listener the INVITE actually arrived on rather than the first-configured one.
- **A SIPp scenario that timed out reported success.** `run_sipp` in
  `scripts/run-tests.sh` exempted exit code 255, which is precisely what SIPp
  returns when a scenario times out — including when an assertion fails and the
  call never completes. Any hanging scenario was green.

### Added
- **`Contact.age_secs`** — seconds since a binding was created or last
  refreshed, for scripts that need their own recency rule (`[c for c in
  registrar.lookup(uri) if c.age_secs < 3600]`). Monotonic, and preserved
  across a restart for bindings restored from a persistence backend; a stored
  record written before age tracking reports `0`.
- **WebSocket tee — stream a copy of a live call's audio without taking the call
  over.** The existing `ws_uri` bridge is a *takeover*: the WebSocket server
  becomes leg A's far side and the A↔B relay is not wired, which is right for
  voice-AI answering a call and wrong for everything else. A tee is send-only and
  additive — the call relays or transcodes exactly as it would otherwise, and a
  copy of its decoded audio streams out, leaving any SIPREC subscription and
  recording on the leg untouched. That is the shape live transcription,
  agent-assist and compliance monitoring need. Available declaratively as the
  `ws_tee`, `ws_tee_direction` (`both` | `caller` | `callee`) and
  `ws_tee_channels` (2 = caller/callee stereo, 1 = mixed mono) media-profile
  fields, and imperatively mid-call as `rtpengine.attach_ws_tee(target, ws_uri,
  direction="both", channels=None)` / `rtpengine.detach_ws_tee(target)`. Requires
  `media.backend: siphon-rtp` (`siphon-rtp-proto` 0.1.5 `AttachWsTee` /
  `DetachWsTee`); rtpengine and rtpproxy reject a tee profile at config load and
  raise on the per-call verbs rather than returning a hollow success that streams
  nothing.
- **`@rtpengine.on_ws_tee_started` / `@rtpengine.on_ws_tee_ended`** — a tee can
  end while the call carries on (the server closes the socket, the transport
  fails), which is otherwise invisible: nothing about the call changes and the
  consumer simply stops receiving audio. `on_ws_tee_ended` reports `reason`
  (`detached` is the only orderly one), plus `frames_sent` and `frames_dropped`
  so a slow consumer is distinguishable from a dead one; an unexpected end is
  logged at WARN whether or not a handler is registered. `on_ws_tee_started`
  carries the negotiated `channels` and `sample_rate` so a consumer decodes the
  binary frames rather than guessing, and `stream_id` correlates the control
  event with the `start` envelope on the socket. Both take the same optional
  `call_id` / `from_tag` filters as `@rtpengine.on_dtmf`.
- **External remote-control plane (ARI/ESL-class) — Phase 1.** An out-of-process
  application can now drive B2BUA calls over a WebSocket, in the model Asterisk
  has with ARI and FreeSWITCH with ESL. A Python `@b2bua.on_invite` handler hands
  a call over with `call.handover("app")` (the ARI *Stasis* model): siphon holds
  the INVITE transaction un-dialed and emits a
  `StasisStart` carrying the full SIP context (real headers, source, R-URI shape,
  body) plus a stable `{channel, call_id, sip_call_id}` id triple that joins CDR
  and HEP with no mapping table. The app then answers / progresses / rejects /
  hangs up / refers the call and reads-writes per-call variables over the socket;
  each command binds to the shipped imperative B2BUA rail and returns immediately
  (a far-end outcome — the callee answering / BYEing — arrives later as an event,
  never as the command reply). New `control:` config block with per-app bearer
  tokens (constant-time compared, feeding the existing auto-ban store), two
  connection modes (a persistent inbound WebSocket listener, and outbound
  per-call-connect where siphon dials the controller at handover — the
  multi-pod default), exactly-one-owner dispatch with per-tenant scoping
  (`forbidden` on a cross-app target), a bounded per-connection outbound queue
  with per-call event/reply ordering and drop-oldest backpressure that can never
  stall the datapath, a handoff deadline with a safe default action (`503` /
  fallback) when no controller acts in time, and `resync` reattach after a
  controller reconnects within the grace window. A parked call is held only by
  the transaction layer's automatic `100 Trying` — siphon synthesizes no
  provisional (a 180 would falsely signal ringing before anything is dialed); the
  controller sends its own `progress` (180 ringback / 183+SDP early media) if it
  wants one, and the real 18x relay end-to-end once the app routes.
  Answer-first (AI-park) mode — `call.handover("ai-app", answer=True, ws_uri=…)` —
  answers the call (`200 OK`) and anchors its media to the `voice_ai` WebSocket
  bridge before handing over (via `answer_local` on the `siphon-rtp` backend, with
  `ws_uri` templated per the media-profile expansion), so the app drives an
  already-connected channel with the AI audio path open; on a backend that cannot
  do it (anything but siphon-rtp) the handover fails visibly (`503`), never a fake
  200. First-class adapter API
  (`ControlAdapter` trait + `SiphonServer::register_control_adapter`) with an
  opaque JSON DTO seam, so a protocol extension registers its own control surface
  over the same rail; the built-in SIP adapter ships in core. Prometheus metrics
  `siphon_control_connections`, `siphon_control_controlled_calls`,
  `siphon_control_commands_total`, `siphon_control_events_dropped_total`,
  `siphon_control_auth_failures_total` and `siphon_control_handoff_timeouts_total`.
  SDK: `call.handover(app, on_lost=, deadline_ms=, vars=)`.
- **Control-plane `route` verb that returns control to siphon with a routing
  decision.** A controller that parked a call (deferred handover) can now hand
  control back so siphon dials the B-leg itself: `route` un-parks the call and
  runs the shipped LCR sequential-failover engine across the supplied `targets`,
  then owns the call thereafter (`@b2bua.on_failure` handles carrier failover).
  This is the consult-and-return flow. An app queries an external LCR / rating
  engine out-of-process (no pool blocked while it thinks) and returns the
  decision as a command. `targets` is a non-empty array of bare URI strings or
  `{uri, next_hop?, headers?, timeout?}` objects; `strategy` defaults to
  `sequential` (v1 runs the sequential engine only, so a parallel/other strategy
  is a typed `unsupported_verb`, never a silent sequential); an optional command
  `headers` object is applied to every attempt's B-leg INVITE. On success siphon
  replies `{state: "routing", targets: N}`, releases the control app (the
  ControlBus channel drains and a `StasisEnd{reason: "routed"}` is emitted so the
  app knows control returned, and the call lives on), and dials the first carrier.
  No routable carrier answers the A-leg `503`; a later B-leg ring-timeout takes
  the normal `408` path. Reuses the same `CallAction::RouteSequence` machinery as
  in-process `call.route(...)` / `call.fork(strategy="sequential")`.
- **Control-plane client SDKs are the official interop path**, now installable:
  `pip install siphon-control` (Python) and `cargo add siphon-control-client`
  (Rust) hide the `siphon-control.v1` wire so a controller is written with
  `@client.on_call` / `await call.answer()` instead of hand-rolled JSON. They
  version independently of siphon core against the protocol and ship on their own
  `control-sdk-v*` release train (PyPI + crates.io via OIDC Trusted Publishing).
  The raw JSON protocol is now framed as the under-the-hood reference for
  building a client in another language. See the
  [control-plane reference](https://siphon-sip.org/reference/control-plane/).
- **Media profiles can drive the `siphon-rtp` WebSocket audio bridge and its DSP
  chain.** The engine has supported handing a leg's audio to an external
  WebSocket media server (decode → L16 uplink, L16 downlink → encode, the WS
  server acting as that leg's far side) for as long as siphon has pinned
  `siphon-rtp-proto` 0.1.4, but siphon never populated the control fields: the
  `NgFlags` → `ProfileFlags` conversion copied the nine fields it knew about and
  swallowed the rest under a `..ProfileFlags::default()` tail, so the bridge was
  unreachable from signalling and no configuration could turn it on. `NgFlags`
  and the `media.profiles` YAML schema now carry `ws_uri`, `ws_vad`,
  `ws_barge_in`, `ws_vad_threshold`, `ws_vad_hangover_ms`, `noise_suppression`
  and `echo_cancellation`, and the conversion is exhaustive — a proto field
  siphon does not carry is now a compile error rather than a silent default.
- **`ws_uri=` on `rtpengine.offer()` / `answer()` / `answer_local()`,** for an
  endpoint the script computes per call (session token, tenant lookup). It wins
  over the profile's own value and is recorded on the media session, so a later
  `answer` reuses the same bridge without repeating it — the same precedence
  `profile=` already had. Both forms expand `{call_id}`, `{from_tag}`,
  `{from_user}` and `{to_user}`; an unrecognised placeholder raises instead of
  passing through as a literal, so a typo cannot reach the engine as a URI path
  segment.
- **Built-in `voice_ai` media profile** — plain RTP toward the caller with noise
  suppression, echo cancellation, VAD and local barge-in on. `ws_uri` is left
  unset (there is no sensible default endpoint) and comes from YAML or per call.
- **`received_from` media-profile flag (opt-in)** — carries the real post-NAT
  source IP siphon saw the request arrive from, gating that leg's media ingress
  to it. For a NATed UA advertising an unroutable private `c=` address this is a
  tighter RTPBleed source gate than the signalled address allows. Off by default,
  so an existing profile emits a byte-identical command; wrong for deployments
  whose media legitimately arrives from a different address than its signalling.
- **`rtcp_mux` media-profile flag** — the RFC 5761 directive list (`offer`,
  `require`, `demux`, `accept`, `reject`, `remove`) overriding the mux decision
  the engine derives from the offered SDP.

- **`sip::validate` — RFC 3261 validation of messages that parse but are still
  invalid.** A message can be perfectly parseable and yet have to be refused: an
  unsupported version, a CSeq that disagrees with the Request-Line, an
  unterminated quoted string in a display name. RFC 3261 wants a *specific
  status* for these, which is only possible if the message parsed first — so the
  parser accepts them, `validate_message` names the rejection and the status, and
  the dispatcher answers it (505 Version Not Supported, otherwise 400 Bad
  Request). A response that fails validation is discarded, since there is nothing
  to answer. Runs after HEP capture, so rejected traffic still appears in packet
  capture. Covers RFC 4475 §3.1.2.1, §3.1.2.4–6, §3.1.2.11–14, §3.1.2.16–18.

  Checks are deliberately narrow so ordinary traffic cannot trip them — the
  scalar check rejects on CSeq alone, because RFC 4475 §3.1.2.4 attributes the
  400 to the CSeq error and explicitly permits an element to process a request
  whose Max-Forwards alone is out of range.

### Changed
- **TLS connection lifecycle logs moved from `info` to `debug`.** The four
  stream transports now share one per-connection reader/writer, and it logs
  "closed by peer", idle timeout and cleanup at `debug` — what the TCP listener
  (the highest-volume of them) already did. A TLS edge with thousands of UEs no
  longer prints a line per connection close at `info`. Warnings and errors are
  unchanged.
- **siphon refuses to start when a `media.profiles` entry sets a field its
  `media.backend` cannot honour,** naming the profile, the direction and the
  field. The WebSocket and DSP flags are `siphon-rtp` only; `received_from` and
  `rtcp_mux` are also real rtpengine NG keys but have no `rtpproxy` equivalent.
  This is a hard failure rather than the boot warning that covers
  `address_family` on `rtpproxy`, because the failure modes differ in kind: an
  ignored `address_family` costs IPv4/IPv6 interworking on a call that still
  works, while an ignored `ws_uri` answers the call and bridges it nowhere —
  silence for the call's whole duration, with nothing logged. A script naming a
  built-in profile the backend cannot honour (built-ins are registered whatever
  the backend, so config validation cannot see them) raises a `ValueError`
  naming the field.
- Invalid `ws_uri` schemes and `rtcp_mux` tokens fail the config load, matching
  the existing `address_family` treatment — the engines ignore an unknown value
  silently, which otherwise lands as a call quietly negotiated the wrong way.

- **Bump the `siphon-bin` SMPP extension to siphon-smpp v1.4.0.** The pin was
  still on v1.3.0: the 1.5.1 entry announcing a move to v1.3.1 never reached
  `siphon-bin/Cargo.toml`, so the manifest and that entry disagreed and the
  extension shipped a release behind what was documented. This moves straight to
  v1.4.0 and picks up both releases:
  - **Optional parameters (TLVs) are readable and writable from a script**, as a
    dict keyed by SMPP 3.4 spec name or by raw integer tag on `submit_via`,
    `submit_multi_via`, `data_via`, `deliver_to` and `data_to`; inbound, `Pdu`
    gained `tlvs`, `tlv(name_or_tag)` and typed shortcuts. That is what makes
    messages past the 254-byte `short_message` limit, `sar_*` concatenation and
    receipts carrying `receipted_message_id` / `message_state` possible at all.
  - **`data_sm` carried no message in either direction.** It has no
    `short_message` field — the body exists only as the `message_payload`
    optional parameter (§4.2.2) — so `data_via` / `data_to` took no message
    argument and inbound `data_sm` always arrived empty. Both ends now carry it,
    and the new `pdu.body` reads whichever of the two the peer used.
  - **A `short_message` over 254 bytes panicked the SMPP runtime**, because
    smpp34's constructors `assert!` on the limit and script input reached them
    unchecked — a 255-byte body took down the tokio task instead of failing the
    call. It now raises.
  - **Inbound `alert_notification` reached handlers as garbage** — its decode
    started at byte 0 while the read loop hands it a complete PDU, so every field
    was 16 bytes off, and it did so without erroring.
  - **`smpp34` 1.2.1's lost-response fix** (the v1.3.1 content): both writer
    tasks registered a request's pending-response entry only *after* the socket
    write returned, and the read loop drops any response it has no entry for, so
    a response landing in that gap was discarded and the caller blocked until its
    30s response timer expired — the PDU was lost, not merely slow. It hit the
    SMSC→ESME direction too, i.e. the delivery-receipt path.

  Only affects builds with `--features smpp`; the plain `siphon` binary is
  unaffected.

- **Content-Length is now validated against the octets actually received.** A
  value that is not a non-negative integer, or that claims more octets than
  arrived, leaves the message unframeable and is rejected instead of being
  papered over with a short read (RFC 3261 §20.14; RFC 4475 §3.1.2.2, §3.1.2.3).
  Stream transports are unaffected — the TCP framer already waits for
  `headers + Content-Length` octets before handing a message to the parser.
- **The Request-Line now requires exactly one SP between elements**, per
  `Request-Line = Method SP Request-URI SP SIP-Version CRLF` (RFC 3261 §25.1). A
  run of spaces made the Request-URI ambiguous (RFC 4475 §3.1.2.9).
- **RFC 4475 tests now run against the byte-exact message corpus.** The 50
  torture messages from RFC 4475 §3 are vendored under `tests/rfc4475/corpus/`
  and driven from a table classified by RFC section, replacing hand-transcribed
  approximations that could not preserve the whitespace, folding and escaping
  the messages exist to test. Fixtures the parser still handles contrary to the
  RFC are enumerated in a `KNOWN_DEVIATIONS` list that fails both on a new
  deviation and on a stale entry, so the gap is explicit and cannot drift. That
  list is currently **empty** — all 50 fixtures are handled as the RFC requires.

### Fixed
- **The extension binary picks up the SMPP bind-handshake fix.** `siphon-bin/`
  moves its `siphon-smpp` pin to v1.5.1, which carries smpp34 1.4.1: both sides
  read the bind handshake with a single `read()` and rejected the buffer when
  anything the peer pipelined behind its bind PDU coalesced into the same
  segment, so an SMSC with queued MT — which sends its first `deliver_sm` the
  moment it accepts the bind — took the session down on arrival and the
  supervisor reconnected into the same failure. The bump also brings the
  listener-failure hooks from v1.5.0 (a refused connect no longer parks the
  server task for the process lifetime), and moves `h2` to 0.4.16 for
  RUSTSEC-2026-0258 (unbounded empty DATA frames), which reaches that graph
  through the HTTP extension.
- **The two excluded workspaces are now covered by the security audit.**
  `siphon-bin/` and `siphon-control-sdk/` are standalone workspaces with their
  own `Cargo.lock`, so the scheduled `cargo-deny` run — which resolves the
  repo-root graph — never saw either of them. `siphon-bin/` had consequently
  drifted onto a `crossbeam-epoch` carrying RUSTSEC-2026-0204 (the advisory the
  server itself moved off in 1.2.1) and a yanked `spin`, and its `siphon-http`
  extension pin pulled the unmaintained `rustls-pemfile` (RUSTSEC-2025-0134);
  all three are cleared — `siphon-http` moves to v1.0.2, which loads TLS certs
  and keys through `rustls-pki-types` instead. Each workspace also gains its
  own `deny.toml`, and the audit's path filters now match nested manifests and
  lockfiles rather than only the root ones. The policy is also split by how it
  behaves over time: `bans` / `licenses` / `sources` are deterministic — they only move when the dependency set moves —
  so they gate every pull request across all three workspaces, failing a GPL
  dependency, an unexpected git source or a duplicate-crate blowup right where
  it was introduced. `advisories` stays on the weekly schedule (plus `main`),
  because a fresh RustSec advisory can land against an unchanged dependency and
  must not turn a green pull request red on untouched code.
- **A branch the proxy failed itself no longer outranks a real answer from a
  sibling branch.** Now that a transport error becomes a 503 and a timeout a
  408, straight class ordering (5xx beats 4xx) handed a branch that never left
  the box the win over one that reached a phone: a parallel fork where branch A
  hit a transport error and branch B answered `486 Busy Here` told the caller
  `500 Server Internal Error`. A locally synthesized failure describes this
  proxy's plumbing, not the callee, so any peer-originated response is now
  preferred; ordering among real responses is unchanged, and a fork where every
  branch failed locally still forwards its best synthesized error.
- **`call.fork()` and `call.dial()` now route a binding through its RFC 3327
  Path.** The B2BUA builds a fresh B-leg INVITE, and it was sent to the
  callee's Contact URI — the address the Path exists to route around (NAT,
  IPsec, a userless or `.invalid` contact). A callee registered through an edge
  proxy was therefore unreachable in B2BUA mode even with a single binding.
  `call.fork()` gains a per-branch route set from each `Contact`'s Path
  (parallel *and* sequential, so serial failover reaches each binding's own
  proxy chain and its per-registration token), and the B-leg now takes its
  destination from the topmost Route when no explicit `next_hop=` is given
  (RFC 3261 §16.6 step 6) — which also makes the existing `route=` argument on
  `call.dial()` actually routable rather than a header that decorated an INVITE
  sent somewhere else. The RFC 3261 §18.1.1 over-MTU UDP→TCP re-probe follows
  the same URI, so an over-MTU B-leg no longer resolves the callee's Contact
  host and lands there in spite of the route set (`mtu:` configured, UDP, a
  DNS-named Contact). A Path route set now also **outranks the binding's
  captured inbound flow** on a B-leg, matching the precedence the proxy path
  already documented: `registrar.lookup()` marks a binding this process accepted
  as `is_local` and surfaces its flow, so flow-first meant a single siphon acting
  as both registrar and B2BUA never honoured a Path at all. A binding with no
  Path still routes over its flow, so connection reuse for a directly-registered
  WebSocket callee (RFC 5626 §5.3 / RFC 7118 §5) is unchanged.
- **A proxied request whose branch never got an answer now gets one.** Two
  independent paths ended at a `warn!` and told nobody, so the upstream UAC sat
  on its `100 Trying` until its own Timer F — 32 s of silence for a failure the
  proxy already knew about. Observed as a call clearing on an application
  server's 30 s media timeout instead of in milliseconds.
  - **A transport error on forwarding is now a 503 on that branch (RFC 3261
    §16.9).** `send_to_target` logged the pool failure and returned
    `ConnectionId::default()` as a sentinel — but that value could not carry the
    meaning: the stream transports return it on failure while UDP returns the
    caller's `fallback_connection_id`, which several call sites legitimately
    pass as exactly that. It now returns a `SendOutcome` that says outright
    whether the transport refused the message.
  - **A client transaction timeout is now a 408 on that branch (RFC 3261 §16.7
    step 2).** The timeout arm logged and reaped without telling the server
    transaction anything. This is the backstop for every way a branch can go
    quiet — a black-holed route, a peer that accepts the connection and never
    answers, a datagram lost on the wire — not just the connect failures §16.9
    covers.
  - Both are injected through the ordinary response path, so fork aggregation
    behaves as it would for a real response: a parallel fork keeps waiting on
    its live branches, a sequential fork advances to the next target, and
    `@proxy.on_reply` / `@proxy.on_failure`, CDR finalisation and the
    server-transaction handoff all run unchanged.
- **A 503 is no longer forwarded upstream; the proxy sends 500 instead**
  (RFC 3261 §16.7 step 6), and drops the `Retry-After` that described the
  unavailable downstream. A 503 says *this next hop* is unavailable, and a UAC
  that saw it would take the whole proxy out of service. Locally generated
  finals (`request.reply(503)`, `reply.reject(503)`) are unaffected — they are
  not responses the proxy is forwarding on behalf of a branch.
- **The reg-event NOTIFY a UE receives is now a conformant in-dialog request.**
  Two independent defects made it one a strict baseband rejects; measured, a
  handset validating it de-registered itself 21–32 s after each successful
  registration, repeatedly, until it stopped attempting IMS registration at all.
  Permissive basebands on the same cores tolerated it and stayed registered, so
  it only became user-visible on handsets that validate.
  - **`presence.notify()` put the subscriber's Contact URI in both `From` and
    `To`.** RFC 3261 §12.2.1.1 requires the dialog's *URIs* there — the local
    URI (the SUBSCRIBE's To) in `From`, the remote URI (its From) in `To` — and
    the Contact is the remote target, which belongs in the Request-URI alone.
    The tags were already correct, so dialog matching by (Call-ID, from-tag,
    to-tag) succeeded and a permissive UA answered 200; only a UA that also
    validates the URIs (RFC 6665 §4.4.1) rejected it. The subscription now
    records the dialog's URIs, via two optional `presence.subscribe_dialog()`
    arguments — `local_uri=` / `remote_uri=`, both defaulting to `resource`,
    which is already correct for any package where the subscriber watches an AoR
    directly (the reg event package, TS 24.341 §5.3.2.4) and in every case
    better than the Contact. Supply them for a watcher subscribed to somebody
    else's resource, where the remote URI is the watcher's own AoR and cannot be
    derived. The Request-URI and next hop still come from the Contact, so a
    NOTIFY that must reach the UE directly is unaffected.
  - **`registrar.reginfo_xml()` rendered AS capability records as `<contact>`
    elements of the user's own registration.** A UE with one binding saw its own
    contact plus one per iFC-matched application server, all
    `state="active" event="registered"` against its own IMPU and
    indistinguishable from its own. RFC 3680 §5.2 defines `<contact>` as a
    contact registered *for the address of record*, and an AS that answered a
    third-party REGISTER has not registered one — TS 24.229 §5.4.1.7 makes the
    3PR a notification to the AS, distinct from §5.7 where an AS genuinely
    registers on the user's behalf. AS records are still stored, still excluded
    from routing, and still available to a watcher that asks
    (`include_as_contacts=True`); they are simply no longer part of the default
    document. The UE-facing capability surface is RFC 6809 `Feature-Caps` on the
    REGISTER 200 OK, which also reaches UEs that never subscribe to the reg
    event package.
- **A terminating request can now fail over between the bindings of one AoR.**
  An AoR with more than one live binding where only one was reachable was
  undeliverable for the full lifetime of the dead binding — observed as a
  79-minute total loss of terminating MESSAGE to a subscriber who was
  registered, reachable and successfully sending throughout; the same shape
  applied to terminating INVITE. Four separate defects sat between a script and
  "try the next contact":
  - `request.fork()` sent every branch with the **first** contact's route set.
    Two bindings of one AoR normally have *different* RFC 3327 Path vectors —
    different edge proxies, or the same edge proxy with a different
    per-registration token — so downstream resolved every branch back to
    binding 0. With `strategy="sequential"` that made failover retry the dead
    contact N times and answer the same error. A `Contact` passed to `fork()`
    now gets its own Route header set built from its Path (in order, RFC 3327
    §5.3), and that route set decides the branch's next hop (RFC 3261 §16.6
    step 6); the Request-URI stays the Contact URI. Bare-string targets keep
    pure Request-URI routing, which is also the way to opt a target out.
  - **`@proxy.on_failure` never fired for a single-destination
    `request.relay()`** — it was dispatched only from the fork aggregator's
    all-branches-failed arm, so a proxy's global failure policy was invisible
    for the commonest case in a proxy and a registered handler simply never
    ran. It now fires for any non-2xx final on a plain relay. `487 Request
    Terminated` is excluded: the transaction was cancelled by the UAC, and
    re-targeting there would resurrect an abandoned call (`@proxy.on_cancel`
    is the hook for that teardown).
  - **Neither failure hook could re-target the request.** Both handed the
    script a `Request` with its inbound flow deliberately replayed for exactly
    that purpose, then dropped it — the action a handler set with
    `request.relay()` / `request.fork()` was never executed, and because the
    reply had not been relayed the error was suppressed too. A retrying
    handler therefore sent nothing at all and the UAC waited for its own timer.
    Both `@proxy.on_failure` and the per-relay `on_failure=` callback now start
    the re-targeted request on the same server transaction, bounded at 8
    retargets per transaction (a chain of fresh client transactions has no
    protocol timer to bound it). This is what the shipped
    [`examples/ims_icscf.py`](examples/ims_icscf.py) S-CSCF failover and the
    cookbook's failure-route snippet always claimed to do.
  - **`Contact` exposed no registration time,** so bindings could not be
    ordered by recency; remaining `expires` is not a substitute, since a UE
    that asked for 600 s and registered a second ago has less time left than
    one that asked for 3600 s an hour ago.
- **The 2xx ACK was relayed once per fork branch,** all resolving to the one UAS
  that answered, because the ACK path iterated the session's client branches
  (a comment there assumed "typically just one"). A 2xx ACK is a new request
  routed by the dialog route set (RFC 3261 §13.2.2.4) and belongs to exactly one
  remote target; a strict UAS treats the duplicate as an out-of-sequence request
  on a dialog it has already confirmed. Now sent once per distinct resolved hop.
- **`registrar.lookup()` did not sort,** despite its own documentation and both
  sibling lookups promising q-value order — it returned backend insertion order
  (oldest first). It now returns highest q first (RFC 3261 §20.10), and within
  one q value the most recently registered binding first. Since almost no UE
  sends q, recency is what actually orders a real AoR's bindings, which is the
  right default when a subscriber's SIM has moved to a new handset and the
  previous binding is still inside its granted expiry.
- **A binding's Path now outranks its captured inbound flow when routing a fork
  branch.** A binding registered *through* a proxy is reached via its Path
  vector; the captured flow answers the narrower "the Contact URI is
  unreachable, write back on the connection the REGISTER arrived on" question,
  and using it here sent the branch to the REGISTER's source while dropping the
  token that identifies which binding the request is for. With no Path the flow
  is unchanged — still the only way back to a WebSocket UE (RFC 5626 §5.3 /
  RFC 7118 §5).
- **B2BUA-originated requests are now retransmitted per RFC 3261 §17.1 on
  unreliable transports.** The proxy datapath relays through the transaction
  layer and so has always had Timer A (INVITE, §17.1.1.2) and Timer E
  (non-INVITE, §17.1.2.2). The B2BUA does not — it owns its legs and routes
  responses by branch, registering no client transaction — so every request it
  originated left the socket exactly once. A single lost datagram therefore
  produced total silence: no retry at 500 ms, nothing on the wire, and the call
  failing on the synthetic `408` when the 30 s answer timeout swept it, with the
  very next call succeeding. It showed up most sharply on an IPsec-protected
  originating leg, where the first packet after an idle gap or across an SA
  re-key is exactly the one at risk — a soft-UE MO call would fail cold and
  answer warm — but it applied to every UDP B2BUA leg. A lost `BYE` was the
  quieter half of the same gap: nothing retried it, so the far end kept the call
  up with its media still anchored.

  Each siphon-originated request (INVITE, CANCEL, BYE, re-INVITE/UPDATE, PRACK,
  REFER, forwarded in-dialog requests) now carries a retransmit schedule keyed on
  its own Via branch and method: `T1` then doubling without a ceiling for INVITE,
  doubling but capped at `T2` for the rest, giving up at `64·T1`. Intervals come
  from the configured transaction timers, so tuning `T1`/`T2` tunes these too.
  The schedule is cancelled by the first response on that branch (§17.1.1.2 — a
  provisional moves Calling → Proceeding), by a `CANCEL` for the INVITE it
  abandons (§9.1), and by the answer-timeout teardown. `ACK` is excluded
  (§17.1.1.3 — it is re-emitted in answer to a retransmitted final, never on a
  timer of its own), as are relayed responses, which belong to the server
  transaction. Reliable transports never arm a schedule and are byte-identical.

  A retransmission leaves the **same local socket** as the original, which is
  what makes it work on a flow-dialled leg: the kernel XFRM selector matches only
  the protected client port, so a retry that fell back to the default listener
  would go out unprotected and be dropped (3GPP TS 33.203 §7.4).

- **A `relay(flow=…)` INVITE's Timer A retransmits no longer leave the wrong
  socket.** The proxy relay and fork paths pinned `source_local_addr: None` on
  their client-transaction timer entries, so while the first send went out the
  flow's socket, every retransmit fell back to the default UDP channel — the
  first-configured listener, typically the plain one — putting the retry outside
  the IPsec SA on a multi-listener host. Retransmits now resolve the same egress
  socket the original send did (captured flow, then IPsec auto-source, then a
  script `send_socket=` pin).

- **Flow-pinned sends are now visible.** A request sent over a captured flow
  (`call.dial(flow=…)` / `relay(flow=…)`) bypasses the normal egress helper, and
  with it that helper's HEP capture — so a flow-pinned B-leg INVITE was the one
  request that never reached Homer. It is captured now, and the B-leg INVITE
  additionally logs its destination, source socket, transport and size at debug
  level. Nothing on that path logged before, which made an absent send line easy
  to misread as the request never having been handed to the transport.

- **`docs/media-engines.md` claimed SIPREC/MPTY subscriptions were unimplemented
  on `siphon-rtp` and would surface an engine error.** They have been wired on
  all three backends since the native backend shipped; the page was steering
  people away from a working path. The same page's "media profiles are identical
  across backends" statement is now qualified with the per-engine capability
  table.
- **SIP parser: four RFC 3261 grammar defects, found by importing the RFC 4475
  torture corpus.** All four are on the receive path used for every inbound
  datagram, so each one meant dropping a message that the RFC requires an
  element to accept and answer:
  - **Whitespace before `HCOLON`.** RFC 3261 §25.1 defines
    `HCOLON = *( SP / HTAB ) ":" SWS`, so `To :` and `Via  :` are legal. The
    header parser required the colon to follow the name immediately and
    rejected the whole message.
  - **`extension-method` token charset.** `extension-method = token`, which
    admits `! % * _ + ` ' ~` alongside alphanumerics, `-` and `.`. Only the
    latter three were accepted, so an unknown method could not be parsed and
    therefore could not be answered with a 501.
  - **Extension-method case.** RFC 3261 §7.1 makes the method case-sensitive.
    Unknown methods were uppercased on parse, so the CSeq no longer echoed the
    Request-Line and the peer saw a method mismatch.
  - **`absoluteURI` Request-URI.** `Request-URI = SIP-URI / SIPS-URI /
    absoluteURI`. A Request-URI in an unknown or atypical scheme
    (`nobodyKnowsThisScheme:...`, `soap.beep://...`) is syntactically valid and
    §8.2.2 requires a 416 Unsupported URI Scheme — which could not be sent,
    because the message failed to parse first.

- **An in-dialog request for a B2BUA call that was just torn down is answered
  `481 Call/Transaction Does Not Exist` instead of being silently dropped
  (RFC 3261 §12.2.2, §15.1.2).** Hang-up glare — both parties send BYE within a
  few hundred milliseconds — left the second BYE arriving after the call was
  gone. It missed every B2BUA intercept (they gate on the same Call-ID lookup
  that has just started failing), fell through to the proxy path, and a script
  with no route for it dropped it. The peer was then left retransmitting to its
  own timer F: 32 s of silence, answered only by the deferred non-INVITE auto-100
  (RFC 4320 §4.2). A VoNR UE reads that as a dead IMS and recovers by releasing
  its IMS PDU session and re-registering, so terminating calls fail for ~40 s.

  `CallActorStore` now remembers the SIP Call-IDs of calls it has torn down —
  every leg, since the two sides carry different Call-IDs and either peer can
  lose the race — and the dispatcher answers 481 for any in-dialog request
  naming one. A live call always wins over a remembered one, so a peer reusing a
  Call-ID for its next call is unaffected, and a Call-ID this node never tracked
  is still left to the script (a proxy loose-routes dialogs it does not own).
  Bounded by both age (32 s, Timer H) and count, so it stays flat under load.

  A re-INVITE for a torn-down call is covered too: it previously reached
  `on_invite` as if it were a brand-new call.

  Also brought the B2BUA BYE / re-INVITE / UPDATE / REFER / NOTIFY handlers to
  the same answer when they lose the race with a concurrent teardown — each
  returned silently where the neighbouring no-dialog-leg path already sent 481.

## [1.5.1] — 2026-07-29

### Added
- **`tls.certificates` — per-domain server certificates selected by inbound SNI
  (RFC 6066).** One `listen.tls` / `listen.wss` socket can now serve a different
  certificate per server name, the equivalent of OpenSIPS `tls_mgm` per-domain
  certificates and Kamailio's `tls_domain`. Previously the whole listener was
  pinned to the single `tls.certificate`/`tls.private_key` pair, so serving
  several domains meant one SAN certificate covering all of them — which couples
  every domain to a single renewal (one failed ACME validation blocks the
  certificate for all of them) and shows every peer the full list. Each entry is
  an independent pair:

  ```yaml
  tls:
    certificate: "/etc/siphon/tls/default.crt"   # served when nothing matches
    private_key: "/etc/siphon/tls/default.key"
    certificates:
      - server_names: ["sip.tenant-a.example", "sip.tenant-a.net"]
        certificate: "/etc/siphon/tls/tenant-a.crt"
        private_key: "/etc/siphon/tls/tenant-a.key"
      - server_names: ["*.tenant-b.example"]
        certificate: "/etc/siphon/tls/tenant-b.crt"
        private_key: "/etc/siphon/tls/tenant-b.key"
  ```

  Names match case-insensitively (RFC 4343); a wildcard matches exactly one
  leading label (RFC 6125 §6.4.3 — `ue.tenant-b.example` yes,
  `tenant-b.example` and `a.b.tenant-b.example` no); an exact entry wins over a
  wildcard covering it. Anything unmatched, including every client that sends no
  SNI at all (any peer addressing siphon by IP literal, which RFC 6066 forbids
  from sending one), falls back to the top-level pair — selection never aborts a
  handshake, and a config without `certificates:` is byte-for-byte the previous
  behaviour. The block is shared by `listen.tls` and `listen.wss` as before, and
  every pair is watched for changes independently, so each domain hot-reloads on
  its own renewal schedule instead of only when some other domain happens to
  renew. A duplicate server name, an entry with an empty `server_names`, a
  malformed wildcard, or a certificate that does not match its key are hard
  startup errors naming the offending path, rather than silently deciding which
  certificate a peer gets. `verify_client` / `client_ca` remain listener-wide.
  The server name is client-supplied plaintext and is used only to pick a
  certificate — it is not an identity signal.

### Fixed
- **A B2BUA B-leg dialled over a captured flow advertised the wrong socket, so
  its responses came back nowhere.** `call.dial(flow=…)` writes the B-leg INVITE
  to the flow's own local socket, but the `Via` sent-by and `Contact` were built
  from the default per-transport listener. The far end answers to the sent-by,
  so the response was directed at a socket the flow does not cover — and on an
  IPsec sec-agree leg (3GPP TS 33.203 §7.4) that means a port outside the
  security association, where the answer is simply lost. The visible symptom was
  an originating call that drew no response at all — not a 4xx, silence — and
  failed with a synthetic `408` at the answer timeout. Worst on a soft-UE
  registering into an IMS core (`registration.flow()` + `call.dial(flow=…)`,
  `examples/ims_ue_b2bua.*`), where the INVITE leaves the protected client port
  while the `Via` named the plain SIP listener. The proxy `relay(flow=…)` path
  has always pinned its `Via` to the flow; the B2BUA path never did.

  A flow-dialled B-leg is now anchored on the flow's socket for its whole life:
  the INVITE's `Via` and `Contact` name it, the leg records it, and every later
  siphon-originated request on that leg — ACK, BYE, CANCEL, auto-PRACK,
  session-timer refresh, bridged re-INVITE/UPDATE — both leaves from it and
  advertises it. B-legs without a flow, and every single-listener deployment, are
  byte-for-byte unchanged.
- **An initial NOTIFY could overtake the 2xx that accepted its subscription.**
  A script that replies to a SUBSCRIBE and then calls `subscribe_state.notify()`
  / `presence.notify()` had the reply and the NOTIFY enqueued as two independent
  messages, which does not order them on UDP. RFC 6665 §4.1.2.3 has the notifier
  send the initial NOTIFY once the subscription is accepted — that is, after the
  2xx. §4.4.1 obliges a subscriber to cope with the reverse arrival order, but
  that allowance exists for a network that reorders in flight; it is not licence
  for the notifier to emit out of order in the first place. Deferred messages
  addressed to the same peer as the reply now leave as ordered followups of it.
  Deferred messages for any other peer are unaffected and still go out at the end
  of the request.
- **A completed transfer could BYE the referrer before telling it the transfer
  succeeded.** At the end of a siphon-terminated REFER the B2BUA sends the
  referrer a terminating `NOTIFY` (sipfrag `200 OK`,
  `Subscription-State: terminated`) and then BYEs that leg. Both went out as
  separate enqueues to the same peer, which does not order them on UDP (same
  cause as the 202/NOTIFY inversion below). Arriving inverted, the referrer
  tears the dialog down on the BYE and answers the late NOTIFY with `481`,
  never learning the outcome of the transfer it requested — RFC 3515 §2.4.4
  makes that NOTIFY the result report, and RFC 5589 §6 shows it ahead of the
  BYE. The pair now travels as one ordered unit when both target the same flow.
- **REFER `202 Accepted` could be overtaken by its own first NOTIFY on UDP.**
  On a siphon-terminated transfer the B2BUA answers `202` and immediately sends
  the `message/sipfrag` `NOTIFY (100 Trying)` that opens the implicit
  subscription. Both were enqueued in the right order, but the UDP transport
  does not preserve it: every UDP worker clones the same outbound receiver
  (flume is MPMC) and owns its own `SO_REUSEPORT` socket, so the two messages
  are routinely picked up by two workers and race to `send_to`. When the NOTIFY
  won, a referrer saw a NOTIFY for a subscription it had not been told existed
  yet — RFC 3515 §2.4.4 has the 202 establish it — and a strict UA is entitled
  to reject it. The pair is now enqueued as one ordered unit that a single
  worker writes in sequence, so nothing can interleave between them. Stream
  transports were never affected (one distributor task per listener) and are
  unchanged. This was also the cause of the intermittent
  `sipp-b2bua-refer` CI failure (`while expecting '202' … received 'NOTIFY'`).
  Regression-guarded by a multi-worker UDP ordering test.
- **A proxy addressed by IP no longer 404s every in-dialog request.** Route
  recognition (RFC 3261 §16.4 — remove the top Route only when it "indicates
  this proxy") matched the Route host against `domain.local` alone, but
  Record-Route is stamped with the *advertised* host, or the bind address when a
  transport configures none. `domain.local` is the list of SIP domains served,
  which for a proxy reached by IP legitimately contains no IP at all, so siphon
  would insert a Record-Route and then refuse to consume the Route the UA
  faithfully echoed back: `request.loose_route()` returned `False` and the
  shipped proxy scripts answered `404` to the BYE (and to every other sequential
  request) of an otherwise healthy dialog. Self-identity is now built from every
  listener in the transport registry plus each one's advertised host, the
  wildcard-bind fallbacks, and the IPsec protected ports — that is, every host
  siphon can actually stamp. `domain.local` remains purely the served-domain
  list, still used for `ruri.is_local` and the Rf/Ro charging role, and still
  honoured as an any-port alias so deployments that worked around this by adding
  their own address to it need no change.
- **Dual-stack and multi-listener deployments are covered.** The dispatcher's
  per-transport listen/advertise maps keep only the *first* listener of each
  transport, so a dual-stack Gm P-CSCF's IPv6 listener — and any second listener
  with its own `advertise` — was absent from the identity. Route recognition now
  reads the full listener registry, the same source loop detection already used.
- **The 2xx ACK no longer strips a Route belonging to a downstream proxy, or
  drops itself.** The ACK path popped the top Route whenever it carried `;lr`
  without checking the Route identified siphon, sending the ACK one hop too far
  past an intervening loose router (RFC 3261 §16.4). Both in-dialog paths now
  share one route-consumption routine, so they cannot disagree about the same
  dialog's route set. This also closes a way for the ACK to be lost outright: an
  unrecognised self-Route became the computed next hop, which the loop guard
  then correctly identified as siphon and silently discarded.
- **A Route at one of siphon's own addresses on a port it does not serve is no
  longer consumed.** Matching ignored ports, so a proxy co-located on the same
  address (an S-CSCF on `:6060` beside a P-CSCF on `:5060`) had its Route
  stripped too, bypassing it entirely. Matching is now port-aware against the
  ports siphon binds, including the IPsec protected ports.
- **The shipped scripts no longer reject an in-dialog request routed via another
  proxy.** `scripts/proxy_default.py` and ten example scripts answered
  `404 Not Here` whenever `request.loose_route()` returned `False`, but a `False`
  return means the top Route belongs to somebody else and `relay()` should follow
  it (RFC 3261 §16.6) — the documented contract, and what the method's own
  docstring says. So a siphon sitting in front of another loose router (a
  P-CSCF ahead of an S-CSCF, an edge proxy ahead of an AS) rejected mid-dialog
  requests it should have forwarded. All twelve sites now loose-route and
  forward unconditionally; the only remaining `404` is `registrar_proxy.py`'s
  genuine "no contacts registered" case.
- **CI now covers Route self-identity on the wire.** A new `sipp-route-selfid`
  job runs `scripts/route_selfid_test.sh` against a config whose `domain.local`
  holds only the served domain — the shape of a proxy addressed by IP. The
  existing functional stack could not catch this class of defect because its
  test config lists the container address under `domain.local`, which makes a
  Record-Route recognisable even when Route recognition is keyed on served
  domains alone. The check is deterministic and needs no capability: the UAC
  waits for a 200 to its in-dialog BYE, which only arrives if the self-Route was
  consumed and the request relayed.
- **`request.loose_route()` fails closed.** On the `@proxy.on_reply` /
  `on_failure` / `on_cancel` handler paths the request carried no self-identity
  at all, and `loose_route()` popped any `;lr` Route unconditionally — the same
  §16.4 violation, reachable from the documented failure-retry pattern. Those
  requests now carry the full identity, and a request without one declines to
  consume rather than stripping a hop it cannot attribute to itself.

### Changed
- **Bump the `siphon-bin` SMPP extension to siphon-smpp v1.3.1**, which picks up
  `smpp34` 1.2.1's lost-response fix: both writer tasks registered a request's
  pending-response entry only *after* the socket write returned, and the read
  loop drops any response it has no entry for, so a response landing in that gap
  was discarded and the caller blocked until its 30s response timer expired —
  the PDU was lost, not merely slow. It hit the SMSC→ESME direction too, i.e.
  the delivery-receipt path. Also surfaces smpp34's `error!` diagnostics in the
  load harness. Only affects builds with `--features smpp`; the plain `siphon`
  binary is unaffected.

## [1.5.0] — 2026-07-27

### Added
- **`address_family` on a media profile — IPv4/IPv6 interworking on the media
  plane.** A `media.profiles.<name>.offer` / `.answer` block can now pin the
  address family the media engine allocates its relay endpoints in for that side
  of the call (`IP4` / `IP6`, the SDP `addrtype` spelling; `ipv4` / `ipv6` are
  accepted and normalised). Unset — the default — keeps today's behaviour: the
  engine follows the offered SDP, so the relay is single-family. Setting it is
  what lets a v6-only access leg (VoNR / IPv6 VoLTE) bridge to a v4 core: the
  profile used toward the core sets `IP4`, the one back toward the UE `IP6`.
  Wired on both modern backends — **rtpengine** receives it as the dedicated
  `"address family"` NG dict key (it is a first-class key there, *not* a token in
  the `flags` list, where the engine would ignore it), **siphon-rtp** as the
  `address_family` control field. The classic `rtpproxy` backend has no
  equivalent — its `6` modifier states the family of the address the command
  carries, it does not select one — so siphon logs a warning at boot naming any
  profile that asks for it there. An unrecognised value fails the config load
  rather than being passed to an engine that would drop it silently.
- **`listen.mtu` — RFC 3261 §18.1.1 UDP→TCP fallback for oversized requests.**
  When `listen.mtu` is set, an outbound SIP *request* built for UDP whose
  serialised length exceeds `mtu − 200` bytes is relayed over TCP instead — but
  only when the next hop has a **reachable** TCP listener (confirmed by a short
  connect probe on the over-MTU path); otherwise it stays on UDP (delivered,
  fragmented) with a `warn`, so an over-MTU request is never dropped against a
  UDP-only peer. This stops an oversized IMS-core NOTIFY (large
  `reginfo+xml` / iFC fan-out) from IP-fragmenting and being silently dropped by
  UEs / IPX peers with strict ICMP filtering. Applies to the proxy relay, fork,
  and B2BUA dial paths; responses follow the request's transport and the inbound
  side is unchanged. Default is off (no behaviour change on a bump); IMS
  deployments set `1280` (the IPv6 minimum MTU). Family-agnostic — works for v4
  and v6 next hops. Kamailio analog: `udp_mtu` + `udp_mtu_try_proto=TCP`.
- **Dual-stack (IPv4 + IPv6) P-CSCF — per-family Gm identity.** A P-CSCF can bind
  a v4 and a v6 Gm listener set at once and now stamps the family-matching local
  identity on each UE's signalling instead of collapsing to the first configured
  listener. Responses, Contact and Record-Route toward the UE carry a v6 host for
  a v6 UE (v4 for v4); the IPsec sec-agree SA's P-CSCF side is selected to match
  the UE's family (a mismatch now errors loudly rather than installing a dead
  mixed-family XFRM selector); the SDP `o=` rewrite emits an unbracketed address
  with the correct `IN IP4`/`IN IP6` addrtype; the IPsec/flow-relay Via paths and
  the `force_send_via` target split are IPv6-bracket correct; and DSCP marking now
  sets `IPV6_TCLASS` on v6 sockets (was IPv4-only, so v6 egress went unmarked).
  Loop detection checks every configured listener across both families. Configure
  explicit per-family listeners, each with an optional per-listener `advertise`
  (see `examples/ims_pcscf.yaml`). Core-side (Mw / outbound) dual-stack is a
  separate follow-up.
- **WhatsApp Business Calling gateway example.** WhatsApp's Business Calling API
  is SIP-over-TLS to `wa.meta.vc`, so SIPhon bridges WhatsApp voice to an internal
  SIP/IMS network as a B2BUA in both directions with no new protocol code — a TLS
  trunk plus a routing script. New `examples/whatsapp_calling.{py,yaml}` (server-
  auth TLS with no client cert, outbound digest via `call.set_credentials()`,
  direction detection via `call.from_gateway()` on Meta's source ranges
  (`gateway.groups[].source_networks`, handshake-verified on TLS), OPUS passthrough,
  SDES via the built-in `srtp_to_rtp`/`rtp_to_srtp` profiles and DTLS-SRTP via new
  `whatsapp_dtls_in`/`whatsapp_dtls_out` profiles, and no session timer since Meta
  rejects re-INVITEs) plus a `docs/cookbook/whatsapp-calling.md` recipe. The
  messaging side (Cloud API) is a separate HTTP example in the siphon-http addon.
  SDK fix along the way: the `Call` mock's `set_from_user()` / `set_ruri_user()`
  now mutate the parsed URI (they previously did string ops on a `SipUri` and
  raised), matching `set_to_user()`.
- **Docker Compose quickstart + Getting started guide.** A root
  `docker-compose.yaml` runs the published image with your `siphon.yaml` and
  `scripts/` bind-mounted (host networking, hot-reload, a SIP `OPTIONS`
  healthcheck), so `git clone && docker compose up -d` starts a working proxy
  with nothing to build. A new `Getting started` docs page leads with that path
  and folds in the native/`.deb`/`.rpm` options plus the common Ubuntu build
  gotchas (old `apt` rustc, missing `python3-dev`).
- **SDK: `Request.remove_headers_matching(prefix)`** in the `siphon-sip` mock,
  mirroring the production request method (it was only on the `call` mock), so
  script unit tests can exercise header-prefix stripping on a proxy request.
- **Cookbook recipes: SIP & SDP manipulation (HMR), Number routing (LNP +
  redirect server), and Quick recipes** (common-case snippets), plus a runnable
  `examples/number_routing.py`. The existing Least-Cost Routing recipe is now
  wired into the docs-site navigation.
- **Least-Cost Routing (LCR) — B2BUA-only.** A new `lcr` scripting namespace
  (`await lcr.route(call)`) queries an external HTTP JSON API for an ordered
  carrier decision (the API owns cost/order; siphon is not a rating engine),
  caches it in a named cache, and `call.route(decision.routes)` executes it with
  **sequential failover**: try cheapest-first, resolve each carrier's
  `gateway_group` to a healthy member (skip a pool that is down), and advance to
  the next carrier on reject/ring-timeout — each attempt a fresh B-leg dialog
  (new Call-ID), so no carrier ever sees a reused Call-ID. On answer,
  `call.active_route` is the carrier that won (stamp it onto a CDR). New `lcr:`
  config (`api_url`, `timeout_ms`, `cache`, `cache_ttl_secs`, `auth_header`,
  `fallback_gateway_group`, `reroute_causes`). Per-carrier shaping: a
  **`tech_prefix`** (dial-prefix prepended to the R-URI userpart), a full `ruri`
  override, a **`number_policy`** (per-carrier From/To/PAI reshaping via a named
  `number_policies:` preset), injected `headers`, and **`cdr_fields`** the API
  auto-stamps onto the CDR when a carrier wins (no per-field script). An unknown
  `gateway_group` is warned, not silently dropped, and `gateway.add_group`/
  `remove_group` let routes reference groups added at runtime (no restart).
  **Reroute causes** — which SIP codes fail over vs. forward to the caller — are
  selectable per-route (API) > per-gateway (`gateway.groups[].reroute_causes`) >
  global (`lcr.reroute_causes`, default `[408, 500, 502, 503, 504]`). B2BUA-only
  by design (dialog hygiene, per-carrier media, charging). Example:
  `examples/lcr_b2bua.py` + a FastAPI reference API `examples/lcr_api_server.py`;
  SDK contract models in `siphon_sdk.lcr`.
- **`call.fork(strategy="sequential")` now actually fails over.** The strategy
  was previously ignored (every target was rung in parallel); it now tries the
  targets one at a time, advancing on failure, via the same engine as
  `call.route(...)`.
- **Diameter Ro online charging (prepaid), reserve-before-connect.** A B2BUA
  reserves credit with a Credit-Control CCR-INITIAL in `@b2bua.on_invite` via
  `await call.ro_authorize()` BEFORE the B-leg is dialed: a grant dials, a denial
  rejects (402) and no B-leg is ever created (no call unless the OCS allows it).
  After the grant siphon runs the SCUR lifecycle itself — CCR-UPDATE on the
  OCS-granted cadence, mid-call disconnect on `4012 CREDIT_LIMIT_REACHED` /
  Final-Unit-Indication, CCR-TERMINATION on BYE (and a zero-usage release on
  pre-answer failure/CANCEL). Configured via a new `ro:` block
  (`reauth_interval_secs`, `requested_seconds`, `service_context_id`, `charge`,
  `on_ocs_failure`, `rating_group`, ...). Voice is SCUR; SMS/RCS is one-shot IEC
  (`diameter.ro_ccr_event`, `Requested-Action = DIRECT_DEBITING`). `4011
  CREDIT_CONTROL_NOT_APPLICABLE` lets a call run free of charge. B2BUA-only:
  mid-call teardown needs session ownership, which is why 3GPP triggers Ro at the
  AS/MMTel-AS, not the P-CSCF. Interoperates with CGRateS. New cookbook
  `docs/cookbook/online-charging-ocs.md` + example `scripts/b2bua_ro_charging.py`.
- **The Ro credit-control scripting methods are now async** (`await`-able):
  `diameter.ro_ccr_initial` / `ro_ccr_update` / `ro_ccr_terminate` / `ro_ccr_event`
  and `call.ro_authorize()` return coroutines, so a slow OCS round-trip runs off
  the Python driver thread instead of blocking it. Mirrored in the `siphon-sip`
  SDK mock (`set_ro_result_code` / `set_ro_granted_time` / `captured_ccrs`).
- **`siphon_rf_sessions` / `siphon_ro_sessions` metrics** — gauges of live Rf
  accounting and Ro credit-control sessions (START/INITIAL without a matching
  STOP/TERMINATION); a monotonic climb under a steady, completed-call workload
  flags a charging-session leak.
- **B2BUA call transfer (REFER, RFC 3515 / 3891 / 5589) with three modes.**
  `@b2bua.on_refer(call)` handles an in-dialog REFER on a tracked call (single
  arg, no reply object, REFER is a request). read the target off `call.refer_to`
  and, for attended transfers, `call.refer_replaces` (Replaces dict:
  `call_id` / `from_tag` / `to_tag` / `early_only`).
- **`call.accept_refer(target=None, next_hop=None, mode=None)`** accepts a
  transfer in one of three modes: `"terminate"` (siphon-terminated, the default)
  answers `202` and the sipfrag NOTIFYs itself, re-resolves `Refer-To` through the
  dial plan as a new leg, re-bridges the surviving party, and BYEs the
  referred-away leg; `"transparent"` re-emits the REFER on the far leg's own
  dialog and relays its `202` + `message/sipfrag` NOTIFYs back to the referrer;
  `None` uses `b2bua.default_refer_mode`. `target=` rewrites the destination and
  `next_hop=` steers egress. `call.reject_refer(code, reason)` declines.
- **siphon-originated (outbound) REFER.** `call.refer(target, replaces=None)`
  sends a REFER deferred from a `@b2bua.*` handler that holds a `call`;
  `b2bua.refer(call_id, target, replaces=None)` is the imperative twin for event
  callbacks that only have a `call_id` (e.g. `@rtpengine.on_dtmf`). use for
  IVR / TAS offload: answer, play a prompt, then hand the caller off.
- **`b2bua.default_refer_mode` config knob** (`terminate` | `transparent`,
  default `terminate`) sets the mode used when `accept_refer(mode=None)`.
- **proxy-mode REFER passthrough** is documented and covered by a SIPp test: in
  proxy mode an in-dialog REFER is loose-routed to the far end (record-route
  required) and its `202` + sipfrag NOTIFYs relay straight back, so the transfer
  runs endpoint-to-endpoint with no siphon-side state. no code change (the generic
  in-dialog branch already handled it); the loop fix below is B2BUA-only.
- **terminate-mode transfer now re-anchors media correctly.** the transfer target
  is offered the **surviving** party's media (not the referrer's, who is being
  dropped), and the survivor is re-INVITEd with the target's answer, so RTP is
  aimed correctly end to end. when the call is media-anchored (rtpengine /
  siphon-rtp) siphon re-anchors the survivor↔target pair on a fresh media session
  and tears down the old survivor↔referrer anchor, keeping the anchor in the media
  path across the transfer (LI / transcoding / NAT preserved).
- **siphon now owns the SDP `o=` line per leg** (a stable session-id with a
  monotonic version) on every offer/answer it emits into a B2BUA dialog. a
  re-anchor (transfer, hold) presents a strictly greater version under the same
  session identity, so a strict RFC 3264 §8 answerer re-negotiates cleanly rather
  than reading a changed offer as unchanged. previously the peer's `o=` was passed
  through with only the username masked.
- **Dashboard charts now have a scale and hover history** (experimental web UI).
  Each sparkline draws its actual y-axis min/max on-chart, and hovering any point
  shows a tooltip with the exact value and how long ago it was sampled, so a dip
  reads as a real number instead of an unlabelled wiggle. Memory is shown to one
  decimal (MB) so a sub-MB change tracks the line instead of looking frozen.
- **Overview flags gateway trouble at a glance** — a "Gateway groups" line in the
  Connections & health block shows how many groups have an unhealthy destination
  (green when all healthy, amber with a count when not), click-through to the
  Gateways view. Backed by a new `gateways` summary in `GET /admin/metrics.json`.
- **Gateways view shows missed health-checks** — a destination that has failed
  consecutive probes shows an `n/threshold missed` badge (amber while still up as
  an early warning, red once down). `GET /admin/gateways` destinations gain
  `checks_missed` and each group gains `failure_threshold`.

### Changed
- **The example `siphon.yaml` now defaults `advertised_address` to `127.0.0.1`**
  so it works out of the box for local use (a softphone on the same host,
  loopback SIPp, the scale-test harness). **Set it to your public / LAN address
  for any real deployment** — a wildcard-bound siphon with no `advertised_address`
  auto-detects a routable interface, which on a multi-homed host (LAN + docker +
  VPN) can be the wrong one.
- **B2BUA answer-timeout is now honored within ~0.5s of the deadline** (was up to
  30s late). The `call.fork`/`call.dial`/`call.route` `timeout=` check moved off
  the 30s orphan sweep onto a dedicated 500ms interval, so a short per-carrier LCR
  ring timeout ("try carrier X for N seconds, then re-route") re-routes promptly
  instead of stalling the call.
- **Calls view shows both the caller and the dialed callee.** Previously it showed
  the A-leg From (which is actually the dialed identity, not the caller) and the
  B-leg target, so a bridged call looked like it only had one side. `GET /admin/calls`
  now returns `a_party` (caller) and `b_party` (dialed callee) in place of
  `from`/`to`, and the B-leg count excludes the re-INVITE/UPDATE response-tracking
  pseudo-legs, so a plain call that re-INVITEd no longer reports two B-legs.

### Fixed
- **`proxy.send_request()` now always emits a From tag (RFC 3261 §8.1.1.3).**
  Script-originated out-of-dialog requests (e.g. an IP-SM-GW delivering an
  RP-ACK or an MT SIP MESSAGE) went on the wire with a tagless `From` when the
  script supplied a `From` header without one, so a strict UAS — a real VoLTE
  handset — answered `400 Bad Request` and every such delivery was rejected. The
  UAC path already auto-managed the other mandatory single-value headers
  (Call-ID, CSeq, Via, Max-Forwards) but treated `From` as opaque pass-through.
  It now guarantees a tag: a script-pinned `From;tag=…` is preserved verbatim,
  an untagged `From` gains a generated tag (display name and existing params
  kept), and a request with no `From` at all is given one built from the
  advertised identity. The compact `f` form is handled identically.
- **B2BUA auto-PRACK for a reliable provisional now routes to the early-dialog
  remote target (the UE `Contact`), not the To AoR.** When the B-leg answered
  preconditions with a reliable `183` (`Require: 100rel`), the auto-PRACK's
  Request-URI fell back to the dialog AoR because the remote `Contact` was only
  captured on the final `2xx` (which hasn't arrived at PRACK time). Against an
  IMS core the home-domain R-URI is treated as a fresh terminating request and
  rejected `482 Loop Detected`, so the UE never gets its PRACK, never rings, and
  the caller CANCELs. The Contact, To-tag and route set are now captured from the
  reliable provisional that establishes the early dialog (RFC 3262 §4 / RFC 3261
  §12.1.2). Forked early dialogs (several `18x` with distinct To-tags/Contacts on
  one INVITE branch) are each PRACKed to their own Contact, with per-dialog PRACK
  de-duplication keyed on the remote To-tag (their RSeq spaces are independent).
- **B2BUA B-leg answer-timeout no longer panics a worker thread.** The
  answer-timeout sweep runs in the dispatcher's async loop (a tokio worker) and
  fires an async `@b2bua.on_failure`; the synchronous dispatch used a bare
  `block_on`, which panics "Cannot start a runtime from within a runtime" on a
  worker thread. It now yields the worker (`block_in_place`) before blocking, so
  the timeout handler runs instead of the worker panicking.
- **B2BUA answer / provisional handling is now race-free under concurrent
  dispatch.** Two check-then-set decisions read a `call_state` snapshot taken
  early in response handling but committed the new state only ~1600 lines later,
  so under multi-worker dispatch two responses for the same call — a `200` and
  its retransmit, or a `180` and its `200` (received in order over one flow but
  processed on different workers) — could both act on a stale "not answered"
  view: (1) two B-leg `200`s both forwarded to the A-leg, delivering a duplicate
  `200` to a caller that already ACKed; (2) a `180` processed behind its `200`
  forwarded to the A-leg after the final response, downgrading the confirmed
  dialog back to Ringing. Both are now claimed atomically under the per-call
  lock (`try_win` / `try_mark_ringing`). Loopback is too fast to expose these,
  but a real TCP trunk with network latency at high call rates widens exactly
  that window.
- **B2BUA auto-PRACK now carries the early-dialog To-tag** (RFC 3262 §4 / RFC 3261
  §12.1.2). When the B-leg sent a reliable provisional (`18x` with `Require:
  100rel`), siphon built the PRACK's `To` from the dialog's remote tag — but that
  field is only populated from the `200 OK`, which hasn't arrived yet at PRACK
  time, so the PRACK went out tag-less and a strict UAS (e.g. an IMS S-CSCF)
  rejected it with `481 Call/Transaction Does Not Exist`, breaking VoLTE calls
  that use reliable provisionals / preconditions. The reliable provisional
  establishes the early dialog, so its To-tag (and route set, already handled) is
  now captured onto the B-leg before the PRACK is built. The SIPp reliable-prov
  scenario now asserts the PRACK's To-tag, which is why this slipped through.
- **B2BUA no longer mis-handles a cancelled B-leg during failover** (surfaced by
  LCR ring-timeout reroute; also affects any CANCEL-then-answer-a-different-leg
  flow). Three fixes: (1) a `2xx` to a B-leg CANCEL shares the INVITE's top Via
  branch (RFC 3261 §9.1), so it was branch-matched and misclassified as the
  cancelled carrier *answering* — marking the wrong leg the winner and sending the
  late ACK / BYE to the cancelled carrier; non-INVITE-CSeq responses are now
  absorbed. (2) A provisional (e.g. a `180` reordered behind its `200` under the
  multi-worker UDP receive) that arrives after the call is answered is dropped
  instead of forwarded (and no longer downgrades the confirmed dialog to Ringing).
  (3) A straggler non-2xx from a cancelled/losing carrier after answer is ACKed
  and absorbed rather than torn down toward the caller.
- **Diameter Session-Id uniqueness under concurrency** — `new_session_id` read
  the Hop-by-Hop/End-to-End counters without reserving them, so two requests
  built concurrently could mint the *same* Session-Id, collapsing two accounting
  or credit-control sessions into one at the CDF/OCS (cross-charging; one STOP
  ending both). Session-Ids now come from a dedicated atomic sequence with a
  wall-clock-seeded high part (RFC 6733 §8.8). Affects Rf and Ro.
- **Diameter charging AVP codes corrected to RFC 8506 / IANA** — the
  Credit-Control (Ro/Gy) AVP dictionary used a self-consistent but non-standard
  numbering (e.g. Granted-Service-Unit, CC-Time, CC-Total-Octets, Final-Unit-*,
  Rating-Group and Multiple-Services-Credit-Control were all on the wrong codes,
  MSCC even under the 3GPP vendor namespace). They now match the on-the-wire
  values a real OCS expects, so Ro requests interoperate instead of being
  rejected/misparsed. A known-answer test pins every code to the registry.
  **Wire-affecting** for anyone already driving Ro/Gy from scripts.
- **Diameter offline-charging (Rf) SMS AVP codes** — SMS-Result (was 3408 =
  SM-Sequence-Number, now 3409) and MTC-IWF-Address (was 3413, now 3406) are
  emitted on the correct codes, so a CDF parses the SMS record fields instead of
  mislabeling them.
- **CER application advertisement** — the Rf accounting application (id 3) was
  advertised as an `Auth-Application-Id` inside a `Vendor-Specific-Application-Id`
  with `Vendor-Id: 0`, two RFC 6733 violations that make strict peers
  (go-diameter/CGRateS) answer `DIAMETER_NO_COMMON_APPLICATION`. Accounting apps
  are now advertised via `Acct-Application-Id`, and base (vendor-0) apps are no
  longer wrapped in a VSAI.
- **Rf accounting hardening** — IMS-Information and SMS-Information now nest under
  a single `Service-Information` (TS 32.299 §7.2.87 allows only one, was two);
  the non-conformant `User-Session-Id` directly under `Service-Information` is
  dropped; a rejected ACR-START no longer opens a local session or INTERIM timer;
  an explicit `Acct-Interim-Interval: 0` from the CDF is honored; and an
  abandoned session (no ACR-STOP) is released by a max-lifetime backstop.
- **in-dialog REFER on a tracked B2BUA call no longer proxy-relays and can no
  longer loop.** a REFER arriving inside a bridged B2BUA dialog used to fall
  through to the proxy relay path, which could bounce it back through the same
  B2BUA and loop. it is now intercepted at the B2BUA and dispatched to
  `@b2bua.on_refer`. with no `@b2bua.on_refer` handler registered siphon rejects
  it locally with `603 Decline` and relays nothing (loop-safe default).
- **B2BUA rtpengine session cleanup on a B-leg-originated BYE.** the media-session
  safety-net delete keyed on the incoming BYE's Call-ID, which is not the store
  key (the A-leg Call-ID) when the BYE comes from the callee (or from the
  survivor / target after a terminate-transfer re-anchor); it now keys on the
  A-leg Call-ID so the session is always cleaned up.

## [1.4.1] — 2026-07-15

### Added
- **Embedded web dashboard on the admin listener — EXPERIMENTAL** (`ui` cargo
  feature + `admin.ui.enabled`). Serves a single-page operator dashboard
  same-origin with the admin API — Overview (live tiles + charts for dialogs, SIP
  request rate, and memory), Calls (active B2BUA calls), Registrations
  (searchable, with force-unregister), Security (threat counters + active bans,
  with lift-ban), Gateways (per-group destination health, with drain/enable),
  System (jemalloc/glibc memory, Python executor pool, runtime facts), and
  Integrations (Diameter / rtpengine / SBI). Assets are baked into the binary (no
  external files, no runtime fetch). The **release Docker image compiles it in by
  default**; the plain `cargo build` leaves it off, so any library consumer pulls
  none of it. Serving the dashboard logs an EXPERIMENTAL warning; a binary built
  without `--features ui` warns and serves nothing when `admin.ui.enabled` is set.
- **`GET /admin/metrics.json`** — a curated JSON snapshot of the live gauges and
  counters (SIP, memory, Python executor, Diameter, rtpengine, SBI, security),
  intended for the dashboard and any custom tooling that would rather not parse
  the Prometheus text format. Cumulative counters are exposed raw so a client
  diffs them over time to derive rates.
- **`GET /admin/gateways`** — per-group gateway dispatcher status: every
  configured group with its algorithm and each destination's health, weight,
  priority, address, transport, and attributes, read from the shared dispatcher
  (no new state or probing). Surfaced as a Gateways panel on the dashboard's
  Integrations page.
- **`POST /admin/gateways/{group}/{destination}/{up|down}`** — manually mark a
  gateway destination up or down (drain a bad carrier from the dashboard, then
  restore it), with a per-destination button on the Gateways panel. Mutating, so
  it requires the admin bearer token.
- **`GET /admin/calls`** — active B2BUA calls (internal id, SIP Call-ID, state,
  A-leg From, B-leg target, and B-leg count), read from the dispatcher's call
  store. Surfaced as a dedicated Calls view on the dashboard (which now groups
  the nav into Monitor / Routing / System, with Gateways in its own Routing
  section). Empty on a proxy-only node.
- **Bearer-token auth for the admin API** (`admin.auth.token`). When set, every
  mutating route (`POST`/`PUT`/`PATCH`/`DELETE` — force-unregister, lift-ban,
  gateway up/down) requires `Authorization: Bearer <token>`, compared in
  constant time; set `admin.auth.protect_reads: true` to require it on the read
  routes and `/metrics` too. Unset leaves the admin API open exactly as before.

### Changed
- **Bound to a wildcard address with no `advertised_address`, Via/Contact and the
  outbound socket source now use the host's auto-detected routable local IP
  instead of `127.0.0.1`.** An instance listening on `0.0.0.0` / `[::]` without
  `advertised_address` used to advertise loopback, which no remote peer can reach
  and from which no new outbound TLS connection can be opened. The shared
  address resolver now performs a dependency-free route lookup to pick the
  primary local address; loopback remains only as a last resort on a host with no
  default route. Setting `advertised_address` explicitly is still recommended
  behind NAT, where the auto-detected address is the private one.

### Fixed
- **In-dialog re-INVITE / UPDATE / BYE are now routed by SIP dialog identity, not
  by source socket.** A B2BUA decided which leg an in-dialog request belonged to
  by comparing the request's source address against that leg's original INVITE
  socket. A peer that opens a fresh connection per transaction (a new TLS
  connection has a new source port, as some carrier SBCs do) or rebinds its NAT
  port therefore looked like it came from the wrong leg: the request was
  reflected back at the leg it arrived on instead of being bridged to the far
  leg. The consequence was a re-INVITE that never reached the other side, media
  that was never renegotiated, and the call being torn down seconds later.
  Direction is now taken from the Call-ID (with the From-tag as a tie-breaker for
  `preserve_call_id` dialogs); an in-dialog request whose Call-ID matches no live
  dialog leg is answered `481 Call/Transaction Does Not Exist`. The originating
  leg's flow is refreshed on every in-dialog request so the response and later
  requests reach the peer's live connection, and a B-to-A forward reuses that
  live connection (falling back to the remote-target Contact when a TLS
  connection has closed) instead of dialing the peer's dead ephemeral source
  port.

## [1.4.0] — 2026-07-14

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
- **Routing a call to a gateway FQDN no longer pays a per-call DNS resolve.** When
  a next hop is a configured `gateway` destination with a hostname URI (an FQDN SIP
  trunk, a Teams Direct Routing SBC `sip*.pstnhub.microsoft.com`), the datapath now
  reuses the address the health prober already resolved for that destination
  instead of doing a blocking `resolve()` on every relay/dial. On a low-traffic
  node the resolver's own cache goes cold between calls, so each call was blocking
  the worker on a fresh A/AAAA lookup — visible as a ~1 second gap between "call
  received" and the outbound request going on the wire (and a matching gap in the
  SIP trace). The cached address is the prober's, refreshed every probe cycle and
  health-checked, and the hostname is still carried through for the R-URI and TLS
  SNI, so nothing on the wire changes. Static-IP destinations and non-gateway next
  hops are unaffected (a bare `IP:port` already skips DNS; an unknown host still
  resolves normally). Enable probing on the group (the default) so the cache stays
  fresh.
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
