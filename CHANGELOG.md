# Changelog

All notable changes to SIPhon are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is lockstep across
the `siphon-sip` crate and the `siphon-sip` Python SDK, driven by the git tag.

## [Unreleased]

## [1.8.1] — 2026-09-04

### Security
- **Inbound connection ceilings, on by default.** Nothing bounded how many
  connections or concurrent handshakes a single source could hold: no per-source
  cap, no global cap, no limit around the TLS handshake. One address opening
  dozens of connections at once pinned a task each for the full 10-second
  handshake timeout, and the auto-ban could not help because it needs *completed*
  failures first. `security.connection_limits` adds four ceilings —
  `max_handshakes_per_source` (32), `max_handshakes` (1024),
  `max_connections_per_source` (256), `max_connections` (16384) — with `0`
  disabling any one of them and `trusted_cidrs` exempt from all of them. Every
  field defaults, so the ceilings apply with no `security:` block configured.

  In-flight handshakes and established connections are counted separately
  because they are abused differently: a handshake is CPU held briefly and no
  legitimate client has many at once, while an established connection is held
  until the peer leaves or the 300 s idle timeout reaps it and a busy NAT
  legitimately holds many. Refused connections are dropped silently and are
  **not** banned — hitting a concurrency ceiling is a capacity fact, not proof of
  intent. New metrics: `siphon_connections_refused_total{reason}`,
  `siphon_stream_connections_active`, `siphon_handshakes_in_flight`.

  **`max_connections_per_source` and carrier NAT:** a CGNAT pool or large
  enterprise NAT can legitimately front more than 256 registrations from one
  address. The default is a runaway detector, not a policy — raise it or set `0`
  where that is your topology, and watch
  `siphon_connections_refused_total{reason="connections_per_source"}`.
- **A non-SIP probe is now refused on every message, not only a connection's
  first line.** The accept-time sniff assumes SIP for a peer that sends nothing
  within its 2-second window — correct for a connection held open for reuse, but
  also a way past the check: connect, wait, then send. Past the sniff, framing
  accepted any block ending `\r\n\r\n`, because a missing `Content-Length`
  defaults to zero, so an HTTP request block framed as a complete "message",
  reached the dispatcher and was rejected only by the parser — which has no
  connection to close and no source to record, leaving a scanner free to probe
  indefinitely over one connection. `frame_sip_message` now checks the start line
  is a SIP request-line or status-line (RFC 3261 §7.1/§7.2; extension methods
  still accepted), so the connection is closed and the source counted as a strong
  `failed_auth_ban` signal wherever the probe arrives. UDP is unchanged — a UDP
  source is spoofable and does not frame.

### Added
- **An LCR failover now leaves a trace, and a record.** A call whose first
  carrier returned `500` and which then answered on the second showed nothing of
  it at `log.level: info` — the four lines describing the failover were `debug`,
  and the only thing kept was `best_error`, a single code that exists to pick
  what the A-leg gets once every carrier is exhausted. A completed call that
  burned a carrier on its way recorded that nowhere, so a failing carrier could
  not be alerted on, trended, or taken to the carrier.

### Changed
- **quick-xml 0.41 → 0.42.** `BytesText` is `str`-backed now, so the reader
  decodes up front and `decode()` is gone; the content accessors
  (`xml10_content()`) apply XML 1.0 end-of-line normalisation and leave entity
  resolution to the caller. Element and attribute names are `str` rather than
  bytes, which removes a set of `from_utf8` conversions at the parse sites.
- **`cdr.write(request|call, extra=…)` now attaches to the auto-emitted CDR
  instead of writing a second record.** With `cdr.auto_emit: true`, siphon
  already tracks a record for the call from the INVITE; a script's `extra`
  fields are merged into it and emitted once at teardown, on the record that
  also carries `timestamp_start` / `timestamp_answer` / `timestamp_end`,
  `duration_secs`, `response_code` and `disconnect_initiator`.

  Before, the script's call queued a separate record built from the identity
  fields alone — no timings, no duration, `response_code: 0` — so attaching
  billing metadata to a call produced two rows the collector had to join on
  Call-ID, one of which was meaningless on its own. Repeat calls now merge on
  top of each other (last write wins per key).

  A standalone record is still written when there is nothing to merge into:
  `auto_emit` off, a request the auto-emit hooks do not track (a MESSAGE, an
  out-of-dialog request), or a call already finalized. **Operators counting CDR
  rows per call will see one row where they saw two**; the fields are unchanged
  and now all on the same row.
- **The auto-emitted CDR carries the Rf correlation.** `rf_session_id` /
  `rf_result_code` (TS 32.299) were stamped only onto a script-written record,
  so an operator running auto-emit never saw them. The auto-emitted record now
  resolves them at teardown — including for a B2BUA call, whose accounting
  record is keyed on the internal call id rather than either leg's dialog, a
  key the stamp never offered.
- **A proxy call's CDR record is opened before the script handler runs and
  finalized after it.** It used to be opened after the handler (only for an
  INVITE the proxy forwarded) and, on the BYE, written before the handler — so
  a `cdr.write(request, extra=…)` from either handler had nothing to attach to.
  Both ends now bracket the handler, and the record is still written when the
  script drops or rejects the BYE.

  An INVITE the proxy does not forward still produces no CDR, as before —
  unless the script attached fields to it, which is a deliberate ask for a
  record of the attempt. That record now carries the code the script answered
  (a 403, a 407) instead of the `response_code: 0` a script-built record had.
- **A binding no longer carries its own copy of two per-process constants.**
  `Contact` stored `instance_id` and `instance_epoch` as an owned `String`
  pair, so a table of a million bindings held a million copies of the same two
  values and paid two allocations per binding for them. They are now one shared
  handle to the process identity, read through `Contact::instance_id()` /
  `Contact::instance_epoch()`. The scripting API is unchanged — `contact.instance_id`
  and `contact.instance_epoch` still return `str | None`. A restore from a
  Redis/Postgres snapshot collapses to one handle per instance that wrote the
  bindings, rather than one per binding.
- **`Contact::source_transport` holds the parsed `Transport` instead of the
  scheme token.** Every consumer wanted a `Transport` anyway — the routing path
  re-parsed the string into one on each send, and two more places kept their own
  copy of that conversion, all now removed. The persisted form is unchanged
  (still the lowercase scheme token), so bindings stay readable across a
  version rollback; an unrecognised scheme restores as "no transport recorded"
  rather than failing the binding.

  Together these take `Contact` from 480 to 416 bytes, which also drops the
  per-AoR binding allocation into a smaller allocator size class. Measured over
  200,000 single-binding AoRs with an instance identity configured: **777 → 641
  bytes per AoR, a 17.5% reduction**, on top of the single-slot change above.
- **The always-on Python worker floor is re-derived against the corrected
  per-worker heap.** `MIN_CORE_THREADS` is a floor on the worker *count*, and
  8 was chosen when a warm worker was believed to cost ~2 MB — effectively a bet
  that the pool's always-on heap would sit near 16 MB. `PER_WORKER_HEAP_MB` was
  later measured at ~8 MB and the constant raised to 10, but the count was never
  revisited, so the same floor came to mean a much larger always-on commitment
  on every instance, 2 cores or 32. It is now 4: still double the 2-thread
  baseline the floor exists to avoid, and on any box with 2 or more cores
  `2 x cpus` already meets it, so the floor stops binding exactly where it was
  costing the most for the least reason.

  Measured on a 2-CPU box, `pool_size` 8 → 4 and thread count 17 → 13. The RSS
  effect is smaller than the arithmetic suggests: ~2 MB at boot and ~7 MB after
  40,000 handled requests, because a worker's mimalloc heap grows with the work
  it does rather than being committed up front — with half the workers, each
  one does twice the work. `PER_WORKER_HEAP_MB` describes a long-running IMS
  deployment's steady state, not a fixed per-worker cost, so it should not be
  read as "workers x 10 MB" on a lightly-loaded instance.
- **Every SIPp scenario now runs on every pull request.** Four had no runner at
  all (`b2bua-refer-outbound`, `b2bua-reinvite-bleg`, `b2bua-reinvite-breject`,
  `b2bua-reinvite-reject`), so the behaviour they described — B-leg-initiated
  re-INVITE Via correctness, and dialog survival when a re-INVITE is rejected
  from either side (RFC 3261 §14.1) — was asserted by nothing. The
  reliable-provisional scenario (`b2bua-reliable-prov`, RFC 3262 100rel
  interworking) existed but was driven only by `scripts/run-tests.sh`, so a
  regression in it was not caught on the PR that caused it; it now has its own
  CI job.
- **Fixed a race in the `b2bua-reinvite-breject` scenario.** A `<pause>` sat
  where the BYE arrives, so an on-time BYE landed before SIPp had armed the
  `recv` and aborted the run as unexpected. Test-side only — siphon sends
  exactly one BYE and retransmits it correctly per RFC 3261 §17.1.
- **`b2bua.default_header_policy` naming an unknown policy now refuses to
  start.** It previously logged a warning and fell back to
  `transparent-b2bua@2026` — the *most* permissive posture — so a typo in the
  name of a trust-boundary control opened the boundary instead of closing it,
  on a node that came up reporting healthy. A misspelled name, or one whose
  `header_policies:` entry is missing, is now a config error naming the policy
  and listing what is available. A policy that cannot compile (unknown
  `rewrite:` / `translate:` op, an unversioned name, a name colliding with a
  built-in, the same header given two verbs, or a rule aimed at a
  framework-managed header such as `Via` or `Record-Route`) is refused at load
  for the same reason. An unknown `header_policy=` passed by a *script* is
  unchanged: it warns and falls back to the configured default, so a script
  typo degrades to the operator's chosen posture rather than failing calls.

### Fixed
- **A request with no credentials no longer counts toward `failed_auth_ban`, and
  an auth-backend outage never does.** Both banned real subscribers.

  A challenge issued because the request carried no `Authorization` is the
  RFC 3261 §22.2 opening leg of challenge-response — every client sends one
  before it has a nonce — and it scored 1, so five in a window earned an hour-long
  ban. Behind CGNAT that address is shared, so the ban landed on every subscriber
  behind it. It is now weighted by the new
  `failed_auth_ban.missing_credentials_weight`, which defaults to `0`; set it to
  `1` for the previous behaviour. Volume stays visible in
  `siphon_auth_failures_total` either way.

  Worse, the HTTP auth backend returned the same "no credential" for *"no such
  user"* and for *"the request failed"*, so a timeout or a connection refusal was
  indistinguishable from a wrong password and scored the high-confidence weight of
  3 — two REGISTER retries during a backend outage banned a subscriber's address
  for an hour, precisely when every subscriber is retrying. The credential check
  is now four-way (valid / absent / rejected / backend unavailable) and a backend
  that could not answer counts nothing. It increments the new
  `siphon_auth_backend_errors_total`, which is worth alerting on: a non-zero rate
  means authentication is failing into 401s for everyone.

  `siphon_credential_failures_total` now counts genuine rejections only; it
  previously included backend errors.
- **A siphon-originated REFER no longer overtakes the answer it depends on.**
  A `call.refer()` issued from `@b2bua.on_answer` was emitted at the point the
  handler ran — which is *before* the A-leg 2xx is forwarded — so the caller
  received an in-dialog REFER for a dialog it had not yet confirmed (RFC 3261
  §13.2.2.4: the UAC confirms the dialog on the 2xx). A real UA answers that
  481. The REFER is now held until the 200 OK is on the wire.

  - Each failed attempt is now recorded against the carrier that was in flight
    (`carrier_id`, `status`, `elapsed_ms`; a ring timeout as `408`) and reported
    at `info` along with the advance to the next carrier.
  - `call.route_attempts` exposes that list to scripts wherever the `Call` is —
    notably in `@b2bua.on_answer`, so a call that *answered* after failing over
    can still name what it burned. `call.active_route` is unchanged and still
    names the winner.
  - `@b2bua.on_route_failure(call, route, code)` fires once per failed attempt,
    including the last. It fires for every non-2xx a carrier returns — a
    definitive `486` as much as a `503` — which is the same set
    `route_attempts` records, so the two can never disagree; filter on `code`
    for what you treat as a carrier's fault. Purely a notification: the failover
    decision is already made and raising in it does not change the call.
  - With `cdr.auto_emit` on, the attempts are stamped onto the CDR as
    `lcr_attempts` (a compact JSON array), alongside the winning carrier's
    existing `cdr_fields`.

  `best_error` is now derived from the attempt list rather than accumulated
  alongside it, so the code the caller receives and the per-attempt record
  cannot drift apart. Selection is unchanged (6xx > 5xx > 4xx).
- **Header policies can now be defined in `siphon.yaml`.** `header_policies:` is
  a top-level map of operator-owned policies, in the same namespace as the four
  built-in presets and selectable the same way — by
  `b2bua.default_header_policy` and by `call.dial(header_policy=…)` /
  `call.fork(header_policy=…)`. It completes the set: `number_policies:` and
  `media.profiles:` were already operator-definable, header policies were the
  one named-policy surface that was not.

  A policy either extends a built-in with `copy` / `strip` / `rewrite` /
  `translate` deltas, or declares both directions in full with an explicit
  `default:`. Under `extends:` the base supplies each direction's default and
  rules, the policy's own rules are matched first, and a direction left out is
  inherited verbatim — so an `extends:` with no rules is a stable local alias
  for a built-in. Header names are exact and case-insensitive, with a trailing
  `*` for a prefix match; within one direction an exact name beats a prefix and
  a longer prefix beats a shorter one, so `strip: ["X-*"]` alongside
  `copy: ["X-Account-Ref"]` is expressible in a single block.

  This is what "that preset, except for these headers" was missing. Before it,
  the only way to let one header cross was to repeat `copy=[…]` on every
  `dial()` / `fork()` call site, which puts a trust-boundary decision in N
  script locations instead of one reviewable config block. Per-call deltas are
  unchanged and still take precedence (exact names only — patterns are a
  config-side feature).

  ```yaml
  header_policies:
    "trunk-edge-plus@1":
      extends: "sip-trunk-edge@2026"
      request:
        copy: ["X-Account-Ref"]

  b2bua:
    default_header_policy: "trunk-edge-plus@1"
  ```
- **XML entity references in element text were silently dropped, since v1.1.1.**
  quick-xml does not deliver one text node per element: an entity reference
  terminates the current `Text` event, arrives as its own `GeneralRef`, and the
  remaining text follows as another `Text`. siphon's three hand-rolled parsers
  read only `Text`, so every `&amp;`, `&lt;`, `&#38;` and the like vanished from
  the value — no error, just a shorter string. The 0.37 → 0.41 bump in v1.1.1
  (RUSTSEC-2026-0194/0195) introduced the split; the compatibility shim written
  at the time restored `BytesText::unescape()` but never saw the references,
  because they had already been routed to an event nobody handled.

  This is not cosmetic for SIP. A URI carries `&` as soon as it has two headers
  (`sip:a@b?X=1&Y=2`), which XML requires be written `&amp;` — so a contact URI
  in a reg-event NOTIFY (RFC 3680), an Application-Server URI in an iFC
  (3GPP TS 29.228) and a display name in SIPREC metadata (RFC 7866) all parsed
  into a *different*, still well-formed value. Affected every release from
  v1.1.1 through 1.8.0.

  All three parsers now resolve `GeneralRef` through one shared
  `xml_text::resolve_general_ref` — the five predefined entities plus decimal
  and hexadecimal numeric references. An unresolvable reference fails the parse
  rather than being dropped, since siphon reads no DTD and inventing
  replacement text is how the bug looked in the first place. The SIPREC parser
  additionally accumulates across fragments instead of assigning, which it had
  to for a split value to survive at all.
- **A media failure at answer no longer connects the call and starts charging.**
  An exception out of `@b2bua.on_answer` was logged and then ignored: the A-leg
  2xx went out a millisecond later, the ACK followed, and the charging clock
  started on a call that had no media path in either direction and never could
  have had one. That handler is where the media backend is driven, so an engine
  that refuses the answer — a codec it will not bridge, a pipeline it cannot
  build — surfaces exactly there, and it surfaces *before* the caller is
  answered. Nothing treated it as fatal, so the call connected, billed for as
  long as the far end kept it, and read as answered in every record.

  A raise from `@b2bua.on_answer` is now a decision to fail the call. The caller
  receives `500`; the answered B-leg is ACKed (RFC 3261 §13.2.2.4, which stops
  its 200 retransmitting) and then BYEd (§15); `@b2bua.on_failure` fires so a
  script's own per-call teardown still runs; the media session is released; and
  any Ro reservation `call.ro_authorize()` opened is closed. The answer-time Rf
  `ACR-START` and Ro `CCR-UPDATE` now follow that gate instead of preceding it,
  so a call siphon is about to fail is never reported as answered in the first
  place.

  **Behaviour change.** A handler that raises used to leave the call connected;
  it now fails it. A script doing work in `on_answer` that is allowed to throw
  must catch its own exceptions. Note also that `@b2bua.on_failure` can now fire
  for a call whose B-leg *did* answer and has already been BYEd, so a handler
  must not assume there was never a B-leg.
- **`call.terminate()` now works from `@b2bua.on_answer`.** The deferred action a
  handler left behind was read back only for `call.refer()`; everything else was
  discarded on the grounds that the call is already answered. That is true of the
  B-leg and false of the A-leg, whose 2xx is only sent afterwards — so terminate
  was both meaningful there and the one lever a script had to stop a call it had
  just discovered could not work, and it was the one being dropped. An action
  that genuinely has no effect once the B-leg has answered is now logged by name
  rather than discarded silently.
- **One event now carries one timestamp.** With `log.file` configured, siphon
  installed a console `fmt` layer and a file `fmt` layer, and each timed the
  event as it formatted it — so a single log line was stamped twice, at two
  different instants. Measured on a running process, the file's stamp was
  between 57 µs and 1.4 ms behind the console's for the same event.

  Invisible while reading a log, and not invisible the moment a log line is
  correlated against a CDR, a HEP capture or an intercept record: which stamp is
  authoritative then depends on which log happens to be in hand, and nothing in
  either says they disagree. On a platform where CDRs, credit ticks and
  intercept records are all stamped from one clock, a log disagreeing with
  itself is not something anyone thinks to check.

  The event is now timed once, before either layer formats it, and both render
  that one value. It goes through the same timer as before, so the rendered
  format is byte-identical and nothing parsing these logs is affected.
- **Registrar lookups now canonicalise the AoR they are given.** `bindings` and
  `aliases` are both keyed on the normalised form, but `Registrar`'s own lookup
  methods took the caller's string as-is, so an AoR that was not already
  canonical missed a binding that was present — and missed by answering "not
  registered" rather than erroring, which reads as a UE problem. Scripts were
  never affected, because the scripting API normalises at its own boundary; the
  exposed surface was every other entry point, notably the admin HTTP API, which
  takes the AoR straight off the URL path. `GET /admin/registrations/alice@example.com`
  (or with a `:5060`, a `;transport=`, or angle brackets) 404'd on a live
  registration, and `DELETE` on the same path reported nothing to remove.

  This also makes a `tel:` URI in an implicit registration set resolvable:
  `normalize_aor` maps `tel:+1555…` to `sip:tel:+1555…`, so the alias was
  stored under a key the raw form never matched.
- **A siphon-originated REFER no longer overtakes the answer it depends on.**
  A `call.refer()` issued from `@b2bua.on_answer` was emitted at the point the
  handler ran — which is *before* the A-leg 2xx is forwarded — so the caller
  received an in-dialog REFER for a dialog it had not yet confirmed (RFC 3261
  §13.2.2.4: the UAC confirms the dialog on the 2xx). A real UA answers that
  481. The REFER is now held until the 200 OK is on the wire.

  Found by `b2bua-refer-outbound`, a SIPp scenario that existed but was wired to
  no runner — the first time it ran, it caught this.
- **B2BUA in-dialog ACKs now carry the dialog's route set (RFC 3261 §12.2.1.1).**
  Three ACK paths built the request with no `Route` header at all: the ACK for a
  re-INVITE's 2xx (so every hold, resume, session-timer refresh and transfer
  media re-anchor), the ACK for a leg siphon originated itself, and the ACK for a
  2xx that raced an outbound CANCEL. The REFER transfer target's leg went one
  further and never captured a route set in the first place — the `Record-Route`
  on its own 200 OK was dropped rather than reversed into the dialog (§12.1.2) —
  so its BYE at hangup was unrouted too.

  Signalling survives this wherever the next hop is willing to route on the
  Request-URI alone: the 200 stops retransmitting and the call reads as answered.
  What does not survive is a proxy that keeps per-dialog state in the parameters
  of its own `Record-Route`. The ACK reaches it without that state, the media path
  is never opened, and the call connects with no audio in either direction while
  every trace of the signalling looks clean. A transferred call is the usual way
  to meet it, since the transfer target is the leg that carried no route set at
  all.

  A dialog-establishing 2xx now sets the route set from its `Record-Route`
  reversed, and a mid-dialog ACK takes it from the leg — a re-INVITE's 200 does
  not re-advertise `Record-Route`, so there is nothing in the response to rebuild
  it from. Those ACKs are also sent to the route set's first hop instead of the
  address the leg was dialled at, which is what §12.2.1.1 asks for and what the
  re-INVITE itself already did.
- **A registration that ended by expiring or by de-REGISTER left four
  per-AoR maps holding it forever.** `remove_all` tore down the auxiliary
  state through `drop_aor_state`, but neither of the two paths a registration
  normally ends on did: `expire_stale` removed the binding and pruned
  `tokens` / `connection_index` while leaving `service_routes`,
  `asserted_identities`, `associated_uris` and the implicit-registration-set
  `aliases` behind, and `save()` with `Expires: 0` emptied the last binding the
  same way. On an IMS deployment — where a script populates all four on every
  REGISTER — that is a permanent entry per completed registration, measured at
  **384 bytes each**, and it is invisible to `siphon_registrar_aors` /
  `registrations_active` because those count `bindings` alone. The gauge reads
  zero while the process keeps growing, which is the hardest shape of leak to
  find from the outside.

  Both paths now drop the auxiliary state with the binding. Expiry does it in
  memory only, matching what that sweep already does with the binding itself:
  a lookup is L1-only, so "this replica stopped seeing refreshes" is an
  inference rather than the instruction a de-REGISTER carries, and deleting the
  shared record on that basis would destroy state a peer replica is still
  serving.

  Measured over 100,000 IMS registrations taken through a full
  register → de-REGISTER cycle, residency after teardown drops from 751 to 367
  bytes per registration, and the remainder is now flat across repeated cycles
  (35,828 KB then 35,826 KB) — hash-table capacity at its high-water mark,
  reused by the next registration rather than retained.
- **The registrar reserved four contact slots for every AoR that only ever
  holds one.** `Vec::push` on an empty vec allocates `MIN_NON_ZERO_CAP` slots
  rather than one, which is 4 for any element of 1 KiB or less. `Contact` is
  ~480 bytes, so an ordinary single-binding registration asked for 1,920 bytes
  — rounded up to a 2 KiB allocator size class — to hold 480 bytes of contact,
  and three quarters of the registrar's largest per-AoR allocation was capacity
  that the overwhelming majority of AoRs never use. At a million bindings that
  is over a gigabyte.

  Bindings are now appended through a helper that reserves exactly, so a
  one-contact AoR occupies one slot. `reserve_exact` is a no-op when there is
  already room, so a multi-device AoR grows one slot at a time instead of
  doubling — a fine trade here, since a REGISTER that adds a device is rare
  next to one that refreshes an existing binding, and a refresh replaces in
  place without reallocating at all.

  Two paths that build a binding list wholesale were right-sized the same way:
  restoring from a Redis/Postgres snapshot at boot (previously grown from empty,
  one push at a time, which on a restart carrying a large binding set is the
  process's steady state rather than a transient) and the RFC 5626 flow-teardown
  partition, which sized for "nothing removed" and kept the freed slots.
- **`listen.udp_recv_buffer_bytes` is a floor now, so it stops shrinking the
  receive queue on a tuned host.** siphon called `setsockopt(SO_RCVBUF)`
  unconditionally, which made the 1 MiB default a *reduction* on any host whose
  `net.core.rmem_default` was above 512 KiB. The two sides are not measured the
  same way — an untouched socket carries `rmem_default` verbatim, while an
  explicit request is doubled by the kernel — so 1 MiB against a 4 MiB default
  landed at 2 MiB, halving the headroom the setting exists to provide. It did it
  silently, too: nothing was clamped, so the read-back warning had nothing to
  say, and `ss -uanm` was the only place the loss was visible.

  The configured size is now the minimum: siphon reads what the socket already
  carries and leaves a larger buffer alone. Deliberately conservative about the
  doubling, so it can decline to raise a buffer already within 2x of the floor,
  but it can never lower one. `0` still means "don't touch the socket at all".

### Performance
- **A proxy no longer pins a whole INVITE per answered call for the full
  transaction timeout.** The `by_dialog_key` entry exists for one purpose:
  routing the end-to-end 2xx ACK, which is a new request and so does not match
  the INVITE server transaction (RFC 3261 §13.2.2.4). It was aged only by
  64*T1 (32 s) from creation, so every *answered* call held its
  `ProxySession` — including a full cloned `original_request` — for 32 s after
  the call had otherwise finished. At 10k cps that is ~320k pinned INVITEs at
  steady state, and it is the bulk of why a proxy row outweighs the equivalent
  B2BUA row, which drops its call state at teardown.

  Once that ACK has been routed the only thing still owed is absorbing a
  *retransmitted* ACK, which the UAS sends in response to a retransmitted 2xx —
  bounded by Timer I (T4, 5 s), not by the transaction timeout. Dialogs that
  have seen their ACK now retire on that shorter window; dialogs still waiting
  for one keep the full timeout unchanged, so a late ACK is never left
  unroutable.

  Measured on the reference box, `scripts/scale_test.sh 1200000 10000 8` (120 s
  of sustained load, long enough for both arms to reach steady state), two
  interleaved reps on jemalloc live bytes:

  | | live bytes | peak CPS | peak CPU |
  |---|---|---|---|
  | before | 4147 / 4165 MB | 9952 / 9960 | 541 / 565 % |
  | after | **2600 / 2628 MB** | 9928 / 9944 | 550 / 553 % |

  **-1.54 GB (-37 %)**, with CPU a wash and CPS at parity.
- **The B2BUA call store no longer retains its peak-concurrency footprint.**
  Third and largest instance of the same shape as the transaction map and the
  timer wheel: `CallActorStore` held `DashMap<String, CallActor>` with the actor
  **inline**, and `CallActor` is ~2.2 KB (an inline `a_leg: Leg`, the `b_legs`
  vectors, session-timer and transfer state), making the bucket ~2.3 KB —
  3.8x the transaction bucket and the biggest retained bucket in siphon.
  `hashbrown` sizes its bucket array for the peak number of live calls and never
  shrinks it, so a box that once carried N concurrent calls kept
  `N/0.875` rounded to a power of two, times 2.3 KB, for the rest of its life,
  with `call_count()` reading 0 the whole time. Boxed, the bucket is 32 bytes.

  No measurable effect on the SIPp bench, and that is expected: the bench tears
  every call down immediately, so concurrent `CallActor`s number in the tens and
  the store never grows a bucket array worth retaining. Four interleaved A/B
  reps of `MODE=b2bua scripts/scale_test.sh 5000 1000 4` on the reference box
  came out as noise around zero (deltas -2.4, +3.0, -1.0 MB after discarding a
  cold first run). The saving is proportional to the **peak concurrent call
  count**, which this workload does not produce: a node that has once held 50k
  simultaneous calls retains ~151 MB of bucket array for the rest of its life
  inline, against ~2 MB boxed.
- **The dispatcher's timer wheel no longer retains its peak-concurrency
  footprint either.** Same shape as the transaction map fixed alongside it:
  `timer_wheel` is a `DashMap<String, TimerEntry>` holding a 176-byte
  `TimerEntry` inline, so the bucket was 200 bytes. `hashbrown` sizes its bucket
  array for the peak number of live entries and never shrinks it, and the wheel
  carries roughly one entry per live transaction timer — so its count tracks
  `rate x Timer J` the same way, and the array stayed at the busiest moment the
  process ever saw for the rest of its life. Boxed, the bucket is 32 bytes.

  Measured on the same experiment (100,000 registrations at 4,800 cps, then
  fully de-registered), against `main` with only this change reverted:

  | | peak RSS | drained RSS | drained live bytes |
  |---|---|---|---|
  | before | 289 MB | 153 MB | 80 MB |
  | after | 267 MB | 121 MB | **47 MB** |

  Post-drain live bytes fall 41 %. Cumulatively with the registrar and
  transaction work in this release, the same workload goes from 563 MB peak
  RSS / 158 MB retained to 267 MB / 47 MB.
- **The transaction table no longer holds its peak-concurrency footprint for
  the life of the process.** `TransactionManager` stored the `Transaction`
  enum inline in its `DashMap`. A `Nist` carries two whole `SipMessage`s
  (`original_request` for the synthesised 100, `last_response` for
  retransmission), which makes `Transaction` 536 bytes and the hash bucket 608.
  `hashbrown` sizes its bucket array for the peak number of live entries and
  never shrinks it, so a box that once ran at N concurrent transactions kept
  `N/0.875` rounded up to a power of two, times 608 bytes, forever — while
  `siphon_transactions_active` read 0 the whole time.

  Concurrency is `rate x Timer J` (32 s), so the retention is set by the
  busiest 32 seconds the process ever saw and grows linearly with offered load.
  Transactions are now boxed: the bucket is 80 bytes, and the 536-byte payload
  comes off the memcpy path that every insert and every table growth paid.
- **siphon's own binary now uses siphon's own allocator tuning.** `src/main.rs`
  installed jemalloc with a bare `#[global_allocator]` and never set
  `malloc_conf`, so it ran jemalloc's stock `background_thread:false` +
  `dirty_decay_ms:10000` — freed pages are returned only opportunistically,
  while an arena is being allocated *into*, which is the opposite of what a
  process does just after a burst. It now goes through `install_allocator!()`,
  the same macro siphon already ships for downstream binaries. Scope: the
  published container image builds `siphon-bin`, which already called the
  macro, so this closes the gap for a source-built root `siphon-sip` binary
  (`cargo install siphon-sip`), not for the official image.

  Measured together, 100,000 registrations driven at 4,800 cps and then
  fully de-registered:

  | | peak RSS | drained RSS | drained live bytes |
  |---|---|---|---|
  | before | 563 MB | 292 MB | 158 MB |
  | after | 452 MB | 158 MB | 83 MB |

  Boxing accounts for the live-bytes drop (158 → 81 MB on its own), the decay
  tuning for the resident drop (267 → 158 MB on its own). Against the
  rate-independent floor of 51 MB, the concurrency-driven retention falls from
  107 MB to 30 MB.
- **De-registration no longer scans the whole alias index.** Pruning the
  implicit-registration-set aliases for one AoR was a `retain` over every alias
  the process held, so tearing down a registration cost O(total aliases) on the
  write path — quadratic across a population of them. The entries to drop are
  now derived from that AoR's own `associated_uris` list, which is what they
  were built from. Taking 100,000 IMS registrations through de-REGISTER goes
  from **50.7 s to 0.45 s**.

## [1.8.0] — 2026-09-02

_Codename: kees._

### Security
- **Refused bare CR/LF in a SIP header block, and closed five framer/parser
  disagreements it was hiding.** siphon's header-value scan runs to the next
  CRLF, so a line ended with a bare LF was absorbed into the *previous* header's
  value — while the stream framer's `Content-Length` scan split on LF and read
  that same line as a header of its own. `X-Pad: a\nContent-Length: 4` +
  `Content-Length: 0` framed as two different messages depending on which half
  of siphon you asked, and an upstream proxy or load balancer that treats bare
  LF as a terminator made a third reading. That is the shape request smuggling
  is built out of. RFC 3261 §7.5 makes CRLF the only terminator, so a header
  block containing a bare CR or LF is now refused; bodies are untouched.

  A new fuzz target asserts the general invariant — *for any bytes the parser
  accepts, the framer must compute the same message length* — and found four
  more divergences, all fixed:

  - A **folded continuation line carrying a `Content-Length`** was a header to
    the framer and part of the previous value to the parser (133 bytes against
    232).
  - The reverse: a **folded `Content-Length` value** the parser read and the
    framer did not.
  - A **continuation line with nothing to continue** (the header section opening
    with a fold) was promoted to a header by the parser and skipped as a fold by
    the framer. Now refused.
  - A **vertical tab in a header name**: `str::trim` is Unicode-aware and
    stripped it, so `content-length\x0b` became `Content-Length` to the parser,
    while the framer's ASCII trim left it alone. Header names are ASCII tokens
    (§25.1), so the parser now trims ASCII too.

- **Refused ambiguous and abusive message shapes.** `validate_message` now
  checks a message's shape before any check that reads a particular field:
  - **A duplicated single-instance header field is `400 Bad Request`** (To,
    From, Call-ID, CSeq, Max-Forwards, Content-Length). RFC 3261 §8.1.1 defines
    these as single-instance, and RFC 4475 names the response rather than leaving
    it to the application layer: §3.3.8 "would respond with a 400 Bad Request
    error", §3.3.9 "should respond with an error". Which copy applies is undefined and implementations
    disagree — siphon reads the first, and an upstream that reads the last
    routes, bills or authorizes the same message against a different identity.
    Content-Length matters twice over: it is what the stream framer reads to
    decide where the *next* message starts, which is the classic
    message-smuggling shape.
  - **A Via stack over 100 deep, or a message with over 256 header fields, is
    `513 Message Too Large`.** Nothing bounded either. `security.max_message_bytes`
    bounds the octets, but 256 KB is still ~8000 one-byte headers, and
    Max-Forwards bounds the hops a request may still take, not the stack a peer
    simply asserts it already traversed — every entry of which is re-serialized
    on each forward. The limits sit an order of magnitude above real traffic (an
    IMS INVITE with a full P-header set runs to about forty headers).

  The two RFC 4475 fixtures for these cases (`TC_MULTI01_I`, `TC_MCL01_I`) were
  classified as "parses" because siphon had no such check; they are now
  classified as the RFC classifies them.

  Known gap: §3.3.9 also says that over TCP "the framing error is not
  recoverable, and the connection should be closed". siphon answers 400 and
  leaves the connection open — the dispatcher has no way to close an inbound
  stream connection. Its own framing stays consistent (framer and parser both
  read the first Content-Length); what is unrecoverable is the disagreement with
  a peer that meant the second.

### Added
- **A playback now reports that it ended.** `PlayStarted` said a prompt began
  and nothing said it finished: the engine's `PlayFinished` was consumed inside
  siphon to resolve a blocking `play_media(wait=True)` and dropped otherwise, so
  a fire-and-forget play — which is every `play` issued over the control plane —
  had no completion signal at all. An app whose next step is "when the prompt
  ends" had to guess from the accept's estimated duration, which a stop, a
  supersede or a decode error all make wrong.

  `PlayFinished` now publishes on the control rail and as
  `@rtpengine.on_play_finished`, carrying the `play_id` that correlates with the
  accept and with `PlayStarted`, the end reason (`completed`, `stopped`,
  `superseded`, `error`), a `completed` flag — only that one reason means the
  prompt was actually heard in full — and the played duration. A blocking
  `play_media` still returns its outcome *and* the event still reaches the
  stream: the two are different consumers, and a signal that appeared only when
  nobody happened to be awaiting is one an app cannot rely on. Typed in the
  SDKs (`SipEvent::PlayFinished`, `PlayFinishedPayload`, a `play_finished()`
  accessor, and the TypeScript interface) rather than arriving as the
  forward-compatible `Other` catch-all.

- **The WebSocket stream lifecycle now reaches the control plane, for the tee as
  well as the bridge.** `stream_start` shipped before any lifecycle events did,
  so an app could start a tee over the control rail and had no way to learn it
  had stopped — the audio just went quiet, which is the exact silent failure
  these events exist to surface. `WsTeeStarted` / `WsTeeEnded` now publish
  alongside `WsBridgeStarted` / `WsBridgeEnded`, carrying the negotiated wire
  shape, the end reason, an `unexpected` flag (`detached` is the only orderly
  end of either) and, for the tee, the frames sent and dropped so an app can see
  its own consumer was the bottleneck.

  All four are typed in the SDKs rather than arriving as the forward-compatible
  `Other` catch-all: new `SipEvent` variants and payload structs on
  `siphon-control-proto`, `ws_tee_started()` / `ws_tee_ended()` /
  `ws_bridge_started()` / `ws_bridge_ended()` accessors plus an
  `is_unexpected_stream_end()` helper on `siphon-control-client`, and the
  matching payload interfaces on the TypeScript client.

- **Attach, re-point and detach a WebSocket *takeover* bridge on a live call.**
  The tee (`attach_ws_tee`) streams a copy while the call keeps relaying; a
  takeover makes the WebSocket server the leg's far side and unwires A↔B. Until
  now a takeover could only be negotiated at offer/answer through `ws_uri` on
  the media profile, so there was no way to point a live bridged leg at a
  different server without dropping the call. New `rtpengine.attach_ws_bridge()`
  / `detach_ws_bridge()` on the script API, `mode: tee|bridge` on the control
  plane's `stream_start` / `stream_stop`, and `@rtpengine.on_ws_bridge_started`
  / `on_ws_bridge_ended` plus `WsBridgeStarted` / `WsBridgeEnded` on the control
  rail.

  Attaching to a call that already has a bridge is a **re-point**, not an error,
  and the media path never returns to the relay in between — a detach-then-attach
  would hand the path back for as long as the next attach took to land, which the
  other party hears as a gap.

  `detach_ws_bridge` is deliberately *not* idempotent, unlike the tee's detach.
  The engine refuses a detach where there is no relay to hand the call back to —
  a `ws_uri`-negotiated bridge is the call's whole media path, and a single-leg
  (`answer_local`) takeover has no second party to relay to — and siphon
  surfaces that refusal rather than smoothing it into a success, because the
  alternative is a live call with no audio path at all. Only `detached` is an
  orderly end: every other `WsBridgeEnded` reason leaves both parties up and
  hearing nothing, so an unexpected end is logged at WARN even with no handler
  registered. Requires `media.backend: siphon-rtp` (rtpengine and rtpproxy
  refuse the verbs rather than answering a hollow success) and
  `siphon-rtp-proto` 0.4.0.

- **`siphon_requests_without_branch_total`.** Counts inbound requests whose
  topmost Via carries no `branch` parameter (mandatory since RFC 3261 §8.1.1.7).
  siphon has no RFC 2543 legacy transaction matching, so these are processed
  statelessly — their retransmissions are not absorbed and each one runs the
  script again. Previously this degradation was invisible outside a debug log.
  The gap is now stated in the feature-readiness matrix; the `transaction::key`
  module documentation had claimed a fallback that was never implemented.

- **Control plane: `ring` is its own verb, split from `progress`.** RFC 3261
  §13.2.1 makes the `180 Ringing` the "callee is being alerted" signal and
  §21.1.2 gives it no session semantics; RFC 3960 §3.1 puts early media on the
  response that carries the SDP. They were one verb, so an application had to
  know which status code meant which. Now `ring` sends a plain 180 — and refuses
  a body rather than putting an early-media offer on the wire under a verb that
  says it only alerts — while `progress` stays the one that opens an early-media
  path. That is what lets an application ring for an interval of its own
  choosing and separately decide whether to open early media. Mirrored in all
  three control SDKs (`Call::ring` / `call.ring()` / `Call.ring()`).

- **Control plane: a `PlayStarted` event.** `play` was fire-and-forget with no
  event at all, and its reply dropped the media engine's `play_id`, so an
  application had nothing to hang a playback watchdog or a gain ramp on and no
  way to correlate one. The `play` reply now carries `play_id` and `duration_ms`
  when the engine reports them, and the accept is also pushed as `PlayStarted`
  with payload `{source, play_id?, duration_ms?}`. The media contract answers
  `play` accept-on-start, so the event means the engine armed the playback, not
  that audio has reached the wire — a `url` source accepts before its body has
  arrived. A play the backend refuses pushes **no** event, so "no `PlayStarted`
  yet" always reads as "not started".

- **`siphon_udp_datagrams_at_buffer_limit_total`.** `recv_from` reports the
  bytes it copied, not the datagram's length, so a datagram that exactly fills
  the receive buffer is indistinguishable from one the kernel truncated.
  Previously this was invisible and surfaced only as an obscure parse error.
  The message is still processed — a genuinely truncated one is refused by the
  parser's Content-Length check — but a non-zero counter means a peer is sending
  UDP well past the point RFC 3261 §18.1.1 requires it to switch to TCP.

- **Framing fuzz target (`stream_framing_fuzz`).** Fuzzes the stream framer's
  invariants — a framed length never exceeds the buffer or the ceiling, and a
  refused message's header block stays inside the buffer — alongside the
  existing parser target in CI.

- **`bridge` — joining two legs siphon already owns.** `originate` shipped the
  ability to place a call; nothing could connect one to another, which is what a
  transfer, a callback-and-connect and an attended hand-off all need. The verb
  is on the external control rail (`bridge` / `unbridge`, addressing two
  channels the same application owns) with an in-process twin
  (`await b2bua.bridge(call_id, with_call_id)` / `b2bua.unbridge(call_id)`).

  A bridge is two RFC 3261 §14 re-INVITEs across two confirmed dialogs, because
  siphon is a B2BUA and each leg is its own offer/answer context (RFC 3264 §8):
  the named `with` leg is re-offered first with the anchor's current media, then
  the anchor with the answer that came back. That order is the one where a
  failure costs least — a peer that refuses leaves the anchor untouched and both
  calls exactly as they were.

  Media attachments come off **both** legs before anything is re-pointed, and
  each teardown is awaited and its reply checked: an announcement still playing
  replaces a leg's outgoing audio, and a WebSocket bridge makes the engine its
  far side, so either one still live when the bridge forms is one-way audio. An
  anchor already relaying between two parties is then renegotiated with
  `reoffer` on the ports it already holds; one the engine answered itself
  (`answer_local`, which is how every controller-owned leg starts) has no far
  leg to answer and is instead deleted and offered onto a fresh engine call-id,
  with the store key staying the leg's SIP Call-ID so every media verb still
  resolves.

  `unbridge` parts the pair without ending it — both legs stay answered, owned
  and held (`a=sendonly`, RFC 3264 §8.4; RFC 6337 §3.1 prefers that to
  `c=0.0.0.0`) — and `on_peer_hangup` (`hangup` by default, or `hold`) decides
  what becomes of the survivor when the other party leaves.

  Refusals are typed and separately actionable rather than one generic error:
  `not_found` (no such leg), `invalid_state` (not answered, already bridged,
  re-INVITE outstanding per RFC 3261 §14.1, no media description, or an
  `unbridge` of a leg that never was), `bad_request` (the same leg twice, or an
  unknown `on_peer_hangup`), `forbidden` (the other leg belongs to another
  application) and `unsupported_verb` (the media backend refused a step). The
  reply reports only that the media was re-pointed and the first re-INVITE is on
  the wire; the verdict arrives as `ChannelBridged` / `BridgeFailed` on both
  channels, and `ChannelUnbridged` when the pair is parted.

  Covered by a SIPp mode (`scripts/run-tests.sh --bridge`, CI job `sipp-bridge`)
  that joins two legs, parts them, joins them again and asserts on three
  independent oracles — the SIP wire, the application's own verdict, and the
  media engine's per-leg packet counters, the last of which is what says audio
  actually flowed in both directions rather than the command having returned ok.

### Changed
- **The feature-readiness matrix now says what evidence each level carries, and
  what none of them carry.** `Implemented` spanned everything from "has unit
  tests" to "has an end-to-end SIPp scenario that runs on every pull request",
  which is too wide a range for an operator to act on. The legend now lists the
  gates weakest to strongest and when each runs, and states plainly that **no
  level asserts interoperability with an independent implementation** — SIPp is
  a message generator, not a SIP element, so a feature can pass every gate and
  still be wrong in a way only another stack would notice.

  It also records which SIPp scenarios do not run per-PR. Four have no runner at
  all (`b2bua-refer-outbound`, `b2bua-reinvite-bleg`, `b2bua-reinvite-breject`,
  `b2bua-reinvite-reject`), so the behaviour they describe is currently asserted
  by nothing.

- **Corrected the PRACK and Session Timers rows in the README**, which said
  "Parser tests" while the matrix described full B2BUA 100rel interworking — the
  two documents disagreed. Session timers have an end-to-end SIPp scenario that
  runs on every PR; PRACK has one that is driven by `scripts/run-tests.sh` and
  **not** by CI, so a regression in the 100rel interworking is not caught on the
  PR that causes it. Both rows now say which.


- **`request.stop_propagation()` — a handler can now keep its decision.**
  Every `@proxy.on_request` whose filter matches runs, and they share one
  request object with a **single action slot**: `reply()` / `relay()` / `fork()`
  assign it rather than sending, and only its final value is executed. So a
  later handler did not run *as well as* an earlier one — it silently replaced
  the earlier one's routing decision, with registration order deciding. An
  `@proxy.on_request("OPTIONS")` answering a health probe beside a bare
  `@proxy.on_request` that relays meant the probe was **never answered**, only
  forwarded. Calling `request.stop_propagation()` stops the chain so nothing can
  overwrite the choice.

  Opt-in: answering is not on its own a request to stop, since a metrics or
  logging handler running afterwards is legitimate, and stopping by default
  would silently drop it. Side effects (`set_header`, `record_route`, logging,
  metrics) still run from every handler — only the routing decision is
  last-writer-wins. Documented in the handler execution model and mirrored in
  the SDK.

  `@diameter.on_request` dispatches the single most specific match instead. That
  difference is deliberate, and now says why: a Diameter request needs exactly
  one answer, where a SIP request can legitimately interest several handlers at
  once. Its docstring previously described the filter as mirroring
  `@proxy.on_request("INVITE")`, which is true of the syntax and false of the
  dispatch.

  The Kamailio/OpenSIPS migration guide mapped `is_method("INVITE")` to
  `@proxy.on_request("INVITE")`. Both of those have exactly one automatic route
  block, so `is_method()` is an *exclusive branch*; the decorator is additive.
  The guide now shows both correct forms.

- **Control plane: `StasisEnd` now carries the SIP status on every teardown that
  had one.** `code` / `response` were only populated on the two originate paths;
  four more now report theirs — `487 Request Terminated` on a CANCEL in either
  direction (RFC 3261 §9.1/§9.2), `408 Request Timeout` on the B2BUA answer
  timeout, and the status siphon actually sent on a `reject`, an unanswered
  `hangup`, or the handoff-deadline default (`503`). A teardown with no SIP
  response (an ordinary BYE, a script-driven terminate) still omits both keys
  rather than inventing one, so `code` present always means a real status was on
  the wire.

- **Control plane: a provisional's reply names what it sent.** `progress`
  reported `state: "ringing"` for every 1xx, including a 183 carrying early
  media. It now replies `{state: "ringing"|"progress", code, early_media}`,
  using the same rule as the callee-side `ChannelStateChange` on an originated
  leg, so there is one vocabulary to learn rather than two.

- **`SipVerb` in `siphon-control-proto` is now `#[non_exhaustive]`** (as
  `SipEvent` already was), so every future verb is additive for consumers rather
  than breaking an exhaustive `match`.

### Fixed
- **A retransmitted CANCEL is absorbed and answered 200, not 481.** RFC 3261
  §9.2 makes a CANCEL a request with its own server transaction, which absorbs
  retransmissions and answers them from its cached response. siphon intercepts
  CANCEL *before* transaction creation, so that transaction never exists and
  nothing absorbed the retransmission. On the proxy path the first CANCEL
  removed the session, so the second fell through to `481 Call/Transaction Does
  Not Exist` — for a CANCEL that had in fact been accepted, on a call already
  487'd. Over UDP that is the ordinary case rather than an edge: Timer E
  retransmits the CANCEL at 500 ms whenever the 200 is lost.

  Worse in the narrow window before the session is removed, where a second copy
  repeated the whole thing — re-forwarding the CANCEL downstream and putting a
  **second 487 on one INVITE server transaction**, which §17.2.1 does not allow.
  Acceptance is now recorded for 64×T1 (Timer J), the window that transaction
  would have held its cached response. The B2BUA path already answered 200 to a
  CANCEL for a call no longer Calling/Ringing and is unchanged.

- **A bridge no longer sends the wrong media detach, leaving the WebSocket
  server owning a leg it was about to renegotiate.** `bridge` tears every
  attachment off both legs before it re-points the media, but it decided what
  was attached from `MediaSession.ws_uri` — which is the *takeover* URI, not the
  tee. So a leg holding a takeover was sent `detach_ws_tee`, which is idempotent
  and answers ok, and the plan then renegotiated a media path the WebSocket
  server still owned: the bridge formed on paper and neither party heard the
  other. The mirror image was true too — a leg with a real tee, attached through
  the script or control API, was recorded nowhere, so its tee was never detached
  and kept streaming across the bridge. The two are now tracked apart and each
  gets its own verb.

- **A request racing an in-flight copy of itself no longer forks the call
  twice.** The dispatcher checks `handle_server_retransmit` and then creates the
  server transaction, which is a check-then-act: when a request and its
  retransmission land on two workers at once, both saw "no transaction" and both
  created one. The second `insert` overwrote the first's live state — its cached
  response and running timers — and, worse, both passed the request to the TU,
  so the script ran twice and forked downstream twice on a fresh branch each
  time. Creation is now atomic: the first caller owns the transaction and a
  concurrent duplicate is absorbed. Reachable under packet loss on UDP, where a
  UAC's Timer A fires while the original is still being processed.

- **A colliding client transaction is refused instead of silently replacing the
  live one.** siphon picks its own branch, so a collision is not a peer
  retransmission — a blind `insert` destroyed a running transaction's timers and
  left its request unanswered.

- **A header with an empty value no longer swallows the next header line.**
  RFC 3261 §25.1 has `SWS = [LWS]` and `LWS = [*WSP CRLF] 1*WSP` — a CRLF after
  the header colon is only whitespace when a space or tab follows it. siphon
  accepted a bare one, so `X:\r\nContent-Length: 5\r\n\r\n` parsed as a single
  header `X` with the value `Content-Length: 5` and no `Content-Length` at all.

- **A UDP datagram prefixed with a stray CRLF is no longer dropped as a parse
  error** (RFC 3261 §7.5). The stream transports drain keepalives in their own
  read tasks, but the parser searched for the header/body boundary before
  skipping the prefix and so found the prefix itself.

- **Bounded stream message size (`security.max_message_bytes`).** A peer on a
  stream transport (TCP/TLS/WS/WSS) could declare an arbitrarily large
  `Content-Length`, send only the header block, and make the reader buffer
  toward the declared size. The existing 64 KB guard covers only a header block
  with no end-of-headers marker, so it did not apply once `\r\n\r\n` had been
  seen — roughly 200 bytes on one connection was enough to drive multi-GB
  growth, before any parsing, authentication or rate limiting ran. Framing now
  enforces a ceiling (default 256 KB, minimum 4096, configurable) across the
  inbound listeners *and* the outbound connection pool, which had no guard at
  all. An over-sized request is answered `513 Message Too Large` (RFC 3261
  §21.4.11) and the connection is closed, so a legitimately over-sized body is
  a diagnosable configuration problem rather than an unexplained reset.

- **Fixed a wrapping length calculation in the stream framer.** A
  `Content-Length` near `usize::MAX` overflowed the headers-plus-body sum.
  Release builds do not enable overflow checks, so it wrapped silently to one
  byte short of the header block: the framer sliced a truncated message and
  desynchronised the stream on a value the peer chose. The sum now saturates,
  so an unrepresentable declaration is refused as over-sized. Found by the new
  framing fuzz target.

- **The ACK for a bridged re-INVITE was addressed to siphon itself.** RFC 3261
  §13.2.2.4 puts the responder's own remote target in the ACK's Request-URI, and
  siphon read it from the 200 OK — but only *after* `sanitize_b2bua_response` had
  rewritten that response's `Contact` to point at siphon, which is correct for
  the copy forwarded to the other leg and wrong for the ACK going back to the
  responder. The far end therefore did not accept the ACK and retransmitted its
  200 until the retransmission handler sent a second, correct one. The call
  survived, so this cost a retransmit and the delay before it rather than the
  dialog, which is why it went unnoticed on every hold and resume. The Contact is
  now captured before the rewrite. The siphon-originated path was already safe,
  but only because its response skips sanitize entirely.

- **The B-leg INVITE no longer carries the session-timer headers twice.** The
  B-leg INVITE is cloned from the caller's, so whatever it asked for is already
  on it — a Teams INVITE arrives with `Session-Expires: 3600`, `Min-SE: 300` and
  `Supported: histinfo,timer`. siphon then *appended* its own, and the callee saw
  both. `Session-Expires` and `Min-SE` are single-value headers (RFC 4028 §4,
  §5): siphon's `Min-SE: 90` next to the caller's `Min-SE: 300` is not a longer
  list, it is two contradictory floors, and which one the far end honours is
  undefined — take the lower and the session refreshes below the interval the
  caller demanded. They are replaced now. `Supported` genuinely is a list header
  (RFC 3261 §7.3.1), so the option tag is merged into the value already there
  instead of arriving as a second `Supported:` line. The refresh-re-INVITE path
  always did this correctly; only the B-leg builder did not.

- **A transfer offered the target the survivor's *original* media, not its
  current media.** siphon tracked the SDP of whichever leg **offered** a
  re-INVITE or UPDATE, never of the leg that merely **answered** one. So a leg
  that only ever answers stayed frozen at whatever it answered the first INVITE
  with. On a Teams trunk that call is set up `a=recvonly`, the carrier answers
  `a=sendonly`, and a re-INVITE a couple of minutes later takes both sides to
  `sendrecv` — but the carrier leg was still remembered as `sendonly`. Transfer
  then, and the target is offered that stale direction: it answers `recvonly`,
  the survivor is re-INVITEd `recvonly` in turn, and both remaining parties sit
  half-duplex — one able only to send, the other only to receive — with no hold
  signalled anywhere for either of them to display. Which leg went stale depended
  on who offered the re-INVITE, which is why this only broke transfers initiated
  from one side of the call. The answerer's own SDP is now tracked too, raw and
  before any rewrite, exactly as the offerer's already was.

- **Two tests that failed at random, both for reasons unrelated to what they
  assert.** `free_port()` bound port 0, read the address and dropped the socket:
  the kernel auto-assigns from the ephemeral range, so between the probe closing
  and the real bind any outbound socket in the process could take that port. And
  `listen()` binds on a spawned task and only *logs* a bind failure, so the test
  never learned — it waited on a listener that was never created and failed as a
  connect timeout, pointing at the wrong thing. Ports now come from a counter
  below the ephemeral range, where nothing is auto-assigned, and are probed on
  both TCP and UDP (separate namespaces; these tests bind either). The three
  copies of the helper are down to two — one shared inside the crate, one for
  `tests/`, which is a separate crate. Measured 4 failures in 20 runs before, 0
  in 25 after.

- **The Python thread-state leak guard now owns the process.** It compares glibc
  in-use bytes across thread-churn batches, but that counter is process-global
  and the parallel test binary allocates on the same order as the signal — it
  failed about one run in four, including a release cut. It gains a control arm
  (spawn/join without touching Python) so the ambient cost is measured and
  subtracted rather than guessed at, and is `#[ignore]`d with a CI step that runs
  it alone, as the CAP_NET_ADMIN tests already are. Alone it is exact: ambient
  0 B, 241664 B leaked, 0 B retained, every run. The guard is unchanged in what
  it proves.

## [1.7.1] — 2026-09-01

### Added
- **Codec manipulation on a media profile (`codec:`).** A profile half can now
  restrict, reorder, drop or transcode codecs — `strip`, `offer`, `transcode`,
  `mask`, `consume`, `accept`, `except`, `ignore` and `set`, each a list of RTP
  payload names:

  ```yaml
  offer:
    transport_protocol: "RTP/AVP"
    codec:
      strip: ["SILK"]                             # the carrier cannot take it
      offer: ["PCMA", "PCMU", "telephone-event"]  # and in this order
  ```

  Put it on the `offer:` half — both engines apply codec manipulation to the
  offer and ignore most of it on an answer. It reaches rtpengine as its own
  nested dict, not as tokens in `flags`, which the engine would drop.

  **One block, both real engines.** rtpengine takes the NG `codec` dictionary;
  the native `siphon-rtp` engine already implements the same model but reads it
  off its flag list, so siphon flattens the block to `codec-<op>-<NAME>` for it
  — the policy is written once. `ignore` and `set` have no native equivalent and
  are refused on that backend; `rtpproxy` is a plain relay with no transcoder and
  refuses the block outright. Refused at config load, never silently dropped.
  Codecs can also still be shaped from a script with the `sdp` namespace.

  An asymmetric codec policy also makes a profile **direction-bound**: it was
  chosen for the party on the far side of that half, so it is not inherited
  across a transfer without an explicit `accept_refer(profile=…)`.

  The `codec: ["offer", "PCMA,PCMU"]` line that `examples/teams_sbc.yaml` used to
  carry was not this shape and never did anything. That form now **fails the
  config load** instead of being silently ignored, and the example carries a real
  codec block.

- **`call.accept_refer(profile=…)` — the media profile for the pairing a
  transfer creates.** A media profile has two halves, and when they differ
  (`srtp_to_rtp` and every other SRTP/DTLS edge) they describe *specific sides*
  of the call. A transfer re-pairs it, and the party a half was written for is
  usually the one leaving — so inheriting the profile re-offers **that party's
  transport to whoever remains**: SRTP toward a plain-RTP carrier, which answers
  `m=audio 0`. The call connects and carries no audio in either direction, and
  the SIP trace looks healthy throughout. Name the profile for the pair that
  remains:

  ```python
  call.accept_refer(target=target, next_hop=gw.uri, mode="terminate",
                    profile="rtp_passthrough")
  ```

  Also accepted as `profile` on the control plane's `accept_refer`, and exposed
  on all three control SDKs (Rust `accept_refer(.., profile)`, Python
  `accept_refer(profile=…)`, TypeScript `acceptRefer({ profile })`). Unset keeps
  the previous inherit behaviour, which is correct for a symmetric profile.

- **`call.refer_side` — which leg sent the REFER** (`"a"` / `"b"`, matching the
  `initiator.side` convention in `@b2bua.on_bye`). Without it a script could not
  work out *which party survives* a transfer, and therefore could not pick the
  profile the surviving pair needs: the survivor is the peer of the referrer, so
  at a mixed edge the right profile flips depending on which side transferred.
  `examples/teams_sbc.py` shows the full rule.

- **A conformant ETSI TS 103 221-1 X1 network element, and the
  network-element-to-ADMF direction that did not exist at all.** The previous
  `lawful_intercept.x1` module was a bespoke REST API — resource routes under
  `/x1/targets`, an invented `urn:etsi:xml:ns:li:task` namespace, XML produced
  by splicing an `xmlns` onto the first `>` of a serde document, a free-text
  LIID as the task key, three target identifier types, and errors as HTTP
  statuses with ad-hoc bodies. None of that is X1, and it had no caller outside
  its own tests: `lawful_intercept.x1` was parsed and drove nothing, so the
  interface was configured, reported as present, and never listened.

  What replaces it is built to **v1.23.1** with the **TS 103 280 v2.19.1**
  dictionary. The ETSI schemas ship verbatim in [`schemas/etsi/`](schemas/etsi/)
  and every message is validated against them **in both directions at runtime** —
  a malformed response of ours fails here rather than at the ADMF. One
  `application/xml` endpoint (`/X1/NE`, configurable) on its own listener with
  mutual TLS and a mandatory `client_ca`; messages dispatched by `xsi:type` out
  of `X1Request` containers and answered one-for-one in an `X1Response`
  container correlated by `x1TransactionId`; a per-message `ErrorResponse`
  carrying a clause 6.7 code, with `X1TopLevelErrorResponse` reserved for a
  container too broken to answer per-message, so one bad message never costs the
  ADMF the answers to its siblings. Because the listener is ours, the handler
  sees the peer certificate: `admfIdentifier` is bound to its subject CN and a
  mismatch is refused `1030`.

  Tasks now key on the **XID** — a UUID, and the same 16 bytes every X2/X3 PDU
  carries — rather than a free-text LIID (which is a *mediation* attribute, and
  lives in `mediationDetails` where several tasks may share one). Target
  identifiers are the dictionary's: `sipUri`, `telUri`, `e164Number`, `impu`,
  `impi`, `imsi`, `imei` and both IP forms, with matching that normalises case,
  URI parameters, display names and number formatting. An identifier type this
  element cannot intercept on is refused `3010` **by name** rather than ignored,
  because an ignored identifier is a warrant that silently matches nothing.

  Destinations are modelled at all, which they were not: `CreateDestination`
  provisions a sink, a task delivers **only** to the DIDs it names, and a
  destination a task still references cannot be removed (`7010`). Delivery is
  scoped per interface, so an `X2Only` collector never receives content and an
  `X3Only` one never receives IRI.

  The outbound direction is new: `ReportNEIssue`, `ReportTaskIssue` and
  `ReportDestinationIssue` (the last is what closes the loop with the X2/X3 loss
  policies — a mediation outage has to be *reported*, not merely survived),
  `Keepalive` on a timer, and `GetAllDetails` reconciliation at startup so a
  restart does not silently diverge the ADMF's view of what is provisioned from
  the element's.

  The clause 6.7 error-code table is cross-checked against sipgate's independent
  MIT implementation of the same specification, and everything siphon emits is
  validated by `xmllint` in CI as a third-party decoder — a round-trip through
  our own reader would pass a shared encode/decode bug.

- **X3 content delivery is wired to the media engine.** On
  `media.backend: siphon-rtp` (and `siphon-rtp-proto` >= 0.3.1) siphon issues
  `AttachX3` when a content warrant matches a dialog-forming request, and
  `DetachX3` at teardown. Each attachment carries the task's XID, the session's
  non-zero Correlation ID — the same value the session's X2 records carry, which
  clause 6 requires and which is now an invariant spanning two binaries — and
  the **target leg**. That last one is derived from which party the warrant
  matched rather than assumed, because TS 103 221-2 §5.2.6 defines a delivered
  packet's direction *relative to the target*: naming the wrong leg inverts the
  direction on every packet and produces a recording that looks fine and is
  backwards.

  The engine's `X3Loss` and any unclean `X3Ended` are raised to the
  Administration Function as destination-level reports. That is what closes the
  loop the specification asks for: warranted content that did not reach the
  agency is a reportable failure, not a degraded recording to be survived
  quietly.

- **An interop test against a real ADMF.** `scripts/run-tests.sh --li` runs
  siphon as a network element against sipgate's `li-simulator-x1x2x3`, which
  plays both the Administration Function and the Mediation and Delivery
  Function, over real mutual TLS with certificates from the simulator's own
  bootstrap. It provisions a destination and a task, reads the task back, and
  checks the refusals (a duplicate XID → 2010, and removing a destination a live
  task still delivers to → 7010) — because a network element that accepted
  everything would pass a success-only test.

  The peer declares `v1.6.1` on the wire while siphon is built to v1.23.1, and
  they interoperate: the message set is identical across the published v1.x
  range, so only the declared string differs. That is the version analysis being
  confirmed rather than assumed.

- **A packet capture of the delivery interface, read back by a third-party
  dissector.** `scripts/validate_li_capture.sh` places a warranted SIPp call,
  captures X2 and X3 with `tcpdump`, and hands the capture to the third-party
  `x2x3PduDissector` plus Wireshark's own SIP and RTP dissectors. It asserts the
  PDU counts, that Wireshark parses SIP inside every X2 record and finds the
  INVITE, the 200, the ACK and the BYE, that every X3 record carries RTP, and
  that the delivered RTP sequence numbers are **contiguous** — the check that
  says the packet count is right rather than merely non-zero, since a gap is a
  lost packet and a repeat is a duplicated one and either leaves a total looking
  healthy. The relayed packets are counted independently from a second capture
  taken in the media engine's own network namespace.

  The estate's delivery interface is fronted by a TLS-terminating tap for this,
  because the engine's X3 is TLS-only with ECDHE certificates and therefore
  cannot be decrypted after the fact. The outer hop stays exactly what
  production is, mutual TLS included; the capture is taken one hop later.
  `scripts/validate_x2_pdu.sh` remains the cheap check on a single encoded PDU
  and needs no estate.

- **A load profile with interception actually switched on**, and the metric to
  watch it with. Every other measurement in this repo — the 16-row baseline and
  the memory-leak soak both — runs with `lawful_intercept` absent, so the
  enforcement path had never been under load despite running on every message
  of every leg of every call. `sipp/li/li_load_test.py` places calls at a rate
  through a node with a live warrant, reports the throughput against the same
  scenario unwarranted, and asserts that the per-session state falls back to
  zero after each cycle rather than climbing. The new
  `siphon_li_remembered_sessions` gauge is what it watches, and is worth
  alerting on in production for the same reason: it is keyed on a value the
  peer chooses, so it must track live dialogs and fall back, and sitting at the
  cap is the signature of a Call-ID flood.

- **Per-target-type detection coverage.** A warrant can be accepted and then
  match nothing, which no provisioning test can catch — provisioning succeeded.
  So `sipp/li/li_target_types_test.py` provisions a warrant on each identifier
  type an IMS can name (`sipUri`, `telUri`, `e164Number`, `impu`, `impi`, on
  both the originating and terminating side), places a real call carrying that
  identity through siphon with SIPp, and checks IRI actually reached the
  mediation function. The matching layer additionally has an exhaustive
  compile-time guard: adding a `TargetIdentifier` variant without deciding how
  it is indexed now fails the build rather than silently matching nothing.

- **`lawful_intercept.x1.admf`** — the network-element-to-ADMF client block
  (`endpoint`, `client_certificate`, `client_private_key`, `server_ca`,
  `keepalive_secs`, `request_timeout_secs`, `reconcile_on_start`). Absent means
  siphon answers X1 but never speaks first.

### Changed
- **Interception is enforced in the dispatcher, not by the Python script.** This
  is a behavioural change and a compliance fix. Interception used to be opt-in:
  the only callers of the matching code were the `li.*` script API, so a script
  that omitted a call on one path silently intercepted nothing there. For a
  warranted intercept a missed leg is a reportable failure, and it must not
  depend on the operator's code being right. siphon now matches every SIP
  message, on every leg, on every path, against the tasks the ADMF provisioned,
  before any handler runs.

  `li.is_target()` still answers the same question. `li.intercept()` and
  `li.stop_intercept()` are kept so existing scripts keep working, but they now
  **report** rather than act — had they kept emitting, every script that calls
  them would produce duplicate IRI records. `li.record()` / `li.stop_recording()`
  are unchanged in purpose (operator-driven SIPREC, which is not a warrant) but
  no longer push a synthetic `SIPREC-<call-id>` record onto the X2 channel; a
  recording is not lawful-intercept product and does not belong on a mediation
  function's warrant feed. Two new read-only properties, `li.task_count` and
  `li.destination_count`, report what the ADMF has provisioned.

- **X2 records carry the task's XID and a non-zero per-session Correlation ID.**
  TS 103 221-2 clause 6 requires that a session's X2 and X3 records share a
  correlation, and since X3 is emitted by the media engine and X2 by this
  process, that is an invariant spanning two binaries. A `correlationID` the
  ADMF provisioned is honoured; otherwise one is derived deterministically from
  the Call-ID (FNV-1a, forced non-zero) so both sides reach the same value
  without exchanging it.

- **`lawful_intercept.x1` configuration.** `auth_token` is **removed** — a
  bearer token is not part of TS 103 221-1 and mutual TLS is the authentication.
  `tls.client_ca` is now **required**: a listener without one would accept
  anyone, so a missing or empty CA bundle is a startup error rather than a
  silent downgrade. New: `ne_identifier` (required), `admf_identifier`, `path`,
  `version`, `bind_admf_identifier_to_certificate`.

- **The X1 listener is bound at startup.** A configured `lawful_intercept.x1`
  that cannot be bound now fails startup instead of coming up with an interface
  that is not listening.

### Removed
- **`lawful_intercept.x3` loses every field it had**, because not one of them
  did anything. `listen_udp` bound a UDP socket to receive RTP mirrored by
  rtpengine, and nothing ever asked any backend to mirror there — nor could it,
  since the block is refused at config load on every backend except
  `siphon-rtp`, and on that one the engine frames the content and delivers it
  straight to the destinations the ADMF provisioned over X1. `delivery_address`,
  `transport` and `encapsulation` described the same path.

  What the block actually did was gate content against `media.backend` and make
  `ActivateTask` refuse a content warrant `3040` on a node that cannot deliver
  one. So it is now a single required `enabled`, and `src/li/x3.rs` — the
  receive-and-forward path none of the removed fields reached — is gone.
  `enabled: true` requires `media.backend: siphon-rtp` and is refused at load on
  anything else; `enabled: false` is the same as leaving the block out, so
  content can be switched off without deleting configuration. Required rather
  than defaulted, so writing the block is a statement rather than an empty
  gesture.

  These fields never functioned in any released version, so nothing that worked
  before stops working; a configuration that still sets them is simply ignored.

### Fixed
- **A transfer no longer silently inherits a direction-bound media profile.**
  When one is inherited with no `profile=` override, siphon now logs a `WARN`
  naming it and saying what will happen, instead of producing a connected call
  with dead audio and no clue why. Same warning on an inbound `INVITE` with
  `Replaces`, which re-pairs the call the same way. siphon does not guess a
  replacement — only the script knows what the surviving pair looks like.

- **`examples/teams_sbc.yaml` no longer shows a config key that does nothing.**
  Both profiles carried `codec: ["offer", "PCMA,PCMU"]`; there is no `codec`
  field on a media profile and nothing encodes it, so the line was silently
  ignored while implying siphon restricts codecs on the operator's behalf — it
  looks like a real rtpengine NG flag, but `NgFlagsConfig` has no such field and
  no `deny_unknown_fields`, so serde dropped it and nothing ever reached the
  engine. Removed, with a note pointing at the mechanism that does work: codec
  selection is done from a script through the `sdp` namespace
  (`filter_codecs`/`remove_codecs`), not through a media profile. Both
  direction-bound profiles are now labelled as such, and the example gains a
  `@b2bua.on_refer` handler showing the `profile=` a Teams SBC needs — the exact
  topology where getting this wrong costs you the audio.

- **A per-dialog map leaked one entry for every call the node completed.** The
  per-session matching decision was released on the `BYE`, which is one message
  too early: the `200` to that BYE then found nothing remembered, re-derived a
  decision that still matched — the `To` header carries the target whichever
  way the BYE travelled — and put it straight back, where nothing would ever
  remove it again. It reached ~27000 entries over 27000 calls, on a map keyed
  by a value the peer chooses.

  The last message of a dialog is the response to its `BYE` or `CANCEL`, not
  the request, and the terminal test now says so. Release happens once per
  message after processing rather than inside the per-warrant loop, because a
  session is one thing however many warrants cover it.

  Found by `sipp/li/li_load_test.py` rather than by a unit test, which is the
  point of adding it: the predicate was self-consistent, so only watching the
  gauge across thousands of generated calls showed it. The tell was counter-
  intuitive — a number that sat perfectly still rather than one that climbed.

- **A retransmission produced a second copy of a record the mediation function
  already had.** Interception is placed before transaction matching, so that a
  script cannot drop a message before it is intercepted, and the cost of that
  placement was that RFC 3261's timers — which resend an unanswered INVITE up
  to seven times — delivered seven IRI records for one INVITE. Worse than the
  duplication, each resend re-ran the session's lifecycle, restarting content
  capture on a call already being captured.

  A message instance is now recorded once per session, keyed on the top `Via`
  branch (§8.1.1.7 requires a new branch for a new transaction, so a resend
  keeps its branch and anything genuinely new does not) plus the CSeq, method
  and status, which separate the messages *within* a transaction — an ACK on
  the INVITE's own branch, a second provisional and a final response all key
  differently. The record is held on the session's own entry, so it is released
  with the session, and past a per-session bound de-duplication stops rather
  than starts dropping: a duplicated record is recoverable at the mediation
  function and a missing one is not.

- **Matching ran per message, which could intercept a call's opening and miss
  its end.** Deciding each message on its own identities assumes every message
  of a dialog carries the target in matchable form, and they do not — a
  re-INVITE from the far end swaps `From` and `To`, an in-dialog REFER or
  NOTIFY carries whoever sent it, and a BYE can come from either side. The
  decision is now taken once per session and keyed on the Call-ID, so a
  warranted session is intercepted in full.

  Three things make that safe. A provisioning generation, bumped by every
  change that alters what matches, so an `ActivateTask` still takes effect on
  calls already in progress rather than being shadowed by a decision taken
  before it arrived. A hard cap, because the Call-ID is chosen by the peer and
  an unbounded map keyed on it is a remote way to exhaust memory; on overflow
  it is cleared, so the degraded mode is the old per-message behaviour and
  never a missed interception. And release at dialog end, so the cap is only
  ever reached by traffic that never terminates. The decision stores XIDs
  rather than the tasks themselves, so a `ModifyTask` is honoured on the next
  message instead of being shadowed by a cached copy. `li.is_target()` asks the
  same question, so the script API can no longer contradict enforcement.

- **X2 delivered the wrong interface's PDUs.** The records siphon sent to the
  Mediation Function were ETSI TS 102 232 PS-PDUs behind a four-octet length
  prefix. TS 102 232 is the *handover* format — what the MDF emits onwards to
  the LEMF — so the network element was speaking a peer's language on its own
  interface. X2 into an MDF is TS 103 221-2, and no conformant mediation
  function could read a byte of what we sent.

  X2 now emits TS 103 221-2 clause 5 PDUs: the 40-octet mandatory header, the
  conditional attribute TLVs, and the SIP message carried **verbatim** as
  payload format 9 rather than a re-serialisation, so the MDF derives whatever
  its handover format needs from the bytes that were actually on the wire
  instead of inheriting the subset of headers this element thought to copy.
  Each record carries the task's XID and the session's correlation — the same
  eight octets the engine puts on that session's X3 content, which is what lets
  the MDF tie the two together — and a direction taken from the matched party,
  because clause 5.2.6 measures direction against the target and the same
  INVITE is "to" or "from" depending on which end the warrant named.

  The encoder refuses rather than emitting anything a peer would reject (a
  payload format on the wrong interface, an over-long attribute), because a
  malformed frame does not lose one record: the receiver reads the next PDU's
  header out of the middle of this one and the connection never recovers.
  Validated against a third-party dissector via `scripts/validate_x2_pdu.sh`,
  and end-to-end against sipgate's mediation function, which decodes and
  validates every PDU it accepts.

- **One failed connection attempt lost a warrant's first record.** The X2
  delivery task dropped a record outright if the connection could not be opened
  on the first try, and that record is the least affordable one to lose: the
  first message of a matched warrant is its Begin, so a mediation function that
  never receives it has a session it cannot open. The attempt that opens the
  connection is also the one most likely to fail — the collector may start
  accepting a moment after the call that triggered it, and anything in front of
  it forks per connection. It now retries, bounded so a collector that is
  genuinely gone cannot stall delivery to the other destinations behind it.

- **`lawful_intercept.x2.transport: tls` did nothing.** The delivery task
  logged the configured transport and then opened a plain `TcpStream`
  regardless, and the `x2.tls` block was read by nothing at all — so an
  operator who configured TLS got cleartext IRI and no indication of it. TLS is
  now wired: a rustls client with the configured CA, a client certificate for
  the mediation function to authenticate the element, and `server_name` for the
  common case where the delivery address is a literal (an X1-provisioned
  destination always is — TS 103 280's `IPAddressPort` carries an
  `IPv4Address`). If any of it is missing or unreadable the delivery task
  refuses to start and says so, rather than falling back to plaintext; a silent
  downgrade on this interface is the worst outcome available.

- **X2 delivered only to the configured address, ignoring the warrant's own
  destinations.** A task's records now go to exactly the X2-capable DIDs it
  names, and to all of them; the configured `delivery_address` remains the
  fallback for a deployment that provisions no destinations over X1.

- **X3 content delivery is refused rather than silently accepted where it cannot
  be performed.** ETSI TS 103 221-2 content framing lives in the media engine,
  so `rtpengine` and `rtpproxy` cannot deliver X3 at all. Configuring
  `lawful_intercept.x3` on either is now refused at config load, naming the
  backend and the remedy; and an `ActivateTask` whose `deliveryType` is
  `X3Only` or `X2andX3` is refused `3040` at the message, because a task can be
  provisioned long after boot. Accepting a warrant and then delivering no
  content is the worst available outcome — it reads as provisioned at the ADMF,
  satisfies every acknowledgement, and the absence only surfaces when someone
  goes looking for product that was never sent.

- **A peer's own XML namespace prefixes survived per-message isolation.**
  Schema-validating each message on its own means extracting it into a
  container of its own, and that wrapper carried a *fixed* prefix list while
  the serialiser emits prefixed names without re-emitting the declarations that
  bound them. Against a peer that happens to choose the same prefixes this is
  invisible; against JAXB, which generates `ns2` for the TS 103 280 dictionary,
  every message carrying a delivery address failed to parse — so no destination
  could be created at all. The wrapper now carries the source document's own
  declarations. Found by running against a real ADMF rather than a test double.

- **A peer that renders milliseconds can now provision warrants.** TS 103 280's
  `QualifiedMicrosecondDateTime` requires exactly six fractional digits, and
  siphon enforced it. Java's `XMLGregorianCalendar` renders three, so every
  message from an ADMF built on it — sipgate's library among them — was refused
  `1010` on `messageTimestamp` before anything else was read, and no warrant
  could be provisioned. Strictness that prevents all provisioning is worse than
  the deviation it rejects, so inbound date-times are now accepted with one to
  nine fractional digits and **normalised to six**, keeping everything siphon
  emits conformant. The deviation is logged at `WARN` each time rather than
  absorbed silently: it is the peer's bug, and the operator should be able to
  raise it. See `src/li/x1/compat.rs`, which is the only place this leniency
  lives.

- **An `ErrorResponse` is now correlatable even when the envelope is what
  failed.** A message whose `messageTimestamp` did not parse previously lost its
  `admfIdentifier` and `x1TransactionId` too, so the ADMF got an error it could
  not tie to any request it had sent. The envelope is now salvaged field by
  field and the message type read from `xsi:type` independently, so only the
  genuinely unreadable fields are substituted.

- **`docs/feature-readiness-matrix.md` claimed X1, X2 and X3 were implemented.**
  Those rows described behaviour that was not in the binary; an operator reading
  the table during vendor selection would reasonably have concluded the ETSI
  work was done. Corrected, including the media-backend constraint on X3.

## [1.7.0] — 2026-08-31

### Added
- **`listen.udp_recv_buffer_bytes` — the UDP listener receive buffer is now
  sized by siphon instead of inherited from the kernel.** Listener sockets set
  `SO_REUSEPORT` and otherwise took whatever `net.core.rmem_default` gave them,
  typically ~212 KB, which is only a few hundred milliseconds of headroom at
  IMS registration rates. A scheduler stall on a busy box then overflows the
  socket queue and the kernel drops the datagrams silently — which a UAC sees
  as a retransmission rather than an error, so it shows up as a sharp cliff in
  the retransmit rate rather than gradual degradation, and looks like a peer
  problem rather than a local one. Defaults to 1 MiB per socket. Because
  `SO_REUSEPORT` gives one socket per worker the real cost is this value times
  the worker count, and socket buffers are charged to the cgroup, so it is
  deliberately modest; set `0` to leave the kernel default alone. siphon now
  reads the granted size back and warns when `net.core.rmem_max` clamped the
  request, which is otherwise invisible.

- **`originate` — a call siphon places itself.** Both the control-plane verb
  (`module: "sip"`, `verb: "originate"`) and the in-process
  `b2bua.originate(...)`. Until now a call could only ever be a *reaction*:
  `call.dial()` builds a B-leg off an INVITE that already arrived, and
  `proxy.send_request()` is a one-shot request/response with no dialog you can
  later answer, transfer or tear down. So click-to-dial, callbacks and outbound
  notification had no primitive at all, and an application driving a transfer
  could not place the leg it wanted to transfer *to*. An originated call is a
  `CallActor` whose A-leg is a UAC dialog siphon owns end to end: it ACKs the 2xx
  (RFC 3261 §13.2.2.4), ACKs a final non-2xx on the INVITE's own branch
  (§17.1.1.3), CANCELs rather than answering a response when abandoned before
  answer (§9.1 — a UAC has no business sending one to the party it is calling),
  and tears down through the same funnel every other B2BUA call uses.
  - **The channel id is supplied by the caller, never minted by siphon.** An
    application stages its per-call context — routing, media plan, its own state
    — keyed on an id it chose before anything reaches the network; returning an
    id instead would force a round-trip a well-built controller has designed out.
    Reusing a **live** id answers the new `conflict` error code (distinct from
    `bad_request`: the frame is fine, the id collides, and retrying the same one
    can never succeed); the id is free again once the call is gone.
  - **The accept is the local action, not the far-end outcome.** The reply comes
    back as soon as the INVITE is on the wire, while the callee is still ringing
    — so ringback or a prompt can start during ring, and one ringing phone never
    serialises a connection's command stream. Ringing, answer and hangup arrive
    afterwards as `ChannelStateChange` / `StasisEnd` events on the supplied id,
    and `StasisEnd` now carries the SIP cause (`code` + `response`) for a leg
    that was rejected, which is the only way a controller can learn *why* when
    there is no A-leg the response was relayed to.
  - **Full outbound identity**: From URI and display name, To URI and display
    name, `P-Asserted-Identity` (RFC 3325 §9.1), RFC 3323 §4.1 / TS 24.607 CLIR
    via `privacy: "restricted"` (applied last, so a custom header cannot undo
    it), a `next_hop` that steers egress without reshaping the R-URI, and
    arbitrary custom headers. Dialog-defining headers are refused rather than
    applied — overwriting one would leave the leg unaddressable for its own ACK.
  - **Media**: either the caller's own SDP offer (any backend, or none), or
    `media: true`, which sends the INVITE offerless and answers the callee's 2xx
    offer locally on the media backend with the answer riding on the ACK. The
    resulting session is keyed on the leg's SIP Call-ID, so `play` / `dtmf` /
    `hold` / `stream_start` work against an originated leg exactly as they do
    against an inbound-anchored one. A backend that cannot do it is refused at
    the command (`unsupported_verb`), never connected as a mute call.
  - Typed refusals throughout — `bad_request`, `conflict`, `not_found` (no
    route), `unsupported_verb`, `unavailable` — each separately actionable, and
    a refused originate registers no channel and places nothing on the wire.

- **`ui` and `sctp` cargo features on `siphon-bin`**, forwarding to the
  `siphon-sip` features of the same name. Previously an extension build had no
  way to turn either on, so composing extensions meant giving up the operator
  dashboard and SCTP transport. The official artifacts build with `ui`.

- **Release-cut now runs the security-advisory gate over the `siphon-bin`
  composition too**, not just the `siphon-sip` graph. The released binary is
  built from that composition, so the extension crates and their dependency
  trees reach operators; an open advisory in one of them would previously have
  left the gate green.

### Changed
- **`hangup` on an un-answered call siphon originated now CANCELs** instead of
  sending a final non-2xx. The response path is correct for an inbound call
  parked under control; on a call siphon placed, siphon is the UAC.
- Two new stable control-plane error codes, `conflict` and `invalid_state`,
  mirrored into `siphon-control-proto` and the TypeScript SDK so a client parses
  them as the refusals they are rather than a transport error.

- **Answering-machine detection — `beep_detection` on a media profile and the
  `@rtpengine.on_beep` handler.** The engine could hear the short record tone an
  answering machine plays before it starts recording, but nothing carried it to a
  script, so a transfer had no way to tell a person from a voicemail box and the
  caller got bridged into the greeting. Arm it per leg (the profile used toward
  the callee is what watches the party that might be a machine) and the tone
  arrives as `fn(call_id, from_tag, to_tag, frequency_hz, duration_ms,
  offset_ms)`, filterable by `call_id` / `from_tag` like the sibling media hooks.
  It fires once per leg per call, so a handler never de-duplicates.
  `beep_cadence_guard_ms` tunes the guard that tells a record tone from a
  cadenced ringback or busy tone; it is also the detection latency, so the event
  trails the tone itself by that long, and `offset_ms` is the offset of the
  **tone**, not of the event.

- **Synthesised call-progress tones and engine-fetched HTTP prompts** —
  `rtpengine.play_media(target, tone=...)` and `url=...`. `tone` takes either a
  preset name (`ringback_eu`, `busy_na`, `dial_uk`, …) or an explicit cadence
  spec (`425/1000,0/4000*inf`), rendered at the leg's codec rate, so early media
  no longer needs a provisioned audio file. `url` is fetched by the **engine**
  from its own network position, bounded engine-side and off the media path: a
  URL that never answers ends the playback, never the leg.

- **Overlay playback with per-play gain** — `rtpengine.play_overlay(...)` mixes
  audio *under* a party's live egress instead of replacing it and returns the
  playback's `play_id`; `rtpengine.set_play_gain(target, play_id, decibels)`
  retunes one that is already running, and `rtpengine.stop_media(target,
  play_id=...)` stops a single slot rather than everything on the leg. Up to four
  overlays run concurrently per direction. This is what a music bed ducked under
  a prompt needs: `play_media` is a *start*, so reusing it to change a level
  would mean "start another playback".

- **Independent L16 wire rates for the WebSocket bridge and tee** —
  `ws_sample_rate` and `ws_tee_sample_rate` on a media profile,
  `rtpengine.attach_ws_tee(..., sample_rate=...)` per attach. The bridge rate
  applies in both directions, so an 8 kHz G.711 call can speak 16 kHz to an
  inference server and a server rendering 24 kHz audio plays at the right speed
  and pitch instead of the wrong one. The tee rate is send-only and never changes
  what the call hears. Both must be a multiple of 1000 within 8000–48000; the
  media engine *fails* the offer rather than clamping, so siphon rejects a bad
  value at config load and at the call instead of letting the box come up healthy
  and answer every call into silence.

- **Selectable uplink voice-activity detector** — `ws_vad_engine: energy |
  neural` on a media profile. `energy` (the default, and the previous behaviour)
  answers "is something loud here", so breathing, mains hum and uncancelled echo
  all read as speech; `neural` answers "is what is here speech" and does not
  turn-start on non-speech noise. An unknown value is a hard config error rather
  than a quiet fall back to the detector the operator was avoiding.

- **Leading minimum-speech run before barge-in** — `ws_vad_min_speech_ms`, the
  counterpart to the existing trailing `ws_vad_hangover_ms`. Without it the
  speech-start edge fires on the first speech frame, which is what lets a cough,
  a door or one burst of echo interrupt a prompt. 60–120 ms is the useful range;
  it adds directly to turn-start latency.

- **All six new profile fields are accepted per call** on `rtpengine.offer()`,
  `answer()` and `answer_local()`, the same way `ws_uri=` already was — so beep
  detection can be armed on one leg of one call without a second profile.

- The native media control contract moved from 0.2.0 to 0.3.0. The JSON wire is
  unchanged (every new field is optional and omitted when unset, and a default
  profile still serialises to `{}`), so an unset knob emits exactly the command
  it did before. A media profile that sets any of the six new fields on the
  `rtpengine` or `rtpproxy` backend is rejected at config load, as the existing
  WebSocket and DSP fields already were: a field the engine never receives is a
  dead call, not a degraded one. Likewise `tone=` / `url=` / `overlay` /
  `gain_decibels` / a targeted `stop_media` / `set_play_gain` raise on those
  backends rather than silently downgrading — an overlay quietly turned into a
  supersede would cut the party's live audio.

- **An outbound REFER on the external control rail now reports a real verdict.**
  An application that asked siphon to transfer a call with the `refer` verb
  learned only that the request had been accepted for processing — the outcome
  existed inside siphon and was thrown away into a log line. Three new events
  carry it on the owning connection: `TransferProgress` while the transfer is
  still moving, then exactly one `TransferCompleted` / `TransferFailed`. Shared
  payload `{stage, refer_to?, code?, reason?, attempt?}`, with `stage` naming
  where the verdict came from (`accepted`, `challenged`, `notify`,
  `transferred`, `refused`, `rejected`, `unauthorized`, `no_outcome`,
  `call_ended`) and `code`/`reason` carrying the SIP status it rests on. Three
  things this fixes: the `2xx` to a REFER is now reported as *progress*, not
  success — RFC 3515 §2.4.4 makes it "accepted for processing", so treating it
  as the answer called every failed transfer a success; the `message/sipfrag`
  body of the REFER-subscription NOTIFY, which is where the real outcome lives,
  is now parsed rather than only logged; and a carrier that challenges the REFER
  and is answered with credentials is distinguishable from one that refuses,
  via the stage plus the 1-based `attempt` number, even though both carry the
  same `407`. Exactly one terminal event is emitted per REFER — including when
  the call is torn down mid-transfer, whose implicit subscription can never
  report — so a transfer is never left pending. The `refer` command reply is
  unchanged (`{refer: "sent"}`): a far-end outcome is never folded into a
  command reply, which would mean blocking a command on the peer.

- **Control SDKs** (Rust `siphon-control-proto` / `siphon-control-client`,
  TypeScript `@siphon-project/control`): the three events, a typed
  `TransferOutcomePayload` + `TransferStage`, `CallEvent::transfer_outcome()` /
  `CallEvent::is_transfer_final()` and the TypeScript `isTransferFinal()`.

- **`siphon-control-proto`'s `SipEvent` is now `#[non_exhaustive]`.** The
  server's event set grows, and without it every addition breaks any downstream
  `match` with an arm per variant. A wildcard arm is now required once, and
  every future event is purely additive. Consumers matching `SipEvent`
  exhaustively need to add `_ => {}`.

- **The official artifacts now ship the `http` extension.** The container image,
  the `.deb`, the `.rpm` and the release tarball are built from the
  extension-composing `siphon-bin` package instead of the plain `siphon-sip`
  one, so the scriptable `http` namespace (inbound `@http.route` handlers plus
  the Rust-backed `http.Client`) is compiled in. Previously it was reachable
  only by building `siphon-bin` yourself, which is a real barrier for anyone
  installing from a package or running the image. It is the one module with no
  deployment prerequisite, so it costs an operator nothing to carry.

  Nothing changes for an existing deployment: the artifact is still a binary
  called `siphon` with the same CLI and the same `siphon.yaml`, the embedded
  `ui` dashboard is still compiled in, and a module that is compiled in but has
  no `extensions:` entry registers nothing and costs nothing at runtime. To
  start using it, add `extensions: { http: /etc/siphon/http.yaml }` — `siphon.yaml`
  now carries a commented reference block for the section. `smpp` and `sigtran`
  keep their deployment prerequisites and still need a `siphon-bin` build.

  `cargo install siphon-sip` is unaffected and still installs the SIP core with
  no extensions; the published crate is byte-identical to 1.6.0.

- **`.deb` maintainer address** is now `maintainers@siphon-sip.org` rather than
  a personal one.

### Fixed
- **The callee is ACKed on every answered call again.** A B-leg response was
  classified from the leg actor's `CallEvent` rather than from its own status
  line, and that event arrives on a per-call channel every leg pushes to, with no
  guarantee it describes the response in hand. The receiver is taken out of the
  map to be waited on, so when a call's `18x` and its `200` are processed at once
  — the normal shape of an answered call — the second handler finds the receiver
  gone and falls back to the status code while the event its own send produced
  stays queued, leaving the stream off by one. The next response then reads its
  predecessor's event, and a `200 OK` read as a `Provisional` skips `set_winner`
  and the deferred B-leg ACK (RFC 3261 §14.1): the callee's `200` is never ACKed,
  it retransmits to Timer B, and the dialog collapses seconds after everyone
  believes the call is up — with nothing wrong on the caller's side. Filtering
  stray `Terminated` events had removed one source of the skew; the
  classification no longer depends on the event at all, which removes the rest.
  Measured at **8-15% of plain B2BUA calls** on a loopback bridge before the fix
  and **0 of 180** after, with a new acceptance gate that drives calls in a tight
  loop — the existing SIPp scenarios never produced the concurrency and so never
  caught it.

- **An inbound `INVITE` with `Replaces` now actually takes the call over.** The
  transferee half of attended transfer (RFC 3891 §3 / RFC 5589 §7): a UA calls in
  naming the dialog it is taking over. siphon matched that dialog, logged it, and
  then let the INVITE through as an ordinary new call — so the transfer only half
  happened. The transferor was left in a call that never ended, and the
  transferee got a second, unrelated call routed by the dial plan instead of the
  one it asked to join. It now hands the call over: the named party is BYE'd
  (§3 requires the replaced dialog to be terminated), the new caller takes its
  place, and the party on the other side is re-INVITEd onto the new media
  (RFC 3261 §14) rather than left sending audio to whoever just left. Works in
  both directions — the named dialog may be the caller's or the callee's, and the
  everyday "answer a call, then transfer it" is the callee case.
  - **Off unless enabled** — `b2bua.accept_replaces: true`. Possession of a
    dialog's identifiers is not proof of authorisation to end that dialog, and
    the triple is handed to the transferee by design and readable by anyone who
    can observe unprotected signalling, so this is a capability an operator opts
    into rather than one an upgrade switches on. Left off, a `Replaces` naming a
    dialog this node hosts is declined `603` rather than ignored — so the bug
    above is fixed either way: the INVITE never becomes an unrelated second call.
  - **The takeover runs only after the script admits the INVITE.** RFC 3891 §5
    makes `Replaces` a call-hijack primitive for anyone who learns a dialog's
    identifiers, and siphon's admission control for an INVITE is the script — so
    an `auth.require_proxy_digest()` (or any `call.reject()`) in
    `@b2bua.on_invite` stops a takeover exactly as it stops a call. Nothing is
    torn down on the say-so of an unauthenticated request. When the script does
    admit it, the takeover replaces whatever routing the script asked for: an
    INVITE with `Replaces` is a request to join an existing call, not a new one
    to route.
  - `early-only` (RFC 3891 §3) is now honoured rather than parsed and ignored: it
    asks to replace a dialog that has not been answered, and siphon only ever
    takes over a confirmed one, so it is declined `486 Busy Here` — the response
    that section names. A `Replaces` naming a dialog that is not answered gets the
    same treatment, and one naming a dialog this node does not host still gets
    `481` as before.

- **A locally-generated 2xx is retransmitted like a relayed one.** `call.answer()`
  sent the 200 once and armed nothing. The B2BUA intercepts the A-leg INVITE
  before a server transaction exists, so nothing underneath recovers a lost 200
  (RFC 3261 §13.3.1.4) and a single dropped packet left the caller ringing until
  it gave up on a call siphon considered answered. Now armed on the same UAS
  schedule as the relayed path and cancelled by the caller's ACK.

- **A blind transfer no longer kills the call when the transferor hangs up
  first.** In a siphon-terminated `REFER` the transferor is free to end its own
  dialog the moment the transfer is accepted (RFC 5589 §7), and real ones do —
  a Microsoft Teams blind transfer BYEs within a few hundred milliseconds of the
  `202`, roughly a second before the transfer target answers. That BYE was
  treated as an ordinary bridge hangup: siphon generated a BYE at the far leg
  (killing the very party the transfer exists to keep), deleted the media
  session and destroyed the call actor. The target's `200 OK` then matched
  nothing and was never ACKed, so it retransmitted to Timer B and the transfer
  target was left in a call no one was on. Both parties dropped and the transfer
  destination rang into nowhere. The referrer's departure is now recognised
  while the transfer is in flight: the BYE is answered `200`, the surviving leg
  is kept, the target is dialled through to completion and bridged, and the
  terminating sipfrag `NOTIFY` and referrer `BYE` are skipped because the
  implicit subscription died with the dialog (RFC 3515 §2.4.4). `@b2bua.on_bye`
  no longer fires for that BYE either — the call is not ending, so a handler
  that tears the call down on it can no longer undo the transfer. If the target
  then *fails*, the now-orphaned surviving leg is released instead of being left
  stranded.

- **Attended transfer emits the `Replaces` it was given.** An attended `REFER`
  carries `Refer-To: <target?Replaces=dialog>`, and RFC 3891 §3 requires that
  dialog reference on the INVITE sent to the transfer target. siphon parsed the
  `Replaces`, used it only to label a log line, and dropped it — so every
  attended transfer degraded silently into a blind one and the held call it was
  meant to take over was never replaced. The reference is now carried onto the
  triggered INVITE, and rewritten to the dialog as the *target* sees it when
  siphon hosts the replaced call: the referrer names it with the identifiers of
  the leg facing itself, which on a B2BUA are meaningless at the far end and
  would draw a `481`. A dialog siphon does not host crosses unchanged.

- **A completed transfer no longer strands the referrer's Call-ID.** The leg the
  transfer promoted away from left the call without its registry entry being
  cleared, and teardown only walks the legs still attached, so the mapping
  outlived the call permanently. A later INVITE reusing that Call-ID matched the
  "call already exists" guard and was absorbed as a retransmission — the caller
  got no response at all, not even a `100`. The promoted-away dialog is now
  retired properly, so a late in-dialog request on it answers `481` like any
  other torn-down leg.

- **Runtime threads no longer orphan a CPython thread state when they are
  reaped — a steady, traffic-independent RSS climb on every deployment.** Each
  tokio runtime thread is pinned to the interpreter at thread start with a held
  `PyGILState_Ensure`, which keeps free-threaded CPython from tearing down and
  re-creating that thread's mimalloc heap on every attach/release cycle. The
  attach was never released, on the assumption that the thread state would be
  reclaimed when the thread itself exited. It is not: an unreleased `GILState`
  keeps CPython from ever destroying the state, and `PyGILState_Ensure`
  allocates it through CPython's *raw* domain (`PyMem_RawCalloc` → `malloc`), so
  the orphan lands on the C heap where neither jemalloc nor the
  `siphon_memory_*` gauges can see it. Harmless for the fixed async workers,
  which live as long as the process — but the same hook runs on tokio's elastic
  blocking pool, whose threads are reaped after their idle keep-alive. Every
  reaped blocking thread leaked **~15.6 KB**, measured. Any deployment doing
  blocking work on a timer (DNS resolution, netlink, TLS handshakes, gateway
  health probes) therefore grew at a constant rate whether or not it was
  carrying calls, with `siphon_memory_allocated_bytes` sitting flat and
  innocent throughout; only `siphon_glibc_in_use_bytes` moved. The pin is now
  released on thread stop, which bounds the blocking pool while leaving the
  optimization it exists for untouched — the workers it targets never stop.

- **A `siphon-bin` build reports the SIPhon version again.** It announced its
  own package version (`0.1.0`) in the startup banner, the `User-Agent`/`Server`
  headers and `/admin/health`, which broke the lockstep guarantee that the
  crate, the binary, the image and the SDK all carry one number. It now inherits
  the `siphon-sip` version it was built against. This matters more than it did
  before, because that build is now what the official artifacts ship.

- **A `487 Request Terminated` answering a CANCEL siphon sent is now ACKed
  (RFC 3261 §17.1.1.3).** It never was, on any CANCELled B2BUA leg. The CANCEL
  paths tear the call down as they put the CANCEL on the wire, which unregisters
  the leg's Via branch, so the `487` that RFC 3261 §9.1 makes the ordinary
  outcome matched nothing and fell out of the response path as an unknown
  branch. The B2BUA registers no client transaction — it runs its own retransmit
  schedule — so nothing generated the ACK further down either. The peer's INVITE
  server transaction then retransmitted the `487` on Timer G until Timer H
  (64\*T1 = 32 s, §17.2.1), holding transaction state at both ends of every
  abandoned call. It costs most on outbound traffic, where CANCEL is routine
  rather than exceptional: each abandoned or timed-out attempt left a peer
  retransmitting for 32 seconds. Existing handling covered only the §9.1 glare
  case — a 2xx that beat the CANCEL — and that path is unchanged: a 2xx is still
  ACKed and BYEd, never reclassified. The ACK rides the INVITE's own branch and
  Request-URI and carries the response's To-tag, so the peer's server
  transaction matches it (§17.2.3), and it is re-sent for every retransmission
  of the response. Fixed for both an ordinary B2BUA B-leg and a call siphon
  placed itself (`originate`), whose pending INVITE sits on the A-leg. The proxy
  path was never affected: it relays and forks through real client transactions,
  whose state machine already emits the ACK and caches it for retransmits.

## [1.6.0] — 2026-08-20

### Added
- **`auth.generate_nonce()` and `auth.validate_nonce(nonce)` are reachable from
  scripts.** Both existed, but in a plain `impl` rather than a `#[pymethods]`
  block, so neither the engine nor the SDK exposed them. A script that verifies
  credentials itself — rather than through a configured `auth.backend` — has to
  build its own `WWW-Authenticate` header, and had no way to mint a nonce this
  engine would recognise coming back, or to reject a replayed one. Validating
  the nonce is what bounds replay of a captured `Authorization`; without it a
  script-side digest check is replayable forever.

- **RFC 3323 caller-ID restriction (CLIR)** — `call.restrict_caller_id()`, and
  `caller_id_presentation: "restricted"` on an LCR route. There was no RFC 3323
  anonymisation anywhere in the tree, so a deployment asserting `Privacy: id`
  left the subscriber's real number in the `From`, leaking it to every carrier
  that renders `From` rather than `P-Asserted-Identity` — which defeats CLIR
  while looking like it works. The two now move together: `From` becomes
  `"Anonymous" <sip:anonymous@anonymous.invalid>` with its dialog tag intact,
  `Privacy: id` is appended to any existing value, `P-Preferred-Identity` is
  dropped (it is the UA's *request*, and forwarding it past a privacy boundary
  re-leaks the number), and `P-Asserted-Identity` keeps the real identity for
  the trusted next hop per RFC 3325 §7.

- **Per-route presented CLI** — `caller_id` on an LCR route, and
  `call.set_caller_id(number)`. The presented CLI is a per-call, per-carrier
  decision the contract could not express: `number_policy` reshapes a number's
  *format* but cannot substitute a different one, `call.set_from_user` is
  tag-safe but identical for every carrier attempt, and a `From` in a route's
  `headers` would take the dialog tag with it. Applied through the same
  tag-preserving path the identity reshaping already uses, to `From` and to
  `P-Asserted-Identity` / `P-Preferred-Identity` where present. Two carriers in
  one answer can now present different CLIs on the same call.

- **CI covers re-INVITE renegotiation on the `siphon-rtp` backend** (`--reoffer`).
  The existing `--reinvite` mode runs the same hold/resume flow against
  rtpengine, where a repeat `offer` on a live call-id *is* the re-offer — so it
  cannot tell a renegotiation from a replacement, which is why the media session
  being replaced on every re-INVITE went unseen. The mock engine now models the
  distinction (an `offer` on a new call-id allocates a port, a repeat `offer`
  replaces the call and allocates a *new* one, a `reoffer` renegotiates in place
  and keeps it, an unknown call-id errors rather than implicitly creating, and a
  codec change is refused the way the real engine refuses it), and the job
  asserts the control verbs the engine actually received: exactly one `offer`
  and a `reoffer` per re-INVITE. Verified against a reverted fix, where the mock
  sees three offers and no re-offers — while SIPp still exits 0, which is why
  the assertion is on the verbs and not on the call outcome.

- **`call.flow`, `Flow.connection_id`, and `Flow` equality/hashing.** A B2BUA
  `Call` exposed no inbound flow at all, so the RFC 5626 authorisation — accept
  an INVITE that arrived on the connection a registration was made on, rather
  than challenging every call with a 407 — could not be written, even though
  `request.flow` and `Contact.flow` both existed. `Flow` also had no `__eq__`,
  so `call.flow == contact.flow` would have compared object identity and
  silently always been `False`; it now compares by value and hashes, so a flow
  works as a dict key or set member too. On a stream transport the comparison is
  an exact match on one accepted socket, which is what makes it stronger than a
  source-address check — the latter is worthless behind carrier NAT, where every
  subscriber shares an address. On UDP a flow is derived from the address pair
  and carries no more assurance than the address does. `call.flow` is `None` for
  an internally-originated call, which is distinguishable from a flow that did
  not match.

- **`password=` / `ha1=` on the digest helpers** (`auth.verify_digest`,
  `require_digest`, `require_www_digest`, `require_proxy_digest`, on a `Request`
  or a `Call`). Verifies the digest response against a credential the script
  supplies, short-circuiting the configured backend — so a deployment that can
  derive credentials in-process needs no credential source configured at all,
  instead of standing up an HTTP endpoint for siphon to fetch a value the script
  already has. `password=` takes the plaintext and answers MD5, SHA-256 and
  SHA-512-256 alike, since H(A1) is derived with whatever algorithm the client
  used (RFC 7616 §3.4.3); `ha1=` takes an already-computed H(A1) so the
  deployment never holds plaintext, at the cost of being bound to the one
  algorithm it was computed for. Passing both raises `ValueError` rather than
  silently preferring one. Everything else is unchanged: the anti-replay nonce
  check still runs, a rejection still arms the 401/407, still counts toward
  `failed_auth_ban`, and still increments `siphon_credential_failures_total`.

- **A CCR-UPDATE at answer, carrying `Time-Stamps`** (TS 32.299 §7.2.97). There
  was no credit-control request at the 200 OK, so an OCS could not tell when
  charging actually started and a Diameter-to-HTTP bridge had nothing to
  translate into a connect event. `SIP-Request-Timestamp` is the INVITE that
  triggered the reservation, `SIP-Response-Timestamp` is the answer;
  `ImsChargingData.response_timestamp` already existed and was never set,
  because at CCR-INITIAL there is no answer yet. Idempotent — a retransmitted
  200 OK neither restarts the clock nor sends a second record.

- **`ro.charge_from`** (`answer` | `invite`, default `answer`) — see above.

- **`destination` on the LCR answer**, at the answer level and per route (the
  route's own wins). Retargets the call at a different destination number
  (RFC 3261 §16.5) *before* the ordinary dial path runs, so `tech_prefix`,
  `number_policy` and gateway-group member selection all still apply on top.
  Previously the only levers were `tech_prefix`, which can only prepend, and
  `ruri`, which replaces the whole Request-URI and so forces the routing API to
  compose each carrier's host by hand — bypassing gateway-group member selection
  and health checks entirely. Accepts a bare number or a full URI, of which only
  the userpart is taken: the host stays siphon's to decide, so a retarget can
  never route a call somewhere the operator did not configure. A `destination`
  alone does not make a route routable — it says who to reach, never how. The
  `To` userpart follows the retarget so the number the call was dialled on never
  reaches the carrier; the tech prefix is deliberately not applied to `To`,
  being a routing artifact of the R-URI rather than part of the called-party
  identity. The field is absent from the wire when unset, so the contract stays
  additive.

- **`security.apiban.ban_ttl_secs` expires blocklist entries** (default `604800`,
  7 days, matching the interval after which APIBAN itself releases an address).
  Entries used to be inserted permanently and the poll only ever fetched
  forward, so the set grew for the life of the process and a false positive
  stayed blocked until a restart — which drops every registration — or until it
  was lifted one address at a time. The TTL is applied as a per-element kernel
  timeout, so nf_tables expires entries without siphon acting, and the userspace
  store enforces the deadline on read as well as sweeping on the poll cycle.
  `0` restores the previous never-expire behaviour. Note the poll still only
  fetches forward from the last seen id: an address whose TTL expires while it
  is still abusive returns when the feed re-lists it, not immediately.

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

- **Media / header / REFER verbs + the two events on the control-plane SDK's
  `sip` facade — all three bindings.** Wraps the SIP-adapter verbs that shipped
  server-side, mirroring the `route()` facade: `play` (one of `file` / `db_id` /
  `blob`, the blob base64-encoded on the wire, plus `repeat` / `start_ms` /
  `duration_ms` / `to_tag`), `stop`, `dtmf` (`digits` plus `duration_ms` /
  `volume_dbm0` / `pause_ms` / `to_tag`), `hold` / `unhold`, `stream_start`
  (`ws_uri`, `direction` ∈ `both` / `caller` / `callee`, `channels` — siphon-rtp
  only, so other backends answer `unsupported_verb`) / `stream_stop`,
  `remove_header`, and `accept_refer` (`{target?, next_hop?, mode?}`) /
  `reject_refer` (`{code, reason?}`). The inbound `ChannelDtmfReceived`
  (`{digit, duration_ms, volume, from_tag}`) and `TransferRequested`
  (`{refer_to, replaces?, from_tag}`) events are added to the client event enums
  with typed payload views so a consumer can match and decode them. Method names
  follow the verbs (`play` / `stop` / `dtmf` / `hold` / `unhold` /
  `streamStart`/`stream_start` / `streamStop`/`stream_stop` /
  `removeHeader`/`remove_header` / `acceptRefer`/`accept_refer` /
  `rejectRefer`/`reject_refer`), idiomatically cased per language. Errors surface
  as the same typed `unsupported_verb` / `bad_request` / `not_found` as the
  sibling verbs. The control SDK version is unchanged (its own `control-sdk-v*`
  train cuts the release).

- **Cold transfer off a call siphon answered itself.** A voice-AI or IVR call has
  no B leg, so the only way to hand the caller on is an in-dialog REFER on the A
  dialog via the imperative `b2bua.refer(call_id, target)` — `call.refer()` is a
  no-op from `@b2bua.on_invite` (the dialog is not confirmed yet) and
  `@b2bua.on_answer` never fires without a B leg. Now covered end to end by a
  functional scenario, wired into `examples/voice_ai_b2bua.py` as "press 0 for an
  agent", and documented in `docs/cookbook/voice-ai.md`.

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
- **`siphon-bin` enables the `http` extension by default.** The package exists
  to compose extension modules, and its default feature set was empty — so a
  bare `cargo build -p siphon-bin` produced a binary with no extensions at all,
  which is just the plain `siphon` anyone can get from `cargo install
  siphon-sip`. HTTP is the module with no deployment prerequisite (no libsctp,
  no upstream SMSC bind, nothing to provision) and the one most scripts reach
  for, so it is now what you get out of the box. Features are additive, so
  `--features smpp` gives you http **and** smpp; `--no-default-features`
  restores the empty build. This affects only the `siphon-bin` package —
  `siphon-sip` itself is unchanged and still ships no extensions.

- **Ro no longer bills ring time.** The usage clock was stamped at
  CCR-INITIAL — which `call.ro_authorize()` fires *before* any carrier is
  dialled — and every reported figure was measured from there, so ring time was
  charged and a call that was never answered could report a full grant of used
  seconds. With two carriers at `timeout_secs: 12`, 24 seconds of a 30-second
  grant could be gone before the callee picked up, and it got worse the longer
  the carrier list. The clock now starts at the 200 OK, which is what TS 32.260
  §5 means by chargeable duration. **This changes billed duration on upgrade for
  any existing Ro deployment**; set the new `ro.charge_from: invite` to keep the
  previous behaviour. Only the clock moved — the reservation still happens at
  INVITE, since reserve-before-connect is the point of the prepaid gate.

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
- **Ro usage is reported as a delta, not per-interval.** A CCR-UPDATE that fails
  now leaves its seconds unreported, so the next record — or the
  CCR-TERMINATION — still covers them exactly once, instead of the interval
  being lost.

- **Ro CCR-UPDATE and CCR-TERMINATION now carry Service-Information.** Both were
  built with `ims_data: None`, so only the Session-Id, the subscriber and the
  units reached the OCS. Nothing after the initial request named the carrier,
  the ICID or the calling/called party, which left a charging backend unable to
  attribute mid-call usage or the final record — and under LCR failover the
  carrier that matters is the one that actually carried the call, so it could
  not be inferred from the CCR-INITIAL either. The `ImsChargingData` built at
  CCR-INITIAL is now carried on the session, stamped with the winning carrier as
  `Outgoing-Trunk-Group-Id` (TS 32.299 §7.2.71) when the call is answered, and
  sent on every subsequent request in the session. Each record's `Time-Stamps`
  describes its own trigger rather than repeating the INVITE's.

- **Ro CCR-TERMINATION now carries `Cause-Code`** (TS 32.299 §7.2.35), so an OCS
  can tell why a call ended. It is taken from the same disconnect cause Rf's
  ACR-STOP already derives — the RFC 3326 `Reason` header, else the SIP status —
  so the two interfaces never disagree. A normal hangup reports `0`, a busy
  `-486`, a ring timeout `-408`; a siphon-initiated teardown reports `-402` when
  the OCS refused further credit (the same status a denied setup answers with)
  and `-408` when the max-session-lifetime backstop fired.

- **A proxied in-dialog request whose Request-URI addresses the proxy itself is
  now forwarded to the dialog's established peer instead of failing as a
  routing loop.** RFC 3261 §12.2.1.1 has the UAC build a mid-dialog request
  from the remote target (the peer's Contact) plus the route set, but a common
  class of UAC keeps the proxy's address in the R-URI — so after the proxy
  consumed its own Route (§16.4) the computed next hop was the proxy itself,
  and the request was answered `482 Loop Detected` (re-INVITE/UPDATE/BYE) or
  silently dropped (the end-to-end 2xx ACK, leaving the UAS retransmitting its
  200 until Timer H). On a hold/resume pair the resume re-INVITE was the
  visible casualty: the caller never got its 200 and the call hung. Both paths
  now fall back to the dialog session's established downstream branch when the
  resolved next hop is one of our own listeners, and only a session whose
  branch *also* points at us still draws the loop answer. A completed
  re-INVITE's per-transaction session teardown also no longer evicts the
  dialog-establishing INVITE's dialog-key entry (the removal twin of the
  insert-side first-writer-wins guard), so the *second* and later in-dialog
  requests of a call still find the dialog. The `--reinvite` SIPp mode now
  actually gates on this: the runner propagates the UAC's exit code, the UAC
  fails on the global timeout, and each re-INVITE's 200 is asserted by CSeq so
  a retransmitted initial-INVITE 200 can no longer mask a lost re-INVITE.

- **`security.trusted_cidrs` now covers the APIBAN blocklist.** The transport
  ACL consulted the fetched set directly, before the deny/allow lists and with
  no trusted check, and the kernel-firewall path had none either — so a trusted
  source that landed on the community feed was dropped anyway and no config
  could save it. Since the kernel drop is port-agnostic, a listed management
  address took ssh down with the trunk. Trusted addresses are now filtered as
  the feed is ingested, ahead of both the userspace store and the kernel set,
  which is what `docs/kernel-firewall.md` already claimed.

- **An LCR route's `headers` can no longer forge a dialog header.** Per-route
  `headers` from the routing answer were injected onto the B-leg INVITE
  verbatim, last (after both the header policy and the number policy) and with
  no guard on the name — so a backend naming `From` overwrote the header
  *including its dialog tag*. That failed silently: the INVITE went out fine and
  the breakage surfaced later as ACKs and BYEs that no longer matched the
  dialog. `To`, `Call-ID`, `CSeq`, `Via`, `Contact`, `Route`, `Record-Route`,
  `Max-Forwards` and `Content-Length` were exposed the same way. The injection
  now skips exactly the set no header policy may touch either, and logs at warn
  naming the carrier and the header. `Proxy-Authorization` stays injectable — a
  per-carrier trunk credential is a legitimate use of it. Use `number_policy` to
  reshape identity headers per carrier.

- **`request.auth_user` and `call.auth_user` are writable.** They hold the
  username exactly as it appeared in the `Authorization` / `Proxy-Authorization`
  header, since that is the string the digest response was computed over.
  Deployments where the authentication identity is not the subscriber identity —
  IMS (a private identity authenticating a public one), or any scheme carrying a
  validity prefix or tenant qualifier in the username — can now reduce it after
  verification, and everything keyed on the authenticated identity reads the new
  value: `registrar.enforce_auth_aor_match` and the CDR's `auth_user`. Without
  this, an unreduced credential never equalled the AoR userpart, so every such
  REGISTER was answered `403` and the only way to deploy was to turn the
  anti-hijack check off entirely. Assign it only on the success path: it asserts
  an identity already proven, it does not prove one.

- **A proxy-mode CDR now carries `auth_user`.** `cdr_session_from_invite` took
  the authenticated username and both of its callers passed `None`, so the
  `auth_user` field on a proxy CDR was always empty even when the script had
  authenticated the caller — while the documentation on
  `CdrSession::set_auth_user` claimed the proxy path supplied it at
  session-build time. It is now read off the request after the handler has run,
  so a script that authenticated the caller (or normalised the identity
  afterwards) is what reaches the record. The B2BUA path was already correct: it
  opens the CDR at INVITE time, before `@b2bua.on_invite` runs, and stamps the
  username on once the handler returns.

- **`auth_user` no longer raises `AttributeError` on a real node.** The SDK mock
  exposed `Request.auth_user` as a writable property while the binding had only
  a getter, so a script assigning it passed pytest and failed at runtime. Mock
  and runtime now agree, on `Call` as well as `Request`.

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

- **A re-INVITE or UPDATE on a `siphon-rtp`-anchored call replaced its media
  session instead of renegotiating it.** siphon has only ever had one verb for
  an SDP offer, and on rtpengine that is correct — a repeat `offer` on a live
  call-id *is* a re-offer, which is how `rtpengine_manage()` has always done
  hold and codec renegotiation. siphon-rtp draws the line differently: a repeat
  `offer` there is a **replacement**, so the engine freed the call and allocated
  fresh ports. The visible damage was not the ports (siphon answers with the
  rewritten SDP either way) but everything attached to them — the WebSocket
  bridge, any `ws_tee`, and any SIPREC subscription were torn down with the old
  call. So putting a voice-AI call on hold, or any mid-dialog renegotiation,
  silently killed the audio path to the AI while the call itself carried on,
  and left a spurious media CDR with reason `replaced` behind. A call this
  process has already anchored now renegotiates with `siphon-rtp-proto` 0.2.0's
  `reoffer`, which keeps the ports, the pipeline and the attachments, and
  carries an RFC 8445 §9 ICE restart when the peer offers new credentials.
  Covers the framework's re-INVITE and UPDATE paths and the script-facing
  `rtpengine.offer()`; rtpengine and rtpproxy still send a plain offer, so their
  wire is byte-identical to before.

- **A re-offer is addressed by the media session's own engine call-id.**
  `rtpengine.offer()` used the SIP Call-ID, but a siphon-terminated transfer
  deliberately re-anchors the surviving pair on a *fresh* engine call-id while
  the store key stays the SIP one — so a re-INVITE after a transfer addressed a
  call-id the engine had never heard of. It now uses `rtpengine_id()`, as every
  other post-offer verb already did, and no longer re-inserts the media session
  on a re-offer (which reset that id and cleared the `to_tag` the answer set).

- **The one case a re-offer cannot serve falls back explicitly.** The engine
  refuses a re-offer that changes the negotiated codec — that needs a pipeline
  rebuild it will not do on a live call — and its error says to replace the call
  instead. That refusal, and only that refusal, is retried as a replacement
  `offer`, which is exactly the behaviour such a re-INVITE had before. It is
  logged at WARN naming the consequence (ports re-allocated, bridge/tee/SIPREC
  dropped) rather than performed silently, and the match is deliberately narrow
  so no other engine error can acquire a call-replacing retry.

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
