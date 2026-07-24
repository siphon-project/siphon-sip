"""
Mock B2BUA Call object — mirrors ``PyCall`` from the Rust engine.

Passed to ``@b2bua.on_invite``, ``@b2bua.on_early_media``,
``@b2bua.on_answer``, ``@b2bua.on_failure``, and ``@b2bua.on_bye`` handlers.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Optional, Union

from siphon_sdk.types import Action, Contact, Flow, MediaHandle, SipUri
from siphon_sdk.request import _parse_uri, _validate_send_socket
from siphon_sdk.lcr import Route


def _validate_replaces(replaces: Optional[dict]) -> None:
    """Validate an attended-transfer ``replaces`` dict (RFC 3891).

    ``None`` (a blind transfer) is always valid.  A dict must carry
    ``call_id``, ``from_tag`` and ``to_tag`` (``early_only`` is optional).
    Raises :class:`ValueError` otherwise.
    """
    if replaces is None:
        return
    required = ("call_id", "from_tag", "to_tag")
    missing = [key for key in required if key not in replaces]
    if missing:
        raise ValueError(
            f"replaces dict must contain {', '.join(required)} "
            f"(missing: {', '.join(missing)})"
        )


class Call:
    """A B2BUA call with two legs (A-leg = caller, B-leg = callee).

    The call object is the primary interface for B2BUA scripts.  It tracks
    call state and provides methods to dial, fork, reject, and terminate.

    Example::

        @b2bua.on_invite
        def new_call(call):
            contacts = registrar.lookup(call.ruri)
            if not contacts:
                call.reject(404, "Not Found")
                return
            call.fork([c.uri for c in contacts], strategy="parallel")

        @b2bua.on_bye
        def call_ended(call, initiator):
            log.info(f"Call ended by {initiator.side}-leg")
            call.terminate()
    """

    def __init__(
        self,
        call_id: Optional[str] = None,
        from_uri: Union[str, SipUri, None] = "sip:alice@example.com",
        to_uri: Union[str, SipUri, None] = "sip:bob@example.com",
        ruri: Union[str, SipUri, None] = "sip:bob@example.com",
        source_ip: str = "127.0.0.1",
        state: str = "calling",
        body: Optional[bytes] = None,
        headers: Optional[dict[str, str]] = None,
        refer_to: Optional[str] = None,
        refer_replaces: Optional[dict] = None,
        transport: str = "udp",
        active_route: Optional[Route] = None,
    ) -> None:
        self._id = call_id or str(uuid.uuid4())
        self._from_uri = _parse_uri(from_uri)
        self._to_uri = _parse_uri(to_uri)
        self._ruri = _parse_uri(ruri)
        self._source_ip = source_ip
        self._state = state
        # Transport the A-leg arrived on.  Not a public property (the real
        # PyCall does not expose one either) — it exists so cdr.write(call)
        # produces a record carrying the A-leg transport, like the engine does.
        self._transport = transport
        self._body = body
        self._call_id = call_id or self._id
        self._headers: dict[str, str] = dict(headers) if headers else {}
        self._actions: list[Action] = []
        # Charging params stashed by ``set_charging_param`` for the Rf
        # B2BUA auto-emit path.  Tests can assert on them via the
        # ``charging_params`` property.
        self._charging_params: list[tuple[str, str]] = []
        self._media = MediaHandle()
        self._refer_to = refer_to
        self._refer_replaces = refer_replaces
        self._contact_user_override: Optional[str] = None
        self._contact_override: Optional[str] = None
        # LCR: the carrier that won the sequential failover. In the engine the
        # dispatcher sets this on the on_answer/on_bye Call; in tests pass
        # ``active_route=`` (or set ``call._active_route``) to simulate the winner.
        self._active_route = active_route
        # Ro reserve-before-connect gate: the result ``ro_authorize`` returns
        # (default a grant), and a record of each call for test assertions.
        self._ro_authorize_result: Optional[dict] = None
        self._ro_authorizations: list[dict] = []

    # -- Properties ------------------------------------------------------------

    @property
    def active_route(self) -> Optional[Route]:
        """The carrier :class:`~siphon_sdk.lcr.Route` that won an LCR sequence
        (``call.route(...)``), or ``None`` for a non-LCR call. Read in
        ``@b2bua.on_answer`` / ``on_bye`` to stamp the carrier onto a CDR."""
        return self._active_route

    @property
    def id(self) -> str:
        """Unique call identifier (UUID)."""
        return self._id

    @property
    def state(self) -> str:
        """Call state: ``"calling"``, ``"ringing"``, ``"answered"``, ``"terminated"``."""
        return self._state

    @property
    def source_ip(self) -> str:
        """Source IP address of the A-leg caller."""
        return self._source_ip

    def from_gateway(self, group_name: str) -> bool:
        """Check if the A-leg source IP is a member of a gateway group.

        The B2BUA equivalent of ``request.from_gateway`` — returns ``True``
        when the A-leg caller's source IP is one of the resolved addresses of
        the gateway group ``group_name`` (configured under ``gateway.groups``
        in ``siphon.yaml``, or via ``gateway.add_group``).  This is siphon's
        answer to Kamailio ``ds_is_from_list()`` / OpenSIPS ``ds_is_in_list()``
        — a routing-direction / trust predicate that replaces hardcoded source
        CIDRs.

        The match is on IP only (source port ignored) against **every**
        resolved address in the group, so a hostname that round-robins across
        many IPs matches on any of them.

        Infallible: returns ``False`` (never raises) when the group does not
        exist, no gateway is configured, or the source IP does not parse.

        Security: on connection-oriented transports (TCP/TLS/WS/WSS) the source
        IP is handshake-verified and trustworthy as an authorization signal; on
        UDP it is spoofable, so ``from_gateway`` there is a best-effort
        direction hint, not an auth gate.

        Args:
            group_name: Name of the gateway group to test membership against.

        Returns:
            ``True`` if the A-leg source IP belongs to the group.

        Example::

            @b2bua.on_invite
            def on_invite(call):
                if call.from_gateway("teams"):
                    # Inbound from Microsoft Teams — bridge to the PBX.
                    call.dial("sip:pbx.internal:5060")
                else:
                    call.reject(403, "Forbidden")
        """
        # Lazy import avoids a circular import (mock_module imports from the
        # request module, which this module also imports at load time).
        from siphon_sdk.mock_module import get_gateway

        return get_gateway().contains_source(group_name, self._source_ip)

    def source_ip_in(self, cidr_list: list[str]) -> bool:
        """Check if the A-leg source IP is within any of the given CIDR ranges.

        The B2BUA counterpart of :meth:`Request.source_ip_in`.  Use it to gate on
        a peer's published source subnets directly, when that peer sources SIP
        from a whole range rather than only the IPs its signalling FQDNs resolve
        to — the case :meth:`from_gateway` (which tracks the destinations' DNS)
        cannot cover.  Accepts IPv4 and IPv6 CIDRs.

        Args:
            cidr_list: List of CIDR strings (e.g. ``["203.0.113.0/24"]``).

        Returns:
            ``True`` if the A-leg source IP falls within any range; ``False`` if
            the source IP does not parse.

        Example::

            if call.source_ip_in(["203.0.113.0/24", "2001:db8::/32"]):
                ...
        """
        try:
            addr = ipaddress.ip_address(self._source_ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(cidr) for cidr in cidr_list)

    @property
    def from_uri(self) -> Optional[SipUri]:
        """From URI of the A-leg INVITE."""
        return self._from_uri

    @property
    def to_uri(self) -> Optional[SipUri]:
        """To URI of the A-leg INVITE."""
        return self._to_uri

    @property
    def ruri(self) -> Optional[SipUri]:
        """Request-URI of the A-leg INVITE."""
        return self._ruri

    @property
    def call_id(self) -> Optional[str]:
        """Call-ID header value."""
        return self._call_id

    @property
    def body(self) -> Optional[bytes]:
        """SDP body content, or ``None``."""
        return self._body

    @property
    def media(self) -> MediaHandle:
        """Handle for media anchoring operations.

        Example::

            call.media.anchor(engine="rtpengine", profile="wss_to_rtp")
            call.media.release()
        """
        return self._media

    @property
    def refer_to(self) -> Optional[str]:
        """Refer-To URI from an incoming REFER request.

        Available in ``@b2bua.on_refer`` handlers.  Returns the URI the
        remote party wants to transfer the call to, or ``None`` if no
        REFER is pending.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                log.info(f"Transfer to {call.refer_to}")
                call.accept_refer()
        """
        return self._refer_to

    @property
    def refer_replaces(self) -> Optional[dict]:
        """Parsed Replaces parameter from the Refer-To header.

        Returns a dict with **four** keys — ``call_id``, ``from_tag``,
        ``to_tag`` and ``early_only`` (a ``bool``) — if the REFER includes a
        Replaces header (attended transfer, RFC 3891), or ``None`` for a blind
        transfer.  ``early_only`` is ``True`` when the Replaces carried the
        ``early-only`` flag (match only a dialog still in the early state).

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                repl = call.refer_replaces
                if repl:
                    log.info(
                        f"Attended transfer, replaces {repl['call_id']} "
                        f"(early_only={repl['early_only']})"
                    )
        """
        return self._refer_replaces

    # -- Call control ----------------------------------------------------------

    async def ro_authorize(
        self,
        *,
        subscription_id: Optional[str] = None,
        subscription_id_type: Optional[str] = None,
    ) -> dict:
        """Reserve prepaid credit (Ro CCR-INITIAL) BEFORE dialing the B-leg — the
        reserve-before-connect gate. Await it in ``@b2bua.on_invite`` and branch:

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                decision = await call.ro_authorize()
                if not decision["authorized"]:
                    call.reject(402, "Payment Required")   # no B-leg dialed
                    return
                call.dial("sip:bob@carrier")               # credit reserved

        On a grant siphon opens the credit-control session, re-authorizes on the
        OCS cadence, disconnects mid-call on exhaustion, and sends
        CCR-TERMINATION on BYE. ``subscription_id`` overrides the charged
        identity (a ``sip:`` URI is typed as a SIP URI, never as an E.164
        number); when omitted it comes from the ``ro.charge`` config. Returns
        ``{"authorized": bool, "result_code": int|None, "granted_time": int|None,
        "session_id": str|None}``.

        Tests can force the outcome with :meth:`set_ro_authorize_result` and
        assert on :attr:`ro_authorizations`.
        """
        self._ro_authorizations.append({
            "subscription_id": subscription_id,
            "subscription_id_type": subscription_id_type,
        })
        if self._ro_authorize_result is not None:
            return dict(self._ro_authorize_result)
        return {
            "authorized": True,
            "result_code": 2001,
            "granted_time": 30,
            "session_id": f"mock-ro;{self._id}",
        }

    def set_ro_authorize_result(
        self,
        authorized: bool,
        *,
        result_code: Optional[int] = None,
        granted_time: Optional[int] = None,
        session_id: Optional[str] = None,
    ) -> None:
        """Test hook — pin what the next :meth:`ro_authorize` returns (e.g. a
        4012 denial so a script's ``call.reject(402)`` branch is exercised)."""
        self._ro_authorize_result = {
            "authorized": authorized,
            "result_code": result_code,
            "granted_time": granted_time,
            "session_id": session_id,
        }

    @property
    def ro_authorizations(self) -> list[dict]:
        """Every ``ro_authorize`` call made on this call (for test assertions)."""
        return self._ro_authorizations

    def reject(self, code: int, reason: str) -> None:
        """Reject the call with an error response.

        Args:
            code: SIP status code (e.g. 404, 486, 503).
            reason: Reason phrase.

        Example::

            call.reject(486, "Busy Here")
        """
        self._state = "terminated"
        self._actions.append(Action(kind="reject", status_code=code, reason=reason))

    def answer(self, code: int, reason: str,
               body: Union[str, bytes, None] = None,
               content_type: str | None = None) -> None:
        """UAS-mode answer — send a final 2xx response to the inbound INVITE
        **immediately**, without bridging to a B-leg.

        The response goes on the wire the moment this is called (not deferred to
        when the handler returns), so an ``async`` handler can answer and then
        keep working — e.g. play a prompt to completion before starting echo —
        without delaying the 200 OK. Synchronous; no ``await`` needed.

        Args:
            code: Final 2xx status code (200, 202, etc.).
            reason: Reason phrase.
            body: Optional response body (``bytes`` or ``str``) — typically SDP.
            content_type: Content-Type for the body (e.g. ``"application/sdp"``).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                await rtpengine.offer(call, profile="ivr")
                call.answer(200, "OK", body=call.body, content_type="application/sdp")
                await rtpengine.play_media(call, file=prompt)   # 200 already sent
                await rtpengine.echo(call)
        """
        if not 200 <= code < 300:
            raise ValueError(
                f"call.answer() requires a 2xx status code; "
                f"use call.reject() for failures (got {code})"
            )
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._state = "answered"
        self._actions.append(Action(
            kind="answer",
            status_code=code,
            reason=reason,
            extras={"body": body, "content_type": content_type},
        ))

    def progress(self, code: int, reason: str = "Ringing",
                 body: Union[str, bytes, None] = None,
                 content_type: str | None = None) -> None:
        """UAS-mode provisional — send a 1xx response to the inbound INVITE
        **immediately** (e.g. ``183 Session Progress`` with early-media SDP, or
        ``180 Ringing``). Does not answer the call: the handler must still
        ``answer()`` / ``dial()`` / ``reject()`` for a final response.

        Args:
            code: Provisional status code (must be 1xx; 100 carries no To-tag).
            reason: Reason phrase.
            body: Optional response body (``bytes`` or ``str``) — early-media SDP.
            content_type: Content-Type for the body (e.g. ``"application/sdp"``).

        Example::

            call.progress(183, "Session Progress", body=sdp, content_type="application/sdp")
        """
        if not 100 <= code < 200:
            raise ValueError(
                f"call.progress() requires a 1xx status code (got {code}); "
                f"use call.answer() for the final response"
            )
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._actions.append(Action(
            kind="progress",
            status_code=code,
            reason=reason,
            extras={"body": body, "content_type": content_type},
        ))

    def dial(
        self,
        uri: str,
        timeout: int = 30,
        next_hop: Optional[str] = None,
        flow: Optional["Flow"] = None,
        header_policy: Optional[str] = None,
        copy: Optional[list[str]] = None,
        strip: Optional[list[str]] = None,
        translate: Optional[list[tuple[str, str]]] = None,
        route: Optional[list[str]] = None,
        send_socket: Optional[str] = None,
        auth_passthrough: bool = False,
        number_policy: Optional[str] = None,
    ) -> None:
        """Dial a single B-leg target.

        Args:
            uri: Destination SIP URI — drives the B-leg R-URI.
            timeout: INVITE timeout in seconds.
            next_hop: Optional routing destination.  When set, the new
                INVITE's R-URI is still built from ``uri`` (so the called
                party / IMPU shape is preserved), but the message is sent
                to ``next_hop``.  Mirrors ``proxy.send_request(next_hop=...)``.
            flow: Captured inbound :class:`Flow` (typically ``contact.flow``
                from ``registrar.lookup()``).  When set, the B-leg INVITE is
                sent over that connection — RFC 5626 §5.3 connection reuse,
                mandatory for a WebSocket callee (RFC 7118 §5) whose Contact
                URI is unresolvable.  Bypasses DNS resolution of
                ``uri``/``next_hop``; guard on ``contact.is_local`` first.
            header_policy: Qualified preset name selecting which header
                policy the framework applies when building the B-leg
                INVITE and forwarding responses back to the A-leg.
                Defaults to ``b2bua.default_header_policy`` from
                ``siphon.yaml`` (which itself defaults to
                ``"transparent-b2bua@2026"``).  Built-in presets:
                ``"transparent-b2bua@2026"`` (today's behaviour),
                ``"ims-intra-trust-domain@2026"`` (intra-trust IMS,
                passes P-* and end-to-end PRACK / preconditions),
                ``"ims-trust-domain-boundary@2026"`` (BGCF/IBCF/P-CSCF
                edge, strict trust-boundary hygiene),
                ``"sip-trunk-edge@2026"`` (plain SIP trunk).
            copy: Per-call delta — headers to copy verbatim regardless of
                the preset's default verb (e.g. ``["X-Operator-Tag"]``).
            strip: Per-call delta — headers to strip regardless of the
                preset's default verb (e.g. ``["History-Info"]``).
            translate: Per-call delta — ``[(header_name, op_name), …]``
                pairs.  ``op_name`` is one of: ``"rfc7044"`` /
                ``"diversion-to-history-info"`` (translate ``Diversion``
                per RFC 7044).  Unknown ops are logged and dropped.
            route: Route header set prepended to the B-leg INVITE *after* the
                A-leg Route/Record-Route are stripped.  Carries the captured
                IMS Service-Route on MO calls so the request traverses the
                originating S-CSCF (RFC 3608).  Each entry is a full route
                value, e.g. ``"<sip:scscf.ims.example.com:6060;lr>"`` — pass
                the list returned by ``registration.service_route(impu)``.
            send_socket: Optional egress socket pin
                (``"<transport>:<ip>:<port>"``, e.g. ``"udp:10.0.0.1:5060"``)
                — the operator equivalent of Kamailio's ``force_send_socket()``.
                Selects which of siphon's own configured listeners the B-leg
                INVITE leaves from on a multi-homed host; the B-leg Via
                advertises that listener's address.  UDP pins the exact
                ``(ip, port)`` listener; TCP/TLS bind the source IP with an
                ephemeral port.  Ignored when ``flow`` is set (the flow already
                pins egress), and when its transport doesn't match the B-leg
                transport.  A malformed spec raises ``ValueError``.
            auth_passthrough: Relay B-leg authentication to the caller
                end-to-end instead of siphon answering it (RFC 3261 §22.3).
                When ``True``, siphon copies ``Proxy-Authenticate`` (B→A) and
                ``Proxy-Authorization`` (A→B) across the B2BUA, and treats a
                B-leg ``401``/``407`` (with no ``set_credentials()`` on this
                call) as a *non-terminal* challenge: it forwards the challenge
                to the caller without firing ``@b2bua.on_failure``, writing a
                failure CDR, or tearing down the anchored media — so the caller
                (which holds the credentials) can authenticate and re-INVITE.
                Use this when the endpoint, not siphon, owns the credentials
                (e.g. an extension authenticating to its own PBX through the
                B2BUA).  Mutually exclusive with ``set_credentials()``; if both
                are set, the stored credentials win.
            number_policy: Named E.164 number policy (from ``number_policies:``)
                applied as the final normalization step: reformats the A-leg
                identity headers that flow to the B-leg plus this dial target.
                Defaults to ``b2bua.default_number_policy`` from ``siphon.yaml``
                when unset (no normalization if that is also unset).  Use
                :meth:`rewrite_identities` for imperative per-identity control.

        Example::

            # Basic dial (uses configured default policy)
            call.dial("sip:bob@10.0.0.2:5060", timeout=30)

            # Device-driven proxy auth: let the extension authenticate to the
            # PBX itself; siphon just relays the challenge and credentials.
            call.dial("sip:bob@pbx.example.com:5060", auth_passthrough=True)

            # IMS edge: stamp canonical IMPU on R-URI, route via I-CSCF,
            # apply the trust-domain-boundary preset for outbound hygiene.
            call.dial(
                "sip:1000@ims.mnc001.mcc001.3gppnetwork.org",
                next_hop="sip:192.0.2.111:4060",
                header_policy="ims-trust-domain-boundary@2026",
                copy=["X-Operator-Tag"],
                strip=["History-Info"],
            )

            # Emergency call — keep PAI / Reason / Geolocation through a
            # trunk edge that would otherwise strip them.
            call.dial(
                "sip:911@psap.example.com",
                header_policy="sip-trunk-edge@2026",
                copy=["Geolocation", "Geolocation-Routing",
                      "P-Asserted-Identity", "Reason"],
            )
        """
        _validate_send_socket(send_socket)
        uri = self._normalize_dial_targets([uri], number_policy)[0]
        self._actions.append(Action(
            kind="dial",
            targets=[uri],
            timeout=timeout,
            next_hop=next_hop,
            extras={
                "flow": flow,
                "header_policy": header_policy,
                "copy": copy or [],
                "strip": strip or [],
                "translate": translate or [],
                "route": route or [],
                "send_socket": send_socket,
                "auth_passthrough": auth_passthrough,
            },
        ))

    def fork(
        self,
        targets: list[Union[str, Contact]],
        strategy: str = "parallel",
        timeout: int = 30,
        header_policy: Optional[str] = None,
        copy: Optional[list[str]] = None,
        strip: Optional[list[str]] = None,
        translate: Optional[list[tuple[str, str]]] = None,
        send_socket: Optional[str] = None,
        auth_passthrough: bool = False,
        number_policy: Optional[str] = None,
    ) -> None:
        """Fork to multiple B-leg targets.

        Args:
            targets: List of URI strings or :class:`Contact` objects.  Pass
                ``Contact`` objects (not just ``.uri``) so a binding this
                process accepted (``contact.is_local``) routes its branch over
                the captured inbound flow — RFC 5626 §5.3 connection reuse,
                mandatory for a WebSocket callee (RFC 7118 §5).  Non-local
                contacts fall back to URI routing.
            strategy: ``"parallel"`` (ring all, first answer wins) or
                      ``"sequential"`` (try in order).
            timeout: Per-branch INVITE timeout in seconds.
            header_policy: Header-policy preset applied to every branch of the
                fork — same semantics as :meth:`dial` (per-branch policy is a
                follow-up).
            copy: Per-call header copy deltas — same semantics as :meth:`dial`.
            strip: Per-call header strip deltas — same semantics as :meth:`dial`.
            translate: Per-call header translation deltas — same semantics as
                :meth:`dial`.
            send_socket: Optional egress socket pin applied to every branch
                (same ``"<transport>:<ip>:<port>"`` form as :meth:`dial`).  A
                per-branch captured flow still takes precedence for that branch.
            auth_passthrough: Relay B-leg authentication to the caller
                end-to-end — same semantics as :meth:`dial`.  Applies to every
                branch of the fork.
            number_policy: Named E.164 number policy applied to every branch
                target plus the A-leg identity headers — same semantics as
                :meth:`dial`.

        Example::

            contacts = registrar.lookup(call.ruri)
            # Pass Contact objects so WebSocket callees route over their flow.
            call.fork(contacts, strategy="parallel", timeout=30)
        """
        _validate_send_socket(send_socket)
        uris = [t.uri if isinstance(t, Contact) else str(t) for t in targets]
        uris = self._normalize_dial_targets(uris, number_policy)
        self._actions.append(Action(
            kind="fork",
            targets=uris,
            strategy=strategy,
            timeout=timeout,
            extras={
                "header_policy": header_policy,
                "copy": copy or [],
                "strip": strip or [],
                "translate": translate or [],
                "send_socket": send_socket,
                "auth_passthrough": auth_passthrough,
            },
        ))

    def route(
        self,
        routes: list["Route"],
        timeout: int = 30,
        send_socket: Optional[str] = None,
    ) -> None:
        """Route the call across an ordered list of carrier :class:`~siphon_sdk.lcr.Route`
        objects with **sequential failover** — B2BUA-only LCR execution.

        The carriers (from ``await lcr.route(call)``, optionally filtered /
        reordered) are tried cheapest-first: dial the first routable carrier
        (a ``gateway_group`` resolved to a healthy member, else ``next_hop`` /
        ``ruri``, with any ``tech_prefix`` prepended and ``headers`` injected),
        and on a reroute cause advance to the next — each attempt a fresh B-leg
        dialog. On answer, :attr:`active_route` is the carrier that won.

        Args:
            routes: Ordered carriers (cheapest first).
            timeout: Default ring timeout (seconds) for a route without its own
                ``timeout_secs``.
            send_socket: Optional egress socket pin applied to every attempt.

        Example::

            @b2bua.on_invite
            async def route(call):
                decision = await lcr.route(call)
                if decision and decision.routes:
                    call.route(decision.routes)
        """
        _validate_send_socket(send_socket)
        self._actions.append(Action(
            kind="route",
            targets=[route.carrier_id for route in routes],
            timeout=timeout,
            extras={"routes": list(routes), "send_socket": send_socket},
        ))

    def terminate(self) -> None:
        """Terminate the call (send BYE to both legs).

        Example::

            @b2bua.on_bye
            def call_ended(call, initiator):
                call.terminate()
        """
        self._state = "terminated"
        self._actions.append(Action(kind="terminate"))

    def accept_refer(self, target: Optional[str] = None,
                     next_hop: Optional[str] = None,
                     mode: Optional[str] = None) -> None:
        """Accept an incoming REFER and honour the transfer.

        Call this from a ``@b2bua.on_refer`` handler to proceed with the
        transfer the remote party asked for.

        Args:
            target: Optionally rewrite the transfer destination before
                honouring it.  Defaults to :attr:`refer_to` (the URI carried
                in the incoming Refer-To header).
            next_hop: Optionally steer egress to a specific next-hop, exactly
                like ``dial(next_hop=...)`` — the R-URI is still built from
                ``target`` (so the referred-to identity is preserved on the
                wire) but the message is sent to ``next_hop``.
            mode: How siphon honours the REFER:

                - ``"terminate"`` — siphon **terminates** the transfer: it
                  answers ``202 Accepted`` locally, re-resolves ``target``
                  (the Refer-To) through the dial plan as a brand-new leg,
                  re-bridges the surviving leg to it, and sends BYE to the
                  referred-away leg.  The transferor drops out; siphon owns
                  both new legs.  The transferee never sees the REFER.
                - ``"transparent"`` — siphon **re-emits** the REFER on the far
                  leg and relays the far leg's ``202 Accepted`` plus the
                  sipfrag ``NOTIFY`` progress reports back to the transferor,
                  staying out of the transfer decision.
                - ``None`` (default) — use the configured
                  ``b2bua.default_refer_mode`` from ``siphon.yaml`` (which
                  itself defaults to ``"terminate"``).

        Raises:
            ValueError: if ``mode`` is not one of ``None``, ``"terminate"``,
                or ``"transparent"``.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                # Blind transfer — let siphon terminate + re-bridge (default).
                call.accept_refer()

            @b2bua.on_refer
            def handle_refer(call):
                # Steer the referred-to leg out a specific trunk, transparently.
                call.accept_refer(next_hop="sip:trunk.example.com:5060",
                                  mode="transparent")
        """
        if mode not in (None, "terminate", "transparent"):
            raise ValueError(
                f"accept_refer(mode=...) must be None, 'terminate', or "
                f"'transparent' (got {mode!r})"
            )
        self._actions.append(Action(
            kind="accept_refer",
            targets=[target] if target else None,
            next_hop=next_hop,
            extras={"mode": mode},
        ))

    def reject_refer(self, code: int, reason: str) -> None:
        """Reject an incoming REFER.

        Args:
            code: SIP status code (e.g. 403, 603).
            reason: Reason phrase.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                call.reject_refer(403, "Forbidden")
        """
        self._actions.append(Action(kind="reject_refer", status_code=code, reason=reason))

    def refer(self, target: str, replaces: Optional[dict] = None) -> None:
        """Originate an outbound REFER — siphon is the *referrer*.

        Use this when siphon itself drives the transfer, e.g. a UAS/IVR
        offload that answers the call, plays a menu, then transfers the caller
        onward.  This is the mirror of :meth:`accept_refer` (which honours a
        REFER siphon *received*).

        Args:
            target: The Refer-To URI — where the remote party should be
                transferred to.
            replaces: For an **attended** transfer, a dict identifying the
                dialog to replace (RFC 3891) with keys ``call_id``,
                ``from_tag`` and ``to_tag`` (and an optional ``early_only``
                bool).  Omit / ``None`` for a **blind** transfer.

        Raises:
            ValueError: if ``replaces`` is given but is missing any of
                ``call_id`` / ``from_tag`` / ``to_tag``.

        Note:
            This is a **deferred** call action — it is honoured after the
            handler returns, so it works from a call-scoped handler like
            ``@b2bua.on_answer``.  From an out-of-band event callback
            (``@rtpengine.on_dtmf``, a timer) where no ``call`` is in scope and
            deferred actions are no-ops, use the imperative
            :func:`b2bua.refer` (keyed by Call-ID) instead.

        Example::

            @b2bua.on_answer
            def on_answer(call, reply):
                # Blind transfer the freshly answered call onward.
                call.refer("sip:+15550142@example.com")

            @b2bua.on_answer
            def attended(call, reply):
                call.refer(
                    "sip:+15550142@example.com",
                    replaces={"call_id": "held-dialog@example.com",
                              "from_tag": "ft-held",
                              "to_tag": "tt-held"},
                )
        """
        _validate_replaces(replaces)
        self._actions.append(Action(
            kind="refer",
            targets=[target],
            next_hop=None,
            extras={"replaces": replaces},
        ))

    def session_timer(self, expires: int, min_se: int = 90,
                      refresher: str = "uac") -> None:
        """Configure session timer (RFC 4028) for this call.

        Args:
            expires: Session-Expires value in seconds.
            min_se: Min-SE value in seconds (default 90).
            refresher: Who refreshes: ``"uac"`` or ``"uas"`` (default ``"uac"``).

        Example::

            @b2bua.on_invite
            def new_call(call):
                call.session_timer(1800, min_se=90, refresher="uac")
                call.dial("sip:bob@example.com")
        """
        self._actions.append(Action(
            kind="session_timer",
            extras={"expires": expires, "min_se": min_se, "refresher": refresher},
        ))

    def keep_call_id(self) -> None:
        """Copy the A-leg Call-ID to the B-leg instead of generating a new one.

        By default the B2BUA generates a fresh Call-ID for each B-leg to fully
        decouple the two SIP dialogs (proper topology hiding).  Call this
        method if you need the trunk to see the same Call-ID as the
        originating side.

        Note: the From-tag is **always** regenerated regardless — it must be
        unique per leg.

        Example::

            @b2bua.on_invite
            def on_invite(call):
                call.keep_call_id()  # trunk sees same Call-ID
                call.dial("sip:trunk@carrier.example.com")
        """
        self._actions.append(Action(kind="keep_call_id"))

    def set_credentials(self, username: str, password: str) -> None:
        """Set outbound credentials for B-leg digest authentication.

        When the B-leg returns 401/407, SIPhon automatically retries the
        INVITE with these credentials instead of firing ``on_failure``.

        Args:
            username: Digest username.
            password: Digest password.

        Example::

            @b2bua.on_invite
            def on_invite(call):
                call.set_credentials("trunk_user", "s3cret")
                call.dial("sip:gw@carrier.example.com")
        """
        self._actions.append(Action(
            kind="set_credentials",
            extras={"username": username, "password": password},
        ))

    def set_ruri_user(self, value: str) -> None:
        """Set the user part of the Request-URI.

        Args:
            value: New user part (e.g. ``"+33123456789"``).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                call.set_ruri_user("+33123456789")
                call.dial("sip:gw@carrier.example.com")
        """
        if self._ruri is not None:
            self._ruri.user = value

    def set_from_user(self, value: str) -> None:
        """Set the user part of the From header URI.

        Preserves display name and tag parameter while replacing the user part.

        Args:
            value: New user part (e.g. ``"+33123456789"``).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                call.set_from_user("+33123456789")
                call.dial("sip:gw@carrier.example.com")
        """
        if self._from_uri is not None:
            self._from_uri.user = value

    def set_to_user(self, value: str) -> None:
        """Set the user part of the To header URI.

        Mirrors :meth:`set_from_user` / :meth:`set_ruri_user` for the To
        header.  Useful at IMS edges (BGCF inbound) where the B-leg R-URI
        is rewritten from a public E.164 to a short-code IMPU and
        downstream nodes expect To to match.

        Preserves scheme/host/port and any existing To-tag — only the
        userpart changes.  Must be called before :meth:`dial` for the
        change to take effect on the B-leg INVITE.

        Args:
            value: New user part (e.g. ``"1000"``).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                call.set_ruri_user("1000")
                call.set_to_user("1000")
                call.dial("sip:1000@ims.mnc001.mcc001.3gppnetwork.org")
        """
        if self._to_uri is not None:
            self._to_uri.user = value

    def rewrite_identities(
        self,
        policy: Optional[str] = None,
        format: Optional[str] = None,
        headers: Optional[list[str]] = None,
        home: Optional[str] = None,
    ) -> int:
        """Rewrite dialable identity userparts into a target E.164 shape.

        Walks From, To, P-Asserted-Identity, P-Preferred-Identity (and any
        opted-in header) on the A-leg INVITE, which flows to the B-leg. Pass
        **either** a named ``policy`` from ``number_policies:`` **or** an inline
        ``format`` (``"e164"`` | ``"plain"`` | ``"international"`` |
        ``"national"``) with an optional ``headers`` list and ``home``
        country-code override. Returns the number of headers changed. Must be
        called before :meth:`dial`.

        Example::

            call.rewrite_identities("ims-e164@2026")
            call.rewrite_identities(format="e164")
        """
        from siphon_sdk import mock_module

        resolved = mock_module.get_numbers()._resolve(policy, format, headers, home)
        return self._apply_number_policy(resolved, include_request_uri=True)

    def _apply_number_policy(self, resolved, include_request_uri: bool) -> int:
        from siphon_sdk.numbers import rewrite_nameaddr_userpart

        changed = 0
        for header in resolved.headers:
            target = resolved.format_for(header)
            if header == "request-uri":
                uri = self._ruri
                if include_request_uri and uri is not None and getattr(uri, "user", None):
                    new = resolved.reformat_user(uri.user, target)
                    if new is not None:
                        uri.user = new
                        changed += 1
            elif header in ("From", "To"):
                uri = self._from_uri if header == "From" else self._to_uri
                if uri is not None and getattr(uri, "user", None):
                    new = resolved.reformat_user(uri.user, target)
                    if new is not None:
                        uri.user = new
                        changed += 1
            else:
                raw = self._headers.get(header)
                if raw:
                    new_value = rewrite_nameaddr_userpart(
                        raw, lambda user: resolved.reformat_user(user, target)
                    )
                    if new_value != raw:
                        self._headers[header] = new_value
                        changed += 1
        return changed

    def _normalize_dial_targets(self, targets: list, number_policy: Optional[str]) -> list:
        """Apply a B2BUA dial/fork number policy: normalize the A-leg header
        identities plus each branch target. Returns the (possibly rewritten)
        targets."""
        from siphon_sdk import mock_module
        from siphon_sdk.numbers import rewrite_nameaddr_userpart

        resolved = mock_module.get_numbers()._resolve_dial(number_policy)
        if resolved is None:
            return targets
        self._apply_number_policy(resolved, include_request_uri=False)
        target_format = resolved.format_for("request-uri")
        return [
            rewrite_nameaddr_userpart(
                target, lambda user: resolved.reformat_user(user, target_format)
            )
            if isinstance(target, str)
            else target
            for target in targets
        ]

    def set_from_host(self, value: str) -> None:
        """Pin the host part of the B-leg From header URI.

        By default the B2BUA rewrites the From URI host to its own advertised
        address (topology hiding — masking the A-leg identity).  At a
        multitenant edge the downstream selects the tenant from the From
        domain: a domainless call lands in an unauthenticated/default routing
        context, so the tenant domain must survive.  ``set_from_host()`` opts
        this leg out of the From host-rewrite and pins the host to ``value``.

        Only the host changes; scheme/user/port/params and the From-tag are
        preserved.  ``value`` is a bare host (no port).  Must be called before
        :meth:`dial` for the change to take effect on the B-leg INVITE — same
        model as :meth:`set_from_user`.

        Args:
            value: New host (e.g. ``"tenant.example.com"``).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                call.set_from_host("tenant.example.com")
                call.dial(str(call.ruri), next_hop="sip:pbx.example.com:5060")
        """
        if self._from_uri is not None:
            self._from_uri.host = value

    def set_to_host(self, value: str) -> None:
        """Pin the host part of the B-leg To header URI.

        By default the B2BUA rewrites the To URI host to the dial-target host.
        ``set_to_host()`` pins it to ``value`` instead, so the To domain does
        what the script says regardless of the routing next-hop (declarative
        replacement for the raw ``set_header("To", "<sip:user@host>")`` idiom).

        Only the host changes; scheme/user/port/params and any To-tag are
        preserved.  ``value`` is a bare host (no port).  Must be called before
        :meth:`dial` — same model as :meth:`set_to_user`.

        Args:
            value: New host (e.g. ``"trunk.example.com"``).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                call.set_to_user(callee)
                call.set_to_host(TRUNK_DOMAIN)
                call.dial(str(call.ruri))
        """
        if self._to_uri is not None:
            self._to_uri.host = value

    def set_from_uri(self, value: str) -> None:
        """Replace the entire From header URI on the B-leg INVITE.

        The whole-URI form of :meth:`set_from_user` / :meth:`set_from_host` —
        rewrites scheme, user, host, port and URI params in one call while
        preserving the display name and From-tag. The host is also pinned (the
        B-leg builder would otherwise rewrite it to the advertised address for
        topology hiding — same opt-out as :meth:`set_from_host`). Must be called
        before :meth:`dial`.

        Args:
            value: New From URI, e.g.
                ``"sip:+31123@tenant.example.com:5060;transport=tcp"``.

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                call.set_from_uri("sip:1001@tenant.example.com:5060")
                call.dial("sip:gw@carrier.example.com")
        """
        self._from_uri = _parse_uri(value)

    def set_to_uri(self, value: str) -> None:
        """Replace the entire To header URI on the B-leg INVITE.

        The whole-URI form of :meth:`set_to_user` / :meth:`set_to_host`,
        preserving the display name and any To-tag. The host is also pinned
        (same opt-out as :meth:`set_to_host`). Must be called before
        :meth:`dial`.

        Args:
            value: New To URI, e.g.
                ``"sip:1000@ims.mnc001.mcc001.3gppnetwork.org"``.
        """
        self._to_uri = _parse_uri(value)

    def set_contact_user(self, value: str) -> None:
        """Inject a userpart into the B-leg Contact URI, keeping siphon's
        advertised host:port.

        The B2BUA advertises its own address as the Contact so in-dialog
        requests (BYE, re-INVITE) route back through siphon; by default that
        Contact is userless (RFC 3261 §8.1.1.8 puts no identity in the Contact
        userpart). ``set_contact_user()`` adds a userpart while leaving the
        host:port untouched, so in-dialog routing still works and the userpart
        rides along — e.g. a downstream that keys a tenant/extension off the
        Contact userpart, the way it does for a REGISTER Contact.

        Pass an empty string to force a userless Contact. Must be called before
        :meth:`dial`.

        Args:
            value: Contact userpart (e.g. the extension).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                call.set_contact_user(call.from_uri.user)
                call.dial("sip:gw@carrier.example.com")
        """
        self._contact_user_override = value

    def set_contact_uri(self, value: str) -> None:
        """Replace the entire B-leg Contact URI — a full override of siphon's
        advertised Contact.

        Power tool for edge deployments that front siphon (GRUU, edge SBC).
        Overriding the host/port moves the in-dialog anchor off siphon, so the
        deployment must route the far side's in-dialog requests back to siphon
        or the dialog breaks. Takes precedence over :meth:`set_contact_user`.
        ``value`` is a bare URI (no angle brackets). Must be called before
        :meth:`dial`.

        Args:
            value: Full Contact URI, e.g. ``"sip:gruu-token@edge.example.com:5060"``.
        """
        self._contact_override = value

    # -- Header access ---------------------------------------------------------

    def get_header(self, name: str) -> Optional[str]:
        """Get the first value of a header (case-insensitive)."""
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def header(self, name: str) -> Optional[str]:
        """Alias for :meth:`get_header`."""
        return self.get_header(name)

    def set_header(self, name: str, value: str) -> None:
        """Set (replace) a header value."""
        self._headers[name] = value

    def set_charging_param(self, name: str, value: str) -> None:
        """Stash a charging-param for the Rf B2BUA auto-emit hook.

        Mirrors :py:meth:`siphon_sdk.request.Request.set_charging_param`
        for B2BUA scripts that get a ``Call`` object.  Recognised names
        map to TS 32.299 IMS-Information AVPs; unknown names are still
        captured so future siphon versions can recognise more without
        breaking deployed scripts.

        Example (BGCF as B2BUA)::

            @b2bua.on_invite
            async def on_invite(call):
                gw = gateway.select("connect")
                call.set_charging_param(
                    "outgoing-trunk-group-id", gw.attrs["group"],
                )
                call.dial(gw.uri)
        """
        self._charging_params.append((name, value))

    @property
    def charging_params(self) -> list[tuple[str, str]]:
        """List of `(name, value)` tuples stashed via
        :meth:`set_charging_param`.  Test helper."""
        return list(self._charging_params)

    def remove_header(self, name: str) -> None:
        """Remove a header entirely."""
        self._headers = {
            k: v for k, v in self._headers.items()
            if k.lower() != name.lower()
        }

    def has_header(self, name: str) -> bool:
        """Check if a header exists."""
        return any(k.lower() == name.lower() for k in self._headers)

    def remove_headers_matching(self, prefix: str) -> None:
        """Remove all headers whose name starts with a prefix.

        Args:
            prefix: Prefix string (e.g. ``"X-"`` removes all custom headers).

        Example::

            call.remove_headers_matching("X-")
        """
        self._headers = {
            k: v for k, v in self._headers.items()
            if not k.startswith(prefix)
        }

    # -- Test helpers ----------------------------------------------------------

    @property
    def actions(self) -> list[Action]:
        """All actions recorded (test-only)."""
        return self._actions

    @property
    def last_action(self) -> Optional[Action]:
        """Most recent action, or ``None``."""
        return self._actions[-1] if self._actions else None
