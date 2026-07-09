"""
Mock SIP Request object — mirrors ``PyRequest`` from the Rust engine.

This is the primary object passed to ``@proxy.on_request`` handlers.
Every property and method is documented with types for LLM consumption.
"""

from __future__ import annotations

import ipaddress
import uuid
from typing import Callable, Optional, Union

from siphon_sdk.types import Action, Contact, SipUri

_SEND_SOCKET_TRANSPORTS = {"udp", "tcp", "tls", "ws", "wss", "sctp"}


def _validate_send_socket(spec: Optional[str]) -> None:
    """Format-validate a ``send_socket=`` spec, mirroring the Rust engine.

    Raises ``ValueError`` on a malformed spec (the real engine rejects it the
    same way).  Existence as a real configured listener is a runtime concern,
    not checked here.
    """
    if spec is None:
        return
    scheme, sep, addr = spec.partition(":")
    if not sep or scheme.lower() not in _SEND_SOCKET_TRANSPORTS:
        raise ValueError(
            f"send_socket {spec!r} must be '<transport>:<ip>:<port>' "
            f"(e.g. 'udp:10.0.0.1:5060'); transport one of "
            f"{sorted(_SEND_SOCKET_TRANSPORTS)}"
        )
    host, colon, port = addr.rpartition(":")
    if not colon or not host:
        raise ValueError(
            f"send_socket {spec!r}: missing '<ip>:<port>' after the transport"
        )
    try:
        int(port)
    except ValueError:
        raise ValueError(f"send_socket {spec!r}: port {port!r} is not an integer") from None
    # Validate the IP literal (strip IPv6 brackets).
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        raise ValueError(f"send_socket {spec!r}: {host!r} is not a valid IP address") from None


def _parse_uri(value: Union[str, SipUri, None]) -> Optional[SipUri]:
    """Parse a string into a SipUri, or pass through if already one."""
    if value is None:
        return None
    if isinstance(value, SipUri):
        return value
    # Minimal parser: sip:user@host:port or sip:host:port
    s = str(value)
    scheme = "sip"
    if s.startswith("sips:"):
        scheme = "sips"
        s = s[5:]
    elif s.startswith("sip:"):
        s = s[4:]
    elif s.startswith("tel:"):
        return SipUri(scheme="tel", user=s[4:], host="")
    user = None
    if "@" in s:
        user, s = s.split("@", 1)
    port = None
    if ":" in s:
        host, port_str = s.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            host = s
    else:
        host = s
    return SipUri(scheme=scheme, user=user, host=host, port=port)


class Request:
    """A SIP request message.

    This object is passed to ``@proxy.on_request`` handlers.  It provides
    read-only access to parsed SIP headers and methods to reply, relay,
    fork, and manipulate the message before forwarding.

    In the real SIPhon engine this is backed by a Rust ``PyRequest`` with
    an ``Arc<Mutex<SipMessage>>`` inside.  The mock version stores
    everything in plain Python attributes.

    Example::

        @proxy.on_request
        def route(request):
            if request.method == "REGISTER":
                request.reply(200, "OK")
                return
            request.relay()
    """

    def __init__(
        self,
        method: str = "INVITE",
        ruri: Union[str, SipUri] = "sip:bob@example.com",
        from_uri: Union[str, SipUri, None] = "sip:alice@example.com",
        to_uri: Union[str, SipUri, None] = "sip:bob@example.com",
        from_tag: Optional[str] = None,
        to_tag: Optional[str] = None,
        call_id: Optional[str] = None,
        cseq: Optional[tuple[int, str]] = None,
        max_forwards: int = 70,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        transport: str = "udp",
        source_ip: str = "127.0.0.1",
        source_port: int = 5060,
        user_agent: Optional[str] = None,
        auth_user: Optional[str] = None,
        contact_expires: Optional[int] = None,
        event: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self._method = method
        self._ruri = _parse_uri(ruri) or SipUri()
        self._from_uri = _parse_uri(from_uri)
        self._to_uri = _parse_uri(to_uri)
        self._from_tag = from_tag or uuid.uuid4().hex[:8]
        self._to_tag = to_tag
        self._call_id = call_id or f"{uuid.uuid4().hex[:16]}@{source_ip}"
        self._cseq = cseq or (1, method)
        self._max_forwards = max_forwards
        self._body = body
        self._content_type = content_type
        self._transport = transport
        self._source_ip = source_ip
        self._source_port = source_port
        self._user_agent = user_agent
        self._auth_user = auth_user
        self._contact_expires = contact_expires
        self._event = event
        self._headers: dict[str, str] = dict(headers) if headers else {}
        self._actions: list[Action] = []
        # Route URIs popped by ``loose_route()``.  Mirrors the production
        # ``PyRequest.consumed_routes`` field — used so scripts that read
        # ``consumed_route_user`` (e.g. for IMS orig/term sescase) can be
        # exercised in tests.
        self._consumed_routes: list[str] = []
        # Charging params stashed by ``set_charging_param`` for the Rf
        # auto-emit path.  Tests can assert on them directly.
        self._charging_params: list[tuple[str, str]] = []

    # -- Read-only properties --------------------------------------------------

    @property
    def method(self) -> str:
        """SIP method string (e.g. ``"INVITE"``, ``"REGISTER"``, ``"BYE"``)."""
        return self._method

    @property
    def ruri(self) -> SipUri:
        """Request-URI as a :class:`SipUri` object."""
        return self._ruri

    @property
    def from_uri(self) -> Optional[SipUri]:
        """From header URI as a :class:`SipUri`, or ``None``."""
        return self._from_uri

    @property
    def to_uri(self) -> Optional[SipUri]:
        """To header URI as a :class:`SipUri`, or ``None``."""
        return self._to_uri

    @property
    def from_tag(self) -> Optional[str]:
        """From-tag parameter (always present for outgoing requests)."""
        return self._from_tag

    @property
    def to_tag(self) -> Optional[str]:
        """To-tag parameter.  ``None`` for initial (out-of-dialog) requests."""
        return self._to_tag

    @property
    def call_id(self) -> Optional[str]:
        """Call-ID header value."""
        return self._call_id

    @property
    def cseq(self) -> Optional[tuple[int, str]]:
        """CSeq as ``(sequence_number, method)`` tuple."""
        return self._cseq

    @property
    def in_dialog(self) -> bool:
        """``True`` if both From-tag and To-tag are present (mid-dialog request)."""
        return self._from_tag is not None and self._to_tag is not None

    @property
    def max_forwards(self) -> int:
        """Max-Forwards header value."""
        return self._max_forwards

    @property
    def body(self) -> Optional[bytes]:
        """Message body (SDP, etc.), or ``None`` if empty."""
        return self._body

    @property
    def content_type(self) -> Optional[str]:
        """Content-Type header value (e.g. ``"application/sdp"``)."""
        return self._content_type

    @property
    def transport(self) -> str:
        """Transport protocol: ``"udp"``, ``"tcp"``, ``"tls"``, ``"ws"``, ``"wss"``."""
        return self._transport

    @property
    def source_ip(self) -> str:
        """Source IP address of the sender."""
        return self._source_ip

    @property
    def source_port(self) -> int:
        """Source port of the sender."""
        return self._source_port

    @property
    def user_agent(self) -> Optional[str]:
        """User-Agent header value."""
        return self._user_agent

    @property
    def auth_user(self) -> Optional[str]:
        """Authenticated username (set after digest auth succeeds)."""
        return self._auth_user

    @auth_user.setter
    def auth_user(self, value: Optional[str]) -> None:
        self._auth_user = value

    @property
    def contact_expires(self) -> Optional[int]:
        """Contact expires value from Contact ``expires=`` param or Expires header."""
        return self._contact_expires

    @property
    def event(self) -> Optional[str]:
        """Event header value (e.g. ``"reg"``, ``"presence"``)."""
        return self._event

    @property
    def route_user(self) -> Optional[str]:
        """User part of the top Route header URI, or ``None``.

        Reflects the *current* state of the Route header — after any
        ``loose_route()`` calls have stripped routes addressed to this
        proxy.  For the user-part of a Route the framework consumed
        (e.g. the IMS service-route's ``orig``/``term`` indicator), use
        :attr:`consumed_route_user`.
        """
        route = self._headers.get("Route")
        if route:
            first = route.split(",", 1)[0].strip()
            uri = _parse_uri(first.strip("<>").split(">")[0].split(";")[0])
            return uri.user if uri else None
        return None

    @property
    def consumed_route_user(self) -> Optional[str]:
        """User part of the first Route entry that ``loose_route()``
        consumed, or ``None`` if no Route was popped yet.

        Mirrors the production ``request.consumed_route_user`` getter so
        IMS scripts can read the ``orig``/``term`` user-part of the
        service-route the P-CSCF preloaded.
        """
        for raw in self._consumed_routes:
            uri = _parse_uri(raw)
            if uri and uri.user:
                return uri.user
        return None

    @property
    def consumed_routes(self) -> list[str]:
        """URIs of all Route entries consumed by ``loose_route()``,
        in the order they were popped (topmost first).

        Empty until the script calls :meth:`loose_route`.
        """
        return list(self._consumed_routes)

    @property
    def consumed_route(self) -> Optional[SipUri]:
        """First Route entry consumed by ``loose_route()``, parsed as a
        :class:`SipUri` so the script can read ``user`` / ``host`` / ``port``
        directly without string-munging.

        Returns ``None`` when no Route was consumed yet.  Convenience over
        :attr:`consumed_route_user` for P-CSCF Path-token MT routing where
        the script needs both the userpart (the opaque token to look up)
        and the host (to verify it points at this proxy).
        """
        for raw in self._consumed_routes:
            uri = _parse_uri(raw)
            if uri:
                return uri
        return None

    @property
    def flow(self):
        """View of the inbound flow this request arrived on, or ``None``
        for synthetic requests without listener context.

        Pass to :meth:`relay` (``flow=`` kwarg) for Path-token MT routing
        — sends the request back over the same listener that received the
        REGISTER without DNS-resolving the URI (RFC 3327 §5 /
        TS 24.229 §5.2.7.2).

        In the mock, returns the test-fixture flow if one was attached
        via the test harness; otherwise ``None``.
        """
        return getattr(self, "_flow", None)

    # -- Response & forwarding -------------------------------------------------

    def reply(self, code: int, reason: str, reliable: bool = False) -> None:
        """Send a SIP response.

        Args:
            code: SIP status code (e.g. 200, 401, 404, 486).
            reason: Reason phrase (e.g. ``"OK"``, ``"Not Found"``).
            reliable: RFC 3262 — when True and ``code`` is 101..199, send as
                a reliable provisional response (``Require: 100rel`` + ``RSeq``).
                Only honoured for INVITE responses where the UAC advertised
                100rel in Supported or Require. Siphon retransmits the
                response per RFC 3262 §3 (T1 doubling to T2, deadline 32s)
                until a matching PRACK arrives, then auto-200s the PRACK.

        Example::

            request.reply(200, "OK")
            request.reply(486, "Busy Here")
            request.reply(183, "Session Progress", reliable=True)
        """
        self._actions.append(Action(
            kind="reply",
            status_code=code,
            reason=reason,
            headers_set=dict(self._pending_headers()),
            headers_removed=list(self._pending_removed()),
            reliable=reliable,
        ))

    def relay(
        self,
        next_hop: Optional[str] = None,
        on_reply: Optional[Callable] = None,
        on_failure: Optional[Callable] = None,
        flow=None,
        send_socket: Optional[str] = None,
    ) -> None:
        """Forward the request to its destination.

        Args:
            next_hop: Optional explicit next-hop URI.  If ``None``, the
                      Request-URI is used as the destination.
            on_reply: Optional callback ``(request, reply)`` invoked when any
                      response arrives for this relay.
            on_failure: Optional callback ``(request, code, reason)`` invoked
                        when an error response (4xx+) arrives.
            flow: Optional :class:`Flow` (typically ``binding.flow`` from
                  ``registrar.lookup_by_token(...)``).  When supplied,
                  bypasses DNS resolution of the Request-URI and sends the
                  request directly to the captured inbound flow's listener
                  — load-bearing for P-CSCF MT routing where the UE's
                  Contact URI is unreachable (NAT, IPSec).
                  Ignores ``next_hop`` when set.
            send_socket: Optional egress socket pin
                  (``"<transport>:<ip>:<port>"``, e.g. ``"udp:10.0.0.1:5060"``)
                  — the operator equivalent of Kamailio's
                  ``force_send_socket()``.  Selects which of siphon's own
                  configured listeners the request leaves from on a multi-homed
                  host.  The outgoing Via advertises that listener's address so
                  the response comes back to the same socket.  UDP pins the
                  exact ``(ip, port)`` listener; TCP/TLS bind the source IP with
                  an ephemeral port.  Ignored when ``flow`` is set (the flow
                  already pins egress), and when its transport doesn't match the
                  routed transport.  A malformed spec raises ``ValueError``; a
                  well-formed spec that names no configured listener is logged
                  and falls back to default routing (never dropped).

        Example::

            request.relay()                           # default routing
            request.relay("sip:proxy@10.0.0.2:5060")  # explicit next-hop
            request.relay(on_reply=my_reply_handler)   # per-relay callback
            request.relay(send_socket="udp:10.0.0.1:5060")  # pin egress NIC
            # Path-token MT routing:
            binding = registrar.lookup_by_token(token)
            request.relay(flow=binding.flow)
        """
        _validate_send_socket(send_socket)
        extras: Optional[dict] = None
        if flow is not None or send_socket is not None:
            extras = {}
            if flow is not None:
                extras["flow"] = flow
            if send_socket is not None:
                extras["send_socket"] = send_socket
        self._actions.append(Action(
            kind="relay",
            next_hop=next_hop,
            headers_set=dict(self._pending_headers()),
            headers_removed=list(self._pending_removed()),
            extras=extras,
        ))
        self._on_reply_callback = on_reply
        self._on_failure_callback = on_failure

    def fork(
        self,
        targets: list[Union[str, Contact]],
        strategy: str = "parallel",
        send_socket: Optional[str] = None,
    ) -> None:
        """Fork the request to multiple targets.

        Args:
            targets: List of URI strings or :class:`Contact` objects.  Pass
                ``Contact`` objects (not just ``.uri``) so a binding this
                process accepted (``contact.is_local``) routes its branch over
                the captured inbound flow — RFC 5626 §5.3 connection reuse,
                the only way to reach a WebSocket UE (RFC 7118 §5).  Non-local
                contacts fall back to URI routing.
            strategy: ``"parallel"`` (all at once, first 2xx wins) or
                      ``"sequential"`` (try in q-value order, next on failure).
            send_socket: Optional egress socket pin applied to every branch
                      (same ``"<transport>:<ip>:<port>"`` form as
                      :meth:`relay`).  A per-branch captured flow still takes
                      precedence over it for that branch.

        Example::

            contacts = registrar.lookup(request.ruri)
            # Pass Contact objects so a WebSocket UE routes over its flow.
            request.fork(contacts)
            request.fork(["sip:a@host", "sip:b@host"], strategy="sequential")
            request.fork(contacts, send_socket="udp:10.0.0.1:5060")
        """
        _validate_send_socket(send_socket)
        uris = [t.uri if isinstance(t, Contact) else str(t) for t in targets]
        self._actions.append(Action(
            kind="fork",
            targets=uris,
            strategy=strategy,
            headers_set=dict(self._pending_headers()),
            headers_removed=list(self._pending_removed()),
            extras={"send_socket": send_socket} if send_socket is not None else None,
        ))

    def record_route(self) -> None:
        """Insert a Record-Route header so that subsequent in-dialog requests
        traverse this proxy.

        Must be called **before** ``relay()`` or ``fork()``.
        """
        self._actions.append(Action(kind="record_route"))

    def loose_route(self) -> bool:
        """Perform RFC 3261 §16.4 loose routing.

        If the topmost Route entry carries an ``lr`` parameter, pop it,
        record its URI on :attr:`consumed_routes`, and return ``True``.
        If a Route header is present but the topmost entry is a strict
        route (no ``lr``), return ``False`` and leave it intact.

        When *no* Route header is present, the mock falls back to
        returning :attr:`in_dialog` to preserve compatibility with
        scripts that gate ``loose_route()`` behind ``in_dialog`` checks
        without setting up explicit Route headers in the test request.

        Example::

            if request.in_dialog:
                if request.loose_route():
                    request.relay()
                else:
                    request.reply(404, "Not Here")
        """
        route = self._headers.get("Route")
        if not route:
            return self.in_dialog

        entries = [entry.strip() for entry in route.split(",") if entry.strip()]
        if not entries:
            return self.in_dialog

        top = entries[0]
        # ;lr is the loose-route flag (RFC 3261 §19.1.1).
        if ";lr" not in top.lower():
            return False

        # Pop the topmost entry and record its URI (without angle brackets
        # or parameters) on consumed_routes.
        popped_uri = top.strip("<>").split(">")[0].split(";")[0].strip()
        self._consumed_routes.append(popped_uri)
        remaining = entries[1:]
        if remaining:
            self._headers["Route"] = ", ".join(remaining)
        else:
            self._headers.pop("Route", None)
        return True

    # -- Header access ---------------------------------------------------------

    def get_header(self, name: str) -> Optional[str]:
        """Get the first value of a header by name (case-insensitive).

        Args:
            name: Header name (e.g. ``"Via"``, ``"Contact"``).

        Returns:
            Header value string or ``None`` if not present.
        """
        for key, value in self._headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def header(self, name: str) -> Optional[str]:
        """Alias for :meth:`get_header`.

        Example::

            ua = request.header("User-Agent")
        """
        return self.get_header(name)

    def set_header(self, name: str, value: str) -> None:
        """Set (replace) a header value.

        Args:
            name: Header name.
            value: New header value.

        Example::

            request.set_header("X-Custom", "my-value")
        """
        self._headers[name] = value

    def set_charging_param(self, name: str, value: str) -> None:
        """Stash a charging-param for the Rf auto-emit hook.

        Recognised names (TS 32.299 IMS-Information AVPs):

        - ``"outgoing-trunk-group-id"`` — BGCF/MGCF settlement
        - ``"incoming-trunk-group-id"``
        - ``"application-server"`` — MMTel-AS
        - ``"application-provided-called-party-address"``

        Unknown names are silently kept on the request so future
        siphon versions can recognise them without breaking scripts.
        Tests can assert on the captured values via the
        ``charging_params`` property.

        Example::

            gw = gateway.select("trunks")
            request.set_charging_param(
                "outgoing-trunk-group-id", gw.attrs["group"],
            )
            request.relay(gw.uri)
        """
        self._charging_params.append((name, value))

    @property
    def charging_params(self) -> list[tuple[str, str]]:
        """List of `(name, value)` tuples stashed via
        :meth:`set_charging_param`.  Test helper."""
        return list(self._charging_params)

    def set_reply_header(self, name: str, value: str) -> None:
        """Set (replace) a single-value header on the response built by
        :meth:`reply` or :meth:`registrar.save`.

        Use this for single-value headers per RFC 3261 §7.3.1 — To, From,
        Contact, Expires, Server, Content-Type, Require, Min-Expires.
        The dispatcher removes any existing header of the same name
        before inserting this one, so the response will carry exactly
        one value even if the framework copied a header from the
        request (e.g. To, From) before the script ran.

        For multi-value headers (Via, Route, Service-Route,
        P-Associated-URI, Path), use :meth:`add_reply_header` instead.

        Args:
            name: Header name.
            value: Header value.

        Example::

            our_tag = f"scscf-{request.call_id[:8]}"
            request.set_reply_header(
                "To", f"{request.get_header('To')};tag={our_tag}"
            )
            request.reply(200, "OK")
        """
        self._set_reply_header_op("replace", name, value)

    def add_reply_header(self, name: str, value: str) -> None:
        """Append a header to the response built by :meth:`reply` or
        :meth:`registrar.save`.

        Use this for multi-value headers — Via, Record-Route, Route,
        Service-Route, P-Associated-URI, Path.  Multiple calls with the
        same name accumulate in insertion order, and any existing values
        copied by the framework (e.g. Via) are preserved.

        For single-value headers, use :meth:`set_reply_header`.

        Args:
            name: Header name.
            value: Header value.

        Example::

            registrar.save(request)
            request.add_reply_header(
                "P-Associated-URI", "<sip:user@ims.net>"
            )
            request.add_reply_header(
                "Service-Route", "<sip:orig@scscf:6060;lr>"
            )
        """
        self._set_reply_header_op("add", name, value)

    def set_reply_to_tag(self, tag: str) -> None:
        """Attach a To-tag to the response built by :meth:`reply`.

        Required by RFC 3261 §12.1.1.2 / RFC 6665 §4.1.3 on the
        dialog-establishing 2xx (and any 1xx that establishes early
        dialog) for INVITE / SUBSCRIBE / REFER from a UAS.

        Reads the request's ``To`` header, sets or overwrites the
        ``;tag=`` parameter, and queues the result for replace
        semantics.  Idempotent: calling twice with different tags
        leaves the most recent tag on the response.

        Args:
            tag: The To-tag value (no ``tag=`` prefix, no quoting).

        Example::

            request.set_reply_to_tag(f"scscf-{request.call_id[:8]}")
            request.reply(200, "OK")
        """
        to_value = self.get_header("To")
        if to_value is None:
            return
        # Strip any existing ;tag=... segment, then append the new one.
        # Mirrors NameAddr semicolon parsing in Rust — angle-bracket
        # contents are URI parameters and stay attached to the URI.
        parts = to_value.split(";")
        head = parts[0]
        kept_params = []
        for param in parts[1:]:
            stripped = param.strip()
            if not stripped:
                continue
            name = stripped.split("=", 1)[0].strip().lower()
            if name == "tag":
                continue
            kept_params.append(stripped)
        rebuilt = head
        for param in kept_params:
            rebuilt += f";{param}"
        rebuilt += f";tag={tag}"
        self._set_reply_header_op("replace", "To", rebuilt)

    def _set_reply_header_op(self, op: str, name: str, value: str) -> None:
        if not hasattr(self, "_reply_headers"):
            self._reply_headers = []
        self._reply_headers.append((op, name, value))

    def get_reply_header(self, name: str) -> Optional[str]:
        """Return the reply header value set by :meth:`set_reply_header`
        or :meth:`add_reply_header`, or ``None`` if not set.

        Test-only convenience — applies replace/add ops in order so the
        result matches what the dispatcher would inject into the outgoing
        response.  Multi-value (``add``) entries are joined with ``, ``.
        """
        applied: list[str] = []
        for op, n, v in getattr(self, "_reply_headers", []):
            if n.lower() != name.lower():
                continue
            if op == "replace":
                applied = [v]
            else:
                applied.append(v)
        return ", ".join(applied) if applied else None

    @property
    def reply_headers(self) -> list[tuple[str, str]]:
        """All ``(name, value)`` pairs queued for the response, with
        replace/add ops resolved (replace wipes earlier values for the
        same name, add appends).  Order preserved per name.
        """
        out: list[tuple[str, str]] = []
        for op, n, v in getattr(self, "_reply_headers", []):
            if op == "replace":
                out = [(en, ev) for (en, ev) in out if en.lower() != n.lower()]
            out.append((n, v))
        return out

    @property
    def reply_header_ops(self) -> list[tuple[str, str, str]]:
        """All ``(op, name, value)`` triples as queued — exposes the raw
        replace/add semantics for tests that need to inspect the queue
        before resolution.
        """
        return list(getattr(self, "_reply_headers", []))

    def set_body(self, body, content_type: str | None = None) -> None:
        """Replace the body of the incoming request message.

        Args:
            body: ``str`` or ``bytes`` — the new body.
            content_type: Optional Content-Type to set alongside the body.

        Example::

            request.set_body(pidf_lo_xml, "application/pidf+xml")
        """
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._body = body
        if content_type is not None:
            self._headers["Content-Type"] = content_type
        self._headers["Content-Length"] = str(len(body))

    def set_reply_body(self, body, content_type: str) -> None:
        """Attach a body to the response built by :meth:`reply`.

        The dispatcher copies this body and sets ``Content-Type`` /
        ``Content-Length`` on the outgoing response.

        Args:
            body: ``str`` or ``bytes`` — the response body.
            content_type: ``Content-Type`` header value.

        Example::

            request.set_reply_body(pidf_lo_xml, "application/pidf+xml")
            request.reply(200, "OK")
        """
        if isinstance(body, str):
            body = body.encode("utf-8")
        self._reply_body = (body, content_type)

    def remove_header(self, name: str) -> None:
        """Remove a header entirely.

        Args:
            name: Header name to remove.
        """
        self._headers = {
            k: v for k, v in self._headers.items()
            if k.lower() != name.lower()
        }

    def has_header(self, name: str) -> bool:
        """Check if a header exists (case-insensitive).

        Args:
            name: Header name.

        Returns:
            ``True`` if the header is present.
        """
        return any(k.lower() == name.lower() for k in self._headers)

    def parse_security_client(self) -> list:
        """Parse the ``Security-Client`` header (RFC 3329 / 3GPP TS 33.203).

        Returns a list of :class:`MockSecurityOffer` objects (one per
        comma-separated offer).  Empty list when the header is absent or
        no offer parses cleanly.

        The mock parser is byte-compatible with the Rust side:

        * Splits on top-level commas (respecting quoted strings).
        * Splits each offer on ``;``; the first token is the mechanism, the
          remaining ``key=value`` pairs populate the offer.
        * UE address is taken from :attr:`source_ip`.
        """
        from siphon_sdk.mock_module import MockSecurityOffer

        raw = self.get_header("Security-Client")
        if not raw:
            return []

        # Top-level comma split (no quoted-string handling needed for
        # Security-Client — it doesn't permit quoted strings per RFC 3329).
        offers: list[MockSecurityOffer] = []
        for chunk in raw.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            parts = [p.strip() for p in chunk.split(";")]
            if not parts:
                continue
            mechanism = parts[0]
            params: dict[str, str] = {}
            for token in parts[1:]:
                if "=" not in token:
                    continue
                k, v = token.split("=", 1)
                params[k.strip().lower()] = v.strip()
            try:
                offer = MockSecurityOffer(
                    mechanism=mechanism,
                    alg=params["alg"],
                    ealg=params.get("ealg", "null"),
                    spi_c=int(params["spi-c"]),
                    spi_s=int(params["spi-s"]),
                    port_c=int(params["port-c"]),
                    port_s=int(params["port-s"]),
                    ue_addr=self._source_ip,
                )
            except (KeyError, ValueError):
                continue
            offers.append(offer)
        return offers

    @property
    def is_ipsec_protected(self) -> bool:
        """Whether this request arrived over an IPsec-protected SA.

        Mock returns ``False`` by default; tests can override the underlying
        ``_is_ipsec_protected`` attribute.
        """
        return getattr(self, "_is_ipsec_protected", False)

    @property
    def matched_sa(self):
        """Handle to the SA that decrypted this request, or ``None``."""
        return getattr(self, "_matched_sa", None)

    def has_body(self, content_type: str) -> bool:
        """Check if the request has a body matching the given content type.

        Args:
            content_type: MIME type to match (e.g. ``"application/sdp"``).

        Returns:
            ``True`` if a body is present and Content-Type matches.
        """
        return self._body is not None and self._content_type == content_type

    # -- Header manipulation ---------------------------------------------------

    def ensure_header(self, name: str, value: str) -> None:
        """Set a header only if it is not already present.

        Args:
            name: Header name.
            value: Value to set if header is missing.
        """
        if not self.has_header(name):
            self.set_header(name, value)

    def remove_from_header_list(self, name: str, value: str) -> None:
        """Remove one value from a comma-separated multi-value header.

        If the header has values ``"A, B, C"`` and you remove ``"B"``,
        the result is ``"A, C"``.

        Args:
            name: Header name.
            value: The specific value to remove.
        """
        current = self.get_header(name)
        if current is None:
            return
        parts = [p.strip() for p in current.split(",")]
        parts = [p for p in parts if p != value]
        if parts:
            self.set_header(name, ", ".join(parts))
        else:
            self.remove_header(name)

    # -- R-URI mutation --------------------------------------------------------

    def set_ruri(self, value: Union[str, SipUri]) -> None:
        """Replace the entire Request-URI.

        Args:
            value: New URI as a string or :class:`SipUri`.
        """
        self._ruri = _parse_uri(value) or self._ruri

    def set_ruri_user(self, value: Optional[str]) -> None:
        """Set the user part of the Request-URI.

        Args:
            value: New user part, or ``None`` to clear.

        Example::

            request.set_ruri_user("bob")
        """
        self._ruri.user = value

    def set_ruri_host(self, value: str) -> None:
        """Set the host part of the Request-URI.

        Args:
            value: New host/domain string.
        """
        self._ruri.host = value

    # -- Display name / path / route -------------------------------------------

    def set_from_display(self, display_name: str) -> None:
        """Rewrite the From header display name.

        Args:
            display_name: New display name (e.g. ``"Alice Smith"``).
        """
        self.set_header("From-Display", display_name)

    def set_to_display(self, display_name: str) -> None:
        """Rewrite the To header display name.

        Args:
            display_name: New display name.
        """
        self.set_header("To-Display", display_name)

    def add_path(self, uri: str) -> None:
        """Prepend a ``Path`` header (P-CSCF registration path).

        Args:
            uri: URI to prepend (e.g. ``"sip:pcscf.ims.example.com;lr"``).
        """
        existing = self.get_header("Path")
        if existing:
            self.set_header("Path", f"<{uri};lr>, {existing}")
        else:
            self.set_header("Path", f"<{uri};lr>")

    def add_pcscf_path(self, token: str) -> None:
        """Insert a Path header (RFC 3327) of the form
        ``<sip:TOKEN@${path_host};lr>`` where ``path_host`` comes from
        the configured ``ipsec.path_host``.

        On the matching mobile-terminating request, the topmost Route
        will be this same URI; ``loose_route()`` consumes it,
        :attr:`consumed_route_user` exposes the token, and
        ``registrar.lookup_by_token(token)`` resolves back to the
        stored binding (TS 24.229 §5.2.7.2).

        The mock implementation uses a fixed test path host
        ``"pcscf.test"`` so unit tests can exercise the Path / Route
        / lookup loop without needing the full siphon config.
        """
        if not token or any(c in token for c in (" ", "\t", "\n", "@", "<", ">")):
            raise ValueError(
                "add_pcscf_path: token must be non-empty and contain no whitespace / '@' / '<' / '>'",
            )
        self.add_path(f"sip:{token}@pcscf.test")

    def prepend_route(self, uri: str) -> None:
        """Prepend a ``Route`` header.

        Args:
            uri: URI to prepend (e.g. ``"sip:scscf.ims.example.com;lr"``).
        """
        existing = self.get_header("Route")
        if existing:
            self.set_header("Route", f"<{uri};lr>, {existing}")
        else:
            self.set_header("Route", f"<{uri};lr>")

    def add_contact_alias(self) -> None:
        """Append ``;alias`` to the Contact URI (NAT traversal)."""
        contact = self.get_header("Contact")
        if contact and ";alias" not in contact:
            self.set_header("Contact", f"{contact};alias")

    # -- NAT fixup -------------------------------------------------------------

    def fix_nated_register(self) -> None:
        """Add ``received=`` and ``rport=`` to top Via using source IP:port.

        Used by edge proxies / P-CSCFs for NAT traversal on REGISTER.
        """
        via = self.get_header("Via")
        if via:
            self.set_header("Via", f"{via};received={self._source_ip};rport=5060")

    def fix_nated_contact(self) -> None:
        """Rewrite Contact URI host:port with source IP:port.

        Used for NAT traversal — ensures replies route back through the
        actual transport address rather than the Contact address the UA
        advertised.
        """
        pass  # Mock: no-op (Contact rewriting is transport-layer)

    # -- Transport control -----------------------------------------------------

    def force_send_via(self, transport: str, target: str) -> None:
        """Override Via header transport and target for outgoing message.

        Args:
            transport: Protocol (``"udp"``, ``"tcp"``, ``"tls"``).
            target: Target address (e.g. ``"10.0.0.2:5060"``).
        """
        self.set_header("X-Force-Via", f"{transport}:{target}")

    # -- Utilities -------------------------------------------------------------

    def generate_icid(self) -> str:
        """Generate a unique ICID (IMS Charging ID) for ``P-Charging-Vector``.

        Returns:
            UUID string suitable for the ``icid-value`` parameter.
        """
        return str(uuid.uuid4())

    def source_ip_in(self, cidr_list: list[str]) -> bool:
        """Check if the source IP is within any of the given CIDR ranges.

        Args:
            cidr_list: List of CIDR strings (e.g. ``["10.0.0.0/8"]``).

        Returns:
            ``True`` if ``source_ip`` falls within any range.

        Example::

            if request.source_ip_in(["10.0.0.0/8", "172.16.0.0/12"]):
                log.info("Trusted network")
        """
        try:
            addr = ipaddress.ip_address(self._source_ip)
        except ValueError:
            return False
        return any(addr in ipaddress.ip_network(cidr) for cidr in cidr_list)

    def from_gateway(self, group_name: str) -> bool:
        """Check if the source IP is a member of a gateway group.

        Returns ``True`` when this request's source IP is one of the resolved
        addresses of the gateway group ``group_name`` (configured under
        ``gateway.groups`` in ``siphon.yaml``, or via ``gateway.add_group``).
        This is siphon's equivalent of Kamailio ``ds_is_from_list()`` /
        OpenSIPS ``ds_is_in_list()`` — a routing-direction / trust predicate
        that replaces hardcoded source CIDRs.

        The match is on IP only (the source port is ignored — gateways answer
        from varied ports) and against **every** resolved address in the
        group, so a hostname that round-robins across many IPs (e.g. Teams'
        ``sip``/``sip2``/``sip3.pstnhub.microsoft.com``) matches on any of
        them.

        Infallible: returns ``False`` (never raises) when the group does not
        exist, no gateway is configured, or the source IP does not parse.

        Security: on connection-oriented transports (TCP/TLS/WS/WSS) the source
        IP is handshake-verified and trustworthy as an authorization signal; on
        UDP it is spoofable, so ``from_gateway`` there is a best-effort
        direction hint, not an auth gate.

        Args:
            group_name: Name of the gateway group to test membership against.

        Returns:
            ``True`` if the source IP belongs to the group.

        Example::

            @proxy.on_request("INVITE")
            def route(request):
                if request.from_gateway("teams"):
                    # Inbound from Microsoft Teams — trust and forward to the PBX.
                    request.relay("sip:pbx.internal:5060")
                else:
                    request.reply(403, "Forbidden")
        """
        # Lazy import avoids a circular import (mock_module imports from this
        # module at load time).
        from siphon_sdk.mock_module import get_gateway

        return get_gateway().contains_source(group_name, self._source_ip)

    # -- Internal helpers (not part of the public API) -------------------------

    def _pending_headers(self) -> dict[str, str]:
        return dict(self._headers)

    def _pending_removed(self) -> list[str]:
        return []

    @property
    def actions(self) -> list[Action]:
        """All actions recorded by this request (test-only)."""
        return self._actions

    @property
    def last_action(self) -> Optional[Action]:
        """The last (most recent) action, or ``None``."""
        return self._actions[-1] if self._actions else None
