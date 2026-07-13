"""
Mock SIP Reply object — mirrors ``PyReply`` from the Rust engine.

Passed to ``@proxy.on_reply``, ``@proxy.on_failure``,
``@proxy.on_register_reply``, ``@b2bua.on_early_media``,
and ``@b2bua.on_answer`` handlers.
"""

from __future__ import annotations

from typing import Optional, Union

from siphon_sdk.types import Action, SipUri
from siphon_sdk.request import _parse_uri


class Reply:
    """A SIP response message.

    This object is passed as the second argument to reply handlers:

    - ``@proxy.on_reply`` — all responses
    - ``@proxy.on_failure`` — aggregated failure response
    - ``@proxy.on_register_reply`` — REGISTER responses

    Example::

        @proxy.on_reply
        async def reply_route(request, reply):
            if reply.status_code == 200 and reply.has_body("application/sdp"):
                await rtpengine.answer(reply)
            reply.relay()
    """

    def __init__(
        self,
        status_code: int = 200,
        reason: str = "OK",
        from_uri: Union[str, SipUri, None] = None,
        to_uri: Union[str, SipUri, None] = None,
        call_id: Optional[str] = None,
        body: Optional[bytes] = None,
        content_type: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        source_ip: Optional[str] = None,
        source_port: Optional[int] = None,
    ) -> None:
        self._status_code = status_code
        self._reason = reason
        self._from_uri = _parse_uri(from_uri)
        self._to_uri = _parse_uri(to_uri)
        self._call_id = call_id
        self._body = body
        self._content_type = content_type
        self._headers: dict[str, str] = dict(headers) if headers else {}
        self._source_ip = source_ip
        self._source_port = source_port
        self._actions: list[Action] = []

    @property
    def status_code(self) -> int:
        """SIP status code (e.g. 200, 404, 503)."""
        return self._status_code

    @property
    def reason(self) -> str:
        """Reason phrase (e.g. ``"OK"``, ``"Not Found"``)."""
        return self._reason

    @property
    def from_uri(self) -> Optional[SipUri]:
        """From header URI."""
        return self._from_uri

    @property
    def to_uri(self) -> Optional[SipUri]:
        """To header URI."""
        return self._to_uri

    @property
    def call_id(self) -> Optional[str]:
        """Call-ID header value."""
        return self._call_id

    @property
    def body(self) -> Optional[bytes]:
        """Response body (e.g. SDP), or ``None``."""
        return self._body

    @property
    def content_type(self) -> Optional[str]:
        """Content-Type header value."""
        return self._content_type

    @property
    def source_ip(self) -> Optional[str]:
        """Source IP of the entity that sent this response, or ``None``.

        Populated on ``@proxy.on_reply``, ``@proxy.on_failure`` per-relay
        callbacks, and the B2BUA ``@b2bua.on_answer`` / ``@b2bua.on_early_media``
        replies (the B-leg peer that answered).  ``None`` on a fork-aggregated
        ``@proxy.on_failure`` reply, where the "best" error is selected across
        branches and no single source applies.  Reply-side counterpart of
        ``request.source_ip``.
        """
        return self._source_ip

    @property
    def source_port(self) -> Optional[int]:
        """Source port of the entity that sent this response, or ``None``
        (see :attr:`source_ip` for when it is populated)."""
        return self._source_port

    def from_gateway(self, group_name: str) -> bool:
        """Check if this response's source IP is a member of a gateway group.

        The reply-side counterpart of ``request.from_gateway`` /
        ``call.from_gateway`` — returns ``True`` when the source IP of the entity
        that sent this response is one of the resolved addresses of the gateway
        group ``group_name`` (configured under ``gateway.groups`` in
        ``siphon.yaml``, or via ``gateway.add_group``).  Use it on a response to
        decide which trunk actually answered — siphon's answer to Kamailio
        ``ds_is_from_list()`` / OpenSIPS ``ds_is_in_list()`` on the reply path.

        The match is on IP only (source port ignored) against **every** resolved
        address in the group, so a hostname that round-robins across many IPs
        matches on any of them.

        Infallible: returns ``False`` (never raises) when the group does not
        exist, no gateway is configured, the response source is unknown (see
        :attr:`source_ip`), or the source IP does not parse.

        Security: on connection-oriented transports (TCP/TLS/WS/WSS) the source
        IP is handshake-verified and trustworthy as an authorization signal; on
        UDP it is spoofable, so ``from_gateway`` there is a best-effort
        direction hint, not an auth gate.

        Args:
            group_name: Name of the gateway group to test membership against.

        Returns:
            ``True`` if the response source IP belongs to the group.

        Example::

            @b2bua.on_answer
            async def on_answer(call, reply):
                if reply.from_gateway("carriers"):
                    log.info("answered by the carrier trunk")
        """
        # Lazy import avoids a circular import (mock_module imports from the
        # request module, which the reply module also imports at load time).
        from siphon_sdk.mock_module import get_gateway

        if self._source_ip is None:
            return False
        return get_gateway().contains_source(group_name, self._source_ip)

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

    def remove_header(self, name: str) -> None:
        """Remove a header entirely."""
        self._headers = {
            k: v for k, v in self._headers.items()
            if k.lower() != name.lower()
        }

    def has_header(self, name: str) -> bool:
        """Check if a header exists (case-insensitive)."""
        return any(k.lower() == name.lower() for k in self._headers)

    def has_body(self, content_type: str) -> bool:
        """Check if the reply has a body matching the given content type.

        Args:
            content_type: MIME type (e.g. ``"application/sdp"``).
        """
        return self._body is not None and self._content_type == content_type

    # -- IPsec / 3GPP TS 33.203 ------------------------------------------------

    def take_av(self):
        """Extract IMS-AKA CK/IK from auth headers and strip ``ck=``/``ik=``.

        Scans ``WWW-Authenticate``, ``Proxy-Authenticate`` and
        ``Authentication-Info`` (in that order).  Returns a
        :class:`MockAuthVectorHandle` only when **both** ``ck`` and ``ik``
        parsed cleanly; otherwise leaves the headers untouched and returns
        ``None``.

        Idempotent: after stripping, a second call returns ``None`` because
        no header still carries ``ck``/``ik``.
        """
        from siphon_sdk.mock_module import MockAuthVectorHandle

        for header_name in ("WWW-Authenticate", "Proxy-Authenticate", "Authentication-Info"):
            value = self.get_header(header_name)
            if value is None:
                continue
            rewritten, parsed = _strip_ck_ik(value)
            if parsed is not None:
                ck, ik = parsed
                self.set_header(header_name, rewritten)
                return MockAuthVectorHandle(ck=ck, ik=ik)
        return None

    # -- Forwarding ------------------------------------------------------------

    def relay(self) -> None:
        """Forward the reply upstream to the UAC.

        Example::

            @proxy.on_reply
            def handle_reply(request, reply):
                reply.relay()
        """
        self._actions.append(Action(kind="relay"))

    def forward(self) -> None:
        """Alias for :meth:`relay`."""
        self.relay()

    def reject(self, code: int, reason: Optional[str] = None) -> bool:
        """Reject an in-progress proxied INVITE from ``@proxy.on_reply``.

        The proxy-side equivalent of the B2BUA's ``call.reject()`` — needed
        because media authorization (``sbi.create_session`` /
        ``diameter.rx_aar``) runs at answer time, when the negotiated SDP is
        available, and a media-authorization failure must reject the leg rather
        than proceed medialess.

        Behaviour depends on the stage of the response this handler is running
        for:

        - **Provisional (1xx) — no final answer yet:** records the reject and
          returns ``True``.  siphon then sends ``code reason`` upstream to the
          UAC and CANCELs the pending downstream branch(es).  This is the clean
          path — typically a reliable ``183 Session Progress`` in the VoLTE
          preconditions / early-media flow, where the SDP answer rides the
          provisional.
        - **Final (>= 200) — UAS already answered:** a proxy cannot retract a
          2xx, so this is a no-op and returns ``False``.  Branch on the return
          value: log the failed authorization and :meth:`relay` to let the
          answer through (best-effort, no dedicated bearer).

        Takes precedence over :meth:`relay` / :meth:`forward` when it returns
        ``True``.

        Args:
            code: SIP final-response code in the 400–699 range (e.g. ``503``).
            reason: optional reason phrase; a sensible default is derived from
                ``code`` when omitted.

        Returns:
            ``True`` if the reject was accepted (provisional stage — siphon will
            send the error + CANCEL); ``False`` if it could not be applied (the
            UAS already sent a final response).

        Raises:
            ValueError: if ``code`` is outside 400–699.

        Example::

            @proxy.on_reply
            async def on_reply(request, reply):
                if request.method == "INVITE" and reply.has_body("application/sdp"):
                    if not await authorize_media(request, reply):
                        if reply.reject(503, "Media Authorization Failed"):
                            return            # 503 + CANCEL sent by siphon
                        log.warn("could not reject answered call; proceeding best-effort")
                reply.relay()
        """
        if not 400 <= code <= 699:
            raise ValueError(
                f"reply.reject() code must be a 400-699 SIP error code, got {code}"
            )
        # A proxy can only fail a leg before the UAS commits a final response.
        if self._status_code >= 200:
            return False
        phrase = reason if reason is not None else _default_reject_reason(code)
        self._actions.append(Action(kind="reject", status_code=code, reason=phrase))
        return True

    # -- Test helpers ----------------------------------------------------------

    @property
    def actions(self) -> list[Action]:
        """All actions recorded (test-only)."""
        return self._actions

    @property
    def last_action(self) -> Optional[Action]:
        """Most recent action, or ``None``."""
        return self._actions[-1] if self._actions else None


_REJECT_REASONS = {
    403: "Forbidden",
    404: "Not Found",
    408: "Request Timeout",
    480: "Temporarily Unavailable",
    486: "Busy Here",
    488: "Not Acceptable Here",
    500: "Server Internal Error",
    503: "Service Unavailable",
    600: "Busy Everywhere",
    603: "Decline",
}


def _default_reject_reason(code: int) -> str:
    """Default reason phrase for a reject code — mirrors the Rust side."""
    if code in _REJECT_REASONS:
        return _REJECT_REASONS[code]
    if 400 <= code <= 499:
        return "Client Error"
    if 500 <= code <= 599:
        return "Server Error"
    return "Global Failure"


def _split_top_level_commas(value: str) -> list[str]:
    """Split a header parameter list on top-level commas, respecting
    double-quoted strings and backslash escapes inside them."""
    out: list[str] = []
    start = 0
    in_quote = False
    escaped = False
    for i, ch in enumerate(value):
        if escaped:
            escaped = False
            continue
        if ch == "\\" and in_quote:
            escaped = True
        elif ch == '"':
            in_quote = not in_quote
        elif ch == "," and not in_quote:
            out.append(value[start:i])
            start = i + 1
    out.append(value[start:])
    return out


def _parse_hex_param(raw: str) -> Optional[bytes]:
    """Parse ``"hex…"`` or ``hex…`` into 16 bytes; ``None`` on length
    mismatch (IMS-AKA AV components are always 128-bit)."""
    trimmed = raw.strip()
    if len(trimmed) >= 2 and trimmed.startswith('"') and trimmed.endswith('"'):
        body = trimmed[1:-1]
    else:
        body = trimmed
    if len(body) != 32:
        return None
    try:
        return bytes.fromhex(body)
    except ValueError:
        return None


def _strip_ck_ik(value: str) -> tuple[str, Optional[tuple[bytes, bytes]]]:
    """Conservative strip — mirrors the Rust ``strip_ck_ik`` logic.

    Returns ``(rewritten, (ck, ik))`` only when both params parsed; the
    original string is returned unchanged with ``None`` otherwise.
    """
    parts = value.split(None, 1)
    if len(parts) < 2:
        return value, None
    scheme, rest = parts[0], parts[1]
    tokens = _split_top_level_commas(rest)
    kept: list[str] = []
    ck: Optional[bytes] = None
    ik: Optional[bytes] = None
    for token in tokens:
        trimmed = token.strip()
        if not trimmed:
            continue
        if "=" not in trimmed:
            kept.append(trimmed)
            continue
        name, raw = trimmed.split("=", 1)
        name_lower = name.strip().lower()
        if name_lower == "ck":
            ck = _parse_hex_param(raw)
            continue
        if name_lower == "ik":
            ik = _parse_hex_param(raw)
            continue
        kept.append(trimmed)
    if ck is None or ik is None:
        return value, None
    rewritten = f"{scheme} {', '.join(kept)}"
    return rewritten, (ck, ik)
