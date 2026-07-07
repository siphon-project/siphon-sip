"""
Mock B2BUA Call object — mirrors ``PyCall`` from the Rust engine.

Passed to ``@b2bua.on_invite``, ``@b2bua.on_early_media``,
``@b2bua.on_answer``, ``@b2bua.on_failure``, and ``@b2bua.on_bye`` handlers.
"""

from __future__ import annotations

import uuid
from typing import Optional, Union

from siphon_sdk.types import Action, Contact, Flow, MediaHandle, SipUri
from siphon_sdk.request import _parse_uri


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
    ) -> None:
        self._id = call_id or str(uuid.uuid4())
        self._from_uri = _parse_uri(from_uri)
        self._to_uri = _parse_uri(to_uri)
        self._ruri = _parse_uri(ruri)
        self._source_ip = source_ip
        self._state = state
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

    # -- Properties ------------------------------------------------------------

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

        Returns a dict with ``call_id``, ``from_tag``, and ``to_tag`` if
        the REFER includes a Replaces header (attended transfer), or
        ``None`` for a blind transfer.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                repl = call.refer_replaces
                if repl:
                    log.info(f"Attended transfer, replaces {repl['call_id']}")
        """
        return self._refer_replaces

    # -- Call control ----------------------------------------------------------

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
               body=None, content_type: str | None = None) -> None:
        """UAS-mode answer — send a final 2xx response to the inbound
        INVITE directly, without bridging to a B-leg.

        Args:
            code: Final 2xx status code (200, 202, etc.).
            reason: Reason phrase.
            body: Optional response body (``bytes`` or ``str``) — typically SDP.
            content_type: Content-Type for the body (e.g. ``"application/sdp"``).

        Example::

            call.answer(200, "OK", body=sdp_bytes, content_type="application/sdp")
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

        Example::

            # Basic dial (uses configured default policy)
            call.dial("sip:bob@10.0.0.2:5060", timeout=30)

            # IMS edge: stamp canonical IMPU on R-URI, route via I-CSCF,
            # apply the trust-domain-boundary preset for outbound hygiene.
            call.dial(
                "sip:5112@ims.mnc088.mcc204.3gppnetwork.org",
                next_hop="sip:172.16.0.111:4060",
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
            header_policy / copy / strip / translate: Same semantics as
                :meth:`dial` — the policy applies to every branch of the
                fork (per-branch policy is a follow-up).

        Example::

            contacts = registrar.lookup(call.ruri)
            # Pass Contact objects so WebSocket callees route over their flow.
            call.fork(contacts, strategy="parallel", timeout=30)
        """
        uris = [t.uri if isinstance(t, Contact) else str(t) for t in targets]
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
            },
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

    def accept_refer(self) -> None:
        """Accept an incoming REFER and initiate the transfer.

        Call this from a ``@b2bua.on_refer`` handler to proceed with the
        call transfer.  The B2BUA will send 202 Accepted to the REFER
        originator and initiate a new INVITE to the Refer-To target.

        Example::

            @b2bua.on_refer
            def handle_refer(call):
                call.accept_refer()
        """
        self._actions.append(Action(kind="accept_refer"))

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
        self._ruri = f"sip:{value}@{self._ruri.split('@', 1)[-1]}" if '@' in self._ruri else self._ruri

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
        # In the mock, just update the from_uri string
        old = self._from_uri
        if '@' in old:
            self._from_uri = f"{value}@{old.split('@', 1)[-1]}"

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
            value: New user part (e.g. ``"5112"``).

        Example::

            @b2bua.on_invite
            async def on_invite(call):
                call.set_ruri_user("5112")
                call.set_to_user("5112")
                call.dial("sip:5112@ims.mnc088.mcc204.3gppnetwork.org")
        """
        if self._to_uri is not None:
            self._to_uri.user = value

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
