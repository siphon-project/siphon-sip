"""
Core SIP types used by SIPhon scripts.

These mirror the Rust PyO3 classes that SIPhon injects at runtime.
All properties and methods carry type annotations and docstrings so that
type checkers and LLMs can reason about script correctness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SipUri:
    """A parsed SIP or SIPS URI (e.g. ``sip:alice@example.com:5060``).

    At runtime this is backed by the Rust ``PySipUri`` class.  The mock
    version is a plain dataclass with the same properties.

    Examples::

        uri = SipUri(user="alice", host="example.com")
        assert str(uri) == "sip:alice@example.com"

        uri = SipUri(scheme="sips", host="proxy.example.com", port=5061)
        assert str(uri) == "sips:proxy.example.com:5061"
    """

    scheme: str = "sip"
    """URI scheme — ``"sip"`` or ``"sips"``."""

    user: Optional[str] = None
    """User part of the URI (e.g. ``"alice"``).  ``None`` for server URIs."""

    host: str = "localhost"
    """Host or domain (e.g. ``"example.com"``, ``"10.0.0.1"``)."""

    port: Optional[int] = None
    """Port number.  ``None`` means default (5060 for SIP, 5061 for SIPS)."""

    # Set by the engine based on the ``domain:`` config list.
    _is_local: bool = False

    @property
    def is_local(self) -> bool:
        """``True`` if the host matches one of the locally configured domains.

        In the mock, set via ``SipUri._is_local = True`` or via the test
        harness ``local_domains`` parameter.
        """
        return self._is_local

    @property
    def is_tel(self) -> bool:
        """``True`` if the scheme is ``tel:``."""
        return self.scheme == "tel"

    def __str__(self) -> str:
        uri = f"{self.scheme}:"
        if self.user is not None:
            uri += f"{self.user}@"
        uri += self.host
        if self.port is not None:
            uri += f":{self.port}"
        return uri

    def __repr__(self) -> str:
        return f"SipUri({self})"


@dataclass
class Flow:
    """Opaque view of an inbound flow captured at REGISTER time.

    Returned by :attr:`Contact.flow` and :attr:`Request.flow`.  Pass back
    to :meth:`Request.relay` (``flow=`` kwarg) to send a request over the
    same listener that received the REGISTER — bypassing DNS resolution
    of the Request-URI.  Used by P-CSCF MT routing (RFC 3327 §5 /
    TS 24.229 §5.2.7.2) where the UE's Contact URI is unreachable
    (NAT, IPSec) and the only path back is the captured flow.

    Treat as opaque: scripts read :attr:`is_alive` for defensive checks
    but should not depend on the internal field shapes.
    """

    transport: str = "udp"
    """Lowercase transport name: ``"udp"``, ``"tcp"``, ``"tls"``, ``"ws"``,
    or ``"wss"``."""

    remote_addr: str = "0.0.0.0:0"
    """String form of the captured UE source address (``"ip:port"``)."""

    local_addr: str = "0.0.0.0:0"
    """String form of the captured listener local address — load-bearing
    for IPSec sec-agree where the protected port pair must be preserved
    (3GPP TS 33.203 §7.4)."""

    @property
    def is_alive(self) -> bool:
        """Whether the flow is still usable.

        For UDP, always ``True``: the listener socket survives any
        individual exchange.  For stream transports (TCP/TLS/WS/WSS), the
        real implementation returns ``True`` only while the *exact* accepted
        connection that delivered the REGISTER is still open on this process
        — a real lookup against the unified stream-connection registry (see
        PyFlow.is_alive in src/script/api/registrar.rs).  A UE that
        reconnected, or whose socket closed, reports ``False``.

        The mock always returns ``True`` (no live connections to track).
        """
        return True


@dataclass
class Contact:
    """A registered contact binding returned by ``registrar.lookup()``.

    Attributes:
        uri: The contact URI string (e.g. ``"sip:alice@192.168.1.5:5060"``).
        q: Quality value between 0.0 and 1.0 (higher = preferred).
        expires: Seconds remaining until this binding expires.
    """

    uri: str
    """Contact URI as a string."""

    q: float = 1.0
    """Quality value (0.0–1.0).  Higher values are preferred.
    Default is 1.0 per RFC 3261."""

    expires: int = 3600
    """Seconds remaining until this contact binding expires."""

    path: list = field(default_factory=list)
    """RFC 3327 Path headers stored with this binding.
    Use as Route headers when routing terminating requests to this contact."""

    instance_id: Optional[str] = None
    """Stable identity of the siphon instance that originally accepted the
    REGISTER (typically the StatefulSet pod name).  ``None`` for legacy
    bindings or deployments that do not configure ``server.instance_id``."""

    instance_epoch: Optional[str] = None
    """Boot-time epoch UUID of the process that accepted the REGISTER.
    Combined with :attr:`instance_id`, distinguishes successive runs of the
    same logical replica."""

    is_local: bool = False
    """``True`` when the binding's ``(instance_id, instance_epoch)`` matches
    the *current* siphon process — i.e. this process accepted the REGISTER.
    Useful for graceful-shutdown deregister and NAT keepalive ownership."""

    flow_token: Optional[str] = None
    """Opaque proxy-side token attached at REGISTER time via
    ``registrar.save(flow_token=...)``.  ``None`` for non-P-CSCF
    bindings."""

    flow: Optional[Flow] = None
    """Captured inbound flow (``Flow`` view).  Pass to
    ``request.relay(flow=...)`` / ``request.fork(contacts)`` /
    ``call.dial(flow=...)`` for RFC 5626 §5.3 connection reuse — the only
    way to reach a WebSocket UE (RFC 7118 §5).  Populated for *any* binding
    this process accepted (no ``flow_token=`` required); ``None`` only for a
    binding restored cross-instance whose local listener / connection id
    aren't available here.  Guard on :attr:`is_local` before routing over
    it."""

    params: list = field(default_factory=list)
    """Contact-header parameters preserved from the originating REGISTER
    (or 3PR 200 OK), excluding ``tag``, ``q``, ``expires``,
    ``+sip.instance``, and ``reg-id`` which are broken out into other
    fields.  Each entry is a ``(name, value)`` tuple — ``value`` is
    ``None`` for flag parameters (e.g. ``+g.3gpp.smsip``) and a string
    for valued parameters (e.g. ``+g.3gpp.icsi-ref="urn:..."``).

    Surfaced verbatim by :func:`registrar.reginfo_xml` as
    ``<unknown-param>`` children per RFC 3680 §5.3.2 so watchers see the
    same capability advertisement the registrar received."""

    kind: str = "ue"
    """``"ue"`` (UE-side binding from a REGISTER — the default and the
    only contacts returned by :func:`registrar.lookup`) or ``"as"``
    (application-server capability record captured from a 3PR 200 OK
    via :func:`registrar.save_as_contact`).  AS contacts surface in
    reg-event NOTIFY bodies (TS 24.229 §5.4.2.1.2) but are excluded
    from routing lookups."""


@dataclass
class Action:
    """Records a single action taken by a handler (reply, relay, fork, etc.).

    Used by the test harness to capture what a script did in response to a
    SIP message, so you can assert on it.
    """

    kind: str
    """Action type: ``"reply"``, ``"relay"``, ``"fork"``, ``"reject"``,
    ``"dial"``, ``"terminate"``, ``"record_route"``, ``"silent_drop"``."""

    status_code: Optional[int] = None
    """For ``reply`` / ``reject`` — the SIP status code (e.g. 200, 404)."""

    reason: Optional[str] = None
    """For ``reply`` / ``reject`` — the reason phrase (e.g. ``"OK"``)."""

    next_hop: Optional[str] = None
    """For ``relay`` — the explicit next-hop URI, or ``None`` for default."""

    targets: Optional[list[str]] = None
    """For ``fork`` — list of target URIs."""

    strategy: Optional[str] = None
    """For ``fork`` — ``"parallel"`` or ``"sequential"``."""

    timeout: Optional[int] = None
    """For ``dial`` / ``fork`` — timeout in seconds."""

    headers_set: dict[str, str] = field(default_factory=dict)
    """Headers that were set/modified before this action."""

    headers_removed: list[str] = field(default_factory=list)
    """Headers that were removed before this action."""

    extras: Optional[dict] = None
    """Additional action-specific data (e.g. session timer params, SRS URI)."""

    reliable: bool = False
    """For ``reply`` — RFC 3262 reliable provisional flag (``Require: 100rel``)."""


@dataclass
class ByeInitiator:
    """Passed to ``@b2bua.on_bye`` handlers indicating which side sent BYE.

    Attributes:
        side: ``"a"`` (caller) or ``"b"`` (callee).
    """

    side: str
    """``"a"`` for the A-leg (caller) or ``"b"`` for the B-leg (callee)."""


@dataclass
class MediaHandle:
    """Handle for media anchoring operations on a B2BUA call.

    Accessible as ``call.media``.  In the mock, ``anchor()`` and
    ``release()`` are recorded as actions.
    """

    is_active: bool = False
    """``True`` if media is currently anchored through an RTP engine."""

    _actions: list[str] = field(default_factory=list)

    def anchor(self, engine: str = "rtpengine", profile: str = "srtp_to_rtp") -> None:
        """Anchor media through an RTP engine.

        Args:
            engine: Engine name (currently only ``"rtpengine"``).
            profile: RTP profile — ``"srtp_to_rtp"``, ``"ws_to_rtp"``,
                     ``"wss_to_rtp"``, or ``"rtp_passthrough"``.
        """
        self.is_active = True
        self._actions.append(f"anchor:{engine}:{profile}")

    def release(self) -> None:
        """Release media anchor, returning to direct RTP flow."""
        self.is_active = False
        self._actions.append("release")
