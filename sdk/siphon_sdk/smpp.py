"""
siphon.smpp — mock of the SMPP 3.4 namespace (siphon-smpp extension).

At runtime the ``smpp`` namespace is injected by the **siphon-smpp**
extension (compiled into a ``siphon-bin`` build with ``--features smpp``),
not by siphon-sip itself. This module mirrors that namespace so SMPP
scripts can be:

1. **Unit tested** with pytest without a running SMSC — see
   :class:`siphon_sdk.smpp_testing.SmppTestHarness`.
2. **Authored with LLM/IDE assistance** — every decorator, send helper and
   pyclass carries the same docstrings and signatures as the runtime.

The runtime namespace is defined by ``python/smpp.py`` (decorators + config
readouts), ``src/pyclasses.rs`` (``Pdu`` / ``Bind`` / …) and ``src/sends.rs``
(the ``*_via`` / ``*_to`` send helpers) in the siphon-smpp repository. Keep
this mock in step with those — the siphon-smpp CI parity check fails the
build if a name here drifts from the runtime.

Quick start::

    from siphon import smpp, log

    @smpp.on_bind
    def authorise(bind):
        if bind.password != "s3cret":
            return bind.reject("ESME_RINVPASWD", "bad password")
        return bind.accept()

    @smpp.on_pdu("submit_sm")
    async def on_submit(pdu, session):
        log.info(f"MO from {pdu.source_addr} -> {pdu.destination_addr}")
        return pdu.reply(message_id="msg-1")
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Callable, Optional, Union


# ---------------------------------------------------------------------------
# SMPP command statuses (mirror src/pyclasses.rs::parse_smpp_status)
# ---------------------------------------------------------------------------

#: Every SMPP command-status name the runtime accepts. Passing anything else
#: to ``pdu.reply(command_status=…)`` / ``bind.reject(status=…)`` raises
#: ``ValueError`` — exactly as the Rust ``parse_smpp_status`` raises a
#: ``PyValueError`` — so a typo surfaces in tests instead of silently
#: falling through to ``ESME_ROK``.
SMPP_STATUSES: frozenset[str] = frozenset({
    "ESME_ROK", "ESME_RINVMSGLEN", "ESME_RINVCMDLEN", "ESME_RINVCMDID",
    "ESME_RINVBNDSTS", "ESME_RALYBND", "ESME_RINVPRTFLG", "ESME_RINVREGDLVFLG",
    "ESME_RSYSERR", "ESME_RINVSRCADR", "ESME_RINVDSTADR", "ESME_RINVMSGID",
    "ESME_RBINDFAIL", "ESME_RINVPASWD", "ESME_RINVSYSID", "ESME_RCANCELFAIL",
    "ESME_RREPLACEFAIL", "ESME_RMSGQFUL", "ESME_RINVSERTYP", "ESME_RINVNUMDESTS",
    "ESME_RINVDLNAME", "ESME_RINVDESTFLAG", "ESME_RINVSUBREP", "ESME_RINVESMCLASS",
    "ESME_RCNTSUBDL", "ESME_RSUBMITFAIL", "ESME_RINVSRCTON", "ESME_RINVSRCNPI",
    "ESME_RINVDSTTON", "ESME_RINVDSTNPI", "ESME_RINVSYSTYP", "ESME_RINVREPFLAG",
    "ESME_RINVNUMMSGS", "ESME_RTHROTTLED", "ESME_RINVSCHED", "ESME_RINVEXPIRY",
    "ESME_RINVDFTMSGID", "ESME_RX_T_APPN", "ESME_RX_P_APPN", "ESME_RX_R_APPN",
    "ESME_RQUERYFAIL",
})


def _validate_status(status: str) -> str:
    """Reject an unknown SMPP status name (mirrors the Rust behaviour)."""
    if status not in SMPP_STATUSES:
        raise ValueError(f"unknown SMPP status: {status!r}")
    return status


def _as_bytes(value: Union[str, bytes, bytearray, None]) -> bytes:
    """Coerce a script-supplied ``short_message`` to bytes.

    The runtime send helpers take ``bytes``; a ``str`` is encoded as UTF-8
    for ergonomics in tests.
    """
    if value is None:
        return b""
    if isinstance(value, str):
        return value.encode("utf-8")
    return bytes(value)


# ---------------------------------------------------------------------------
# Delivery-receipt parser (mirror src/pyclasses.rs::Receipt::parse)
# ---------------------------------------------------------------------------

# Canonical receipt keys, longest-first so ``submit date`` is matched before
# a bare ``date``. Output name is the snake_case form exposed to Python.
_RECEIPT_KEYS: tuple[tuple[str, str], ...] = (
    ("submit date", "submit_date"),
    ("done date", "done_date"),
    ("dlvrd", "dlvrd"),
    ("stat", "stat"),
    ("text", "text"),
    ("sub", "sub"),
    ("err", "err"),
    ("id", "id"),
)


def _parse_receipt(sm: bytes) -> Optional[dict[str, str]]:
    """Best-effort parse of the de-facto SMSC delivery-receipt body.

    Returns a dict with the keys that were present (``id``, ``sub``,
    ``dlvrd``, ``submit_date``, ``done_date``, ``stat``, ``err``, ``text``)
    plus ``raw`` (the undecoded body), or ``None`` when the body has no
    ``key:value`` structure. The format is not standardised across SMSCs,
    so always keep ``raw`` as the source of truth.
    """
    raw = sm.decode("utf-8", errors="replace")
    hay = raw.lower()

    hits: list[tuple[int, int, str]] = []
    for key, field in _RECEIPT_KEYS:
        needle = f"{key}:"
        pos = hay.find(needle)
        if pos == -1:
            continue
        # Skip if this position is already claimed by a longer key
        # (e.g. the ``date:`` inside ``submit date:``).
        if any(pos >= p and pos < p + length for p, length, _ in hits):
            continue
        hits.append((pos, len(needle), field))

    if not hits:
        return None
    hits.sort(key=lambda h: h[0])

    out: dict[str, str] = {}
    for i, (pos, key_len, field) in enumerate(hits):
        val_start = pos + key_len
        val_end = hits[i + 1][0] if i + 1 < len(hits) else len(raw)
        out[field] = raw[val_start:val_end].strip()
    out["raw"] = raw
    return out


# ---------------------------------------------------------------------------
# Pyclasses (mirror src/pyclasses.rs + src/sends.rs response types)
# ---------------------------------------------------------------------------

class MockPduReply:
    """What an ``@smpp.on_pdu`` handler returns — the outcome of
    ``pdu.reply(...)`` / ``pdu.reply_query(...)``.

    You rarely construct this directly; use ``pdu.reply(...)``. ``ok`` is a
    convenience for tests.
    """

    def __init__(self, *, command_status: str = "ESME_ROK",
                 message_id: Optional[str] = None,
                 message_state: Optional[int] = None,
                 final_date: str = "", error_code: int = 0) -> None:
        self.command_status = _validate_status(command_status)
        self.message_id = message_id
        self.message_state = message_state
        self.final_date = final_date
        self.error_code = error_code

    @property
    def ok(self) -> bool:
        """True when ``command_status == "ESME_ROK"``."""
        return self.command_status == "ESME_ROK"

    def __repr__(self) -> str:
        return (f"PduReply(command_status={self.command_status!r}, "
                f"message_id={self.message_id!r})")


class MockPdu:
    """The PDU passed into an ``@smpp.on_pdu`` handler.

    Common surface for ``submit_sm`` / ``deliver_sm`` / ``data_sm`` /
    ``cancel_sm`` / ``query_sm`` / ``replace_sm`` / ``submit_sm_multi``.
    Field names mirror SMPP 3.4 §5.2; not every field is meaningful for
    every command (e.g. ``message_id`` is set only for cancel/query/replace,
    ``destinations`` only for ``submit_sm_multi``).
    """

    def __init__(
        self,
        *,
        command: str = "submit_sm",
        message_id: str = "",
        service_type: str = "",
        source_addr_ton: int = 1,
        source_addr_npi: int = 1,
        source_addr: str = "",
        dest_addr_ton: int = 1,
        dest_addr_npi: int = 1,
        destination_addr: str = "",
        esm_class: int = 0,
        protocol_id: int = 0,
        priority_flag: int = 0,
        registered_delivery: int = 0,
        data_coding: int = 0,
        sm_length: int = 0,
        destinations: Optional[list[str]] = None,
        short_message: Union[str, bytes, None] = b"",
    ) -> None:
        self.command = command
        self.message_id = message_id
        self.service_type = service_type
        self.source_addr_ton = source_addr_ton
        self.source_addr_npi = source_addr_npi
        self.source_addr = source_addr
        self.dest_addr_ton = dest_addr_ton
        self.dest_addr_npi = dest_addr_npi
        self.destination_addr = destination_addr
        self.esm_class = esm_class
        self.protocol_id = protocol_id
        self.priority_flag = priority_flag
        self.registered_delivery = registered_delivery
        self.data_coding = data_coding
        self.sm_length = sm_length
        self.destinations = destinations or []
        self.short_message = _as_bytes(short_message)

    @property
    def is_tpdu(self) -> bool:
        """True when ``short_message`` carries a TPDU (UDHI bit, ``esm_class
        & 0x40``). Decode the payload with an SMS-TPDU codec rather than as
        a literal message."""
        return bool(self.esm_class & 0x40)

    @property
    def is_dlr(self) -> bool:
        """True when this ``deliver_sm`` is an SMSC **delivery receipt**
        (``esm_class & 0x04``). Route these back to the ESME that originally
        requested ``registered_delivery``; see :attr:`receipt`."""
        return bool(self.esm_class & 0x04)

    @property
    def receipt(self) -> Optional[dict[str, str]]:
        """Parsed delivery-receipt fields, or ``None`` when this PDU is not a
        DLR / the body doesn't follow the de-facto receipt format. Keys:
        ``id``, ``sub``, ``dlvrd``, ``submit_date``, ``done_date``, ``stat``,
        ``err``, ``text`` (those present), plus ``raw``."""
        if not self.is_dlr:
            return None
        return _parse_receipt(self.short_message)

    def reply(self, *, command_status: str = "ESME_ROK",
              message_id: Optional[str] = None) -> MockPduReply:
        """Build a reply for the dispatcher. Default is ``ESME_ROK`` with no
        message_id; pass ``command_status="ESME_RSUBMITFAIL"`` etc. to reject,
        or ``message_id="…"`` on success (submit_sm path). Raises
        ``ValueError`` on an unknown status name."""
        return MockPduReply(command_status=command_status, message_id=message_id)

    def reply_query(self, *, message_state: int,
                    message_id: Optional[str] = None,
                    final_date: str = "", error_code: int = 0) -> MockPduReply:
        """Build a ``query_sm_resp``. ``message_state`` is the SMPP
        message-state code (1=ENROUTE, 2=DELIVERED, 3=EXPIRED, 4=DELETED,
        5=UNDELIVERABLE, 6=ACCEPTED, 7=UNKNOWN, 8=REJECTED). ``message_id``
        defaults to the queried ``pdu.message_id``. To reject a query use
        ``pdu.reply(command_status="ESME_RQUERYFAIL")`` instead."""
        return MockPduReply(
            command_status="ESME_ROK",
            message_id=message_id if message_id is not None else self.message_id,
            message_state=message_state,
            final_date=final_date,
            error_code=error_code,
        )

    def __repr__(self) -> str:
        return (f"Pdu(command={self.command}, source_addr={self.source_addr}, "
                f"destination_addr={self.destination_addr}, "
                f"esm_class=0x{self.esm_class:02x}, dcs=0x{self.data_coding:02x}, "
                f"len={self.sm_length})")


class MockBindResult:
    """Outcome of ``@smpp.on_bind`` — what ``bind.accept()`` /
    ``bind.reject(...)`` return. Truthy when the bind is accepted."""

    def __init__(self, *, accept: bool, status: str = "ESME_ROK",
                 reason: str = "") -> None:
        self.accept = accept
        self.status = status
        self.reason = reason

    def __bool__(self) -> bool:
        return self.accept

    def __repr__(self) -> str:
        if self.accept:
            return "BindResult(accept)"
        return f"BindResult(reject, status={self.status!r}, reason={self.reason!r})"


class MockBind:
    """Argument to ``@smpp.on_bind``. Authorise the bind by returning
    ``bind.accept()`` or ``bind.reject("ESME_RINVPASWD", "why")`` (a bare
    truthy/falsy return also works). With no ``@smpp.on_bind`` handler the
    default is **reject** — binds are closed by default."""

    def __init__(self, *, system_id: str = "", password: str = "",
                 client_addr: str = "") -> None:
        self.system_id = system_id
        self.password = password
        self.client_addr = client_addr

    def accept(self) -> MockBindResult:
        """Accept the bind. ``return bind.accept()``."""
        return MockBindResult(accept=True, status="ESME_ROK", reason="")

    def reject(self, status: str = "ESME_RBINDFAIL",
               reason: str = "") -> MockBindResult:
        """Reject the bind with an explicit SMPP status and operator-facing
        reason (logged). Common statuses: ``ESME_RINVPASWD`` (bad password),
        ``ESME_RINVSYSID`` (unknown system_id), ``ESME_RBINDFAIL`` (generic),
        ``ESME_RTHROTTLED`` (rate-limited). Raises ``ValueError`` on an
        unknown status name."""
        return MockBindResult(accept=False, status=_validate_status(status),
                              reason=reason)

    def __repr__(self) -> str:
        return f"Bind(system_id={self.system_id!r}, client_addr={self.client_addr!r})"


class MockSession:
    """Per-PDU context — which side delivered this PDU and which session.

    ``kind`` is ``"esme"`` when an external client bound to our listener, or
    ``"bind"`` when the PDU arrived via one of our outbound binds.
    """

    def __init__(self, *, kind: str = "esme", session_id: str = "",
                 system_id: str = "", client_addr: str = "") -> None:
        if kind not in ("esme", "bind"):
            raise ValueError(f"session kind must be 'esme' or 'bind', got {kind!r}")
        self.kind = kind
        self.session_id = session_id
        self.system_id = system_id
        self.client_addr = client_addr

    def __repr__(self) -> str:
        return (f"Session(kind={self.kind}, system_id={self.system_id!r}, "
                f"session_id={self.session_id!r}, client_addr={self.client_addr!r})")


class MockAlertNotification:
    """Payload for ``@smpp.on_pdu("alert_notification")`` — an SMSC telling us
    (on an outbound bind) that a previously-unavailable MS is reachable again,
    so queued MT can be flushed. ``source_addr`` is the MS, ``esme_addr`` the
    ESME the alert targets, ``ms_availability_status`` the availability state
    (0=available, 1=denied, 2=unavailable) when present."""

    def __init__(self, *, source_addr: str = "", esme_addr: str = "",
                 ms_availability_status: Optional[int] = None) -> None:
        self.source_addr = source_addr
        self.esme_addr = esme_addr
        self.ms_availability_status = ms_availability_status

    @property
    def command(self) -> str:
        return "alert_notification"

    def __repr__(self) -> str:
        return (f"AlertNotification(source_addr={self.source_addr!r}, "
                f"esme_addr={self.esme_addr!r}, "
                f"ms_availability_status={self.ms_availability_status!r})")


class MockSmppResp:
    """Response returned by the send helpers. ``command_status`` is the SMPP
    status name (``ESME_ROK`` on success); ``message_id`` is the SMSC-assigned
    id when the op returns one (``submit_sm`` / ``submit_sm_multi``), empty
    otherwise."""

    def __init__(self, *, command_status: str = "ESME_ROK",
                 message_id: str = "") -> None:
        self.command_status = command_status
        self.message_id = message_id

    @property
    def ok(self) -> bool:
        return self.command_status == "ESME_ROK"

    def __repr__(self) -> str:
        return (f"SmppResp(command_status={self.command_status!r}, "
                f"message_id={self.message_id!r})")


class MockQueryResp:
    """Response returned by ``query_via`` — the result of a ``query_sm``.
    ``message_state`` is the SMPP message-state code (1=ENROUTE … 8=REJECTED),
    ``final_date`` the SMPP-format absolute time (empty if not final),
    ``error_code`` the network error code."""

    def __init__(self, *, command_status: str = "ESME_ROK", message_id: str = "",
                 message_state: int = 1, final_date: str = "",
                 error_code: int = 0) -> None:
        self.command_status = command_status
        self.message_id = message_id
        self.message_state = message_state
        self.final_date = final_date
        self.error_code = error_code

    @property
    def ok(self) -> bool:
        return self.command_status == "ESME_ROK"

    def __repr__(self) -> str:
        return (f"QueryResp(command_status={self.command_status!r}, "
                f"message_id={self.message_id!r}, message_state={self.message_state}, "
                f"final_date={self.final_date!r}, error_code={self.error_code})")


# Default config shape mirrors src/install.rs::build_config_dict.
def _default_config() -> dict[str, Any]:
    return {
        "server": {
            "bind_address": "0.0.0.0",
            "port": 2775,
            "session_init_timer_ms": 30000,
            "enquire_link_timer_ms": 30000,
            "inactivity_timer_ms": 0,
            "response_timer_ms": 30000,
            "max_msg_per_sec": 0,
            "throttle_action": "pace",
        },
        "binds": [],
        "routing": {"default_chain": [], "rules": []},
    }


# ---------------------------------------------------------------------------
# The smpp namespace
# ---------------------------------------------------------------------------

def _registry() -> Any:
    """Resolve the mock ``_siphon_registry`` installed by ``mock_module.install()``.

    Deferred (imported at decorator-call time) so this module has no import
    dependency on ``mock_module`` — exactly how the runtime ``python/smpp.py``
    defers ``import _siphon_registry``.
    """
    import _siphon_registry as registry
    return registry


class MockSmpp:
    """Mock ``smpp`` namespace — decorators, config readouts, send helpers and
    pyclasses, matching the siphon-smpp runtime namespace.

    Outbound sends (``submit_via`` / ``data_via`` / …) and inbound sends
    (``deliver_to`` / ``data_to`` / ``alert_to``) are recorded on
    :attr:`sent` for test assertions instead of hitting a real SMSC.
    """

    # Pyclasses attached to the namespace (``siphon.smpp.Pdu`` etc.).
    Pdu = MockPdu
    PduReply = MockPduReply
    Bind = MockBind
    BindResult = MockBindResult
    Session = MockSession
    AlertNotification = MockAlertNotification
    SmppResp = MockSmppResp
    QueryResp = MockQueryResp

    def __init__(self) -> None:
        #: Recorded outbound/inbound sends — a list of ``(op, kwargs)`` tuples.
        self.sent: list[tuple[str, dict[str, Any]]] = []
        #: Config dict (shape mirrors ``src/install.rs::build_config_dict``).
        self._config: dict[str, Any] = _default_config()
        #: Optional canned ``query_via`` result (else ENROUTE).
        self._query_result: Optional[MockQueryResp] = None

    # -- test helpers -------------------------------------------------------

    def clear(self) -> None:
        """Reset recorded sends and config (called by ``mock_module.reset()``)."""
        self.sent.clear()
        self._config = _default_config()
        self._query_result = None

    def set_config(self, config: dict[str, Any]) -> None:
        """Replace the mock ``_config`` (drives ``config()`` / ``binds()`` /
        ``bind_address()`` / ``routing_rules()``)."""
        self._config = config

    def set_query_result(self, resp: MockQueryResp) -> None:
        """Set the :class:`MockQueryResp` the next ``query_via`` returns."""
        self._query_result = resp

    # -- decorators ---------------------------------------------------------

    def on_bind(self, fn: Callable) -> Callable:
        """Authorise an SMPP bind. Handler receives a :class:`MockBind` and
        returns ``bind.accept()`` / ``bind.reject(status, reason)`` (or a bare
        truthy/falsy). With no handler, binds are rejected by default."""
        _registry().register("smpp.on_bind", None, fn,
                             asyncio.iscoroutinefunction(fn), None)
        return fn

    def on_pdu(self, command: str) -> Callable:
        """Register a handler for a specific SMPP command:
        ``"submit_sm"``, ``"submit_sm_multi"``, ``"deliver_sm"`` (check
        ``pdu.is_dlr`` for delivery receipts), ``"data_sm"``, ``"cancel_sm"``,
        ``"query_sm"`` (reply via ``pdu.reply_query(...)``), ``"replace_sm"``,
        ``"alert_notification"`` (first arg is an :class:`MockAlertNotification`).

        Handler signature ``(pdu, session)``; return ``pdu.reply(...)`` /
        ``pdu.reply_query(...)`` / ``None`` (same as ``pdu.reply()``)."""
        def decorator(fn: Callable) -> Callable:
            _registry().register("smpp.on_pdu", None, fn,
                                 asyncio.iscoroutinefunction(fn),
                                 {"command": command})
            return fn
        return decorator

    def on_session(self, event: str) -> Callable:
        """Lifecycle hook; ``event`` is ``"bound"`` or ``"unbound"``. Handler
        signature ``(session)``; fires when an inbound ESME binds/unbinds
        (``session.kind == "esme"``) and when an outbound bind comes up/goes
        down (``session.kind == "bind"``). Return value ignored."""
        def decorator(fn: Callable) -> Callable:
            _registry().register("smpp.on_session", event, fn,
                                 asyncio.iscoroutinefunction(fn),
                                 {"event": event})
            return fn
        return decorator

    # -- config readouts ----------------------------------------------------

    def bind_address(self) -> str:
        """Listening address, e.g. ``"0.0.0.0:2775"`` — useful for /healthz."""
        server = self._config["server"]
        return f"{server['bind_address']}:{server['port']}"

    def config(self) -> dict[str, Any]:
        """Read-only view of the addon config as a dict."""
        return dict(self._config)

    def binds(self) -> list[dict[str, Any]]:
        """List of outbound bind descriptors (``name``, ``host``, ``port``,
        ``system_id``, ``bind_type``, …)."""
        return list(self._config.get("binds", []))

    def routing_rules(self) -> tuple[list[str], list[dict[str, Any]]]:
        """Returns ``(default_chain, rules)`` as ``(list[str], list[dict])``."""
        routing = self._config.get("routing", {})
        return routing.get("default_chain", []), routing.get("rules", [])

    # -- outbound send helpers (target a bind by name) ----------------------

    async def submit_via(self, *, bind: str, source_addr: str,
                         destination_addr: str, short_message: Union[str, bytes],
                         **fields: Any) -> MockSmppResp:
        """Submit a ``submit_sm`` via the named outbound bind. Resolves to a
        :class:`MockSmppResp` carrying the SMSC message_id."""
        return self._record_submit("submit_via", dict(
            bind=bind, source_addr=source_addr, destination_addr=destination_addr,
            short_message=_as_bytes(short_message), **fields))

    async def submit_multi_via(self, *, bind: str, source_addr: str,
                              destinations: list[str],
                              short_message: Union[str, bytes],
                              **fields: Any) -> MockSmppResp:
        """Submit one message to many destinations (``submit_sm_multi``) via the
        named outbound bind. Resolves to a :class:`MockSmppResp`."""
        return self._record_submit("submit_multi_via", dict(
            bind=bind, source_addr=source_addr, destinations=destinations,
            short_message=_as_bytes(short_message), **fields))

    async def data_via(self, *, bind: str, source_addr: str,
                       destination_addr: str, **fields: Any) -> MockSmppResp:
        """Send a ``data_sm`` via the named outbound bind."""
        self.sent.append(("data_via", dict(
            bind=bind, source_addr=source_addr,
            destination_addr=destination_addr, **fields)))
        return MockSmppResp()

    async def cancel_via(self, *, bind: str, message_id: str,
                         **fields: Any) -> MockSmppResp:
        """Cancel a previously-submitted message via the named outbound bind."""
        self.sent.append(("cancel_via", dict(
            bind=bind, message_id=message_id, **fields)))
        return MockSmppResp()

    async def query_via(self, *, bind: str, message_id: str,
                        **fields: Any) -> MockQueryResp:
        """Query the state of a previously-submitted message via the named
        outbound bind. Resolves to a :class:`MockQueryResp` (defaults to
        ENROUTE; override with :meth:`set_query_result`)."""
        self.sent.append(("query_via", dict(
            bind=bind, message_id=message_id, **fields)))
        if self._query_result is not None:
            return self._query_result
        return MockQueryResp(message_id=message_id, message_state=1)

    async def replace_via(self, *, bind: str, message_id: str,
                          **fields: Any) -> MockSmppResp:
        """Replace a previously-submitted message via the named outbound bind."""
        record = dict(bind=bind, message_id=message_id, **fields)
        if "short_message" in record:
            record["short_message"] = _as_bytes(record["short_message"])
        self.sent.append(("replace_via", record))
        return MockSmppResp()

    # -- inbound send helpers (target a bound ESME by session_id) -----------

    async def deliver_to(self, *, session_id: str, source_addr: str,
                         destination_addr: str, short_message: Union[str, bytes],
                         **fields: Any) -> MockSmppResp:
        """Deliver a ``deliver_sm`` to a bound ESME (by ``session_id``) — the
        SMSC→ESME half: MT/MO content and delivery receipts route back through
        here (set ``esm_class=0x04`` + a receipt body for a DLR)."""
        self.sent.append(("deliver_to", dict(
            session_id=session_id, source_addr=source_addr,
            destination_addr=destination_addr,
            short_message=_as_bytes(short_message), **fields)))
        return MockSmppResp()

    async def data_to(self, *, session_id: str, source_addr: str,
                      destination_addr: str, **fields: Any) -> MockSmppResp:
        """Send a ``data_sm`` to a bound ESME (by ``session_id``)."""
        self.sent.append(("data_to", dict(
            session_id=session_id, source_addr=source_addr,
            destination_addr=destination_addr, **fields)))
        return MockSmppResp()

    async def alert_to(self, *, session_id: str, source_addr: str,
                       esme_addr: str, **fields: Any) -> MockSmppResp:
        """Send an ``alert_notification`` to a bound ESME — tell it a
        previously-unavailable MS is reachable again so it can flush queued MT."""
        self.sent.append(("alert_to", dict(
            session_id=session_id, source_addr=source_addr,
            esme_addr=esme_addr, **fields)))
        return MockSmppResp()

    # -- internals ----------------------------------------------------------

    def _record_submit(self, op: str, record: dict[str, Any]) -> MockSmppResp:
        self.sent.append((op, record))
        return MockSmppResp(message_id=uuid.uuid4().hex)
