"""
Call Detail Record (CDR) contract — the JSON siphon writes to its CDR sinks.

This is the **single typed source** for the record shape. It mirrors the Rust
serde struct in ``src/cdr/mod.rs`` and is what every sink emits: one JSON object
per HTTP POST (webhook), per line (JSON-lines file), per syslog message.
Collectors build against it::

    from siphon_sdk.cdr import CallDetailRecord

    @app.post("/cdr")
    async def collect(payload: dict) -> dict:
        record = CallDetailRecord.from_dict(payload)
        if record.is_media:
            for leg in record.media_legs:
                print(leg.role, leg.codec, leg.mos_average)
        else:
            print(record.call_id, record.duration_secs, record.extra)
        return {"ok": True}

``examples/cdr_collector.py`` is a runnable FastAPI receiver built this way.

**Take the body as ``dict`` and call :meth:`CallDetailRecord.from_dict`** rather
than annotating the handler parameter as the dataclass directly. Custom fields
from ``cdr.write(extra={...})`` are *flattened* into the top level of the JSON,
and a framework that validates against the declared fields (FastAPI/pydantic
does) drops every one of them before the handler sees it. ``from_dict`` puts
them in :attr:`CallDetailRecord.extra` instead, which is the whole reason this
type exists.

**Three record flavours share the one shape**, told apart by ``method``:

* a call record — ``INVITE`` / ``BYE`` / whatever the script wrote;
* a registration record — ``REGISTER``, with the change in ``extra["reg_event"]``
  (``cdr.auto_emit`` + ``cdr.include_register``);
* a media record — ``MEDIA``, emitted by the media engine at end of call with
  per-leg quality figures in ``extra``. It carries no URIs: join it to the call
  record on ``call_id``.

Zero-dependency dataclasses (matching the rest of ``siphon_sdk``). Parsing is
lenient — a missing field reads as empty/zero rather than raising, because the
HTTP sink has no retry and a collector that throws loses the record.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

__all__ = ["CallDetailRecord", "LcrAttempt", "MediaLeg"]

TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
"""The format siphon writes every timestamp field in: UTC, millisecond
precision, ``Z`` suffix (e.g. ``"2026-03-06T14:23:01.042Z"``)."""

#: Fields siphon always emits (the non-``Option`` ones in the Rust struct).
_ALWAYS: tuple = (
    "timestamp",
    "call_id",
    "from_uri",
    "to_uri",
    "ruri",
    "method",
    "response_code",
    "duration_secs",
    "source_ip",
    "destination_ip",
    "transport",
)

#: Fields emitted as JSON ``null`` when unset.
_NULLABLE: tuple = (
    "timestamp_start",
    "timestamp_answer",
    "timestamp_end",
    "user_agent",
    "auth_user",
    "disconnect_initiator",
    "sip_reason",
)

#: Fields left out of the JSON entirely when unset (``skip_serializing_if``).
_OMITTED_WHEN_UNSET: tuple = ("rf_session_id", "rf_result_code")

#: Every key that is a declared field — anything else in the payload is a
#: flattened custom field and belongs in :attr:`CallDetailRecord.extra`.
_KNOWN_KEYS = frozenset(_ALWAYS + _NULLABLE + _OMITTED_WHEN_UNSET)


def _as_int(value: Any) -> Optional[int]:
    """Parse a value written as a string into an int, or ``None`` if it isn't one."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> Optional[float]:
    """Parse a value written as a string into a float, or ``None`` if it isn't one."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    """Parse a CDR timestamp into a timezone-aware UTC :class:`~datetime.datetime`.

    Returns ``None`` for ``None`` and for anything that doesn't parse, so a
    collector never dies on a malformed field::

        parse_timestamp("2026-03-06T14:23:01.042Z")
        # datetime(2026, 3, 6, 14, 23, 1, 42000, tzinfo=timezone.utc)
    """
    if not value:
        return None
    try:
        return datetime.strptime(value, TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        pass
    try:  # tolerate an offset form from a collector that re-serialized the record
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


@dataclass
class LcrAttempt:
    """One carrier siphon burned on a sequential-failover call.

    The B2BUA stamps the whole attempt list onto the CDR as a JSON array in
    ``extra["lcr_attempts"]`` (``extra`` is a flat string map, so it is encoded
    rather than nested). :attr:`CallDetailRecord.lcr_attempts` decodes it — this
    is how a carrier that answers 5xx before the call completes on the next one
    is trendable at all; the winning carrier's own fields arrive as ordinary
    ``extra`` keys.
    """

    carrier_id: str
    """The ``carrier_id`` the LCR API returned for this route."""

    status: int
    """Final SIP status this carrier gave, or the synthesized one on timeout."""

    elapsed_ms: int
    """Milliseconds from dialing this carrier to that status."""

    dialed: bool
    """False when the route was never dialed (no healthy gateway in its group,
    for example) — those cost no time and mean something different from a
    carrier that was tried and failed."""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LcrAttempt":
        return cls(
            carrier_id=str(data.get("carrier_id", "")),
            status=_as_int(data.get("status")) or 0,
            elapsed_ms=_as_int(data.get("elapsed_ms")) or 0,
            dialed=bool(data.get("dialed", False)),
        )


@dataclass
class MediaLeg:
    """One leg's end-of-call figures, parsed out of a ``MEDIA`` record's ``extra``.

    The media engine writes each leg's figures into the flat ``extra`` map under
    a per-leg prefix (``near_``, ``far_``, then ``leg2_``, ``leg3_``, …), all as
    strings. :attr:`CallDetailRecord.media_legs` turns them back into numbers.

    The quality fields are ``None`` on a leg with no userspace actor (a plain
    in-kernel relay) or one that never received media, so "not measured" stays
    distinguishable from "measured as zero" — never treat a ``None`` MOS as a
    bad call.
    """

    role: str
    """Which leg: ``"near"`` (the offerer), ``"far"`` (the answerer), or
    ``"leg2"``/``"leg3"``/… for further legs. This is the ``extra`` key prefix."""

    tag: str
    """The leg's SIP tag — the offerer's ``from_tag`` (near) or the answerer's
    ``to_tag`` (far)."""

    codec: Optional[str] = None
    """Negotiated audio codec name, when known."""

    packets_in: int = 0
    bytes_in: int = 0
    packets_out: int = 0
    bytes_out: int = 0

    packets_dropped: int = 0
    """Packets dropped on the engine's side of this leg (source-gate / latch /
    jitter overflow) — **not** network loss. For that see :attr:`packets_lost`."""

    ssrc: Optional[int] = None
    """The inbound stream's SSRC (RFC 3550), when measured."""

    packets_lost: Optional[int] = None
    """Cumulative network packets lost inbound (RFC 3550 §6.4.1), when measured."""

    loss_percent: Optional[float] = None
    """Inbound network packet loss as a percentage, when measured."""

    jitter_ms: Optional[float] = None
    """Inbound interarrival jitter in milliseconds (RFC 3550 §6.4.1)."""

    rtt_ms: Optional[float] = None
    """Engine↔peer round-trip time in milliseconds, when a reception report
    yielded one."""

    mos_average: Optional[float] = None
    """Mean ITU-T G.107 MOS across the call, when measured."""

    mos_min: Optional[float] = None
    """Lowest MOS across the call."""

    mos_max: Optional[float] = None
    """Highest MOS across the call."""

    mos_basis: Optional[str] = None
    """How the MOS was derived: ``"full"`` (includes the G.107 delay term) or
    ``"loss+jitter"``. Compare MOS values only within the same basis."""

    text_packets: Optional[int] = None
    """RFC 4103 real-time text packets received. Present only when the call
    negotiated a plaintext ``m=text`` stream *and* a text observability feature
    (recording, or ``text_events``) promoted it."""

    text_characters: Optional[int] = None
    """T.140 characters received on the text stream."""

    text_missing_markers: Optional[int] = None
    """U+FFFD loss markers inserted in the text stream (RFC 4103 §5.3)."""

    text_recovered_from_redundancy: Optional[int] = None
    """Text packets recovered from RFC 4103 redundancy."""

    @classmethod
    def from_extra(cls, role: str, extra: Dict[str, str]) -> "MediaLeg":
        """Build one leg from the ``{role}_*`` keys of a ``MEDIA`` record's ``extra``."""

        def get(suffix: str) -> Any:
            return extra.get(f"{role}_{suffix}")

        return cls(
            role=role,
            tag=str(get("tag") or ""),
            codec=get("codec"),
            packets_in=_as_int(get("packets_in")) or 0,
            bytes_in=_as_int(get("bytes_in")) or 0,
            packets_out=_as_int(get("packets_out")) or 0,
            bytes_out=_as_int(get("bytes_out")) or 0,
            packets_dropped=_as_int(get("packets_dropped")) or 0,
            ssrc=_as_int(get("ssrc")),
            packets_lost=_as_int(get("packets_lost")),
            loss_percent=_as_float(get("loss_percent")),
            jitter_ms=_as_float(get("jitter_ms")),
            rtt_ms=_as_float(get("rtt_ms")),
            mos_average=_as_float(get("mos_average")),
            mos_min=_as_float(get("mos_min")),
            mos_max=_as_float(get("mos_max")),
            mos_basis=get("mos_basis"),
            text_packets=_as_int(get("text_packets")),
            text_characters=_as_int(get("text_characters")),
            text_missing_markers=_as_int(get("text_missing_markers")),
            text_recovered_from_redundancy=_as_int(get("text_recovered_from_redundancy")),
        )


@dataclass
class CallDetailRecord:
    """One record as siphon writes it to a CDR sink."""

    timestamp: str = ""
    """When the record was generated, in :data:`TIMESTAMP_FORMAT`."""

    call_id: str = ""
    """SIP Call-ID. The join key between a call record and its ``MEDIA``
    record. Empty on a ``REGISTER`` record — the registrar event stream carries
    no Call-ID."""

    from_uri: str = ""
    """From URI. Empty on a ``MEDIA`` record."""

    to_uri: str = ""
    """To URI. Empty on a ``MEDIA`` record."""

    ruri: str = ""
    """Request-URI. Empty on a ``MEDIA`` record."""

    method: str = ""
    """SIP method — ``INVITE`` / ``BYE`` / …, or the two synthetic kinds
    ``REGISTER`` (registrar event) and ``MEDIA`` (end-of-call media summary)."""

    response_code: int = 0
    """Final response code; ``0`` when the call got no final response."""

    timestamp_start: Optional[str] = None
    """When the call started (INVITE sent/received)."""

    timestamp_answer: Optional[str] = None
    """When the call was answered (2xx). ``None`` on an unanswered call."""

    timestamp_end: Optional[str] = None
    """When the call ended (BYE or timeout)."""

    duration_secs: float = 0.0
    """Answered duration in seconds — answer to end, ``0.0`` when never
    answered. On a ``MEDIA`` record this is the media session's lifetime
    instead, with the exact figure in ``extra["media_duration_ms"]``.

    This is conversation time, not call time: for the ringing period, subtract
    :attr:`started_at` from :attr:`answered_at`."""

    source_ip: str = ""
    """Source IP of the request."""

    destination_ip: str = ""
    """Destination IP (next hop).

    Reads empty on every record siphon emits today — the field is declared and
    serialized, but no emit path fills it in. Don't build a collector on it;
    take the egress side from your own routing data until it is wired."""

    transport: str = ""
    """``"udp"`` | ``"tcp"`` | ``"tls"`` | ``"ws"`` | ``"wss"``."""

    user_agent: Optional[str] = None
    """User-Agent header, when the message carried one."""

    auth_user: Optional[str] = None
    """Authenticated username, after digest auth."""

    disconnect_initiator: Optional[str] = None
    """Who ended the call: ``"caller"`` | ``"callee"`` | ``"timeout"`` |
    ``"error"``."""

    sip_reason: Optional[str] = None
    """Reason header value from the BYE (RFC 3326), when present."""

    rf_session_id: Optional[str] = None
    """Diameter Rf accounting Session-Id (3GPP TS 32.299) the CDF returned, when
    Rf auto-emit is on — cross-references this record with the accounting
    record. Absent from the JSON when unset."""

    rf_result_code: Optional[int] = None
    """Result-Code (RFC 6733 §7.1) of the final ACR-STOP exchange, so rejected
    or dropped accounting is visible without joining a second stream. Absent
    from the JSON when unset."""

    extra: Dict[str, str] = field(default_factory=dict)
    """Custom fields, **flattened into the top level of the JSON** — siphon does
    not nest them. Sources: ``cdr.write(extra={...})`` from a script, an LCR
    route's ``cdr_fields``, ``reg_event`` on a ``REGISTER`` record, and the
    per-leg media figures on a ``MEDIA`` record. Values are always strings on
    the wire; use :attr:`media_legs` for the media ones."""

    # -- parsing ---------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CallDetailRecord":
        """Parse one record, routing every unrecognised top-level key to :attr:`extra`.

        That routing is the inverse of the Rust ``#[serde(flatten)]`` and is why
        this method exists: it is what keeps a script's custom fields.
        """
        return cls(
            timestamp=data.get("timestamp") or "",
            call_id=data.get("call_id") or "",
            from_uri=data.get("from_uri") or "",
            to_uri=data.get("to_uri") or "",
            ruri=data.get("ruri") or "",
            method=data.get("method") or "",
            response_code=_as_int(data.get("response_code")) or 0,
            timestamp_start=data.get("timestamp_start"),
            timestamp_answer=data.get("timestamp_answer"),
            timestamp_end=data.get("timestamp_end"),
            duration_secs=_as_float(data.get("duration_secs")) or 0.0,
            source_ip=data.get("source_ip") or "",
            destination_ip=data.get("destination_ip") or "",
            transport=data.get("transport") or "",
            user_agent=data.get("user_agent"),
            auth_user=data.get("auth_user"),
            disconnect_initiator=data.get("disconnect_initiator"),
            sip_reason=data.get("sip_reason"),
            rf_session_id=data.get("rf_session_id"),
            rf_result_code=_as_int(data.get("rf_result_code")),
            extra={key: value for key, value in data.items() if key not in _KNOWN_KEYS},
        )

    @classmethod
    def from_json(cls, payload: Any) -> "CallDetailRecord":
        """Parse one record from a JSON document — a webhook body, or one line
        of the JSON-lines file sink::

            with open("/var/log/siphon/cdr.jsonl") as handle:
                records = [CallDetailRecord.from_json(line) for line in handle]
        """
        return cls.from_dict(json.loads(payload))

    def to_dict(self) -> Dict[str, Any]:
        """Serialize back to siphon's wire shape.

        Round-trips: the nullable fields stay ``null``, ``rf_*`` are omitted when
        unset, and :attr:`extra` is flattened back into the top level.
        """
        out: Dict[str, Any] = {
            "timestamp": self.timestamp,
            "call_id": self.call_id,
            "from_uri": self.from_uri,
            "to_uri": self.to_uri,
            "ruri": self.ruri,
            "method": self.method,
            "response_code": self.response_code,
            "timestamp_start": self.timestamp_start,
            "timestamp_answer": self.timestamp_answer,
            "timestamp_end": self.timestamp_end,
            "duration_secs": self.duration_secs,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "transport": self.transport,
            "user_agent": self.user_agent,
            "auth_user": self.auth_user,
            "disconnect_initiator": self.disconnect_initiator,
            "sip_reason": self.sip_reason,
        }
        for name in _OMITTED_WHEN_UNSET:
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        out.update(self.extra)
        return out

    def to_json(self) -> str:
        """Serialize to a JSON document (one line, as the file sink writes it)."""
        return json.dumps(self.to_dict())

    # -- record kind -----------------------------------------------------

    @property
    def is_media(self) -> bool:
        """True for the media engine's end-of-call summary — see :attr:`media_legs`.

        It carries no URIs, source or transport; join it to the call record on
        :attr:`call_id`."""
        return self.method == "MEDIA"

    @property
    def is_register(self) -> bool:
        """True for a registrar state-change record — see :attr:`reg_event`."""
        return self.method == "REGISTER"

    @property
    def answered(self) -> bool:
        """True when the call reached an answer (it has an answer timestamp)."""
        return self.timestamp_answer is not None

    @property
    def reg_event(self) -> Optional[str]:
        """On a ``REGISTER`` record, the registrar change: ``"registered"`` |
        ``"refreshed"`` | ``"deregistered"`` | ``"expired"``. The AoR is in
        :attr:`from_uri` / :attr:`to_uri` / :attr:`ruri`."""
        return self.extra.get("reg_event")

    @property
    def lcr_attempts(self) -> List[LcrAttempt]:
        """The carriers this call burned before it settled, decoded from
        ``extra["lcr_attempts"]``. Empty when the call took one route (or the
        deployment doesn't use LCR)::

            burned = [a for a in record.lcr_attempts if a.dialed
                      and a.status >= 400]
        """
        raw = self.extra.get("lcr_attempts")
        if not raw:
            return []
        try:
            decoded = json.loads(raw)
        except (TypeError, ValueError):
            return []
        if not isinstance(decoded, list):
            return []
        return [
            LcrAttempt.from_dict(entry) for entry in decoded if isinstance(entry, dict)
        ]

    # -- teardown --------------------------------------------------------

    @property
    def reason_protocol(self) -> Optional[str]:
        """Protocol of the Reason header (RFC 3326): ``"Q.850"``, ``"SIP"``, …"""
        if not self.sip_reason:
            return None
        return self.sip_reason.split(";", 1)[0].strip() or None

    @property
    def reason_cause(self) -> Optional[int]:
        """The Reason header's ``cause=`` value (RFC 3326) — for ``Q.850``, the
        ITU cause code: 16 normal clearing, 31 normal unspecified, 102 recovery
        on timer expiry, …

        The cause is what separates a clean hangup from a timer teardown on two
        calls that both read ``response_code: 200`` with the callee as
        :attr:`disconnect_initiator`."""
        if not self.sip_reason:
            return None
        match = re.search(r"(?:^|;)\s*cause\s*=\s*(\d+)", self.sip_reason)
        return int(match.group(1)) if match else None

    @property
    def reason_text(self) -> Optional[str]:
        """The Reason header's ``text=`` value, unquoted."""
        if not self.sip_reason:
            return None
        match = re.search(r'(?:^|;)\s*text\s*=\s*"([^"]*)"', self.sip_reason)
        if match:
            return match.group(1)
        match = re.search(r"(?:^|;)\s*text\s*=\s*([^;]+)", self.sip_reason)
        return match.group(1).strip() if match else None

    # -- timestamps ------------------------------------------------------

    @property
    def generated_at(self) -> Optional[datetime]:
        """:attr:`timestamp` as a timezone-aware UTC datetime."""
        return parse_timestamp(self.timestamp)

    @property
    def started_at(self) -> Optional[datetime]:
        """:attr:`timestamp_start` as a timezone-aware UTC datetime."""
        return parse_timestamp(self.timestamp_start)

    @property
    def answered_at(self) -> Optional[datetime]:
        """:attr:`timestamp_answer` as a timezone-aware UTC datetime."""
        return parse_timestamp(self.timestamp_answer)

    @property
    def ended_at(self) -> Optional[datetime]:
        """:attr:`timestamp_end` as a timezone-aware UTC datetime."""
        return parse_timestamp(self.timestamp_end)

    # -- media -----------------------------------------------------------

    @property
    def media_reason(self) -> Optional[str]:
        """On a ``MEDIA`` record, why the media session ended: ``"delete"``
        (controller teardown) or ``"media_timeout"`` (dead-path reap). A
        ``media_timeout`` on a call the signalling side thinks completed is the
        one-way-audio / stalled-media signature worth alerting on."""
        return self.extra.get("media_reason")

    @property
    def media_duration_ms(self) -> Optional[int]:
        """On a ``MEDIA`` record, the media session lifetime in milliseconds
        (the engine's logical clock, ~1 s grain)."""
        return _as_int(self.extra.get("media_duration_ms"))

    @property
    def media_legs(self) -> List[MediaLeg]:
        """The per-leg figures of a ``MEDIA`` record, in engine order: index 0 is
        the near (offerer) leg, index 1 the far (answerer) leg.

        Empty on any other record::

            if record.is_media:
                worst = min((leg.mos_average for leg in record.media_legs
                             if leg.mos_average is not None), default=None)
        """
        legs: List[MediaLeg] = []
        index = 0
        while True:
            if index == 0:
                role = "near"
            elif index == 1:
                role = "far"
            else:
                role = f"leg{index}"
            if f"{role}_tag" not in self.extra:
                break
            legs.append(MediaLeg.from_extra(role, self.extra))
            index += 1
        return legs
