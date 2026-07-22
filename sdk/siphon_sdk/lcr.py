"""
LCR (Least-Cost Routing) HTTP contract — the JSON siphon exchanges with an
external LCR API.

This is the **single typed source** for the wire contract (contract version
``"1"``). It mirrors the Rust serde structs in ``src/lcr/mod.rs`` and is what
the reference server in ``examples/lcr_api_server.py`` implements. Operators
building their own LCR API can build against these models::

    from siphon_sdk.lcr import LcrRequest, LcrResponse, Route

    def decide(req: LcrRequest) -> LcrResponse:
        return LcrResponse(routes=[Route(carrier_id="carrier-a",
                                         gateway_group="carrier-a-pool",
                                         rate=0.0042)],
                           cache_ttl_secs=300)

siphon calls this API from a **B2BUA** script only (``await lcr.route(call)``);
see ``docs/cookbook/least-cost-routing.md`` for why LCR is B2BUA-only.

Zero-dependency dataclasses (matching the rest of ``siphon_sdk``). ``to_dict()``
omits ``None`` / empty fields to match the Rust ``skip_serializing_if``, and
aliases ``from_uri``/``to_uri`` to the JSON ``from``/``to`` keys (which are
Python reserved words).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONTRACT_VERSION = "1"
"""Contract version siphon sends in :attr:`LcrRequest.version`."""


@dataclass
class LcrSource:
    """Ingress context on an :class:`LcrRequest`."""

    ip: str
    """Source IP of the A-leg."""

    transport: str = "udp"
    """A-leg transport: ``"udp"`` | ``"tcp"`` | ``"tls"`` | ``"ws"`` | ``"wss"``."""

    trunk_group: Optional[str] = None
    """Ingress trunk / customer group the call arrived on, if known. Part of
    the decision cache key."""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ip": self.ip, "transport": self.transport}
        if self.trunk_group is not None:
            out["trunk_group"] = self.trunk_group
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LcrSource":
        return cls(
            ip=data["ip"],
            transport=data.get("transport", "udp"),
            trunk_group=data.get("trunk_group"),
        )


@dataclass
class LcrRequest:
    """The query siphon POSTs to the LCR API for each new call."""

    call_id: str
    """A-leg Call-ID (for the API's own correlation)."""

    from_uri: str
    """A-leg From URI. Serializes to the JSON key ``"from"``."""

    to_uri: str
    """A-leg To URI. Serializes to the JSON key ``"to"``."""

    dialed_number: str
    """The number being dialed, normalized by the script (canonical ``+E.164``
    recommended) — this is what the API rates."""

    source: LcrSource
    """Ingress context."""

    version: str = CONTRACT_VERSION
    """Contract version."""

    attributes: Dict[str, str] = field(default_factory=dict)
    """Free-form script-supplied hints (customer id, rate-deck id, …)."""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "version": self.version,
            "call_id": self.call_id,
            "from": self.from_uri,
            "to": self.to_uri,
            "dialed_number": self.dialed_number,
            "source": self.source.to_dict(),
        }
        if self.attributes:
            out["attributes"] = dict(self.attributes)
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LcrRequest":
        return cls(
            call_id=data["call_id"],
            from_uri=data["from"],
            to_uri=data["to"],
            dialed_number=data["dialed_number"],
            source=LcrSource.from_dict(data["source"]),
            version=data.get("version", CONTRACT_VERSION),
            attributes=dict(data.get("attributes", {})),
        )


@dataclass
class Route:
    """One carrier attempt in an :class:`LcrResponse`.

    At least one of :attr:`gateway_group` / :attr:`next_hop` / :attr:`ruri`
    must be set for the route to be routable.
    """

    carrier_id: str
    """Opaque carrier identifier — carried into CDR/charging, never routed on."""

    gateway_group: Optional[str] = None
    """Configured ``gateway:`` group to route through. siphon resolves it to a
    healthy member at dial time and skips the route if the whole group is down.
    Preferred over :attr:`next_hop` so carrier health-probing applies."""

    next_hop: Optional[str] = None
    """Explicit next-hop URI (used when no :attr:`gateway_group`, or to pin the
    wire destination while :attr:`ruri` shapes the Request-URI)."""

    ruri: Optional[str] = None
    """Request-URI override for this carrier (else the dialed number is kept).
    Full control over the number shape the carrier sees."""

    tech_prefix: Optional[str] = None
    """Tech-prefix / dial-prefix prepended to the B-leg R-URI userpart for this
    carrier (e.g. ``"1010288"``). Many carriers key routing/billing on a prefix
    in front of the E.164 number."""

    rate: Optional[float] = None
    """Per-minute rate — carried into CDR/charging, not used for routing."""

    currency: Optional[str] = None
    """Rate currency (ISO 4217), e.g. ``"USD"``."""

    billing_increment: Optional[int] = None
    """Billing increment in seconds (60 = per-minute, 1 = per-second)."""

    min_duration: Optional[int] = None
    """Minimum billable duration in seconds."""

    timeout_secs: Optional[int] = None
    """Per-attempt ring timeout in seconds (else the call-level default)."""

    headers: Dict[str, str] = field(default_factory=dict)
    """Headers to inject on this carrier's B-leg INVITE (account token, routing
    tag). Applied after the header policy, so they always land on the wire."""

    reroute_causes: List[int] = field(default_factory=list)
    """SIP codes from this carrier that fail over to the next (overrides the
    per-gateway and global sets). For a carrier that sends non-standard codes."""

    def is_routable(self) -> bool:
        """A route is routable if it names a gateway group, next-hop, or R-URI."""
        return bool(self.gateway_group or self.next_hop or self.ruri)

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"carrier_id": self.carrier_id}
        for name in (
            "gateway_group",
            "next_hop",
            "ruri",
            "tech_prefix",
            "rate",
            "currency",
            "billing_increment",
            "min_duration",
            "timeout_secs",
        ):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        if self.headers:
            out["headers"] = dict(self.headers)
        if self.reroute_causes:
            out["reroute_causes"] = list(self.reroute_causes)
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Route":
        return cls(
            carrier_id=data["carrier_id"],
            gateway_group=data.get("gateway_group"),
            next_hop=data.get("next_hop"),
            ruri=data.get("ruri"),
            tech_prefix=data.get("tech_prefix"),
            rate=data.get("rate"),
            currency=data.get("currency"),
            billing_increment=data.get("billing_increment"),
            min_duration=data.get("min_duration"),
            timeout_secs=data.get("timeout_secs"),
            headers=dict(data.get("headers", {})),
            reroute_causes=list(data.get("reroute_causes", [])),
        )


@dataclass
class LcrReject:
    """An API-side instruction to reject the call instead of routing it."""

    code: int
    """SIP status code (e.g. 503, 403)."""

    reason: str
    """SIP reason phrase."""

    def to_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "reason": self.reason}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LcrReject":
        return cls(code=int(data["code"]), reason=data["reason"])


@dataclass
class LcrResponse:
    """The ordered decision the LCR API returns to siphon."""

    routes: List[Route] = field(default_factory=list)
    """Carriers to try, cheapest/most-preferred first. Empty + ``reject=None``
    means "no route"."""

    cache_ttl_secs: Optional[int] = None
    """How long (seconds) siphon may cache this decision. ``None`` / ``0`` = do
    not cache. The API fully controls caching via this field."""

    reject: Optional[LcrReject] = None
    """When set, siphon rejects the call with this code/reason instead of
    dialing (an API-side block)."""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"routes": [route.to_dict() for route in self.routes]}
        if self.cache_ttl_secs is not None:
            out["cache_ttl_secs"] = self.cache_ttl_secs
        if self.reject is not None:
            out["reject"] = self.reject.to_dict()
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LcrResponse":
        reject = data.get("reject")
        return cls(
            routes=[Route.from_dict(route) for route in data.get("routes", [])],
            cache_ttl_secs=data.get("cache_ttl_secs"),
            reject=LcrReject.from_dict(reject) if reject else None,
        )


__all__ = [
    "CONTRACT_VERSION",
    "LcrSource",
    "LcrRequest",
    "Route",
    "LcrReject",
    "LcrResponse",
]
