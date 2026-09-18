"""
Gateway provisioning contract — the JSON siphon reads from a
``gateway.backend: http`` source.

This is the **single typed source** for the wire contract (contract version
``"1"``). It mirrors the Rust serde structs in ``src/gateway/source.rs`` and is
what the reference server in ``examples/provisioning_api_server.py``
implements::

    from siphon_sdk.gateways import GatewayListResponse, GatewayRow

    def gateways() -> GatewayListResponse:
        return GatewayListResponse(gateways=[
            GatewayRow(group="carriers", uri="sip:gw1.carrier.example:5060",
                       weight=3, username="trunk1", password="…"),
        ])

One row is one destination; rows are gathered into groups by :attr:`GatewayRow.group`,
which is the name ``gateway.select()`` takes. siphon ``GET``s the endpoint every
``refresh_secs`` and reconciles.

**Health survives a refresh.** A destination whose definition has not changed is
carried over as-is, keeping whatever the health prober has learned about it. A
carrier that is down stays down across a poll rather than being marked healthy
again every 30 seconds. Change anything a call would notice — the URI, address,
transport, weight, priority, attributes or credentials — and it becomes a new
destination, which starts healthy, because it is a different peer or a different
way of reaching one.

**Linking to an outbound registration.** :attr:`GatewayRow.registers` names an
AoR from the registrant source. A destination with no credentials of its own
then answers challenges with that registration's, so one trunk's secret is
defined once. :attr:`GatewayRow.require_registration` additionally keeps the
destination out of selection while that registration is down — opt-in, because
silently withholding a destination is worse than trying it.

Zero-dependency dataclasses (matching the rest of ``siphon_sdk``). ``to_dict()``
omits ``None`` / empty fields to match the Rust ``skip_serializing_if``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONTRACT_VERSION = "1"
"""Contract version siphon expects in :attr:`GatewayListResponse.version`."""


@dataclass
class GatewayRow:
    """One gateway destination."""

    group: str
    """Group this destination belongs to — the name ``gateway.select()`` takes."""

    uri: str
    """SIP URI to route to, e.g. ``"sip:gw1.carrier.example:5060"``. A
    ``;transport=`` parameter here sets the transport when :attr:`transport` is
    omitted."""

    address: Optional[str] = None
    """Socket address to send to. Resolved from the URI host when omitted; a
    hostname is re-resolved on each health-probe cycle."""

    transport: Optional[str] = None
    """``"udp"``, ``"tcp"`` or ``"tls"``. Falls back to the URI parameter, then
    UDP."""

    weight: int = 1
    """Weight for weighted round-robin."""

    priority: int = 1
    """Priority tier; lower is tried first, so a higher tier is a failover
    pool."""

    algorithm: Optional[str] = None
    """Load balancing for the whole group: ``"weighted"`` (default),
    ``"round_robin"`` or ``"hash"``. Taken from the first row of each group."""

    attrs: Dict[str, str] = field(default_factory=dict)
    """Free-form attributes, matched by ``gateway.select(attrs=…)``."""

    source_networks: List[str] = field(default_factory=list)
    """Source CIDRs whose senders also count as members of this group for
    ``request.from_gateway()`` / ``call.from_gateway()``. Group-wide."""

    username: Optional[str] = None
    """Digest username this destination challenges with."""

    password: Optional[str] = None
    """Plaintext password. Supply this or :attr:`ha1`, never both."""

    ha1: Optional[str] = None
    """Pre-computed ``H(username:realm:password)`` hex string."""

    ha1_algorithm: str = "md5"
    """Which hash :attr:`ha1` was computed with: ``"md5"`` (default),
    ``"sha-256"`` or ``"sha-512-256"``."""

    registers: Optional[str] = None
    """AoR of an outbound registration this destination belongs to. With no
    credentials of its own, it answers challenges with that registration's."""

    require_registration: bool = False
    """Keep this destination out of selection while :attr:`registers` is not
    registered. Needs :attr:`registers`."""

    enabled: bool = True
    """``False`` drops the destination without removing the row."""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "group": self.group,
            "uri": self.uri,
            "weight": self.weight,
            "priority": self.priority,
            "ha1_algorithm": self.ha1_algorithm,
            "require_registration": self.require_registration,
            "enabled": self.enabled,
        }
        for name in (
            "address",
            "transport",
            "algorithm",
            "username",
            "password",
            "ha1",
            "registers",
        ):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        if self.attrs:
            out["attrs"] = dict(self.attrs)
        if self.source_networks:
            out["source_networks"] = list(self.source_networks)
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GatewayRow":
        return cls(
            group=data["group"],
            uri=data["uri"],
            address=data.get("address"),
            transport=data.get("transport"),
            weight=data.get("weight", 1),
            priority=data.get("priority", 1),
            algorithm=data.get("algorithm"),
            attrs=dict(data.get("attrs", {})),
            source_networks=list(data.get("source_networks", [])),
            username=data.get("username"),
            password=data.get("password"),
            ha1=data.get("ha1"),
            ha1_algorithm=data.get("ha1_algorithm", "md5"),
            registers=data.get("registers"),
            require_registration=data.get("require_registration", False),
            enabled=data.get("enabled", True),
        )


@dataclass
class GatewayListResponse:
    """What a ``gateway.backend: http`` endpoint answers ``GET {url}`` with.

    The list is the complete desired state, not a delta: a group whose rows are
    all gone is removed. An endpoint that cannot answer should fail the request
    rather than return an empty list — siphon keeps its current groups when a
    source is unreadable, precisely so an outage does not leave the node with
    nowhere to route, and an empty ``200`` is indistinguishable from "delete
    everything".
    """

    gateways: List[GatewayRow] = field(default_factory=list)
    """Every destination that should exist right now."""

    version: str = CONTRACT_VERSION
    """Contract version. siphon logs a mismatch and carries on."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "gateways": [row.to_dict() for row in self.gateways],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GatewayListResponse":
        return cls(
            gateways=[GatewayRow.from_dict(row) for row in data.get("gateways", [])],
            version=data.get("version", CONTRACT_VERSION),
        )


__all__ = ["CONTRACT_VERSION", "GatewayRow", "GatewayListResponse"]
