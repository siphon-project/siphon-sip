"""
Outbound-registration provisioning contract — the JSON siphon reads from a
``registrant.backend: http`` source.

This is the **single typed source** for the wire contract (contract version
``"1"``). It mirrors the Rust serde structs in ``src/registrant/source.rs`` and
is what the reference server in ``examples/provisioning_api_server.py``
implements. A controller that owns trunks as data builds against these models::

    from siphon_sdk.registrants import RegistrantListResponse, RegistrantRow

    def trunks() -> RegistrantListResponse:
        return RegistrantListResponse(registrants=[
            RegistrantRow(aor="sip:trunk1@carrier.example",
                          registrar="sip:carrier.example:5060",
                          username="trunk1",
                          password="…"),
        ])

siphon ``GET``s the endpoint every ``refresh_secs`` and reconciles its live
registrations against the answer: adding trunks it has not registered, removing
ones the list no longer carries, and re-registering ones whose credentials or
target changed. A row it has already registered unchanged is left completely
alone, so polling does not churn the estate.

**The secret.** Supply ``password`` or ``ha1``, never both. A password is the
general case: it answers whatever the registrar challenges with. An ``ha1`` is
``H(username:realm:password)`` and cannot be reversed to the password, so a
store holding one cannot leak it — but it is still password-equivalent *for its
realm*, and it is bound to the hash it was computed with (RFC 7616 §3.4.3), so a
registrar that challenges with SHA-256 cannot be answered from an MD5 one.

This HTTP source exists for the deployment that seals its trunk secrets at rest:
the controller unseals in-process and serves the credential over a trusted local
channel, so siphon never sees the sealed form.

Zero-dependency dataclasses (matching the rest of ``siphon_sdk``). ``to_dict()``
omits ``None`` fields to match the Rust ``skip_serializing_if``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

CONTRACT_VERSION = "1"
"""Contract version siphon expects in :attr:`RegistrantListResponse.version`."""


@dataclass
class RegistrantRow:
    """One trunk that should be registered."""

    aor: str
    """Address of record to register, e.g. ``"sip:trunk1@carrier.example"``."""

    registrar: str
    """Where the REGISTER goes, e.g. ``"sip:carrier.example:5060"``. A host with
    no port defaults to 5060, or 5061 for ``transport="tls"``."""

    username: str
    """Digest username."""

    password: Optional[str] = None
    """Plaintext password. Supply this or :attr:`ha1`, never both."""

    ha1: Optional[str] = None
    """Pre-computed ``H(username:realm:password)`` hex string. Not reversible to
    the password, but still password-equivalent for its realm."""

    ha1_algorithm: str = "md5"
    """Which hash :attr:`ha1` was computed with: ``"md5"`` (default),
    ``"sha-256"`` or ``"sha-512-256"``. Must match what the registrar
    challenges with (RFC 7616 §3.4.3)."""

    realm: Optional[str] = None
    """Realm hint. Taken from the registrar's challenge when omitted."""

    interval: Optional[int] = None
    """Re-registration interval in seconds. ``registrant.default_interval``
    when omitted."""

    contact: Optional[str] = None
    """Contact URI override. Built from the local address when omitted."""

    transport: str = "udp"
    """``"udp"`` (default), ``"tcp"`` or ``"tls"``."""

    enabled: bool = True
    """``False`` de-registers the trunk without removing the row — what a UI's
    "disable" switch wants. siphon sends ``Expires: 0`` and drops the entry."""

    gateway: Optional[str] = None
    """Optional ``gateway:`` group this trunk's calls egress through, linking
    the registration to a gateway destination so one row describes one trunk."""

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "aor": self.aor,
            "registrar": self.registrar,
            "username": self.username,
            "transport": self.transport,
            "enabled": self.enabled,
            "ha1_algorithm": self.ha1_algorithm,
        }
        for name in ("password", "ha1", "realm", "interval", "contact", "gateway"):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        return out

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegistrantRow":
        return cls(
            aor=data["aor"],
            registrar=data["registrar"],
            username=data["username"],
            password=data.get("password"),
            ha1=data.get("ha1"),
            ha1_algorithm=data.get("ha1_algorithm", "md5"),
            realm=data.get("realm"),
            interval=data.get("interval"),
            contact=data.get("contact"),
            transport=data.get("transport", "udp"),
            enabled=data.get("enabled", True),
            gateway=data.get("gateway"),
        )


@dataclass
class RegistrantListResponse:
    """What a ``registrant.backend: http`` endpoint answers ``GET {url}`` with.

    The list is the complete desired state, not a delta: a trunk that is absent
    is de-registered. An endpoint that cannot answer should fail the request
    rather than return an empty list — siphon keeps its current registrations
    when a source is unreadable, precisely so an outage does not tear the estate
    down, and an empty ``200`` is indistinguishable from "delete everything".
    """

    registrants: List[RegistrantRow] = field(default_factory=list)
    """Every trunk that should be registered right now."""

    version: str = CONTRACT_VERSION
    """Contract version. siphon logs a mismatch and carries on."""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "registrants": [row.to_dict() for row in self.registrants],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RegistrantListResponse":
        return cls(
            registrants=[
                RegistrantRow.from_dict(row) for row in data.get("registrants", [])
            ],
            version=data.get("version", CONTRACT_VERSION),
        )


__all__ = ["CONTRACT_VERSION", "RegistrantRow", "RegistrantListResponse"]
