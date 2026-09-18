"""
Reference provisioning API for SIPhon — a runnable example of the JSON contracts
that `registrant.backend: http` and `gateway.backend: http` read.

This is **illustrative**: a trivial in-memory table stands in for the controller
that actually owns the trunks (a PBX, a provisioning database, a tenant
service). Swap `TRUNKS` and the two builders for your own store. The request /
response shapes are the contract siphon speaks — kept in one typed place in
`siphon_sdk.registrants` and `siphon_sdk.gateways` (see
docs/reference/registrant-api.md and gateway-api.md).

One table feeds both endpoints on purpose. A trunk is one thing to the operator
who created it: an outbound registration *and* somewhere calls egress to. Here
one row produces a `RegistrantRow` and a `GatewayRow` that name each other, so
the credential is defined once and the gateway inherits it.

Run:
    pip install fastapi uvicorn siphon-sip
    uvicorn examples.provisioning_api_server:app --host 0.0.0.0 --port 8080

Point siphon at it:
    registrant:
      backend: http
      http: { url: "http://127.0.0.1:8080/registrants" }
    gateway:
      backend: http
      http: { url: "http://127.0.0.1:8080/gateways" }
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from fastapi import FastAPI

from siphon_sdk.gateways import GatewayListResponse, GatewayRow
from siphon_sdk.registrants import RegistrantListResponse, RegistrantRow

app = FastAPI(title="SIPhon provisioning reference API")


@dataclass
class Trunk:
    """What the controller owns: one trunk, both halves of it."""

    name: str
    aor: str
    registrar: str
    username: str
    #: In a real controller this is sealed at rest and unsealed in-process, which
    #: is the whole reason to serve the trunk list over HTTP rather than let
    #: siphon read the database directly: the seal never leaves this process.
    password: str
    egress_uri: str
    transport: str = "udp"
    weight: int = 1
    enabled: bool = True
    #: Carriers that only accept calls from a registered peer. Dialling one while
    #: its registration is down just earns a rejection, so the destination is
    #: better withheld.
    requires_registration: bool = False
    attrs: Dict[str, str] = field(default_factory=dict)


TRUNKS: List[Trunk] = [
    Trunk(
        name="carrier-a",
        aor="sip:trunk1@carrier-a.example",
        registrar="sip:sip.carrier-a.example:5060",
        username="trunk1",
        password="…",
        egress_uri="sip:sip.carrier-a.example:5060",
        weight=3,
        requires_registration=True,
        attrs={"region": "eu-west"},
    ),
    Trunk(
        name="carrier-b",
        aor="sip:trunk2@carrier-b.example",
        registrar="sips:sip.carrier-b.example:5061",
        username="trunk2",
        password="…",
        egress_uri="sips:sip.carrier-b.example:5061",
        transport="tls",
        attrs={"region": "eu-central"},
    ),
]

#: Every trunk here egresses through one group, so `gateway.select("carriers")`
#: load-balances across the carriers that are currently usable.
GROUP = "carriers"


@app.get("/registrants")
def registrants() -> dict:
    """The trunks siphon should keep registered.

    The complete desired state: a trunk that stops appearing is de-registered
    with `Expires: 0`, and one with `enabled: false` is too. Fail the request
    rather than returning an empty list if the store is unreachable — siphon
    keeps its current registrations when a source cannot be read, and an empty
    `200` is indistinguishable from "delete everything".
    """
    return RegistrantListResponse(
        registrants=[
            RegistrantRow(
                aor=trunk.aor,
                registrar=trunk.registrar,
                username=trunk.username,
                password=trunk.password,
                transport=trunk.transport,
                enabled=trunk.enabled,
                # Names the group this trunk's calls egress through, so the two
                # halves of one trunk are visibly one thing.
                gateway=GROUP,
            )
            for trunk in TRUNKS
        ]
    ).to_dict()


@app.get("/gateways")
def gateways() -> dict:
    """Where calls egress to.

    Each row carries no credentials of its own: `registers` points at the
    trunk's registration and the destination answers challenges with that
    credential, so rotating a password is one edit rather than two that can
    drift apart.
    """
    return GatewayListResponse(
        gateways=[
            GatewayRow(
                group=GROUP,
                uri=trunk.egress_uri,
                transport=trunk.transport,
                weight=trunk.weight,
                attrs=trunk.attrs,
                registers=trunk.aor,
                require_registration=trunk.requires_registration,
                enabled=trunk.enabled,
            )
            for trunk in TRUNKS
        ]
    ).to_dict()
