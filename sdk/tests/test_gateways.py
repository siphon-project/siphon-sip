"""The gateway provisioning contract (siphon_sdk.gateways).

Mirrors the Rust serde structs in src/gateway/source.rs. A drift between the two
is a wire-contract break, so the shapes are asserted rather than assumed.
"""

from siphon_sdk.gateways import CONTRACT_VERSION, GatewayListResponse, GatewayRow


def row(**overrides):
    base = dict(group="carriers", uri="sip:gw1.carrier.example:5060")
    base.update(overrides)
    return GatewayRow(**base)


def test_minimal_row_carries_the_documented_defaults():
    encoded = row().to_dict()
    assert encoded["weight"] == 1
    assert encoded["priority"] == 1
    assert encoded["ha1_algorithm"] == "md5"
    assert encoded["enabled"] is True
    assert encoded["require_registration"] is False


def test_absent_optionals_are_omitted_not_null():
    encoded = row().to_dict()
    for absent in ("address", "transport", "algorithm", "username", "password", "ha1", "registers"):
        assert absent not in encoded
    # Empty collections are omitted too, matching skip_serializing_if.
    assert "attrs" not in encoded
    assert "source_networks" not in encoded


def test_round_trip_preserves_every_field():
    original = row(
        address="203.0.113.10:5060",
        transport="tls",
        weight=3,
        priority=2,
        algorithm="hash",
        attrs={"region": "eu-west"},
        source_networks=["203.0.113.0/24"],
        username="trunk1",
        ha1="939e7578ed9e3c518a452acee763bce9",
        ha1_algorithm="sha-256",
        registers="sip:trunk1@carrier.example",
        require_registration=True,
        enabled=False,
    )
    assert GatewayRow.from_dict(original.to_dict()) == original


def test_response_round_trips():
    response = GatewayListResponse(
        gateways=[row(), row(uri="sip:gw2.carrier.example:5060")]
    )
    assert GatewayListResponse.from_dict(response.to_dict()) == response


def test_response_defaults_to_the_current_contract_version():
    assert GatewayListResponse().version == CONTRACT_VERSION
    assert GatewayListResponse.from_dict({"gateways": []}).version == CONTRACT_VERSION


def test_rows_share_a_group_name():
    # One row is one destination; the group is what gathers them, and it is what
    # gateway.select() takes.
    response = GatewayListResponse(
        gateways=[row(), row(uri="sip:gw2.carrier.example:5060")]
    )
    assert {entry["group"] for entry in response.to_dict()["gateways"]} == {"carriers"}


def test_a_linked_row_can_gate_on_its_registration():
    linked = row(registers="sip:trunk1@carrier.example", require_registration=True)
    encoded = linked.to_dict()
    assert encoded["registers"] == "sip:trunk1@carrier.example"
    assert encoded["require_registration"] is True
    # No credentials of its own: it inherits the registration's.
    assert "password" not in encoded
    assert "username" not in encoded
