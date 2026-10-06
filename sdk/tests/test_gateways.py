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
    for absent in (
        "address",
        "transport",
        "algorithm",
        "username",
        "password",
        "ha1",
        "registers",
        "probe",
        "probe_interval_secs",
        "probe_failure_threshold",
        "probe_from_user",
        "probe_from_domain",
        "inbound_max_concurrent_calls",
        "inbound_max_calls_per_second",
        "inbound_reject_code",
        "inbound_retry_after_secs",
    ):
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
        probe=True,
        probe_interval_secs=10,
        probe_failure_threshold=5,
        probe_from_user="edge",
        probe_from_domain="sbc.example.com",
        inbound_max_concurrent_calls=300,
        inbound_max_calls_per_second=30,
        inbound_reject_code=486,
        inbound_retry_after_secs=5,
    )
    assert GatewayRow.from_dict(original.to_dict()) == original


def test_the_inbound_limit_fields_use_the_names_siphon_reads():
    encoded = row(
        inbound_max_concurrent_calls=300,
        inbound_max_calls_per_second=30,
        inbound_reject_code=486,
    ).to_dict()
    assert encoded["inbound_max_concurrent_calls"] == 300
    assert encoded["inbound_max_calls_per_second"] == 30
    assert encoded["inbound_reject_code"] == 486
    assert "inbound_retry_after_secs" not in encoded


def test_a_zero_retry_after_is_sent_not_omitted():
    # 0 is the value that turns the header off; dropping it as "falsy" would
    # leave the default of one second in force.
    encoded = row(inbound_max_concurrent_calls=10, inbound_retry_after_secs=0).to_dict()
    assert encoded["inbound_retry_after_secs"] == 0


def test_the_row_fields_mirror_the_rust_struct():
    """Every `inbound_*` field of the Rust `GatewayRow` exists here, and no
    more: a drift is a wire-contract break."""
    import dataclasses
    import re
    from pathlib import Path

    source = (Path(__file__).resolve().parents[2] / "src/gateway/source.rs").read_text()
    struct = source[source.index("pub struct GatewayRow {"):]
    struct = struct[: struct.index("\n}\n")]
    rust = set(re.findall(r"pub (inbound_\w+):", struct))
    python = {f.name for f in dataclasses.fields(GatewayRow) if f.name.startswith("inbound_")}
    assert rust == python
    assert len(rust) == 4


def test_probe_false_is_sent_not_omitted():
    # False is the value that matters here; dropping it as "falsy" would leave
    # the group probed by default.
    encoded = row(probe=False).to_dict()
    assert encoded["probe"] is False


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
