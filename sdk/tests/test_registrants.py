"""The outbound-registration provisioning contract (siphon_sdk.registrants).

Mirrors the Rust serde structs in src/registrant/source.rs. A drift between the
two is a wire-contract break, so the shapes are asserted rather than assumed.
"""

from siphon_sdk.registrants import (
    CONTRACT_VERSION,
    RegistrantListResponse,
    RegistrantRow,
)


def row(**overrides):
    base = dict(
        aor="sip:trunk1@carrier.example",
        registrar="sip:carrier.example:5060",
        username="trunk1",
        password="secret123",
    )
    base.update(overrides)
    return RegistrantRow(**base)


def test_minimal_row_carries_the_documented_defaults():
    encoded = row().to_dict()
    assert encoded["transport"] == "udp"
    assert encoded["enabled"] is True
    assert encoded["ha1_algorithm"] == "md5"


def test_absent_optionals_are_omitted_not_null():
    # The Rust side uses skip_serializing_if, so an endpoint built from these
    # models produces exactly what siphon's samples show.
    encoded = row().to_dict()
    for absent in ("ha1", "realm", "interval", "contact", "gateway"):
        assert absent not in encoded


def test_round_trip_preserves_every_field():
    original = row(
        password=None,
        ha1="939e7578ed9e3c518a452acee763bce9",
        ha1_algorithm="sha-256",
        realm="carrier.example",
        interval=1800,
        contact="sip:trunk1@203.0.113.7:5060",
        transport="tls",
        enabled=False,
        gateway="carriers",
    )
    assert RegistrantRow.from_dict(original.to_dict()) == original


def test_response_round_trips():
    response = RegistrantListResponse(
        registrants=[row(), row(aor="sip:trunk2@carrier.example")]
    )
    assert RegistrantListResponse.from_dict(response.to_dict()) == response


def test_response_defaults_to_the_current_contract_version():
    assert RegistrantListResponse().version == CONTRACT_VERSION
    # A payload with no version is read as the current one, so an endpoint is
    # not forced to emit it.
    assert (
        RegistrantListResponse.from_dict({"registrants": []}).version
        == CONTRACT_VERSION
    )


def test_an_ha1_row_needs_no_password():
    hashed = row(password=None, ha1="939e7578ed9e3c518a452acee763bce9")
    encoded = hashed.to_dict()
    assert "password" not in encoded
    assert encoded["ha1"] == "939e7578ed9e3c518a452acee763bce9"


def test_disabled_rows_survive_the_round_trip():
    # `enabled: false` is how a UI's disable switch de-registers a trunk while
    # keeping the row, so it must not be dropped as a falsy default.
    disabled = row(enabled=False)
    assert disabled.to_dict()["enabled"] is False
    assert RegistrantRow.from_dict(disabled.to_dict()).enabled is False
