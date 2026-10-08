"""Tests for the Teams Direct Routing SBC example (examples/teams_sbc.py),
driven through the SDK mocks.

Covers the transfer handler: a siphon-terminated transfer dials its target
directly, so ``@b2bua.on_refer`` has to pick both the trunk the new leg leaves
on and the media profile for the pair that remains. With a Teams side and a
carrier side that is four pairings (survivor x target), and each must get its
own ``next_hop`` and ``profile``.
"""
import asyncio
import importlib.util
import pathlib

import pytest

from siphon_sdk import mock_module

mock_module.install()

from siphon import gateway  # noqa: E402  (must come after install)
from siphon_sdk.call import Call  # noqa: E402

EXAMPLE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent
    / "examples"
    / "teams_sbc.py"
)
TEAMS_URI = "sip:teams-trunk.example.com:5061;transport=tls"
CARRIER_URI = "sip:sip.carrier.example.net:5060"
# RFC 5737 TEST-NET-3 addresses standing in for the two trunks' sources.
TEAMS_IP = "203.0.113.50"
CARRIER_IP = "203.0.113.20"

PSTN_TARGET = "sip:+15550142@sbc.example.com"
TEAMS_TARGET = "sip:teams-trunk.example.com:5061;x-token=opaque"


def _load_example():
    spec = importlib.util.spec_from_file_location("teams_sbc_example", EXAMPLE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def _fresh_mocks():
    mock_module.reset()
    gateway.add_group("teams", [{"uri": TEAMS_URI, "address": f"{TEAMS_IP}:5061"}])
    gateway.add_group("carrier", [{"uri": CARRIER_URI, "address": f"{CARRIER_IP}:5060"}])
    yield
    mock_module.reset()


def _actions(call, kind):
    return [action for action in call._actions if action.kind == kind]


def _transfer(source_ip, refer_side, refer_to):
    """Run on_refer for a call whose A-leg came from ``source_ip``."""
    module = _load_example()
    call = Call(source_ip=source_ip, refer_to=refer_to, refer_side=refer_side)
    asyncio.run(module.on_refer(call))
    return call


# (A-leg source, referring side) for each party that can transfer. Teams refers
# from the A-leg of a Teams -> carrier call and from the B-leg of a
# carrier -> Teams call; the carrier is the mirror.
TEAMS_REFERS = [(TEAMS_IP, "a"), (CARRIER_IP, "b")]
CARRIER_REFERS = [(CARRIER_IP, "a"), (TEAMS_IP, "b")]


@pytest.mark.parametrize("source_ip,refer_side", TEAMS_REFERS)
def test_teams_transfers_to_pstn_leaves_via_carrier_as_plain_rtp(source_ip, refer_side):
    call = _transfer(source_ip, refer_side, PSTN_TARGET)

    (accepted,) = _actions(call, "accept_refer")
    assert accepted.targets == [PSTN_TARGET]
    assert accepted.next_hop == CARRIER_URI
    assert accepted.extras["mode"] == "terminate"
    assert accepted.extras["profile"] == "rtp_passthrough"


@pytest.mark.parametrize("source_ip,refer_side", TEAMS_REFERS)
def test_teams_transfers_to_teams_goes_back_to_teams_as_srtp(source_ip, refer_side):
    """The carrier leg survives and the target is a Teams user: the new leg must
    go out the Teams trunk, RTP in and SRTP out, with the target untouched."""
    call = _transfer(source_ip, refer_side, TEAMS_TARGET)

    (accepted,) = _actions(call, "accept_refer")
    assert accepted.targets == [TEAMS_TARGET]
    assert accepted.next_hop == TEAMS_URI
    assert accepted.extras["profile"] == "rtp_to_srtp"


@pytest.mark.parametrize("source_ip,refer_side", CARRIER_REFERS)
def test_carrier_transfers_to_pstn_keeps_teams_survivor_on_srtp(source_ip, refer_side):
    call = _transfer(source_ip, refer_side, PSTN_TARGET)

    (accepted,) = _actions(call, "accept_refer")
    assert accepted.next_hop == CARRIER_URI
    assert accepted.extras["profile"] == "srtp_to_rtp"


@pytest.mark.parametrize("source_ip,refer_side", CARRIER_REFERS)
def test_carrier_transfers_to_teams_is_srtp_both_ends(source_ip, refer_side):
    call = _transfer(source_ip, refer_side, TEAMS_TARGET)

    (accepted,) = _actions(call, "accept_refer")
    assert accepted.next_hop == TEAMS_URI
    assert accepted.extras["profile"] == "srtp_to_srtp"


def test_transfer_without_a_target_is_rejected():
    call = _transfer(TEAMS_IP, "a", None)

    (rejected,) = _actions(call, "reject_refer")
    assert rejected.status_code == 400
    assert not _actions(call, "accept_refer")


@pytest.mark.parametrize("target,group", [(PSTN_TARGET, "carrier"), (TEAMS_TARGET, "teams")])
def test_transfer_is_refused_when_the_target_trunk_is_down(target, group):
    """503, never a fallback to the other trunk: the wrong side cannot reach
    the target and would get the wrong media profile."""
    module = _load_example()
    uri = TEAMS_URI if group == "teams" else CARRIER_URI
    gateway.mark_down(group, uri)
    call = Call(source_ip=TEAMS_IP, refer_to=target, refer_side="a")
    asyncio.run(module.on_refer(call))

    (rejected,) = _actions(call, "reject_refer")
    assert rejected.status_code == 503
    assert not _actions(call, "accept_refer")


@pytest.mark.parametrize(
    "uri,host",
    [
        ("sip:teams-trunk.example.com:5061;transport=tls", "teams-trunk.example.com"),
        ("sip:+15550142@SBC.example.com", "sbc.example.com"),
        ("sip:+15550142;npdi@sbc.example.com:5060;user=phone", "sbc.example.com"),
        ("sips:alice@sbc.example.com?Replaces=abc%40host", "sbc.example.com"),
        ("sip:alice@[2001:db8::1]:5061", "2001:db8::1"),
    ],
)
def test_uri_host(uri, host):
    assert _load_example().uri_host(uri) == host
