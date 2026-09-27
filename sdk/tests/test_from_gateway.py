"""Tests for the ``from_gateway`` source-membership predicate on the proxy
``Request``, the B2BUA ``Call``, and the ``Reply`` mocks.

``request.from_gateway("group")`` / ``call.from_gateway("group")`` /
``reply.from_gateway("group")`` return ``True`` when the message's source IP is
one of the resolved addresses of the named gateway group — siphon's equivalent
of Kamailio ``ds_is_from_list()`` / OpenSIPS ``ds_is_in_list()``.
"""
import pytest

from siphon_sdk import mock_module

mock_module.install()

from siphon import gateway  # noqa: E402  (must come after install)
from siphon_sdk.call import Call  # noqa: E402
from siphon_sdk.reply import Reply  # noqa: E402
from siphon_sdk.request import Request  # noqa: E402


def setup_function(_):
    mock_module.reset()


def _register_teams_group():
    # RFC 5737 TEST-NET-3 addresses standing in for Teams' SIP hubs.
    gateway.add_group(
        "teams",
        [
            {"uri": "sip:sip.pstnhub.microsoft.com", "address": "203.0.113.10:5061"},
            {"uri": "sip:sip2.pstnhub.microsoft.com", "address": "203.0.113.11:5061"},
            {"uri": "sip:sip3.pstnhub.microsoft.com", "address": "203.0.113.12:5061"},
        ],
    )


# --- Request.from_gateway --------------------------------------------------


def test_request_from_gateway_true_for_member():
    _register_teams_group()
    request = Request(source_ip="203.0.113.11")
    assert request.from_gateway("teams") is True


def test_request_from_gateway_false_for_non_member():
    _register_teams_group()
    request = Request(source_ip="198.51.100.5")
    assert request.from_gateway("teams") is False


def test_request_from_gateway_false_for_unknown_group():
    _register_teams_group()
    request = Request(source_ip="203.0.113.10")
    assert request.from_gateway("nonexistent") is False


def test_request_from_gateway_false_when_no_groups():
    request = Request(source_ip="203.0.113.10")
    assert request.from_gateway("teams") is False


def test_request_from_gateway_false_for_bad_source_ip():
    _register_teams_group()
    request = Request(source_ip="not-an-ip")
    assert request.from_gateway("teams") is False


# --- Call.from_gateway -----------------------------------------------------


def test_call_from_gateway_true_for_member():
    _register_teams_group()
    call = Call(source_ip="203.0.113.12")
    assert call.from_gateway("teams") is True


def test_call_from_gateway_false_for_non_member():
    _register_teams_group()
    call = Call(source_ip="192.0.2.1")
    assert call.from_gateway("teams") is False


def test_call_from_gateway_false_for_unknown_group():
    _register_teams_group()
    call = Call(source_ip="203.0.113.10")
    assert call.from_gateway("nonexistent") is False


def test_call_from_gateway_matches_ip_ignoring_port():
    # Membership is IP-only — the source port never participates.
    gateway.add_group("trunk", [{"uri": "sip:gw", "address": "192.0.2.50:5060"}])
    call = Call(source_ip="192.0.2.50")
    assert call.from_gateway("trunk") is True


# --- Reply.from_gateway ----------------------------------------------------


def test_reply_from_gateway_true_for_member():
    _register_teams_group()
    reply = Reply(status_code=200, source_ip="203.0.113.11")
    assert reply.from_gateway("teams") is True
    assert reply.source_ip == "203.0.113.11"


def test_reply_from_gateway_false_for_non_member():
    _register_teams_group()
    reply = Reply(status_code=200, source_ip="198.51.100.5")
    assert reply.from_gateway("teams") is False


def test_reply_from_gateway_false_for_unknown_group():
    _register_teams_group()
    reply = Reply(status_code=200, source_ip="203.0.113.10")
    assert reply.from_gateway("nonexistent") is False


def test_reply_from_gateway_false_when_source_unknown():
    # A fork-aggregated @proxy.on_failure reply carries no single source.
    _register_teams_group()
    reply = Reply(status_code=503)
    assert reply.source_ip is None
    assert reply.source_port is None
    assert reply.from_gateway("teams") is False


def test_reply_from_gateway_false_for_bad_source_ip():
    _register_teams_group()
    reply = Reply(status_code=200, source_ip="not-an-ip")
    assert reply.from_gateway("teams") is False


# --- Call.source_ip_in (CIDR membership, the from_gateway complement) -------


def test_call_source_ip_in_matches_v4_and_v6():
    # For a peer that sources from a whole published subnet rather than only its
    # FQDN-resolved IPs, a script gates on the ranges directly.
    call = Call(source_ip="203.0.113.9")
    assert call.source_ip_in(["203.0.113.0/24"]) is True
    assert call.source_ip_in(["198.51.100.0/24"]) is False
    # IPv6 source inside a documented /32.
    call6 = Call(source_ip="2001:db8::5")
    assert call6.source_ip_in(["2001:db8::/32"]) is True
    assert call6.source_ip_in(["2001:db9::/32"]) is False


def test_call_source_ip_in_false_for_unparseable_source():
    call = Call(source_ip="not-an-ip")
    assert call.source_ip_in(["203.0.113.0/24"]) is False


# --- add_group(destinations=[{"transport": ...}]) ---
#
# Lives here because this file is where the gateway mock is driven. siphon dials a
# destination over UDP or over a connection the outbound pool opens, and the pool
# opens TCP and TLS only, so anything else is refused instead of being quietly
# downgraded — the Rust binding used to fall through to UDP and dial a `TLS`
# destination in the clear.


def test_add_group_refuses_a_destination_transport_siphon_cannot_dial():
    for transport in ["sctp", "SCTP", "ws", "wss", "tpc"]:
        with pytest.raises(ValueError, match="can dial"):
            gateway.add_group(
                "carriers",
                [{"uri": "sip:gw1.carrier.example:5060",
                  "address": "203.0.113.10:5060",
                  "transport": transport}],
            )
        assert gateway.groups() == []


def test_add_group_accepts_the_dialable_destination_transports():
    for transport in [None, "udp", "tcp", "tls", "TLS"]:
        mock_module.reset()
        destination = {"uri": "sip:gw1.carrier.example:5060",
                       "address": "203.0.113.10:5060"}
        if transport is not None:
            destination["transport"] = transport
        gateway.add_group("carriers", [destination])
        assert gateway.groups() == ["carriers"]
