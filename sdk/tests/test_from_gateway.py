"""Tests for the ``from_gateway`` source-membership predicate on the proxy
``Request``, the B2BUA ``Call``, and the ``Reply`` mocks.

``request.from_gateway("group")`` / ``call.from_gateway("group")`` /
``reply.from_gateway("group")`` return ``True`` when the message's source IP is
one of the resolved addresses of the named gateway group — siphon's equivalent
of Kamailio ``ds_is_from_list()`` / OpenSIPS ``ds_is_in_list()``.
"""
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
