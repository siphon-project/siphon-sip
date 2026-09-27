"""Request-URI rewrites on the Request mock, mirroring the runtime."""

import pytest

from siphon_sdk.request import Request
from siphon_sdk.types import SipUri


def make_request() -> Request:
    return Request(method="INVITE", ruri="sip:bob@biloxi.example.com")


def test_set_ruri_is_a_method_taking_a_string():
    request = make_request()
    request.set_ruri("sip:newuser@newhost.example.com:5080")
    assert request.ruri.user == "newuser"
    assert request.ruri.host == "newhost.example.com"
    assert request.ruri.port == 5080


def test_set_ruri_takes_a_sip_uri():
    request = make_request()
    request.set_ruri(SipUri(user="carol", host="replacement.example.com"))
    assert str(request.ruri) == "sip:carol@replacement.example.com"


def test_ruri_is_assignable():
    request = make_request()
    request.ruri = "sip:dave@elsewhere.example.com"
    assert request.ruri.user == "dave"
    assert request.ruri.host == "elsewhere.example.com"


def test_set_ruri_user_and_host():
    request = make_request()
    request.set_ruri_user("+15551234567")
    request.set_ruri_host("gw1.example.net")
    assert str(request.ruri) == "sip:+15551234567@gw1.example.net"


@pytest.mark.parametrize("host", ["gw1.example.net", "192.0.2.10"])
def test_set_ruri_host_accepts_domains_and_ipv4(host):
    request = make_request()
    request.set_ruri_host(host)
    assert request.ruri.host == host


@pytest.mark.parametrize("host", ["2001:db8::10", "[2001:db8::10]"])
def test_set_ruri_host_brackets_ipv6_once(host):
    request = make_request()
    request.set_ruri_host(host)
    assert request.ruri.host == "[2001:db8::10]"


@pytest.mark.parametrize(
    "host",
    [
        "",
        "gw1.example.net:5080",
        "192.0.2.10:5060",
        "sip:gw1.example.net",
        "bob@gw1.example.net",
        "gw1.example.net;transport=tcp",
        "[gw1.example.net]",
        "[2001:db8::10]:5060",
    ],
)
def test_set_ruri_host_refuses_a_port_or_a_whole_uri(host):
    request = make_request()
    with pytest.raises(ValueError):
        request.set_ruri_host(host)
    assert request.ruri.host == "biloxi.example.com"
