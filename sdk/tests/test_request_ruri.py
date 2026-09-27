"""Request-URI rewrites on the Request mock, mirroring the runtime rules."""

import pytest

from siphon_sdk.request import Request
from siphon_sdk.types import SipUri


def make_request() -> Request:
    return Request(method="INVITE", ruri="sip:bob@biloxi.example.com")


def test_set_ruri_is_a_method_taking_a_string():
    request = make_request()
    request.set_ruri("sip:newuser@newhost.example.com:5080")
    assert str(request.ruri) == "sip:newuser@newhost.example.com:5080"


def test_set_ruri_takes_a_sip_uri():
    request = make_request()
    request.set_ruri(SipUri(user="carol", host="replacement.example.com"))
    assert str(request.ruri) == "sip:carol@replacement.example.com"


def test_ruri_property_assignment_is_set_ruri():
    request = make_request()
    request.ruri = "sip:dave@elsewhere.example.com"
    assert str(request.ruri) == "sip:dave@elsewhere.example.com"


def test_rfc4694_user_parameters_reach_the_wire():
    request = make_request()
    target = "sip:+15551234567;npdi;rn=+15559876543@carrier.example.net;user=phone"
    request.set_ruri(target)
    assert request.ruri.user == "+15551234567"
    assert request.ruri.host == "carrier.example.net"
    assert request.ruri.params == {"user": "phone"}
    assert request.ruri.user_params == {"npdi": "", "rn": "+15559876543"}
    assert str(request.ruri) == target


def test_user_params_is_empty_without_userinfo_parameters():
    assert make_request().ruri.user_params == {}


@pytest.mark.parametrize(
    "uri",
    [
        "sips:bob@example.com:5061;transport=tcp",
        "sip:[2001:db8::10]:5060",
        "tel:+15551234567",
        "tel:1234;phone-context=example.com",
        "urn:service:sos",
    ],
)
def test_set_ruri_round_trips(uri):
    request = make_request()
    request.set_ruri(uri)
    assert str(request.ruri) == uri


@pytest.mark.parametrize(
    "uri",
    [
        "sip:",
        "sip:bob@example.com garbage",
        "sip:bob@example.com>",
        "sip:bob@[example.com]",
        "sip:bob@example.com;user=a b",
        "sip:bob@example.com:50x60",
    ],
)
def test_set_ruri_refuses_what_is_not_one_uri(uri):
    request = make_request()
    with pytest.raises(ValueError):
        request.set_ruri(uri)
    assert str(request.ruri) == "sip:bob@biloxi.example.com"


def test_set_ruri_user_and_host():
    request = make_request()
    request.set_ruri_user("+15551234567")
    request.set_ruri_host("gw1.example.net")
    assert str(request.ruri) == "sip:+15551234567@gw1.example.net"


def test_set_ruri_user_takes_service_codes():
    request = make_request()
    request.set_ruri_user("*21#")
    assert str(request.ruri) == "sip:*21#@biloxi.example.com"


@pytest.mark.parametrize("user", ["", "bob@example.com", "sip:bob", "a b", "123;npdi"])
def test_set_ruri_user_refuses_structure(user):
    request = make_request()
    with pytest.raises(ValueError):
        request.set_ruri_user(user)


def test_set_ruri_user_none_drops_user_parameters():
    request = make_request()
    request.set_ruri("sip:+15551234567;npdi;rn=+15559876543@carrier.example.net")
    request.set_ruri_user(None)
    assert str(request.ruri) == "sip:carrier.example.net"


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


def test_set_ruri_param_adds_replaces_and_writes_flags():
    request = make_request()
    request.set_ruri("sip:bob@biloxi.example.com;transport=udp;lr")
    request.set_ruri_param("Transport", "tcp")
    request.set_ruri_param("ob")
    # Replaced in place: the existing spelling is kept.
    assert str(request.ruri) == "sip:bob@biloxi.example.com;transport=tcp;lr;ob"


def test_set_ruri_param_collapses_a_duplicated_name():
    request = make_request()
    request.set_ruri("sip:bob@biloxi.example.com;x=1;y;X=2")
    request.set_ruri_param("x", "3")
    assert str(request.ruri) == "sip:bob@biloxi.example.com;x=3;y"


@pytest.mark.parametrize(
    "name,value", [("user", "a;b"), ("user", ""), ("a b", "x"), ("", None)]
)
def test_set_ruri_param_refuses_what_is_not_a_parameter(name, value):
    request = make_request()
    with pytest.raises(ValueError):
        request.set_ruri_param(name, value)


def test_remove_ruri_param_reports_whether_it_removed():
    request = make_request()
    request.set_ruri("sip:bob@biloxi.example.com;transport=tcp;lr")
    assert request.remove_ruri_param("TRANSPORT") is True
    assert request.remove_ruri_param("maddr") is False
    assert str(request.ruri) == "sip:bob@biloxi.example.com;lr"


def test_tel_phone_context_param_stays_consistent():
    request = make_request()
    request.set_ruri("tel:1234;phone-context=example.com")
    request.set_ruri_param("phone-context", "example.net")
    assert request.ruri.host == "example.net"
    assert str(request.ruri) == "tel:1234;phone-context=example.net"


def test_assigning_on_request_ruri_writes_the_request():
    request = make_request()
    request.ruri.user = "+15551234567"
    request.ruri.host = "gw1.example.net"
    request.ruri.port = 5080
    assert str(request.ruri) == "sip:+15551234567@gw1.example.net:5080"


def test_assigning_on_request_ruri_is_checked():
    request = make_request()
    with pytest.raises(ValueError):
        request.ruri.host = "gw1.example.net:5080"


def test_a_ruri_reference_stays_live_across_set_ruri():
    request = make_request()
    held = request.ruri
    request.set_ruri("sip:carol@gw1.example.net")
    held.user = "dave"
    assert str(request.ruri) == "sip:dave@gw1.example.net"
