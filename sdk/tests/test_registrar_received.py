"""Tests for ``Contact.received`` — the transport source of the REGISTER.

The engine records the source address on every binding and its doc-comment
says to route on it instead of the Contact URI: behind NAT the UE advertises
a private address in its Contact while the packet arrives from a public one,
and only the latter is reachable (the OpenSIPS ``received_avp`` equivalent).

It is stored as a full SIP URI — ``sip:<ip>:<port>;transport=<proto>``, see
``PyContact::received_string`` — not a bare ``host:port``, which is what lets
``examples/registrar_proxy.py`` fork straight on ``c.received or c.uri``.
The mock has to produce that same shape or a script that tests green here
would fork to a non-URI on the engine.
"""
from types import SimpleNamespace

from siphon_sdk import mock_module
from siphon_sdk.request import Request
from siphon_sdk.types import Contact


def _fresh_registrar():
    mock_module.install()
    registrar = mock_module.get_registrar()
    registrar._store.clear()
    registrar._associated_uris.clear()
    registrar._aliases.clear()
    registrar._tokens.clear()
    return registrar


def _register(
    source_ip: str = "198.51.100.20",
    source_port: int = 41234,
    transport: str = "udp",
    to_uri: str = "sip:alice@example.com",
):
    return Request(
        method="REGISTER",
        ruri="sip:registrar.example.com",
        to_uri=to_uri,
        from_uri=to_uri,
        transport=transport,
        source_ip=source_ip,
        source_port=source_port,
    )


def test_contact_defaults_to_no_received():
    """Existing scripts and fixtures are unaffected — the field is additive."""
    assert Contact(uri="sip:alice@192.0.2.10:5060").received is None


def test_save_stamps_received_from_the_register_source():
    registrar = _fresh_registrar()

    assert registrar.save(_register("198.51.100.20", 41234)) is True

    contacts = registrar.lookup("sip:alice@example.com")
    assert len(contacts) == 1
    assert contacts[0].received == "sip:198.51.100.20:41234;transport=udp"


def test_received_carries_the_registers_transport():
    """A TCP REGISTER must not be described as UDP — the URI is a routing hint."""
    registrar = _fresh_registrar()
    registrar.save(_register("198.51.100.20", 41234, transport="tcp"))

    assert (
        registrar.lookup("sip:alice@example.com")[0].received
        == "sip:198.51.100.20:41234;transport=tcp"
    )


def test_lookup_returns_received_intact():
    """The field survives the store round-trip, not just the save call."""
    registrar = _fresh_registrar()
    registrar.save(_register("198.51.100.21", 5062))

    first = registrar.lookup("sip:alice@example.com")[0]
    second = registrar.lookup("sip:alice@example.com")[0]
    assert first.received == second.received
    assert first.received == "sip:198.51.100.21:5062;transport=udp"


def test_save_proxy_stamps_received_from_the_register_source():
    registrar = _fresh_registrar()
    reply = SimpleNamespace(
        status_code=200,
        get_header=lambda name: {"Expires": "3600"}.get(name),
        relay=lambda: None,
    )

    assert registrar.save_proxy(_register("198.51.100.22", 33445), reply) is True
    assert (
        registrar.lookup("sip:alice@example.com")[0].received
        == "sip:198.51.100.22:33445;transport=udp"
    )


def test_save_falls_back_for_requests_without_a_source_port():
    """Duck-typed stand-ins that only model ``source_ip`` still work."""
    registrar = _fresh_registrar()
    request = SimpleNamespace(
        to_uri="sip:bob@example.com",
        ruri=SimpleNamespace(user="bob"),
        source_ip="198.51.100.23",
        method="REGISTER",
        reply=lambda code, reason: None,
    )

    registrar.save(request)

    assert (
        registrar.lookup("sip:bob@example.com")[0].received
        == "sip:198.51.100.23:5060;transport=udp"
    )


def test_add_contact_carries_received_through():
    registrar = _fresh_registrar()
    registrar.add_contact(
        "sip:carol@example.com",
        Contact(
            uri="sip:carol@10.0.0.5:5060",
            received="sip:198.51.100.24:19876;transport=udp",
        ),
    )

    assert (
        registrar.lookup("sip:carol@example.com")[0].received
        == "sip:198.51.100.24:19876;transport=udp"
    )


def test_received_wins_over_a_private_contact_uri_when_routing():
    """The behaviour the engine doc-comment promises, now expressible.

    The UE put its private address in the Contact; the REGISTER arrived from
    a public one.  ``received or uri`` has to pick the routable address, and
    the result has to be a URI ``fork()`` will accept.
    """
    registrar = _fresh_registrar()
    registrar.add_contact(
        "sip:dave@example.com",
        Contact(
            uri="sip:dave@10.0.0.5:5060",
            received="sip:198.51.100.25:47001;transport=udp",
        ),
    )

    contact = registrar.lookup("sip:dave@example.com")[0]
    target = contact.received or contact.uri

    assert target == "sip:198.51.100.25:47001;transport=udp"
    assert target != contact.uri
    assert target.startswith("sip:")


def test_received_falls_back_to_uri_for_a_binding_without_source_info():
    """A binding restored from a backend that never captured the source."""
    registrar = _fresh_registrar()
    registrar.add_contact(
        "sip:erin@example.com", Contact(uri="sip:erin@198.51.100.26:5060")
    )

    contact = registrar.lookup("sip:erin@example.com")[0]
    assert (contact.received or contact.uri) == "sip:erin@198.51.100.26:5060"


def test_a_mock_saved_binding_can_be_forked_on():
    """End-to-end shape check: the idiomatic NAT-safe line reaches fork()."""
    registrar = _fresh_registrar()
    registrar.save(_register("198.51.100.28", 52001))

    invite = Request(method="INVITE", ruri="sip:alice@example.com")
    contacts = registrar.lookup("sip:alice@example.com")
    invite.fork([c.received or c.uri for c in contacts])

    assert invite.actions[-1].targets == [
        "sip:198.51.100.28:52001;transport=udp"
    ]


def test_fix_nated_register_writes_the_observed_source_port():
    """``rport=`` is the real source port, not a hardcoded 5060."""
    request = _register("198.51.100.27", 41234)
    request.set_header("Via", "SIP/2.0/UDP 10.0.0.5:5060;branch=z9hG4bKnashds7")

    request.fix_nated_register()

    via = request.get_header("Via")
    assert ";received=198.51.100.27" in via
    assert ";rport=41234" in via
