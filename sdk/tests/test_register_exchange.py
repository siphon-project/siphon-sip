"""``request.wire``, ``reply.wire`` and the ``exchange`` an
``@registrar.on_change`` handler may take (3GPP TS 24.229 clause 5.4.1.7).

The engine hands a handler that names ``exchange`` the REGISTER as received and
the 200 OK it sent; a 3-argument handler is called as it always was. The mock
has no 200 to capture, so its exchange carries the request and no response.
"""
from siphon_sdk import mock_module
from siphon_sdk.reply import Reply
from siphon_sdk.request import Request
from siphon_sdk.types import RegisterExchange

AOR = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"
RAW = (
    b"REGISTER sip:ims.mnc001.mcc001.3gppnetwork.org SIP/2.0\r\n"
    b"v: SIP/2.0/UDP 192.0.2.20:5070;branch=z9hG4bK-sdk\r\n"
    b"Subject: folded\r\n across two lines\r\n"
    b"i: sdk-wire-1\r\n\r\n"
)


def _register(wire=None, contact="<sip:001010000000001@192.0.2.20:5070>", expires="3600"):
    return Request(
        method="REGISTER",
        ruri="sip:ims.mnc001.mcc001.3gppnetwork.org",
        from_uri=AOR,
        to_uri=AOR,
        source_ip="192.0.2.20",
        source_port=5070,
        headers={"Contact": [contact], "Expires": expires},
        wire=wire,
    )


def _registrar():
    mock_module.reset()
    mock_module.install()
    return mock_module.get_registrar()


def test_request_and_reply_wire_default_to_none_and_carry_what_they_are_given():
    assert Request().wire is None
    assert Reply().wire is None
    assert Request(wire=RAW).wire == RAW
    assert Reply(wire=b"SIP/2.0 200 OK\r\n\r\n").wire == b"SIP/2.0 200 OK\r\n\r\n"


def test_a_handler_that_names_exchange_gets_the_request_bytes_of_the_save():
    registrar = _registrar()
    seen = []

    @registrar.on_change
    def changed(aor, event, contacts, exchange):
        seen.append((aor, event, exchange))

    assert registrar.save(_register(wire=RAW)) is True

    assert len(seen) == 1
    aor, event, exchange = seen[0]
    assert (aor, event) == (AOR, "registered")
    assert isinstance(exchange, RegisterExchange)
    assert exchange.request == RAW
    assert exchange.response is None, "the mock builds no 200 to capture"
    assert "RegisterExchange(request=" in repr(exchange)


def test_a_save_of_a_request_without_wire_hands_over_no_exchange():
    registrar = _registrar()
    seen = []

    @registrar.on_change
    def changed(aor, event, contacts, exchange):
        seen.append(exchange)

    registrar.save(_register())
    assert seen == [None]


def test_a_three_argument_handler_is_called_as_before():
    registrar = _registrar()
    plain, with_exchange = [], []

    @registrar.on_change
    def three(aor, event, contacts):
        plain.append(event)

    @registrar.on_change
    def four(aor, event, contacts, exchange=None):
        with_exchange.append(exchange)

    registrar.save(_register(wire=RAW))
    assert plain == ["registered"]
    assert with_exchange[0].request == RAW


def test_a_de_register_carries_its_own_request_and_an_expiry_none():
    registrar = _registrar()
    seen = []

    @registrar.on_change
    def changed(aor, event, contacts, exchange):
        seen.append((event, exchange.request if exchange else None))

    registrar.save(_register(wire=b"first"))
    registrar.save(_register(wire=b"second", expires="0"))
    registrar._fire_on_change(AOR, "expired")

    assert seen == [
        ("registered", b"first"),
        ("deregistered", b"second"),
        ("expired", None),
    ]


def test_on_change_runs_after_the_reply_is_queued():
    registrar = _registrar()
    request = _register(wire=RAW)
    replies_at_change = []

    @registrar.on_change
    def changed(aor, event, contacts, exchange):
        replies_at_change.append(len(request.actions))

    registrar.save(request)
    assert replies_at_change == [1], "the 200 was already queued"
