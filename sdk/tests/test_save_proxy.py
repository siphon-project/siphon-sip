"""Tests for ``registrar.save_proxy(request, reply)`` — the proxy-shaped
variant that reads the granted ``Expires`` from the upstream's reply
instead of from the UE's request, applies no local cap, and does not
generate a 200 OK (the proxy relays the upstream's reply itself).
"""
from types import SimpleNamespace

import pytest

from siphon_sdk import mock_module


def _fresh_registrar():
    mock_module.install()
    registrar = mock_module.get_registrar()
    registrar._store.clear()
    registrar._associated_uris.clear()
    registrar._aliases.clear()
    return registrar


def _fake_register(to_uri: str, source_ip: str = "10.0.0.1"):
    """Stand-in for an inbound REGISTER on the proxy."""
    return SimpleNamespace(
        to_uri=to_uri,
        ruri=SimpleNamespace(user="alice"),
        source_ip=source_ip,
        method="REGISTER",
        reply=lambda code, reason: None,
    )


def _fake_reply(expires: str | None):
    """Stand-in for the upstream's 200 OK to REGISTER."""
    headers = {"Expires": expires} if expires is not None else {}
    return SimpleNamespace(
        status_code=200,
        get_header=lambda name: headers.get(name),
        relay=lambda: None,
    )


def test_save_proxy_caches_binding_using_reply_expires():
    registrar = _fresh_registrar()
    request = _fake_register("sip:alice@ims.example.com")
    reply = _fake_reply("3600")

    assert registrar.save_proxy(request, reply) is True
    assert registrar.is_registered("sip:alice@ims.example.com")


def test_save_proxy_with_zero_expires_clears_binding():
    registrar = _fresh_registrar()
    request = _fake_register("sip:alice@ims.example.com")
    # Pre-populate.
    registrar.save_proxy(request, _fake_reply("3600"))
    assert registrar.is_registered("sip:alice@ims.example.com")

    # De-REGISTER round-trip — upstream granted 0.
    registrar.save_proxy(request, _fake_reply("0"))
    assert not registrar.is_registered("sip:alice@ims.example.com")


def test_save_proxy_raises_when_reply_missing_expires():
    """RFC 3261 §10.3 step 8: registrar of record must include the
    granted Expires.  A reply without it is a misbehaving upstream and
    save_proxy refuses to guess."""
    registrar = _fresh_registrar()
    request = _fake_register("sip:alice@ims.example.com")
    reply = _fake_reply(None)

    with pytest.raises(ValueError, match="Expires"):
        registrar.save_proxy(request, reply)


def test_save_proxy_with_aliases_registers_implicit_set():
    registrar = _fresh_registrar()
    request = _fake_register("sip:alice@ims.example.com")
    reply = _fake_reply("3600")

    registrar.save_proxy(
        request, reply,
        aliases=["tel:+15551234", "sip:wildcard@ims.example.com"],
    )

    assert registrar.is_registered("sip:alice@ims.example.com")
    assert registrar.is_registered("tel:+15551234")
    assert registrar.is_registered("sip:wildcard@ims.example.com")


def test_save_proxy_does_not_call_request_reply():
    """The proxy relays the upstream's response itself; save_proxy must
    not generate a 200 OK on its own (in contrast to ``save``).  We
    assert this by giving the request a ``reply`` that would raise if
    invoked."""
    def boom(*_args, **_kwargs):
        raise AssertionError("save_proxy must not call request.reply()")

    registrar = _fresh_registrar()
    request = SimpleNamespace(
        to_uri="sip:alice@ims.example.com",
        ruri=SimpleNamespace(user="alice"),
        source_ip="10.0.0.1",
        method="REGISTER",
        reply=boom,
    )
    reply = _fake_reply("3600")

    registrar.save_proxy(request, reply)  # must not raise
