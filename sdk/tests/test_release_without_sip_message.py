"""Tests for the two teardowns a script drives without a SIP message in hand:
``rtpengine.delete_call`` (media by Call-ID) and ``registrar.remove_contact``
(one binding of a multi-contact AoR).
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from siphon_sdk import mock_module
from siphon_sdk.types import Contact


@pytest.fixture
def registrar():
    mock_module.install()
    registrar = mock_module.get_registrar()
    registrar.clear()
    return registrar


def _bind(registrar, aor: str, uri: str, token=None) -> None:
    registrar.add_contact(aor, Contact(uri=uri, q=1.0, expires=3600, flow_token=token))
    if token is not None:
        registrar._tokens[token] = aor


class TestRemoveContact:
    AOR = "sip:alice@ims.example.com"

    def test_one_contact_goes_and_the_other_stays(self, registrar):
        _bind(registrar, self.AOR, "sip:alice@192.0.2.10:5060", token="t-a")
        _bind(registrar, self.AOR, "sip:alice@192.0.2.11:5060", token="t-b")
        events = []
        registrar._fire_on_change = lambda aor, event: events.append((aor, event))

        assert registrar.remove_contact(self.AOR, "<sip:alice@192.0.2.10:5060>") is True

        assert [c.uri for c in registrar.lookup(self.AOR)] == ["sip:alice@192.0.2.11:5060"]
        assert "t-a" not in registrar._tokens
        assert "t-b" in registrar._tokens
        assert events == [(self.AOR, "deregistered")]

    def test_the_stored_uri_is_matched_as_it_stands(self, registrar):
        _bind(registrar, self.AOR, "sip:alice@192.0.2.10:5060")
        _bind(registrar, self.AOR, "sip:alice@192.0.2.10:5060;transport=tcp")

        assert registrar.remove_contact(self.AOR, "sip:alice@192.0.2.10:5060;transport=tcp")
        assert [c.uri for c in registrar.lookup(self.AOR)] == ["sip:alice@192.0.2.10:5060"]
        assert not registrar.remove_contact(self.AOR, "sip:alice@192.0.2.10")

    def test_last_contact_drops_the_aor_and_its_ims_state(self, registrar):
        _bind(registrar, self.AOR, "sip:alice@192.0.2.10:5060")
        registrar._service_routes[self.AOR] = ["<sip:scscf.ims.example.com;lr>"]
        contact = registrar.lookup(self.AOR)[0]

        assert registrar.remove_contact(self.AOR, contact) is True

        assert registrar.is_registered(self.AOR) is False
        assert self.AOR not in registrar._service_routes

    def test_nothing_matched_returns_false(self, registrar):
        _bind(registrar, self.AOR, "sip:alice@192.0.2.10:5060")
        assert registrar.remove_contact(self.AOR, "sip:alice@192.0.2.99") is False
        assert registrar.remove_contact("sip:nobody@ims.example.com", "sip:x@192.0.2.10") is False
        assert len(registrar.lookup(self.AOR)) == 1


class TestDeleteCall:
    def test_releases_once_and_records_the_call_id(self):
        engine = mock_module.MockRtpEngine()

        assert asyncio.run(engine.delete_call("call-1")) is True
        assert asyncio.run(engine.delete_call("call-1", from_tag="tag-a")) is False

        assert engine.operations == [("delete_call", "call-1"), ("delete_call", "call-1")]

    def test_empty_call_id_is_refused(self):
        engine = mock_module.MockRtpEngine()
        with pytest.raises(ValueError):
            asyncio.run(engine.delete_call(""))
