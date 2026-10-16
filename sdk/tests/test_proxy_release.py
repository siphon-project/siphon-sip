"""``proxy.release``: ending a Record-Routed session by Call-ID from outside a
SIP transaction (TS 24.229 §5.2.8.1)."""

from __future__ import annotations

import asyncio

import pytest

from siphon_sdk.mock_module import MockProxy


def test_release_finds_a_releasable_session_once():
    proxy = MockProxy()
    proxy.add_releasable_session("call@192.0.2.1")
    reason = 'SIP;cause=503;text="Bearer released"'
    assert asyncio.run(proxy.release("call@192.0.2.1", reason=reason)) is True
    assert asyncio.run(proxy.release("call@192.0.2.1")) is False
    assert proxy.releases[0] == {
        "call_id": "call@192.0.2.1",
        "reason": reason,
        "toward": "both",
        "status": 487,
        "released": True,
    }


def test_an_unknown_call_id_is_false():
    proxy = MockProxy()
    assert asyncio.run(proxy.release("nobody@192.0.2.1", toward="callee")) is False


@pytest.mark.parametrize("toward,status", [("sideways", 487), ("both", 200), ("caller", 700)])
def test_arguments_it_cannot_act_on_raise(toward, status):
    proxy = MockProxy()
    with pytest.raises(ValueError):
        proxy.release("call@192.0.2.1", toward=toward, status=status)
