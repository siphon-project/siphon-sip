"""``scope=`` on ``rtpengine.offer`` / ``answer`` / ``delete``."""

import asyncio

import pytest

from siphon_sdk.call import Call
from siphon_sdk.mock_module import MockRtpEngine


def run(coroutine):
    return asyncio.run(coroutine)


def test_each_leg_records_its_scope_and_reuses_its_own_profile():
    engine = MockRtpEngine()
    target = ("call-1", "tag-a")
    run(engine.offer(target, profile="access_v4", sdp="v=0\r\n", scope="orig"))
    run(engine.offer(target, profile="access_v6", sdp="v=0\r\n", scope="term"))
    run(engine.answer(target, sdp="v=0\r\n", scope="orig"))
    run(engine.delete("call-1"))
    assert engine.media_scopes == [
        ("offer", "orig"),
        ("offer", "term"),
        ("answer", "orig"),
        ("delete", None),
    ]
    assert ("answer", "access_v4") in engine.operations


@pytest.mark.parametrize("scope", ["", "has space", "semi;colon", "x" * 65])
def test_an_invalid_scope_is_refused(scope):
    engine = MockRtpEngine()
    with pytest.raises(ValueError):
        run(engine.offer(("call-1", "tag-a"), sdp="v=0\r\n", scope=scope))
    assert engine.media_scopes == []


def test_a_b2bua_call_takes_no_scope():
    engine = MockRtpEngine()
    with pytest.raises(ValueError, match="B2BUA"):
        run(engine.delete(Call(), scope="orig"))


def test_delete_call_takes_a_scope():
    engine = MockRtpEngine()
    run(engine.delete_call("call-1", scope="orig"))
    run(engine.delete_call("call-2"))
    assert engine.media_scopes == [("delete_call", "orig"), ("delete_call", None)]
    with pytest.raises(ValueError):
        run(engine.delete_call("call-3", scope="bad scope"))
